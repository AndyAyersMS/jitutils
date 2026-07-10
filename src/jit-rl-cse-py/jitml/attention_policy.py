"""Custom SB3 features extractor: attention over CSE candidates.

Alternative to the default flatten-then-MLP feature extractor. The
observation is a Dict with two channels:

* ``candidates``: ``(MAX_CSE, FEATURES_PER_CANDIDATE)`` -- one row per
  (padded) candidate.
* ``method``: ``(METHOD_LEVEL_FEATURES,)`` -- method-scope context.

This module embeds each candidate row, runs multi-head self-attention
across the candidate dimension so each candidate's representation is
context-aware of the others, mean-pools to a single vector, embeds the
method-level channel, concatenates the two, and passes them through a
small MLP head. The result is the ``features_dim``-sized tensor that
SB3's policy/value heads consume.

Rationale: CSE decisions are inherently pairwise -- picking one
candidate often obviates or enables others. A flatten-then-MLP feature
extractor learns to reason across candidates by position, which is
brittle to the (essentially arbitrary) index ordering the JIT hands us.
Attention treats the candidate list as a set and is index-agnostic.

Padding: candidate rows beyond the method's true CSE count are zero.
This first pass does NOT mask them out of attention -- that's a
straightforward follow-up if training quality shows padding noise is a
real problem. The zero rows still contribute (weak) noise to attention
outputs but the MLP head can typically learn to filter it.

Usage::

    model = JitCseModel("PPO", use_attention=True)
    model.train(ctx, method_ids, out_dir, iterations=100_000)
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import torch
from torch import nn

try:
    from stable_baselines3.common.torch_layers import BaseFeaturesExtractor
except ImportError:  # pragma: no cover - guarded by users installing SB3
    BaseFeaturesExtractor = object  # type: ignore

import gymnasium as gym


class AttentionOverCandidatesExtractor(BaseFeaturesExtractor):
    """Attention-based extractor for the Dict CSE observation."""

    def __init__(
        self,
        observation_space: gym.spaces.Dict,
        features_dim: int = 128,
        embed_dim: int = 64,
        num_heads: int = 4,
        num_attn_layers: int = 1,
        dropout: float = 0.0,
        use_separate_stop_head: bool = False,
    ):
        if not isinstance(observation_space, gym.spaces.Dict):
            raise TypeError(
                "AttentionOverCandidatesExtractor requires a Dict observation space "
                f"(got {type(observation_space).__name__}). Wrap your env with the "
                "Dict-producing JitCseEnv, or use MlpPolicy for flat observations."
            )
        if "candidates" not in observation_space.spaces or "method" not in observation_space.spaces:
            raise ValueError(
                "Observation space must have 'candidates' and 'method' keys."
            )

        cand_space = observation_space.spaces["candidates"]
        method_space = observation_space.spaces["method"]
        max_cse = cand_space.shape[0]

        # When ``use_separate_stop_head=True`` this extractor emits
        # (batch, max_cse+1) logits directly -- one per candidate plus
        # one for the stop action. Callers should then set
        # ``net_arch=[]`` on the policy so SB3's action_net becomes a
        # linear pass-through (Linear(max_cse+1, max_cse+1)). The
        # decoupled stop-scorer is a targeted fix for the "compulsive
        # firing on A_nothing" pattern observed in C4/C4-ext: with a
        # shared candidate/stop head, the stop logit was learned as a
        # function of pooled candidate features, so methods with any
        # non-trivial candidate got a low stop probability regardless
        # of whether stopping was actually the right call.
        if use_separate_stop_head:
            features_dim = max_cse + 1

        super().__init__(observation_space, features_dim=features_dim)

        self._max_cse = max_cse
        self._per_cand_feats = cand_space.shape[1]
        self._method_feats = method_space.shape[0]
        self._use_separate_stop_head = use_separate_stop_head

        if embed_dim % num_heads != 0:
            raise ValueError(
                f"embed_dim ({embed_dim}) must be divisible by num_heads ({num_heads})."
            )

        self.candidate_embed = nn.Linear(self._per_cand_feats, embed_dim)
        self.method_embed = nn.Linear(self._method_feats, embed_dim)

        # Optional stack of self-attention layers over the candidate dim.
        # Uses PyTorch's TransformerEncoderLayer for the classic
        # (attn + LN + FFN + LN) block, batch-first for readability.
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=embed_dim,
            nhead=num_heads,
            dim_feedforward=embed_dim * 2,
            dropout=dropout,
            batch_first=True,
            norm_first=True,
        )
        self.attn = nn.TransformerEncoder(encoder_layer, num_layers=num_attn_layers)

        if use_separate_stop_head:
            # Per-candidate scorer over post-attention embeddings; one
            # scalar per candidate.
            self.candidate_scorer = nn.Linear(embed_dim, 1)
            # Stop scorer reads ONLY method-level features -- keeps the
            # stop decision from being blurred by mean-pooled candidate
            # noise. Rationale mirrors LinearPerCandidateExtractor's
            # split.
            self.stop_scorer = nn.Linear(self._method_feats, 1)
        else:
            self.head = nn.Sequential(
                nn.Linear(embed_dim * 2, features_dim),
                nn.ReLU(),
            )

    def forward(self, observations: Dict[str, torch.Tensor]) -> torch.Tensor:  # type: ignore[override]
        cands = observations["candidates"]  # (batch, max_cse, per_cand_feats)
        method = observations["method"]     # (batch, method_feats)

        # Build a padding mask so attention ignores zero-padded candidate
        # rows (which sit past the method's true CSE count and are all
        # zeros by the env encoder's construction). Without this mask the
        # policy can learn positional shortcuts -- e.g. always attend to
        # candidate #1 -- since the fixed-position noise is stable across
        # methods.
        #
        # ``key_padding_mask``: True where the row is padding.
        padding_mask = (cands.abs().sum(dim=-1) == 0)  # (batch, max_cse)

        cand_emb = self.candidate_embed(cands)          # (batch, max_cse, embed_dim)
        cand_out = self.attn(cand_emb, src_key_padding_mask=padding_mask)

        if self._use_separate_stop_head:
            # Per-candidate score = Linear(embed_dim, 1) on attention
            # outputs. Concatenate the method-level stop score.
            cand_scores = self.candidate_scorer(cand_out).squeeze(-1)  # (batch, max_cse)
            stop_score = self.stop_scorer(method)                      # (batch, 1)
            return torch.cat([cand_scores, stop_score], dim=-1)         # (batch, max_cse+1)

        # Mean-pool over real candidates only (denominator = # non-padding
        # rows). Guard against divide-by-zero for the (theoretical)
        # all-padding batch element.
        keep = (~padding_mask).unsqueeze(-1).float()    # (batch, max_cse, 1)
        cand_pooled = (cand_out * keep).sum(dim=1) / keep.sum(dim=1).clamp(min=1.0)

        method_emb = self.method_embed(method)          # (batch, embed_dim)

        combined = torch.cat([cand_pooled, method_emb], dim=-1)
        return self.head(combined)


def make_attention_policy_kwargs(
    features_dim: int = 128,
    embed_dim: int = 64,
    num_heads: int = 4,
    num_attn_layers: int = 1,
    net_arch: Optional[Any] = None,
    use_separate_stop_head: bool = False,
) -> Dict[str, Any]:
    """Convenience builder for ``policy_kwargs`` passed to PPO/A2C.

    Set ``net_arch`` to something small (e.g. ``[64]``) since most of
    the modeling capacity now lives in the attention extractor.

    When ``use_separate_stop_head=True`` the extractor emits action
    logits directly (features_dim == max_cse+1); ``net_arch`` is forced
    to ``[]`` so SB3's action_net is a linear pass-through.
    """
    if use_separate_stop_head:
        # Extractor produces max_cse+1 logits already; do NOT add an
        # MLP head or the shared/stop split is lost inside SB3's
        # subsequent action_net + hidden layers.
        arch = []
    else:
        arch = net_arch if net_arch is not None else [64]
    return {
        "features_extractor_class": AttentionOverCandidatesExtractor,
        "features_extractor_kwargs": {
            "features_dim": features_dim,
            "embed_dim": embed_dim,
            "num_heads": num_heads,
            "num_attn_layers": num_attn_layers,
            "use_separate_stop_head": use_separate_stop_head,
        },
        "net_arch": arch,
    }


__all__ = ["AttentionOverCandidatesExtractor", "make_attention_policy_kwargs"]
