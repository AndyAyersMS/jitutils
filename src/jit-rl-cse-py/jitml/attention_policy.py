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

        super().__init__(observation_space, features_dim=features_dim)

        cand_space = observation_space.spaces["candidates"]
        method_space = observation_space.spaces["method"]
        self._max_cse = cand_space.shape[0]
        self._per_cand_feats = cand_space.shape[1]
        self._method_feats = method_space.shape[0]

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

        self.head = nn.Sequential(
            nn.Linear(embed_dim * 2, features_dim),
            nn.ReLU(),
        )

    def forward(self, observations: Dict[str, torch.Tensor]) -> torch.Tensor:  # type: ignore[override]
        cands = observations["candidates"]  # (batch, max_cse, per_cand_feats)
        method = observations["method"]     # (batch, method_feats)

        cand_emb = self.candidate_embed(cands)          # (batch, max_cse, embed_dim)
        cand_out = self.attn(cand_emb)                  # (batch, max_cse, embed_dim)
        cand_pooled = cand_out.mean(dim=1)              # (batch, embed_dim)

        method_emb = self.method_embed(method)          # (batch, embed_dim)

        combined = torch.cat([cand_pooled, method_emb], dim=-1)
        return self.head(combined)


def make_attention_policy_kwargs(
    features_dim: int = 128,
    embed_dim: int = 64,
    num_heads: int = 4,
    num_attn_layers: int = 1,
    net_arch: Optional[Any] = None,
) -> Dict[str, Any]:
    """Convenience builder for ``policy_kwargs`` passed to PPO/A2C.

    Set ``net_arch`` to something small (e.g. ``[64]``) since most of
    the modeling capacity now lives in the attention extractor.
    """
    return {
        "features_extractor_class": AttentionOverCandidatesExtractor,
        "features_extractor_kwargs": {
            "features_dim": features_dim,
            "embed_dim": embed_dim,
            "num_heads": num_heads,
            "num_attn_layers": num_attn_layers,
        },
        "net_arch": net_arch if net_arch is not None else [64],
    }


__all__ = ["AttentionOverCandidatesExtractor", "make_attention_policy_kwargs"]
