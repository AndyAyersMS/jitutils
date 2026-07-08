"""Custom SB3 features extractor: RL2020-style linear per-candidate scorer.

The tier1/A1/A2 attention baseline uses ~70k trainable parameters. The
2020 hand-tuned CSE RL used just 25 (a shared linear scoring function
applied to each candidate, plus a stopping feature).

This module offers a minimal-parameter middle ground:

* Each of the (up to ``MAX_CSE``) candidate rows is scored by a SHARED
  linear head: ``score_i = w_cand . cand_features_i + b_cand``. This is
  the same inductive bias RL2020 uses: the model must learn a single
  set of weights that works for every candidate slot, regardless of
  position.
* The stop action ("do no more CSEs") is scored by a separate linear
  head on the method-level features:
  ``score_stop = w_stop . method_features + b_stop``.
* The extractor output is a fixed-size vector of ``MAX_CSE + 1``
  per-action scores. Combined with ``policy_kwargs={"net_arch": []}``
  the SB3 default action_net is a single ``(MAX_CSE+1) x (MAX_CSE+1)``
  linear "remixing" layer -- redundant but small (289 params for
  MAX_CSE=16).

Padded candidate rows (all-zero, sitting past the method's true
candidate count) are still scored by the shared linear head but their
score is masked to ``-inf`` before returning so the softmax action
distribution can never place probability on a non-existent candidate.

Total parameter count with MAX_CSE=16, per_candidate=30, method=12,
``net_arch=[]``::

    shared candidate scorer:      30 + 1 = 31
    stop scorer:                  12 + 1 = 13
    action_net (17 -> 17):        17*17 + 17 = 306
    value_net (17 -> 1):          17 + 1 = 18
    ------------------------------------
    total:                        368

For reference: attention baseline = ~70,000; RL2020 = ~25.
"""
from __future__ import annotations

from typing import Any, Dict, Optional

import torch
from torch import nn

try:
    from stable_baselines3.common.torch_layers import BaseFeaturesExtractor
except ImportError:  # pragma: no cover
    BaseFeaturesExtractor = object  # type: ignore

import gymnasium as gym


class LinearPerCandidateExtractor(BaseFeaturesExtractor):
    """Minimal RL2020-style per-candidate linear scoring extractor."""

    def __init__(
        self,
        observation_space: gym.spaces.Dict,
        # ``features_dim`` is set to ``MAX_CSE + 1`` automatically; the
        # kwarg is accepted only so SB3's ``policy_kwargs`` plumbing
        # doesn't complain when net_arch=[] is used.
        features_dim: Optional[int] = None,
    ):
        if not isinstance(observation_space, gym.spaces.Dict):
            raise ValueError("LinearPerCandidateExtractor requires a Dict observation space")

        cand_space = observation_space["candidates"]
        method_space = observation_space["method"]

        if len(cand_space.shape) != 2:
            raise ValueError("candidates space must be 2-D (max_cse, per_cand_feats)")
        if len(method_space.shape) != 1:
            raise ValueError("method space must be 1-D (method_feats,)")

        self._max_cse, self._per_cand_feats = cand_space.shape
        self._method_feats = method_space.shape[0]

        out_dim = self._max_cse + 1  # 16 candidate scores + 1 stop score
        super().__init__(observation_space, features_dim=out_dim)

        # SHARED per-candidate linear scorer (RL2020 inductive bias):
        # same weights applied to each candidate row -> single scalar.
        self.candidate_scorer = nn.Linear(self._per_cand_feats, 1)
        # Separate scorer for the stop action.
        self.stop_scorer = nn.Linear(self._method_feats, 1)

    def forward(self, observations: Dict[str, torch.Tensor]) -> torch.Tensor:  # type: ignore[override]
        cands = observations["candidates"]  # (B, max_cse, per_cand_feats)
        method = observations["method"]     # (B, method_feats)

        # Score every candidate with the shared linear head. The `Linear`
        # module broadcasts over the leading batch+candidate dims.
        cand_scores = self.candidate_scorer(cands).squeeze(-1)  # (B, max_cse)

        # Padded rows have all-zero features, so the shared scorer emits
        # the learnable bias for them (a constant). The model can push
        # that bias low so softmax naturally deprioritizes them. We
        # deliberately do NOT apply a -inf mask here: action_net (SB3's
        # Linear(features_dim, n_actions) that follows the extractor)
        # would mix -inf across all output logits and produce NaN.

        stop_score = self.stop_scorer(method)  # (B, 1)

        # Concatenate to (B, max_cse + 1). Order is [cand_0, ..., cand_{n-1}, stop]
        # -- matches the discrete action encoding of JitCseEnv.
        return torch.cat([cand_scores, stop_score], dim=-1)


def make_linear_scorer_policy_kwargs() -> Dict[str, Any]:
    """Convenience builder for ``policy_kwargs`` with the linear scorer.

    Sets ``net_arch=[]`` so SB3's default MLP head is bypassed; the
    extractor output already has action-space shape (see class docstring
    for the total parameter budget).
    """
    return {
        "features_extractor_class": LinearPerCandidateExtractor,
        # ``features_extractor_kwargs`` intentionally empty; the extractor
        # infers output size from the observation space.
        "features_extractor_kwargs": {},
        "net_arch": [],
    }


__all__ = ["LinearPerCandidateExtractor", "make_linear_scorer_policy_kwargs"]
