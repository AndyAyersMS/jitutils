"""Tests for the observation / reward wrappers."""
# pylint: disable=protected-access

import os
import sys

import gymnasium as gym
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from jitml.jit_cse import FEATURES  # noqa: E402
from jitml.constants import MAX_CSE  # noqa: E402
from jitml.wrappers import NormalizeFeaturesWrapper  # noqa: E402


class _FakeEnv(gym.Env):
    """Minimal env stub exposing the fields NormalizeFeaturesWrapper touches."""

    def __init__(self):
        super().__init__()
        # Match JitCseEnv's real observation_columns layout so the
        # log1p mask calculation lands on the same slots it would in
        # production.
        from jitml.method_context import JitType
        self.observation_columns = [f"type_{JitType(i).name.lower()}" for i in range(1, 7)] + [
            "can_apply", "live_across_call", "const", "shared_const",
            "make_cse", "has_call", "containable",
            "cost_ex", "cost_sz", "use_count", "def_count",
            "use_wt_cnt_x100", "def_wt_cnt_x100",
            "distinct_locals", "local_occurrences",
            "enreg_count_int", "enreg_count_float", "enreg_count_simd", "enreg_count_msk",
        ]
        assert len(self.observation_columns) == FEATURES, \
            f"columns={len(self.observation_columns)} vs FEATURES={FEATURES}"
        self.observation_space = gym.spaces.Box(
            low=np.zeros((MAX_CSE, FEATURES), dtype=np.float32),
            high=np.ones((MAX_CSE, FEATURES), dtype=np.float32),
            dtype=np.float32,
        )
        self.action_space = gym.spaces.Discrete(MAX_CSE + 1)


def test_normalizer_preserves_shape_and_dtype():
    env = _FakeEnv()
    wrapped = NormalizeFeaturesWrapper(env)
    assert wrapped.observation_space.shape == (MAX_CSE, FEATURES)
    assert wrapped.observation_space.dtype == np.float32


def test_normalizer_leaves_booleans_and_onehot_alone():
    env = _FakeEnv()
    wrapped = NormalizeFeaturesWrapper(env)

    obs = np.zeros((MAX_CSE, FEATURES), dtype=np.float32)
    # First 6 are the one-hot type, next 7 are booleans. Set them all to 1.
    obs[:, :13] = 1.0
    # Set a count-like feature (cost_ex, index 13) to a big value.
    obs[:, 13] = 1000.0

    out = wrapped.observation(obs)

    # One-hot and boolean columns are unchanged.
    assert np.all(out[:, :13] == 1.0)
    # log1p(1000) ~= 6.908755
    assert np.allclose(out[:, 13], np.log1p(1000.0), atol=1e-4)


def test_normalizer_compresses_large_counts():
    env = _FakeEnv()
    wrapped = NormalizeFeaturesWrapper(env)

    obs = np.zeros((MAX_CSE, FEATURES), dtype=np.float32)
    # Populate all count-like features with a mix of small and huge values.
    obs[0, 13:] = 1.0
    obs[1, 13:] = 10.0
    obs[2, 13:] = 1e5

    out = wrapped.observation(obs)

    # log1p compresses each row into a small range: log1p(1e5) ~= 11.5.
    assert np.all(np.isfinite(out))
    assert np.all(out[:, 13:] <= 20.0)  # matches the widened box upper bound
    # log1p is monotone.
    assert (out[0, 13] < out[1, 13] < out[2, 13])


def test_normalizer_handles_negative_values_gracefully():
    """A pathological -1 (never produced by the JIT today, but robust
    to future feature additions) is clamped to 0 before log1p."""
    env = _FakeEnv()
    wrapped = NormalizeFeaturesWrapper(env)

    obs = np.zeros((MAX_CSE, FEATURES), dtype=np.float32)
    obs[0, 13] = -1.0
    out = wrapped.observation(obs)
    # Should be log1p(0) == 0, not NaN.
    assert out[0, 13] == 0.0
    assert np.all(np.isfinite(out))


def test_curriculum_buckets():
    """Verify ``curriculum_buckets`` partitions methods by candidate count."""
    from jitml.constants import curriculum_buckets, MIN_CSE
    from jitml.method_context import MethodContext

    def make(index: int, num_cand: int) -> MethodContext:
        # Enough viable candidates to pass is_acceptable_for_cse.
        from jitml.method_context import CseCandidate, JitType
        cands = [
            CseCandidate(
                index=i,
                viable=True,
                live_across_call=False,
                const=False,
                shared_const=False,
                make_cse=False,
                has_call=False,
                containable=False,
                type=JitType.INT.value,
                cost_ex=1, cost_sz=1,
                use_count=1, def_count=1,
                use_wt_cnt_x100=100, def_wt_cnt_x100=100,
                distinct_locals=1, local_occurrences=1,
                bb_count=1, block_spread=0,
                enreg_count_int=1, enreg_count_float=0,
                enreg_count_simd=0, enreg_count_msk=0,
            )
            for i in range(num_cand)
        ]
        return MethodContext(index=index, name=f"m{index}", hash=f"{index:x}",
                             total_bytes=0, prolog_size=0, instruction_count=0,
                             perf_score=1.0, bytes_allocated=0, num_cse=0,
                             num_cse_candidate=num_cand, cse_candidates=cands)

    # Skip candidate counts below MIN_CSE (=3) — those get filtered out.
    methods = [make(i, i) for i in range(MIN_CSE, 17)]  # counts 3..16
    tiers = curriculum_buckets(methods)
    assert len(tiers) == 4
    # thresholds default is (3, 6, 10, 16): tier 0 = 1..3, tier 1 = 4..6,
    # tier 2 = 7..10, tier 3 = 11..16.
    assert [m.num_cse_candidate for m in tiers[0]] == [3]
    assert [m.num_cse_candidate for m in tiers[1]] == [4, 5, 6]
    assert [m.num_cse_candidate for m in tiers[2]] == [7, 8, 9, 10]
    assert [m.num_cse_candidate for m in tiers[3]] == [11, 12, 13, 14, 15, 16]
