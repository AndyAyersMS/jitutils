"""Tests for the observation / reward wrappers."""
# pylint: disable=protected-access

import os
import sys

import gymnasium as gym
import numpy as np

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from jitml.jit_cse import (  # noqa: E402
    FEATURES_PER_CANDIDATE,
    METHOD_LEVEL_FEATURES,
    JitCseEnv,
)
from jitml.constants import MAX_CSE  # noqa: E402
from jitml.wrappers import NormalizeFeaturesWrapper  # noqa: E402


class _FakeEnv(gym.Env):
    """Minimal env stub exposing the fields NormalizeFeaturesWrapper touches."""

    def __init__(self):
        super().__init__()
        # Mirror JitCseEnv's schema exactly so the log1p mask lands
        # on the same slots it would in production.
        self.per_candidate_columns = list(JitCseEnv.per_candidate_columns)
        self.method_columns = list(JitCseEnv.method_columns)
        self.observation_columns = self.per_candidate_columns + self.method_columns
        self.observation_space = gym.spaces.Dict({
            "candidates": gym.spaces.Box(
                low=np.zeros((MAX_CSE, FEATURES_PER_CANDIDATE), dtype=np.float32),
                high=np.ones((MAX_CSE, FEATURES_PER_CANDIDATE), dtype=np.float32),
                dtype=np.float32,
            ),
            "method": gym.spaces.Box(
                low=np.zeros((METHOD_LEVEL_FEATURES,), dtype=np.float32),
                high=np.ones((METHOD_LEVEL_FEATURES,), dtype=np.float32),
                dtype=np.float32,
            ),
        })
        self.action_space = gym.spaces.Discrete(MAX_CSE + 1)


def _blank_obs():
    return {
        "candidates": np.zeros((MAX_CSE, FEATURES_PER_CANDIDATE), dtype=np.float32),
        "method":     np.zeros(METHOD_LEVEL_FEATURES, dtype=np.float32),
    }


def test_normalizer_preserves_shapes_and_dtypes():
    env = _FakeEnv()
    wrapped = NormalizeFeaturesWrapper(env)
    assert isinstance(wrapped.observation_space, gym.spaces.Dict)
    cand = wrapped.observation_space.spaces["candidates"]
    method = wrapped.observation_space.spaces["method"]
    assert cand.shape == (MAX_CSE, FEATURES_PER_CANDIDATE)
    assert method.shape == (METHOD_LEVEL_FEATURES,)
    assert cand.dtype == np.float32
    assert method.dtype == np.float32


def test_normalizer_leaves_booleans_and_onehot_alone():
    env = _FakeEnv()
    wrapped = NormalizeFeaturesWrapper(env)

    obs = _blank_obs()
    # First 6 are one-hot type, next 7 are booleans (columns 0..12).
    obs["candidates"][:, :13] = 1.0
    # Set a count-like feature (cost_ex, index 13) to a big value.
    obs["candidates"][:, 13] = 1000.0

    out = wrapped.observation(obs)
    assert np.all(out["candidates"][:, :13] == 1.0)
    assert np.allclose(out["candidates"][:, 13], np.log1p(1000.0), atol=1e-4)


def test_normalizer_compresses_large_counts_in_both_channels():
    env = _FakeEnv()
    wrapped = NormalizeFeaturesWrapper(env)

    obs = _blank_obs()
    # Populate all count-like candidate features with a mix of small and huge values.
    obs["candidates"][0, 13:] = 1.0
    obs["candidates"][1, 13:] = 10.0
    obs["candidates"][2, 13:] = 1e5
    # And the method-level features.
    obs["method"][:] = [1.0, 10.0, 100.0, 1000.0, 10000.0]

    out = wrapped.observation(obs)
    assert np.all(np.isfinite(out["candidates"]))
    assert np.all(np.isfinite(out["method"]))
    assert np.all(out["candidates"][:, 13:] <= 20.0)
    assert np.all(out["method"] <= 20.0)
    # log1p is monotone.
    assert (out["candidates"][0, 13] < out["candidates"][1, 13] < out["candidates"][2, 13])
    for i in range(len(out["method"]) - 1):
        assert out["method"][i] < out["method"][i + 1]


def test_normalizer_handles_negative_values_gracefully():
    """A pathological -1 (never produced by the JIT today, but robust
    to future feature additions) is clamped to 0 before log1p."""
    env = _FakeEnv()
    wrapped = NormalizeFeaturesWrapper(env)

    obs = _blank_obs()
    obs["candidates"][0, 13] = -1.0
    obs["method"][0] = -1.0
    out = wrapped.observation(obs)
    # Should be log1p(0) == 0, not NaN.
    assert out["candidates"][0, 13] == 0.0
    assert out["method"][0] == 0.0
    assert np.all(np.isfinite(out["candidates"]))
    assert np.all(np.isfinite(out["method"]))


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


def test_get_observation_produces_dict_with_correct_shapes():
    """JitCseEnv.get_observation returns a dict with candidates + method
    channels correctly shaped and with the method-level features pulled
    from the first candidate."""
    from jitml.method_context import CseCandidate, JitType, MethodContext

    def cand(idx: int, bb=42, ei=7, ef=3, es=1, em=0) -> CseCandidate:
        return CseCandidate(
            index=idx, viable=True, live_across_call=False, const=False,
            shared_const=False, make_cse=False, has_call=False,
            containable=False, type=JitType.INT.value,
            cost_ex=5, cost_sz=3, use_count=2, def_count=1,
            use_wt_cnt_x100=250, def_wt_cnt_x100=100,
            distinct_locals=4, local_occurrences=6,
            bb_count=bb, block_spread=2,
            enreg_count_int=ei, enreg_count_float=ef,
            enreg_count_simd=es, enreg_count_msk=em,
        )

    method = MethodContext(index=1, name="m", hash="a", total_bytes=0,
                           prolog_size=0, instruction_count=0, perf_score=1.0,
                           bytes_allocated=0, num_cse=0, num_cse_candidate=3,
                           cse_candidates=[cand(0), cand(1), cand(2)])
    obs = JitCseEnv.get_observation(method)
    assert set(obs.keys()) == {"candidates", "method"}
    assert obs["candidates"].shape == (MAX_CSE, FEATURES_PER_CANDIDATE)
    assert obs["method"].shape == (METHOD_LEVEL_FEATURES,)
    assert obs["candidates"].dtype == np.float32
    # Method-level features come from the first candidate.
    np.testing.assert_array_equal(
        obs["method"],
        np.array([42, 7, 3, 1, 0], dtype=np.float32),
    )
