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
    PER_CANDIDATE_SCHEMA,
    METHOD_SCHEMA,
    FEATURE_KIND_BOOL,
    FEATURE_KIND_ONEHOT,
    FEATURE_KIND_COUNT,
)
from jitml.constants import MAX_CSE  # noqa: E402
from jitml.wrappers import NormalizeFeaturesWrapper  # noqa: E402


# Precompute the column indices per category so tests are robust to
# future schema additions.
def _idx_where(schema, kinds):
    return [i for i, (_n, k) in enumerate(schema) if k in kinds]


CAND_NONCOUNT_IDX = _idx_where(PER_CANDIDATE_SCHEMA, (FEATURE_KIND_BOOL, FEATURE_KIND_ONEHOT))
CAND_COUNT_IDX = _idx_where(PER_CANDIDATE_SCHEMA, (FEATURE_KIND_COUNT,))
METHOD_COUNT_IDX = _idx_where(METHOD_SCHEMA, (FEATURE_KIND_COUNT,))


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
    # Set every non-count column (one-hot + booleans) to 1.0; the first
    # count column gets a big value to check log1p application.
    obs["candidates"][:, CAND_NONCOUNT_IDX] = 1.0
    first_count = CAND_COUNT_IDX[0]
    obs["candidates"][:, first_count] = 1000.0

    out = wrapped.observation(obs)
    assert np.all(out["candidates"][:, CAND_NONCOUNT_IDX] == 1.0)
    assert np.allclose(out["candidates"][:, first_count], np.log1p(1000.0), atol=1e-4)


def test_normalizer_compresses_large_counts_in_both_channels():
    env = _FakeEnv()
    wrapped = NormalizeFeaturesWrapper(env)

    obs = _blank_obs()
    # Populate all count-like candidate features with a mix of small and huge values.
    obs["candidates"][0, CAND_COUNT_IDX] = 1.0
    obs["candidates"][1, CAND_COUNT_IDX] = 10.0
    obs["candidates"][2, CAND_COUNT_IDX] = 1e5
    # And the method-level count features -- use an increasing series
    # so log1p produces a strictly-increasing output we can assert against.
    monotone_counts = np.logspace(0, len(METHOD_COUNT_IDX) - 1, num=len(METHOD_COUNT_IDX))
    obs["method"][METHOD_COUNT_IDX] = monotone_counts.astype(np.float32)

    out = wrapped.observation(obs)
    assert np.all(np.isfinite(out["candidates"]))
    assert np.all(np.isfinite(out["method"]))
    assert np.all(out["candidates"][:, CAND_COUNT_IDX] <= 20.0)
    assert np.all(out["method"][METHOD_COUNT_IDX] <= 20.0)
    # log1p is monotone: first count column should show strictly-increasing rows.
    first_count = CAND_COUNT_IDX[0]
    assert (out["candidates"][0, first_count]
            < out["candidates"][1, first_count]
            < out["candidates"][2, first_count])
    method_out = out["method"][METHOD_COUNT_IDX]
    for i in range(len(method_out) - 1):
        assert method_out[i] < method_out[i + 1]


def test_normalizer_handles_negative_values_gracefully():
    """A pathological -1 (never produced by the JIT today, but robust
    to future feature additions) is clamped to 0 before log1p."""
    env = _FakeEnv()
    wrapped = NormalizeFeaturesWrapper(env)

    obs = _blank_obs()
    first_count = CAND_COUNT_IDX[0]
    first_method_count = METHOD_COUNT_IDX[0]
    obs["candidates"][0, first_count] = -1.0
    obs["method"][first_method_count] = -1.0
    out = wrapped.observation(obs)
    # Should be log1p(0) == 0, not NaN.
    assert out["candidates"][0, first_count] == 0.0
    assert out["method"][first_method_count] == 0.0
    assert np.all(np.isfinite(out["candidates"]))
    assert np.all(np.isfinite(out["method"]))


def test_normalizer_scales_tier1_log_ratio_and_enum_features():
    """Tier-1 additions (``log_use_wt_x1000``, ``log_def_wt_x1000``,
    ``block_spread_x1000_per_bb``, ``code_opt_kind``) go through the
    non-log1p path: divide by 1000 (or by 2 for the small enum) to
    recover the raw log / ratio / bucket value."""
    from jitml.jit_cse import PER_CANDIDATE_SCHEMA, METHOD_SCHEMA

    def idx(schema, name):
        return next(i for i, (n, _k) in enumerate(schema) if n == name)

    log_use_i = idx(PER_CANDIDATE_SCHEMA, "log_use_wt_x1000")
    log_def_i = idx(PER_CANDIDATE_SCHEMA, "log_def_wt_x1000")
    bs_ratio_i = idx(PER_CANDIDATE_SCHEMA, "block_spread_x1000_per_bb")
    agg_i     = idx(METHOD_SCHEMA, "aggressive_ref_cnt_x1000")
    mod_i     = idx(METHOD_SCHEMA, "moderate_ref_cnt_x1000")
    lfr_i     = idx(METHOD_SCHEMA, "large_frame")
    hfr_i     = idx(METHOD_SCHEMA, "huge_frame")
    opt_i     = idx(METHOD_SCHEMA, "code_opt_kind")

    env = _FakeEnv()
    wrapped = NormalizeFeaturesWrapper(env)

    obs = _blank_obs()
    # Realistic JIT-emitted values (from the smoke run).
    obs["candidates"][0, log_use_i] = 12899.0     # log(400/1e-3) * 1000
    obs["candidates"][0, log_def_i] = 11513.0     # log(100/1e-3) * 1000
    obs["candidates"][0, bs_ratio_i] = 286.0      # 2/7 * 1000
    obs["method"][agg_i] = 50000.0                # aggressiveRefCnt * 1000
    obs["method"][mod_i] = 100000.0               # moderateRefCnt * 1000
    obs["method"][lfr_i] = 1.0                    # large_frame (bool)
    obs["method"][hfr_i] = 0.0                    # huge_frame (bool)
    obs["method"][opt_i] = 2.0                    # code_opt_kind = FAST_CODE

    out = wrapped.observation(obs)
    # log-x1000: divided by 1000 (no log1p), recover ~12.899, ~11.513.
    assert np.isclose(out["candidates"][0, log_use_i], 12.899, atol=1e-3)
    assert np.isclose(out["candidates"][0, log_def_i], 11.513, atol=1e-3)
    # ratio-x1000: divided by 1000, recover ~0.286.
    assert np.isclose(out["candidates"][0, bs_ratio_i], 0.286, atol=1e-3)
    # Method-level counts (agg/mod) do get log1p on top of a no-op /1.0
    # divide, since they're declared FEATURE_KIND_COUNT (not
    # LOG_X1000). Verify they're logged.
    assert np.isclose(out["method"][agg_i], np.log1p(50000.0), atol=1e-3)
    assert np.isclose(out["method"][mod_i], np.log1p(100000.0), atol=1e-3)
    # Bool method fields untouched.
    assert out["method"][lfr_i] == 1.0
    assert out["method"][hfr_i] == 0.0
    # Enum small: divide by 2, recover 1.0.
    assert np.isclose(out["method"][opt_i], 1.0, atol=1e-6)


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

    # Include candidate counts across the range [MIN_CSE..MAX_CSE-1]. With
    # MIN_CSE=1 and default thresholds (3, 6, 10, 16), tier 0 now captures
    # counts 1..3 (previously just 3 when MIN_CSE was 3).
    methods = [make(i, i) for i in range(MIN_CSE, 17)]  # counts MIN_CSE..16
    tiers = curriculum_buckets(methods)
    assert len(tiers) == 4
    # thresholds default is (3, 6, 10, 16): tier 0 = 1..3, tier 1 = 4..6,
    # tier 2 = 7..10, tier 3 = 11..16.
    assert [m.num_cse_candidate for m in tiers[0]] == [1, 2, 3]
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
                           cse_candidates=[cand(0), cand(1), cand(2)],
                           aggressive_ref_cnt_x1000=50000,
                           moderate_ref_cnt_x1000=100000,
                           large_frame=False, huge_frame=False,
                           code_opt_kind=0)
    obs = JitCseEnv.get_observation(method)
    assert set(obs.keys()) == {"candidates", "method"}
    assert obs["candidates"].shape == (MAX_CSE, FEATURES_PER_CANDIDATE)
    assert obs["method"].shape == (METHOD_LEVEL_FEATURES,)
    assert obs["candidates"].dtype == np.float32
    # Method-level features: [bb_count, enreg_int, enreg_flt, enreg_simd,
    # enreg_msk, aggressive_ref_cnt_x1000, moderate_ref_cnt_x1000,
    # large_frame, huge_frame, code_opt_kind, add_cse_count,
    # spill_at_weight_x1000].
    np.testing.assert_array_equal(
        obs["method"],
        np.array([42, 7, 3, 1, 0, 50000, 100000, 0, 0, 0, 0, 0], dtype=np.float32),
    )
