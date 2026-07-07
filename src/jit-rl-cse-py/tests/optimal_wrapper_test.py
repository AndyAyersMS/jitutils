"""Unit tests for OptimalCseWrapper's reward-shaping logic.

Phase-2 of the beat-baseline campaign uses this wrapper for the first
real integration test. These unit tests exercise the reward paths in
isolation (no real SPMI) so a bug in the ``_get_reward`` state machine
would be caught here rather than at 19:45 tonight.
"""
# pylint: disable=protected-access

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from jitml.method_context import CseCandidate, JitType, MethodContext  # noqa: E402
from jitml.wrappers import OptimalCseWrapper, OPTIMAL_BONUS, SUBOPTIMAL_PENALTY, NEUTRAL_PENALTY  # noqa: E402


def _cand(idx: int, viable: bool = True, applied: bool = False) -> CseCandidate:
    return CseCandidate(
        index=idx, applied=applied, viable=viable,
        live_across_call=False, const=False, shared_const=False, make_cse=False,
        has_call=False, containable=False, type=JitType.INT.value,
        cost_ex=1, cost_sz=1, use_count=1, def_count=1,
        use_wt_cnt_x100=100, def_wt_cnt_x100=100,
        distinct_locals=1, local_occurrences=1,
        bb_count=1, block_spread=0,
        enreg_count_int=1, enreg_count_float=0,
        enreg_count_simd=0, enreg_count_msk=0,
    )


def _method(name: str, perf_score: float, num_cand: int = 3,
            cses_chosen=None) -> MethodContext:
    return MethodContext(
        index=1, name=name, hash="abc",
        total_bytes=0, prolog_size=0, instruction_count=0,
        perf_score=perf_score, bytes_allocated=0,
        num_cse=len(cses_chosen or []), num_cse_candidate=num_cand,
        cses_chosen=list(cses_chosen or []),
        cse_candidates=[_cand(i) for i in range(num_cand)],
    )


class _MockSuperPmi:
    """Returns preset per-decision perf_scores for _get_all_cses probes."""

    def __init__(self, alt_scores):
        # alt_scores: dict of frozenset(decisions) -> perf_score
        self._alt_scores = alt_scores
        self.calls = []

    def jit_method(self, m_id, **kwargs):
        decisions = tuple(kwargs.get("JitRLHookCSEDecisions", []))
        self.calls.append((m_id, decisions))
        score = self._alt_scores.get(frozenset(decisions), None)
        if score is None:
            return None
        return _method(name=f"m{m_id}", perf_score=score,
                       cses_chosen=list(decisions))


def _make_wrapper(mock_pmi):
    w = OptimalCseWrapper.__new__(OptimalCseWrapper)
    w.superpmi = mock_pmi
    return w


def test_reward_passthrough_when_truncated():
    w = _make_wrapper(_MockSuperPmi({}))
    info = {"truncated": True, "action_is_valid": True}
    assert w._get_reward(0.42, info) == 0.42


def test_reward_passthrough_when_invalid_action():
    w = _make_wrapper(_MockSuperPmi({}))
    info = {"truncated": False, "action_is_valid": False}
    assert w._get_reward(0.42, info) == 0.42


def test_stop_no_penalty_when_no_alternative_improves():
    """Model chose to STOP (action=None). If none of the remaining
    applicable CSEs would improve the perf score, no penalty."""
    previous = _method("prev", perf_score=100.0)
    # All alternatives are equal or worse than previous (100.0)
    mock = _MockSuperPmi({
        frozenset([0]): 100.0,
        frozenset([1]): 100.5,
        frozenset([2]): 101.0,
    })
    w = _make_wrapper(mock)
    info = {"truncated": False, "action_is_valid": True, "action": None,
            "method_index": 1, "previous": previous, "current": previous}
    reward = w._get_reward(0.0, info)
    assert reward == 0.0, f"expected 0 penalty, got {reward}"


def test_stop_penalty_when_better_alternative_exists():
    """Model chose to STOP, but there was a better CSE it could have picked."""
    previous = _method("prev", perf_score=100.0)
    mock = _MockSuperPmi({
        frozenset([0]): 100.0,
        frozenset([1]): 95.0,  # 5% improvement missed
        frozenset([2]): 100.5,
    })
    w = _make_wrapper(mock)
    info = {"truncated": False, "action_is_valid": True, "action": None,
            "method_index": 1, "previous": previous, "current": previous}
    reward = w._get_reward(0.0, info)
    assert reward == SUBOPTIMAL_PENALTY, f"expected penalty {SUBOPTIMAL_PENALTY}, got {reward}"


def test_apply_neutral_penalty_when_perf_unchanged():
    """Model applied a CSE but perf_score didn't change."""
    previous = _method("prev", perf_score=100.0)
    current = _method("curr", perf_score=100.0, cses_chosen=[0])
    w = _make_wrapper(_MockSuperPmi({}))
    info = {"truncated": False, "action_is_valid": True, "action": 0,
            "method_index": 1, "previous": previous, "current": current}
    reward = w._get_reward(0.0, info)
    assert reward == NEUTRAL_PENALTY, f"expected NEUTRAL_PENALTY, got {reward}"


def test_apply_optimal_bonus_when_best_of_alternatives():
    """Model applied CSE #1 and improved to 90.0; alternatives (CSE #0, #2)
    would have produced 95 / 92. Model picked the best -> bonus."""
    previous = _method("prev", perf_score=100.0)
    current = _method("curr", perf_score=90.0, cses_chosen=[1])
    mock = _MockSuperPmi({
        frozenset([0]): 95.0,
        frozenset([2]): 92.0,
    })
    w = _make_wrapper(mock)
    info = {"truncated": False, "action_is_valid": True, "action": 1,
            "method_index": 1, "previous": previous, "current": current}
    reward = w._get_reward(0.0, info)
    assert reward == OPTIMAL_BONUS, f"expected OPTIMAL_BONUS, got {reward}"


def test_apply_no_bonus_when_a_better_alternative_existed():
    """Model applied CSE #1 -> 92.0; but CSE #0 -> 85.0 would have been better."""
    previous = _method("prev", perf_score=100.0)
    current = _method("curr", perf_score=92.0, cses_chosen=[1])
    mock = _MockSuperPmi({
        frozenset([0]): 85.0,   # much better
        frozenset([2]): 95.0,
    })
    w = _make_wrapper(mock)
    info = {"truncated": False, "action_is_valid": True, "action": 1,
            "method_index": 1, "previous": previous, "current": current}
    reward = w._get_reward(0.0, info)
    assert reward == 0.0, f"expected no bonus, got {reward}"


def test_get_all_cses_skips_selected_and_already_applied():
    """_get_all_cses should skip the just-selected candidate and any
    already-applied ones."""
    prev = _method("prev", perf_score=100.0, num_cand=4, cses_chosen=[2])
    prev.cse_candidates[2].applied = True  # already applied
    mock = _MockSuperPmi({
        frozenset([2, 0]): 90.0,
        frozenset([2, 1]): 95.0,
        frozenset([2, 3]): 92.0,
    })
    w = _make_wrapper(mock)
    # We just selected CSE #1; the wrapper should probe #0 and #3 but not #1 or #2.
    results = w._get_all_cses(m_idx=1, previous=prev, selected=1)

    probed_decisions = [c[1] for c in mock.calls]
    # Expect probes with decision sets (2,0) and (2,3), NOT (2,1) or (2,2).
    assert (2, 0) in probed_decisions or frozenset([2, 0]) in [frozenset(d) for d in probed_decisions]
    assert (2, 3) in probed_decisions or frozenset([2, 3]) in [frozenset(d) for d in probed_decisions]
    # None of the calls should include index 1 (the just-selected) or index 2 (already applied,
    # can_apply=False)
    for _, d in mock.calls:
        assert 1 not in d[-1:], "should not probe the just-selected CSE"
    # 3 results (one per probed decision)
    assert len(results) == 2


def test_get_all_cses_drops_none_results():
    """If jit_method returns None for some alternative (JIT failed on that
    combination), _get_all_cses should silently drop it."""
    prev = _method("prev", perf_score=100.0, num_cand=3)
    mock = _MockSuperPmi({
        frozenset([0]): 90.0,
        # frozenset([1]) intentionally missing -> mock returns None
        frozenset([2]): 92.0,
    })
    w = _make_wrapper(mock)
    results = w._get_all_cses(m_idx=1, previous=prev, selected=None)
    assert len(results) == 2, f"expected 2 (dropped the None), got {len(results)}"
    scores = sorted(r.perf_score for r in results)
    assert scores == [90.0, 92.0]
