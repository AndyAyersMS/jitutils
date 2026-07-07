"""Unit test for LogCallback._update_stats sign-convention.

Regression test for a copy-paste bug at machine_learning.py:242 that
made ``results/better_than_heuristic`` never emit -1 for losses (both
ternary branches checked ``final < heuristic``). The metric was a
[0,1] win-fraction rather than the intended signed [-1, +1] balance.
Fixed 2026-07-06.
"""
# pylint: disable=protected-access

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

torch = pytest.importorskip("torch")
sb3 = pytest.importorskip("stable_baselines3")


class _FakeMethod:
    def __init__(self, cses_chosen):
        self.cses_chosen = cses_chosen


def _make_stats():
    """Build a bare LogCallback for _update_stats testing (no SB3 wiring)."""
    from jitml.machine_learning import LogCallback
    cb = LogCallback.__new__(LogCallback)
    cb._rewards = []
    cb._invalid_choices = []
    cb._result_vs_heuristic = []
    cb._result_vs_no_cse = []
    cb._better_or_worse = []
    cb._choice_count = []
    # Force ``self.locals`` interface used by _update_stats.
    cb.locals = {"infos": []}
    return cb


def _info(final, heuristic, no_cse=None, total_reward=0.0, cses=None):
    return {
        "final_score": final,
        "heuristic_score": heuristic,
        "no_cse_score": no_cse if no_cse is not None else heuristic * 1.1,
        "total_reward": total_reward,
        "current": _FakeMethod(cses_chosen=cses or []),
    }


def test_better_appends_positive_one():
    """Model beats heuristic (final < heuristic) → +1."""
    cb = _make_stats()
    cb.locals["infos"].append(_info(final=90.0, heuristic=100.0))
    cb._update_stats()
    assert cb._better_or_worse == [1]


def test_worse_appends_negative_one():
    """Model loses (final > heuristic) → -1. THIS IS THE REGRESSION CASE
    that was broken pre-fix: the buggy version returned 0 here."""
    cb = _make_stats()
    cb.locals["infos"].append(_info(final=110.0, heuristic=100.0))
    cb._update_stats()
    assert cb._better_or_worse == [-1]


def test_equal_appends_zero():
    """final == heuristic → 0."""
    cb = _make_stats()
    cb.locals["infos"].append(_info(final=100.0, heuristic=100.0))
    cb._update_stats()
    assert cb._better_or_worse == [0]


def test_mixed_batch_produces_signed_mean():
    """Batch with wins, losses, ties → mean is a signed balance in [-1,+1].
    Pre-fix, worse cases were counted as 0 so this mean would be biased upward."""
    cb = _make_stats()
    cb.locals["infos"].extend([
        _info(final=90.0, heuristic=100.0),   # +1 (win)
        _info(final=95.0, heuristic=100.0),   # +1 (win)
        _info(final=100.0, heuristic=100.0),  #  0 (tie)
        _info(final=110.0, heuristic=100.0),  # -1 (loss)
        _info(final=120.0, heuristic=100.0),  # -1 (loss)
    ])
    cb._update_stats()
    assert sum(cb._better_or_worse) == 0, "2 wins + 2 losses + 1 tie should sum to 0"
    assert len(cb._better_or_worse) == 5
    # Buggy pre-fix version would have appended [1, 1, 0, 0, 0] with sum=2.


def test_vs_heuristic_pct_delta_is_signed():
    """Sanity: the vs_heuristic metric uses (heuristic - final)/heuristic,
    so wins are positive and losses are negative. This one was correct
    even in the buggy version."""
    cb = _make_stats()
    cb.locals["infos"].append(_info(final=90.0, heuristic=100.0))   # +0.10
    cb.locals["infos"].append(_info(final=110.0, heuristic=100.0))  # -0.10
    cb._update_stats()
    assert cb._result_vs_heuristic[0] == pytest.approx(+0.10)
    assert cb._result_vs_heuristic[1] == pytest.approx(-0.10)
