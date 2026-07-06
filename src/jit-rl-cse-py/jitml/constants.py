"""Constants and parameters for the project."""

from typing import Sequence

import numpy as np
from .method_context import MethodContext

MIN_CSE = 3
MAX_CSE = 16

INVALID_ACTION_PENALTY = -0.05
INVALID_ACTION_LIMIT = 20

CSE_SUCCESS_THRESHOLD = -5.0

def is_acceptable_for_cse(method):
    """Returns True if the method is acceptable for training on JitCseEnv."""
    applicable = len([x for x in method.cse_candidates if x.viable])
    return MIN_CSE <= applicable and len(method.cse_candidates) <= MAX_CSE

def split_for_cse(methods : Sequence[MethodContext], test_percent=0.1, seed=42):
    """Splits the methods into those that can be used for training and those that can't.
    Returns the test and train sets.

    ``seed`` is threaded through to the numpy RNG so callers can pin the
    split deterministically to a chosen seed (default 42, matching
    historical behaviour).
    """
    method_by_cse = {}

    for x in methods:
        if is_acceptable_for_cse(x):
            method_by_cse.setdefault(x.num_cse, []).append(x)

    # convert method_by_cse to a list of methods
    methods_list = []
    for value in method_by_cse.values():
        methods_list.append(value)

    test = []
    train = []

    # Sort the groups of methods by length to ensure we don't care what order we process them in.
    # Then sort each method by id before shuffling to (again) ensure we get the same result.
    methods_list.sort(key=len)
    rnd = np.random.default_rng(seed=seed)
    for method_group in methods_list:
        split = int(len(method_group) * test_percent)

        # Discard any groups that are too small to split.
        if split > 0:
            method_group.sort(key=lambda x: x.index)
            rnd.shuffle(method_group)
            test.extend(method_group[:split])
            train.extend(method_group[split:])

    return test, train


def curriculum_buckets(methods: Sequence[MethodContext],
                       thresholds: Sequence[int] = (3, 6, 10, 16)) -> list:
    """Partition ``methods`` into curriculum tiers by candidate count.

    Returns a list of method-context lists, one per tier. ``thresholds``
    defines the (exclusive) upper bound on ``num_cse_candidate`` for
    each tier: with the default ``(3, 6, 10, 16)`` the returned tiers
    contain methods with 1-3, 4-6, 7-10 and 11-16 candidates respectively.

    Training callers can consume tiers in order (easy first) to
    implement a simple curriculum: warm the policy up on low-candidate
    methods, then progressively include harder ones. Methods below the
    ``is_acceptable_for_cse`` gate are skipped.
    """
    tiers: list = [[] for _ in thresholds]
    ordered = sorted(thresholds)

    for m in methods:
        if not is_acceptable_for_cse(m):
            continue
        n = m.num_cse_candidate
        for i, upper in enumerate(ordered):
            if n <= upper:
                tiers[i].append(m)
                break

    return tiers
