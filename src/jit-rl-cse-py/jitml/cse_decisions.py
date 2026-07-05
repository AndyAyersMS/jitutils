"""This builds a DataFrame from the SuperPmi data for individual CSE decisions.  Essentially we will JIT every possible
CSE decision and compare the performance of the JITted code to the original JITted code.  We will then build a
DataFrame with this data.

The DataFrame will have the following columns:
- method: The method index.
- cse_index: The CSE index.
- no_cse_score: The performance score of the method without CSE.
- heuristic_score: The performance score of the method with the current CSE's chosen by heuristic.
- cse_score: The performance score of the method with only the current CSE applied.
- heuristic_selected: True if the heuristic selected this CSE.
- All CseCandidate fields.
"""

import os
from typing import Dict, List

import numpy as np
from pandas import DataFrame, read_csv
import pandas as pd
from tqdm import tqdm

from .superpmi import SuperPmiCache, SuperPmi, MethodKind
from .method_context import CseCandidate, JitType, MethodContext
from .constants import CSE_SUCCESS_THRESHOLD

def update_data(data : Dict[str, List[object]], no_cse_method : MethodContext, heuristic_method : MethodContext,
               cse_candidate : CseCandidate, selected, perf_score : float, diff : float):
    """Builds the data dictionary for a dataframe."""

    assert no_cse_method.index == heuristic_method.index
    data.setdefault("method", []).append(no_cse_method.index)
    data.setdefault("cse_index", []).append(cse_candidate.index)
    data.setdefault("no_cse_score", []).append(no_cse_method.perf_score)
    data.setdefault("heuristic_score", []).append(heuristic_method.perf_score)
    data.setdefault("cse_score", []).append(perf_score)
    data.setdefault("heuristic_selected", []).append(cse_candidate.index - 1 in heuristic_method.cses_chosen)
    data.setdefault("selected", []).append(selected.copy())
    data.setdefault("diff", []).append(diff)
    for key, value in cse_candidate.model_dump().items():
        if key == "type":
            value = JitType(value)

        data.setdefault(key, []).append(value)

def single_to_dataframe(mch, core_root) -> DataFrame:
    """Converts single CSE SuperPmi data to a DataFrame."""
    applied = {}

    cache = SuperPmiCache(mch, core_root)
    with SuperPmi(mch, core_root) as superpmi:
        cse_perfscores = cache.get_cse_perfscores(superpmi)

        # applicable
        for method, scores in cse_perfscores.items():
            method = int(method)
            no_cse_method = cache.jit_method(superpmi, method, MethodKind.NO_CSE)
            heuristic_method = cache.jit_method(superpmi, method, MethodKind.HEURISTIC)
            if not no_cse_method or not heuristic_method:
                print(f"Skipping {method} due to missing methods.")
                continue

            for i, score in enumerate(scores):
                cse_candidate = no_cse_method.cse_candidates[i]
                if cse_candidate.viable:
                    if score is not None:
                        update_data(applied, no_cse_method, heuristic_method, cse_candidate, [cse_candidate.index],
                                    score, score - no_cse_method.perf_score)

    return DataFrame.from_dict(applied)

def _get_cse_count(perfscores : List[float | None]):
    return sum(1 for x in perfscores if x is not None)

def multi_to_dataframe(mch, core_root, filename) -> DataFrame:
    """Generates a dataset of multiple CSE chocies per method."""
    # pylint: disable=too-many-locals
    multi = {}
    partials = []

    cache = SuperPmiCache(mch, core_root)
    with SuperPmi(mch, core_root) as superpmi:
        cse_perfscores = cache.get_cse_perfscores(superpmi)

        # applicable

        total = sum(_get_cse_count(x) for x in cse_perfscores.values())
        progress = tqdm(cse_perfscores.items(), desc="Processing multi CSEs", smoothing=0, total=total)
        for method, scores in progress:
            method = int(method)
            no_cse_method = cache.jit_method(superpmi, method, MethodKind.NO_CSE)
            heuristic_method = cache.jit_method(superpmi, method, MethodKind.HEURISTIC)
            if not no_cse_method or not heuristic_method:
                print(f"Skipping {method} due to missing methods.")
                continue

            _apply_cses(multi, cache, superpmi, no_cse_method, heuristic_method, scores)
            progress.update(_get_cse_count(scores))

            if 'method' in multi and len(multi['method']) > 250_000:
                partial_name = f"{filename}.partial.{len(partials)}.csv"
                partials.append(partial_name)

                df = DataFrame.from_dict(multi)
                df.to_csv(partial_name)

                multi = {}

                print()
                print(f"Saved to: {partial_name}")

        progress.close()

    frames = []
    if partials:
        for partial_name in partials:
            frames.append(read_csv(partial_name, index_col=0))

    frames.append(DataFrame.from_dict(multi))
    return pd.concat(frames)

def _apply_cses(data, cache, superpmi, no_cse_method, heuristic_method, scores):
    # Recursively dive into each CSE which is viable and has a perf_score below the threshold.
    # This will not recurse infinitely since there's a maximum of 64 CSEs per method.  We also
    # will not hit factorial growth since we are only recursing for 'remaining' CSEs.  We will
    # still apply other CSEs as we go, but not all the way down.  That's (n * (n-1)) growth instead
    # of n! growth.
    def update_func(prev_method, method, candidate, selected):
        candidate = method.cse_candidates[selected[-1]]
        diff = method.perf_score - prev_method.perf_score
        update_data(data, no_cse_method, heuristic_method, candidate, selected, method.perf_score, diff)

    selected = []
    viable = [c for c in no_cse_method.cse_candidates if c.viable and scores[c.index] is not None]
    successful = [c.index for c in viable if scores[c.index] - no_cse_method.perf_score < CSE_SUCCESS_THRESHOLD]

    np.random.shuffle(successful)
    while successful:
        selected.append(successful.pop())
        _apply_sub_cses(selected, successful, cache, superpmi, no_cse_method, update_func)

    unsuccessful = [c.index for c in viable if c.index not in successful]
    for c in unsuccessful:
        candidate = no_cse_method.cse_candidates[c]
        update_data(data, no_cse_method, heuristic_method, candidate, [c], scores[c],
                    scores[c] - no_cse_method.perf_score)

def _apply_sub_cses(applied : List[int], remaining : List[int], cache : SuperPmiCache, superpmi : SuperPmi,
                 prev_method : MethodContext, update_func):
    # Grab the method index
    method_index = prev_method.index

    # Despite the method/variable names, we are actually applying the CSE at the end of the applied list
    candidate = prev_method.cse_candidates[applied[-1]]

    # jit this method with the current CSE applied and see if it worked
    curr_method = cache.jit_method(superpmi, method_index, applied)
    if not curr_method:
        return

    # Store the data of this method
    update_func(prev_method, curr_method, candidate, applied)

    # 'remaining' is the order in which we are going to apply CSEs.  We will take a brief pause here to
    # NON RECURSIVELY apply up to 5 CSEs in 'remaining' to the current method.  This will allow us to see
    # how the performance of the method changes with each CSE applied without running into factorial growth.
    if len(remaining) > 1:
        to_apply = np.random.choice(remaining[:-1], min(5, len(remaining) - 1), replace=False)
        for r in to_apply:
            # temporarily apply the CSE
            applied.append(r)

            # be careful to use the curr_method's cse_candidates, not the prev_method's.
            candidate = curr_method.cse_candidates[r]
            method = cache.jit_method(superpmi, method_index, applied)
            if method:
                update_func(curr_method, method, candidate, applied)

            # undo the CSE here, we will apply it again deeper in the recursion
            applied.pop()

    if remaining:
        applied.append(remaining.pop())
        _apply_sub_cses(applied, remaining, cache, superpmi, curr_method, update_func)
        remaining.append(applied.pop())

def get_individual_cse_perf(mch, core_root) -> DataFrame:
    """Gets or creates the DataFrame for the given mch file."""
    filename = f"{mch}.cse.single.csv"
    if os.path.exists(filename):
        return read_csv(filename, index_col=0)

    df = single_to_dataframe(mch, core_root)
    df.to_csv(filename)
    return df

def get_multi_cse_perf(mch, core_root) -> DataFrame:
    """Gets or creates the DataFrame for the given mch file."""
    filename = f"{mch}.cse.multi.csv"
    if os.path.exists(filename):
        return read_csv(filename, index_col=0)

    df = multi_to_dataframe(mch, core_root, filename)
    df.to_csv(filename)
    return df

__all__ = [get_individual_cse_perf.__name__, get_multi_cse_perf.__name__]
