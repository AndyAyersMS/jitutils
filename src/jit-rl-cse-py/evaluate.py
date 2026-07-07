#!/usr/bin/python

"""Evaluates a trained CSE model against the default JIT heuristic.

Produces a per-method CSV with perf-score deltas plus passive metrics
(code size, instruction count, prolog size) and prints an aggregate
summary showing how often the learned policy improves on the built-in
heuristic and by how much (arithmetic mean + geometric mean of the
relative perf-score delta).

Usage:
    python evaluate.py <model_path_or_dir> <mch> \\
        --core_root <PATH> [--algorithm PPO|A2C|DQN] \\
        [--test-seed 42] [--test-only] [--limit N]

If ``model_path_or_dir`` is a directory, every ``*.zip`` model inside
is evaluated in newest-first order.
"""
from __future__ import annotations

import argparse
import math
import os
import shutil
import sys
from dataclasses import dataclass
from typing import Iterable, List, Optional

import numpy as np
import pandas as pd
import tqdm

from jitml import JitCseEnv, JitCseModel, MethodContext, SuperPmi, SuperPmiCache
from jitml.superpmi import MethodKind
from train import validate_core_root

# ---------------------------------------------------------------------------
# Model rollout
# ---------------------------------------------------------------------------

@dataclass
class RolloutRow:
    """One CSV row for a single evaluated method."""
    method_id: int
    name: str
    method_hash: str
    num_candidates: int
    chosen_cses: List[int]
    heuristic_perfscore: float
    rl_perfscore: float
    no_cse_perfscore: float
    delta_vs_heuristic: float             # rl - heuristic (negative = better)
    pct_delta_vs_heuristic: float         # (rl - heuristic) / heuristic
    heuristic_total_bytes: int
    rl_total_bytes: int
    heuristic_instr_count: int
    rl_instr_count: int
    heuristic_prolog_size: int
    rl_prolog_size: int
    status: str                           # "ok", "jit_failed", "no_candidates"
    # Optional RL2020 baseline (populated only when --include-rl2020 is set;
    # NaN otherwise). RL2020 = CSE_HeuristicParameterized with
    # s_defaultParameters -- the 2020-trained JIT-internal RL model.
    rl2020_perfscore: float = float("nan")
    pct_delta_vs_rl2020: float = float("nan")


def _greedy_action(jitrl: JitCseModel, method: MethodContext, can_terminate: bool) -> Optional[int]:
    """Deterministically pick the most-likely allowed action for this method.

    Returns the CSE candidate index to apply, or ``None`` to stop.
    """
    obs = JitCseEnv.get_observation(method)
    probs = jitrl.action_probabilities(obs)

    terminate = len(probs) - 1
    if not can_terminate:
        probs = probs[:-1]

    for action in np.argsort(probs)[::-1]:
        if action == terminate:
            return None
        if action < len(method.cse_candidates) and method.cse_candidates[action].can_apply:
            return int(action)

    raise ValueError("no valid action; policy is degenerate for this state")


def _rollout(superpmi: SuperPmi, jitrl: JitCseModel, method_id: int,
             include_rl2020: bool = False) -> RolloutRow:
    """Perform a single greedy rollout for one method and return the row.

    If ``include_rl2020`` is True, also compile the method with the JIT's
    built-in parameterized heuristic (``JitRLCSEGreedy=1``, i.e. the 2020
    trained RL model) and fill in the ``rl2020_perfscore`` /
    ``pct_delta_vs_rl2020`` columns.
    """
    heuristic = superpmi.jit_method(method_id, JitMetrics=1)
    no_cse    = superpmi.jit_method(method_id, JitMetrics=1, JitRLHook=1, JitRLHookCSEDecisions=[])

    if heuristic is None or no_cse is None:
        return RolloutRow(method_id=method_id, name="?", method_hash="?", num_candidates=0,
                          chosen_cses=[], heuristic_perfscore=0.0, rl_perfscore=0.0,
                          no_cse_perfscore=0.0, delta_vs_heuristic=0.0,
                          pct_delta_vs_heuristic=0.0, heuristic_total_bytes=0,
                          rl_total_bytes=0, heuristic_instr_count=0, rl_instr_count=0,
                          heuristic_prolog_size=0, rl_prolog_size=0, status="jit_failed")

    rl2020_score = float("nan")
    if include_rl2020:
        rl2020_ctx = superpmi.jit_method(method_id, JitMetrics=1, JitRLCSEGreedy=1)
        if rl2020_ctx is not None:
            rl2020_score = rl2020_ctx.perf_score

    chosen: List[int] = []
    curr: MethodContext = no_cse
    while any(c.can_apply for c in curr.cse_candidates):
        try:
            action = _greedy_action(jitrl, curr, can_terminate=bool(chosen))
        except ValueError:
            break
        if action is None:
            break

        chosen.append(action)
        step = superpmi.jit_method(method_id, JitMetrics=1, JitRLHook=1, JitRLHookCSEDecisions=chosen)
        if step is None:
            return RolloutRow(method_id=method_id, name=heuristic.name,
                              method_hash=heuristic.hash,
                              num_candidates=len(no_cse.cse_candidates),
                              chosen_cses=chosen, heuristic_perfscore=heuristic.perf_score,
                              rl_perfscore=curr.perf_score,
                              no_cse_perfscore=no_cse.perf_score,
                              delta_vs_heuristic=curr.perf_score - heuristic.perf_score,
                              pct_delta_vs_heuristic=_pct(curr.perf_score, heuristic.perf_score),
                              heuristic_total_bytes=heuristic.total_bytes,
                              rl_total_bytes=curr.total_bytes,
                              heuristic_instr_count=heuristic.instruction_count,
                              rl_instr_count=curr.instruction_count,
                              heuristic_prolog_size=heuristic.prolog_size,
                              rl_prolog_size=curr.prolog_size,
                              status="jit_failed",
                              rl2020_perfscore=rl2020_score,
                              pct_delta_vs_rl2020=_pct(curr.perf_score, rl2020_score)
                                                    if not math.isnan(rl2020_score) else float("nan"))
        curr = step

    status = "ok" if chosen else "no_candidates"
    return RolloutRow(method_id=method_id, name=heuristic.name, method_hash=heuristic.hash,
                      num_candidates=len(no_cse.cse_candidates),
                      chosen_cses=chosen,
                      heuristic_perfscore=heuristic.perf_score,
                      rl_perfscore=curr.perf_score,
                      no_cse_perfscore=no_cse.perf_score,
                      delta_vs_heuristic=curr.perf_score - heuristic.perf_score,
                      pct_delta_vs_heuristic=_pct(curr.perf_score, heuristic.perf_score),
                      heuristic_total_bytes=heuristic.total_bytes,
                      rl_total_bytes=curr.total_bytes,
                      heuristic_instr_count=heuristic.instruction_count,
                      rl_instr_count=curr.instruction_count,
                      heuristic_prolog_size=heuristic.prolog_size,
                      rl_prolog_size=curr.prolog_size,
                      status=status,
                      rl2020_perfscore=rl2020_score,
                      pct_delta_vs_rl2020=_pct(curr.perf_score, rl2020_score)
                                            if not math.isnan(rl2020_score) else float("nan"))


def _pct(rl: float, baseline: float) -> float:
    if baseline == 0.0 or math.isnan(baseline):
        return 0.0
    return (rl - baseline) / baseline


# ---------------------------------------------------------------------------
# Evaluation driver
# ---------------------------------------------------------------------------

def _rollout_all(superpmi: SuperPmi, jitrl: JitCseModel, method_ids: Iterable[int],
                 label: str, include_rl2020: bool = False) -> pd.DataFrame:
    method_ids = list(method_ids)
    rows: List[RolloutRow] = []
    for m_id in tqdm.tqdm(method_ids, desc=f"Evaluating {label}", colour='green',
                          ncols=max(shutil.get_terminal_size().columns - 8, 40),
                          ascii=True):
        rows.append(_rollout(superpmi, jitrl, m_id, include_rl2020=include_rl2020))

    return pd.DataFrame([r.__dict__ for r in rows])


def _summarize(df: pd.DataFrame, label: str) -> None:
    print()
    print("=" * 70)
    print(f"{label}  (n={len(df)})")
    print("=" * 70)

    ok = df[df.status == "ok"]
    print(f"  status: ok={len(ok)}  jit_failed={(df.status == 'jit_failed').sum()}  "
          f"no_candidates={(df.status == 'no_candidates').sum()}")
    if ok.empty:
        return

    improved  = ok[ok.rl_perfscore < ok.heuristic_perfscore]
    same      = ok[ok.rl_perfscore == ok.heuristic_perfscore]
    regressed = ok[ok.rl_perfscore > ok.heuristic_perfscore]

    print(f"  vs. heuristic: better={len(improved)}  same={len(same)}  worse={len(regressed)}")

    # Arithmetic mean pct delta (negative = better).
    pct_mean = ok.pct_delta_vs_heuristic.mean()
    # Geometric mean of (rl / heuristic) requires positive perf_scores; guard.
    ratios = (ok.rl_perfscore / ok.heuristic_perfscore).replace([np.inf, -np.inf], np.nan).dropna()
    ratios = ratios[ratios > 0]
    geomean_ratio = math.exp(np.log(ratios).mean()) if not ratios.empty else float("nan")
    print(f"  arithmetic mean pct delta vs heuristic: {pct_mean * 100:+.3f}%  "
          f"(negative = better)")
    print(f"  geometric mean ratio (rl/heuristic):    {geomean_ratio:.5f}  "
          f"({(geomean_ratio - 1.0) * 100:+.3f}%)")

    # Code size comparison (passive metric)
    bytes_ratio = (ok.rl_total_bytes / ok.heuristic_total_bytes).replace(
        [np.inf, -np.inf], np.nan).dropna()
    bytes_ratio = bytes_ratio[bytes_ratio > 0]
    if not bytes_ratio.empty:
        gm = math.exp(np.log(bytes_ratio).mean())
        print(f"  geometric mean code-size ratio:         {gm:.5f}  "
              f"({(gm - 1.0) * 100:+.3f}%)")

    # Optional RL2020 baseline comparison. Only shown when the DataFrame
    # actually carries non-NaN rl2020_perfscore values (i.e., evaluate
    # was run with --include-rl2020).
    if "rl2020_perfscore" in ok.columns and ok["rl2020_perfscore"].notna().any():
        rl2020_ok = ok[ok.rl2020_perfscore.notna()]
        r_improved  = rl2020_ok[rl2020_ok.rl_perfscore < rl2020_ok.rl2020_perfscore]
        r_same      = rl2020_ok[rl2020_ok.rl_perfscore == rl2020_ok.rl2020_perfscore]
        r_regressed = rl2020_ok[rl2020_ok.rl_perfscore > rl2020_ok.rl2020_perfscore]
        rl2020_pct_mean = rl2020_ok.pct_delta_vs_rl2020.mean()
        rl2020_ratios = (rl2020_ok.rl_perfscore / rl2020_ok.rl2020_perfscore).replace(
            [np.inf, -np.inf], np.nan).dropna()
        rl2020_ratios = rl2020_ratios[rl2020_ratios > 0]
        r_geo = math.exp(np.log(rl2020_ratios).mean()) if not rl2020_ratios.empty else float("nan")
        print(f"  vs. RL2020:   better={len(r_improved)}  same={len(r_same)}  worse={len(r_regressed)}")
        print(f"  arithmetic mean pct delta vs RL2020:    {rl2020_pct_mean * 100:+.3f}%  "
              f"(negative = better)")
        print(f"  geometric mean ratio (rl/rl2020):       {r_geo:.5f}  "
              f"({(r_geo - 1.0) * 100:+.3f}%)")


def _resolve_methods(cache: SuperPmiCache, test_seed: Optional[int],
                     test_only: bool, limit: Optional[int]):
    """Return (test_ids, train_ids), applying optional --limit truncation."""
    del test_seed  # SuperPmiCache split is currently seed-42-fixed in constants.py;
                  # a seed override would need to invalidate the on-disk split file.
    test_ids  = list(cache.test_methods)
    train_ids = list(cache.train_methods)
    if limit:
        test_ids  = test_ids[:limit]
        train_ids = [] if test_only else train_ids[:limit]
    if test_only:
        train_ids = []
    return test_ids, train_ids


def _enumerate_models(path: str) -> List[str]:
    if os.path.isfile(path):
        return [path]

    def key(name: str) -> int:
        tail = os.path.splitext(name)[0].split("_")[-1]
        return int(tail) if tail.isdigit() else 10**9

    zips = [os.path.join(path, f) for f in os.listdir(path) if f.endswith(".zip")]
    return sorted(zips, key=lambda p: key(os.path.basename(p)), reverse=True)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("model_path", help="A .zip model file or a directory containing them.")
    parser.add_argument("mch", help="MCH file to evaluate against.")
    parser.add_argument("--core_root", default=None, help="Path to Core_Root.")
    parser.add_argument("--algorithm", default="PPO", choices=("PPO", "A2C", "DQN"))
    parser.add_argument("--test-seed", type=int, default=42,
                        help="Random seed for the train/test split (reserved for future use).")
    parser.add_argument("--test-only", action="store_true",
                        help="Skip the train-set rollout; useful when you only care about held-out data.")
    parser.add_argument("--limit", type=int, default=None,
                        help="Optionally cap each of train/test to at most N methods.")
    parser.add_argument("--include-rl2020", action="store_true",
                        help="Also compile each method with the JIT's built-in parameterized "
                             "heuristic (JitRLCSEGreedy=1, i.e. the 2020-trained RL model) "
                             "and add a ``rl_perfscore vs rl2020_perfscore`` comparison to "
                             "the CSV + summary.")

    args = parser.parse_args()
    args.core_root = validate_core_root(args.core_root)
    return args


def main(args: argparse.Namespace) -> int:
    if not os.path.exists(args.model_path):
        print(f"error: {args.model_path} does not exist.", file=sys.stderr)
        return 2

    if not SuperPmiCache.exists(args.mch):
        print(f"Building SuperPmiCache for {args.mch} -- this may take several minutes...")
    cache = SuperPmiCache(args.mch, args.core_root)

    test_ids, train_ids = _resolve_methods(cache, args.test_seed, args.test_only, args.limit)
    if not test_ids and not train_ids:
        print("error: no methods available to evaluate.", file=sys.stderr)
        return 1

    for model_path in _enumerate_models(args.model_path):
        model_name = os.path.splitext(os.path.basename(model_path))[0]
        print(f"\n### model: {model_name}  ({model_path})")

        jitrl = JitCseModel(args.algorithm)
        jitrl.load(model_path)

        model_dir = args.model_path if os.path.isdir(args.model_path) else os.path.dirname(model_path)

        with SuperPmi(args.mch, args.core_root) as spmi:
            if test_ids:
                test_df = _rollout_all(spmi, jitrl, test_ids, f"{model_name} test",
                                        include_rl2020=args.include_rl2020)
                test_csv = os.path.join(model_dir, f"{model_name}_test.csv")
                test_df.to_csv(test_csv, index=False)
                _summarize(test_df, f"TEST  ({model_name})")

            if train_ids:
                train_df = _rollout_all(spmi, jitrl, train_ids, f"{model_name} train",
                                         include_rl2020=args.include_rl2020)
                train_csv = os.path.join(model_dir, f"{model_name}_train.csv")
                train_df.to_csv(train_csv, index=False)
                _summarize(train_df, f"TRAIN ({model_name})")

    return 0


if __name__ == "__main__":
    sys.exit(main(_parse_args()))

