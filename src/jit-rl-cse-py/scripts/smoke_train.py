"""Minimal smoke training run for jit-rl-cse-py.

Unlike ``train.py``, this script does not require a full-MCH SuperPmiCache
(which would enumerate every method in the MCH twice up front and take
tens of minutes on a large collection). Instead it hand-picks a small
number of methods that actually have CSE candidates, pre-populates the
per-mch cache with just those methods, and runs a short PPO training
loop end-to-end.

Intended purpose: confirm the parser + env + policy training path works
against a real Checked JIT and a downloaded MCH. Not a research run --
the resulting model is throw-away.

Usage:
    python scripts/smoke_train.py \\
        --core_root <PATH> \\
        --mch <PATH> \\
        --output_dir <OUT> \\
        [--iterations 20000] [--num_methods 20] [--scan_limit 400]

Exit code 0 on success.
"""
# pylint: disable=protected-access

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import List

# Allow running from the repo tree without an install.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from jitml.method_context import MethodContext  # noqa: E402
from jitml.superpmi import MethodKind, SuperPmi, SuperPmiCache, SuperPmiContext  # noqa: E402
from jitml.constants import is_acceptable_for_cse, split_for_cse  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core_root", required=True)
    parser.add_argument("--mch", required=True)
    parser.add_argument("--output_dir", required=True)
    parser.add_argument("--iterations", type=int, default=20_000,
                        help="PPO training iterations (default 20k, ~2 min).")
    parser.add_argument("--num_methods", type=int, default=20,
                        help="How many CSE-eligible methods to train on (default 20).")
    parser.add_argument("--scan_limit", type=int, default=400,
                        help="How many methods to scan from the MCH looking for candidates "
                             "before giving up (default 400).")
    parser.add_argument("--no-stratify", action="store_true",
                        help="Disable stratified candidate-count bucketing in _pick_methods "
                             "(fall back to picking the first N CSE-eligible methods).")
    parser.add_argument("--algorithm", default="PPO", choices=("PPO", "A2C", "DQN"))
    parser.add_argument("--parallel", type=int, default=None,
                        help="Number of parallel SubprocVecEnv workers (each spawns its own "
                             "superpmi + JIT). Default: single-process.")
    parser.add_argument("--normalize-features", action="store_true",
                        help="Wrap the env with NormalizeFeaturesWrapper (log1p count-like features).")
    parser.add_argument("--delta-reward", action="store_true",
                        help="Wrap the env with DeltaVsHeuristicRewardWrapper "
                             "(episode-end shaping term = (heuristic - final) / heuristic).")
    parser.add_argument("--optimal-reward", action="store_true",
                        help="Wrap the env with OptimalCseWrapper (per-step reward against best-of-"
                             "alternatives; densifies the reward signal but adds ~4-5x per-step JIT cost).")
    parser.add_argument("--attention", action="store_true",
                        help="Use the AttentionOverCandidatesExtractor custom SB3 policy "
                             "(requires PPO or A2C).")
    parser.add_argument("--ent-coef", type=float, default=0.01,
                        help="PPO entropy bonus coefficient (default 0.01). Higher values "
                             "keep the policy exploratory; 0.02-0.05 is a common range when "
                             "the policy is collapsing to a single action.")
    parser.add_argument("--clip-range", type=float, default=0.2,
                        help="PPO trust-region clip range (default 0.2). Lower (e.g. 0.1) "
                             "tightens the trust region, smoothing KL swings.")
    return parser.parse_args()


def _pick_methods(spmi: SuperPmi, scan_limit: int, want: int,
                  stratified: bool = True) -> List[MethodContext]:
    """Scan the MCH one method at a time; return up to ``want`` methods
    that pass ``is_acceptable_for_cse`` (i.e. have between MIN_CSE and
    MAX_CSE viable candidates).

    If ``stratified`` is True (default), the picks are balanced across
    candidate-count buckets [1-3], [4-6], [7-10], [11-16] so the training
    distribution isn't dominated by whichever bucket happens to be dense
    at the front of the MCH. This directly addresses the training bias
    the Phase-0 diagnostic surfaced (policy learning positional shortcuts
    from a homogeneous training set).
    """
    if not stratified:
        keeps: List[MethodContext] = []
        for idx in range(1, scan_limit + 1):
            try:
                ctx = spmi.jit_method(idx, JitMetrics=1, JitRLHook=1,
                                      JitRLHookEmitFeatureNames=1,
                                      JitRLHookCSEDecisions=[])
            except Exception as exc:  # noqa: BLE001
                print(f"  idx={idx}: jit failed ({type(exc).__name__}: {exc}); skipping")
                continue
            if ctx is None or not is_acceptable_for_cse(ctx):
                continue
            keeps.append(ctx)
            if len(keeps) >= want:
                break
        return keeps

    # Stratified path: fill four candidate-count buckets in parallel.
    buckets = ((1, 3), (4, 6), (7, 10), (11, 16))
    per_bucket = max(1, want // len(buckets))
    holds: List[List[MethodContext]] = [[] for _ in buckets]

    def bucket_of(n: int) -> int:
        for i, (lo, hi) in enumerate(buckets):
            if lo <= n <= hi:
                return i
        return -1

    for idx in range(1, scan_limit + 1):
        # Stop if every bucket is full.
        if all(len(h) >= per_bucket for h in holds):
            break
        try:
            ctx = spmi.jit_method(idx, JitMetrics=1, JitRLHook=1,
                                  JitRLHookEmitFeatureNames=1,
                                  JitRLHookCSEDecisions=[])
        except Exception as exc:  # noqa: BLE001
            print(f"  idx={idx}: jit failed ({type(exc).__name__}: {exc}); skipping")
            continue
        if ctx is None or not is_acceptable_for_cse(ctx):
            continue
        b = bucket_of(ctx.num_cse_candidate)
        if b < 0 or len(holds[b]) >= per_bucket:
            continue
        holds[b].append(ctx)

    picked = [m for h in holds for m in h]
    print(f"  stratified picks per bucket: "
          f"{[f'{buckets[i][0]}-{buckets[i][1]}={len(h)}' for i, h in enumerate(holds)]}")
    return picked


def _prime_cache(mch: str, core_root: str, methods_no_cse: List[MethodContext],
                 methods_heuristic: List[MethodContext]) -> None:
    """Write ``methods_no_cse`` and ``methods_heuristic`` to the JSON
    files SuperPmiCache expects, plus the train/test split file. This
    is what lets us construct a SuperPmiCache instance without triggering
    a full-MCH enumeration."""
    no_cse_file    = SuperPmiCache._get_cache_file(mch, MethodKind.NO_CSE)
    heuristic_file = SuperPmiCache._get_cache_file(mch, MethodKind.HEURISTIC)
    split_file     = SuperPmiCache._get_split_file(mch)

    def dump(path: str, methods: List[MethodContext]) -> None:
        with open(path, "w", encoding="utf-8") as f:
            # Emit by alias so the JSON schema matches the JIT-emitted
            # feature names (matches the format written by
            # ``SuperPmiCache._load_all_methods``).
            json.dump([m.model_dump(by_alias=True) for m in methods], f)

    dump(no_cse_file, methods_no_cse)
    dump(heuristic_file, methods_heuristic)

    # Deterministic split — use a large test_percent so even a tiny number
    # of methods still produces a non-empty split (split_for_cse discards
    # groups smaller than 1/test_percent). For the smoke path we always
    # keep at least one training method by force.
    test, train = split_for_cse(methods_no_cse, test_percent=0.5)
    train_ids = [m.index for m in train]
    test_ids  = [m.index for m in test]
    if not train_ids:
        # Fall back: split_for_cse dropped groups smaller than 2; put
        # everything into train and pick one for test if we have >= 2.
        all_ids = [m.index for m in methods_no_cse]
        train_ids = all_ids[1:] or all_ids
        test_ids  = all_ids[:1] if len(all_ids) >= 2 else []
    with open(split_file, "w", encoding="utf-8") as f:
        json.dump([test_ids, train_ids], f)


def main() -> int:
    args = _parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    print(f"[1/5] scanning up to {args.scan_limit} methods for {args.num_methods} "
          f"CSE-eligible candidates...")
    t0 = time.time()
    with SuperPmi(args.mch, args.core_root) as spmi:
        picked = _pick_methods(spmi, args.scan_limit, args.num_methods,
                               stratified=not args.no_stratify)
    print(f"      picked {len(picked)} methods in {time.time()-t0:.1f}s")

    if len(picked) < 3:
        print(f"FAIL: only found {len(picked)} CSE-eligible methods in the first "
              f"{args.scan_limit} of the MCH; try increasing --scan_limit.", file=sys.stderr)
        return 1

    print("[2/5] priming heuristic-baseline for the picked methods...")
    t0 = time.time()
    heuristics: List[MethodContext] = []
    with SuperPmi(args.mch, args.core_root) as spmi:
        for m in picked:
            h = spmi.jit_method(m.index, JitMetrics=1)
            if h is not None:
                heuristics.append(h)
    print(f"      {len(heuristics)} heuristics collected in {time.time()-t0:.1f}s")

    print("[3/5] writing per-mch cache JSON so JitCseEnv can start fast...")
    _prime_cache(args.mch, args.core_root, picked, heuristics)

    print("[4/5] constructing JitCseEnv + PPO...")
    from jitml import JitCseEnv, JitCseModel  # lazy-imports torch/SB3
    from jitml import NormalizeFeaturesWrapper, DeltaVsHeuristicRewardWrapper, OptimalCseWrapper
    ctx = SuperPmiContext(core_root=args.core_root, mch=args.mch)
    # Load the split we just wrote; use the train side.
    _, train_ids = SuperPmiCache.get_test_train_methods(args.mch, args.core_root)
    if not train_ids:
        print("FAIL: primed cache produced an empty training set.", file=sys.stderr)
        return 1
    print(f"      training on {len(train_ids)} methods: {train_ids[:10]}...")

    wrappers = []
    if args.normalize_features:
        wrappers.append(NormalizeFeaturesWrapper)
        print("      + NormalizeFeaturesWrapper")
    if args.delta_reward:
        wrappers.append(DeltaVsHeuristicRewardWrapper)
        print("      + DeltaVsHeuristicRewardWrapper")
    if args.optimal_reward:
        wrappers.append(OptimalCseWrapper)
        print("      + OptimalCseWrapper (dense per-step reward; ~4-5x per-step JIT cost)")

    model = JitCseModel(args.algorithm, use_attention=args.attention,
                        ent_coef=args.ent_coef, clip_range=args.clip_range)
    if args.attention:
        print(f"      + AttentionOverCandidatesExtractor ({args.algorithm})")
    print(f"      ent_coef={args.ent_coef:g}  clip_range={args.clip_range:g}")

    print(f"[5/5] running {args.algorithm} for {args.iterations} iterations...")
    t0 = time.time()
    save_path = model.train(ctx, train_ids, args.output_dir,
                            iterations=args.iterations, parallel=args.parallel,
                            progress_bar=False, wrappers=wrappers)
    elapsed = time.time() - t0

    print(f"OK: {args.algorithm} trained {args.iterations} iters in {elapsed:.1f}s; "
          f"model saved to {save_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
