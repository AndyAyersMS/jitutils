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
from typing import Dict, List, Optional, Tuple

# Allow running from the repo tree without an install.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from jitml.method_context import MethodContext  # noqa: E402
from jitml.superpmi import MethodKind, SuperPmi, SuperPmiCache, SuperPmiContext  # noqa: E402
from jitml.constants import MAX_CSE, is_acceptable_for_cse, split_for_cse  # noqa: E402


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
    parser.add_argument("--hard-stop-reward", action="store_true",
                        help="Wrap the env with HardStopRewardWrapper: replaces per-step "
                             "reward with a pure episode-end signal (heur - final)/heur, "
                             "with asymmetric penalty for regressions. Targets the "
                             "'fire on A_nothing' pattern where per-step reward mis-teaches "
                             "the policy that firing one CSE is safe.")
    parser.add_argument("--hard-stop-scale", type=float, default=1.0,
                        help="Scale for HardStopRewardWrapper improvement reward "
                             "(default 1.0).")
    parser.add_argument("--hard-stop-asym", type=float, default=2.0,
                        help="Multiplier for HardStopRewardWrapper regression penalty "
                             "(default 2.0, i.e. regressions weighted 2x improvements).")
    parser.add_argument("--optimal-reward", action="store_true",
                        help="Wrap the env with OptimalCseWrapper (per-step reward against best-of-"
                             "alternatives; densifies the reward signal but adds ~4-5x per-step JIT cost).")
    parser.add_argument("--attention", action="store_true",
                        help="Use the AttentionOverCandidatesExtractor custom SB3 policy "
                             "(requires PPO or A2C).")
    parser.add_argument("--attention-separate-stop-head", action="store_true",
                        help="With --attention, use a separate stop-action scorer over "
                             "method-level features (instead of sharing the candidate "
                             "head). Targets the 'compulsive firing on A_nothing' pattern "
                             "diagnosed post-C4: with a shared head, the stop logit is a "
                             "function of pooled candidate features, so any non-trivial "
                             "candidate suppresses stop probability regardless of whether "
                             "stopping is actually right. Splits the decision cleanly.")
    parser.add_argument("--linear-scorer", action="store_true",
                        help="Use the RL2020-style LinearPerCandidateExtractor: shared linear "
                             "scorer across candidates + separate scorer for the stop action. "
                             "~350 params total (vs ~70k for --attention). Mutually exclusive "
                             "with --attention.")
    parser.add_argument("--ent-coef", type=float, default=0.01,
                        help="PPO entropy bonus coefficient (default 0.01). Higher values "
                             "keep the policy exploratory; 0.02-0.05 is a common range when "
                             "the policy is collapsing to a single action.")
    parser.add_argument("--clip-range", type=float, default=0.2,
                        help="PPO trust-region clip range (default 0.2). Lower (e.g. 0.1) "
                             "tightens the trust region, smoothing KL swings.")
    parser.add_argument("--net-arch", type=str, default=None,
                        help="Override the SB3 policy/value MLP head sizes. Comma-separated "
                             "ints, e.g. '32,32'. Empty string '' means a linear head "
                             "(single dense layer, no hidden units). Default (unset) uses "
                             "the SB3 built-in default (typically [64, 64]). Useful to test "
                             "whether the neural net is overparameterized vs the training-"
                             "set size.")
    parser.add_argument("--skip-indices", type=str, default=None,
                        help="Path to a file containing a list of method indices (one per "
                             "line) to skip during scanning. Useful when scanning a big "
                             "MCH that contains held-out test indices (e.g. scanning "
                             "combined.tier1.mch while excluding the 750 methods that live "
                             "in test.mch).")
    return parser.parse_args()


def _pick_methods(spmi: SuperPmi, scan_limit: int, want: int,
                  stratified: bool = True,
                  skip_indices: Optional[set] = None) -> List[MethodContext]:
    """Scan the MCH one method at a time; return up to ``want`` methods
    that pass ``is_acceptable_for_cse`` (i.e. have between MIN_CSE and
    MAX_CSE viable candidates).

    If ``stratified`` is True (default), the picks are balanced along
    **two axes**:

    1. **Candidate count**: 6 buckets covering the current MIN_CSE..MAX_CSE
       range: [1-2], [3-5], [6-10], [11-16], [17-24], [25-MAX_CSE].
       Prevents the training distribution from being dominated by narrow
       methods (which vastly outnumber wide methods in real code).
    2. **Heuristic behavior**: 4 buckets by ``heur_perf / no_cse_perf``:
       - A: heuristic did nothing (``heur >= 0.995 * no_cse``)
       - B: heuristic helped modestly (``0.95 * no_cse <= heur < 0.995 * no_cse``)
       - C: heuristic helped substantially (``0.80 <= heur < 0.95``)
       - D: heuristic helped dramatically (``heur < 0.80``)
       Ensures the training set includes the "heur does nothing" class
       (11 of 18 persistent worst-cases pre-fix were this pattern) and
       the "heur does a lot" class (where the RL must learn extensive
       CSE application).

    Total 24 cells; target ~``want // 24`` methods per cell. Requires an
    extra JIT call per acceptable scanned method (to establish the
    heuristic baseline for bucketing), so scanning is slower than the
    single-axis path.
    """
    if not stratified:
        keeps: List[MethodContext] = []
        for idx in range(1, scan_limit + 1):
            if skip_indices is not None and idx in skip_indices:
                continue
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

    # Two-axis stratified path: 6 cand-count buckets x 4 heur-behavior buckets.
    cand_buckets = ((1, 2), (3, 5), (6, 10), (11, 16), (17, 24), (25, MAX_CSE))
    heur_labels = ("A_nothing", "B_modest", "C_substantial", "D_dramatic")
    n_cells = len(cand_buckets) * len(heur_labels)
    per_cell = max(1, want // n_cells)

    # cells[(cand_bucket_idx, heur_bucket_idx)] -> list of MethodContext
    cells: Dict[Tuple[int, int], List[MethodContext]] = {}
    for ci in range(len(cand_buckets)):
        for hi in range(len(heur_labels)):
            cells[(ci, hi)] = []

    def cand_bucket_of(n: int) -> int:
        for i, (lo, hi) in enumerate(cand_buckets):
            if lo <= n <= hi:
                return i
        return -1

    def heur_bucket_of(heur_ps: float, no_cse_ps: float) -> int:
        # Guard: perf-scores of ~0 shouldn't happen for real methods; treat
        # as "heur did nothing" if the ratio can't be computed.
        if no_cse_ps <= 0:
            return 0
        ratio = heur_ps / no_cse_ps
        if ratio >= 0.995:
            return 0  # A: nothing
        if ratio >= 0.95:
            return 1  # B: modest
        if ratio >= 0.80:
            return 2  # C: substantial
        return 3      # D: dramatic

    for idx in range(1, scan_limit + 1):
        if skip_indices is not None and idx in skip_indices:
            continue
        # Stop if every cell is full.
        if all(len(v) >= per_cell for v in cells.values()):
            break
        try:
            # Step 1: get features + no_cse baseline (empty CSE list).
            ctx = spmi.jit_method(idx, JitMetrics=1, JitRLHook=1,
                                  JitRLHookEmitFeatureNames=1,
                                  JitRLHookCSEDecisions=[])
        except Exception as exc:  # noqa: BLE001
            print(f"  idx={idx}: jit(RLHook) failed ({type(exc).__name__}: {exc}); skipping")
            continue
        if ctx is None or not is_acceptable_for_cse(ctx):
            continue

        # Bail early if the cand bucket is already full — avoid the second
        # (heuristic) JIT call which is the expensive part.
        ci = cand_bucket_of(ctx.num_cse_candidate)
        if ci < 0:
            continue
        if all(len(cells[(ci, hi)]) >= per_cell for hi in range(len(heur_labels))):
            continue

        # Step 2: heuristic baseline (no RLHook, uses default CSE_Heuristic).
        try:
            heur = spmi.jit_method(idx, JitMetrics=1)
        except Exception as exc:  # noqa: BLE001
            print(f"  idx={idx}: jit(heuristic) failed ({type(exc).__name__}: {exc}); skipping")
            continue
        if heur is None:
            continue

        hi = heur_bucket_of(heur.perf_score, ctx.perf_score)
        if len(cells[(ci, hi)]) >= per_cell:
            continue
        cells[(ci, hi)].append(ctx)

    picked = [m for cell in cells.values() for m in cell]
    print(f"  two-axis stratified picks (cand_bucket x heur_bucket, target={per_cell}/cell):")
    for ci, (lo, hi_c) in enumerate(cand_buckets):
        row = "    "
        for hii, hlabel in enumerate(heur_labels):
            row += f"cand[{lo}-{hi_c}]:{hlabel[0]}={len(cells[(ci, hii)]):>3d}  "
        print(row)
    print(f"  total picked: {len(picked)}")
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

    if args.attention_separate_stop_head and not args.attention:
        print("FAIL: --attention-separate-stop-head requires --attention.", file=sys.stderr)
        return 2
    if args.attention_separate_stop_head and args.net_arch is not None:
        print("FAIL: --attention-separate-stop-head forces net_arch=[] so cannot be "
              "combined with --net-arch.", file=sys.stderr)
        return 2

    skip_indices: Optional[set] = None
    if args.skip_indices:
        with open(args.skip_indices, encoding="utf-8") as f:
            skip_indices = {int(line.strip()) for line in f if line.strip()}
        print(f"      loaded {len(skip_indices)} indices to skip from {args.skip_indices}")

    print(f"[1/5] scanning up to {args.scan_limit} methods for {args.num_methods} "
          f"CSE-eligible candidates...")
    t0 = time.time()
    with SuperPmi(args.mch, args.core_root) as spmi:
        picked = _pick_methods(spmi, args.scan_limit, args.num_methods,
                               stratified=not args.no_stratify,
                               skip_indices=skip_indices)
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
    from jitml import (NormalizeFeaturesWrapper, DeltaVsHeuristicRewardWrapper,
                       HardStopRewardWrapper, OptimalCseWrapper)
    from functools import partial
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
    if args.hard_stop_reward:
        wrappers.append(partial(HardStopRewardWrapper,
                                scale=args.hard_stop_scale,
                                asym_penalty=args.hard_stop_asym))
        print(f"      + HardStopRewardWrapper (scale={args.hard_stop_scale:g}, "
              f"asym_penalty={args.hard_stop_asym:g})")
    if args.optimal_reward:
        wrappers.append(OptimalCseWrapper)
        print("      + OptimalCseWrapper (dense per-step reward; ~4-5x per-step JIT cost)")

    net_arch = None
    if args.net_arch is not None:
        net_arch = [int(x) for x in args.net_arch.split(",") if x.strip() != ""]

    attention_kwargs = {}
    if args.attention_separate_stop_head:
        attention_kwargs["use_separate_stop_head"] = True

    model = JitCseModel(args.algorithm, use_attention=args.attention,
                        use_linear_scorer=args.linear_scorer,
                        ent_coef=args.ent_coef, clip_range=args.clip_range,
                        net_arch=net_arch,
                        attention_kwargs=attention_kwargs)
    if args.attention:
        stop_head = " + separate stop head" if args.attention_separate_stop_head else ""
        print(f"      + AttentionOverCandidatesExtractor{stop_head} ({args.algorithm})")
    if args.linear_scorer:
        print(f"      + LinearPerCandidateExtractor ({args.algorithm})")
    if net_arch is not None:
        print(f"      net_arch={net_arch}")
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
