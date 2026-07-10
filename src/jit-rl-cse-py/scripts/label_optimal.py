"""Label each method in an MCH with its (near-)optimal CSE subset.

Uses ``JitRLHookCSEDecisions`` (the same JIT path our RL env uses at
train + inference time). For each method, enumerates CSE subsets to
find the one that minimizes perf-score:

* If the number of viable candidates ``k <= --exhaustive-cutoff``
  (default 9), tries all 2^k subsets exhaustively.
* Otherwise, MCMC-style random search: ``--mcmc-trials`` random
  subsets (default 512) plus the empty subset and the "all viable"
  subset as sanity anchors.

Also fetches the heuristic and no-CSE perfscores per method for
comparison, so consumers can compute per-method::

    heuristic_gap  = (heuristic - optimum) / heuristic       # positive == room to improve
    no_cse_gap     = (no_cse - optimum) / no_cse

The output JSON schema (dict keyed by method_id as string):

    {
      "<method_id>": {
        "n_candidates":       int,
        "n_viable":           int,
        "labeling_mode":      "exhaustive" | "mcmc",
        "n_trials":           int,
        "optimal_subset":     [int, ...],     # candidate-array indices
        "optimal_perfscore":  float,
        "heuristic_perfscore": float,
        "heuristic_cses":     [int, ...],     # what heuristic picked (JIT's own indexing)
        "no_cse_perfscore":   float
      },
      ...
    }

Design notes:
* Empirically confirmed (on method 6): RLHook and JitCSEMask reach the
  same ceiling on the same method, just with different index encodings.
  RLHook is chosen here so training labels are in the same action-space
  as the RL env's ``JitRLHookCSEDecisions`` action.
* Empirically confirmed: order within a subset does NOT matter when
  submitted via JitRLHookCSEDecisions (tested on methods 6, 100).
  So this is a SET-prediction problem, not sequence.
* Non-viable candidates are automatically no-ops when included in a
  subset, so we only need to enumerate viable-candidate subsets.

Usage::

    python scripts/label_optimal.py \\
        --core_root <path>/Core_Root \\
        --mch C:/spmi/mch-tier1/train_big.mch \\
        --out C:/spmi/mch-tier1/train_big.optimal.json \\
        --limit 200 \\
        --parallel 8

``--limit`` optionally caps the number of methods processed (useful
for dry-runs). ``--parallel`` launches N SuperPmi workers in a
process pool, each handling a slice of the method list. Use ``0`` to
run serially (default).
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import itertools
import json
import os
import random
import sys
import time
from typing import Dict, List, Optional, Set, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jitml.superpmi import SuperPmi
from jitml.method_context import MethodContext


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True)
    p.add_argument("--out", required=True,
                   help="Output JSON path.")
    p.add_argument("--limit", type=int, default=None,
                   help="Optionally cap the number of methods processed.")
    p.add_argument("--indices", type=str, default=None,
                   help="Path to a file with method indices (one per line) to process. "
                        "If omitted, scans all methods in the MCH.")
    p.add_argument("--scan_limit", type=int, default=None,
                   help="If --indices is not given, scan up to this many methods (default: all).")
    p.add_argument("--exhaustive-cutoff", type=int, default=9,
                   help="Enumerate all 2^k subsets for methods with k <= this many "
                        "viable candidates (default 9, i.e. up to 512 subsets).")
    p.add_argument("--mcmc-trials", type=int, default=512,
                   help="Number of random subsets to try for methods above the "
                        "exhaustive cutoff (default 512, matching RLCSE 2020).")
    p.add_argument("--parallel", type=int, default=0,
                   help="Number of parallel SuperPmi workers (0=serial, default). "
                        "Each worker spawns its own long-lived superpmi.exe.")
    p.add_argument("--seed", type=int, default=42,
                   help="Random seed for MCMC trial subset generation (default 42).")
    p.add_argument("--resume", action="store_true",
                   help="If --out already exists, load it and skip methods already labeled.")
    p.add_argument("--bbinstr-sample-rate", type=float, default=1.0,
                   help="Down-sample rate for methods compiled as 'Instrumented Tier1' "
                        "(BBINSTR flag). These methods are still tier1 PGO-optimized but "
                        "are being additionally instrumented for future profile refinement, "
                        "which is less interesting for CSE training. Default 1.0 keeps all; "
                        "e.g. 0.3 keeps 30 pct of Instrumented Tier1 methods.")
    return p.parse_args()


def _viable_indices(m: MethodContext) -> List[int]:
    """Candidate-array indices (0..n-1) whose ``can_apply`` is True."""
    return [i for i, c in enumerate(m.cse_candidates) if c.can_apply]


def _score_subset(spmi: SuperPmi, method_id: int, subset: List[int]) -> Optional[float]:
    """JIT the method with ``subset`` applied via JitRLHookCSEDecisions.
    Returns the perfscore, or None on JIT failure."""
    try:
        r = spmi.jit_method(method_id, JitMetrics=1, JitRLHook=1,
                            JitRLHookCSEDecisions=list(subset))
    except Exception:  # noqa: BLE001
        return None
    return r.perf_score if r is not None else None


def _label_method(spmi: SuperPmi, method_id: int, exhaustive_cutoff: int,
                  mcmc_trials: int, rng: random.Random,
                  bbinstr_sample_rate: float = 1.0) -> Optional[Dict]:
    """Compute the optimal-subset label for one method. Returns None if
    the method has no viable candidates or the initial JIT fails.

    When ``bbinstr_sample_rate < 1.0``, methods compiled as
    'Instrumented Tier1' (BBINSTR flag; still tier1 PGO-optimized but
    also being instrumented for future profile refinement) are randomly
    dropped so the training set is biased toward pure Tier1 methods.
    """
    try:
        no_cse = spmi.jit_method(method_id, JitMetrics=1, JitRLHook=1,
                                 JitRLHookEmitFeatureNames=1,
                                 JitRLHookCSEDecisions=[])
    except Exception:  # noqa: BLE001
        return None
    if no_cse is None:
        return None

    # Bias against Instrumented Tier1 (BBINSTR) methods if requested.
    if bbinstr_sample_rate < 1.0 and no_cse.compile_mode == "Instrumented Tier1":
        if rng.random() >= bbinstr_sample_rate:
            return None

    viable = _viable_indices(no_cse)
    if not viable:
        return None

    k = len(viable)
    n = no_cse.num_cse_candidate

    # Also get the heuristic baseline for reference. Non-fatal if it fails.
    try:
        h = spmi.jit_method(method_id, JitMetrics=1)
        heur_perf = h.perf_score if h is not None else float("nan")
        heur_cses = list(h.cses_chosen) if (h is not None and hasattr(h, "cses_chosen")) else []
    except Exception:  # noqa: BLE001
        heur_perf = float("nan")
        heur_cses = []

    best_subset: List[int] = []
    best_perf = no_cse.perf_score
    n_tried = 0

    if k <= exhaustive_cutoff:
        mode = "exhaustive"
        for mask in range(1 << k):
            subset = [viable[i] for i in range(k) if mask & (1 << i)]
            perf = _score_subset(spmi, method_id, subset)
            n_tried += 1
            if perf is not None and perf < best_perf:
                best_perf = perf
                best_subset = subset
    else:
        mode = "mcmc"
        seen: Set[frozenset] = set()

        def try_subset(sub: List[int]) -> bool:
            """Try ``sub``, update best if better, return True if it was a new best."""
            nonlocal best_perf, best_subset, n_tried
            key = frozenset(sub)
            if key in seen:
                return False
            seen.add(key)
            perf = _score_subset(spmi, method_id, sub)
            n_tried += 1
            if perf is not None and perf < best_perf:
                best_perf = perf
                best_subset = list(sub)
                return True
            return False

        # Anchor points: empty and all-viable.
        try_subset([])
        try_subset(list(viable))

        # HILL CLIMB from a "good" starting point (the heuristic's own
        # choice, subset-intersected with viable). Randomly-initialized
        # 512-trial search covers 1.5pct of 2^15 space -- likely misses
        # the true optimum. Hill-climb explores O(k) neighbors per
        # iteration, converges to a LOCAL optimum in <10 iters. To
        # escape local optima, restart from random subsets between
        # climbs. Combined coverage of local optima >> pure random.
        heur_start = [i for i in viable if i in heur_cses] if heur_cses else []
        # Additional starting points: heuristic subset, all-viable
        # subset (already tried), and random subsets.
        starts: List[List[int]] = [heur_start] if heur_start else []

        # As many random starts as our budget allows. Reserve at least
        # ``k+1`` trials per climb (init + k flip attempts). If we still
        # have budget, restart.
        est_climb_cost = k + 1
        max_random_starts = max(1, (mcmc_trials - n_tried) // est_climb_cost - 1)
        for _ in range(min(max_random_starts, 8)):  # cap at 8 random restarts
            size = rng.randint(1, k)
            starts.append(sorted(rng.sample(viable, size)))

        for start in starts:
            current = list(start)
            try_subset(current)
            improved = True
            while improved and n_tried < mcmc_trials:
                improved = False
                # Try all single-bit flips (add/remove one CSE from the
                # current subset). First-improvement acceptance.
                current_set = set(current)
                for c in viable:
                    if n_tried >= mcmc_trials:
                        break
                    if c in current_set:
                        candidate_subset = sorted(current_set - {c})
                    else:
                        candidate_subset = sorted(current_set | {c})
                    if try_subset(candidate_subset):
                        current = candidate_subset
                        improved = True
                        break  # first-improvement: restart flip loop
            if n_tried >= mcmc_trials:
                break

        mode = "mcmc-hillclimb"

    return {
        "n_candidates": n,
        "n_viable": k,
        "labeling_mode": mode,
        "n_trials": n_tried,
        "optimal_subset": best_subset,
        "optimal_perfscore": best_perf,
        "heuristic_perfscore": heur_perf,
        "heuristic_cses": heur_cses,
        "no_cse_perfscore": no_cse.perf_score,
    }


def _resolve_indices(mch: str, core_root: str, indices_file: Optional[str],
                     scan_limit: Optional[int], limit: Optional[int],
                     already_done: Set[int]) -> List[int]:
    """Determine which method ids to label."""
    ids: List[int] = []
    if indices_file:
        with open(indices_file, encoding="utf-8") as f:
            ids = [int(line.strip()) for line in f if line.strip()]
    else:
        # Scan the MCH for methods with any candidates. Uses one throwaway
        # SPMI instance; caller-supplied ``scan_limit`` bounds the walk.
        # Also stop after N CONSECUTIVE invalid indices, since indices
        # past the MCH's end will each trigger a costly spmi restart.
        with SuperPmi(mch, core_root) as spmi:
            top = scan_limit if scan_limit else 10_000_000
            consecutive_invalid = 0
            MAX_CONSECUTIVE_INVALID = 30
            for idx in range(1, top + 1):
                try:
                    m = spmi.jit_method(idx, JitMetrics=1, JitRLHook=1,
                                        JitRLHookEmitFeatureNames=1,
                                        JitRLHookCSEDecisions=[])
                except Exception:  # noqa: BLE001
                    consecutive_invalid += 1
                    if idx > 100 and not ids:
                        break  # never found any -- probably no methods
                    if consecutive_invalid >= MAX_CONSECUTIVE_INVALID:
                        break  # past end of MCH
                    continue
                if m is None:
                    consecutive_invalid += 1
                    if idx > 100 and not ids:
                        break
                    if consecutive_invalid >= MAX_CONSECUTIVE_INVALID:
                        break
                    continue
                consecutive_invalid = 0
                if _viable_indices(m):
                    ids.append(idx)
    if already_done:
        ids = [i for i in ids if i not in already_done]
    if limit is not None:
        ids = ids[:limit]
    return ids


def _worker(mch: str, core_root: str, method_ids: List[int],
            exhaustive_cutoff: int, mcmc_trials: int, seed: int,
            bbinstr_sample_rate: float = 1.0) -> Dict[str, Dict]:
    """One process-pool worker: label a slice of methods."""
    import sys
    rng = random.Random(seed)
    out: Dict[str, Dict] = {}
    with SuperPmi(mch, core_root) as spmi:
        for method_id in method_ids:
            # Log which method we're about to work on so, if we hang here,
            # a status check reveals the exact trigger (worker-level log
            # + os.getpid).
            print(f"    [pid {os.getpid()}] method {method_id}", flush=True)
            label = _label_method(spmi, method_id, exhaustive_cutoff, mcmc_trials,
                                  rng, bbinstr_sample_rate=bbinstr_sample_rate)
            if label is not None:
                out[str(method_id)] = label
    return out


def main() -> int:
    args = _parse_args()

    # Resume support.
    labels: Dict[str, Dict] = {}
    if args.resume and os.path.exists(args.out):
        with open(args.out, encoding="utf-8") as f:
            labels = json.load(f)
        print(f"Resuming: {len(labels)} methods already labeled in {args.out}")
    already_done = {int(k) for k in labels.keys()}

    print(f"Resolving methods to label...")
    ids = _resolve_indices(args.mch, args.core_root, args.indices,
                           args.scan_limit, args.limit, already_done)
    print(f"  {len(ids)} methods to label "
          f"(exhaustive_cutoff={args.exhaustive_cutoff}, mcmc_trials={args.mcmc_trials})")
    if not ids:
        print("nothing to do")
        return 0

    t0 = time.time()

    if args.parallel and args.parallel > 1:
        # Dynamic work distribution: submit MANY small task chunks and let
        # ProcessPoolExecutor's internal scheduler pick them up. Static
        # 1/N slicing (previous approach) caused wall-clock imbalance
        # when one slice happened to draw all the MCMC-requiring wide
        # methods -- other workers would finish and idle for many
        # minutes waiting for the slow one. Small chunks keep IPC
        # overhead low while enabling work stealing.
        chunk_size = max(1, min(20, len(ids) // (args.parallel * 4) + 1))
        chunks: List[List[int]] = []
        for i in range(0, len(ids), chunk_size):
            chunks.append(ids[i:i + chunk_size])
        print(f"  {len(chunks)} chunks of ~{chunk_size} methods across {args.parallel} workers")
        with cf.ProcessPoolExecutor(max_workers=args.parallel) as pool:
            futures = [
                pool.submit(_worker, args.mch, args.core_root, chunk,
                            args.exhaustive_cutoff, args.mcmc_trials,
                            args.seed + ci, args.bbinstr_sample_rate)
                for ci, chunk in enumerate(chunks)
            ]
            for i, fut in enumerate(cf.as_completed(futures)):
                sub = fut.result()
                labels.update(sub)
                if (i + 1) % 4 == 0 or (i + 1) == len(futures):
                    print(f"  chunk {i+1}/{len(chunks)} done ({len(sub)} labels, "
                          f"total={len(labels)}, elapsed {time.time()-t0:.1f}s)")
                    _save_json(args.out, labels)
    else:
        rng = random.Random(args.seed)
        with SuperPmi(args.mch, args.core_root) as spmi:
            for i, method_id in enumerate(ids):
                label = _label_method(spmi, method_id, args.exhaustive_cutoff,
                                      args.mcmc_trials, rng,
                                      bbinstr_sample_rate=args.bbinstr_sample_rate)
                if label is not None:
                    labels[str(method_id)] = label
                if (i + 1) % 25 == 0:
                    _save_json(args.out, labels)
                    print(f"  {i+1}/{len(ids)}  elapsed {time.time()-t0:.1f}s  "
                          f"({len(labels)} labels total)")

    _save_json(args.out, labels)
    print(f"\nDone: {len(labels)} total labels in {args.out} "
          f"(elapsed {time.time()-t0:.1f}s)")

    # Quick gap summary.
    if labels:
        import numpy as np
        heur = np.array([v["heuristic_perfscore"] for v in labels.values()])
        opt = np.array([v["optimal_perfscore"] for v in labels.values()])
        nocse = np.array([v["no_cse_perfscore"] for v in labels.values()])
        # Filter out NaN
        valid = ~np.isnan(heur) & (heur > 0) & (opt > 0)
        if valid.sum() > 0:
            gap = (heur[valid] - opt[valid]) / heur[valid] * 100
            print(f"\nGap summary over {valid.sum()} valid methods:")
            print(f"  arith mean heur->opt improvement: {gap.mean():+.3f}%")
            print(f"  median: {np.median(gap):+.3f}%   max: {gap.max():+.3f}%")
            print(f"  methods where heur == opt: {(gap < 0.01).sum()} ({100*(gap<0.01).mean():.0f}%)")
            print(f"  methods with >1% gap:       {(gap > 1.0).sum()} ({100*(gap>1.0).mean():.0f}%)")
    return 0


def _save_json(path: str, obj: Dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f)
    os.replace(tmp, path)


if __name__ == "__main__":
    sys.exit(main())
