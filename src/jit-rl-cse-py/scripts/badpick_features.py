"""Per-candidate analysis: what distinguishes candidates the hand-crafted
heuristic picks INCORRECTLY (bad picks — heur says yes, MCMC-optimum says no)
from candidates it picks CORRECTLY (both say yes)?

For each MCH+labels pair, this:
  1. Jits each method via SPMI with feature-emit hooks (JitRLHookEmitFeatureNames)
  2. For every candidate, looks up:
       - `heuristic_cses` (what heur picked)  — from label JSON
       - `optimal_subset` (what MCMC picked)  — from label JSON
     and classifies as one of:
       - kept_both       (both say yes)
       - bad_pick        (heur says yes, opt says no)  ← target of analysis
       - missed          (heur says no,  opt says yes)
       - rejected_both   (both say no)
  3. Aggregates per-feature statistics for bad_pick vs kept_both.
     Feature is a "discriminator" if its bad_pick vs kept_both distributions
     are well-separated (KS-like statistic).

Output: a summary table showing feature discriminators sorted by informative
strength (higher = better simple-rule candidate).
"""
import argparse
import json
import math
import os
import statistics
import sys
from collections import defaultdict
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jitml.superpmi import SuperPmi
from jitml.jit_cse import PER_CANDIDATE_SCHEMA


CANDIDATE_FEATURE_NAMES = [name for name, _ in PER_CANDIDATE_SCHEMA]


def collect(mch: str, core_root: str, labels_path: str, jit_path: Optional[str],
            gap_threshold: float, sample_limit: int
            ) -> Dict[str, List[List[float]]]:
    """For each candidate, classify and record its feature vector."""
    with open(labels_path, encoding="utf-8") as f:
        all_labels = json.load(f)

    # Filter to methods with gap > threshold. Sort by gap descending to get
    # the worst cases first (informative for the analysis budget).
    sel: List[tuple] = []
    for mid, rec in all_labels.items():
        heur = rec.get("heuristic_perfscore")
        opt = rec.get("optimal_perfscore")
        if heur is None or opt is None or heur <= 0:
            continue
        gap = (heur - opt) / heur * 100.0
        if gap > gap_threshold:
            sel.append((gap, int(mid), rec))
    sel.sort(key=lambda x: -x[0])
    if sample_limit and sample_limit > 0:
        sel = sel[:sample_limit]

    print(f"Analyzing {len(sel)} methods with gap > {gap_threshold}%")

    # Buckets of raw feature vectors, keyed by classification.
    buckets: Dict[str, List[List[float]]] = {
        "kept_both": [],
        "bad_pick": [],
        "missed": [],
        "rejected_both": [],
    }
    processed = 0
    with SuperPmi(mch, core_root, jit_path=jit_path) as spmi:
        for gap, mid, rec in sel:
            processed += 1
            if processed % 100 == 0:
                print(f"  {processed}/{len(sel)}...")
            try:
                m = spmi.jit_method(
                    mid,
                    JitMetrics=1,
                    JitRLHook=1,
                    JitRLHookEmitFeatureNames=1,
                    # Use empty subset to trigger "listing" mode; per-candidate
                    # features are printed via JitRLHookEmitFeatures.
                    JitRLHookCSEDecisions=[],
                )
            except Exception as e:  # noqa: BLE001
                continue
            if m is None:
                continue
            feats = m.candidate_features  # (n_cand, n_features)
            if feats is None or len(feats) == 0:
                continue

            heur_set = set(rec.get("heuristic_cses", []))
            opt_set = set(rec.get("optimal_subset", []))
            # Note: heuristic_cses and optimal_subset are indexed differently:
            # optimal_subset uses candidate-array indices (0..n_cand-1) matching
            # the feature-array order. heuristic_cses uses JIT's internal cse index.
            # We need to map. Look at m.viable_indices which are the same array
            # indices as feats.
            viable = m.viable_indices  # List[int] of array indices
            # Map heur_set (JIT internal indices) to array indices.
            # m.candidates is aligned with feats.
            # See jit_cse.py MethodContext. Look at heur_selected_indices helper
            # if present, else derive: labels' heuristic_cses is JIT internal;
            # we compare against m.heuristic_selection which returns array indices.
            try:
                heur_arr_idx = set(m.heuristic_selected_indices())
            except AttributeError:
                # Fallback: match by 'make_cse' feature (candidate.MakeCSE flag)
                make_cse_col = CANDIDATE_FEATURE_NAMES.index("make_cse")
                heur_arr_idx = {i for i, row in enumerate(feats) if row[make_cse_col] > 0.5}

            for i, row in enumerate(feats):
                if i not in viable:
                    # non-viable candidates are auto-no-ops; skip
                    continue
                heur_yes = i in heur_arr_idx
                opt_yes = i in opt_set
                if heur_yes and opt_yes:
                    key = "kept_both"
                elif heur_yes and not opt_yes:
                    key = "bad_pick"
                elif not heur_yes and opt_yes:
                    key = "missed"
                else:
                    key = "rejected_both"
                buckets[key].append(list(row))

    return buckets


def summarize(buckets: Dict[str, List[List[float]]]) -> None:
    n_features = len(CANDIDATE_FEATURE_NAMES)
    print()
    print("BUCKET SIZES")
    print("-" * 60)
    for k, v in buckets.items():
        print(f"  {k:<15}: {len(v)}")

    kept_both = buckets["kept_both"]
    bad_pick = buckets["bad_pick"]

    if not bad_pick or not kept_both:
        print("Not enough data for bad-pick analysis")
        return

    # For each feature: compute mean(kept_both) vs mean(bad_pick), difference
    # normalized by pooled stddev (Cohen's d style).
    print()
    print(f"FEATURE DISCRIMINATOR RANKING  (kept_both n={len(kept_both)} vs bad_pick n={len(bad_pick)})")
    print("-" * 80)
    print(f"{'feature':<30} {'good_mean':>10} {'bad_mean':>10} {'diff':>7} {'|d|':>6}")

    ranked = []
    for j in range(n_features):
        good_vals = [row[j] for row in kept_both]
        bad_vals = [row[j] for row in bad_pick]
        good_mean = statistics.mean(good_vals)
        bad_mean = statistics.mean(bad_vals)
        try:
            good_sd = statistics.stdev(good_vals) if len(good_vals) > 1 else 0.0
            bad_sd = statistics.stdev(bad_vals) if len(bad_vals) > 1 else 0.0
        except statistics.StatisticsError:
            good_sd = bad_sd = 0.0
        pooled = math.sqrt((good_sd**2 + bad_sd**2) / 2) or 1e-9
        d = (bad_mean - good_mean) / pooled
        diff = bad_mean - good_mean
        ranked.append((abs(d), j, good_mean, bad_mean, diff, d))

    ranked.sort(key=lambda x: -x[0])
    for _absd, j, good_mean, bad_mean, diff, d in ranked[:20]:
        name = CANDIDATE_FEATURE_NAMES[j]
        print(f"{name:<30} {good_mean:>10.3f} {bad_mean:>10.3f} {diff:>+7.3f} {abs(d):>6.3f}")

    # For BOOL / one-hot features (name starts with type_ or is a known bool),
    # print rate difference explicitly.
    print()
    print("BOOL FEATURE RATE DIFF (kept_both% -> bad_pick%)")
    print("-" * 60)
    bool_feats = [j for j, name in enumerate(CANDIDATE_FEATURE_NAMES)
                  if name.startswith("type_") or name in {
                      "can_apply", "live_across_call", "const", "shared_const",
                      "make_cse", "has_call", "containable", "const_and_live",
                      "const_and_min_cost", "min_cost_and_live",
                      "containable_and_low_cost", "live_across_call_lsra"}]
    rows = []
    for j in bool_feats:
        good_rate = statistics.mean([row[j] for row in kept_both])
        bad_rate = statistics.mean([row[j] for row in bad_pick])
        rows.append((abs(bad_rate - good_rate), j, good_rate, bad_rate))
    rows.sort(key=lambda x: -x[0])
    for _abs, j, gr, br in rows[:15]:
        name = CANDIDATE_FEATURE_NAMES[j]
        print(f"{name:<30} {100*gr:>6.1f}%  ->  {100*br:>6.1f}%   (delta {100*(br-gr):+.1f}pp)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--core_root", required=True)
    ap.add_argument("--mch", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--jit-path", default=None)
    ap.add_argument("--gap-threshold", type=float, default=5.0,
                    help="Only analyze methods with heur→optimum gap > this pct (default 5)")
    ap.add_argument("--limit", type=int, default=500,
                    help="Cap number of methods (default 500).")
    args = ap.parse_args()

    buckets = collect(args.mch, args.core_root, args.labels,
                      args.jit_path, args.gap_threshold, args.limit)
    summarize(buckets)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
