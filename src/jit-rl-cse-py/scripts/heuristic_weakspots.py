"""Analyze heuristic weak spots: methods where the hand-crafted CSE heuristic
is far from MCMC-optimum. Pool all our labeled sources and rank by gap.

For each of the top-N worst methods:
- Show n_candidates, n_viable, heur_perfscore, optimum_perfscore, gap%
- Show heur_cses (what the heur chose) vs optimal_subset (MCMC winner)
- Group by "n_candidates" bucket to see if there's a size regime where heur fails most

Also compute aggregate statistics per source:
- What fraction of methods have >5% gap?
- What's the P90/P95/P99 gap?
- Which source is worst?

Output: worst-cases printable summary + a JSON with top-500 methods for
follow-up SPMI feature-inspection.
"""
import argparse
import json
import os
import statistics
import sys
from collections import Counter, defaultdict
from typing import Dict, List, Tuple


def load_labels(path: str) -> Dict[str, dict]:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def gap_pct(heur: float, opt: float) -> float:
    """+gap means heuristic is worse than optimum (lower perf-score is better).

    Returns absolute gap in percent of the heur score.
    """
    if heur <= 0:
        return 0.0
    return (heur - opt) / heur * 100.0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sources", nargs="+", required=True,
                    help="Label JSON files to pool (from label_optimal.py)")
    ap.add_argument("--top", type=int, default=200,
                    help="Show top-N worst methods by gap")
    ap.add_argument("--out", default=None,
                    help="Write per-method info as JSON here")
    args = ap.parse_args()

    per_source: Dict[str, List[dict]] = {}
    all_records: List[Tuple[float, str, str, dict]] = []  # (gap_pct, source, method_id, record)
    for src_path in args.sources:
        src = os.path.basename(os.path.dirname(src_path)) or os.path.basename(src_path)
        labels = load_labels(src_path)
        per_source[src] = []
        for mid, rec in labels.items():
            heur = rec.get("heuristic_perfscore")
            opt = rec.get("optimal_perfscore")
            if heur is None or opt is None:
                continue
            gap = gap_pct(heur, opt)
            per_source[src].append(gap)
            all_records.append((gap, src, mid, rec))

    print("=" * 72)
    print(f"POOLED SUMMARY  n_methods={len(all_records)}")
    print("=" * 72)
    all_gaps = [g for g, _, _, _ in all_records]
    all_gaps.sort()
    print(f"  mean gap: {statistics.mean(all_gaps):.3f}%")
    print(f"  median:   {statistics.median(all_gaps):.3f}%")
    print(f"  P90:      {all_gaps[int(len(all_gaps)*0.90)]:.3f}%")
    print(f"  P95:      {all_gaps[int(len(all_gaps)*0.95)]:.3f}%")
    print(f"  P99:      {all_gaps[int(len(all_gaps)*0.99)]:.3f}%")
    print(f"  max:      {max(all_gaps):.3f}%")
    n_over_1 = sum(1 for g in all_gaps if g > 1.0)
    n_over_5 = sum(1 for g in all_gaps if g > 5.0)
    n_over_10 = sum(1 for g in all_gaps if g > 10.0)
    print(f"  gap > 1%:  {n_over_1} ({100*n_over_1/len(all_gaps):.1f}%)")
    print(f"  gap > 5%:  {n_over_5} ({100*n_over_5/len(all_gaps):.1f}%)")
    print(f"  gap > 10%: {n_over_10} ({100*n_over_10/len(all_gaps):.1f}%)")

    print()
    print("PER-SOURCE SUMMARY")
    print("-" * 72)
    print(f"{'source':<35} {'n':>6} {'mean':>7} {'P95':>7} {'>5%':>6} {'>10%':>6}")
    for src, gaps in sorted(per_source.items()):
        gaps_sorted = sorted(gaps)
        p95 = gaps_sorted[int(len(gaps_sorted)*0.95)]
        over5 = sum(1 for g in gaps if g > 5)
        over10 = sum(1 for g in gaps if g > 10)
        print(f"{src:<35} {len(gaps):>6} {statistics.mean(gaps):>6.2f}% {p95:>6.2f}% "
              f"{over5:>5} {over10:>5}")

    # Bucket by n_candidates
    print()
    print("BY n_candidates BUCKET")
    print("-" * 72)
    print(f"{'bucket':<12} {'n_methods':>10} {'mean_gap':>10} {'P95_gap':>10} {'frac>5%':>10}")
    by_ncand: Dict[int, List[float]] = defaultdict(list)
    for gap, _src, _mid, rec in all_records:
        n = rec.get("n_candidates", 0)
        # Bucket by 1, 2, 3, 4-5, 6-9, 10-19, 20+
        if n <= 3:
            bucket = f"n={n}"
        elif n <= 5:
            bucket = "n=4-5"
        elif n <= 9:
            bucket = "n=6-9"
        elif n <= 19:
            bucket = "n=10-19"
        else:
            bucket = "n>=20"
        by_ncand[bucket].append(gap)

    # Preserve ordering
    for bucket in ["n=0", "n=1", "n=2", "n=3", "n=4-5", "n=6-9", "n=10-19", "n>=20"]:
        if bucket not in by_ncand:
            continue
        gaps = by_ncand[bucket]
        gaps_sorted = sorted(gaps)
        p95 = gaps_sorted[int(len(gaps_sorted)*0.95)] if gaps_sorted else 0
        over5 = sum(1 for g in gaps if g > 5)
        print(f"{bucket:<12} {len(gaps):>10} {statistics.mean(gaps):>9.2f}% {p95:>9.2f}% "
              f"{100*over5/len(gaps):>9.2f}%")

    # Sort all methods by gap descending
    all_records.sort(key=lambda x: -x[0])

    print()
    print(f"TOP {args.top} WORST METHODS")
    print("-" * 72)
    print(f"{'gap%':>7} {'source':<25} {'mid':>7} {'n_cand':>6} {'n_viable':>8} "
          f"{'n_heur':>7} {'n_opt':>6}")
    for gap, src, mid, rec in all_records[:args.top]:
        n_c = rec.get("n_candidates", 0)
        n_v = rec.get("n_viable", 0)
        n_h = len(rec.get("heuristic_cses", []))
        n_o = len(rec.get("optimal_subset", []))
        print(f"{gap:>6.2f}% {src:<25} {mid:>7} {n_c:>6} {n_v:>8} {n_h:>7} {n_o:>6}")

    # Heuristic-direction analysis: is heur under-selecting or over-selecting vs optimum?
    print()
    print("DIRECTION OF FAILURE (n_heur vs n_opt) for methods with >5% gap")
    print("-" * 72)
    under = over = same = 0
    delta_hist = Counter()
    for gap, _src, _mid, rec in all_records:
        if gap <= 5.0:
            continue
        n_h = len(rec.get("heuristic_cses", []))
        n_o = len(rec.get("optimal_subset", []))
        d = n_h - n_o  # positive = heur picked more than optimum
        delta_hist[d] += 1
        if d < 0:
            under += 1
        elif d > 0:
            over += 1
        else:
            same += 1
    total = under + over + same
    if total:
        print(f"  heur picked FEWER than optimum: {under} ({100*under/total:.1f}%)")
        print(f"  heur picked SAME COUNT as opt:  {same} ({100*same/total:.1f}%)")
        print(f"  heur picked MORE than optimum:  {over} ({100*over/total:.1f}%)")
        print(f"  histogram of n_heur - n_opt (top 10):")
        for d, c in sorted(delta_hist.items(), key=lambda x: -x[1])[:10]:
            sign = "+" if d > 0 else ""
            print(f"    {sign}{d:>3}: {c}")

    # Write JSON if requested
    if args.out:
        out_data = [
            {
                "gap_pct": gap,
                "source": src,
                "method_id": mid,
                "n_candidates": rec.get("n_candidates"),
                "n_viable": rec.get("n_viable"),
                "heuristic_cses": rec.get("heuristic_cses", []),
                "optimal_subset": rec.get("optimal_subset", []),
                "heuristic_perfscore": rec.get("heuristic_perfscore"),
                "optimal_perfscore": rec.get("optimal_perfscore"),
                "no_cse_perfscore": rec.get("no_cse_perfscore"),
            }
            for gap, src, mid, rec in all_records
        ]
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out_data, f, indent=1)
        print(f"\nWrote {args.out} ({len(out_data)} records)")

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
