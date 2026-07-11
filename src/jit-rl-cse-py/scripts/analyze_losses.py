"""Loss deep-dive: characterize methods where JitCseImitation regresses
vs the heuristic on a given MCH.

For each losing method, records:
- method name (via MethodContext.name)
- num viable CSE candidates
- heuristic-applied subset + perfscore
- imit-applied subset + perfscore
- optimum subset (from labels if provided) + perfscore
- delta imit-vs-heur

Aggregates by benchmark class (namespace prefix) so we can see whether
losses cluster.
"""
from __future__ import annotations
import argparse, csv, json, os, sys, re
from collections import defaultdict
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from jitml.superpmi import SuperPmi


def _bench_class(fullname):
    if not fullname or fullname == "?":
        return "?"
    cls = fullname.rsplit(":", 1)[0] if ":" in fullname else fullname
    cls = re.sub(r"`\d+\[.*?\](?=[.$])", "", cls)
    return cls


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True)
    p.add_argument("--limit", type=int, default=5000)
    p.add_argument("--threshold", type=str, default="0.30")
    p.add_argument("--optimum-labels", type=str, default=None)
    p.add_argument("--out-csv", type=str, required=True)
    args = p.parse_args()

    optima = {}
    if args.optimum_labels and os.path.exists(args.optimum_labels):
        with open(args.optimum_labels) as f:
            optima = json.load(f)
        print(f"Loaded {len(optima)} optimum labels")

    rows = []
    with SuperPmi(args.mch, args.core_root) as spmi:
        for mid in range(1, args.limit + 1):
            try:
                heur = spmi.jit_method(mid, JitMetrics=1, timeout=10)
            except Exception:
                continue
            if heur is None or heur.perf_score <= 0:
                continue
            try:
                imit = spmi.jit_method(mid, JitMetrics=1,
                                       JitCseImitation=1,
                                       JitCseImitationThreshold=args.threshold,
                                       timeout=10)
            except Exception:
                continue
            if imit is None or imit.perf_score <= 0:
                continue
            delta_pct = (imit.perf_score - heur.perf_score) / heur.perf_score * 100
            if delta_pct < 0.05:
                continue  # not a regression

            n_viable = sum(1 for c in heur.cse_candidates if c.viable) if heur.cse_candidates else 0
            opt_perf = None
            opt_n = None
            if optima and str(mid) in optima:
                lbl = optima[str(mid)]
                opt_perf = lbl.get("optimal_perfscore")
                opt_n = len(lbl.get("optimal_subset", []))

            rows.append({
                "method_id": mid,
                "name": heur.name,
                "compile_mode": heur.compile_mode,
                "n_viable": n_viable,
                "heur_perf": heur.perf_score,
                "heur_n": heur.num_cse,
                "imit_perf": imit.perf_score,
                "imit_n": imit.num_cse,
                "opt_perf": opt_perf,
                "opt_n": opt_n,
                "delta_pct": delta_pct,
            })
            if len(rows) % 25 == 0:
                print(f"  losses: {len(rows)}, last mid={mid}")

    print(f"\nTotal regressions: {len(rows)}")
    if not rows:
        return 0

    # Sort by absolute regression size
    rows.sort(key=lambda r: -r["delta_pct"])

    with open(args.out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["method_id", "name", "compile_mode", "n_viable",
                    "heur_perf", "heur_n", "imit_perf", "imit_n",
                    "opt_perf", "opt_n", "delta_pct"])
        for r in rows:
            w.writerow([r["method_id"], r["name"], r["compile_mode"],
                        r["n_viable"], f"{r['heur_perf']:.2f}", r["heur_n"],
                        f"{r['imit_perf']:.2f}", r["imit_n"],
                        f"{r['opt_perf']:.2f}" if r["opt_perf"] else "",
                        r["opt_n"] if r["opt_n"] is not None else "",
                        f"{r['delta_pct']:+.4f}"])
    print(f"Wrote {args.out_csv}")

    # Aggregate by benchmark class
    by_cls = defaultdict(list)
    for r in rows:
        by_cls[_bench_class(r["name"])].append(r["delta_pct"])

    print(f"\nTop 20 benchmark classes by mean regression:")
    ranked = sorted(by_cls.items(), key=lambda x: -np.mean(x[1]))
    for cls, deltas in ranked[:20]:
        print(f"  n={len(deltas):>3d}  mean_delta={np.mean(deltas):>+6.3f}%  "
              f"max_delta={max(deltas):>+6.3f}%  {cls}")

    # Aggregate by viable-cand count
    by_nv = defaultdict(list)
    for r in rows:
        by_nv[r["n_viable"]].append(r["delta_pct"])
    print(f"\nBy viable-candidate count:")
    for nv in sorted(by_nv.keys()):
        deltas = by_nv[nv]
        print(f"  n_viable={nv:>2d}: {len(deltas):>3d} methods, mean_delta={np.mean(deltas):+.3f}%")

    # Aggregate imit_n vs heur_n
    over_fire = sum(1 for r in rows if r["imit_n"] > r["heur_n"])
    under_fire = sum(1 for r in rows if r["imit_n"] < r["heur_n"])
    same = len(rows) - over_fire - under_fire
    print(f"\nApplied-subset comparison (imit vs heur):")
    print(f"  over-firing (imit_n > heur_n):  {over_fire} ({100*over_fire/len(rows):.1f}%)")
    print(f"  under-firing (imit_n < heur_n): {under_fire} ({100*under_fire/len(rows):.1f}%)")
    print(f"  same count:                     {same} ({100*same/len(rows):.1f}%)")

    # If optima available, gap-to-optimum analysis
    with_opt = [r for r in rows if r["opt_perf"] is not None and r["opt_perf"] > 0]
    if with_opt:
        gap_imit = np.array([(r["imit_perf"] - r["opt_perf"]) / r["opt_perf"] * 100 for r in with_opt])
        gap_heur = np.array([(r["heur_perf"] - r["opt_perf"]) / r["opt_perf"] * 100 for r in with_opt])
        print(f"\nGap-to-optimum (over {len(with_opt)} methods with labels):")
        print(f"  imit gap: mean={gap_imit.mean():+.3f}%  median={np.median(gap_imit):+.3f}%")
        print(f"  heur gap: mean={gap_heur.mean():+.3f}%  median={np.median(gap_heur):+.3f}%")
        # Cases where heur was AT optimum but imit missed
        heur_at_opt = sum(1 for g in gap_heur if abs(g) < 0.1)
        print(f"  heur was at-optimum (gap<0.1%): {heur_at_opt} of {len(with_opt)}")

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
