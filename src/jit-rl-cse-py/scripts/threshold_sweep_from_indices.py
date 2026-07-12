"""Threshold sweep on a SPECIFIC set of method IDs from an indices file.
Useful when the MCH contains lots of trivial methods that dilute the
signal (e.g. arm64 where most Tier0 methods have zero CSE candidates).
"""
from __future__ import annotations
import argparse, os, sys, time
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from jitml.superpmi import SuperPmi


def _summary(name, deltas):
    valid = ~np.isnan(deltas) & np.isfinite(deltas)
    if not valid.any():
        print(f"  {name}: no data"); return
    d = deltas[valid]
    b = (d < -0.05).sum(); w = (d > 0.05).sum(); s = len(d) - b - w
    arith = d.mean()
    ratios = 1.0 + d/100.0
    geo = (np.exp(np.log(ratios[ratios > 0]).mean()) - 1) * 100
    print(f"  {name:24s} n={len(d):>4d}  b/s/w={b:>4d}/{s:>4d}/{w:>4d}  "
          f"arith={arith:+.3f}%  geo={geo:+.3f}%")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True)
    p.add_argument("--jit-path", default=None)
    p.add_argument("--indices", required=True)
    p.add_argument("--thresholds", type=str, default="0.20,0.30,0.40,0.50")
    args = p.parse_args()

    with open(args.indices) as f:
        method_ids = [int(x.strip()) for x in f if x.strip()]
    thresholds = [float(x.strip()) for x in args.thresholds.split(",")]
    print(f"Sweeping thresholds {thresholds} on {len(method_ids)} methods from indices file")

    heur_perf = {}
    with SuperPmi(args.mch, args.core_root, jit_path=args.jit_path) as spmi:
        for mid in method_ids:
            try:
                m = spmi.jit_method(mid, JitMetrics=1, timeout=10)
            except Exception:
                continue
            if m is None or m.perf_score <= 0: continue
            heur_perf[mid] = m.perf_score
    print(f"Heuristic baseline collected: {len(heur_perf)}")

    results = {}
    for thr in thresholds:
        t1 = time.time()
        perfs = {}
        thr_str = f"{thr:.4f}"
        with SuperPmi(args.mch, args.core_root, jit_path=args.jit_path) as spmi:
            for mid in heur_perf.keys():
                try:
                    m = spmi.jit_method(mid, JitMetrics=1,
                                        JitCseImitation=1,
                                        JitCseImitationThreshold=thr_str,
                                        timeout=10)
                except Exception:
                    continue
                if m is None or m.perf_score <= 0: continue
                perfs[mid] = m.perf_score
        results[thr] = perfs
        print(f"Threshold {thr:.3f}: {len(perfs)} methods in {time.time()-t1:.0f}s")

    print(f"\n{'='*70}\nSummary:")
    for thr in thresholds:
        perfs = results[thr]
        common = sorted(set(heur_perf) & set(perfs))
        h = np.array([heur_perf[m] for m in common])
        i = np.array([perfs[m] for m in common])
        d = (i - h) / h * 100
        _summary(f"threshold={thr:.3f}", d)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
