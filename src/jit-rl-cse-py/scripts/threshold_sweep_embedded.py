"""Threshold sweep: run the JIT-embedded imitation heuristic at several
thresholds and compare aggregate perf-scores vs baseline heuristic.

JitCseImitationThreshold is now a STRING config; pass float values
like "0.30" directly. Historical note: an earlier CONFIG_INTEGER
version hit the JIT's hex-parsing quirk (bare "300" == 0x300 = 768
= threshold 0.768 instead of the expected 0.30), which produced a
"threshold 0.30 pothole" that turned out to be pure config-parse
noise, not a real model artifact.
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
    p.add_argument("--limit", type=int, default=5000)
    p.add_argument("--thresholds", type=str, default="0.10,0.20,0.30,0.40,0.50,0.60",
                   help="Comma-separated float thresholds (e.g. \"0.20,0.30,0.40\").")
    args = p.parse_args()

    thresholds = [float(x.strip()) for x in args.thresholds.split(",")]
    print(f"Sweeping thresholds: {thresholds}")
    print(f"Sample: first {args.limit} methods of {os.path.basename(args.mch)}")

    heur_perf = {}
    t0 = time.time()
    with SuperPmi(args.mch, args.core_root) as spmi:
        for mid in range(1, args.limit + 1):
            try:
                m = spmi.jit_method(mid, JitMetrics=1, timeout=10)
            except Exception:
                continue
            if m is None or m.perf_score <= 0: continue
            heur_perf[mid] = m.perf_score
            if len(heur_perf) % 500 == 0:
                print(f"  heuristic baseline: {len(heur_perf)} methods ({time.time()-t0:.0f}s)")
    print(f"Heuristic baseline collected: {len(heur_perf)} methods in {time.time()-t0:.0f}s")

    results = {}
    for thr in thresholds:
        t1 = time.time()
        perfs = {}
        thr_str = f"{thr:.4f}"
        with SuperPmi(args.mch, args.core_root) as spmi:
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

    print(f"\n{'='*70}")
    print(f"Summary vs heuristic baseline ({len(heur_perf)} methods total):")
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

