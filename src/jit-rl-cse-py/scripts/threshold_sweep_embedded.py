"""Threshold sweep: run the JIT-embedded imitation heuristic at several
thresholds and compare aggregate perf-scores vs baseline heuristic.

Because features gathered at CSE-phase-entry differ slightly from those
gathered at DumpMetrics-time (which is what v7 was trained on), a more
conservative threshold may partially compensate.

Runs each threshold in ONE superpmi streaming session -- much faster
than eval_embedded_v7.py's per-method 3-call pattern.
"""
from __future__ import annotations
import argparse, os, sys, time
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from jitml.superpmi import SuperPmi


def _eval_one(spmi, mid, threshold_x1000, want_heur=False):
    """Return dict of (imit_perf, heur_perf) or None."""
    try:
        imit = spmi.jit_method(mid, JitMetrics=1,
                               JitCseImitation=1,
                               JitCseImitationThreshold=threshold_x1000,
                               timeout=10)
    except Exception:
        return None
    if imit is None or imit.perf_score <= 0:
        return None
    if not want_heur:
        return {"imit": imit.perf_score, "cse_n": imit.num_cse}
    try:
        heur = spmi.jit_method(mid, JitMetrics=1, timeout=10)
    except Exception:
        return None
    if heur is None or heur.perf_score <= 0:
        return None
    return {"imit": imit.perf_score, "heur": heur.perf_score, "cse_n": imit.num_cse}


def _summary(name, deltas):
    valid = ~np.isnan(deltas) & np.isfinite(deltas)
    if not valid.any():
        print(f"  {name}: no data"); return
    d = deltas[valid]
    b = (d < -0.05).sum(); w = (d > 0.05).sum(); s = len(d) - b - w
    arith = d.mean()
    ratios = 1.0 + d/100.0
    geo = (np.exp(np.log(ratios[ratios>0]).mean()) - 1) * 100
    print(f"  {name:20s} n={len(d):>4d}  b/s/w={b:>4d}/{s:>4d}/{w:>4d}  "
          f"arith={arith:+.3f}%  geo={geo:+.3f}%")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True)
    p.add_argument("--limit", type=int, default=5000)
    p.add_argument("--thresholds", type=str, default="300,400,500",
                   help="Comma-separated thresholds in x1000 fixed-point (e.g. 300 = 0.30)")
    args = p.parse_args()

    thresholds = [int(x) for x in args.thresholds.split(",")]
    print(f"Sweeping thresholds {thresholds} on first {args.limit} methods of {os.path.basename(args.mch)}")

    # Collect heuristic baseline once, in a single session.
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

    # For each threshold, collect imitation perf.
    results = {}  # thr -> {mid: perf}
    for thr in thresholds:
        t1 = time.time()
        perfs = {}
        with SuperPmi(args.mch, args.core_root) as spmi:
            for mid in heur_perf.keys():
                try:
                    m = spmi.jit_method(mid, JitMetrics=1,
                                        JitCseImitation=1,
                                        JitCseImitationThreshold=thr,
                                        timeout=10)
                except Exception:
                    continue
                if m is None or m.perf_score <= 0: continue
                perfs[mid] = m.perf_score
        results[thr] = perfs
        print(f"Threshold {thr/1000:.2f}: {len(perfs)} methods in {time.time()-t1:.0f}s")

    print(f"\n{'='*70}")
    print(f"Summary vs heuristic baseline ({len(heur_perf)} methods total):")
    for thr in thresholds:
        perfs = results[thr]
        common = sorted(set(heur_perf) & set(perfs))
        h = np.array([heur_perf[m] for m in common])
        i = np.array([perfs[m] for m in common])
        d = (i - h) / h * 100
        _summary(f"threshold={thr/1000:.2f}", d)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
