"""Find methods where JitCseImitationThreshold=0.30 is materially WORSE
than both 0.25 and 0.40. Prints the applied subset at each threshold
plus the sigmoid probs, so we can see whether removing certain low-prob
candidates hurts because of CSE-interaction (helper effect) or
per-candidate model calibration.
"""
from __future__ import annotations
import argparse, os, sys, re
import numpy as np
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from jitml.superpmi import SuperPmi


def _run(spmi, mid, thr_x1000, want_dump=False):
    kwargs = dict(JitMetrics=1, JitCseImitation=1,
                  JitCseImitationThreshold=thr_x1000, timeout=10)
    if want_dump:
        kwargs["JitCseImitationDump"] = 1
    try:
        m = spmi.jit_method(mid, **kwargs)
    except Exception:
        return None
    return m


def _extract_dump(spmi, mid, thr_x1000):
    """Run under JitCseImitationDump=1, capture the IMIT_PROBS + subset."""
    # Use jitgo via subprocess of superpmi -c to catch stdout
    import subprocess
    core = os.path.dirname(spmi.jit_path)
    superpmi = spmi.superpmi_path
    proc = subprocess.run([superpmi, "-c", str(mid), spmi.jit_path, spmi.mch,
                           "-jitoption", "JitCseImitation=1",
                           "-jitoption", "JitCseImitationDump=1",
                           "-jitoption", f"JitCseImitationThreshold={thr_x1000}",
                           "-jitoption", "JitMetrics=1"],
                          capture_output=True, text=True, timeout=30)
    text = proc.stdout
    probs_line = None
    for line in text.split("\n"):
        line = line.strip()
        if line.startswith("IMIT_PROBS,"):
            probs_line = line
            break
    if not probs_line:
        return None
    parts = probs_line.split(",")[1:]
    probs = [float(x) for x in parts]
    return probs


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True)
    p.add_argument("--limit", type=int, default=2000)
    args = p.parse_args()

    # Collect perfscores at three thresholds.
    perfs = {}   # mid -> {thr: perf}
    subsets_count = {}  # mid -> {thr: num_applied}
    with SuperPmi(args.mch, args.core_root) as spmi:
        for mid in range(1, args.limit + 1):
            row = {}
            counts = {}
            for thr in (250, 300, 400):
                m = _run(spmi, mid, thr)
                if m is None or m.perf_score <= 0:
                    row = None; break
                row[thr] = m.perf_score
                counts[thr] = m.num_cse
            if row is not None and len(row) == 3:
                perfs[mid] = row
                subsets_count[mid] = counts

    print(f"Collected 3-threshold perfscores for {len(perfs)} methods")

    # Find pothole methods: t=300 perf > max(t=250, t=400) by material margin
    pothole = []
    for mid, r in perfs.items():
        p25 = r[250]; p30 = r[300]; p40 = r[400]
        # both 25 and 40 improve on the pothole
        if p30 > 1.001 * p25 and p30 > 1.001 * p40:
            pothole.append((mid, r, subsets_count[mid]))

    print(f"Pothole methods (t=0.30 worse than both t=0.25 and t=0.40 by >0.1%): {len(pothole)}")
    pothole.sort(key=lambda x: -(x[1][300] - min(x[1][250], x[1][400])))

    print("\nTop 15 pothole methods by absolute regression:")
    print(f"{'mid':>5s}  {'p25':>10s} n25 {'p30':>10s} n30 {'p40':>10s} n40  d(25->30)  d(30->40)")
    for mid, r, cs in pothole[:15]:
        p25, p30, p40 = r[250], r[300], r[400]
        d1 = (p30 - p25) / p25 * 100
        d2 = (p40 - p30) / p30 * 100
        print(f"{mid:>5d}  {p25:>10.2f} n={cs[250]:>2d} {p30:>10.2f} n={cs[300]:>2d} "
              f"{p40:>10.2f} n={cs[400]:>2d}  {d1:>+6.2f}%  {d2:>+6.2f}%")

    # Aggregate: how much of the +0.27% at t=0.30 comes from pothole methods?
    total = 0.0
    total_pothole = 0.0
    heur_baseline = {}
    # For aggregate contribution, use t=0.40 as the "would-have-been-heuristic-like" proxy
    for mid, r in perfs.items():
        p30 = r[300]
        p_ref = r[400]  # use best-threshold as reference
        d = (p30 - p_ref) / p_ref * 100
        total += d
        if any(mid == pmid for pmid, _, _ in pothole):
            total_pothole += d
    if perfs:
        print(f"\nMean regression at t=0.30 vs t=0.40:")
        print(f"  all methods:      {total/len(perfs):+.3f}%")
        print(f"  pothole methods:  {total_pothole/max(1,len(pothole)):+.3f}%")
        print(f"  non-pothole:      {(total-total_pothole)/max(1,len(perfs)-len(pothole)):+.3f}%")

if __name__ == "__main__":
    sys.exit(main() or 0)
