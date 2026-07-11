"""Measure JIT throughput overhead of JitCseImitation=1 vs the default
heuristic. Runs superpmi replay end-to-end (no jitoptions) then repeats
with imitation enabled, and reports methods/sec + wall-clock delta.

Uses --parallel 1 to avoid measurement noise from IO contention.
"""
from __future__ import annotations
import argparse, subprocess, time, os, sys, re


def _run(superpmi: str, jit: str, mch: str, extra_options: list, verbose: bool = False) -> tuple:
    """Run superpmi replay, return (wall_time_sec, methods_jitted, methods_failed)."""
    params = [superpmi, jit, mch, "-v", "q"]
    for opt in extra_options:
        params.extend(["-jitoption", opt])
    t0 = time.time()
    proc = subprocess.run(params, capture_output=True, text=True, timeout=1800)
    elapsed = time.time() - t0
    out = proc.stdout + proc.stderr
    if verbose:
        # Print last ~10 lines of output for inspection
        for line in out.rstrip().split("\n")[-10:]:
            print(f"    {line}")
    jitted = 0
    failed = 0
    m = re.search(r"Loaded\s+(\d+)\s+Jitted\s+(\d+)\s+FailedCompile\s+(\d+)", out)
    if m:
        jitted = int(m.group(2))
        failed = int(m.group(3))
    return elapsed, jitted, failed


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True)
    p.add_argument("--n-runs", type=int, default=3,
                   help="Run each config N times and report best-of-N wall-clock.")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    superpmi = os.path.join(args.core_root, "superpmi.exe")
    jit = os.path.join(args.core_root, "clrjit.dll")

    configs = [
        ("heuristic (default)", []),
        ("imitation (t=0.30)", ["JitCseImitation=1", "JitCseImitationThreshold=0.30"]),
        ("imitation (t=0.30) w/ early emit", ["JitCseImitation=1", "JitCseImitationThreshold=0.30",
                                              "JitRLHookEmitEarly=1"]),
    ]

    results = {}
    for label, opts in configs:
        print(f"\n=== {label} ===")
        times = []
        for run in range(args.n_runs):
            wall, jitted, failed = _run(superpmi, jit, args.mch, opts, args.verbose)
            print(f"  run {run+1}: {wall:6.2f}s  jitted={jitted}  failed={failed}")
            times.append(wall)
        best = min(times)
        # Use jitted count from last run (they should all match)
        rate = jitted / best if best > 0 else 0
        results[label] = (best, jitted, rate)
        print(f"  best: {best:.2f}s  {rate:.0f} methods/sec")

    print("\n" + "=" * 70)
    print("Summary (best-of-N):")
    baseline = results["heuristic (default)"][0]
    for label, (wall, jitted, rate) in results.items():
        pct = (wall - baseline) / baseline * 100
        print(f"  {label:40s} {wall:6.2f}s  ({pct:+5.1f}% vs baseline)  {rate:.0f} m/s")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
