"""Run BenchmarkDotNet on a set of methods with and without
JitCseImitation embedded in the runtime's clrjit.dll, and report
wall-clock delta alongside the perf-score delta we already have.

Uses `DOTNET_JitPath` to swap the JIT. Uses BDN's `--filter` and
`--runtimes` to select benchmarks.

Requirements:
* MicroBenchmarks project already built (see performance/README.md).
* dotnet SDK with net11.0 (uses repo-internal `.dotnet` by default).
* Release-mode clrjit.dll with imitation baked in.

Outputs a summary table to stdout + a CSV to --out-csv.
"""
from __future__ import annotations
import argparse, os, re, subprocess, sys, time, csv, glob, shutil, json


def _parse_bdn_json_report(json_path: str) -> dict:
    """Parse BDN's *-report-full.json and return {benchmark_key: mean_ns}."""
    with open(json_path, encoding="utf-8-sig") as f:
        data = json.load(f)
    out = {}
    for bench in data.get("Benchmarks", []):
        name = bench.get("MethodTitle") or bench.get("Method") or "?"
        params_dict = bench.get("Parameters", "")
        mean_ns = bench.get("Statistics", {}).get("Mean")
        if mean_ns is None:
            continue
        key = f"{name}[{params_dict}]" if params_dict else name
        out[key] = float(mean_ns)
    return out


def _run_bdn(dotnet: str, dll: str, filter_: str, corerun: str, imit: bool,
             threshold: str, workdir: str, save_dir: str, run_tag: str) -> dict:
    """Invoke BDN once via --corerun. Save its JSON reports under
    save_dir/run_tag/. Return dict {benchmark_key: mean_ns}."""

    # Clear results dir before invoking so we can precisely map the newest
    # *-report-full.json files to this run.
    results_dir = os.path.join(os.path.dirname(dll), "BenchmarkDotNet.Artifacts", "results")
    if os.path.exists(results_dir):
        for f in glob.glob(os.path.join(results_dir, "*-report-full.json")):
            try:
                os.remove(f)
            except OSError:
                pass

    params = [dotnet, "exec", dll, "--filter", filter_,
              "--coreRun", corerun]
    if imit:
        params.extend(["--envVars",
                       f"DOTNET_JitCseImitation:1",
                       f"DOTNET_JitCseImitationThreshold:{threshold}"])

    print(f"    running: {filter_} (imit={imit})", flush=True)
    t0 = time.time()
    proc = subprocess.run(params, cwd=workdir, capture_output=True, text=True, timeout=1800)
    elapsed = time.time() - t0
    print(f"      finished in {elapsed:.0f}s", flush=True)
    if proc.returncode != 0:
        print(f"      BDN exited {proc.returncode}", flush=True)
        for line in proc.stdout.split("\n")[-10:]:
            print(f"        {line}")
        for line in proc.stderr.split("\n")[-5:]:
            print(f"        stderr: {line}")

    # Collect the fresh JSON reports.
    save_run_dir = os.path.join(save_dir, run_tag)
    os.makedirs(save_run_dir, exist_ok=True)
    reports = glob.glob(os.path.join(results_dir, "*-report-full.json"))
    combined = {}
    for rep in reports:
        try:
            partial = _parse_bdn_json_report(rep)
            combined.update(partial)
            shutil.copy(rep, os.path.join(save_run_dir, os.path.basename(rep)))
        except Exception as e:
            print(f"      parse error {rep}: {e}")

    return combined


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--dotnet", default=r"C:\repos\runtime4\.dotnet\dotnet.exe")
    p.add_argument("--dll",
                   default=r"C:\repos\performance\artifacts\bin\MicroBenchmarks\Release\net11.0\MicroBenchmarks.dll")
    p.add_argument("--workdir",
                   default=r"C:\repos\performance\src\benchmarks\micro")
    p.add_argument("--corerun", required=True,
                   help="Path to corerun.exe in a Core_Root with the imitation-embedded clrjit.dll.")
    p.add_argument("--threshold", default="0.30")
    p.add_argument("--filter", action="append", required=True,
                   help="One or more BDN --filter patterns.")
    p.add_argument("--out-csv", required=True)
    p.add_argument("--save-dir", default=None,
                   help="Directory to copy BDN JSON reports into (default: alongside out-csv).")
    args = p.parse_args()

    save_dir = args.save_dir or os.path.join(os.path.dirname(os.path.abspath(args.out_csv)),
                                             "bdn_raw")
    os.makedirs(save_dir, exist_ok=True)

    all_baseline = {}
    all_imit = {}

    for filt in args.filter:
        print(f"\n=== filter: {filt} ===")
        tag = filt.strip('*').replace('*', '_').replace('.', '_').replace('+', '_').replace(':', '_')
        base = _run_bdn(args.dotnet, args.dll, filt, args.corerun, False,
                        args.threshold, args.workdir, save_dir, run_tag=f"baseline_{tag}")
        imit = _run_bdn(args.dotnet, args.dll, filt, args.corerun, True,
                        args.threshold, args.workdir, save_dir, run_tag=f"imit_{tag}")
        all_baseline.update(base)
        all_imit.update(imit)

    print("\n" + "=" * 80)
    print(f"{'Benchmark':60s}  {'base_ns':>12s}  {'imit_ns':>12s}  {'delta':>8s}")
    print("-" * 80)
    rows = []
    for name in sorted(set(all_baseline) & set(all_imit)):
        b = all_baseline[name]
        i = all_imit[name]
        delta_pct = (i - b) / b * 100
        print(f"{name[:60]:60s}  {b:>12.1f}  {i:>12.1f}  {delta_pct:>+7.2f}%")
        rows.append((name, b, i, delta_pct))

    with open(args.out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["benchmark", "baseline_ns", "imit_ns", "delta_pct"])
        for r in rows:
            w.writerow(r)
    print(f"\nWrote {args.out_csv}")

    if rows:
        deltas = [r[3] for r in rows]
        arith = sum(deltas) / len(deltas)
        import math
        geo = (math.exp(sum(math.log(1 + d/100) for d in deltas) / len(deltas)) - 1) * 100
        print(f"\nArith mean wall-clock delta: {arith:+.3f}%")
        print(f"Geo   mean wall-clock delta: {geo:+.3f}%")
        wins = sum(1 for d in deltas if d < -0.5)
        losses = sum(1 for d in deltas if d > 0.5)
        print(f"Wins ( <-0.5pp): {wins}   Losses (>+0.5pp): {losses}   Same: {len(deltas)-wins-losses}")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)

