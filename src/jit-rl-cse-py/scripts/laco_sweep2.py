"""Focused LACO sweep — key configurations only, decimal thresholds via string config.
Runs in parallel where possible (async subprocess per MCH).
"""
import argparse
import csv
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


CONFIGS = [
    # (name, size, uc_max, uc_kind, require_not_containable)
    ("shipped_S8_UC3wtd_C",   "8",  "3",   0, 0),  # current default
    ("S8_UC1wtd_C",           "8",  "1",   0, 0),  # tighter UC
    ("S8_UC30wtd_C",          "8",  "30",  0, 0),  # in-between
    ("S8_UC100wtd_C",         "8",  "100", 0, 0),  # discriminator's best on arm64
    ("S8_UC300wtd_C",         "8",  "300", 0, 0),  # 3 unit-blocks
    ("S8_UC3raw_C",           "8",  "3",   1, 0),  # raw variant
    ("S8_UC5raw_C",           "8",  "5",   1, 0),  # raw variant
    ("S8_UC10raw_C",          "8",  "10",  1, 0),
    ("S8_UC3wtd_NC",          "8",  "3",   0, 1),  # + notContainable
    ("S8_UC100wtd_NC",        "8",  "100", 0, 1),
    ("S6_UC100wtd_C",         "6",  "100", 0, 0),  # lower Size
    ("S10_UC100wtd_C",        "10", "100", 0, 0),  # higher Size
    ("S12_UC100wtd_C",        "12", "100", 0, 0),  # decimal 12 (fixed with string)
    ("S16_UC100wtd_C",        "16", "100", 0, 0),  # decimal 16
    ("S8_UC30raw_C",          "8",  "30",  1, 0),
    ("S8_UC3wtd_C_off",       "0",  "0",   0, 0),  # off (Size=0 disables)
]


def run_asmdiffs(base_jit: str, diff_jit: str, core_root: str, mch: str,
                 diff_env, target_arch: str, target_os: str,
                 runtime_dir: str):
    cmd = [
        "python", os.path.join(runtime_dir, "src", "coreclr", "scripts", "superpmi.py"),
        "asmdiffs",
        "-base_jit_path", base_jit,
        "-diff_jit_path", diff_jit,
        "-core_root", core_root,
        "-mch_files", mch,
        "-target_arch", target_arch,
        "-target_os", target_os,
        "--no_progress",
    ]
    for k, v in diff_env.items():
        cmd += ["-diff_jit_option", f"{k}={v}"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    text = result.stdout + result.stderr

    def _ext(pat, default=None, group=1):
        m = re.search(pat, text)
        return m.group(group) if m else default

    def _i(s):
        try: return int((s or "0").replace(",", ""))
        except: return 0
    def _f(s):
        try: return float(s or "0")
        except: return 0.0

    return {
        "contexts":       _i(_ext(r"(\d[\d,]*)\s+contexts with diffs", "0")),
        "perf_imp":       _i(_ext(r"\((\d+)\s+PerfScore improvements,")),
        "perf_reg":       _i(_ext(r"PerfScore improvements,\s+(\d+)\s+PerfScore regressions")),
        "perf_delta":     _f(_ext(r"Total PerfScore of delta:\s+(-?[0-9.]+)")),
        "perf_delta_pct": _f(_ext(r"Total PerfScore of delta:\s+-?[0-9.]+\s+\((-?[0-9.]+)%")),
        "bytes_delta":    _i(_ext(r"Total bytes of delta:\s+(-?[0-9,]+)")),
        "bytes_delta_pct":_f(_ext(r"Total bytes of delta:\s+-?[0-9,]+\s+\((-?[0-9.]+)%")),
        "geomean_pct":    _f(_ext(r"Relative PerfScore Geomean:\s+(-?[0-9.]+)%")),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--core-root", required=True)
    ap.add_argument("--x64-base-jit", required=True)
    ap.add_argument("--x64-diff-jit", required=True)
    ap.add_argument("--arm64-base-jit", required=True)
    ap.add_argument("--arm64-diff-jit", required=True)
    ap.add_argument("--x64-mch", action="append", default=[])
    ap.add_argument("--arm64-mch", action="append", default=[])
    ap.add_argument("--out-csv", required=True)
    ap.add_argument("--parallel", type=int, default=3)
    ap.add_argument("--runtime-dir", default=r"C:\repos\runtime4")
    args = ap.parse_args()

    tasks = []
    for cfg in CONFIGS:
        name, size, uc, uc_kind, nc = cfg
        env = {
            "JitCseLacoVeto": "1",
            "JitCseLacoVetoSizeThreshold": size,
            "JitCseLacoVetoUseCountMax": uc,
            "JitCseLacoVetoUseCountKind": str(uc_kind),
            "JitCseLacoVetoRequireNotContainable": str(nc),
        }
        for mch in args.x64_mch:
            mch_name = os.path.basename(mch).replace(".windows.x64.checked.mch", "")
            tasks.append(("x64", mch_name, name, args.x64_base_jit, args.x64_diff_jit, args.core_root, mch, env, "x64", "windows"))
        for mch in args.arm64_mch:
            mch_name = os.path.basename(mch).replace(".linux.arm64.checked.mch", "").replace(".linux.arm64.Release.mch", "")
            tasks.append(("arm64", mch_name, name, args.arm64_base_jit, args.arm64_diff_jit, args.core_root, mch, env, "arm64", "linux"))

    print(f"Running {len(tasks)} tasks with parallel={args.parallel}")

    with open(args.out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["arch", "mch", "config", "contexts", "perf_imp", "perf_reg",
                    "perf_delta_pct", "bytes_delta_pct", "geomean_pct"])
        f.flush()

        with ThreadPoolExecutor(max_workers=args.parallel) as ex:
            futures = {}
            for t in tasks:
                arch, mch_name, cfg_name, base_jit, diff_jit, core_root, mch, env, ta, tos = t
                fut = ex.submit(run_asmdiffs, base_jit, diff_jit, core_root, mch, env, ta, tos, args.runtime_dir)
                futures[fut] = (arch, mch_name, cfg_name)
            done = 0
            for fut in as_completed(futures):
                arch, mch_name, cfg_name = futures[fut]
                done += 1
                try:
                    r = fut.result()
                    if r:
                        w.writerow([arch, mch_name, cfg_name, r["contexts"],
                                    r["perf_imp"], r["perf_reg"],
                                    r["perf_delta_pct"], r["bytes_delta_pct"],
                                    r["geomean_pct"]])
                        f.flush()
                        print(f"  {done}/{len(tasks)}  {arch} {mch_name} {cfg_name}: contexts={r['contexts']} imp/reg={r['perf_imp']}/{r['perf_reg']}")
                    else:
                        print(f"  {done}/{len(tasks)}  {arch} {mch_name} {cfg_name}: FAILED")
                except Exception as e:
                    print(f"  {done}/{len(tasks)}  {arch} {mch_name} {cfg_name}: ERROR {e}")


if __name__ == "__main__":
    sys.exit(main() or 0)
