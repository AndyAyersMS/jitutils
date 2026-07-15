"""Cross-source LACO parameter sweep via SPMI asmdiffs.

Runs superpmi.py asmdiffs for a grid of (Size, UseCount, UseCountKind,
RequireNotContainable) values across multiple MCHs and aggregates:
- Total PerfScore delta / Total bytes delta
- Number of contexts with diffs
- PerfScore improvements vs regressions

Rank each configuration by an aggregate score.
"""
import argparse
import csv
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from typing import Dict, List, Optional


def run_asmdiffs(base_jit: str, diff_jit: str, core_root: str, mch: str,
                 diff_env: Dict[str, str], target_arch: str, target_os: str
                 ) -> Optional[Dict]:
    """Run superpmi.py asmdiffs, return parsed summary dict or None on failure."""
    cmd = [
        "python", os.path.join(os.environ.get("RUNTIME_DIR", r"C:\repos\runtime4"),
                                "src", "coreclr", "scripts", "superpmi.py"),
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
    if result.returncode not in (0, 1):
        return None
    text = result.stdout + result.stderr

    def extract(pat, default=None, group=1):
        m = re.search(pat, text)
        return m.group(group) if m else default

    contexts = extract(r"(\d[\d,]*)\s+contexts with diffs", "0")
    perf_imp = extract(r"\((\d+)\s+PerfScore improvements,")
    perf_reg = extract(r"PerfScore improvements,\s+(\d+)\s+PerfScore regressions")
    perf_delta = extract(r"Total PerfScore of delta:\s+(-?[0-9.]+)")
    perf_delta_pct = extract(r"Total PerfScore of delta:\s+-?[0-9.]+\s+\((-?[0-9.]+)%")
    bytes_delta = extract(r"Total bytes of delta:\s+(-?[0-9,]+)")
    bytes_delta_pct = extract(r"Total bytes of delta:\s+-?[0-9,]+\s+\((-?[0-9.]+)%")
    geomean = extract(r"Relative PerfScore Geomean:\s+(-?[0-9.]+)%")

    def _int(s):
        try: return int((s or "0").replace(",", ""))
        except: return 0
    def _float(s):
        try: return float(s or "0")
        except: return 0.0

    return {
        "contexts": _int(contexts),
        "perf_imp": _int(perf_imp),
        "perf_reg": _int(perf_reg),
        "perf_delta": _float(perf_delta),
        "perf_delta_pct": _float(perf_delta_pct),
        "bytes_delta": _int(bytes_delta),
        "bytes_delta_pct": _float(bytes_delta_pct),
        "geomean_pct": _float(geomean),
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
    args = ap.parse_args()

    # Configurations to test.
    configs: List[Dict[str, str]] = []
    # Baseline: currently shipped
    for use_kind, kind_name in [(0, "wtd"), (1, "raw")]:
        for size in [6, 8, 10, 12, 16]:
            for uc in [1, 2, 3, 5, 8]:
                for require_not_containable in [0, 1]:
                    configs.append({
                        "name": f"S{size}_UC{uc}_{kind_name}_NC{require_not_containable}",
                        "env": {
                            "JitCseLacoVeto": "1",
                            "JitCseLacoVetoSizeThreshold": str(size),
                            "JitCseLacoVetoUseCountMax": str(uc),
                            "JitCseLacoVetoUseCountKind": str(use_kind),
                            "JitCseLacoVetoRequireNotContainable": str(require_not_containable),
                        },
                    })

    # This is a lot — 5 * 5 * 2 * 2 = 100 configs. Reduce for time budget:
    reduced = []
    for c in configs:
        name = c["name"]
        # Keep a manageable subset: SizeUC pairs at (6,3), (8,3), (10,3), (8,5), (12,5),
        # variants of use_kind for the most promising (S8_UC3 raw/wtd, S8_UC5 raw/wtd),
        # and NC=0 vs NC=1 for a small subset.
        if any(t in name for t in [
            "S6_UC3_wtd_NC0", "S6_UC3_raw_NC0",
            "S8_UC1_wtd_NC0", "S8_UC1_raw_NC0",
            "S8_UC2_wtd_NC0", "S8_UC2_raw_NC0",
            "S8_UC3_wtd_NC0", "S8_UC3_raw_NC0",
            "S8_UC3_wtd_NC1", "S8_UC3_raw_NC1",
            "S8_UC5_wtd_NC0", "S8_UC5_raw_NC0",
            "S8_UC8_raw_NC0",
            "S10_UC3_wtd_NC0", "S10_UC3_raw_NC0",
            "S12_UC3_wtd_NC0", "S12_UC3_raw_NC0",
            "S12_UC5_wtd_NC0", "S12_UC5_raw_NC0",
        ]):
            reduced.append(c)
    configs = reduced

    print(f"Testing {len(configs)} configurations across "
          f"{len(args.x64_mch)} x64 MCHs + {len(args.arm64_mch)} arm64 MCHs")

    with open(args.out_csv, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["mch", "arch", "config", "contexts", "perf_imp", "perf_reg",
                    "perf_delta_pct", "bytes_delta_pct", "geomean_pct"])

        for cfg in configs:
            for mch in args.x64_mch:
                mch_name = os.path.basename(mch).replace(".windows.x64.checked.mch", "")
                print(f"  x64 {mch_name}  {cfg['name']}...")
                r = run_asmdiffs(args.x64_base_jit, args.x64_diff_jit,
                                 args.core_root, mch, cfg["env"],
                                 "x64", "windows")
                if r:
                    w.writerow([mch_name, "x64", cfg["name"], r["contexts"],
                                r["perf_imp"], r["perf_reg"],
                                r["perf_delta_pct"], r["bytes_delta_pct"],
                                r["geomean_pct"]])
                    f.flush()
            for mch in args.arm64_mch:
                mch_name = os.path.basename(mch).replace(".linux.arm64.checked.mch", "").replace(".linux.arm64.Release.mch", "")
                print(f"  arm64 {mch_name}  {cfg['name']}...")
                r = run_asmdiffs(args.arm64_base_jit, args.arm64_diff_jit,
                                 args.core_root, mch, cfg["env"],
                                 "arm64", "linux")
                if r:
                    w.writerow([mch_name, "arm64", cfg["name"], r["contexts"],
                                r["perf_imp"], r["perf_reg"],
                                r["perf_delta_pct"], r["bytes_delta_pct"],
                                r["geomean_pct"]])
                    f.flush()

    print(f"\nWrote {args.out_csv}")


if __name__ == "__main__":
    sys.exit(main() or 0)
