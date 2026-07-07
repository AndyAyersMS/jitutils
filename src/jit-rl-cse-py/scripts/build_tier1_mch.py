"""Build train.mch and test.mch containing only PGO-calibrated Tier1
(and optionally Tier1-OSR) methods extracted from a set of source
MCH files.

Uses ``mcs -dumpMap`` to enumerate method contexts with their JIT
flag list (fast, no JIT invocation). Filters for the ``TIER1`` +
``HAS_PGO`` flag combo (weighted-count features are calibrated to
real execution frequencies). ``--include-osr`` optionally accepts
the same combo but with the ``OSR`` flag also set (on-stack
replacement variants).

Pipeline:

  1. ``mcs -dumpMap`` each source MCH -> parse CSV -> identify
     method indices that match the filter and whose ``num_cand``
     is in ``[MIN_CSE, MAX_CSE]``. Write a ``.mcl`` file per source.
     (``num_cand`` is NOT in dumpMap output, so we also cross-
     reference the parsed method-context stream via jitml.SuperPmi
     -- but only for the surviving indices, not the whole MCH.)
     Actually: we accept ALL Tier1+PGO methods regardless of
     num_cand at this stage, and rely on the training pipeline's
     ``is_acceptable_for_cse`` filter to skip methods without
     enough candidates at load time. This keeps this script fast.

  2. ``mcs -copy <mcl> <src.mch> <subset.mch>`` extracts each source's
     surviving indices into a per-source subset MCH.

  3. ``mcs -merge combined.mch <staging>\\*.mch -dedup`` merges the
     subsets into one MCH, dropping duplicates.

  4. Combined MCH is split into ``train.mch`` and ``test.mch`` at
     ``--train-size`` / ``--test-size`` methods using a seeded random
     permutation (via two more ``.mcl`` files + ``mcs -copy``).

All intermediate ``.mcl`` / subset MCH files are kept in
``<output-dir>/staging/`` for inspection.

Usage:

    python scripts/build_tier1_mch.py \\
        --core_root <PATH> \\
        --mch-dir C:\\spmi\\mch\\<GUID>\\ \\
        --sources aspnet2.run.windows.x64.checked.mch \\
                  libraries_tests.run.windows.x64.Release.mch \\
                  benchmarks.run_pgo.windows.x64.checked.mch \\
        --output-dir C:\\spmi\\mch-tier1 \\
        --train-size 5000 --test-size 1000 --include-osr
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import random
import subprocess
import sys
from typing import List, Optional


def dump_map(core_root: str, mch: str) -> str:
    """Run ``mcs -dumpMap`` on ``mch`` and return the CSV output as a
    single string (fast, no JIT invocation, ~7s per GB of MCH)."""
    mcs = os.path.join(core_root, "mcs.exe")
    result = subprocess.run(
        [mcs, "-v", "q", "-dumpMap", mch],
        capture_output=True, text=True, check=True,
    )
    return result.stdout


def parse_and_filter_map(csv_text: str, include_osr: bool) -> List[int]:
    """Parse the ``mcs -dumpMap`` CSV output and return indices of
    methods whose JIT flag string contains ``TIER1`` and ``HAS_PGO``.
    OSR variants are gated by ``include_osr``.

    Columns of the CSV (from dumpMap): index, method name, full sig,
    jit flags, os. The flag column is a space-separated list of tokens
    like ``DEBUG_INFO``, ``TIER1``, ``HAS_PGO``, ``OSR``.
    """
    kept: List[int] = []
    reader = csv.reader(io.StringIO(csv_text))
    header = next(reader, None)
    if header is None or header[0].strip().lower() != "index":
        raise ValueError("dumpMap output missing expected header row")

    for row in reader:
        if len(row) < 4:
            continue
        try:
            idx = int(row[0])
        except ValueError:
            continue
        flags = row[3].strip().split()
        if "TIER1" not in flags:
            continue
        if "HAS_PGO" not in flags:
            continue
        if "OSR" in flags and not include_osr:
            continue
        kept.append(idx)
    return kept


def write_mcl(indices: List[int], path: str) -> None:
    """mcs expects a sorted list of line-delimited indices (1-based)."""
    indices = sorted(set(indices))
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        for i in indices:
            f.write(f"{i}\n")


def run_mcs(core_root: str, args: List[str]) -> None:
    """Invoke mcs.exe with the given argv suffix. Raises on non-zero exit."""
    mcs = os.path.join(core_root, "mcs.exe")
    cmd = [mcs, "-v", "n"] + args
    print(f"  $ mcs {' '.join(args)}")
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        print(result.stdout)
        print(result.stderr, file=sys.stderr)
        raise SystemExit(f"mcs.exe exited {result.returncode}")


def count_methods_in_mch(core_root: str, mch: str) -> int:
    """Fast per-method count via ``mcs -dumpMap`` line count (minus header)."""
    out = dump_map(core_root, mch)
    return max(sum(1 for line in out.splitlines() if line.strip()) - 1, 0)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--core_root", required=True,
                    help="Path to Core_Root containing mcs.exe.")
    ap.add_argument("--mch-dir", required=True,
                    help="Directory containing the source MCH files.")
    ap.add_argument("--sources", nargs="+", required=True,
                    help="Filenames (relative to --mch-dir) of source MCH files.")
    ap.add_argument("--output-dir", required=True,
                    help="Directory to write train.mch, test.mch, and staging/*.")
    ap.add_argument("--train-size", type=int, required=True,
                    help="Number of methods to put in train.mch.")
    ap.add_argument("--test-size", type=int, required=True,
                    help="Number of methods to put in test.mch (disjoint from train).")
    ap.add_argument("--include-osr", action="store_true",
                    help="Also accept methods with the OSR flag (default: skip OSR variants).")
    ap.add_argument("--seed", type=int, default=42,
                    help="Random seed for the train/test split.")
    ap.add_argument("--dry-run", action="store_true",
                    help="Scan + report counts; skip the mcs -copy / -merge steps.")
    args = ap.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    staging = os.path.join(args.output_dir, "staging")
    os.makedirs(staging, exist_ok=True)

    tag_desc = "TIER1+HAS_PGO (incl. OSR)" if args.include_osr else "TIER1+HAS_PGO (no OSR)"
    print(f"Building {tag_desc} MCH from {len(args.sources)} sources...")

    # Step 1: mcs -dumpMap each source, filter, write .mcl.
    per_source_kept = {}
    for src in args.sources:
        mch = os.path.join(args.mch_dir, src)
        if not os.path.exists(mch):
            print(f"  MISSING: {mch}", file=sys.stderr)
            return 2
        print(f"\n[dumpMap] {src}")
        csv_text = dump_map(args.core_root, mch)
        kept = parse_and_filter_map(csv_text, args.include_osr)
        total = max(sum(1 for line in csv_text.splitlines() if line.strip()) - 1, 0)
        pct = 100.0 * len(kept) / max(total, 1)
        print(f"  {src}: {len(kept)} kept out of {total} total ({pct:.1f}%)")
        if kept:
            mcl = os.path.join(staging, src.replace(".mch", ".mcl"))
            write_mcl(kept, mcl)
            per_source_kept[src] = (mch, mcl, len(kept))

    total_kept = sum(v[2] for v in per_source_kept.values())
    print(f"\nTotal kept across sources: {total_kept}")

    if args.dry_run:
        print("Dry run -- skipping mcs -copy / -merge / -split steps.")
        return 0

    if total_kept < args.train_size + args.test_size:
        print(f"ERROR: only {total_kept} methods survived filtering; "
              f"asked for train+test = {args.train_size + args.test_size}.",
              file=sys.stderr)
        return 3

    # Step 2: mcs -copy each source -> subset MCH.
    for src, (mch, mcl, count) in per_source_kept.items():
        subset = os.path.join(staging, src.replace(".mch", ".tier1.mch"))
        print(f"\n[copy] {src} ({count} methods) -> {os.path.basename(subset)}")
        run_mcs(args.core_root, ["-copy", mcl, mch, subset])

    # Step 3: mcs -merge subsets -> combined MCH (with -dedup).
    combined = os.path.join(staging, "combined.tier1.mch")
    print(f"\n[merge] {len(per_source_kept)} subsets -> {os.path.basename(combined)}")
    pattern = os.path.join(staging, "*.tier1.mch")
    run_mcs(args.core_root, ["-merge", combined, pattern, "-dedup"])

    # Step 4: count combined, split into train / test.
    combined_count = count_methods_in_mch(args.core_root, combined)
    print(f"\n[count] combined has {combined_count} methods after dedup")

    if combined_count < args.train_size + args.test_size:
        print(f"ERROR: post-dedup count {combined_count} < train+test "
              f"{args.train_size + args.test_size}.", file=sys.stderr)
        return 4

    # mcs uses 1-based indexing.
    rng = random.Random(args.seed)
    all_indices = list(range(1, combined_count + 1))
    rng.shuffle(all_indices)
    test_indices  = sorted(all_indices[:args.test_size])
    train_indices = sorted(all_indices[args.test_size:args.test_size + args.train_size])

    train_mcl = os.path.join(staging, "train.mcl")
    test_mcl  = os.path.join(staging, "test.mcl")
    write_mcl(train_indices, train_mcl)
    write_mcl(test_indices, test_mcl)

    train_mch = os.path.join(args.output_dir, "train.mch")
    test_mch  = os.path.join(args.output_dir, "test.mch")
    print(f"\n[copy] combined -> train.mch ({args.train_size} methods)")
    run_mcs(args.core_root, ["-copy", train_mcl, combined, train_mch])
    print(f"[copy] combined -> test.mch ({args.test_size} methods)")
    run_mcs(args.core_root, ["-copy", test_mcl, combined, test_mch])

    # Step 5: mcs -toc for random-access acceleration.
    print(f"\n[toc] indexing train/test MCHs")
    run_mcs(args.core_root, ["-toc", train_mch])
    run_mcs(args.core_root, ["-toc", test_mch])

    print(f"\nDone. Outputs:")
    print(f"  {train_mch}  ({args.train_size} methods)")
    print(f"  {test_mch}   ({args.test_size} methods)")
    print(f"  staging area: {staging}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
