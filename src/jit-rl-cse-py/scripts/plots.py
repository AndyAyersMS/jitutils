#!/usr/bin/python
"""Render summary plots from an evaluate.py CSV.

Usage:
    python scripts/plots.py <csv_file> [--out <dir>]

Emits three PNGs in the same directory as the CSV (or ``--out`` if
supplied):

* ``<name>_delta_hist.png`` -- histogram of the per-method
  ``pct_delta_vs_heuristic``, with a vertical line at 0 (parity).
* ``<name>_cumulative.png`` -- cumulative distribution of the sorted
  per-method delta (how many methods gain / lose by X pct).
* ``<name>_by_candidates.png`` -- boxplot of pct delta bucketed by
  ``num_candidates``, useful to see where the model helps or hurts.

Only depends on pandas + numpy + matplotlib (already in the pyproject
requirements).
"""
from __future__ import annotations

import argparse
import os
import sys

import matplotlib
matplotlib.use("Agg")  # headless render
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402


def _plot_delta_histogram(df: pd.DataFrame, base: str, out_dir: str) -> str:
    fig, ax = plt.subplots(figsize=(7, 4))
    pct = (df.pct_delta_vs_heuristic * 100).dropna()
    ax.hist(pct, bins=30, color="#4477aa", edgecolor="black")
    ax.axvline(0.0, color="red", linestyle="--", linewidth=1, label="parity")
    ax.set_xlabel("per-method pct delta vs heuristic (negative = better)")
    ax.set_ylabel("method count")
    ax.set_title(f"{base}: perf-score delta distribution (n={len(pct)})")
    ax.legend()
    path = os.path.join(out_dir, f"{base}_delta_hist.png")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def _plot_cumulative(df: pd.DataFrame, base: str, out_dir: str) -> str:
    fig, ax = plt.subplots(figsize=(7, 4))
    pct = np.sort((df.pct_delta_vs_heuristic * 100).dropna().to_numpy())
    if pct.size:
        cum = np.arange(1, len(pct) + 1) / len(pct)
        ax.plot(pct, cum, marker="o", markersize=3, color="#4477aa")
    ax.axvline(0.0, color="red", linestyle="--", linewidth=1, label="parity")
    ax.set_xlabel("pct delta vs heuristic (negative = better)")
    ax.set_ylabel("cumulative fraction of methods")
    ax.set_title(f"{base}: cumulative distribution")
    ax.legend()
    ax.grid(True, linewidth=0.3)
    path = os.path.join(out_dir, f"{base}_cumulative.png")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def _plot_by_candidates(df: pd.DataFrame, base: str, out_dir: str) -> str:
    fig, ax = plt.subplots(figsize=(7, 4))
    buckets = df[df.status == "ok"].groupby("num_candidates").pct_delta_vs_heuristic
    labels: list[int] = []
    data: list[np.ndarray] = []
    for k, series in buckets:
        labels.append(int(k))
        data.append((series * 100).to_numpy())

    if data:
        ax.boxplot(data, tick_labels=labels, showfliers=True)
    ax.axhline(0.0, color="red", linestyle="--", linewidth=1)
    ax.set_xlabel("# CSE candidates in method")
    ax.set_ylabel("pct delta vs heuristic")
    ax.set_title(f"{base}: delta by candidate count")
    ax.grid(True, axis="y", linewidth=0.3)
    path = os.path.join(out_dir, f"{base}_by_candidates.png")
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("csv", help="Path to an evaluate.py CSV.")
    parser.add_argument("--out", default=None, help="Output directory (default: csv directory).")
    args = parser.parse_args()

    if not os.path.isfile(args.csv):
        print(f"error: {args.csv} not found", file=sys.stderr)
        return 2

    df = pd.read_csv(args.csv)
    required = {"pct_delta_vs_heuristic", "num_candidates", "status"}
    if not required.issubset(df.columns):
        print(f"error: CSV is missing required columns {required - set(df.columns)}",
              file=sys.stderr)
        return 1

    out_dir = args.out or os.path.dirname(os.path.abspath(args.csv))
    os.makedirs(out_dir, exist_ok=True)
    base = os.path.splitext(os.path.basename(args.csv))[0]

    ok = df[df.status == "ok"]
    if ok.empty:
        print("warning: no rows with status='ok'; plots will be sparse.")

    p1 = _plot_delta_histogram(ok, base, out_dir)
    p2 = _plot_cumulative(ok, base, out_dir)
    p3 = _plot_by_candidates(df, base, out_dir)

    print(f"wrote {p1}")
    print(f"wrote {p2}")
    print(f"wrote {p3}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
