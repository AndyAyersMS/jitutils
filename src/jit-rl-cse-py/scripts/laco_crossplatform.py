"""Cross-platform LACO wall-clock analysis.

Reads the three A/B CSVs (x64 = bdn_ab_laco_x64.csv, Cobalt = bdn_ab_arm64_cobalt_laco.csv,
M4 = bdn_ab_m4_laco.csv) and produces:
1. Per-benchmark unified table (delta% per platform)
2. Consistency-of-sign analysis (benchmarks where all 3 agree vs disagree)
3. Best-per-platform ranked wins/losses
"""
import csv
import os
import statistics


SESS = r"C:\Users\andya\.copilot\session-state\e0c45c58-07ca-44b1-bdd1-50010f6ae096\files"


def parse(csv_path, delta_col):
    """Return dict {benchmark_name: delta_pct}."""
    out = {}
    with open(csv_path, encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            n = row["benchmark"]
            try:
                out[n] = float(row[delta_col])
            except (KeyError, ValueError):
                pass
    return out


def normalize_name(n):
    """Truncate IsMatch/WriteDeep parameter noise for cross-CSV join."""
    # x64 CSV uses "IsMatch_Multithreading[total=40000&unique=1600&cacheSiz"
    # (truncated to 55 chars in the printed table). Match on prefix.
    return n.split("[")[0] + ("[" + n[n.find("[")+1:n.find("=")+1] if "=" in n[:60] else "")


def main():
    x64 = parse(os.path.join(SESS, "bdn_ab_laco_x64.csv"), "delta_pct")
    cobalt = parse(os.path.join(SESS, "bdn_ab_arm64_cobalt_laco.csv"), "delta_pct")
    m4 = parse(os.path.join(SESS, "bdn_ab_m4_laco.csv"), "delta_pct")

    print(f"x64: {len(x64)} benchmarks")
    print(f"cobalt: {len(cobalt)} benchmarks")
    print(f"m4: {len(m4)} benchmarks")

    # Join. The x64 CSV has truncated names (55 char print). Try direct match.
    all_names = set(x64) | set(cobalt) | set(m4)

    joined = []
    for name in sorted(all_names):
        row = {
            "name": name,
            "x64": x64.get(name),
            "cobalt": cobalt.get(name),
            "m4": m4.get(name),
        }
        joined.append(row)

    print()
    print(f"{'benchmark':<64} {'x64%':>8} {'cobalt%':>8} {'m4%':>8}")
    print("-" * 92)
    for row in joined:
        x = f"{row['x64']:+.2f}%" if row['x64'] is not None else "  —  "
        c = f"{row['cobalt']:+.2f}%" if row['cobalt'] is not None else "  —  "
        m = f"{row['m4']:+.2f}%" if row['m4'] is not None else "  —  "
        print(f"{row['name'][:64]:<64} {x:>8} {c:>8} {m:>8}")

    # Consistency analysis: benchmarks where all 3 have data
    complete = [r for r in joined if r['x64'] is not None and r['cobalt'] is not None and r['m4'] is not None]
    print()
    print(f"Benchmarks with data on all 3 platforms: {len(complete)}")

    # Signs
    all_win = [r for r in complete if r['x64'] < -0.5 and r['cobalt'] < -0.5 and r['m4'] < -0.5]
    all_neg = [r for r in complete if r['x64'] > 0.5 and r['cobalt'] > 0.5 and r['m4'] > 0.5]
    mixed = [r for r in complete if r not in all_win and r not in all_neg]

    print()
    print(f"WIN ON ALL 3 (delta < -0.5 everywhere): {len(all_win)}")
    for r in all_win:
        print(f"  {r['name'][:64]:<64} x64={r['x64']:+.2f}%  cobalt={r['cobalt']:+.2f}%  m4={r['m4']:+.2f}%")

    print()
    print(f"REGRESS ON ALL 3 (delta > 0.5 everywhere): {len(all_neg)}")
    for r in all_neg:
        print(f"  {r['name'][:64]:<64} x64={r['x64']:+.2f}%  cobalt={r['cobalt']:+.2f}%  m4={r['m4']:+.2f}%")

    print()
    print(f"MIXED (disagreement): {len(mixed)}")
    for r in mixed:
        print(f"  {r['name'][:64]:<64} x64={r['x64']:+.2f}%  cobalt={r['cobalt']:+.2f}%  m4={r['m4']:+.2f}%")

    # Per-platform medians
    print()
    print("PER-PLATFORM MEDIANS")
    for arch, ds in [("x64", [r['x64'] for r in complete]),
                     ("cobalt", [r['cobalt'] for r in complete]),
                     ("m4", [r['m4'] for r in complete])]:
        wins = sum(1 for d in ds if d < -0.5)
        losses = sum(1 for d in ds if d > 0.5)
        print(f"  {arch:<8} median={statistics.median(ds):+.2f}%  wins(<-0.5)={wins}  losses(>0.5)={losses}")


if __name__ == "__main__":
    main()
