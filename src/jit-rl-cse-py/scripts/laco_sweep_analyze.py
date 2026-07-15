"""Analyze laco_sweep2.csv — rank configurations across MCHs.

For each configuration:
- Compute aggregate metrics: total contexts, total imp/reg, avg geomean, sum PS%
- Compute per-arch summary (x64 vs arm64)
- Rank by a composite score

Scoring:
  score = (perf_imp - perf_reg)                   # net methods improved
        - abs(perf_delta_pct) * total_contexts    # penalty for aggregate perf change
        - abs(bytes_delta_pct) * total_contexts   # penalty for size change

Simpler: rank by number of PerfScore improvements minus regressions,
weighted by arch (x64 counts 1.0, arm64 counts 1.0 since both are targets).
"""
import argparse
import csv
import sys
from collections import defaultdict


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--csv", required=True)
    args = ap.parse_args()

    rows = []
    with open(args.csv, encoding="utf-8") as f:
        r = csv.DictReader(f)
        for row in r:
            rows.append(row)

    # Group by config, split x64 vs arm64
    by_cfg = defaultdict(lambda: {"x64": [], "arm64": []})
    for row in rows:
        by_cfg[row["config"]][row["arch"]].append(row)

    print(f"Configs: {len(by_cfg)}")
    print()
    hdr = f"{'config':<24} {'arch':<6} {'contexts':>9} {'imp':>5} {'reg':>5} {'net':>5} {'PS%':>7} {'geo%':>7}"
    print(hdr)
    print("-" * len(hdr))

    # Compute per-config aggregate
    per_cfg = []
    for cfg, buckets in sorted(by_cfg.items()):
        for arch in ["x64", "arm64"]:
            bs = buckets[arch]
            if not bs: continue
            total_ctx = sum(int(b["contexts"]) for b in bs)
            total_imp = sum(int(b["perf_imp"]) for b in bs)
            total_reg = sum(int(b["perf_reg"]) for b in bs)
            avg_ps = sum(float(b["perf_delta_pct"]) for b in bs) / len(bs)
            avg_geo = sum(float(b["geomean_pct"]) for b in bs) / len(bs)
            print(f"{cfg:<24} {arch:<6} {total_ctx:>9} {total_imp:>5} {total_reg:>5} "
                  f"{total_imp-total_reg:>+5} {avg_ps:>+6.3f}% {avg_geo:>+6.3f}%")

    print()
    print("=== RANKING by (imp-reg) aggregated across arches ===")
    print()
    ranked = []
    for cfg, buckets in by_cfg.items():
        rows_all = buckets["x64"] + buckets["arm64"]
        if not rows_all: continue
        total_ctx = sum(int(b["contexts"]) for b in rows_all)
        total_imp = sum(int(b["perf_imp"]) for b in rows_all)
        total_reg = sum(int(b["perf_reg"]) for b in rows_all)
        avg_ps = sum(float(b["perf_delta_pct"]) for b in rows_all) / len(rows_all)
        avg_geo = sum(float(b["geomean_pct"]) for b in rows_all) / len(rows_all)
        # separate arch sums
        x64_net = sum(int(b["perf_imp"]) - int(b["perf_reg"]) for b in buckets["x64"])
        a64_net = sum(int(b["perf_imp"]) - int(b["perf_reg"]) for b in buckets["arm64"])
        ranked.append((total_imp - total_reg, cfg, total_ctx, total_imp, total_reg, avg_ps, avg_geo, x64_net, a64_net))
    ranked.sort(key=lambda x: -x[0])

    print(f"{'config':<24} {'ctx':>6} {'imp':>5} {'reg':>5} {'net':>5} {'x64_net':>7} {'a64_net':>7} {'PS%':>7}")
    for score, cfg, ctx, imp, reg, ps, geo, x64_net, a64_net in ranked:
        print(f"{cfg:<24} {ctx:>6} {imp:>5} {reg:>5} {score:>+5} {x64_net:>+6} {a64_net:>+6} {ps:>+6.3f}%")


if __name__ == "__main__":
    sys.exit(main() or 0)
