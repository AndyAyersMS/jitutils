"""What distinguishes a LACO-target CSE that MCMC keeps vs one MCMC rejects?

Rule LACO fires on: LiveAcrossCall AND Size>=8. Among candidates matching that,
we want to further refine: which should be vetoed vs kept?

Uses the existing labels + a fresh JitRLHook feature extraction to build
per-candidate feature vectors, then compares two buckets:
 - LACO-target CSEs kept by MCMC-optimum  (rule shouldn't fire)
 - LACO-target CSEs rejected by MCMC-optimum  (rule should fire)

Reports the top discriminating features between these buckets.
"""
import argparse
import json
import math
import os
import statistics
import sys
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from jitml.superpmi import SuperPmi


def _extract(c) -> Dict[str, float]:
    r = {}
    fields_num = ["cost_ex", "cost_sz", "use_count", "def_count",
                  "use_wt_cnt_x100", "def_wt_cnt_x100",
                  "distinct_locals", "local_occurrences",
                  "bb_count", "block_spread",
                  "enreg_count_int", "enreg_count_float",
                  "enreg_count_simd", "enreg_count_msk"]
    fields_bool = ["live_across_call", "const", "shared_const", "make_cse",
                   "has_call", "containable"]
    for f in fields_num:
        try: r[f] = float(getattr(c, f, 0) or 0)
        except: r[f] = 0.0
    for f in fields_bool:
        r[f] = 1.0 if getattr(c, f, False) else 0.0
    r["use_wt_cnt"] = r["use_wt_cnt_x100"] / 100.0
    r["def_wt_cnt"] = r["def_wt_cnt_x100"] / 100.0
    r["type"] = float(getattr(c, "type", 0) or 0)
    return r


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--core_root", required=True)
    ap.add_argument("--mch", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--jit-path", default=None)
    ap.add_argument("--size-min", type=int, default=8)
    ap.add_argument("--limit", type=int, default=2000)
    args = ap.parse_args()

    with open(args.labels, encoding="utf-8") as f:
        labels = json.load(f)

    keep_bucket: List[Dict[str, float]] = []
    veto_bucket: List[Dict[str, float]] = []

    mids = list(labels.keys())[:args.limit]
    with SuperPmi(args.mch, args.core_root, jit_path=args.jit_path) as spmi:
        for i, mid in enumerate(mids):
            if (i+1) % 200 == 0:
                print(f"  {i+1}/{len(mids)}...  keep={len(keep_bucket)}  veto={len(veto_bucket)}")
            rec = labels[mid]
            opt = set(rec.get("optimal_subset", []))
            try:
                m = spmi.jit_method(int(mid), JitMetrics=1, JitRLHook=1,
                                    JitRLHookEmitFeatureNames=1)
            except Exception:
                continue
            if m is None or not m.cse_candidates:
                continue
            for idx, c in enumerate(m.cse_candidates):
                if not c.viable: continue
                if not c.live_across_call: continue
                if c.cost_sz < args.size_min: continue
                # This candidate matches LACO's Size+LAC predicate.
                feats = _extract(c)
                if idx in opt:
                    keep_bucket.append(feats)
                else:
                    veto_bucket.append(feats)

    print()
    print(f"Bucket sizes: keep={len(keep_bucket)}  veto={len(veto_bucket)}")
    if not keep_bucket or not veto_bucket:
        print("Not enough data.")
        return 1

    all_feats = list(keep_bucket[0].keys())
    ranked = []
    for f in all_feats:
        kv = [r[f] for r in keep_bucket]
        vv = [r[f] for r in veto_bucket]
        km = statistics.mean(kv); vm = statistics.mean(vv)
        try:
            ks = statistics.stdev(kv) if len(kv) > 1 else 0.0
            vs = statistics.stdev(vv) if len(vv) > 1 else 0.0
        except statistics.StatisticsError:
            ks = vs = 0.0
        pooled = math.sqrt((ks**2 + vs**2) / 2) or 1e-9
        d = (vm - km) / pooled
        ranked.append((abs(d), f, km, vm, d))
    ranked.sort(key=lambda x: -x[0])

    print()
    print("DISCRIMINATORS: features where 'MCMC-veto' differs from 'MCMC-keep'")
    print(f"  higher |d| means the feature separates the two groups more cleanly")
    print(f"  (n_keep={len(keep_bucket)} n_veto={len(veto_bucket)})")
    print("-" * 82)
    print(f"{'feature':<25} {'keep_mean':>10} {'veto_mean':>10} {'diff':>10} {'|d|':>6}")
    for _absd, f, km, vm, d in ranked[:25]:
        diff = vm - km
        print(f"{f:<25} {km:>10.3f} {vm:>10.3f} {diff:>+10.3f} {abs(d):>6.3f}")

    # Test some candidate rules
    print()
    print("CANDIDATE RULES (on the LAC + Size>=8 subset)")
    print("-" * 82)
    for name, pred in [
        ("use_count <= 3 (raw)", lambda r: r["use_count"] <= 3),
        ("use_count <= 2 (raw)", lambda r: r["use_count"] <= 2),
        ("use_wt_cnt <= 3 (weighted, /100)", lambda r: r["use_wt_cnt"] <= 3),
        ("use_wt_cnt <= 100 (weighted, /100)", lambda r: r["use_wt_cnt"] <= 100),
        ("!containable", lambda r: r["containable"] < 0.5),
        ("use_count <= 3 AND !containable", lambda r: r["use_count"] <= 3 and r["containable"] < 0.5),
        ("cost_ex <= 4", lambda r: r["cost_ex"] <= 4),
        ("has_call (nested call)", lambda r: r["has_call"] >= 0.5),
        ("distinct_locals >= 2", lambda r: r["distinct_locals"] >= 2),
        ("bb_count < 100", lambda r: r["bb_count"] < 100),
    ]:
        fires_keep = sum(1 for r in keep_bucket if pred(r))
        fires_veto = sum(1 for r in veto_bucket if pred(r))
        total_fires = fires_keep + fires_veto
        prec = fires_veto / total_fires * 100 if total_fires else 0
        recall = fires_veto / len(veto_bucket) * 100 if veto_bucket else 0
        net = fires_veto - fires_keep
        print(f"  {name:<45} prec={prec:>5.1f}%  recall={recall:>5.1f}%  net={net:>+4}  "
              f"(veto_hit={fires_veto} keep_hit={fires_keep})")

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
