"""Per-candidate analysis: what feature patterns distinguish candidates the
hand-crafted heuristic picks INCORRECTLY (bad_pick — heur says yes, MCMC-optimum
says no) from candidates it picks CORRECTLY (kept_both)?

For each method with a large heuristic gap (>= --gap-threshold%), this:
  1. Re-JITs the method (no override) to obtain candidate features + heur picks
  2. Classifies each viable candidate:
       - kept_both      (heur=yes, opt=yes)
       - bad_pick       (heur=yes, opt=no)  <- target
       - missed         (heur=no,  opt=yes)
       - rejected_both  (heur=no,  opt=no)
  3. Aggregates per-feature stats: mean, effect-size (Cohen's d), rate-diff
     for boolean fields. Sorted by |d| so the top rows are the strongest
     discriminators — candidates for a simple "add a NO override" rule.
"""
import argparse
import json
import math
import os
import statistics
import sys
from collections import Counter
from typing import Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jitml.superpmi import SuperPmi
from jitml.method_context import CseCandidate


NUMERIC_FIELDS = [
    "cost_ex", "cost_sz", "use_count", "def_count",
    "use_wt_cnt_x100", "def_wt_cnt_x100",
    "distinct_locals", "local_occurrences",
    "bb_count", "block_spread",
    "enreg_count_int", "enreg_count_float", "enreg_count_simd", "enreg_count_msk",
]
BOOL_FIELDS = [
    "viable", "live_across_call", "const", "shared_const",
    "make_cse", "has_call", "containable",
]
# Also derived
DERIVED_FIELDS = [
    "use_wt_cnt",  # x100 -> real
    "def_wt_cnt",
    "type_int",    # one-hot
    "type_long",
    "type_float",
    "type_double",
    "type_struct",
    "type_simd",
    "log_use_wt",           # log1p(use_wt)
    "log_def_wt",           # log1p(def_wt)
    "use_wt_x_use_cnt",     # dynamic pressure proxy (from features[18])
]


def extract(c: CseCandidate) -> Dict[str, float]:
    """Return a flat feature dict for one candidate."""
    r: Dict[str, float] = {}
    for f in NUMERIC_FIELDS:
        try:
            r[f] = float(getattr(c, f, 0) or 0)
        except (TypeError, ValueError):
            r[f] = 0.0
    for f in BOOL_FIELDS:
        r[f] = 1.0 if getattr(c, f, False) else 0.0
    # Derived
    r["use_wt_cnt"] = r["use_wt_cnt_x100"] / 100.0
    r["def_wt_cnt"] = r["def_wt_cnt_x100"] / 100.0
    r["log_use_wt"] = math.log1p(max(0.0, r["use_wt_cnt"]))
    r["log_def_wt"] = math.log1p(max(0.0, r["def_wt_cnt"]))
    r["use_wt_x_use_cnt"] = r["use_wt_cnt"] * r["use_count"]
    # Type one-hot
    t = int(getattr(c, "type", 0) or 0)
    for i, name in enumerate(("type_int", "type_long", "type_float",
                              "type_double", "type_struct", "type_simd"), start=1):
        r[name] = 1.0 if t == i else 0.0
    return r


def collect(mch: str, core_root: str, labels_path: str,
            jit_path: Optional[str], gap_threshold: float,
            sample_limit: int) -> Dict[str, List[Dict[str, float]]]:
    with open(labels_path, encoding="utf-8") as f:
        all_labels = json.load(f)

    sel: List[tuple] = []
    for mid, rec in all_labels.items():
        heur = rec.get("heuristic_perfscore")
        opt = rec.get("optimal_perfscore")
        if heur is None or opt is None or heur <= 0:
            continue
        gap = (heur - opt) / heur * 100.0
        if gap >= gap_threshold:
            sel.append((gap, int(mid), rec))
    sel.sort(key=lambda x: -x[0])
    if sample_limit and sample_limit > 0:
        sel = sel[:sample_limit]

    print(f"Analyzing {len(sel)} methods with gap >= {gap_threshold}%")

    buckets: Dict[str, List[Dict[str, float]]] = {
        "kept_both": [], "bad_pick": [], "missed": [], "rejected_both": [],
    }
    skipped = 0
    with SuperPmi(mch, core_root, jit_path=jit_path) as spmi:
        for i, (gap, mid, rec) in enumerate(sel):
            if (i + 1) % 100 == 0:
                print(f"  {i+1}/{len(sel)}...")
            try:
                # Run with RL hook to emit per-candidate features. Note that
                # cses_chosen will be empty in this mode; we use the labels'
                # cached heuristic_cses (which came from a separate default-heur
                # run when the label was created).
                m = spmi.jit_method(mid, JitMetrics=1, JitRLHook=1,
                                    JitRLHookEmitFeatureNames=1)
            except Exception:  # noqa: BLE001
                skipped += 1
                continue
            if m is None or not m.cse_candidates:
                skipped += 1
                continue
            heur_yes_indices = set(rec.get("heuristic_cses", []))
            opt_yes_indices = set(rec.get("optimal_subset", []))
            for arr_idx, c in enumerate(m.cse_candidates):
                if not c.viable:
                    continue
                heur_yes = arr_idx in heur_yes_indices
                opt_yes = arr_idx in opt_yes_indices
                if heur_yes and opt_yes:
                    key = "kept_both"
                elif heur_yes and not opt_yes:
                    key = "bad_pick"
                elif not heur_yes and opt_yes:
                    key = "missed"
                else:
                    key = "rejected_both"
                buckets[key].append(extract(c))

    print(f"  skipped: {skipped}")
    return buckets


def summarize(buckets: Dict[str, List[Dict[str, float]]]) -> None:
    print()
    print("BUCKET SIZES")
    for k, v in buckets.items():
        print(f"  {k:<15}: {len(v)}")

    kept = buckets["kept_both"]
    bad = buckets["bad_pick"]
    if not kept or not bad:
        print("Not enough data.")
        return

    all_feats = list(kept[0].keys())
    ranked = []
    for f in all_feats:
        gv = [row[f] for row in kept]
        bv = [row[f] for row in bad]
        gm = statistics.mean(gv)
        bm = statistics.mean(bv)
        try:
            gs = statistics.stdev(gv) if len(gv) > 1 else 0.0
            bs = statistics.stdev(bv) if len(bv) > 1 else 0.0
        except statistics.StatisticsError:
            gs = bs = 0.0
        pooled = math.sqrt((gs**2 + bs**2) / 2) or 1e-9
        d = (bm - gm) / pooled
        ranked.append((abs(d), f, gm, bm, d))
    ranked.sort(key=lambda x: -x[0])

    print()
    print(f"FEATURE DISCRIMINATOR RANKING  (kept_both n={len(kept)} vs bad_pick n={len(bad)})")
    print("-" * 82)
    print(f"{'feature':<25} {'good_mean':>12} {'bad_mean':>12} {'diff':>12} {'|d|':>6}")
    for _absd, f, gm, bm, d in ranked[:30]:
        diff = bm - gm
        print(f"{f:<25} {gm:>12.3f} {bm:>12.3f} {diff:>+12.3f} {abs(d):>6.3f}")

    # Also compare bad_pick vs missed  (what heur got wrong in each direction)
    missed = buckets["missed"]
    if missed:
        print()
        print(f"BAD_PICK vs MISSED  (n_bad={len(bad)} n_missed={len(missed)})")
        print("-" * 82)
        print(f"{'feature':<25} {'bad_mean':>12} {'missed_mean':>12} {'diff':>12} {'|d|':>6}")
        ranked2 = []
        for f in all_feats:
            bv = [row[f] for row in bad]
            mv = [row[f] for row in missed]
            bm = statistics.mean(bv)
            mm = statistics.mean(mv)
            try:
                bs = statistics.stdev(bv) if len(bv) > 1 else 0.0
                ms = statistics.stdev(mv) if len(mv) > 1 else 0.0
            except statistics.StatisticsError:
                bs = ms = 0.0
            pooled = math.sqrt((bs**2 + ms**2) / 2) or 1e-9
            d = (bm - mm) / pooled
            ranked2.append((abs(d), f, bm, mm, d))
        ranked2.sort(key=lambda x: -x[0])
        for _absd, f, bm, mm, d in ranked2[:15]:
            diff = bm - mm
            print(f"{f:<25} {bm:>12.3f} {mm:>12.3f} {diff:>+12.3f} {abs(d):>6.3f}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--core_root", required=True)
    ap.add_argument("--mch", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--jit-path", default=None)
    ap.add_argument("--gap-threshold", type=float, default=5.0)
    ap.add_argument("--limit", type=int, default=500)
    args = ap.parse_args()

    buckets = collect(args.mch, args.core_root, args.labels,
                      args.jit_path, args.gap_threshold, args.limit)
    summarize(buckets)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
