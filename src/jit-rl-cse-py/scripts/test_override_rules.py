"""Test simple override rules against label buckets.

For each proposed rule R (a predicate on CseCandidate features), computes:
  precision_bad  = fraction of R-hits that were bad_pick (heur said yes, opt said no)
  recall_bad     = fraction of bad_picks captured by R
  precision_kept = fraction of R-hits that were kept_both (rule would misfire)
  recall_kept    = fraction of kept_both mistakenly captured (false positive)

Good rules have high precision_bad (>= 60%) and high recall_bad (>= 20%).
"""
import argparse
import json
import math
import os
import statistics
import sys
from typing import Callable, Dict, List, Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jitml.superpmi import SuperPmi
from jitml.method_context import CseCandidate, MethodContext


def collect(mch: str, core_root: str, labels_path: str,
            jit_path: Optional[str], gap_threshold: float,
            sample_limit: int
            ) -> Dict[str, List[tuple]]:
    """Returns {bucket_name: [(method_ctx, candidate), ...]}."""
    with open(labels_path, encoding="utf-8") as f:
        all_labels = json.load(f)

    sel = []
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

    buckets: Dict[str, List[tuple]] = {
        "kept_both": [], "bad_pick": [], "missed": [], "rejected_both": [],
    }
    with SuperPmi(mch, core_root, jit_path=jit_path) as spmi:
        for i, (gap, mid, rec) in enumerate(sel):
            if (i+1) % 100 == 0:
                print(f"  {i+1}/{len(sel)}...")
            try:
                m = spmi.jit_method(mid, JitMetrics=1, JitRLHook=1,
                                    JitRLHookEmitFeatureNames=1)
            except Exception:  # noqa: BLE001
                continue
            if m is None or not m.cse_candidates:
                continue
            heur_yes = set(rec.get("heuristic_cses", []))
            opt_yes = set(rec.get("optimal_subset", []))
            for arr_idx, c in enumerate(m.cse_candidates):
                if not c.viable:
                    continue
                hy = arr_idx in heur_yes
                oy = arr_idx in opt_yes
                if hy and oy:
                    buckets["kept_both"].append((m, c))
                elif hy and not oy:
                    buckets["bad_pick"].append((m, c))
                elif not hy and oy:
                    buckets["missed"].append((m, c))
                else:
                    buckets["rejected_both"].append((m, c))
    return buckets


# Rule = predicate over (MethodContext, CseCandidate)
# Returns True if the rule "fires" (would override heur to NO)
RULES: List[tuple] = [
    ("const AND live_across_call",
     lambda m, c: c.const and c.live_across_call),
    ("const AND bb_count < 50",
     lambda m, c: c.const and m.num_cse_candidate > 0 and m.bb_count if hasattr(m, 'bb_count') else False),
    ("const AND !has_call",
     lambda m, c: c.const and not c.has_call),
    ("const (any)",
     lambda m, c: c.const),
    ("live_across_call AND use_count <= 2",
     lambda m, c: c.live_across_call and c.use_count <= 2),
    ("live_across_call AND !make_cse AND use_count <= 2",
     lambda m, c: c.live_across_call and not c.make_cse and c.use_count <= 2),
    ("live_across_call AND cost_sz >= 8",
     lambda m, c: c.live_across_call and c.cost_sz >= 8),
    ("const AND live_across_call AND use_count <= 3",
     lambda m, c: c.const and c.live_across_call and c.use_count <= 3),
    ("make_cse AND const",
     lambda m, c: c.make_cse and c.const),
    ("cost_sz >= 8 AND !const",
     lambda m, c: c.cost_sz >= 8 and not c.const),
    ("live_across_call AND !containable",
     lambda m, c: c.live_across_call and not c.containable),
    ("const AND use_count == 1",
     lambda m, c: c.const and c.use_count == 1),
    ("const AND use_wt_cnt_x100 < 200",
     lambda m, c: c.const and c.use_wt_cnt_x100 < 200),
    # combined stronger
    ("const AND (live_across_call OR use_count <= 2)",
     lambda m, c: c.const and (c.live_across_call or c.use_count <= 2)),
    ("live_across_call AND (const OR cost_sz >= 8)",
     lambda m, c: c.live_across_call and (c.const or c.cost_sz >= 8)),
    ("live_across_call AND (const OR cost_sz >= 12)",
     lambda m, c: c.live_across_call and (c.const or c.cost_sz >= 12)),
    ("live_across_call AND cost_sz >= 6",
     lambda m, c: c.live_across_call and c.cost_sz >= 6),
    ("live_across_call AND cost_sz >= 10",
     lambda m, c: c.live_across_call and c.cost_sz >= 10),
    ("live_across_call AND !containable AND use_count <= 3",
     lambda m, c: c.live_across_call and not c.containable and c.use_count <= 3),
    ("live_across_call AND const AND use_count <= 5",
     lambda m, c: c.live_across_call and c.const and c.use_count <= 5),
    ("const AND use_count <= 2",
     lambda m, c: c.const and c.use_count <= 2),
    ("const AND use_wt_cnt <= 5.0",
     lambda m, c: c.const and (c.use_wt_cnt_x100 / 100.0) <= 5.0),
    # baseline: how much bad-picking is there in total?
    ("__all__ (baseline)",
     lambda m, c: True),
]


def eval_rule(name: str, pred: Callable, buckets: Dict[str, List[tuple]]) -> None:
    counts = {k: 0 for k in buckets}
    for k, items in buckets.items():
        for m, c in items:
            try:
                if pred(m, c):
                    counts[k] += 1
            except Exception:  # noqa: BLE001
                pass

    # A rule fires when it says "override to NO". So the rule helps when:
    #   heur said yes AND opt said no  (bad_pick) — CORRECTED
    # And hurts when:
    #   heur said yes AND opt said yes  (kept_both) — WRONGLY VETOED
    # It doesn't affect heur-no cases (missed/rejected_both) because heur
    # already said no there.

    hits_bad = counts["bad_pick"]
    hits_good = counts["kept_both"]
    total_bad = len(buckets["bad_pick"])
    total_good = len(buckets["kept_both"])
    total_hits = hits_bad + hits_good  # rule fires only on heur-yes candidates

    prec = hits_bad / total_hits if total_hits else 0.0
    recall = hits_bad / total_bad if total_bad else 0.0
    fp_rate = hits_good / total_good if total_good else 0.0

    # Net effect: (bad_picks removed) - (good_picks removed) = hits_bad - hits_good.
    # If positive, rule is a net-win.
    net = hits_bad - hits_good

    print(f"  {name:<52} prec={100*prec:>5.1f}%  recall={100*recall:>5.1f}%  "
          f"FPrate={100*fp_rate:>5.1f}%  net={net:>+4}  "
          f"(bad_removed={hits_bad}, good_removed={hits_good})")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--core_root", required=True)
    ap.add_argument("--mch", required=True)
    ap.add_argument("--labels", required=True)
    ap.add_argument("--jit-path", default=None)
    ap.add_argument("--gap-threshold", type=float, default=5.0)
    ap.add_argument("--limit", type=int, default=500)
    args = ap.parse_args()

    print("Collecting bucket data...")
    buckets = collect(args.mch, args.core_root, args.labels,
                      args.jit_path, args.gap_threshold, args.limit)
    print()
    for k, v in buckets.items():
        print(f"  {k:<15}: {len(v)}")

    print()
    print("RULE EVALUATION")
    print("-" * 100)
    print(f"  {'rule':<52} {'precision':<12} {'recall':<12} {'FP':<12}")
    for name, pred in RULES:
        eval_rule(name, pred, buckets)

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
