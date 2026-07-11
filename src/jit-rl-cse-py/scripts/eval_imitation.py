"""Evaluate an imitation-trained model on an MCH.

Loads a checkpoint from ``scripts/train_imitation.py`` and computes,
for each method in the given MCH:

* The imitation model's predicted CSE subset (sigmoid > threshold).
* The perf-score achieved by applying that subset via
  ``JitRLHookCSEDecisions``.
* Comparison against the heuristic and the (optional) optimum from
  ``label_optimal.py``.

Reports the same b/s/w breakdown + arith/geo means as
``evaluate.py`` so results are directly comparable to the RL runs.

Usage::

    python scripts/eval_imitation.py \\
        --core_root <path>/Core_Root \\
        --mch C:/spmi/mch-tier1/test.mch \\
        --checkpoint <run>/best_val.pt \\
        --config <run>/config.json \\
        --optimum-labels <mch>.optimal.json \\
        --threshold 0.5
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
import time
from typing import Dict, List, Optional

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.train_imitation import ImitationScorer, _NORMALIZER
from jitml.constants import MAX_CSE
from jitml.jit_cse import JitCseEnv
from jitml.superpmi import SuperPmi


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True)
    p.add_argument("--checkpoint", required=True,
                   help="Path to .pt checkpoint from train_imitation.py.")
    p.add_argument("--config", required=True,
                   help="Path to config.json from train_imitation.py.")
    p.add_argument("--optimum-labels", type=str, default=None,
                   help="Optional: path to <mch>.optimal.json for the "
                        "SAME MCH; enables printing the ceiling gap.")
    p.add_argument("--threshold", type=float, default=0.5,
                   help="Sigmoid probability threshold to include a "
                        "candidate in the applied subset (default 0.5).")
    p.add_argument("--limit", type=int, default=None,
                   help="Optionally cap the number of methods evaluated.")
    p.add_argument("--include-rl2020", action="store_true",
                   help="Also collect JitRLCSEGreedy baseline scores.")
    p.add_argument("--jit-path", default=None,
                   help="Optional override for the JIT dll (e.g. clrjit_universal_arm64_x64.dll "
                        "for cross-jitting arm64 collections on an x64 host).")
    p.add_argument("--out-csv", type=str, default=None,
                   help="Optional: write per-method results here.")
    return p.parse_args()


def _method_pass(spmi: SuperPmi, model: ImitationScorer, method_id: int,
                 threshold: float, device: torch.device, include_rl2020: bool
                 ) -> Optional[Dict]:
    """Run the imitation model on one method + collect comparison JITs."""
    try:
        no_cse = spmi.jit_method(method_id, JitMetrics=1, JitRLHook=1,
                                 JitRLHookEmitFeatureNames=1,
                                 JitRLHookEmitEarly=1,
                                 JitRLHookCSEDecisions=[])
    except Exception:  # noqa: BLE001
        return None
    if no_cse is None:
        return None

    try:
        heur = spmi.jit_method(method_id, JitMetrics=1)
    except Exception:  # noqa: BLE001
        heur = None
    if heur is None:
        return None

    obs = JitCseEnv.get_observation(no_cse)
    cands_norm, method_norm = _NORMALIZER.normalize(obs["candidates"], obs["method"])
    cands = torch.from_numpy(cands_norm.astype(np.float32)).unsqueeze(0).to(device)
    method = torch.from_numpy(method_norm.astype(np.float32)).unsqueeze(0).to(device)
    with torch.no_grad():
        logits = model(cands, method).squeeze(0)   # (MAX_CSE,)
        probs = torch.sigmoid(logits).cpu().numpy()

    # Consider only viable candidates.
    viable = [i for i, c in enumerate(no_cse.cse_candidates[:MAX_CSE]) if c.can_apply]
    subset = [i for i in viable if probs[i] > threshold]

    # Apply the subset.
    if subset:
        try:
            r = spmi.jit_method(method_id, JitMetrics=1, JitRLHook=1,
                                JitRLHookCSEDecisions=subset)
        except Exception:  # noqa: BLE001
            r = None
        rl_perf = r.perf_score if r is not None else no_cse.perf_score
    else:
        rl_perf = no_cse.perf_score

    rl2020_perf = float("nan")
    if include_rl2020:
        try:
            r20 = spmi.jit_method(method_id, JitMetrics=1, JitRLCSEGreedy=1)
            if r20 is not None:
                rl2020_perf = r20.perf_score
        except Exception:  # noqa: BLE001
            pass

    return {
        "method_id": method_id,
        "n_viable": len(viable),
        "subset": subset,
        "n_applied": len(subset),
        "rl_perfscore": rl_perf,
        "heuristic_perfscore": heur.perf_score,
        "no_cse_perfscore": no_cse.perf_score,
        "rl2020_perfscore": rl2020_perf,
        # Per-candidate probabilities of the viable ones, rounded for logging.
        "viable_probs": [round(float(probs[i]), 3) for i in viable],
    }


def _summarize(rows: List[Dict], optimum_labels: Optional[Dict], label: str) -> None:
    """Compute and print the same summary evaluate.py does."""
    if not rows:
        print(f"{label}: no rows")
        return

    heur = np.array([r["heuristic_perfscore"] for r in rows])
    rl = np.array([r["rl_perfscore"] for r in rows])
    valid = (heur > 0) & (rl > 0)
    if not valid.any():
        print(f"{label}: no valid rows"); return

    delta = (rl[valid] - heur[valid]) / heur[valid] * 100
    b = (delta < -0.05).sum(); w = (delta > 0.05).sum(); s = valid.sum() - b - w
    arith = delta.mean()
    ratios = rl[valid] / heur[valid]
    geo = (np.exp(np.log(ratios[ratios > 0]).mean()) - 1) * 100

    print(f"\n{'='*70}")
    print(f"{label}  (n={valid.sum()})")
    print(f"{'='*70}")
    print(f"  vs heuristic: better={b}  same={s}  worse={w}")
    print(f"  arith mean pct delta vs heuristic: {arith:+.3f}%")
    print(f"  geo    mean pct delta vs heuristic: {geo:+.3f}%")

    rl20 = np.array([r["rl2020_perfscore"] for r in rows])
    v20 = valid & ~np.isnan(rl20) & (rl20 > 0)
    if v20.any():
        d20 = (rl[v20] - rl20[v20]) / rl20[v20] * 100
        b2 = (d20 < -0.05).sum(); w2 = (d20 > 0.05).sum(); s2 = v20.sum() - b2 - w2
        arith20 = d20.mean()
        r20 = rl[v20] / rl20[v20]
        geo20 = (np.exp(np.log(r20[r20 > 0]).mean()) - 1) * 100
        print(f"  vs RL2020:    better={b2}  same={s2}  worse={w2}")
        print(f"  arith mean pct delta vs RL2020: {arith20:+.3f}%")
        print(f"  geo    mean pct delta vs RL2020: {geo20:+.3f}%")

    if optimum_labels is not None:
        # Also compare to the labeled optimum ceiling.
        opt_perfs = []
        rl_perfs = []
        for r in rows:
            if not (r["heuristic_perfscore"] > 0 and r["rl_perfscore"] > 0):
                continue
            mid = str(r["method_id"])
            if mid not in optimum_labels:
                continue
            opt_perfs.append(optimum_labels[mid]["optimal_perfscore"])
            rl_perfs.append(r["rl_perfscore"])
        if opt_perfs:
            opt_arr = np.array(opt_perfs)
            rl_arr = np.array(rl_perfs)
            gap = (rl_arr - opt_arr) / opt_arr * 100
            print(f"  vs LABELED OPTIMUM ({len(opt_perfs)} methods):")
            print(f"    arith mean pct delta vs opt: {gap.mean():+.3f}%   "
                  f"(gap remaining above the optimum)")


def main() -> int:
    args = _parse_args()

    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    model = ImitationScorer(
        embed_dim=cfg["embed_dim"], num_heads=cfg["num_heads"],
        num_attn_layers=cfg["num_attn_layers"], dropout=cfg.get("dropout", 0.0),
    ).to(device)
    model.load_state_dict(torch.load(args.checkpoint, map_location=device))
    model.eval()
    print(f"Loaded checkpoint {args.checkpoint} "
          f"({sum(p.numel() for p in model.parameters())} params)")

    optimum_labels = None
    if args.optimum_labels:
        with open(args.optimum_labels, encoding="utf-8") as f:
            optimum_labels = json.load(f)
        print(f"Loaded {len(optimum_labels)} optimum labels from {args.optimum_labels}")

    rows: List[Dict] = []
    t0 = time.time()
    with SuperPmi(args.mch, args.core_root, jit_path=args.jit_path) as spmi:
        idx = 1
        while True:
            if args.limit is not None and len(rows) >= args.limit:
                break
            row = _method_pass(spmi, model, idx, args.threshold, device,
                               args.include_rl2020)
            if row is not None:
                rows.append(row)
                if len(rows) % 50 == 0:
                    print(f"  {len(rows)} rows  elapsed {time.time()-t0:.0f}s")
            idx += 1
            # Stop when we've clearly walked past the MCH.
            if idx > 100 and (idx - len(rows)) > 200 and row is None:
                break

    print(f"\nCollected {len(rows)} rows in {time.time()-t0:.0f}s")

    if args.out_csv:
        import csv
        with open(args.out_csv, "w", encoding="utf-8", newline="") as f:
            wr = csv.writer(f)
            wr.writerow(["method_id", "n_viable", "n_applied", "subset",
                         "rl_perfscore", "heuristic_perfscore",
                         "no_cse_perfscore", "rl2020_perfscore"])
            for r in rows:
                wr.writerow([r["method_id"], r["n_viable"], r["n_applied"],
                             r["subset"], r["rl_perfscore"],
                             r["heuristic_perfscore"], r["no_cse_perfscore"],
                             r["rl2020_perfscore"]])
        print(f"  wrote per-method CSV: {args.out_csv}")

    _summarize(rows, optimum_labels, f"IMITATION ({os.path.basename(args.checkpoint)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
