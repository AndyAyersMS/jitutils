"""Compare two imitation checkpoints on a shared list of method ids.

Usage::

    python scripts/eval_two_models.py \\
        --core_root <cr> --mch <mch> --jit-path <jit> \\
        --checkpoint-a <a.pt> --config-a <a.json> --label-a v7_x64 \\
        --checkpoint-b <b.pt> --config-b <b.json> --label-b v8_arm64 \\
        --indices <ids.txt> --labels <labels.json> --threshold 0.3

Applies each model's predicted subset via ``JitRLHookCSEDecisions``,
reports b/s/w + arith/geo pct delta of each vs heuristic, and prints
a paired diff so we can see where the two models disagree.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.train_imitation import ImitationScorer, _NORMALIZER
from jitml.constants import MAX_CSE
from jitml.jit_cse import JitCseEnv
from jitml.superpmi import SuperPmi


def _load(ckpt: str, cfg: str, device: torch.device) -> ImitationScorer:
    with open(cfg) as f:
        conf = json.load(f)
    model = ImitationScorer(**{k: conf[k] for k in
        ("embed_dim", "num_heads", "num_attn_layers", "dropout")
        if k in conf})
    state = torch.load(ckpt, map_location=device, weights_only=True)
    model.load_state_dict(state, strict=False)
    model.to(device).eval()
    return model


def _apply(spmi: SuperPmi, model: ImitationScorer, method_id: int,
           threshold: float, device: torch.device) -> tuple:
    """Return (subset, subset_perfscore, heur_perfscore, no_cse_perfscore)."""
    try:
        no_cse = spmi.jit_method(method_id, JitMetrics=1, JitRLHook=1,
                                 JitRLHookEmitFeatureNames=1,
                                 JitRLHookEmitEarly=1,
                                 JitRLHookCSEDecisions=[])
    except Exception:
        return None
    if no_cse is None:
        return None

    try:
        heur = spmi.jit_method(method_id, JitMetrics=1)
    except Exception:
        heur = None
    if heur is None:
        return None

    obs = JitCseEnv.get_observation(no_cse)
    cn, mn = _NORMALIZER.normalize(obs["candidates"], obs["method"])
    cands = torch.from_numpy(cn.astype(np.float32)).unsqueeze(0).to(device)
    method = torch.from_numpy(mn.astype(np.float32)).unsqueeze(0).to(device)
    with torch.no_grad():
        logits = model(cands, method).squeeze(0)
        probs = torch.sigmoid(logits).cpu().numpy()

    viable = [i for i, c in enumerate(no_cse.cse_candidates[:MAX_CSE]) if c.can_apply]
    subset = [i for i in viable if probs[i] > threshold]
    if subset:
        try:
            r = spmi.jit_method(method_id, JitMetrics=1, JitRLHook=1,
                                JitRLHookCSEDecisions=subset)
        except Exception:
            r = None
        perf = r.perf_score if r is not None else no_cse.perf_score
    else:
        perf = no_cse.perf_score

    return subset, perf, heur.perf_score, no_cse.perf_score


def _summary(deltas: np.ndarray, name: str) -> None:
    valid = ~np.isnan(deltas)
    if not valid.any():
        print(f"  {name}: no data"); return
    d = deltas[valid]
    b = (d < -0.05).sum(); w = (d > 0.05).sum(); s = len(d) - b - w
    arith = d.mean()
    ratios = 1.0 + d/100.0
    geo = (np.exp(np.log(ratios[ratios>0]).mean()) - 1) * 100
    print(f"  {name:12s}: n={len(d):>4d}  b/s/w={b:>3d}/{s:>3d}/{w:>3d}  "
          f"arith={arith:+.3f}%  geo={geo:+.3f}%")


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True)
    p.add_argument("--jit-path", default=None)
    p.add_argument("--checkpoint-a", required=True)
    p.add_argument("--config-a", required=True)
    p.add_argument("--label-a", default="A")
    p.add_argument("--checkpoint-b", required=True)
    p.add_argument("--config-b", required=True)
    p.add_argument("--label-b", default="B")
    p.add_argument("--indices", required=True,
                   help="Text file with one method_id per line.")
    p.add_argument("--threshold", type=float, default=0.3)
    p.add_argument("--out-csv", type=str, default=None)
    args = p.parse_args()

    device = torch.device("cpu")
    model_a = _load(args.checkpoint_a, args.config_a, device)
    model_b = _load(args.checkpoint_b, args.config_b, device)

    with open(args.indices) as f:
        ids = [int(x.strip()) for x in f if x.strip()]
    print(f"Evaluating {len(ids)} methods on {os.path.basename(args.mch)}")
    print(f"  A = {args.label_a}  ckpt={os.path.basename(args.checkpoint_a)}")
    print(f"  B = {args.label_b}  ckpt={os.path.basename(args.checkpoint_b)}")
    print(f"  threshold = {args.threshold}")

    rows = []
    with SuperPmi(args.mch, args.core_root, jit_path=args.jit_path) as spmi:
        for i, mid in enumerate(ids):
            ra = _apply(spmi, model_a, mid, args.threshold, device)
            if ra is None:
                continue
            rb = _apply(spmi, model_b, mid, args.threshold, device)
            if rb is None:
                continue
            _, pa, heur, nocse = ra
            _, pb, _, _ = rb
            rows.append({
                "method_id": mid,
                "heur": heur,
                "a_perf": pa,
                "b_perf": pb,
                "no_cse": nocse,
            })
            if (i + 1) % 100 == 0:
                print(f"  .. {i+1}/{len(ids)} evaluated ({len(rows)} valid)")

    if not rows:
        print("no valid rows")
        return 1

    heur = np.array([r["heur"] for r in rows])
    a = np.array([r["a_perf"] for r in rows])
    b = np.array([r["b_perf"] for r in rows])
    ok = (heur > 0) & (a > 0) & (b > 0)

    da = (a[ok] - heur[ok]) / heur[ok] * 100
    db = (b[ok] - heur[ok]) / heur[ok] * 100

    print(f"\nResults (n_valid={ok.sum()}):")
    _summary(da, args.label_a)
    _summary(db, args.label_b)

    # Paired: where do the two models disagree materially?
    diff = db - da  # negative means B is better
    print(f"\nPaired diff (B - A), n={len(diff)}:")
    print(f"  B strictly better (>0.05pp): {(diff < -0.05).sum()}")
    print(f"  ~same (within 0.05pp):        {(np.abs(diff) <= 0.05).sum()}")
    print(f"  A strictly better (>0.05pp):  {(diff > 0.05).sum()}")

    if args.out_csv:
        import csv
        with open(args.out_csv, "w", newline="") as f:
            wr = csv.writer(f)
            wr.writerow(["method_id", "heur", "a_perf", "b_perf",
                         "a_pct", "b_pct", "b_minus_a_pct"])
            for i, r in enumerate(rows):
                if not ok[i]:
                    continue
                wr.writerow([r["method_id"], r["heur"],
                             r["a_perf"], r["b_perf"],
                             f"{da[np.where(np.where(ok)[0]==i)[0][0]]:+.3f}",
                             f"{db[np.where(np.where(ok)[0]==i)[0][0]]:+.3f}",
                             f"{diff[np.where(np.where(ok)[0]==i)[0][0]]:+.3f}"])
        print(f"\nWrote {args.out_csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
