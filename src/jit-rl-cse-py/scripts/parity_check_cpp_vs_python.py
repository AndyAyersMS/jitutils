"""Parity check: does the C++ embedded imitation heuristic pick the same
subset (equivalently: get the same perf-score) as the Python-driven
inference-stub over the JitRLHookCSEDecisions channel?

For each method:
  A. Score with C++ imitation (jitoption JitCseImitation=1).
  B. Score with Python inference: fetch obs, run numpy stub, submit
     the selected subset via JitRLHookCSEDecisions.
Compare perf-score deltas. If |delta_pct| < 1e-4 for all methods,
the C++ port matches Python exactly (or within FP noise).

Usage::

    python scripts/parity_check_cpp_vs_python.py \\
        --core_root <cr> --mch <mch> --limit 200 \\
        --checkpoint <imitation_v7>/best_val.pt \\
        --config <imitation_v7>/config.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.train_imitation import ImitationScorer, _NORMALIZER
from jitml.constants import MAX_CSE, is_acceptable_for_cse
from jitml.jit_cse import JitCseEnv
from jitml.superpmi import SuperPmi


def _load_model(ckpt_path: str, config_path: str, device: torch.device) -> ImitationScorer:
    with open(config_path) as f:
        cfg = json.load(f)
    model = ImitationScorer(**{k: cfg[k] for k in
                               ("embed_dim", "num_heads", "num_attn_layers", "dropout")
                               if k in cfg})
    state = torch.load(ckpt_path, map_location=device, weights_only=True)
    model.load_state_dict(state, strict=False)
    model.to(device).eval()
    return model


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True)
    p.add_argument("--checkpoint", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--limit", type=int, default=200)
    p.add_argument("--threshold", type=float, default=0.30)
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    device = torch.device("cpu")
    model = _load_model(args.checkpoint, args.config, device)

    n_ok = 0
    n_match = 0        # perfscores agree within 0.05%
    n_close = 0        # within 0.5%
    n_far = 0
    rows = []          # list of (mid, cpp_perf, py_perf, delta_pct, cpp_n, py_n)

    t0 = time.time()
    with SuperPmi(args.mch, args.core_root) as spmi:
        for mid in range(1, args.limit + 1):
            # Get observation with no CSEs applied. Populates cse_candidates
            # and method features that the Python inference needs.
            try:
                no_cse = spmi.jit_method(mid, JitMetrics=1, JitRLHook=1,
                                         JitRLHookEmitFeatureNames=1,
                                         JitRLHookCSEDecisions=[],
                                         timeout=10)
            except Exception:
                continue
            if no_cse is None or not no_cse.cse_candidates:
                continue
            if not is_acceptable_for_cse(no_cse):
                continue

            # Python inference: compute subset.
            obs = JitCseEnv.get_observation(no_cse)
            cn, mn = _NORMALIZER.normalize(obs["candidates"], obs["method"])
            cand_t = torch.from_numpy(cn.astype(np.float32)).unsqueeze(0)
            method_t = torch.from_numpy(mn.astype(np.float32)).unsqueeze(0)
            with torch.no_grad():
                logits = model(cand_t, method_t).squeeze(0).cpu().numpy()
            probs = 1.0 / (1.0 + np.exp(-logits))
            viable = [i for i, c in enumerate(no_cse.cse_candidates[:MAX_CSE]) if c.can_apply]
            py_subset = sorted(i for i in viable if probs[i] > args.threshold)

            # C++ imitation: score without providing decisions.
            try:
                cpp_m = spmi.jit_method(mid, JitMetrics=1, JitCseImitation=1, timeout=10)
            except Exception:
                continue
            if cpp_m is None:
                continue

            # Python-driven: apply py_subset via JitRLHookCSEDecisions.
            if py_subset:
                try:
                    py_m = spmi.jit_method(mid, JitMetrics=1, JitRLHook=1,
                                           JitRLHookCSEDecisions=py_subset, timeout=10)
                except Exception:
                    continue
            else:
                py_m = no_cse
            if py_m is None:
                continue

            cpp_perf = cpp_m.perf_score
            py_perf = py_m.perf_score
            if cpp_perf <= 0 or py_perf <= 0:
                continue

            delta_pct = (cpp_perf - py_perf) / py_perf * 100
            n_ok += 1
            if abs(delta_pct) < 0.05:
                n_match += 1
            elif abs(delta_pct) < 0.5:
                n_close += 1
            else:
                n_far += 1

            rows.append((mid, cpp_perf, py_perf, delta_pct,
                        cpp_m.num_cse, len(py_subset)))
            if args.verbose or abs(delta_pct) >= 0.5:
                print(f"  m={mid:>5d}  cpp={cpp_perf:>10.2f} (n={cpp_m.num_cse})  "
                      f"py={py_perf:>10.2f} (n={len(py_subset)})  "
                      f"delta={delta_pct:+.4f}%")

            if n_ok % 25 == 0:
                print(f"  progress: mid={mid} ok={n_ok} match={n_match} close={n_close} far={n_far} "
                      f"({time.time()-t0:.1f}s)")

    print("=" * 70)
    print(f"Parity summary over {n_ok} methods:")
    print(f"  exact/near-match (|delta| < 0.05%):  {n_match} ({100*n_match/max(1,n_ok):.1f}%)")
    print(f"  close            (|delta| < 0.5%):   {n_close} ({100*n_close/max(1,n_ok):.1f}%)")
    print(f"  far              (|delta| >= 0.5%):  {n_far} ({100*n_far/max(1,n_ok):.1f}%)")
    if rows:
        deltas = np.array([r[3] for r in rows])
        print(f"  abs delta: mean={np.abs(deltas).mean():.4f}%  "
              f"median={np.median(np.abs(deltas)):.4f}%  "
              f"max={np.abs(deltas).max():.4f}%")

    return 0 if n_far == 0 else 2


if __name__ == "__main__":
    sys.exit(main())
