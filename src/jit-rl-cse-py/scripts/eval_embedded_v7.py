"""Full-test-set eval of the JIT-embedded imitation heuristic. Compares:

  * Heuristic baseline (no jitoptions)
  * Embedded C++ imitation (JitCseImitation=1)
  * Python-driven imitation via JitRLHookCSEDecisions (reference)

Reports b/s/w + arith/geo pct-delta of both imitation modes vs
heuristic, and paired diff between them.
"""
from __future__ import annotations
import argparse, json, os, sys, time
import numpy as np, torch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.train_imitation import ImitationScorer, _NORMALIZER
from jitml.constants import MAX_CSE, is_acceptable_for_cse
from jitml.jit_cse import JitCseEnv
from jitml.superpmi import SuperPmi


def _load(ckpt_path, cfg_path, device):
    with open(cfg_path) as f: cfg = json.load(f)
    model = ImitationScorer(**{k: cfg[k] for k in
        ("embed_dim","num_heads","num_attn_layers","dropout") if k in cfg})
    state = torch.load(ckpt_path, map_location=device, weights_only=True)
    model.load_state_dict(state, strict=False)
    model.to(device).eval()
    return model


def _summary(name, deltas):
    valid = ~np.isnan(deltas)
    if not valid.any():
        print(f"  {name}: no data"); return
    d = deltas[valid]
    b = (d < -0.05).sum(); w = (d > 0.05).sum(); s = len(d) - b - w
    arith = d.mean()
    ratios = 1.0 + d/100.0
    geo = (np.exp(np.log(ratios[ratios>0]).mean()) - 1) * 100
    print(f"  {name:20s} n={len(d):>4d}  b/s/w={b:>3d}/{s:>3d}/{w:>3d}  "
          f"arith={arith:+.3f}%  geo={geo:+.3f}%")


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True)
    p.add_argument("--checkpoint", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--limit", type=int, default=1000)
    p.add_argument("--threshold", type=float, default=0.30)
    p.add_argument("--out-csv", type=str, default=None)
    args = p.parse_args()

    device = torch.device("cpu")
    model = _load(args.checkpoint, args.config, device)

    rows = []
    t0 = time.time()
    with SuperPmi(args.mch, args.core_root) as spmi:
        for mid in range(1, args.limit + 1):
            try:
                no_cse = spmi.jit_method(mid, JitMetrics=1, JitRLHook=1,
                                         JitRLHookEmitFeatureNames=1,
                                         JitRLHookEmitEarly=1,
                                         JitRLHookCSEDecisions=[],
                                         timeout=10)
            except Exception:
                continue
            if no_cse is None or not is_acceptable_for_cse(no_cse):
                continue
            if not no_cse.cse_candidates:
                continue

            # Heuristic baseline
            try:
                heur = spmi.jit_method(mid, JitMetrics=1, timeout=10)
            except Exception:
                continue
            if heur is None: continue

            # Python-driven imitation
            obs = JitCseEnv.get_observation(no_cse)
            cn, mn = _NORMALIZER.normalize(obs["candidates"], obs["method"])
            cand_t = torch.from_numpy(cn.astype(np.float32)).unsqueeze(0)
            method_t = torch.from_numpy(mn.astype(np.float32)).unsqueeze(0)
            with torch.no_grad():
                logits = model(cand_t, method_t).squeeze(0).cpu().numpy()
            probs = 1.0 / (1.0 + np.exp(-logits))
            viable = [i for i, c in enumerate(no_cse.cse_candidates[:MAX_CSE]) if c.can_apply]
            py_subset = sorted(i for i in viable if probs[i] > args.threshold)
            if py_subset:
                try:
                    pym = spmi.jit_method(mid, JitMetrics=1, JitRLHook=1,
                                          JitRLHookCSEDecisions=py_subset, timeout=10)
                except Exception:
                    continue
            else:
                pym = no_cse
            if pym is None: continue

            # Embedded C++ imitation
            try:
                cppm = spmi.jit_method(mid, JitMetrics=1, JitCseImitation=1, timeout=10)
            except Exception:
                continue
            if cppm is None: continue

            if heur.perf_score <= 0 or pym.perf_score <= 0 or cppm.perf_score <= 0:
                continue
            rows.append({
                "method_id": mid,
                "heur": heur.perf_score,
                "py":   pym.perf_score,
                "cpp":  cppm.perf_score,
                "py_n": len(py_subset),
                "cpp_n": cppm.num_cse,
            })
            if len(rows) % 50 == 0:
                print(f"  progress: mid={mid} valid={len(rows)} ({time.time()-t0:.0f}s)")

    if not rows:
        print("no rows"); return 1

    heur = np.array([r["heur"] for r in rows])
    py = np.array([r["py"] for r in rows])
    cpp = np.array([r["cpp"] for r in rows])
    dpy = (py - heur) / heur * 100
    dcpp = (cpp - heur) / heur * 100

    print(f"\nEvaluated {len(rows)} methods with viable candidates:")
    _summary("Python-driven",   dpy)
    _summary("C++-embedded",    dcpp)
    diff = dcpp - dpy
    print(f"\nPaired (C++ minus Python), n={len(diff)}:")
    print(f"  |cpp - py| < 0.05pp: {(np.abs(diff) < 0.05).sum()}")
    print(f"  |cpp - py| < 0.5pp:  {(np.abs(diff) < 0.5).sum()}")
    print(f"  |cpp - py| >= 0.5pp: {(np.abs(diff) >= 0.5).sum()}")
    print(f"  |cpp - py| mean:     {np.abs(diff).mean():.4f}pp")
    print(f"  |cpp - py| median:   {np.median(np.abs(diff)):.4f}pp")

    if args.out_csv:
        import csv
        with open(args.out_csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["method_id","heur","py","cpp","py_n","cpp_n","py_pct","cpp_pct","diff_pct"])
            for i, r in enumerate(rows):
                w.writerow([r["method_id"], r["heur"], r["py"], r["cpp"],
                            r["py_n"], r["cpp_n"], f"{dpy[i]:+.4f}",
                            f"{dcpp[i]:+.4f}", f"{diff[i]:+.4f}"])
        print(f"\nWrote {args.out_csv}")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
