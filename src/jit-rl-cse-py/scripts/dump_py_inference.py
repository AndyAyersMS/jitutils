"""Dump Python-side normalized features + logits for one method, for
direct comparison against C++ JitCseImitationDump output.
"""
from __future__ import annotations
import argparse, json, os, sys
import numpy as np, torch
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from scripts.train_imitation import ImitationScorer, _NORMALIZER
from jitml.jit_cse import JitCseEnv
from jitml.superpmi import SuperPmi

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True)
    p.add_argument("--checkpoint", required=True)
    p.add_argument("--config", required=True)
    p.add_argument("--method", type=int, required=True)
    args = p.parse_args()

    with open(args.config) as f: cfg = json.load(f)
    model = ImitationScorer(**{k: cfg[k] for k in ("embed_dim","num_heads","num_attn_layers","dropout") if k in cfg})
    state = torch.load(args.checkpoint, map_location="cpu", weights_only=True)
    model.load_state_dict(state, strict=False); model.eval()

    with SuperPmi(args.mch, args.core_root) as spmi:
        m = spmi.jit_method(args.method, JitMetrics=1, JitRLHook=1,
                            JitRLHookEmitFeatureNames=1, JitRLHookCSEDecisions=[])
    if m is None:
        print("failed to jit method"); return 1

    obs = JitCseEnv.get_observation(m)
    cn, mn = _NORMALIZER.normalize(obs["candidates"], obs["method"])

    print(f"PY_METHOD_FEAT," + ",".join(f"{v:.6f}" for v in mn))
    for i in range(len(m.cse_candidates)):
        if i >= 32: break
        print(f"PY_CAND_FEAT #{i}," + ",".join(f"{v:.6f}" for v in cn[i]))

    cand_t = torch.from_numpy(cn.astype(np.float32)).unsqueeze(0)
    method_t = torch.from_numpy(mn.astype(np.float32)).unsqueeze(0)
    with torch.no_grad():
        logits = model(cand_t, method_t).squeeze(0).cpu().numpy()
    probs = 1.0 / (1.0 + np.exp(-logits))
    print("PY_LOGITS," + ",".join(f"{v:.6f}" for v in logits))
    print("PY_PROBS," + ",".join(f"{v:.6f}" for v in probs))

if __name__ == "__main__":
    sys.exit(main() or 0)
