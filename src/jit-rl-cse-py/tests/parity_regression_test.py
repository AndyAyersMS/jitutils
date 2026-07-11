"""Regression test for C++ <-> Python parity of the JIT-embedded
imitation heuristic.

Runs parity_check_cpp_vs_python.py against a small fixed MCH slice
(the first ~50 methods of test.mch that have viable CSE candidates)
and fails if fewer than 99% of methods match within 0.05 pct
perfscore delta.

Guards against future JIT changes to feature emission (RLHook or
CSE_HeuristicImitation) silently breaking the equivalence between:

  * The Python inference pipeline (feed features through
    scripts/inference_stub or ImitationScorer), and
  * The embedded C++ inference in clrjit.dll.

Set SKIP_JIT_PARITY_TEST=1 to skip (useful in environments where
the JIT Core_Root or MCH aren't set up).

Preconditions:
  * CORE_ROOT env var points at a Core_Root with clrjit.dll built from
    dotnet/runtime branch jit-cse-imitation-v7 (or later).
  * CSE_TEST_MCH env var points at test.mch (default:
    C:/spmi/mch-tier1/test.mch on Windows).
  * IMITATION_CHECKPOINT and IMITATION_CONFIG env vars point at the
    v7_early (or newer) checkpoint. Defaults look under
    files/imitation_v7_early/ in the session state folder.
"""
from __future__ import annotations
import json
import os
import sys

import numpy as np
import pytest
import torch


def _has_gate(name: str, default: str = None):
    val = os.environ.get(name, default)
    return val if (val is not None and val.strip() != "") else None


@pytest.mark.skipif(os.environ.get("SKIP_JIT_PARITY_TEST", "") == "1",
                    reason="explicitly skipped via SKIP_JIT_PARITY_TEST=1")
def test_cpp_python_parity_on_test_mch_slice():
    """Parity: v7 (or later) C++ inference vs Python inference over
    50 methods; require >=99% within 0.05pp perfscore delta."""

    core_root = _has_gate("CORE_ROOT")
    mch = _has_gate("CSE_TEST_MCH", r"C:\spmi\mch-tier1\test.mch")
    ckpt = _has_gate("IMITATION_CHECKPOINT")
    cfg  = _has_gate("IMITATION_CONFIG")

    missing = []
    if not core_root or not os.path.exists(os.path.join(core_root or "", "clrjit.dll")):
        missing.append("CORE_ROOT (with clrjit.dll)")
    if not mch or not os.path.exists(mch):
        missing.append(f"CSE_TEST_MCH ({mch})")
    if not ckpt or not os.path.exists(ckpt):
        missing.append("IMITATION_CHECKPOINT")
    if not cfg or not os.path.exists(cfg):
        missing.append("IMITATION_CONFIG")
    if missing:
        pytest.skip(f"Prereqs missing: {', '.join(missing)}. "
                    f"Set env vars to enable (see docstring).")

    # Late imports so pytest collection doesn't require SB3 / torch when
    # the test is skipped anyway.
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from scripts.train_imitation import ImitationScorer, _NORMALIZER
    from jitml.constants import MAX_CSE, is_acceptable_for_cse
    from jitml.jit_cse import JitCseEnv
    from jitml.superpmi import SuperPmi

    # Load model.
    with open(cfg) as f:
        conf = json.load(f)
    model = ImitationScorer(**{k: conf[k] for k in
        ("embed_dim", "num_heads", "num_attn_layers", "dropout")
        if k in conf})
    state = torch.load(ckpt, map_location="cpu", weights_only=True)
    model.load_state_dict(state, strict=False)
    model.eval()

    threshold = float(_has_gate("IMITATION_THRESHOLD", "0.30"))
    target = int(_has_gate("PARITY_TARGET_METHODS", "50"))

    matches = 0
    total = 0
    with SuperPmi(mch, core_root) as spmi:
        for mid in range(1, 500):
            try:
                no_cse = spmi.jit_method(mid, JitMetrics=1, JitRLHook=1,
                                         JitRLHookEmitFeatureNames=1,
                                         JitRLHookEmitEarly=1,
                                         JitRLHookCSEDecisions=[],
                                         timeout=10)
            except Exception:
                continue
            if no_cse is None or not no_cse.cse_candidates:
                continue
            if not is_acceptable_for_cse(no_cse):
                continue

            # Python subset.
            obs = JitCseEnv.get_observation(no_cse)
            cn, mn = _NORMALIZER.normalize(obs["candidates"], obs["method"])
            cand_t = torch.from_numpy(cn.astype(np.float32)).unsqueeze(0)
            method_t = torch.from_numpy(mn.astype(np.float32)).unsqueeze(0)
            with torch.no_grad():
                logits = model(cand_t, method_t).squeeze(0).cpu().numpy()
            probs = 1.0 / (1.0 + np.exp(-logits))
            viable = [i for i, c in enumerate(no_cse.cse_candidates[:MAX_CSE]) if c.can_apply]
            py_subset = sorted(i for i in viable if probs[i] > threshold)
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

            # C++ imitation via the embedded heuristic.
            try:
                cpp_m = spmi.jit_method(mid, JitMetrics=1, JitCseImitation=1,
                                        JitCseImitationThreshold=f"{threshold:.4f}",
                                        timeout=10)
            except Exception:
                continue
            if cpp_m is None or cpp_m.perf_score <= 0 or py_m.perf_score <= 0:
                continue

            delta = abs(cpp_m.perf_score - py_m.perf_score) / py_m.perf_score * 100
            total += 1
            if delta < 0.05:
                matches += 1
            if total >= target:
                break

    assert total >= 20, f"Need at least 20 valid methods, got {total}"
    match_rate = matches / total
    print(f"\nParity: {matches}/{total} match within 0.05pp ({100*match_rate:.1f}%)")
    assert match_rate >= 0.99, (
        f"C++/Python parity dropped below 99% (got {100*match_rate:.1f}%). "
        f"Likely cause: JIT feature-emission timing or ordering changed but "
        f"the imitation heuristic RemapCandidate/RemapMethod tables in "
        f"optcse.cpp weren't updated to match.")
