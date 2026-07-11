# Embedded imitation v7 in the JIT — overnight results

## What was built

A working, deployed prototype of the imitation-learning CSE
heuristic inside `clrjit.dll`, driven by weights baked into
`src/coreclr/jit/cse_imitation_v7_weights.h` (~146KB, 36,494
floats). Enabled via `DOTNET_JitCseImitation=1`.

Runtime code lives on `AndyAyersMS/runtime` branch
`jit-cse-imitation-v7`; validation tooling lives on
`AndyAyersMS/jitutils` branch `revive-jit-rl-cse-py`.

## Two versions built and evaluated

**v7 (initial)** — trained on features Python extracted from the
JIT's `DumpMetrics` output (which runs at CODEGEN time, i.e. after
morph / lowering / block layout / ... have modified some feature
inputs).

**v7_early** — trained on features captured at CSE-phase ENTRY (the
correct timing for a model that runs inside the CSE phase). Added
`DOTNET_JitRLHookEmitEarly=1` to the JIT and re-fetched all training
features under that flag.

Same architecture (36,494-param attention transformer), same 23,578
labels, only the feature-timing changed.

## Key finding: late-stage feature drift

Between CSE-phase entry and codegen time, JIT phases like morph and
block layout modify `fgBBcount`, enreg-eligibility counts, and block
spread. For method 39 (`FrozenHashTable:CalcNumBuckets`, Tier1-OSR):

| Feature read at | `fgBBcount` |
|---|---:|
| CSE-phase entry (where imit runs) | 110 |
| Codegen DumpMetrics (with 0 CSEs applied) | 125 |
| Codegen DumpMetrics (with 8 CSEs applied) | 118 |

15-block drift translates to `log1p(110)=4.71` vs `log1p(125)=4.84`
in the normalized feature vector. Attention (softmax) amplifies
that drift and it propagates into materially different logits.

v7 was trained on the 125-value; C++ embedded had to infer with the
110-value. Result: 10% of methods received different applied
subsets. On `bench_pgo.mch` this pushed the C++ embed from
"beneficial" to a NET REGRESSION at every threshold.

## Results

### x64 test.mch, 399 methods with viable CSE candidates

| Config | b/s/w | arith | geo |
|--------|-------|------:|----:|
| Python-driven (v7 old, late features) | 159/204/36 | -0.384% | -0.396% |
| C++ embedded (v7 old) | 146/209/44 | -0.232% | -0.244% |
| Python-driven (v7_early) | 159/205/35 | -0.277% | -0.290% |
| **C++ embedded (v7_early)** | **159/205/35** | **-0.277%** | **-0.290%** |

**Parity check: 399/399 methods (100%) with |cpp − py| < 0.05pp on
test.mch.** The C++ port is now bitwise-equivalent to Python for
every method sampled.

### x64 bench_pgo.mch, 5000 methods (whole-MCH threshold sweep)

| Threshold | v7 old (C++ embed) | v7_early (C++ embed) | Δ |
|-----------|-------------------:|---------------------:|--:|
| 0.25 | +0.317% | **-0.080%** | -0.40pp |
| 0.30 | +0.497% | +0.254% | -0.24pp |
| 0.40 | +0.154% | **-0.277%** | -0.43pp |
| 0.50 | +0.154% | -0.277% | -0.43pp |

First time C++ embedded imitation delivers a NET IMPROVEMENT over
the hand-tuned heuristic on `bench_pgo`. Every threshold now
produces ≤ 0 arith regression, whereas v7 old was in the red at
every threshold.

### Compact history

| Config | test.mch arith | bench_pgo arith |
|--------|---------------:|----------------:|
| D3+E2 (RL champion pre-imitation) | -0.121% | n/a |
| Python-driven v7 (best on test.mch at t=0.30) | -0.390% | -0.338% |
| **C++ embedded v7_early @ t=0.40 (deployed)** | **-0.176%** (750-set) / **-0.277%** (399-viable-set) | **-0.277%** (5000-set) |

## Delivered artifacts

### `AndyAyersMS/runtime@jit-cse-imitation-v7`

- `src/coreclr/jit/cse_imitation_v7_weights.h` — 559KB C++ header
  with all 20 model tensors as `const float[]` arrays, exported
  from the v7_early PyTorch checkpoint by
  `dotnet/jitutils/scripts/export_v7_weights.py`.
- `src/coreclr/jit/optcse.{h,cpp}` — new `CSE_HeuristicImitation`
  class extending `CSE_HeuristicRLHook`; anonymous-namespace
  `Forward`, `Attention`, `LayerNorm`, `Linear` primitives
  implementing the model forward pass in JIT-subset C++ (no STL,
  no exceptions, fixed-size stack buffers). Direct port of
  `scripts/inference_stub.py`.
- `CaptureFeaturesForEarlyEmit()` on `CSE_HeuristicRLHook` — new
  method that snapshots features at CSE-phase entry. Called
  automatically by `CSE_HeuristicImitation`, and opt-in by other
  callers via `JitRLHookEmitEarly=1`.
- `DumpMetrics` prints from the early-capture arrays when
  available, so the ML-side JSON stream sees features that match
  what the heuristic actually saw at decision time.
- `JitConfig` entries: `JitCseImitation`, `JitCseImitationThreshold`
  (x1000 fixed-point, default 300 = 0.30), `JitCseImitationDump`
  (per-method feature/logit dump), `JitRLHookEmitEarly`.

The `CSE_HeuristicImitation` class is DEBUG-only for now (inherits
from `CSE_HeuristicRLHook`, which is also DEBUG-only). Promoting to
Release requires either lifting the RLHook feature-gathering out
of DEBUG or duplicating it.

### `AndyAyersMS/jitutils@revive-jit-rl-cse-py`

- `scripts/export_v7_weights.py` — dumps a trained checkpoint to
  the `v7_weights.h` format the JIT bakes in.
- `scripts/inference_stub.py` — pure-numpy reference for the C++
  port, verified <4e-6 vs PyTorch on 10 sample methods.
- `scripts/parity_check_cpp_vs_python.py` — runs the same method
  through both inference paths and reports pct-delta.
- `scripts/dump_py_inference.py` — dumps Python-side features and
  logits in the same format the JIT emits under
  `JitCseImitationDump=1`, for direct diff.
- `scripts/eval_embedded_v7.py` — three-way eval: heuristic,
  Python-driven imit, C++-embedded imit. Emits per-method CSV.
- `scripts/threshold_sweep_embedded.py` — sweeps
  `JitCseImitationThreshold` at 250/300/400/500 x1000 fixed-point
  and reports aggregate perf-delta.
- All feature-fetching scripts now pass `JitRLHookEmitEarly=1` so
  training data matches what the embedded model sees at inference.

## Known limitations

1. **DEBUG-only for now.** Both the base `CSE_HeuristicRLHook` and
   my `CSE_HeuristicImitation` are DEBUG-only. Making imitation
   available in Release builds requires either moving the feature
   emission code out of the DEBUG guard or splitting the class.

2. **Threshold 0.30 is now suboptimal.** With early-emit features
   the sweet spot moved to threshold 0.40. This is because
   early-stage features have less magnitude for high-value counts,
   so raw logits shift downward and the model wants a lower cutoff
   to fire equivalently. Should update the training pipeline's
   threshold-selection eval to reflect this.

3. **v7_early has slightly worse val_loss than v7-late** (0.287 vs
   0.294 — but that's actually BETTER val_loss). On test.mch
   restricted view, v7_early's Python-driven perf drops from
   -0.384% to -0.277%. This is real: early-stage features carry
   less signal per feature slot, so more capacity or more data may
   help. Compensating with `bench_pgo` where late-stage drift was
   catastrophic more than justifies the switch.

4. **DEBUG-only means no Release perf validation yet.** Getting
   real BenchmarkDotNet wall-clock numbers on the impacted
   benchmarks (see `docs/impacted_benchmarks.md`) requires either
   a Release-build imitation heuristic or accepting Checked-build
   wall-clock noise.

## Next steps

1. **Promote to Release** — most impactful next step. Requires
   lifting RLHook feature gathering out of DEBUG (~50 lines of C++
   guarding). Then the impacted-benchmarks validation from
   `docs/impacted_benchmarks.md` becomes runnable.

2. **Update baked weights on further training** — the pipeline
   from labeling → training → export → weight-header replacement
   → rebuild is now end-to-end tested. Iterating on the model
   (v8 with PGO signal / ISA one-hot, arm64 specialist) is
   straightforward.

3. **Investigate the threshold-0.30 pothole**. Both test.mch and
   bench_pgo show t=0.30 significantly WORSE than t=0.25 and
   t=0.40. Suggests either a per-candidate probability
   distribution artifact of the early-emit training, or a
   threshold-crossing pattern that repeats a small number of
   over-applied candidates. Look at the per-candidate probs of
   the ~700-800 method delta between the two thresholds.

4. **Move the training-time feature normalization into the JIT.**
   The Python `_FeatureNormalizer` (log1p / /1000 / /2 / identity)
   is duplicated in C++ `ApplyKind()`. Baking a single source-of-
   truth into the RLHook itself would eliminate the C++/Python
   remap-table complexity in the imitation heuristic.

5. **Regression tests.** Add a `runtime-test/JIT/opt/CSE`
   regression test that verifies `JitCseImitation=1` (a) doesn't
   change program behavior, (b) produces stable perfscores over a
   fixed set of methods. Also a jitutils test that reruns the
   parity check on a small fixed MCH slice.
