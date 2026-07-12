# MDBench / Dhrystone deepdive → v11 feature proposal

## Motivation

v10 achieves -0.2% perfscore on bench_pgo and 6/0 wall-clock wins/losses
on 8 BDN benchmarks (arith -2.37%). But a small tail of benchmarks
(MDLogicArray, MDMulMatrix Tier1-OSR, NDhrystone) still regresses on
perfscore even at the wall-clock-tuned threshold t=0.50. We wanted to
understand WHY the imitation model over-fires on these methods to design
a targeted fix.

## Method

- Rebuilt Checked JIT with is_osr feature emission and v10 weights.
- Wrote `scripts/dhrystone_deepdive.py` to run per-method superpmi
  comparisons on 25 Benchstone / EMFloat / Dhrystone methods pulled
  from `benchmarks.run_pgo.windows.x64.checked.tier1.mch`.
- Wrote `scripts/compare_modes.py` to sweep the first 8000 methods and
  aggregate deltas by `compile_mode`.

## Finding: 100% of the perfscore regression is on Tier1-OSR

For methods 1..8000 of bench_pgo.mch at t=0.50:

| Mode      | n    | wins | losses | mean_d% | weighted total delta   |
|-----------|-----:|-----:|-------:|--------:|-----------------------:|
| Tier1     | 3939 |  731 |    108 | -0.517% | -0.009% (89.1M ~ neutral) |
| Tier1-OSR |  887 |  194 |     69 | -0.189% | **+12.946%** (156.6M → 176.9M) |

Total regressions >0.5%: 177
Regressions on OSR: 69 (39% by count, but ~100% by weighted perfscore mass)

**Perfscore-weighted regression, all methods**: +22.07%.
**Perfscore-weighted regression, OSR-only**: +22.24%.

The 108 non-OSR regressions have TINY perfscores (13, 21, 25 units).
Their per-benchmark delta% looks large but the absolute impact on
wall-clock is negligible.

## Top 3 regressions all Tier1-OSR

| idx  | delta%   | heur perf | imit perf | h_n | i_n | mode      | method                                          |
|-----:|---------:|----------:|----------:|----:|----:|-----------|-------------------------------------------------|
| 7372 | +58.38%  | 5,460,486 | 8,648,480 | 25  | 20  | Tier1-OSR | Benchstone.BenchF.InvMt:Test():bool             |
| 3843 | +22.19%  | 37,691,693| 46,056,443| 17  | 24  | Tier1-OSR | Benchstone.MDBenchI.MDMulMatrix:Inner           |
| 3845 | +22.19%  | 37,899,782| 46,310,542| 17  | 24  | Tier1-OSR | Benchstone.MDBenchI.MDMulMatrix:Inner (clone)   |

The pattern in MDMulMatrix:
- **Tier1-OSR** (3845): heuristic picks 17 CSEs on 30 candidates.
  Imitation picks 24 → +22% perfscore regression.
- **Tier1**       (3846): heuristic picks 24 CSEs on 25 candidates.
  Imitation picks 25 → +0.03% (neutral).

The same source method compiles fine at Tier1 with 24 CSEs but blows
up at Tier1-OSR with 24 CSEs. The heuristic's frame/spillWeight logic
knows to be conservative on OSR; the imitation model doesn't have that
signal.

## Why is OSR different?

Tier1-OSR methods:
- Enter mid-loop (at a patchpoint), not at the method prologue.
- Have all locals from the interpreter frame passed on the stack in a
  special "OSR frame".
- The JIT builds an extended frame that includes both the interpreter
  frame (untouched, so callee-preserved regs must be spilled around it)
  and its own JIT frame on top.
- Callee-saved integer registers spent on the interpreter frame are
  UNAVAILABLE for register allocation in the JIT body.

Net effect: fewer registers available for enregistering CSE temporaries.
The heuristic knows this indirectly via `aggressiveRefCnt` / spill
weights, but the ML model's per-candidate features don't fully capture
it — both Tier1 and Tier1-OSR variants of MDMulMatrix have essentially
identical method-level features (only `spill_at_weight_x1000` differs
slightly: 15607 vs 17916).

## Feature to add

Method-level bool `is_osr` from `m_compiler->opts.IsOSR()`.

Emission slot: 12th in `s_methodFeatureNames`, becoming Python
METHOD_SCHEMA slot 16. `maxMethodFeatures` bumps 11 → 12; METHOD_SCHEMA
length 16 → 17.

Trained model then has a direct signal to be more conservative on
Tier1-OSR methods without needing to infer it from correlated features.

## Verification (post-training)

Post-v11 retrain, `dhrystone_deepdive.py` should show MDMulMatrix
Tier1-OSR at ~0% delta (matching heuristic's 17-CSE choice). InvMt
Test():bool should also recover. If it does, this is a real signal;
if it doesn't, the model may need additional capacity or a targeted
loss term to weight OSR examples more heavily.
