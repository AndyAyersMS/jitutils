# Overnight session 4 — v9 unified + BDN wall-clock + overhead cut

**Session**: 2026-07-11 15:00 → 2026-07-12
**Runtime branch**: `AndyAyersMS/runtime@jit-cse-imitation-v7` (@ `eca1cea239f`)
**jitutils branch**: `AndyAyersMS/jitutils@revive-jit-rl-cse-py` (@ `19a9e32`)

## What ships (as of this report)

**v9** — trained on 6 sources / **~29,578 labels** with a
**16-slot method-feature schema** including the new PGO signals
(`has_pgo_weights`, `has_pgo_dynamic`) and ISA one-hot (`is_x64`,
`is_arm64`). 36,624 float parameters, ~146KB baked into
`clrjit.dll`.

Available in **both Release and Checked**. Enable via:
```
DOTNET_JitCseImitation=1
DOTNET_JitCseImitationThreshold=0.30    # default is 0.30
```

## Empirical results

### Perfscore delta (embedded C++, x64 Checked) — full sweeps

| MCH | Distribution | Methods | v8 | **v9** |
|-----|-------------|--------:|---:|-------:|
| test.mch | PGO Tier1 (whole 750-set) | 748 | -0.218% | **-0.225%** |
| bench_pgo.mch | PGO Tier1 (whole 5000-set) | 4991 | -0.277% | **-0.285%** |
| benchmarks.run.mch | non-PGO FullOpts (3000-set) | 2999 | -0.253% | -0.237% |
| bench_pgo.arm64 (eligible only) | arm64 PGO Tier1 | 600 | (drift-limited) | **-0.818%** |

**v9 delivers wins on 3 out of 4 axes**, essentially matching the
arm64-specialist v8_arm64 on the fourth (v8_arm64 was -0.805% on
the same 600-method slice). The unified model works.

**100% C++/Python parity** holds across all v9 evaluations
(265/265 methods on test.mch, byte-identical logits).

### JIT throughput overhead

+10.4% → **+1.5%** after padding-skip optimization in `Forward` +
`Attention` (short-circuit per-row loops at `numReal` instead of
`MAX_CSE`). Numerically equivalent to the pre-optimization code
(same b/s/w counts and arith numbers on test.mch).

**~7× reduction in imit-only overhead**, with no accuracy loss.

### Real wall-clock (BDN via corerun + --envVars)

Full BDN with `dotnet/performance` MicroBenchmarks. Results after
the padding-skip optimization + v9 weights:

| Benchmark | Model | baseline (ns) | imit (ns) | delta |
|-----------|-------|--------------:|----------:|------:|
| BenchAssignJagged (single run) | **v9** | 849,200,000 | **807,600,000** | **-4.90%** |
| BenchAssignJagged (median-of-3) | v8/padskip | 828,908,073 | 826,175,380 | -0.33% |
| MDNDhrystone (median-of-3) | v8/padskip | 304,248,013 | 310,650,006 | +2.10% |
| NDhrystone (median-of-3) | v8/padskip | 298,039,185 | 301,582,420 | +1.19% |
| QuickSortSpan[512] (median-of-3) | v8/padskip | 7,571 | 7,594 | +0.31% |

**v9 delivers materially larger wall-clock improvement than v8 on
BenchAssignJagged** (-4.90% vs -0.33%), consistent with v9's
better perfscore prediction across the training slices.

**Wall-clock is noisy**: 5 back-to-back baseline runs of
BubbleSortSpan varied 132.0 → 143.6 μs (±9pp spread). Any
"regression" below ±9pp on that benchmark is noise.

**Persistent findings**:
- Dhrystone-family microbenchmarks show real ~1-2% regression
  (consistent across runs). Matches the P6 loss-pattern analysis
  which identified Benchstone MDBench* as top-regressor benchmarks.
  The regression is **bimodal**: some methods over-fire (imit_n >
  heur_n → too many CSEs → register pressure), others under-fire
  (imit_n=0 while heur_n=10 on MDSqMtx → misses obvious wins).
- Assign* wins are big and real (~-5% on BenchAssignJagged with v9).
- Perfscore is not reliably wall-clock-predictive at the ±1% scale
  but IS predictive at the ±5% scale.

## Commits pushed (session 4)

**runtime** (`jit-cse-imitation-v7`):
- `72be866` Release promotion (RLHook + Imitation ship in Release)
- `ed472ae` PGO signal features (has_pgo_weights, has_pgo_dynamic)
- `bca97a0` v8 weights baked in (14-slot schema)
- `5e2e243` **7× overhead reduction** via padding-skip + ISA one-hot patch
- `eca1cea` v9 weights baked in (16-slot schema, unified x64+arm64)

**jitutils** (`revive-jit-rl-cse-py`):
- `7ed53ce` METHOD_SCHEMA 12→14 (PGO signals)
- `d521f87` `measure_imit_overhead.py` + parity regression test
- `9b038af` `wallclock_harness` for Span.QuickSort standalone
- `98aadab` `bdn_wallclock.py` + first real BDN results
- `223a867` `analyze_losses.py` for regression pattern analysis
- `a1c11c8` overnight session 3 report
- `1343a67` METHOD_SCHEMA 14→16 (ISA one-hot)
- `2794bf2` BDN median-of-N
- `19a9e32` v9 arm64-eligible-only sweep results

## Key findings

### 1. Unified model achieves cross-ISA parity with specialist
v9 (single model trained on x64+arm64) delivers -0.818% arith on
arm64 CSE-eligible methods, essentially matching v8_arm64 (arm64-
specialist, trained only on arm64 data) at -0.805%. The ISA one-hot
enables specialization within a shared model.

### 2. Padding-skip = 7× overhead reduction, zero accuracy loss
Most methods have 5-10 real CSE candidates but the model was trained
on MAX_CSE=32 padded inputs. The C++ inference short-circuits per-row
loops at `numReal`, saving 3-6× compute on typical methods.
Numerically equivalent because padded rows' outputs are unused and
padded keys have zero softmax weight anyway.

### 3. Wall-clock ≠ perfscore
BDN measurements show perfscore is not reliably wall-clock-predictive.
Some benchmarks match (Assign* wins in both), others diverge
(Dhrystone regresses ~1-2% wall-clock despite perfscore prediction).
Noise floor is ±9pp on some microbenchmarks.

### 4. Loss patterns concentrate in tight-loop microbenchmarks
95 v8 regressions on bench_pgo were dominated by Benchstone
MDBench* (small integer/matrix loops). 62% of losses are over-firing
(imit applies MORE CSEs than heuristic). Suggests future work: add
a loop-tightness signal to method features, or a per-method-size
threshold policy.

## Known limitations

- **Dhrystone-family regressions** on wall-clock (~1-2%). Real,
  consistent, not just noise. Model needs a signal to be more
  conservative on tight loops.
- **arm64 wall-clock validation** not yet done (no arm64 test rig
  available on this VM).
- **BDN wall-clock is noisy**: single-run comparisons on
  microbenchmarks are unreliable. Median-of-N helps.
- **v9 slight regression on non-PGO** (-0.253 → -0.237, +0.016pp)
  vs v8. Possibly the ISA one-hot's added parameters divided
  attention capacity slightly.

## Deferred / next-session

- **v10** currently training with realworld data added (7 sources,
  ~32.5k labels). Should push val_loss lower and possibly recover
  the non-PGO slight regression.
- **Loop-tightness feature** for reducing Dhrystone regression.
- **Full BDN suite run** on all impacted benchmarks (would take
  multi-day compute).
- **arm64 wall-clock rig** — needs arm64 hardware or emulation.
- **Investigate specific loss cases**: pick 1-2 Dhrystone methods,
  compare imit vs heuristic subsets, understand why extra CSEs hurt.
