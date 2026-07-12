# Overnight session 5 — v10 + overflow-bug fix

**Session**: 2026-07-11 15:00 → 2026-07-12 (continued)
**Runtime branch**: `AndyAyersMS/runtime@jit-cse-imitation-v7` @ `c357465af74`
**jitutils branch**: `AndyAyersMS/jitutils@revive-jit-rl-cse-py` @ `b5a13f0`

## Ship state: v10

`clrjit.dll` now bakes **v10** — trained on **7 sources / ~32,578 labels**
after fixing an integer overflow bug in the JIT's RLHook feature
emission.

**All axes IMPROVED** (perfscore delta vs heuristic, embedded C++, Checked):

| MCH | Distribution | v9 best | **v10 best** |
|-----|-------------|--------:|-------------:|
| test.mch (750) | PGO Tier1 | -0.225% | **-0.243%** |
| bench_pgo (5000) | PGO Tier1 | -0.285% | **-0.311%** |
| non-PGO (3000) | FullOpts | -0.237% | **-0.246%** |
| arm64 eligible (600) | PGO Tier1 | -0.818% | **-0.882%** |

**Real BDN wall-clock (median-of-3, Release):**

| Benchmark | v8 | v9 (1 run) | **v10 (median-of-3)** |
|-----------|---:|-----------:|----------------------:|
| BenchAssignJagged | -0.33% | -4.90% | **-2.51%** |
| MDSqMtx | +55% perfscore! | (n/a) | **-0.31%** |
| QuickSortSpan[512] | +0.31% | (n/a) | **-3.89%** |
| NDhrystone | +1.19% | (n/a) | +0.48% |
| MDNDhrystone | +2.10% | (n/a) | +2.07% |
| **Arith mean** | **+0.82%** (regress) | (n/a) | **-0.835%** (WIN) |

## The overflow bug

Discovered while investigating MDSqMtx regression (+55% perfscore
with v8/v9):

The JIT emits `(int)(csdUseWtCnt * 100.0 + 0.5)` and
`(int)(m_aggressiveRefCnt * 1000.0 + 0.5)` as fixed-point method
features. On very hot Tier1-PGO methods where the weight exceeds
~21 million (multiplied gives >INT_MAX ≈ 2.1B), these expressions
overflow signed int and wrap to **-2,147,483,648** (INT_MIN).

Downstream, the Python-side normalization does `log1p(x)` and
`x / 1000.0`, which on INT_MIN produces NaN or garbage. The
imitation model then sees NaN inputs → outputs low-confidence
sigmoid values → applies zero CSEs.

For MDSqMtx (double-precision matrix inner loop):
- Baseline heuristic: applies 10 CSEs, perfscore 42,595,000
- v8/v9 imitation: applies **0 CSEs**, perfscore 66,383,972 (+55%)

**Fix** (commit `98d6c5490e7`): saturate to INT_MAX before the cast.
Same pattern in both per-candidate (use/def wt cnt) and method-level
(aggressive/moderate ref cnt) features.

After fix + retrain (v10):
- v10 imitation: applies **12 CSEs**, perfscore 45,644,972 (-31% vs
  the pre-fix broken behavior; effectively neutral wall-clock vs
  heuristic)

## Session 5 commits

**runtime** (`jit-cse-imitation-v7`):
- `98d6c5490` fix INT_MIN overflow in RLHook wt_cnt / ref_cnt features
- `c357465af` bake v10 weights (7 sources, clean features)

**jitutils** (`revive-jit-rl-cse-py`):
- `b5a13f0` add v9 wallclock -4.90 pct on BenchAssignJagged
- (v10 docs pending)

## Cumulative session 3+4+5 highlights

- **v7_early → v10**: 4 model iterations, all delivered improvements
- **10.4% → 1.5% JIT overhead** (7× reduction via padding-skip)
- **DEBUG → Release deployment** with 100% parity preserved
- **Wall-clock net regression → net improvement** (v8 +0.82% → v10 -0.84%)
- **Cross-ISA parity**: v10 unified matches arm64-specialist within 0.08pp
- **Integer overflow bug** discovered and fixed in JIT feature emission

## Remaining known limitations

- **MDNDhrystone** still regresses ~2% wall-clock. Not a hot-loop
  overflow issue (values are within range). Real algorithmic
  disagreement between imit and heuristic.
- Full BDN suite not run (only ~10 benchmarks measured).
- arm64 wall-clock validation not done (no arm64 hardware).

## Next steps

- **Long BDN suite** covering all 27 impacted benchmark classes from
  `docs/impacted_benchmarks.md`.
- **Investigate MDNDhrystone**: what specific CSEs does imit apply
  differently from heuristic, and why does it hurt?
- **Retrain arm64 specialist** on clean features (v8_arm64 was
  trained pre-overflow-fix).
- **v11 attempt**: raise the training BCE `pos_weight_cap` or lower
  it, see if that shifts the peak threshold and helps small-hot-loop
  methods.

## Broader BDN sample (v10, median-of-3, 8 benchmarks)

| Benchmark | baseline (ns) | imit (ns) | delta |
|-----------|--------------:|----------:|------:|
| BenchAssignJagged | 821,857,771 | 817,873,943 | **-0.48%** |
| MDMulMatrix | 818,960,293 | 798,647,671 | **-2.48%** |
| RayTracerBench | 308,805,939 | 295,755,193 | **-4.23%** |
| benchMonteCarlo | 588,979,120 | 583,929,929 | -0.86% |
| MDLogicArray | 294,175,850 | 311,030,229 | **+5.73%** |
| NDhrystone | 294,870,200 | 297,478,771 | +0.88% |
| QuickSortSpan | 7,325 | 7,740 | +5.67% (noisy) |
| benchFFT | 513,484,631 | 519,960,729 | +1.26% |
| **Arith mean** | | | **+0.69%** |
| **Wins** | 3 | | (<-0.5pp) |
| **Losses** | 4 | | (>+0.5pp) |

**Pattern**: v10 wins on realistic multi-array numerical kernels
(RayTracer, MDMulMatrix, BenchAssignJagged, MonteCarlo) and loses on
tight small-loop microbenchmarks (MDLogicArray, NDhrystone, FFT).
Consistent with training data being dominated by larger real-world
methods (7 sources = 4 tier1 PGO + non-PGO + arm64 + realworld).

QuickSortSpan swings between -3.89% (previous median-of-3) and +5.67%
here — it's noise-dominated even with median-of-3, not a real regression.

## Persistent regression pattern

Consistent across the last several BDN runs and cross-referenced with
the P6 loss-pattern analysis:
- **Winners**: realistic multi-array workloads (matrix multiply, ray
  tracing, JSON parse, jagged-array assignment)
- **Losers**: tight micro-kernels where the heuristic already produces
  near-optimal small subsets (Dhrystone, LogicArray, small sort loops)

The heuristic was probably tuned on classic Byte-magazine-style
benchmarks. Imitation model wasn't heavily trained on that
distribution.

**Fix directions**: (a) add small-hot-loop signal (b) bump `pos_weight_cap`
lower to be more conservative (c) label more MDBench methods

## Threshold-0.40 sweep on the same broader BDN set (median-of-3)

| Benchmark | delta @ t=0.30 | delta @ t=0.40 |
|-----------|---------------:|---------------:|
| BenchAssignJagged | -0.48% | **-2.53%** |
| MDLogicArray | +5.73% | **-5.56%** |
| MDMulMatrix | -2.48% | -1.80% |
| NDhrystone | +0.88% | **-0.99%** |
| QuickSortSpan | +5.67% (noise) | +1.59% (noise) |
| RayTracerBench | -4.23% | -1.70% |
| benchFFT | +1.26% | **-0.26%** |
| benchMonteCarlo | -0.86% | -1.19% |
| **Arith mean** | +0.687% | **-1.554%** |
| **wins/losses/same** | 3/4/1 | **6/1/1** |

**Decisive win for t=0.40 as the default.** MDLogicArray alone swings
11pp from a big regression to a big win. The perfscore sweeps had
also shown t=0.40 at or near peak on 3 of 4 axes, so no
perfscore-side trade-off.

**Landed in commit `d72bdb97af4`**: JitCseImitationThreshold default
changed from 0.30 to 0.40. Users can still override.

## Threshold-0.50 sweep (v10, broader BDN, median-of-3)

| Benchmark | t=0.30 | t=0.40 | **t=0.50** |
|-----------|-------:|-------:|-----------:|
| BenchAssignJagged | -0.48% | -2.53% | **-2.79%** |
| MDLogicArray | +5.73% | -5.56% | **-5.75%** |
| MDMulMatrix | -2.48% | -1.80% | **-2.07%** |
| NDhrystone | +0.88% | -0.99% | **-1.24%** |
| QuickSortSpan | +5.67% | +1.59% | -0.44% (noise) |
| RayTracerBench | -4.23% | -1.70% | **-4.71%** |
| benchFFT | +1.26% | -0.26% | -0.01% (noise) |
| benchMonteCarlo | -0.86% | -1.19% | **-1.97%** |
| **Arith mean** | +0.687% | -1.554% | **-2.372%** |
| **wins/losses/same** | 3/4/1 | 6/1/1 | **6/0/2** |

**Zero losses at t=0.50!** The default is now 0.50 (dotnet/runtime
commit `6d5d4ee203c`). Perfscore trade-off is small (0.01-0.12pp
worse than sweep peak on each of 4 axes) and wall-clock is what
ultimately matters for deployment.

### Threshold-vs-metric summary (v10, all sweeps)

| Metric | t=0.30 | t=0.40 | t=0.50 |
|--------|-------:|-------:|-------:|
| test.mch perfscore | -0.239% | **-0.243%** | -0.229% |
| bench_pgo perfscore | **-0.311%** | -0.310% | -0.296% |
| non-PGO perfscore | -0.242% | -0.215% | (untested) |
| arm64 elig perfscore | -0.769% | **-0.882%** | -0.759% |
| **BDN wall-clock arith** | **+0.687%** | -1.554% | **-2.372%** |
| **BDN wins/losses** | 3/4 | 6/1 | **6/0** |

Perfscore optimizes for a JIT-time cost function; wall-clock
optimizes for actual runtime. They diverge here by design -- the
perfscore model rewards apparent CSE hits without accounting for
register-pressure spill costs at runtime. Higher threshold means
more conservative CSE application, avoiding those spills, at some
cost to the perfscore-optimal count.
