# Unified vs separate models: strategy for cross-cutting distributions

## The problem

Two "different-distribution" axes have emerged that could each argue
for splitting the model into per-axis variants:

1. **PGO vs non-PGO methods.** PGO methods carry calibrated
   execution-count weights; non-PGO methods have JIT-static
   estimates. Weight magnitudes and reliability differ by 10-100×.
2. **Target ISA (x64 vs arm64 vs wasm).** Different register files,
   different absolute per-opcode costs, different CSE thresholds.

## Recommendation: **start unified**

Add both axes as explicit input features to a single model. Only
fall back to separate models if measured per-axis performance
against a unified model falls short by a material margin (≥ 0.1pp
arith-mean pct-delta vs heuristic on the same test slice).

**Concrete arm64 transfer data (2026-07-10 overnight, phase-3):**

Compared v7-x64 (trained on 23,578 x64-only labels) against
v8_arm64 (trained on 2,400 arm64-only labels) on a 600-method
held-out arm64 test slice from
`benchmarks.run_pgo.windows.arm64.checked.mch`:

| Model | Training data | b/s/w vs heur | arith% | geo% |
|-------|--------------|---------------|-------:|-----:|
| v7 (x64), naive transfer | 23,578 x64 | 130/315/155 | **+1.527%** | +0.924% |
| v8_arm64 (native) | 2,400 arm64 | 223/337/40 | **-0.805%** | -0.844% |

Paired diff (v8-arm64 minus v7-x64):
- v8-arm64 strictly better on 236/600 methods
- ~same on 331/600
- v7-x64 strictly better on 33/600

**Interpretation**: Naive cross-ISA transfer without any ISA signal
is a clear net negative: v7 makes many more losing decisions on
arm64 than a small arm64-only model. This does NOT contradict the
unified recommendation — it argues for the ISA one-hot feature. The
model needs an explicit signal that this is arm64 code before it
can specialize its predictions. Whether that signal is best carried
via a shared model with an ISA feature (unified) or via separate
per-ISA models (fully specialized) is what v9 (unified) needs to
measure. The bar v9 must clear: match v8_arm64's -0.805% on the
arm64 slice AND match v7-x64's -0.390% on the x64 slice, all with
one model.

## Rationale

### 1. Feature encoding is trivial

- **PGO axis**: two booleans (`has_pgo_weights`, `has_pgo_dynamic`)
  from `docs/pgo_signal_feature_spec.md`. Total added parameters:
  ~256 (two extra input slots × 128 output units for the first
  feed-forward layer).
- **ISA axis**: 3-way one-hot (`isa_x64`, `isa_arm64`, `isa_wasm`)
  emitted trivially from the JIT (single `#if defined(TARGET_*)`
  check). Total added parameters: ~384.

For v7 (36k total params), adding ~640 params for both axes is a
< 2% capacity increase. No structural refactor needed.

### 2. Transfer learning is a strict positive

- arm64 tier1+PGO likely has ~1/3 to 1/2 the training-eligible
  method count of x64 (validation from Phase 3's arm64 scan will
  confirm exact numbers). A unified model gets ~2-3× the effective
  training pool for arm64-specific patterns via shared feature
  extraction on x64-labeled methods.
- Non-PGO methods have entirely different weight statistics. Left
  as a separate distribution the model learns two disjoint policies
  from disjoint samples; sharing the extractor layers lets the
  non-PGO subset benefit from the PGO subset's much better
  gradient signal on the shared perceptual features (candidate cost,
  live-across-call, register class, etc.).

### 3. Attention over candidates is already ISA-agnostic

The v7 attention model reasons about per-candidate features:
type, cost_ex/cost_sz, use/def counts, live-across-call,
containable, etc. These are ALL emitted by the JIT in
target-independent units:

- `cost_ex` / `cost_sz` are unitless multiples derived from
  `IND_COST_EX` / `IND_COST_SZ`, target-scaled by the JIT itself.
- `enreg_count_int/float/simd/msk` already partition by register
  class, absorbing part of the ISA gap.
- `has_call` / `live_across_call` are structural, not target-
  specific.

The dominant ISA-specific effect is method-level
(`m_registerPressure` differs) and is already normalized by the
JIT-emitted `spill_at_weight_x1000` signal.

### 4. Empirical evidence from v7's own weight regimes

v7 already handles internal weight-magnitude heterogeneity:
`libraries_tests` (BBINSTR-heavy, additional profile instrumentation
in the emitted code) and `benchmarks_pgo` (pure Tier1 PGO) differ in
weight statistics and per-candidate distributions. v7 (+libtests)
IMPROVED overall (-0.344 → -0.390) with an added source, no
per-source specialization needed. This is direct evidence that a
36k-param attention model can absorb multiple distributions
concurrently.

By contrast, when we made v7 architecturally bigger (v5 with 150k
params) it OVERFIT to the smaller pool. The bottleneck is data,
not capacity — which strengthens the unified argument (unified
model has more data per parameter than any per-axis variant would).

## When to split

Adopt separate models ONLY if BOTH conditions hold:

1. Unified model underperforms a per-axis-trained baseline by ≥
   0.1pp arith-mean pct-delta on the axis's test slice, measured on
   at least 200 methods per axis to keep signal above noise.
2. The gap does not close after doubling per-axis training data
   (i.e. it's a genuine model-capacity or feature-interference
   issue, not a data-scarcity artifact).

Even then, prefer **fine-tuning** — train unified, then continue-
train on axis-specific data with a smaller learning rate. Cheaper
to deploy than truly separate models and keeps most transfer-
learning benefits.

## Concrete plan for adopting the unified approach

### Phase A (weeks): PGO signal

1. Land the JIT patch from `docs/pgo_signal_feature_spec.md`.
2. Extend jitml's `METHOD_LEVEL_FEATURES` from 12 to 14 slots.
3. Add non-PGO tier1 (`Tier1-FullOpts`) methods to the labeling
   pool — probably ~2000 to start, drawn from
   `benchmarks.run` (non-pgo) or `libraries.pmi`.
4. Train v8 on the mixed pool. Confirm `has_pgo_dynamic` shows up
   as a non-trivial feature via attention-weight inspection.
5. Compare v8-on-PGO-slice vs v7-on-PGO-slice: if v8 doesn't
   regress on PGO ≥ 0.05pp, unified wins even before non-PGO
   validation.

### Phase B (weeks): ISA extension

1. Emit ISA one-hot from `CSE_HeuristicRLHook::GetMethodFeatures`
   (add 3 more `features[i++] = X ? 1 : 0;` blocks with
   `#ifdef TARGET_AMD64` etc.). Extend `s_methodFeatureNames`
   correspondingly.
2. Extend jitml's `METHOD_LEVEL_FEATURES` to 17.
3. Label ~2000-3000 arm64 tier1+PGO methods (Phase 3 of this
   overnight plan delivered 3,000 arm64 labels from
   `benchmarks.run_pgo.windows.arm64.checked.mch`; v8_arm64
   trained on 2,400 of them hits -0.805% arith on 600-method
   held-out slice).
4. Train v9 unified on {x64_tier1_pgo + arm64_tier1_pgo +
   x64_non_pgo + arm64_non_pgo}, ~30k-40k total labels.
5. Evaluate v9 on per-axis test slices; compare to per-axis
   specialists. **Success criterion**: v9-on-arm64-slice within
   0.1pp of v8_arm64's -0.805% AND v9-on-x64-slice within
   0.1pp of v7's -0.390%.

### Phase C: wasm (if/when required)

Same recipe. Wasm has very different codegen constraints (no
regs, no SIMD in most builds) but the same feature emission path
applies. Expect wasm test slice to show larger residuals
initially — its distribution is furthest from x64/arm64.

## Deployment consequences

A unified model means the JIT ships **one** set of weights
(`v7_weights.h`) rather than one per axis. Weight file stays
~144KB regardless of number of ISAs supported. This is a real
maintenance win — the JIT team owns one artifact, and updating
it (retraining) is one action rather than N.

If we split later, we ship one weight file per axis and the JIT
selects at compile time. Minor complexity increase but not
prohibitive.

## Risks

- **Feature interference**: unified model could learn to over-index
  on the axis features and under-learn cross-axis patterns.
  Mitigation: monitor attention weights on the axis-signal method
  features; if the model routes ~100% of variance through them,
  that's evidence of "gating" behavior and separate models may
  actually be simpler. So far v7 does not do this on its two
  existing extractor-level distinguishers (`code_opt_kind`,
  `bbinstr_sample_rate`-selected subpopulation).
- **Test-time inference cost**: unified model has slightly more
  parameters but the extra ~640 params (~2%) is negligible vs the
  36k total. Not a concern.
- **Debugging**: harder to reason about "why did unified do X" than
  "why did the arm64 specialist do X". Mitigable via ablation:
  score with axis features zeroed vs true, delta = axis contribution.

## Anti-recommendation: don't preemptively split by micro-axis

Beyond PGO and ISA, resist the urge to split by (Tier1 vs
Tier1-OSR, Instrumented vs pure, ...) micro-distinctions. Every
split shrinks the per-model training pool, and v7's own history
shows adding data to a unified pool beats specializing on subsets.
Micro-axis distributional differences should be handled as input
features, not as separate models.

## Summary

| Question | Recommendation |
|----------|---------------|
| PGO vs non-PGO | UNIFIED; add 2 boolean features |
| x64 vs arm64 vs wasm | UNIFIED; add 3-way ISA one-hot |
| When to split | Only if unified is ≥ 0.1pp worse on axis slice AND doesn't close with more data |
| Weight-file deployment | Single `v7_weights.h` per model generation |
| Fine-tuning fallback | Preferred over full separate models if per-axis tuning ever needed |
