# PGO signal feature spec (JIT patch required, doc only)

## Motivation

Imitation v7 is trained exclusively on PGO Tier1 methods (`Tier1` and
`Tier1-OSR` compile modes filtered via `is_pgo_calibrated_tier1`),
because their per-block/candidate weights are calibrated by real
execution counts rather than static loop-nesting estimates. When we
eventually train a unified model over PGO **and** non-PGO methods,
the model needs to know at inference time which weight regime it's
looking at — a `use_wt_cnt_x100=1000` under PGO means "this expr
was hit ~1000× per method invocation", whereas the same value under
non-PGO means "the JIT estimated ~10 iterations of some enclosing
loop times some branch prob".

Without an explicit PGO-availability signal, the model has to
implicitly infer this from correlation between the weight magnitudes
and downstream perf-score effects. That works in one weight regime
but is brittle when training pools mix regimes.

## Two proposed method-level features

Both are already computed on `Compiler` and reachable from
`CSE_HeuristicRLHook::GetMethodFeatures` (this heuristic lives on
`Compiler*` — see `src/coreclr/jit/optcse.h:259`).

### 1. `has_pgo_weights` (bool → int 0/1)

Sourced from `Compiler::fgPgoHaveWeights`
(`src/coreclr/jit/compiler.h:7084`). True when the JIT loaded any
form of profile weights for this method — dynamic PGO, static PGO,
synthesized profile, or stress-mode. Broadly, "were the weights
data-driven at all".

### 2. `has_pgo_dynamic` (bool → int 0/1)

Sourced from `Compiler::fgPgoDynamic`
(`src/coreclr/jit/compiler.h:7086`). True only when weights came
from actual runtime instrumentation. Excludes synthesized and
static profiles. This is the "trustworthy edge counts" signal.

`(has_pgo_weights=1, has_pgo_dynamic=1)` → strong Tier1+PGO signal
(current v7 training distribution). `(1,0)` → static or synthesized
weights. `(0,0)` → no weights, using JIT's static estimates.

## JIT patch sketch

Total change: ~20 lines. Extends
`CSE_HeuristicRLHook::s_methodFeatureNames` from 7 to 9 entries and
`GetMethodFeatures` to emit the two new ints.

### `src/coreclr/jit/optcse.cpp:3689` — `GetMethodFeatures`

Insert after the existing `spill_at_weight_x1000` block (line 3747)
and BEFORE the `assert(i <= maxMethodFeatures)`:

```cpp
    // PGO availability signals. Let the ML model condition on
    // whether the per-candidate weights are calibrated by real
    // execution counts (dynamic PGO), some other profile source
    // (static / synthesized), or purely static JIT estimates.
    features[i++] = m_pCompiler->fgPgoHaveWeights ? 1 : 0;
    features[i++] = m_pCompiler->fgPgoDynamic ? 1 : 0;
```

### `src/coreclr/jit/optcse.cpp:3775` — `s_methodFeatureNames`

Extend the array (feature ordering must match `GetMethodFeatures`):

```cpp
const char* const CSE_HeuristicRLHook::s_methodFeatureNames[] = {
    "aggressive_ref_cnt_x1000", "moderate_ref_cnt_x1000", "large_frame", "huge_frame", "code_opt_kind",
    "add_cse_count",            "spill_at_weight_x1000",
    // PGO availability signals so a unified ML model can distinguish
    // dynamic-PGO Tier1 methods from statically-weighted ones.
    "has_pgo_weights",          "has_pgo_dynamic",
};
```

### `src/coreclr/jit/optcse.h` — `maxMethodFeatures`

Bump the compile-time constant to 9 (currently 7 for the ordering
`aggressive_ref_cnt / moderate_ref_cnt / large_frame / huge_frame /
code_opt_kind / add_cse_count / spill_at_weight_x1000`). Search for
`maxMethodFeatures` in `optcse.h` and update.

## jitutils-side mirror

`jitml/method_context.py` parses the `methodFeatureNames` line and
constructs a fixed-order tuple. Extend `METHOD_LEVEL_FEATURES` from
12 to 14 slots (the first 5 are the original tier-1 features from
`b45a531`, 2 more from the sequence-aware `eabefdad177` patch,
these 2 new ones, and 5 padding/reserved slots). The tuple ordering
is order-of-emission from the JIT — no reordering needed as long as
we append.

`train_imitation.py`'s `_FeatureNormalizer` normalizes method-level
features via `/1000` for x1000 fixed-point features and identity for
booleans. `has_pgo_weights` and `has_pgo_dynamic` are already
booleans (0/1) so identity normalization applies — no code change
needed there beyond `_FeatureNormalizer` picking up the two new
slots automatically from the JIT feature-name emission.

## Data-distribution check

Applied `mcs -jitflags` across our current 4 MCH sources
(all currently HAS_DYNAMIC_PROFILE):

| Source | # methods | HAS_PGO | Tier1+PGO subset |
|--------|----------:|--------:|-----------------:|
| train_big | ~4111 labeled | 100% | 100% |
| aspnet2 | ~3778 labeled | 100% | 100% |
| bench_pgo | ~7629 labeled | 100% | 100% |
| libtests | ~8060 labeled | 100% | mixed (BBINSTR sampled 30%) |

**All current v7 training data has (1,1) for these features** — so
adding them to v7 as-is would be a constant column, learned as bias
only. The signal only becomes useful once we mix in non-PGO
methods (Tier0-FullOpts or FullOpts-only compilations) into a
future v8+ training pool.

## Deployment order

1. Land the ~20-line JIT patch on `AndyAyersMS/runtime` (any
   branch; changes are isolated to `optcse.{h,cpp}`).
2. Extend `jitml/method_context.py::METHOD_LEVEL_FEATURES` size and
   verify the parser still round-trips (via
   `scripts/verify_interface.py`).
3. Bump v7's `METHOD_LEVEL_FEATURES=12` config to `14`. Old v7
   checkpoint remains usable if the two new slots are zeroed at
   inference (they were absent in training data anyway).
4. Only when training v8 do we bring in non-PGO methods and expect
   the new features to carry information.

## Alternative considered and rejected

Deriving PGO availability from the `bb_count` field or from
weight-magnitude statistics on the training side (Python) rather
than in the JIT: too brittle. `bb_count` correlates with method
complexity, not with profiler availability. Weight-magnitude
heuristics ("if any `use_wt_cnt > 100000` assume PGO") are
Goodhart-adjacent and mis-classify low-hot-count PGO methods.

Emitting the signal explicitly from the JIT is trivial and
authoritative.

## Verification / test

After the JIT patch, run:

```
python scripts/verify_interface.py --core-root <cr> --mch <mch> --require-m3
```

and confirm the emitted `methodFeatureNames` line contains
`has_pgo_weights, has_pgo_dynamic` at the correct trailing
positions, and that method contexts parse without extra warnings.
Extend `tests/superpmi_parser_test.py` with a sample method
context containing the new slots to lock in the wire format.
