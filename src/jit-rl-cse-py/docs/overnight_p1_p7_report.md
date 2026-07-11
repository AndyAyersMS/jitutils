# Overnight session 3 (P1-P7) — final report

**Session**: 2026-07-10 18:00 → 2026-07-11 morning
**Runtime branch**: `AndyAyersMS/runtime@jit-cse-imitation-v7`
**jitutils branch**: `AndyAyersMS/jitutils@revive-jit-rl-cse-py`

## What ships

**v8** is now the deployed model. Trained on **26,578 mixed labels**
(4 PGO sources + 1 non-PGO source) with the 14-slot method-feature
schema (12 old + 2 new PGO signals). Embedded in `clrjit.dll` at
36,624 float parameters, ~146KB in `.rdata`.

Enable via:
```
DOTNET_JitCseImitation=1
DOTNET_JitCseImitationThreshold=0.30    # optional, default is 0.30
```

Available in both Checked and **Release** builds now.

## Empirical results

**All three axes now improve** (v7-late was net regression on
bench_pgo; v7_early couldn't run on non-PGO due to schema mismatch):

| MCH | Distribution | v7 late | v7_early | **v8** |
|-----|-------------|--------:|---------:|-------:|
| test.mch (whole 750-set) | PGO Tier1 | -0.176% | -0.189% @ t=0.40 | **-0.218%** @ t=0.50 |
| bench_pgo.mch (5000) | PGO Tier1 | +0.154% (regress!) | -0.277% @ t=0.30 | **-0.277%** @ t=0.30 |
| benchmarks.run.mch (3000) | non-PGO FullOpts | (untested) | (schema mismatch) | **-0.253%** @ t=0.30 |

**C++/Python parity: 100% (265/265)** on x64 test.mch. First
wall-clock validation (Span.QuickSort, 3 runs × 500 sorts): -1.6%
wall-clock delta (perf-score prediction was -5.5%). Signs agree;
directional correlation confirmed.

**JIT throughput overhead**: +10.4% wall-clock on superpmi replay of
test.mch. Non-trivial; addressable via SIMD-ifying the Linear /
attention primitives (future work).

## Phases completed

1. **P1 — Release promotion**: lifted `CSE_HeuristicRLHook` and
   `CSE_HeuristicImitation` out of `#ifdef DEBUG` in optcse.h/.cpp.
   Kept `CSE_HeuristicRL` (softmax/RL) DEBUG-only. Changed all
   RLHook-related `JitConfig` entries to `RELEASE_CONFIG_*`. Inline-
   parsed `JitRLHookCSEDecisions` to avoid the DEBUG-only
   `ConfigIntArray` dependency. Release build works, IMIT_PROBS is
   byte-identical to Checked.

2. **P3 — JIT throughput overhead**: superpmi replay of test.mch
   with `JitCseImitation=1` adds **+10.4%** wall-clock vs default
   heuristic. Adding `JitRLHookEmitEarly=1` costs another +0.1%.

3. **P4 — v7_early cross-transfer to arm64**: on 600-method arm64
   held-out slice:
   - v7_early (x64-trained, naive transfer): **-0.157% arith**
   - v8_arm64 (native, trained on late-emit features): -0.017% arith
   Huge improvement from yesterday's v7-late naive transfer of
   +1.527%. Caveat: v8_arm64 was trained pre-early-emit so its
   own numbers are drift-limited; a fair comparison needs
   retraining v8_arm64 on early features.

4. **P5a — PGO signal patch**: added `has_pgo_weights` and
   `has_pgo_dynamic` to `CSE_HeuristicRLHook::GetMethodFeatures`,
   bumped `maxMethodFeatures` 7→9. jitutils METHOD_SCHEMA extended
   12→14 to match. Backwards-compatible (defaults to False for
   older cached JSON).

5. **P5b — non-PGO labeling**: labeled 3000 methods from
   `benchmarks.run.windows.x64.checked.mch` (100% FullOpts, all
   non-PGO). 232s wall-clock with 8 parallel workers. 60% at heur
   optimum, mean +1.002% headroom.

6. **P5c — v8 training**: multi-source dataset (4 PGO + 1 non-PGO
   = 26,578 labels) with 14-slot method schema. 100 epochs, ~70min
   total (57min feature loading + 15min training). Best val_loss
   0.2918 (v7_early was 0.2868). 36,624 params.

7. **P5d — v8 embedding + eval**: exported to `v7_weights.h`,
   updated `RemapMethod` to conditionally populate the 2 new PGO
   slots when `METHOD_FEATURES >= 14`. Rebuilt Checked JIT.
   Threshold sweep + parity check confirm the numbers above.

8. **P2 — Wall-clock validation (partial)**: standalone
   `wallclock_harness` project running Span.QuickSort under
   Stopwatch. Baseline 64,457 ns/sort → imitation 63,456 ns/sort
   → **-1.6% wall-clock**. Signs match perfscore prediction of
   -5.5%.

9. **P7 — Parity regression test**: `tests/parity_regression_test.py`
   in jitutils, env-gated. Runs 50 methods through both inference
   paths; fails if <99% match. Passes on v8.

## Commits pushed (this session)

**runtime** (`jit-cse-imitation-v7`):
- `72be866b5e5` Release promotion + `RELEASE_CONFIG_*` migration
- `ed472ae210e` PGO signal features + `maxMethodFeatures` 7→9
- `bca97a0d270` v8 weights + `RemapMethod` extended

**jitutils** (`revive-jit-rl-cse-py`):
- `7ed53ce`  METHOD_SCHEMA 12→14 with PGO signals
- `d521f87` `measure_imit_overhead.py` + parity regression test
- `9b038af` `wallclock_harness` for Span.QuickSort

## Deferred / next-session

- **P6 — Loss deep-dive**: still open. 99 methods regress on
  bench_pgo @ t=0.30 with v8. Not yet analyzed by pattern.
- **v8_arm64 retrained on early-emit features**: needed for a fair
  P4 comparison. Currently v8_arm64 was labeled pre-early-emit so
  its numbers are drift-limited.
- **Reduce +10.4% JIT overhead**: SIMD the Linear/Attention
  primitives; sparsity-skip padding rows in Attention.
- **Full BDN wall-clock sweep**: only Span.QuickSort measured so
  far. Extend to EMFloat, Regex, LINQ.Lookup for stronger
  perfscore↔wall-clock correlation.
- **Investigate wider training pool**: `realworld.run.mch` and
  `libraries.pmi.mch` are large untapped sources.
- **Add ISA one-hot feature**: v9 could be unified across
  x64+arm64. Groundwork done in `docs/unified_vs_separate.md`.

## Session-side artifacts (in files/, not committed)

- `imitation_v8/` — best_val.pt, config.json, train.log
- `v8_export/` — exported v7_weights.{h,json}
- `label_nonpgo_bench/labels.json` — 3000 non-pgo labels
- `nonpgo_indices.txt` — the 3000 method IDs used
- `p2_wallclock/` — copy of the wall-clock harness with build artifacts
- `v7_early_vs_v8_arm64.csv` — 600-method paired eval
