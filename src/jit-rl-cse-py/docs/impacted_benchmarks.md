# Benchmarks impacted by imitation v7 (bench_pgo.mch analysis)

## Summary

Evaluated imitation v7 @ threshold=0.3 on the first 10,000 methods of
`benchmarks.run_pgo.windows.x64.checked.tier1.mch`.

**Aggregate**:
- 4617 methods with viable CSE candidates
- **1638 wins** (35%) vs 210 losses (5%)
- Arith mean pct-delta: **-0.338%**
- Geo mean pct-delta: **-0.352%**
- Gap remaining vs labeled optimum: +0.217% (76% of methods with
  candidates are already at the labeled optimum)

Once v7 is embedded in the JIT, these are the concrete benchmarks
whose JIT-reported perf-scores should improve. Real wall-clock
correlation is the phase-3 validation — this doc identifies what
to measure.

## Top benchmark classes ranked by total absolute perf-score reduction

Filtered to wins with `heur - rl > 100` perfscore units (183 methods
total across 1638 wins, capturing the highest-impact ones).

| Total perfscore Δ | Methods | Mean pct | Best pct | Benchmark class |
|-----------------:|--------:|---------:|---------:|-----------------|
| 44,145 | 6 | -5.00% | -5.50% | `Span.Sorting` |
| 14,088 | 22 | -3.02% | -3.66% | `System.Text.RegularExpressions.Regex` (RunAllMatchesWithCallback etc.) |
| 10,980 | 18 | -1.44% | -3.95% | `System.Linq.Enumerable` (ToLookup path) |
| 7,691 | 6 | -4.00% | -4.00% | `System.Text.RegularExpressions.Tests.Perf_Regex_Cache` |
| 7,257 | 2 | -1.12% | -1.19% | `AssignRect` |
| 6,429 | 26 | -1.07% | -1.12% | `System.IO.Tests.TextReaderReadLineTests` |
| 4,552 | 10 | -6.10% | -6.12% | `System.SpanHelpers` |
| 4,538 | 11 | -3.43% | -3.48% | `System.Collections.Generic.Dictionary` (ValueTuple keys) |
| 2,907 | 17 | -3.97% | -3.99% | `Dictionary.ValueCollection` |
| 2,665 | 1 | -0.63% | -0.63% | `Benchmarks.SIMD.RayTracer.RayTracer` |
| 2,264 | 3 | -3.98% | -4.04% | `System.Linq.Lookup` |
| 2,164 | 5 | -1.25% | -1.58% | `NumericSortJagged` |
| 1,801 | 1 | **-21.58%** | **-21.58%** | `EMFloatClass.Run()` ← biggest relative win |
| 1,782 | 1 | -2.39% | -2.39% | `CscBench` |
| 1,733 | 8 | -0.78% | -1.39% | `System.Text.Json.JsonDocument` |
| 1,228 | 1 | -1.84% | -1.84% | `Benchstone.BenchI.NDhrystone` |
| 1,132 | 3 | -0.48% | -0.60% | `AssignJagged` |
| 993 | 6 | -3.52% | **-7.55%** | `System.Collections.Generic.ArraySortHelper<int>` |
| 792 | 3 | -1.79% | -1.80% | `System.Text.Json.Tests.Perf_Deep` |
| 762 | 2 | -0.81% | -1.04% | `System.Threading.Tests.Perf_Timer` |
| 609 | 2 | -0.84% | -0.84% | `System.Text.RegularExpressions.RegexInterpreter` |
| 563 | 1 | -2.75% | -2.75% | `SciMark2.MonteCarlo` |
| 521 | 1 | -0.61% | -0.61% | `BenchmarkDotNet.Extensions.ValuesGenerator` |
| 517 | 3 | -0.84% | -0.97% | `System.Threading.ThreadPoolWorkQueue` |
| 500 | 1 | -0.30% | -0.30% | `SciMark2.FFT` |
| 459 | 1 | -0.66% | -0.66% | `Benchstone.MDBenchI.MDNDhrystone` |
| 452 | 1 | -0.61% | -0.61% | `AsciiStringSearchValuesTeddyBase` |

## Top single methods by absolute perf-score reduction

| Method ID | Heur | v7 | Δ abs | Δ pct | Cand | Method name |
|----------:|-----:|---:|------:|------:|-----:|-------------|
| 8291 | 375,746 | 355,107 | 20,640 | -5.49% | 13 | `Span.Sorting` |
| 91 | 374,742 | 354,137 | 20,605 | -5.50% | 14 | `Span.Sorting` |
| 6578 | 349,209 | 345,535 | 3,674 | -1.05% | 12 | `AssignRect` |
| 6570 | 301,042 | 297,459 | 3,583 | -1.19% | 26 | `AssignRect` |
| 6294 | 422,866 | 420,201 | 2,665 | -0.63% | 14 | `RayTracer:RenderSequential` |
| 5210 | 8,344 | 6,544 | 1,801 | **-21.58%** | 6 | `EMFloatClass:Run()` |
| 8974 | 74,675 | 72,893 | 1,782 | -2.39% | 19 | `CscBench:DataflowBench()` |
| 1908 (+ 5 clones) | 32,028 | 30,747 | 1,282 | -4.00% | 17-18 | `Perf_Regex_Cache:CreatePatterns` (6 tier1 variants) |
| 3836 | 66,911 | 65,683 | 1,228 | -1.84% | 28 | `Benchstone.BenchI.NDhrystone` |
| 3776 | 67,452 | 66,387 | 1,065 | -1.58% | 16 | `NumericSortJagged` |
| 7778 | 23,472 | 22,663 | 809 | -3.45% | 5 | `Dictionary<ValueTuple<int,T,T>,T>:Resize` |
| 8235 (+ 8 clones) | ~22K | ~21K | ~800 | ~-3.6% | 9 | `Regex:RunAllMatchesWithCallback` (9 tier1 variants) |
| 7365 (+ 2 clones) | ~19K | ~18K | ~774 | ~-4% | 18 | `System.Linq.Lookup.Create` (3 variants) |

## Priority list for real-world validation

Order these by "biggest total impact × easiest to run in isolation":

### Tier 1 — run first (highest expected wall-clock signal)

1. **Span.Sorting** — top absolute win, single-benchmark class. Under
   `src/benchmarks/micro/libraries/System.Runtime/Span.cs` (Sorting).
2. **EMFloatClass** — biggest RELATIVE win (-21.58%). Old
   FloatingPoint microbenchmark; under
   `src/benchmarks/coreclr/Bytemark/` or similar.
3. **Regex.RunAllMatchesWithCallback + Perf_Regex_Cache** — 22+6+9
   methods affected across the Regex hot path. Under
   `src/benchmarks/micro/libraries/System.Text.RegularExpressions/`.
   Total impact ~30K perfscore reduction across many hot methods.
4. **System.Linq (Enumerable + Lookup)** — LINQ hot paths, 18+3
   methods. Under `src/benchmarks/micro/libraries/System.Linq/`.

### Tier 2 — next batch

5. **AssignRect / AssignJagged** — old Benchstone benchmarks under
   `src/benchmarks/coreclr/Benchstone/`.
6. **Benchmarks.SIMD.RayTracer** — under `src/benchmarks/real-world/`
   or `src/benchmarks/coreclr/`.
7. **Benchstone.BenchI.NDhrystone / MDNDhrystone** — classic Dhrystone.
8. **NumericSortJagged** — under Benchstone.
9. **CscBench** — Roslyn compiler benchmark; larger dependency graph.
10. **SciMark2.MonteCarlo / FFT** — under real-world benchmarks.

### Tier 3 — lower-priority (smaller / mixed impact)

11. **System.IO.Tests.TextReaderReadLineTests** — 26 methods but
    ~1% each; wall-clock impact will be diffuse.
12. **System.Text.Json** — 8 JsonDocument + 3 Perf_Deep methods.
13. **System.Collections.Dictionary / ArraySortHelper** — many
    methods, smaller per-method deltas.
14. **System.Threading.ThreadPoolWorkQueue / Perf_Timer** — small
    absolute impact.

## Loss list (methods where v7 hurts)

210 methods with pct_delta > +0.05%. Should also spot-check some of
these post-embedding to confirm the reported perfscore regression
matches wall-clock (or that they're noise below measurement floor).

See `bench_pgo_wins_named.csv` for the full sorted list of wins
with method names attached. A losses-named CSV can be generated
identically.

## How to validate perf-score correlation (blocked pending JIT embed)

For each benchmark in the priority list:

1. **Baseline**: build .NET runtime + run the benchmark (dotnet run
   under BenchmarkDotNet). Record wall-clock.
2. **v7**: same build with `DOTNET_JitCseImitationV7=1` (or whatever
   config flag we choose). Record wall-clock.
3. Compare wall-clock delta to perfscore delta:
   - If |wall-clock Δ%| ≥ 0.5 × |perfscore Δ%| across most
     benchmarks → perf-score is directionally predictive; ship v7.
   - If wall-clock Δ is noise while perfscore Δ is large → JIT
     perf-score is not the right optimization target and we need a
     different reward signal.
   - If wall-clock Δ is CONSISTENTLY OPPOSITE-SIGNED → alarming;
     investigate (may indicate v7 optimizes for JIT-time metric that
     doesn't reflect true CSE benefit).

**Cannot execute this validation autonomously overnight** — requires:
(a) JIT patch to embed v7 (see `docs/embed_v7.md`), OR
(b) a JitCSEMask override mechanism per method (would need JIT patch
    also, or a build of superpmi that supports per-method mask files).

## Data provenance

- Model: `imitation_v7/best_val.pt`, `imitation_v7/config.json`
- Eval MCH: `C:\spmi\mch-tier1\staging\benchmarks.run_pgo.windows.x64.checked.tier1.mch`
- Eval command: `python scripts/eval_imitation.py --checkpoint <ckpt>
    --config <cfg> --mch <mch> --optimum-labels <labels> --threshold 0.3
    --limit 10000 --include-rl2020 --out-csv <out>`
- Enriched CSV: `imitation_v7/bench_pgo_wins_named.csv` (183 methods
  with abs_delta > 100 and method names attached)
