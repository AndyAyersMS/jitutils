# Wall-clock validation harness for JIT-embedded imitation v7/v8

Minimal standalone .NET program that runs the top perfscore-impacted
benchmark methods under `System.Diagnostics.Stopwatch`. Uses
`DOTNET_JitPath` to swap between baseline heuristic and JIT-embedded
imitation heuristic, and reports geo-mean speedup.

This is a shortcut for full BenchmarkDotNet -- sufficient to answer
"does the perf-score prediction correlate with wall-clock" for a
sample of hot methods. NOT sufficient for making promotion decisions
across the whole benchmark suite.

## Benchmarks included

Ported from `dotnet/performance` src/benchmarks/micro/:
- `Span.QuickSort` (from `runtime/Span/Sorting.cs`) -- top absolute
  perfscore win (-5.5%)

`EMFloat.Run` and `Regex.RunAllMatchesWithCallback` are also on the
impacted-benchmark list but they pull in significant dependencies
(the whole EMFloatClass/EmFloatStruct BYTEmark port, or the whole
`System.Text.RegularExpressions.Perf_Regex_Cache` benchmark project);
add them if you want more coverage.

## Usage (Windows PowerShell)

```powershell
$dotnet = "C:\repos\runtime4\.dotnet\dotnet.exe"
$imit = "C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Release\clrjit.dll"
$exe = ".\bin\Release\net11.0\WallClockHarness.dll"

& $dotnet build -c Release

# Baseline (uses whatever clrjit the runtime ships)
for ($run = 1; $run -le 5; $run++) {
    & $dotnet exec $exe --iters 500 --size 512 --warmup 500
}

# Imitation (v7_early @ t=0.30)
$env:DOTNET_JitPath = $imit
$env:DOTNET_JitCseImitation = "1"
$env:DOTNET_JitCseImitationThreshold = "0.30"
for ($run = 1; $run -le 5; $run++) {
    & $dotnet exec $exe --iters 500 --size 512 --warmup 500
}
Remove-Item env:DOTNET_JitPath, env:DOTNET_JitCseImitation, env:DOTNET_JitCseImitationThreshold
```

## Empirical result on x64, Span.QuickSort size=512

| Config           | best ns/sort | mean ns/sort |
|------------------|-------------:|-------------:|
| baseline heur    |      63,585  |      64,457  |
| **imitation v7_early @ t=0.30** | **62,224** | **63,456** |

Wall-clock delta ~ -1.6% (mean of 3 runs each). Perf-score prediction
for Span.Sorting was -5.5%. Signs agree; the wall-clock delta is
smaller because perf-score is a JIT-cost prediction while sort is
memory-bandwidth-bound.

## Ideas for extensions

- Add EMFloat / MonteCarlo / other CPU-bound impacted benchmarks;
  expect closer perf-score : wall-clock correlation than sort.
- Wrap in a script that parses stdout, does geo-mean across runs,
  and prints a table.
- Compare Checked vs Release JIT overhead on the same benchmark to
  isolate the imitation-inference cost from the CSE-decision cost.
