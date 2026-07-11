// Standalone wall-clock validation harness for the JIT-embedded imitation
// heuristic. Runs Span.QuickSort (the top-perfscore-impacted benchmark
// per files/impacted_benchmarks.md) under Stopwatch.
//
// Ported and simplified from
// dotnet/performance/src/benchmarks/micro/runtime/Span/Sorting.cs.
//
// Usage:
//   set DOTNET_JitPath=<clrjit.dll>
//   set DOTNET_JitCseImitation=1                  (only for imit run)
//   set DOTNET_JitCseImitationThreshold=0.30      (only for imit run)
//   dotnet run -c Release -- --iters 500 --size 512
//
// Warms up 100 iters (which is enough to get the sort methods
// Tier1-JITted), then times `iters` iterations. Reports geo-mean ns
// per sort call.

using System;
using System.Diagnostics;
using System.Runtime.CompilerServices;

internal static class Program
{
    private static int Main(string[] args)
    {
        int size = 512;
        int iters = 500;
        int warmup = 100;
        for (int i = 0; i < args.Length - 1; i++)
        {
            if (args[i] == "--iters") iters = int.Parse(args[i + 1]);
            else if (args[i] == "--size") size = int.Parse(args[i + 1]);
            else if (args[i] == "--warmup") warmup = int.Parse(args[i + 1]);
        }

        // Build the array of arrays (each iteration sorts a fresh copy of
        // the same unique-values array; this is what BDN's Utils.FillArrays
        // does).
        int[] template = new int[size];
        var rng = new Random(42);
        for (int i = 0; i < size; i++) template[i] = rng.Next();
        int[][] arrays = new int[iters + warmup][];
        for (int i = 0; i < arrays.Length; i++)
        {
            arrays[i] = new int[size];
            Array.Copy(template, arrays[i], size);
        }

        // Warmup: run enough to Tier1-JIT the sort code.
        for (int i = 0; i < warmup; i++)
        {
            TestQuickSortSpan(new Span<int>(arrays[i]));
        }
        // Refill so warmup arrays get replaced (Setup pattern).
        for (int i = 0; i < warmup; i++)
        {
            Array.Copy(template, arrays[i], size);
        }

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < iters; i++)
        {
            TestQuickSortSpan(new Span<int>(arrays[i]));
        }
        sw.Stop();

        double nsPerCall = sw.Elapsed.TotalMilliseconds * 1e6 / iters;
        Console.WriteLine($"Span.QuickSortSpan size={size} iters={iters}  warmup={warmup}");
        Console.WriteLine($"  total_ms = {sw.Elapsed.TotalMilliseconds:F3}");
        Console.WriteLine($"  ns_per_sort = {nsPerCall:F1}");
        return 0;
    }

    [MethodImpl(MethodImplOptions.NoInlining)]
    private static void TestQuickSortSpan(Span<int> data)
    {
        if (data.Length <= 1) return;

        int lo = 0;
        int hi = data.Length - 1;
        int i, j;
        int pivot, temp;
        for (i = lo, j = hi, pivot = data[hi]; i < j;)
        {
            while (i < j && data[i] <= pivot) { ++i; }
            while (j > i && data[j] >= pivot) { --j; }
            if (i < j)
            {
                temp = data[i];
                data[i] = data[j];
                data[j] = temp;
            }
        }
        if (i != hi)
        {
            temp = data[i];
            data[i] = pivot;
            data[hi] = temp;
        }
        TestQuickSortSpan(data.Slice(0, i));
        TestQuickSortSpan(data.Slice(i + 1));
    }
}
