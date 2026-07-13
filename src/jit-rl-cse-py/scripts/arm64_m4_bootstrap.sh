#!/usr/bin/env bash
#
# Bootstrap arm64 wall-clock A/B comparison of v11 vs v12b JIT.
#
# Assumes:
#   * you already have dotnet/runtime cloned somewhere (RUNTIME_DIR below)
#   * you have or can install .NET 10.0 SDK (build.sh installs its own)
#   * git remote 'origin' points to dotnet/runtime (we add AndyAyersMS/runtime as 'andy')
#   * you have BasicRepos ~= 20GB free disk for a second clone of performance
#
# What it does:
#   1. Adds AndyAyersMS/runtime as remote 'andy' and fetches v11 + v12b branches
#   2. Builds Release clr+libs on the v11 branch, saves libclrjit_v11.dylib
#   3. Same for v12b, saves libclrjit_v12b.dylib
#   4. Clones dotnet/performance (or uses existing) and builds MicroBenchmarks
#   5. Runs the interleaved A/B harness across our 12 filter groups
#   6. Prints results
#
# Total time on M4 Pro: ~1 hour (mostly build) then ~2 hours (BDN A/B)

set -euo pipefail

# ─── EDIT THESE PATHS ────────────────────────────────────────────────────
RUNTIME_DIR="${RUNTIME_DIR:-$HOME/repos/runtime}"        # your dotnet/runtime clone
PERF_DIR="${PERF_DIR:-$HOME/repos/performance}"           # dotnet/performance (will clone if missing)
BENCH_DIR="${BENCH_DIR:-$HOME/arm64-cse-bench}"           # scratch dir for JITs + results
# ─────────────────────────────────────────────────────────────────────────

mkdir -p "$BENCH_DIR"
LOG="$BENCH_DIR/bootstrap.log"
echo "Log: $LOG"
exec > >(tee -a "$LOG") 2>&1

echo "=== Step 1: fetch v11 and v12b branches ==="
cd "$RUNTIME_DIR"
if ! git remote get-url andy >/dev/null 2>&1; then
    git remote add andy https://github.com/AndyAyersMS/runtime
fi
git fetch andy jit-cse-imitation-v11:refs/remotes/andy/jit-cse-imitation-v11 --update-head-ok || \
    git fetch andy jit-cse-imitation-v11
git fetch andy jit-cse-imitation-v12b:refs/remotes/andy/jit-cse-imitation-v12b --update-head-ok || \
    git fetch andy jit-cse-imitation-v12b

# Show HEAD commits for verification
echo "  v11  HEAD: $(git rev-parse andy/jit-cse-imitation-v11)"
echo "  v12b HEAD: $(git rev-parse andy/jit-cse-imitation-v12b)"

# Ensure clean tree; stash if anything
git stash --include-untracked || true

build_and_save() {
    local branch="$1"
    local label="$2"
    echo ""
    echo "=== Step 2 ($label): build Release clr+libs on $branch ==="
    git checkout -B "$branch-local" "andy/$branch"
    # Force rebuild by touching source files touched by these branches
    touch src/coreclr/jit/optcse.cpp src/coreclr/jit/optcse.h src/coreclr/jit/cse_imitation_v7_weights.h 2>/dev/null || true
    ./build.sh clr+libs -c Release
    src_jit="$RUNTIME_DIR/artifacts/bin/coreclr/osx.arm64.Release/libclrjit.dylib"
    if [[ ! -f "$src_jit" ]]; then
        echo "ERROR: libclrjit.dylib not found at $src_jit" >&2
        ls "$RUNTIME_DIR/artifacts/bin/coreclr" 2>/dev/null || true
        exit 1
    fi
    cp -v "$src_jit" "$BENCH_DIR/libclrjit_${label}.dylib"
    # Also snapshot the Core_Root for this build
    core_root_src="$RUNTIME_DIR/artifacts/tests/coreclr/osx.arm64.Release/Tests/Core_Root"
    if [[ ! -d "$core_root_src" ]]; then
        echo "Core_Root not present; generating layout..."
        ./src/tests/build.sh arm64 Release generatelayoutonly /p:BuildNativeTests=false
    fi
    if [[ ! -d "$BENCH_DIR/core_root" ]]; then
        cp -R "$core_root_src" "$BENCH_DIR/core_root"
        echo "  copied Core_Root to $BENCH_DIR/core_root"
    fi
}

build_and_save jit-cse-imitation-v11  v11
build_and_save jit-cse-imitation-v12b v12b

echo ""
echo "=== Step 3: performance repo ==="
if [[ ! -d "$PERF_DIR" ]]; then
    echo "Cloning dotnet/performance to $PERF_DIR..."
    git clone --depth 1 https://github.com/dotnet/performance "$PERF_DIR"
fi

# Force a specific TFM: net10.0 is the most-stable currently-supported target.
# PERFLAB_TARGET_FRAMEWORKS is what MicroBenchmarks.csproj reads to narrow the
# set of TFMs it builds -- without this it tries all supported (net8..net11)
# and restore only pulls one, causing "does not have a target for netX.0".
BENCH_TFM="net10.0"
export PERFLAB_TARGET_FRAMEWORKS="$BENCH_TFM"
echo "  using TFM: $BENCH_TFM (PERFLAB_TARGET_FRAMEWORKS=$PERFLAB_TARGET_FRAMEWORKS)"

# Install the SDK the perf repo wants (via its dotnet-install) if not on PATH
if [[ ! -x "$PERF_DIR/.dotnet/dotnet" ]]; then
    cd "$PERF_DIR"
    if [[ ! -f dotnet-install.sh ]]; then
        curl -fsSL -o dotnet-install.sh https://dot.net/v1/dotnet-install.sh
        chmod +x dotnet-install.sh
    fi
    ./dotnet-install.sh --jsonfile global.json --install-dir "$PERF_DIR/.dotnet"
fi
export PATH="$PERF_DIR/.dotnet:$PATH"
export DOTNET_ROOT="$PERF_DIR/.dotnet"

cd "$PERF_DIR/src/benchmarks/micro"

# Build the .csproj directly (not the .sln) so Reporting.csproj (netstandard2.0)
# isn't force-built for net10.0. The csproj-direct path consumes Reporting's
# netstandard2.0 assets naturally.
rm -rf obj bin
dotnet build MicroBenchmarks.csproj -c Release -f "$BENCH_TFM"

BENCH_DLL="$PERF_DIR/artifacts/bin/MicroBenchmarks/Release/$BENCH_TFM/MicroBenchmarks.dll"
if [[ ! -f "$BENCH_DLL" ]]; then
    echo "ERROR: MicroBenchmarks.dll not found at $BENCH_DLL" >&2
    exit 1
fi
echo "  built: $BENCH_DLL"

echo ""
echo "=== Step 4: run A/B ==="
# Locate dotnet
DOTNET="$(command -v dotnet)"
if [[ -z "$DOTNET" ]]; then
    # Try the one runtime installed
    DOTNET="$RUNTIME_DIR/.dotnet/dotnet"
fi
CORE_ROOT="$BENCH_DIR/core_root"
CORERUN="$CORE_ROOT/corerun"
if [[ ! -f "$CORERUN" ]]; then
    echo "ERROR: corerun not found at $CORERUN" >&2
    exit 1
fi

# Fetch the harness (portable version) from AndyAyersMS/jitutils
HARNESS="$BENCH_DIR/bdn_ab_portable.py"
if [[ ! -f "$HARNESS" ]]; then
    curl -fsSL -o "$HARNESS" \
        https://raw.githubusercontent.com/AndyAyersMS/jitutils/revive-jit-rl-cse-py/src/jit-rl-cse-py/scripts/bdn_ab_portable.py
fi

python3 "$HARNESS" \
    --dotnet "$DOTNET" \
    --dll "$BENCH_DLL" \
    --workdir "$PERF_DIR/src/benchmarks/micro" \
    --v10-jit "$BENCH_DIR/libclrjit_v11.dylib" \
    --v11-jit "$BENCH_DIR/libclrjit_v12b.dylib" \
    --v10-threshold "0.30" \
    --v11-threshold "0.30" \
    --v10-label "v11" \
    --v11-label "v12b" \
    --core-root "$CORE_ROOT" \
    --corerun  "$CORERUN" \
    --n-runs 3 \
    --out-csv "$BENCH_DIR/bdn_ab_arm64_m4pro.csv" \
    --filter '*Perf_Deep*' \
    --filter '*BenchNumericSortJagged*' \
    --filter '*MDLogicArray*' \
    --filter '*MDMulMatrix*' \
    --filter '*RayTracerBench*' \
    --filter '*BenchEmFloat*' \
    --filter '*BenchAssignRect*' \
    --filter '*BenchAssignJagged*' \
    --filter '*MDNDhrystone*' \
    --filter '*BenchI.NDhrystone*' \
    --filter '*Perf_Regex_Cache.IsMatch_Multithreading*' \
    --filter '*Span.Sorting.QuickSort*'

echo ""
echo "=== Done ==="
echo "Results: $BENCH_DIR/bdn_ab_arm64_m4pro.csv"
echo "Log: $LOG"
