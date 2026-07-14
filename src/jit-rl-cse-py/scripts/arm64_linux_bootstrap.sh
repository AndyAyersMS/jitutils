#!/usr/bin/env bash
#
# Bootstrap arm64 wall-clock A/B v11 vs v12b on Ubuntu arm64 (Cobalt 100).
#
# Assumes:
#   * fresh Ubuntu 24.04 arm64 VM
#   * script is run as user with sudo access
#   * NO existing runtime/performance clones (does everything from scratch)
#
# What it does:
#   1. Installs apt build deps for dotnet/runtime + python3 + curl
#   2. Clones AndyAyersMS/runtime, fetches v11 and v12b branches
#   3. Builds Release clr+libs on each branch, saves libclrjit_{v11,v12b}.so
#   4. Clones dotnet/performance, builds MicroBenchmarks
#   5. Runs interleaved A/B across 12 benchmark filter groups
#   6. CSV written to $BENCH_DIR/bdn_ab_arm64_cobalt.csv
#
# Total time on D8ps_v6 (8 vCPU): ~40 min build + ~2h A/B ≈ 3h
# Total time on D16ps_v6 (16 vCPU): ~20 min build + ~2h A/B ≈ 2.5h

set -euo pipefail

# ─── configurable via env ────────────────────────────────────────────────
BENCH_DIR="${BENCH_DIR:-$HOME/arm64-cse-bench}"
RUNTIME_DIR="${RUNTIME_DIR:-$BENCH_DIR/runtime}"
PERF_DIR="${PERF_DIR:-$BENCH_DIR/performance}"
# ─────────────────────────────────────────────────────────────────────────

mkdir -p "$BENCH_DIR"
LOG="$BENCH_DIR/bootstrap.log"
echo "Log: $LOG"
exec > >(tee -a "$LOG") 2>&1
echo "Start: $(date)"

echo "=== Step 0: install deps ==="
# Detect package manager (apt=Ubuntu, dnf=RHEL/Fedora/AL, tdnf=Azure Linux/Mariner)
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y git build-essential cmake ninja-build clang python3 python3-pip curl zip \
        libssl-dev libkrb5-dev liblttng-ust-dev libunwind-dev libnuma-dev libicu-dev tar libcurl4-openssl-dev
elif command -v tdnf >/dev/null 2>&1; then
    # Azure Linux 3 / CBL-Mariner
    sudo tdnf install -y git gcc glibc-devel make cmake ninja-build clang python3 python3-pip ca-certificates \
        curl zip tar which util-linux \
        openssl-devel krb5-devel libunwind-devel numactl-devel icu icu-devel libcurl-devel \
        lttng-ust-devel binutils gcc-c++
elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y git gcc gcc-c++ make cmake ninja-build clang python3 python3-pip curl zip tar which \
        openssl-devel krb5-devel libunwind-devel numactl-devel libicu libicu-devel libcurl-devel \
        lttng-ust-devel util-linux
elif command -v yum >/dev/null 2>&1; then
    sudo yum install -y git gcc gcc-c++ make cmake ninja-build clang python3 python3-pip curl zip tar which \
        openssl-devel krb5-devel libunwind-devel numactl-devel libicu libicu-devel libcurl-devel \
        lttng-ust-devel
else
    echo "ERROR: no known package manager (apt/tdnf/dnf/yum)" >&2
    exit 1
fi

echo ""
echo "=== Step 1: clone runtime (AndyAyersMS fork) ==="
if [[ ! -d "$RUNTIME_DIR" ]]; then
    git clone --no-tags --branch jit-cse-imitation-v12b \
        https://github.com/AndyAyersMS/runtime "$RUNTIME_DIR"
    cd "$RUNTIME_DIR"
    git remote add upstream https://github.com/dotnet/runtime
    git fetch --no-tags origin jit-cse-imitation-v11
else
    cd "$RUNTIME_DIR"
    git fetch --no-tags origin jit-cse-imitation-v11 jit-cse-imitation-v12b
fi

echo "  v11  HEAD: $(git rev-parse origin/jit-cse-imitation-v11)"
echo "  v12b HEAD: $(git rev-parse origin/jit-cse-imitation-v12b)"

# Install runtime's dependencies (some apt-based)
sudo ./eng/common/native/install-dependencies.sh || true

build_and_save() {
    local branch="$1"
    local label="$2"
    echo ""
    echo "=== Step 2 ($label): build Release clr+libs on $branch ==="
    cd "$RUNTIME_DIR"
    git checkout -B "$branch-local" "origin/$branch"
    # Force JIT rebuild if source timestamps don't reflect the branch switch
    touch src/coreclr/jit/optcse.cpp src/coreclr/jit/optcse.h src/coreclr/jit/cse_imitation_v7_weights.h 2>/dev/null || true
    ./build.sh clr+libs -c Release -p:FeatureXplatEventSource=false
    src_jit="$RUNTIME_DIR/artifacts/bin/coreclr/linux.arm64.Release/libclrjit.so"
    if [[ ! -f "$src_jit" ]]; then
        echo "ERROR: libclrjit.so not found at $src_jit" >&2
        find "$RUNTIME_DIR/artifacts/bin/coreclr" -maxdepth 2 -type d 2>/dev/null || true
        exit 1
    fi
    cp -v "$src_jit" "$BENCH_DIR/libclrjit_${label}.so"
    core_root_src="$RUNTIME_DIR/artifacts/tests/coreclr/linux.arm64.Release/Tests/Core_Root"
    if [[ ! -d "$core_root_src" ]]; then
        echo "Generating Core_Root layout..."
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
    git clone --depth 1 https://github.com/dotnet/performance "$PERF_DIR"
fi
cd "$PERF_DIR"

# Install the SDK the perf repo wants (via its dotnet-install)
if [[ ! -x "$PERF_DIR/.dotnet/dotnet" ]]; then
    if [[ ! -f dotnet-install.sh ]]; then
        curl -fsSL -o dotnet-install.sh https://dot.net/v1/dotnet-install.sh
        chmod +x dotnet-install.sh
    fi
    ./dotnet-install.sh --jsonfile global.json --install-dir "$PERF_DIR/.dotnet"
fi
export PATH="$PERF_DIR/.dotnet:$PATH"
export DOTNET_ROOT="$PERF_DIR/.dotnet"

BENCH_TFM="net10.0"
export PERFLAB_TARGET_FRAMEWORKS="$BENCH_TFM"
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
DOTNET="$PERF_DIR/.dotnet/dotnet"
CORE_ROOT="$BENCH_DIR/core_root"
CORERUN="$CORE_ROOT/corerun"
if [[ ! -f "$CORERUN" ]]; then
    echo "ERROR: corerun not found at $CORERUN" >&2
    exit 1
fi

HARNESS="$BENCH_DIR/bdn_ab_portable.py"
curl -fsSL -o "$HARNESS" \
    https://raw.githubusercontent.com/AndyAyersMS/jitutils/revive-jit-rl-cse-py/src/jit-rl-cse-py/scripts/bdn_ab_portable.py

python3 "$HARNESS" \
    --dotnet "$DOTNET" \
    --dll "$BENCH_DLL" \
    --workdir "$PERF_DIR/src/benchmarks/micro" \
    --v10-jit "$BENCH_DIR/libclrjit_v11.so" \
    --v11-jit "$BENCH_DIR/libclrjit_v12b.so" \
    --v10-threshold "0.30" \
    --v11-threshold "0.30" \
    --v10-label "v11" \
    --v11-label "v12b" \
    --core-root "$CORE_ROOT" \
    --corerun  "$CORERUN" \
    --n-runs 3 \
    --out-csv "$BENCH_DIR/bdn_ab_arm64_cobalt.csv" \
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
echo "End: $(date)"
echo "Results: $BENCH_DIR/bdn_ab_arm64_cobalt.csv"
echo "Log: $LOG"
