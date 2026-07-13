#!/usr/bin/env python3
"""Cross-platform BDN interleaved A/B v10 vs v11 (or v11 vs v12b, etc.).

Portable version of scripts/bdn_ab_v10_v11.py for macOS/Linux/Windows.
Auto-detects platform to select correct .dll/.dylib/.so and corerun name.

Usage on macOS:
  python3 bdn_ab_portable.py \\
      --v10-jit  /path/to/clrjit_v11.dylib \\
      --v11-jit  /path/to/clrjit_v12b.dylib \\
      --v10-threshold 0.30 \\
      --v11-threshold 0.30 \\
      --core-root /path/to/Core_Root \\
      --corerun  /path/to/Core_Root/corerun \\
      --dll /path/to/performance/artifacts/bin/MicroBenchmarks/Release/net10.0/MicroBenchmarks.dll \\
      --workdir /path/to/performance/src/benchmarks/micro \\
      --dotnet /path/to/dotnet \\
      --out-csv results.csv \\
      --n-runs 3 \\
      --filter '*MDMulMatrix*'
"""
import argparse, os, subprocess, glob, json, shutil, time, csv, sys, statistics, platform


def _is_windows():
    return platform.system() == 'Windows'


def _is_darwin():
    return platform.system() == 'Darwin'


def _jit_filename():
    if _is_windows():
        return 'clrjit.dll'
    if _is_darwin():
        return 'libclrjit.dylib'
    return 'libclrjit.so'


def _parse_bdn_json(json_path):
    with open(json_path, encoding='utf-8-sig') as f:
        d = json.load(f)
    out = {}
    for b in d.get('Benchmarks', []):
        name = b.get('MethodTitle') or b.get('Method') or '?'
        params = b.get('Parameters', '')
        mean = b.get('Statistics', {}).get('Mean')
        if mean is None:
            continue
        key = f'{name}[{params}]' if params else name
        out[key] = float(mean)
    return out


def _run_bdn(dotnet, dll, filt, corerun, env_extra, workdir, tag_dir):
    results_dir = os.path.join(os.path.dirname(dll), 'BenchmarkDotNet.Artifacts', 'results')
    if os.path.exists(results_dir):
        for f in glob.glob(os.path.join(results_dir, '*-report-full.json')):
            try: os.remove(f)
            except OSError: pass
    cmd = [dotnet, 'exec', dll, '--filter', filt, '--coreRun', corerun]
    if env_extra:
        cmd += ['--envVars'] + env_extra
    print(f'    {os.path.basename(tag_dir)}: {filt}', flush=True)
    t0 = time.time()
    proc = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, timeout=1800)
    elapsed = time.time() - t0
    print(f'      done in {elapsed:.0f}s (rc={proc.returncode})', flush=True)
    if proc.returncode != 0:
        # Print the last few stderr / stdout lines for diagnostic
        for ln in proc.stdout.split('\n')[-10:]:
            print(f'      stdout: {ln}')
        for ln in proc.stderr.split('\n')[-5:]:
            print(f'      stderr: {ln}')
    os.makedirs(tag_dir, exist_ok=True)
    reports = glob.glob(os.path.join(results_dir, '*-report-full.json'))
    combined = {}
    for rep in reports:
        try:
            combined.update(_parse_bdn_json(rep))
            shutil.copy(rep, os.path.join(tag_dir, os.path.basename(rep)))
        except Exception as e:
            print(f'      parse err: {e}')
    return combined


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--dotnet', required=True, help='Path to dotnet binary')
    ap.add_argument('--dll', required=True, help='Path to MicroBenchmarks.dll')
    ap.add_argument('--workdir', required=True, help='Working directory (usually performance/src/benchmarks/micro)')
    ap.add_argument('--v10-jit', required=True, help='Path to first JIT (labeled v10 in output)')
    ap.add_argument('--v11-jit', required=True, help='Path to second JIT (labeled v11 in output)')
    ap.add_argument('--core-root', required=True, help='Core_Root directory; script swaps clrjit here')
    ap.add_argument('--corerun', required=True, help='Path to corerun (or corerun.exe on Windows)')
    ap.add_argument('--out-csv', required=True)
    ap.add_argument('--save-dir', default=None)
    ap.add_argument('--filter', action='append', required=True)
    ap.add_argument('--n-runs', type=int, default=3)
    ap.add_argument('--v10-threshold', default='0.50')
    ap.add_argument('--v11-threshold', default='0.30')
    ap.add_argument('--v10-label', default='v10')
    ap.add_argument('--v11-label', default='v11')
    args = ap.parse_args()

    save_dir = args.save_dir or os.path.dirname(os.path.abspath(args.out_csv))
    os.makedirs(save_dir, exist_ok=True)

    core_jit = os.path.join(args.core_root, _jit_filename())
    print(f'Platform: {platform.system()} / {platform.machine()}')
    print(f'JIT filename: {_jit_filename()}')
    print(f'Core_Root JIT slot: {core_jit}')
    for j in (args.v10_jit, args.v11_jit):
        if not os.path.exists(j):
            print(f'ERROR: JIT not found: {j}', file=sys.stderr)
            return 1

    runs = {
        f'{args.v10_label}_base': {},
        f'{args.v10_label}_imit': {},
        f'{args.v11_label}_base': {},
        f'{args.v11_label}_imit': {},
    }

    for run_idx in range(args.n_runs):
        print(f'\n=== run {run_idx+1}/{args.n_runs} ===', flush=True)
        for jit_ver, jit_src, thr in [(args.v10_label, args.v10_jit, args.v10_threshold),
                                       (args.v11_label, args.v11_jit, args.v11_threshold)]:
            print(f'  installing {jit_ver} into Core_Root ({jit_src})', flush=True)
            shutil.copy(jit_src, core_jit)
            for cfg in ['base', 'imit']:
                env_extra = None
                if cfg == 'imit':
                    env_extra = [
                        'DOTNET_JitCseImitation:1',
                        f'DOTNET_JitCseImitationThreshold:{thr}',
                    ]
                key = f'{jit_ver}_{cfg}'
                for filt in args.filter:
                    tag = f'{key}_r{run_idx}_' + filt.replace('*','_').replace(':','_').replace('.','_').replace('(','_').replace(')','_')
                    tag_dir = os.path.join(save_dir, 'bdn_raw', tag)
                    result = _run_bdn(args.dotnet, args.dll, filt, args.corerun, env_extra, args.workdir, tag_dir)
                    for k, v in result.items():
                        runs[key].setdefault(k, []).append(v)

    all_benchmarks = set()
    for cfg in runs:
        all_benchmarks.update(runs[cfg].keys())

    print('\n' + '=' * 200)
    v10 = args.v10_label
    v11 = args.v11_label
    hdr = f'{"benchmark":<55} '
    for cfg in [f'{v10}_base', f'{v10}_imit', f'{v11}_base', f'{v11}_imit']:
        hdr += f'{cfg+"_med":>16} '
    hdr += f'{v10+"_dpct":>10} {v11+"_dpct":>10} {"base_drift%":>11}'
    print(hdr)
    print('-' * 200)

    rows = []
    for name in sorted(all_benchmarks):
        m = {}
        for cfg in runs:
            vs = sorted(runs[cfg].get(name, []))
            m[cfg] = statistics.median(vs) if vs else float('nan')
        v10_base_v = m[f'{v10}_base']
        v10_imit_v = m[f'{v10}_imit']
        v11_base_v = m[f'{v11}_base']
        v11_imit_v = m[f'{v11}_imit']
        v10_d = (v10_imit_v - v10_base_v) / v10_base_v * 100 if v10_base_v else 0
        v11_d = (v11_imit_v - v11_base_v) / v11_base_v * 100 if v11_base_v else 0
        base_drift = (v11_base_v - v10_base_v) / v10_base_v * 100 if v10_base_v else 0
        line = f'{name[:55]:<55} '
        line += f'{v10_base_v:>16.1f} {v10_imit_v:>16.1f} {v11_base_v:>16.1f} {v11_imit_v:>16.1f} '
        line += f'{v10_d:>+9.2f}% {v11_d:>+9.2f}% {base_drift:>+10.3f}%'
        print(line)
        rows.append([name, v10_base_v, v10_imit_v, v11_base_v, v11_imit_v, v10_d, v11_d, base_drift])

    with open(args.out_csv, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['benchmark',
                    f'{v10}_base', f'{v10}_imit', f'{v11}_base', f'{v11}_imit',
                    f'{v10}_delta_pct', f'{v11}_delta_pct', 'base_drift_pct'])
        for r in rows:
            w.writerow(r)
    print(f'\nWrote {args.out_csv}')

    if rows:
        v10_d = [r[5] for r in rows]
        v11_d = [r[6] for r in rows]
        drift = [r[7] for r in rows]
        print(f'\nBase drift ({v11} vs {v10}):  min={min(drift):+.2f}%  median={statistics.median(drift):+.2f}%  max={max(drift):+.2f}%')
        print(f'{v10} imit vs base:     median={statistics.median(v10_d):+.2f}%  (n_wins={sum(1 for d in v10_d if d<-0.5)})')
        print(f'{v11} imit vs base:     median={statistics.median(v11_d):+.2f}%  (n_wins={sum(1 for d in v11_d if d<-0.5)})')

    return 0

if __name__ == '__main__':
    sys.exit(main() or 0)
