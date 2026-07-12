"""Controlled A/B: alternately run v10 and v11 on the same set of BDN filters
in a single session, to eliminate temporal environmental drift.

For each filter and each config (heur baseline, v10-imit@0.50, v11-imit@0.30),
run N times and record. Reports the median and IQR for each config, plus
the delta of imit vs its own-run baseline.
"""
import argparse, os, subprocess, glob, json, shutil, time, csv, sys, statistics


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
    print(f'    {tag_dir}: {filt}', flush=True)
    t0 = time.time()
    proc = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, timeout=1800)
    elapsed = time.time() - t0
    print(f'      done in {elapsed:.0f}s (rc={proc.returncode})', flush=True)
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
    ap.add_argument('--dotnet', default=r'C:\repos\runtime4\.dotnet\dotnet.exe')
    ap.add_argument('--dll', default=r'C:\repos\performance\artifacts\bin\MicroBenchmarks\Release\net11.0\MicroBenchmarks.dll')
    ap.add_argument('--workdir', default=r'C:\repos\performance\src\benchmarks\micro')
    ap.add_argument('--v10-jit', required=True)
    ap.add_argument('--v11-jit', required=True)
    ap.add_argument('--core-root', required=True, help='Core_Root dir; we\'ll swap clrjit.dll in here')
    ap.add_argument('--corerun', required=True)
    ap.add_argument('--out-csv', required=True)
    ap.add_argument('--save-dir', default=None)
    ap.add_argument('--filter', action='append', required=True)
    ap.add_argument('--n-runs', type=int, default=3)
    args = ap.parse_args()

    save_dir = args.save_dir or os.path.dirname(os.path.abspath(args.out_csv))
    os.makedirs(save_dir, exist_ok=True)

    core_jit = os.path.join(args.core_root, 'clrjit.dll')

    # Structure:  results[filter][config] = list of medians for benchmark -> mean_ns dict-of-lists.
    # We aggregate PER-benchmark across runs.
    # runs[cfg][bench_key] = list of mean_ns values across N runs.
    runs = {
        'v10_base':  {},
        'v10_imit':  {},
        'v11_base':  {},
        'v11_imit':  {},
    }

    for run_idx in range(args.n_runs):
        print(f'\n=== run {run_idx+1}/{args.n_runs} ===', flush=True)
        # Interleave: v10 (base + imit) then v11 (base + imit).
        # Swap clrjit.dll each JIT change.
        for jit_ver, jit_src in [('v10', args.v10_jit), ('v11', args.v11_jit)]:
            print(f'  installing {jit_ver} into Core_Root', flush=True)
            shutil.copy(jit_src, core_jit)
            for cfg in ['base', 'imit']:
                env_extra = None
                if cfg == 'imit':
                    thr = '0.50' if jit_ver == 'v10' else '0.30'
                    env_extra = [
                        'DOTNET_JitCseImitation:1',
                        f'DOTNET_JitCseImitationThreshold:{thr}',
                    ]
                key = f'{jit_ver}_{cfg}'
                for filt in args.filter:
                    tag = f'{key}_r{run_idx}_{filt.replace("*","_").replace(":","_").replace(".","_")}'
                    tag_dir = os.path.join(save_dir, 'bdn_raw', tag)
                    result = _run_bdn(args.dotnet, args.dll, filt, args.corerun, env_extra, args.workdir, tag_dir)
                    for k, v in result.items():
                        runs[key].setdefault(k, []).append(v)

    # Report.
    all_benchmarks = set()
    for cfg in runs:
        all_benchmarks.update(runs[cfg].keys())

    print('\n' + '=' * 200)
    hdr = f'{"benchmark":<55} '
    for cfg in ['v10_base','v10_imit','v11_base','v11_imit']:
        hdr += f'{cfg+"_med":>13} '
    hdr += f'{"v10_dpct":>9} {"v11_dpct":>9} {"base_drift%":>11}'
    print(hdr)
    print('-' * 200)

    rows = []
    for name in sorted(all_benchmarks):
        m = {}
        for cfg in runs:
            vs = sorted(runs[cfg].get(name, []))
            m[cfg] = statistics.median(vs) if vs else float('nan')
        v10_d = (m['v10_imit'] - m['v10_base']) / m['v10_base'] * 100
        v11_d = (m['v11_imit'] - m['v11_base']) / m['v11_base'] * 100
        base_drift = (m['v11_base'] - m['v10_base']) / m['v10_base'] * 100
        line = f'{name[:55]:<55} '
        for cfg in ['v10_base','v10_imit','v11_base','v11_imit']:
            line += f'{m[cfg]:>13.1f} '
        line += f'{v10_d:>+8.2f}% {v11_d:>+8.2f}% {base_drift:>+10.3f}%'
        print(line)
        rows.append([name, m['v10_base'], m['v10_imit'], m['v11_base'], m['v11_imit'], v10_d, v11_d, base_drift])

    with open(args.out_csv, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['benchmark','v10_base','v10_imit','v11_base','v11_imit','v10_delta_pct','v11_delta_pct','base_drift_pct'])
        for r in rows:
            w.writerow(r)
    print(f'\nWrote {args.out_csv}')

    if rows:
        v10_d = [r[5] for r in rows]
        v11_d = [r[6] for r in rows]
        drift = [r[7] for r in rows]
        print(f'\nBase drift (v11 vs v10):  min={min(drift):+.2f}%  median={statistics.median(drift):+.2f}%  max={max(drift):+.2f}%')
        print(f'v10 imit vs its base:     median={statistics.median(v10_d):+.2f}%  (n_wins={sum(1 for d in v10_d if d<-0.5)})')
        print(f'v11 imit vs its base:     median={statistics.median(v11_d):+.2f}%  (n_wins={sum(1 for d in v11_d if d<-0.5)})')

if __name__ == '__main__':
    sys.exit(main() or 0)
