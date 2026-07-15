#!/usr/bin/env python3
"""Env-var A/B harness for the LACO veto (or any similar toggle).

Instead of swapping clrjit DLLs like bdn_ab_portable.py does, this runs the
same JIT twice per filter — once with a set of env vars ("cfg A", e.g.
baseline), once with a different set ("cfg B", e.g. LACO enabled). Interleaves
within a single session to control for thermal drift.

Usage:
    python bdn_ab_envvars.py \
      --dotnet /usr/bin/dotnet \
      --dll /repo/performance/artifacts/bin/MicroBenchmarks/Release/net11.0/MicroBenchmarks.dll \
      --workdir /repo/performance/src/benchmarks/micro \
      --core-root /repo/runtime/artifacts/tests/coreclr/windows.x64.Release/Tests/Core_Root \
      --corerun ...corerun.exe \
      --jit /path/to/clrjit.dll \
      --a-label baseline \
      --b-label laco \
      --b-env "DOTNET_JitCseLacoVeto:1" \
      --b-env "DOTNET_JitCseLacoVetoSizeThreshold:8" \
      --b-env "DOTNET_JitCseLacoVetoUseCountMax:3" \
      --n-runs 3 --out-csv results.csv \
      --filter '*MDMulMatrix*' --filter '*RayTracerBench*'
"""
import argparse, csv, glob, json, os, shutil, statistics, subprocess, sys, time


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
    ap.add_argument('--dotnet', required=True)
    ap.add_argument('--dll', required=True)
    ap.add_argument('--workdir', required=True)
    ap.add_argument('--jit', required=False,
                    help='Path to single clrjit DLL used for both configs. '
                         'If omitted, both --a-jit and --b-jit are required.')
    ap.add_argument('--a-jit', default=None, help='Per-config JIT for cfg A')
    ap.add_argument('--b-jit', default=None, help='Per-config JIT for cfg B')
    ap.add_argument('--core-root', required=True)
    ap.add_argument('--corerun', required=True)
    ap.add_argument('--out-csv', required=True)
    ap.add_argument('--save-dir', default=None)
    ap.add_argument('--filter', action='append', required=True)
    ap.add_argument('--n-runs', type=int, default=3)
    ap.add_argument('--a-label', default='a')
    ap.add_argument('--b-label', default='b')
    ap.add_argument('--a-env', action='append', default=[],
                    help='Env var for cfg A, "NAME:VALUE" (repeatable)')
    ap.add_argument('--b-env', action='append', default=[],
                    help='Env var for cfg B, "NAME:VALUE" (repeatable)')
    args = ap.parse_args()

    save_dir = args.save_dir or os.path.dirname(os.path.abspath(args.out_csv))
    os.makedirs(save_dir, exist_ok=True)

    if args.jit and (args.a_jit or args.b_jit):
        print('ERROR: pass either --jit OR (--a-jit + --b-jit), not both', file=sys.stderr)
        return 2
    if not args.jit and not (args.a_jit and args.b_jit):
        print('ERROR: pass --jit for single-jit A/B, or both --a-jit and --b-jit', file=sys.stderr)
        return 2

    # Determine JIT filename in Core_Root (assume matching name)
    core_jit_name = 'clrjit.dll' if sys.platform == 'win32' else \
                    ('libclrjit.dylib' if sys.platform == 'darwin' else 'libclrjit.so')
    core_jit = os.path.join(args.core_root, core_jit_name)
    if args.jit:
        print(f'Installing {args.jit} into {core_jit}')
        shutil.copy(args.jit, core_jit)
    a_jit = args.a_jit or args.jit
    b_jit = args.b_jit or args.jit
    print(f'A ({args.a_label}) JIT: {a_jit}')
    print(f'B ({args.b_label}) JIT: {b_jit}')

    runs = {args.a_label: {}, args.b_label: {}}
    for run_idx in range(args.n_runs):
        print(f'\n=== run {run_idx+1}/{args.n_runs} ===')
        for lbl, env_list, jit in [(args.a_label, args.a_env, a_jit),
                                    (args.b_label, args.b_env, b_jit)]:
            if not args.jit:  # per-config JIT
                print(f'  installing {jit} into Core_Root')
                shutil.copy(jit, core_jit)
            for filt in args.filter:
                tag = f'{lbl}_r{run_idx}_' + filt.replace('*','_').replace(':','_').replace('.','_')
                tag_dir = os.path.join(save_dir, 'bdn_raw', tag)
                result = _run_bdn(args.dotnet, args.dll, filt, args.corerun,
                                  env_list, args.workdir, tag_dir)
                for k, v in result.items():
                    runs[lbl].setdefault(k, []).append(v)

    all_benches = set()
    for cfg in runs:
        all_benches.update(runs[cfg])

    print('\n' + '=' * 130)
    hdr = f'{"benchmark":<55} {args.a_label+"_med":>16} {args.b_label+"_med":>16} {"delta%":>10}'
    print(hdr)
    print('-' * 130)
    rows = []
    for name in sorted(all_benches):
        a_vs = sorted(runs[args.a_label].get(name, []))
        b_vs = sorted(runs[args.b_label].get(name, []))
        a_med = statistics.median(a_vs) if a_vs else float('nan')
        b_med = statistics.median(b_vs) if b_vs else float('nan')
        d = (b_med - a_med) / a_med * 100 if a_med else 0.0
        print(f'{name[:55]:<55} {a_med:>16.1f} {b_med:>16.1f} {d:>+9.2f}%')
        rows.append([name, a_med, b_med, d])

    with open(args.out_csv, 'w', newline='') as f:
        w = csv.writer(f)
        w.writerow(['benchmark', f'{args.a_label}_med', f'{args.b_label}_med', 'delta_pct'])
        for r in rows:
            w.writerow(r)
    print(f'\nWrote {args.out_csv}')

    if rows:
        ds = [r[3] for r in rows]
        wins = sum(1 for d in ds if d < -0.5)
        print(f'{args.b_label} vs {args.a_label} median delta: {statistics.median(ds):+.2f}%  wins(<-0.5%)={wins}/{len(ds)}')

    return 0


if __name__ == '__main__':
    sys.exit(main() or 0)
