"""Gap-to-optimum analysis: how close does each model get to the MCMC-optimum
perfscore per method?

For each labeled method:
  - Load optimal_perfscore from label_bench_pgo/labels.json
  - Compute heur perfscore (with a specific JIT dll)
  - Compute v11 imit perfscore
  - Compute v12b imit perfscore
  - Report: sum of (perf - opt) / opt across all methods

The lower the gap, the closer to best-known.
"""
import subprocess, re, sys, os, json

SUPERPMI = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\superpmi.exe'
V11 = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v11.dll'
V12B = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v12b.dll'
V12D = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v12d.dll'
MCH = r'C:\spmi\mch-tier1\staging\benchmarks.run_pgo.windows.x64.checked.tier1.mch'
LABELS = r'C:\Users\andya\.copilot\session-state\e0c45c58-07ca-44b1-bdd1-50010f6ae096\files\label_bench_pgo\labels.json'


def run_all(jit, imit=False, threshold=None, limit=8000):
    args = [SUPERPMI, jit, MCH, '-v', 'q', '-c', f'1-{limit}',
            '-jitoption', 'JitMetrics=1']
    if imit:
        args += ['-jitoption', 'JitCseImitation=1',
                 '-jitoption', f'JitCseImitationThreshold={threshold}']
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = {}
    for line in p.stdout:
        ln = line.decode('utf-8', 'replace').rstrip()
        if not ln.startswith(';'):
            continue
        idx = re.search(r'spmi index (\d+)', ln)
        perf = re.search(r'PerfScore ([0-9.]+)', ln)
        nc = re.search(r'num cse (\d+)', ln)
        mode = re.search(r'\(([^)]+)\)\s*$', ln)
        if not (idx and perf):
            continue
        out[int(idx.group(1))] = {
            'perf': float(perf.group(1)),
            'num_cse': int(nc.group(1)) if nc else 0,
            'mode': mode.group(1) if mode else '',
        }
    p.wait(timeout=10)
    return out


def gap_stats(name, model_perfs, labels):
    n = 0
    n_at_opt = 0
    n_beats_opt = 0
    n_worse_than_heur = 0
    sum_gap_pct = 0.0
    sum_gap_pct_weighted = 0.0  # weighted by opt_perf
    sum_opt = 0.0
    sum_model = 0.0
    total_heur_perf_sum = 0.0
    total_heur_gap_sum = 0.0

    for mid_str, lbl in labels.items():
        mid = int(mid_str)
        if mid not in model_perfs:
            continue
        opt = lbl.get('optimal_perfscore', 0)
        heur = lbl.get('heuristic_perfscore', 0)
        if opt <= 0:
            continue
        model = model_perfs[mid]['perf']
        gap = (model - opt) / opt * 100
        heur_gap = (heur - opt) / opt * 100
        sum_gap_pct += gap
        sum_gap_pct_weighted += gap * opt
        sum_opt += opt
        sum_model += model
        total_heur_perf_sum += heur
        total_heur_gap_sum += (heur - opt) * 100 / opt if opt else 0
        n += 1
        if abs(gap) < 0.01:
            n_at_opt += 1
        if gap < -0.01:
            n_beats_opt += 1
        if model > heur + 0.01:
            n_worse_than_heur += 1

    mean_gap = sum_gap_pct / n if n else 0
    weighted_gap = sum_gap_pct_weighted / sum_opt if sum_opt else 0
    aggregate = (sum_model - sum_opt) / sum_opt * 100

    print(f'  {name:22s}  n={n:<5d}  mean_gap={mean_gap:+7.3f}%  weighted_gap={weighted_gap:+7.3f}%  '
          f'aggregate={aggregate:+7.3f}%  at_opt={n_at_opt:>4d} ({n_at_opt/n*100:>4.1f}%)  '
          f'beats_opt={n_beats_opt:>3d}  worse_than_heur={n_worse_than_heur:>3d}')


def main():
    with open(LABELS) as f:
        labels = json.load(f)
    print(f'Loaded {len(labels)} MCMC-optimum labels for bench_pgo.mch')

    print('\nCollecting per-method perfscores...')
    print('  heur baseline...', flush=True)
    heur = run_all(V11, imit=False)
    print(f'    {len(heur)} methods')
    print('  v11 @ 0.30...', flush=True)
    v11 = run_all(V11, imit=True, threshold='0.30')
    print(f'    {len(v11)} methods')
    print('  v12b @ 0.30...', flush=True)
    v12b = run_all(V12B, imit=True, threshold='0.30')
    print(f'    {len(v12b)} methods')
    print('  v12d @ 0.40...', flush=True)
    v12d = run_all(V12D, imit=True, threshold='0.40')
    print(f'    {len(v12d)} methods')

    # "Optimum" reference: use the label's optimal_perfscore (best over exhaustive/MCMC search).
    print(f'\nGap-to-MCMC-optimum on {len(labels)} labeled methods:')
    print(f'{"":22s}  {"n":<5s}  mean_gap        weighted_gap    aggregate       at_opt         beats_opt worse_than_heur')
    gap_stats('heur (baseline)', heur, labels)
    gap_stats('v11 @ 0.30', v11, labels)
    gap_stats('v12b @ 0.30', v12b, labels)
    gap_stats('v12d @ 0.40', v12d, labels)


if __name__ == '__main__':
    main()
