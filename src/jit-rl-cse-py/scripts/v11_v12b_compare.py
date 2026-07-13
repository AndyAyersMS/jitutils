"""Quick SPMI perfscore comparison v11 vs v12b across a few thresholds.

For the first N methods of bench_pgo.mch:
  - Run heur (baseline)
  - Run v11 at t=0.30
  - Run v12b at various thresholds (0.30, 0.40, 0.50)
Report aggregate perfscore delta vs heur for each.
"""
import subprocess, re, sys, os

SUPERPMI = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\superpmi.exe'
MCH = r'C:\spmi\mch-tier1\staging\benchmarks.run_pgo.windows.x64.checked.tier1.mch'
V11 = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v11.dll'
V12B = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v12b.dll'
V12C = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v12c.dll'
V12D = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v12d.dll'


def run_range(jit, imit=False, threshold=None, limit=8000):
    args = [SUPERPMI, jit, MCH, '-v', 'q', '-c', f'1-{limit}',
            '-jitoption', 'JitMetrics=1']
    if imit:
        args += ['-jitoption', 'JitCseImitation=1']
        if threshold:
            args += ['-jitoption', f'JitCseImitationThreshold={threshold}']
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = {}  # mid -> (perf, num_cse, num_cand, mode)
    for line in p.stdout:
        ln = line.decode('utf-8', 'replace').rstrip()
        if not ln.startswith(';'):
            continue
        idx = re.search(r'spmi index (\d+)', ln)
        perf = re.search(r'PerfScore ([0-9.]+)', ln)
        nc = re.search(r'num cse (\d+)', ln)
        nca = re.search(r'num cand (\d+)', ln)
        mode = re.search(r'\(([^)]+)\)\s*$', ln)
        if not (idx and perf):
            continue
        ncand = int(nca.group(1)) if nca else 0
        if ncand < 1:
            continue
        out[int(idx.group(1))] = (float(perf.group(1)),
                                   int(nc.group(1)) if nc else 0,
                                   ncand, mode.group(1) if mode else '')
    p.wait(timeout=10)
    return out


def summarize(name, heur, other):
    common = set(heur.keys()) & set(other.keys())
    total_h = sum(heur[k][0] for k in common)
    total_o = sum(other[k][0] for k in common)
    tier1 = [k for k in common if 'Tier1' in heur[k][3] and 'OSR' not in heur[k][3]]
    osr = [k for k in common if 'OSR' in heur[k][3]]
    total_t1_h = sum(heur[k][0] for k in tier1)
    total_t1_o = sum(other[k][0] for k in tier1)
    total_osr_h = sum(heur[k][0] for k in osr)
    total_osr_o = sum(other[k][0] for k in osr)
    total_cse_h = sum(heur[k][1] for k in common)
    total_cse_o = sum(other[k][1] for k in common)
    print(f'  {name}: n={len(common)} '
          f'total_perf {total_h:.0f} -> {total_o:.0f} = {(total_o-total_h)/total_h*100:+.3f}% '
          f'| Tier1 {(total_t1_o-total_t1_h)/total_t1_h*100:+.3f}% '
          f'| OSR {(total_osr_o-total_osr_h)/total_osr_h*100:+.3f}% '
          f'| total_cse {total_cse_h} -> {total_cse_o}')


def main():
    print('Heuristic baseline...', flush=True)
    heur = run_range(V11, imit=False)
    print(f'  {len(heur)} methods with candidates')

    for jit_name, jit in [('v11', V11), ('v12b', V12B), ('v12c', V12C), ('v12d', V12D)]:
        for thr in ['0.20', '0.30', '0.40', '0.50']:
            print(f'{jit_name} @ t={thr}...', flush=True)
            r = run_range(jit, imit=True, threshold=thr)
            summarize(f'{jit_name}@{thr}', heur, r)


if __name__ == '__main__':
    main()
