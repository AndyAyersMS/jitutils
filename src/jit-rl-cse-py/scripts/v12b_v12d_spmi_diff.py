"""Per-method SPMI perfscore comparison v12b vs v12d on bench_pgo.

Both at their preferred thresholds (v12b @ 0.30, v12d @ 0.40).
"""
import subprocess, re, sys, os

SUPERPMI = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\superpmi.exe'
V12B = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v12b.dll'
V12D = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v12d.dll'
V11  = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v11.dll'
MCH  = r'C:\spmi\mch-tier1\staging\benchmarks.run_pgo.windows.x64.checked.tier1.mch'


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
        nca = re.search(r'num cand (\d+)', ln)
        mode = re.search(r'\(([^)]+)\)\s*$', ln)
        name = re.search(r'for method ([^ ]+)', ln)
        if not (idx and perf and name):
            continue
        ncand = int(nca.group(1)) if nca else 0
        if ncand < 1:
            continue
        out[int(idx.group(1))] = {
            'perf': float(perf.group(1)),
            'num_cse': int(nc.group(1)) if nc else 0,
            'num_cand': ncand,
            'mode': mode.group(1) if mode else '',
            'name': name.group(1),
        }
    p.wait(timeout=10)
    return out


def main():
    print('Loading v11 @ 0.30...', flush=True)
    v11 = run_all(V11, imit=True, threshold='0.30')
    print(f'  {len(v11)} methods')
    print('Loading v12b @ 0.30...', flush=True)
    v12b = run_all(V12B, imit=True, threshold='0.30')
    print(f'  {len(v12b)} methods')
    print('Loading v12d @ 0.40...', flush=True)
    v12d = run_all(V12D, imit=True, threshold='0.40')
    print(f'  {len(v12d)} methods')

    common = set(v11) & set(v12b) & set(v12d)

    # Compare v12b vs v12d per method: which has better (lower) perfscore
    v12b_wins = []  # v12b better than v12d
    v12d_wins = []
    ties = 0
    for mid in common:
        p_b = v12b[mid]['perf']
        p_d = v12d[mid]['perf']
        if abs(p_b - p_d) < 0.5:
            ties += 1
            continue
        delta_bd = (p_d - p_b) / p_b * 100  # positive if v12d worse than v12b
        if delta_bd > 0.5:
            v12b_wins.append((mid, delta_bd, v12b[mid]))
        elif delta_bd < -0.5:
            v12d_wins.append((mid, -delta_bd, v12b[mid]))

    print(f'\nDirect per-method comparison v12b vs v12d:')
    print(f'  v12b wins:  {len(v12b_wins)} methods ({sum(1 for w in v12b_wins if "OSR" in w[2]["mode"])} OSR)')
    print(f'  v12d wins:  {len(v12d_wins)} methods ({sum(1 for w in v12d_wins if "OSR" in w[2]["mode"])} OSR)')
    print(f'  ties:       {ties}')

    # Sum absolute perfscore differences
    total_v12b = sum(v12b[m]['perf'] for m in common)
    total_v12d = sum(v12d[m]['perf'] for m in common)
    total_v11 = sum(v11[m]['perf'] for m in common)
    print(f'\nTotal perfscore across {len(common)} methods:')
    print(f'  v11 @ 0.30:  {total_v11:12.0f}')
    print(f'  v12b @ 0.30: {total_v12b:12.0f} (vs v11: {(total_v12b-total_v11)/total_v11*100:+.3f}%)')
    print(f'  v12d @ 0.40: {total_v12d:12.0f} (vs v11: {(total_v12d-total_v11)/total_v11*100:+.3f}%)')
    print(f'                                         (v12d vs v12b: {(total_v12d-total_v12b)/total_v12b*100:+.3f}%)')

    # Top diffs (largest v12b advantage over v12d)
    print(f'\nTop 15 methods where v12b beats v12d most:')
    for mid, d, m in sorted(v12b_wins, key=lambda x: -x[1])[:15]:
        print(f'  {mid:>6} {m["mode"][:11]:<11} d={d:+7.2f}% v12b_perf={v12b[mid]["perf"]:>10.0f} v12d_perf={v12d[mid]["perf"]:>10.0f} {m["name"][:70]}')

    print(f'\nTop 15 methods where v12d beats v12b most:')
    for mid, d, m in sorted(v12d_wins, key=lambda x: -x[1])[:15]:
        print(f'  {mid:>6} {m["mode"][:11]:<11} d={d:+7.2f}% v12b_perf={v12b[mid]["perf"]:>10.0f} v12d_perf={v12d[mid]["perf"]:>10.0f} {m["name"][:70]}')


if __name__ == '__main__':
    main()
