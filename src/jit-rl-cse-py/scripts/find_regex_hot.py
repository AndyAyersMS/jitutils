"""Find hot Regex methods in bench_pgo.mch."""
import subprocess, re, sys

superpmi = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\superpmi.exe'
jit      = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit.dll'
mch      = r'C:\spmi\mch-tier1\staging\benchmarks.run_pgo.windows.x64.checked.tier1.mch'

p = subprocess.Popen([superpmi, jit, mch, '-v', 'q', '-jitoption', 'JitMetrics=1'],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
hits = []
for line in p.stdout:
    ln = line.decode('utf-8', 'replace').rstrip()
    if not re.search(r'RegularExpressions', ln):
        continue
    idx_m = re.search(r'spmi index (\d+)', ln)
    perf_m = re.search(r'PerfScore ([0-9.]+)', ln)
    name_m = re.search(r'for method ([^ ]+)', ln)
    nc_m = re.search(r'num cse (\d+)', ln)
    ncand_m = re.search(r'num cand (\d+)', ln)
    mode_m = re.search(r'\(([^)]+)\)\s*$', ln)
    if not (idx_m and perf_m and name_m):
        continue
    perf = float(perf_m.group(1))
    ncand = int(ncand_m.group(1)) if ncand_m else 0
    if ncand < 3:
        continue
    if perf < 100:
        continue
    hits.append((int(idx_m.group(1)), perf, int(nc_m.group(1)) if nc_m else 0, ncand,
                 name_m.group(1), mode_m.group(1) if mode_m else ''))
p.terminate()
p.wait(timeout=5)
hits.sort(key=lambda x: -x[1])
print(f'{"idx":>6} {"perf":>12} {"h_n":>4} {"cand":>4} {"name":<80} mode')
for h in hits[:50]:
    print(f'{h[0]:>6} {h[1]:>12.0f} {h[2]:>4d} {h[3]:>4d} {h[4][:80]:<80} {h[5]}')
print(f'\ntotal Regex methods with candidates>=3, perf>=100: {len(hits)}')
