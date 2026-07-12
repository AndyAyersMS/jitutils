"""Find Regex:IsMatch, Regex:Match, Regex:Run entry points and helpers."""
import subprocess, re

superpmi = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\superpmi.exe'
jit      = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v10.dll'
mch      = r'C:\spmi\mch-tier1\staging\benchmarks.run_pgo.windows.x64.checked.tier1.mch'
p = subprocess.Popen([superpmi, jit, mch, '-v', 'q', '-jitoption', 'JitMetrics=1'],
                     stdout=subprocess.PIPE, stderr=subprocess.PIPE)
for line in p.stdout:
    ln = line.decode('utf-8', 'replace').rstrip()
    if not re.search(r'IsMatch|Regex.Match\b|Perf_Regex_Cache', ln):
        continue
    if 'RegularExpressions' not in ln:
        continue
    idx_m = re.search(r'spmi index (\d+)', ln)
    perf_m = re.search(r'PerfScore ([0-9.]+)', ln)
    name_m = re.search(r'for method ([^ ]+)', ln)
    nc_m = re.search(r'num cse (\d+)', ln)
    ncand_m = re.search(r'num cand (\d+)', ln)
    mode_m = re.search(r'\(([^)]+)\)\s*$', ln)
    if not (idx_m and perf_m and name_m):
        continue
    ncand = int(ncand_m.group(1)) if ncand_m else 0
    if ncand < 1:
        continue
    idx = int(idx_m.group(1))
    perf = float(perf_m.group(1))
    ncse = int(nc_m.group(1)) if nc_m else 0
    mode = mode_m.group(1) if mode_m else ''
    print(f'{idx:>6} {perf:>12.1f} nc={ncse:>2d} nca={ncand:>2d} {mode:<10} {name_m.group(1)[:80]}')
p.terminate()
p.wait(timeout=5)
