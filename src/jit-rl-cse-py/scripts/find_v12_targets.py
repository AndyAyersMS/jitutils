"""Find hot methods for RayTracer and Regex-cache-hit paths in bench_pgo.mch."""
import subprocess, re, sys

SUPERPMI = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\superpmi.exe'
JIT      = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v10.dll'
MCH      = r'C:\spmi\mch-tier1\staging\benchmarks.run_pgo.windows.x64.checked.tier1.mch'


def scan(pattern, min_ncand=2, min_perf=10):
    p = subprocess.Popen([SUPERPMI, JIT, MCH, '-v', 'q', '-jitoption', 'JitMetrics=1'],
                         stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    hits = []
    rx = re.compile(pattern)
    for line in p.stdout:
        ln = line.decode('utf-8', 'replace').rstrip()
        if not rx.search(ln):
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
        perf = float(perf_m.group(1))
        if ncand < min_ncand or perf < min_perf:
            continue
        hits.append((int(idx_m.group(1)), perf, int(nc_m.group(1)) if nc_m else 0, ncand,
                     name_m.group(1), mode_m.group(1) if mode_m else ''))
    p.terminate()
    p.wait(timeout=5)
    return hits


def print_hits(name, hits, top=25):
    hits.sort(key=lambda x: -x[1])
    print(f'\n=== {name} ({len(hits)} total, showing top {top}) ===')
    print(f'{"idx":>6} {"perf":>12} {"h_n":>3} {"nca":>3} {"mode":<12} name')
    for h in hits[:top]:
        print(f'{h[0]:>6} {h[1]:>12.0f} {h[2]:>3d} {h[3]:>3d} {h[5][:12]:<12} {h[4][:80]}')


def main():
    # RayTracer: Benchmarks.SIMD.RayTracer namespace
    rt = scan(r'RayTracer|Sphere|Plane|Vector3|Vector4|SceneObject|Camera|Light', min_ncand=3, min_perf=50)
    # Filter down to actual RayTracer classes
    rt_relevant = [h for h in rt if 'RayTracer' in h[4] or 'Benchmarks.SIMD' in h[4]]
    print_hits('RayTracer-related methods', rt_relevant)

    # Regex cache-hit path (for u=7, cs=15): RegexInterpreter, RegexRunner, small helpers
    # Get is called every time (cache lookup); Add is NOT called (all hits)
    rgx = scan(r'RegexInterpreter|RegexRunner|Regex:IsMatch|RegexCache:Get\b|RegexFindOpt', min_ncand=2, min_perf=20)
    print_hits('Regex cache-hit path', rgx)


if __name__ == '__main__':
    main()
