"""Compare heur/v10/v11 CSE decisions on RayTracer + Regex-cache-hit hot methods."""
import subprocess, re, sys, os

SUPERPMI = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\superpmi.exe'
V10 = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v10.dll'
V11 = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v11.dll'
MCH = r'C:\spmi\mch-tier1\staging\benchmarks.run_pgo.windows.x64.checked.tier1.mch'

_RE_PERF = re.compile(r'PerfScore ([0-9.]+)')
_RE_INDEX = re.compile(r'spmi index (\d+)')
_RE_NUMCSE = re.compile(r'num cse (\d+)')
_RE_NUMCAND = re.compile(r'num cand (\d+)')
_RE_SEQ = re.compile(r'seq ([0-9,\-]+)(?= spmi index )')
_RE_NAME = re.compile(r'for method ([^ ]+)')
_RE_MODE = re.compile(r'\(([^)]+)\)\s*$')


def run_one(mid, jit, imit=False, threshold=None):
    args = [SUPERPMI, jit, MCH, '-v', 'q', '-c', str(mid), '-jitoption', 'JitMetrics=1']
    if imit:
        args += ['-jitoption', 'JitCseImitation=1']
        if threshold:
            args += ['-jitoption', f'JitCseImitationThreshold={threshold}']
    p = subprocess.run(args, capture_output=True, text=True, timeout=30)
    for line in p.stdout.split('\n'):
        if not line.startswith(';'):
            continue
        idx_m = _RE_INDEX.search(line)
        if not idx_m or int(idx_m.group(1)) != mid:
            continue
        return {
            'perf': float(_RE_PERF.search(line).group(1)),
            'num_cse': int(_RE_NUMCSE.search(line).group(1)) if _RE_NUMCSE.search(line) else 0,
            'num_cand': int(_RE_NUMCAND.search(line).group(1)) if _RE_NUMCAND.search(line) else 0,
            'seq': _RE_SEQ.search(line).group(1) if _RE_SEQ.search(line) else '',
            'mode': _RE_MODE.search(line).group(1) if _RE_MODE.search(line) else '',
            'name': _RE_NAME.search(line).group(1) if _RE_NAME.search(line) else '',
        }
    return None


def bits(seq):
    if not seq: return set()
    return set(int(x) for x in seq.split(','))


def compare(mids, title):
    print(f'\n=== {title} ===')
    print(f'{"mid":>6} {"mode":<11} {"name":<48} {"cand":>4} {"h_perf":>10} {"h_n":>3} {"v10_perf":>10} {"v10_n":>4} {"v11_perf":>10} {"v11_n":>4}  {"v10dh%":>7} {"v11dh%":>7}  same_v10v11')
    for mid in mids:
        h = run_one(mid, V10, imit=False)
        v10 = run_one(mid, V10, imit=True, threshold='0.50')
        v11 = run_one(mid, V11, imit=True, threshold='0.30')
        if not (h and v10 and v11):
            print(f'{mid} MISSING')
            continue
        d10 = (v10['perf'] - h['perf'])/h['perf']*100 if h['perf'] else 0
        d11 = (v11['perf'] - h['perf'])/h['perf']*100 if h['perf'] else 0
        v10bits = bits(v10['seq'])
        v11bits = bits(v11['seq'])
        hbits = bits(h['seq'])
        same = v10bits == v11bits
        print(f'{mid:>6} {h["mode"][:11]:<11} {h["name"][:48]:<48} {h["num_cand"]:>4} '
              f'{h["perf"]:>10.1f} {h["num_cse"]:>3d} '
              f'{v10["perf"]:>10.1f} {v10["num_cse"]:>4d} '
              f'{v11["perf"]:>10.1f} {v11["num_cse"]:>4d}  '
              f'{d10:>+6.2f}% {d11:>+6.2f}%  {same}')
        # Show decision differences
        if not same:
            v10_only = sorted(v10bits - v11bits)
            v11_only = sorted(v11bits - v10bits)
            print(f'       v10-only bits: {v10_only}   v11-only bits: {v11_only}')


def main():
    # RayTracer hot methods
    raytracer_mids = [6294, 6302, 6301, 6298, 6304, 6299, 6295, 6297]
    compare(raytracer_mids, 'RayTracer methods')

    # Regex cache-hit path candidates. For u=7/cs=15 the cache is always-hit.
    # Interpret + FindOpt + Regex.ScanInternal are the hot ones.
    regex_hit_mids = [
        # Top Tier1-OSR interpreter scans
        13955, 4365, 13943, 4376, 5191, 12115, 12126,
        # Tier1 interpreter/scan
        15822, 15821, 13962, 13963,
        # RegexFindOptimizations
        4380, 15777, 15778, 13349, 3732, 7193, 15516, 7768,
        # Regex methods
        3754, 15790,
    ]
    compare(regex_hit_mids, 'Regex cache-hit path')


if __name__ == '__main__':
    main()
