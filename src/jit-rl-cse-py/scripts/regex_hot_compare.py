"""Compare v10 vs v11 vs heur decisions on specific Regex hot methods.

For each specified method:
  - Run heur baseline (no imitation)
  - Run v10 imit at t=0.50
  - Run v11 imit at t=0.30
  - Report: perfscore, num_cse applied, applied bitset, cse_candidates set
"""
import subprocess, re, sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SUPERPMI = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\superpmi.exe'
JIT_V10  = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v10.dll'
JIT_V11  = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v11.dll'
MCH      = r'C:\spmi\mch-tier1\staging\benchmarks.run_pgo.windows.x64.checked.tier1.mch'

_RE_PERF = re.compile(r'PerfScore ([0-9.]+)')
_RE_INDEX = re.compile(r'spmi index (\d+)')
_RE_NUMCSE = re.compile(r'num cse (\d+)')
_RE_NUMCAND = re.compile(r'num cand (\d+)')
_RE_SEQ = re.compile(r'seq ([0-9,\-]+)(?= spmi index )')
_RE_NAME = re.compile(r'for method ([^ ]+)')
_RE_MODE = re.compile(r'\(([^)]+)\)\s*$')
_RE_BYTES = re.compile(r'Total bytes of code (\d+)')
_RE_INSTR = re.compile(r'instruction count (\d+)')


def run_method(mid, jit, imit=False, threshold=None):
    args = [SUPERPMI, jit, MCH, '-v', 'q', '-c', str(mid), '-jitoption', 'JitMetrics=1']
    if imit:
        args += ['-jitoption', 'JitCseImitation=1']
        if threshold is not None:
            args += ['-jitoption', f'JitCseImitationThreshold={threshold}']
    p = subprocess.run(args, capture_output=True, text=True, timeout=30)
    for line in p.stdout.split('\n'):
        if not line.startswith(';'):
            continue
        idx = _RE_INDEX.search(line)
        if not idx or int(idx.group(1)) != mid:
            continue
        perf = _RE_PERF.search(line)
        nc = _RE_NUMCSE.search(line)
        ncand = _RE_NUMCAND.search(line)
        seq = _RE_SEQ.search(line)
        mode = _RE_MODE.search(line)
        name = _RE_NAME.search(line)
        bs = _RE_BYTES.search(line)
        ic = _RE_INSTR.search(line)
        return {
            'perf': float(perf.group(1)) if perf else None,
            'num_cse': int(nc.group(1)) if nc else 0,
            'num_cand': int(ncand.group(1)) if ncand else 0,
            'seq': seq.group(1) if seq else '',
            'mode': mode.group(1) if mode else '',
            'name': name.group(1) if name else '',
            'bytes': int(bs.group(1)) if bs else 0,
            'instr': int(ic.group(1)) if ic else 0,
        }
    return None


def compare(mid):
    heur = run_method(mid, JIT_V10, imit=False)  # heur behavior is the same in both jits
    v10  = run_method(mid, JIT_V10, imit=True, threshold='0.50')
    v11  = run_method(mid, JIT_V11, imit=True, threshold='0.30')
    if not (heur and v10 and v11):
        return None
    def bits(seq):
        if not seq:
            return set()
        return set(int(x) for x in seq.split(','))
    hbits = bits(heur['seq'])
    v10bits = bits(v10['seq'])
    v11bits = bits(v11['seq'])
    return {
        'mid': mid,
        'name': heur['name'],
        'mode': heur['mode'],
        'ncand': heur['num_cand'],
        'heur': (heur['perf'], heur['num_cse'], sorted(hbits), heur['bytes'], heur['instr']),
        'v10':  (v10['perf'],  v10['num_cse'],  sorted(v10bits), v10['bytes'], v10['instr']),
        'v11':  (v11['perf'],  v11['num_cse'],  sorted(v11bits), v11['bytes'], v11['instr']),
        'v10_vs_heur_bits_added':   sorted(v10bits - hbits),
        'v10_vs_heur_bits_removed': sorted(hbits - v10bits),
        'v11_vs_heur_bits_added':   sorted(v11bits - hbits),
        'v11_vs_heur_bits_removed': sorted(hbits - v11bits),
        'v10_vs_v11_bits_added':    sorted(v10bits - v11bits),
        'v10_vs_v11_bits_removed':  sorted(v11bits - v10bits),
    }


def main():
    # Hot methods driving Perf_Regex_Cache.IsMatch_Multithreading[cs=15]
    # (cache miss dominates, so constructor + interpret + init)
    hot_mids = [
        # RegexCache lookup path (contended in multithreading)
        8708,  # RegexCache:GetOrAdd
        8712,  # RegexCache:Get
        9487,  # RegexCache:Add
        15772, # RegexCache:GetOrAdd (Tier1 variant)
        15753, # RegexCache:Get (Tier1 variant)
        # Regex constructor (called on cache miss)
        2318,  # Regex:.ctor
        10384, # Regex:.ctor (clone)
        # RegexRunner (called per IsMatch)
        1913, 2277, 3752, 5885, 8693, 12355, 13960,
        # Regex scan
        15821, # Regex:ScanInternal
        15822, # RegexInterpreter:Scan
        # Sample of Regex:Count / RunAllMatchesWithCallback (Tier1)
        12365, # Regex:Count
        12366, # Regex:RunAllMatchesWithCallback
        6248,  # Regex:Count Tier1
        6249,  # Regex:RunAllMatchesWithCallback Tier1
    ]

    print(f'{"mid":>6} {"mode":>10} {"name":<70} {"nca":>3} '
          f'{"h_perf":>10} {"h_n":>3} '
          f'{"v10_perf":>10} {"v10_n":>4} '
          f'{"v11_perf":>10} {"v11_n":>4} '
          f'{"v10dh%":>7} {"v11dh%":>7} {"v11dv10%":>8}')
    print('-' * 200)
    for mid in hot_mids:
        r = compare(mid)
        if not r:
            print(f'{mid:>6}  MISSING')
            continue
        h_perf = r['heur'][0]
        v10_perf = r['v10'][0]
        v11_perf = r['v11'][0]
        d10 = (v10_perf - h_perf)/h_perf*100 if h_perf else 0
        d11 = (v11_perf - h_perf)/h_perf*100 if h_perf else 0
        dv = (v11_perf - v10_perf)/v10_perf*100 if v10_perf else 0
        print(f'{mid:>6} {r["mode"][:10]:>10} {r["name"][:70]:<70} {r["ncand"]:>3} '
              f'{h_perf:>10.1f} {r["heur"][1]:>3d} '
              f'{v10_perf:>10.1f} {r["v10"][1]:>4d} '
              f'{v11_perf:>10.1f} {r["v11"][1]:>4d} '
              f'{d10:>+6.2f}% {d11:>+6.2f}% {dv:>+7.2f}%')
        if r['v10_vs_v11_bits_added'] or r['v10_vs_v11_bits_removed']:
            print(f'       v10-only bits: {r["v10_vs_v11_bits_added"]}   v11-only bits: {r["v10_vs_v11_bits_removed"]}')

if __name__ == '__main__':
    main()
