"""Focused deep-dive on Benchstone microbenchmarks where imitation
regresses vs heuristic.

For each interesting method (MDLogicArray, MDNDhrystone, NDhrystone,
EMFloatClass, MDMulMatrix, ...) in benchmarks.run_pgo.mch, runs superpmi
three times and reports:
  - heur:            perfscore, seq bits, num_cse
  - imit @ 0.30:     perfscore, seq bits, num_cse  (perfscore-optimal)
  - imit @ 0.50:     perfscore, seq bits, num_cse  (wall-clock-optimal)
  - mcmc opt (opt):  perfscore, seq bits, num_cse  (from label pool if present)

Then prints per-candidate features so we can spot WHICH extra CSE(s)
the imitation model wants that the heuristic refuses.
"""
from __future__ import annotations
import argparse, json, os, re, subprocess, sys

SUPERPMI = r"C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\superpmi.exe"
JIT      = r"C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit.dll"

_RE_INDEX  = re.compile(r'spmi index (\d+)')
_RE_PERF   = re.compile(r'PerfScore ([0-9.]+)')
_RE_NAME   = re.compile(r'for method ([^ ]+)')
_RE_NUMCSE = re.compile(r'num cse (\d+)')
_RE_NUMCAND = re.compile(r'num cand (\d+)')
_RE_SEQ    = re.compile(r'seq ([0-9,\-]+)(?= spmi index )')
_RE_FEATURES = re.compile(r' features #(\S+)')
_RE_MODE   = re.compile(r'\(([^)]+)\)\s*$')


def run_range(mch, start, end, *jit_opts, features=False):
    """Run superpmi over -c start-end with extra jit options. Return list of parsed method dicts."""
    c_arg = f"{start}" if start == end else f"{start}-{end}"
    args = [SUPERPMI, JIT, mch, '-v', 'q', '-c', c_arg,
            '-jitoption', 'JitMetrics=1']
    if features:
        args += ['-jitoption', 'JitRLHook=1', '-jitoption', 'JitRLHookEmitFeatures=1',
                 '-jitoption', 'JitRLHookEmitFeatureNames=1']
    for opt in jit_opts:
        args += ['-jitoption', opt]
    p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out = []
    for line in p.stdout:
        ln = line.decode('utf-8', errors='replace').rstrip()
        if not ln.startswith(';'):
            continue
        idx_m = _RE_INDEX.search(ln)
        perf_m = _RE_PERF.search(ln)
        name_m = _RE_NAME.search(ln)
        if not (idx_m and perf_m and name_m):
            continue
        nc_m = _RE_NUMCSE.search(ln)
        ncand_m = _RE_NUMCAND.search(ln)
        seq_m = _RE_SEQ.search(ln)
        mode_m = _RE_MODE.search(ln)
        features_m = _RE_FEATURES.search(ln)
        out.append({
            'index': int(idx_m.group(1)),
            'name': name_m.group(1),
            'perf': float(perf_m.group(1)),
            'num_cse': int(nc_m.group(1)) if nc_m else 0,
            'num_cand': int(ncand_m.group(1)) if ncand_m else 0,
            'seq': seq_m.group(1) if seq_m else '',
            'mode': mode_m.group(1) if mode_m else '',
            'features': features_m.group(1) if features_m else '',
        })
    p.wait(timeout=10)
    return out


TARGETS = re.compile(r'(MDLogicArray|MDMulMatrix|MDNDhrystone|BenchI\.NDhrystone|EMFloatClass)')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mch', default=r'C:\spmi\mch-tier1\staging\benchmarks.run_pgo.windows.x64.checked.tier1.mch')
    ap.add_argument('--scan-max', type=int, default=8000, help='Highest method index to scan')
    ap.add_argument('--labels', default=None, help='MCMC optimum labels JSON (optional)')
    ap.add_argument('--out', default=None, help='Write detailed comparison to file')
    args = ap.parse_args()

    print(f'Scanning 1..{args.scan_max} for benchstone matches...', flush=True)
    heur = run_range(args.mch, 1, args.scan_max)
    matches = [m for m in heur if TARGETS.search(m['name'])]
    print(f'  {len(matches)} matches')

    # Group by (name, mode) to keep only one representative per method + tier
    seen = {}
    for m in matches:
        key = (m['name'], m['mode'])
        # prefer the highest perfscore (i.e. hot Tier1-OSR) if there are dupes
        if key not in seen or m['perf'] > seen[key]['perf']:
            seen[key] = m
    matches = list(seen.values())
    print(f'  {len(matches)} unique after dedup')

    labels = {}
    if args.labels and os.path.exists(args.labels):
        with open(args.labels) as f:
            labels = json.load(f)
        print(f'  loaded {len(labels)} MCMC labels')

    # For each match, run imit @ 0.30 and 0.50 on that specific index
    lines = []
    print(f'\n{"idx":>5}  {"heur":>10} {"i030":>10} {"i050":>10} {"opt":>10}  '
          f'{"h_n":>3} {"030_n":>4} {"050_n":>4} {"opt_n":>4}  '
          f'{"030_d%":>6} {"050_d%":>6}  {"name":<80}  {"mode":<20}')
    for m in sorted(matches, key=lambda x: -x['perf']):
        idx = m['index']
        i030 = run_range(args.mch, idx, idx,
                          'JitCseImitation=1', 'JitCseImitationThreshold=0.30')
        i050 = run_range(args.mch, idx, idx,
                          'JitCseImitation=1', 'JitCseImitationThreshold=0.50')
        i030m = i030[0] if i030 else None
        i050m = i050[0] if i050 else None
        opt_perf = None
        opt_n = None
        opt_seq = None
        if str(idx) in labels:
            lbl = labels[str(idx)]
            opt_perf = lbl.get('optimal_perfscore')
            opt_n = len(lbl.get('optimal_subset', []))
            opt_seq = ','.join(str(s) for s in lbl.get('optimal_subset', []))
        d030 = (i030m['perf'] - m['perf']) / m['perf'] * 100 if i030m else None
        d050 = (i050m['perf'] - m['perf']) / m['perf'] * 100 if i050m else None

        row = (f"{idx:>5}  {m['perf']:>10.1f} "
               f"{(i030m['perf'] if i030m else 0):>10.1f} "
               f"{(i050m['perf'] if i050m else 0):>10.1f} "
               f"{(opt_perf if opt_perf else 0):>10.1f}  "
               f"{m['num_cse']:>3d} "
               f"{(i030m['num_cse'] if i030m else 0):>4d} "
               f"{(i050m['num_cse'] if i050m else 0):>4d} "
               f"{(opt_n if opt_n is not None else -1):>4d}  "
               f"{(d030 if d030 is not None else 0):>+6.2f} "
               f"{(d050 if d050 is not None else 0):>+6.2f}  "
               f"{m['name'][:80]:<80}  {m['mode']:<20}")
        print(row)
        lines.append({
            'index': idx,
            'name': m['name'],
            'mode': m['mode'],
            'heur_perf': m['perf'],
            'heur_num_cse': m['num_cse'],
            'heur_num_cand': m['num_cand'],
            'heur_seq': m['seq'],
            'i030_perf': i030m['perf'] if i030m else None,
            'i030_num_cse': i030m['num_cse'] if i030m else None,
            'i030_seq': i030m['seq'] if i030m else None,
            'i050_perf': i050m['perf'] if i050m else None,
            'i050_num_cse': i050m['num_cse'] if i050m else None,
            'i050_seq': i050m['seq'] if i050m else None,
            'opt_perf': opt_perf,
            'opt_n': opt_n,
            'opt_seq': opt_seq,
            'delta_030_pct': d030,
            'delta_050_pct': d050,
        })

    if args.out:
        with open(args.out, 'w') as f:
            json.dump(lines, f, indent=2)
        print(f'\nWrote {args.out}')

    # Summary
    print('\n' + '=' * 100)
    n_reg_030 = sum(1 for r in lines if r['delta_030_pct'] and r['delta_030_pct'] > 1)
    n_reg_050 = sum(1 for r in lines if r['delta_050_pct'] and r['delta_050_pct'] > 1)
    n_win_030 = sum(1 for r in lines if r['delta_030_pct'] and r['delta_030_pct'] < -1)
    n_win_050 = sum(1 for r in lines if r['delta_050_pct'] and r['delta_050_pct'] < -1)
    print(f'@0.30: {n_win_030} wins  {n_reg_030} regressions (>1%)')
    print(f'@0.50: {n_win_050} wins  {n_reg_050} regressions (>1%)')
    return 0

if __name__ == '__main__':
    sys.exit(main())
