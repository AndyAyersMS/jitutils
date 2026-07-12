"""Check whether regressions cluster on Tier1-OSR compile mode.

Uses `run_range` from dhrystone_deepdive.py to scan a range of methods
and compare heur vs imit@0.50, grouping by compile_mode.
"""
from __future__ import annotations
import argparse, os, sys, subprocess, re
from collections import defaultdict

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from dhrystone_deepdive import run_range, TARGETS


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--mch', default=r'C:\spmi\mch-tier1\staging\benchmarks.run_pgo.windows.x64.checked.tier1.mch')
    ap.add_argument('--start', type=int, default=1)
    ap.add_argument('--end', type=int, default=5000)
    ap.add_argument('--threshold', default='0.50')
    args = ap.parse_args()

    print(f'Running heur on {args.start}..{args.end}...', flush=True)
    heur = run_range(args.mch, args.start, args.end)
    heur_map = {m['index']: m for m in heur if m['num_cand'] > 0}
    print(f'  {len(heur_map)} methods with CSE candidates')

    print(f'Running imit@{args.threshold} on same range...', flush=True)
    imit = run_range(args.mch, args.start, args.end,
                     'JitCseImitation=1', f'JitCseImitationThreshold={args.threshold}')
    imit_map = {m['index']: m for m in imit if m['num_cand'] > 0}
    print(f'  {len(imit_map)} imit methods')

    # Compare
    by_mode = defaultdict(lambda: {'n': 0, 'wins': 0, 'losses': 0, 'total_h_perf': 0, 'total_i_perf': 0, 'sum_delta_pct': 0, 'max_regress': 0, 'max_regress_name': None})
    all_regressions = []
    for idx, h in heur_map.items():
        if idx not in imit_map:
            continue
        i = imit_map[idx]
        if h['perf'] <= 0:
            continue
        d = (i['perf'] - h['perf']) / h['perf'] * 100
        mode = h['mode']
        by_mode[mode]['n'] += 1
        by_mode[mode]['total_h_perf'] += h['perf']
        by_mode[mode]['total_i_perf'] += i['perf']
        by_mode[mode]['sum_delta_pct'] += d
        if d < -0.5:
            by_mode[mode]['wins'] += 1
        elif d > 0.5:
            by_mode[mode]['losses'] += 1
            all_regressions.append((idx, d, h['perf'], i['perf'], mode, h['name'], h['num_cse'], i['num_cse']))
        if d > by_mode[mode]['max_regress']:
            by_mode[mode]['max_regress'] = d
            by_mode[mode]['max_regress_name'] = h['name']

    print('\n' + '=' * 100)
    print(f'{"mode":<20} {"n":>6} {"wins":>6} {"losses":>6} {"mean_d%":>8} {"total_h":>12} {"total_i":>12} {"total_d%":>8} {"max_reg%":>8}  max_reg_method')
    print('-' * 130)
    for mode, s in sorted(by_mode.items(), key=lambda x: -x[1]['n']):
        mean_d = s['sum_delta_pct'] / s['n']
        total_d = (s['total_i_perf'] - s['total_h_perf']) / s['total_h_perf'] * 100
        print(f'{mode:<20} {s["n"]:>6d} {s["wins"]:>6d} {s["losses"]:>6d} '
              f'{mean_d:>+7.3f}% {s["total_h_perf"]:>12.0f} {s["total_i_perf"]:>12.0f} '
              f'{total_d:>+7.3f}% {s["max_regress"]:>+7.2f}%  {s["max_regress_name"]}')

    print('\nTop 20 regressions (by delta%):')
    print(f'{"idx":>6} {"delta%":>8} {"heur":>12} {"imit":>12} {"h_n":>3} {"i_n":>3} {"mode":<16} name')
    for r in sorted(all_regressions, key=lambda x: -x[1])[:20]:
        idx, d, hp, ip, mode, name, hn, in_ = r
        print(f'{idx:>6} {d:>+7.2f}% {hp:>12.0f} {ip:>12.0f} {hn:>3d} {in_:>3d} {mode:<16} {name[:80]}')

    print(f'\nTotal regressions >0.5%: {len(all_regressions)}')
    n_osr = sum(1 for r in all_regressions if 'OSR' in r[4])
    print(f'Regressions where mode contains "OSR": {n_osr} ({n_osr / max(1, len(all_regressions)) * 100:.1f}%)')

    # Perfscore-weighted regression
    total_h_reg = sum(r[2] for r in all_regressions)
    total_i_reg = sum(r[3] for r in all_regressions)
    print(f'Total regression perfscore: {total_h_reg:.0f} -> {total_i_reg:.0f} = {(total_i_reg - total_h_reg) / total_h_reg * 100:+.3f}%')
    osr_regs = [r for r in all_regressions if 'OSR' in r[4]]
    if osr_regs:
        total_h_osr = sum(r[2] for r in osr_regs)
        total_i_osr = sum(r[3] for r in osr_regs)
        print(f'OSR-only regression perfscore: {total_h_osr:.0f} -> {total_i_osr:.0f} = {(total_i_osr - total_h_osr) / total_h_osr * 100:+.3f}%')

    return 0

if __name__ == '__main__':
    sys.exit(main())
