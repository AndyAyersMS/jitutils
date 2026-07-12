"""For each hot Regex method, dump disasm under v10 and v11 imit configs
and report whether the assembly is bit-identical.
"""
import subprocess, os, hashlib, sys

SUPERPMI = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\superpmi.exe'
V10 = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v10.dll'
V11 = r'C:\repos\runtime4\artifacts\bin\coreclr\windows.x64.Checked\clrjit_v11.dll'
MCH = r'C:\spmi\mch-tier1\staging\benchmarks.run_pgo.windows.x64.checked.tier1.mch'


def dump_asm(jit, mid, imit, threshold):
    args = [SUPERPMI, jit, MCH, '-v', 'q', '-c', str(mid),
            '-jitoption', 'JitDisasm=*']
    if imit:
        args += ['-jitoption', 'JitCseImitation=1',
                 '-jitoption', f'JitCseImitationThreshold={threshold}']
    r = subprocess.run(args, capture_output=True, timeout=30)
    return r.stdout  # bytes


def digest(b):
    return hashlib.sha256(b).hexdigest()[:16]


def main():
    hot_mids = [
        (8708, 'RegexCache:GetOrAdd', 'Tier1'),
        (8712, 'RegexCache:Get', 'Tier1'),
        (9487, 'RegexCache:Add', 'Tier1'),
        (2318, 'Regex:.ctor', 'Tier1'),
        (10384, 'Regex:.ctor (clone)', 'Tier1'),
        (12355, 'RegexRunner:InitializeForScan', 'Tier1'),
        (15821, 'Regex:ScanInternal', 'Tier1'),
        (15822, 'RegexInterpreter:Scan', 'Tier1'),
        (12365, 'Regex:Count', 'Tier1'),
        (12366, 'Regex:RunAllMatchesWithCallback', 'Tier1'),
        (6248, 'Regex:Count', 'Tier1'),
        (6249, 'Regex:RunAllMatchesWithCallback', 'Tier1'),
    ]
    print(f'{"mid":>6} {"mode":<10} {"name":<40} {"heur10":<20} {"heur11":<20} {"v10i":<20} {"v11i":<20} {"heur10=heur11":<15} {"v10i=v11i":<10} {"heur=v10i":<10} {"heur=v11i":<10}')
    for mid, name, mode in hot_mids:
        # Two heur runs: one with v10 dll, one with v11 dll (should be identical if imit isn't invoked)
        heur10 = dump_asm(V10, mid, imit=False, threshold=None)
        heur11 = dump_asm(V11, mid, imit=False, threshold=None)
        v10i = dump_asm(V10, mid, imit=True, threshold='0.50')
        v11i = dump_asm(V11, mid, imit=True, threshold='0.30')
        # Strip everything before the actual method's disasm
        # The disasm usually starts with '; Assembly listing for method ...'
        # Concat everything for now.
        d_h10 = digest(heur10)
        d_h11 = digest(heur11)
        d_v10 = digest(v10i)
        d_v11 = digest(v11i)
        print(f'{mid:>6} {mode:<10} {name:<40} {d_h10:<20} {d_h11:<20} {d_v10:<20} {d_v11:<20} {str(d_h10==d_h11):<15} {str(d_v10==d_v11):<10} {str(d_h10==d_v10):<10} {str(d_h10==d_v11):<10}')


if __name__ == '__main__':
    main()
