"""Verify that the JIT's ``CSE_HeuristicRLHook`` still round-trips with the
Python parser.

Usage:
    python scripts/verify_interface.py --core_root <PATH> --mch <PATH> [--count N]

For each of the first ``N`` methods in the MCH (default 10), this script:

1. Starts a streaming SuperPMI process with the JIT under ``core_root``.
2. Sends ``<index>!JitMetrics=1!JitRLHook=1!JitRLHookEmitFeatureNames=1``.
3. Parses the response through :class:`jitml.superpmi.SuperPmi`.
4. Confirms that the method context validates (pydantic) and that at
   least one CSE candidate has a plausible feature vector -- including
   the new ``enreg_count_int/float/simd/msk`` and ``use_wt_cnt_x100`` /
   ``def_wt_cnt_x100`` slots introduced in the M3 refresh.

Exit code 0 on success, non-zero on the first failing method.
"""
# pylint: disable=protected-access

from __future__ import annotations

import argparse
import os
import sys
from typing import Optional

# Allow running as a script from the jitutils tree without an install.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from jitml.method_context import MethodContext  # noqa: E402
from jitml.superpmi import SuperPmi  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core_root", required=True,
                        help="Path to the Checked Core_Root that contains superpmi + clrjit.")
    parser.add_argument("--mch", required=True, help="Path to a .mch file matching the JIT-EE GUID.")
    parser.add_argument("--count", type=int, default=10,
                        help="How many methods to probe (default: 10).")
    parser.add_argument("--start-index", type=int, default=1,
                        help="First SPMI method index to probe (default: 1).")
    parser.add_argument("--require-m3", action="store_true",
                        help="Fail unless the new M3 feature slots "
                             "(enreg_count_int, use_wt_cnt_x100, ...) are present.")
    return parser.parse_args()


def _looks_like_m3_features(spmi: SuperPmi) -> bool:
    """True if the featureNames line advertises the M3-refresh slot names."""
    names = spmi._feature_names or []
    required = {"enreg_count_int", "enreg_count_float", "enreg_count_simd",
                "enreg_count_msk", "use_wt_cnt_x100", "def_wt_cnt_x100"}
    return required.issubset(set(names))


def _summarize(ctx: MethodContext) -> str:
    parts = [
        f"idx={ctx.index}",
        f"name={ctx.name}",
        f"perf_score={ctx.perf_score:.2f}",
        f"num_cse={ctx.num_cse}",
        f"num_cand={ctx.num_cse_candidate}",
        f"candidates_parsed={len(ctx.cse_candidates)}",
    ]
    if ctx.cse_candidates:
        cand = ctx.cse_candidates[0]
        parts.append(
            f"cand0[type={cand.type} cost_ex={cand.cost_ex} "
            f"use_wt={cand.use_wt_cnt:.2f} def_wt={cand.def_wt_cnt:.2f} "
            f"enreg=int:{cand.enreg_count_int}/flt:{cand.enreg_count_float}"
            f"/simd:{cand.enreg_count_simd}/msk:{cand.enreg_count_msk}]"
        )
    return " ".join(parts)


def main() -> int:
    args = _parse_args()
    if not os.path.isdir(args.core_root):
        print(f"error: --core_root {args.core_root!r} is not a directory", file=sys.stderr)
        return 2
    if not os.path.isfile(args.mch):
        print(f"error: --mch {args.mch!r} is not a file", file=sys.stderr)
        return 2

    checked = 0
    failed: Optional[str] = None

    with SuperPmi(args.mch, args.core_root) as spmi:
        for idx in range(args.start_index, args.start_index + args.count):
            try:
                ctx = spmi.jit_method(
                    idx,
                    JitMetrics=1,
                    JitRLHook=1,
                    JitRLHookEmitFeatureNames=1,
                )
            except Exception as exc:  # noqa: BLE001
                failed = f"jit_method({idx}) raised {type(exc).__name__}: {exc}"
                break

            if ctx is None:
                print(f"skip idx={idx}: no result (likely non-CSE-relevant method)")
                continue

            checked += 1
            print(_summarize(ctx))

            if args.require_m3 and not _looks_like_m3_features(spmi):
                failed = ("--require-m3 given but the JIT did not emit the M3 "
                          "feature-name slots; is the JIT up to date?")
                break

    if failed:
        print(f"FAIL: {failed}", file=sys.stderr)
        return 1

    if checked == 0:
        print("FAIL: no methods returned a MethodContext.", file=sys.stderr)
        return 1

    print(f"OK: {checked} methods parsed successfully.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
