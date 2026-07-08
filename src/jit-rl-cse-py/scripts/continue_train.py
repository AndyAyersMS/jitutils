"""Resume PPO training from a previously-saved ppo.zip.

The training env is reconstructed from the primed SuperPmiCache JSONs
(no re-scanning of the MCH; ``smoke_train.py`` already wrote them).
The saved model's optimizer / running mean statistics are preserved so
this continues where the previous run left off (rather than starting
fresh with the previous run's final weights).

Example -- extend A2 by another 500k iters::

    python scripts/continue_train.py \\
        --core_root <CoreRoot> \\
        --mch C:\\spmi\\mch-tier1\\train_big.mch \\
        --input-model <A2>/ppo.zip \\
        --output_dir <A2_ext> \\
        --iterations 500000
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

# Make jitml importable when running from repo root without pip install.
REPO_ROOT = str(Path(__file__).resolve().parent.parent)
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from jitml.superpmi import SuperPmiCache, SuperPmiContext  # noqa: E402


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True,
                   help="MCH used for the original training run (needed to "
                        "locate the primed SuperPmiCache JSONs).")
    p.add_argument("--input-model", required=True,
                   help="Path to the previous run's ppo.zip.")
    p.add_argument("--output_dir", required=True,
                   help="New output dir. Fresh TB logs will be written under "
                        "<output_dir>/logs so the continuation shows as a new "
                        "run in TensorBoard.")
    p.add_argument("--iterations", type=int, default=500_000,
                   help="Additional PPO iterations to run (default 500k).")
    p.add_argument("--algorithm", default="PPO", choices=("PPO",),
                   help="Only PPO continuation is supported today.")
    p.add_argument("--normalize-features", action="store_true",
                   help="Wrap env with NormalizeFeaturesWrapper. MUST match the "
                        "original run.")
    return p.parse_args()


def main() -> int:
    args = _parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    if not os.path.exists(args.input_model):
        print(f"ERROR: input model {args.input_model} not found", file=sys.stderr)
        return 2

    print(f"[1/4] loading train IDs from primed SuperPmiCache for {args.mch}...")
    _, train_ids = SuperPmiCache.get_test_train_methods(args.mch, args.core_root)
    if not train_ids:
        print("FAIL: no training IDs found in primed cache. Run smoke_train.py first.",
              file=sys.stderr)
        return 1
    print(f"      {len(train_ids)} training methods: {train_ids[:10]}...")

    print("[2/4] constructing env (matching original training config)...")
    from jitml import JitCseEnv, NormalizeFeaturesWrapper  # lazy torch/SB3 import
    from jitml.machine_learning import LogCallback
    from stable_baselines3 import PPO

    ctx = SuperPmiContext(core_root=args.core_root, mch=args.mch)
    env = JitCseEnv(ctx, train_ids)
    if args.normalize_features:
        env = NormalizeFeaturesWrapper(env)
        print("      + NormalizeFeaturesWrapper")

    print(f"[3/4] loading model from {args.input_model}")
    tb_log = os.path.join(args.output_dir, "logs")
    model = PPO.load(args.input_model, env=env, tensorboard_log=tb_log)
    print(f"      loaded model already trained for {model.num_timesteps} timesteps")

    print(f"[4/4] resuming PPO for {args.iterations} more iterations...")
    t0 = time.time()
    callback = LogCallback(model, args.output_dir)
    # reset_num_timesteps=False keeps the step counter monotone so the
    # TB scalars in <output_dir>/logs pick up numerically after the
    # original run.
    model.learn(args.iterations, progress_bar=False, callback=callback,
                reset_num_timesteps=False)
    elapsed = time.time() - t0

    save_path = os.path.join(args.output_dir, "ppo.zip")
    model.save(save_path)
    print(f"OK: extended by {args.iterations} iters in {elapsed:.1f}s; "
          f"saved to {save_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
