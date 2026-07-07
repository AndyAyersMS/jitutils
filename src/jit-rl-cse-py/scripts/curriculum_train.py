"""Curriculum-training variant of smoke_train.py for Phase-3 of the
beat-baseline campaign.

Design: PPO with SB3 defaults, same Dict observation + attention +
normalization stack as Phase-1 / Phase-2, but with a scheduled expansion
of the candidate-count pool during training:

  * stage 0 (0-25% of budget):   tier 1 methods only  (1-3 candidates)
  * stage 1 (25-50% of budget):  tier 1 + 2           (1-6)
  * stage 2 (50-75% of budget):  tier 1 + 2 + 3       (1-10)
  * stage 3 (75-100% of budget): all tiers            (1-16)

Implementation: no gym-Wrapper needed. A ``CurriculumCallback`` mutates
``env.methods`` at the tier-transition step thresholds; ``__select_method``
does ``np.random.choice(self.methods)`` so the change takes effect on
the very next episode. Works for both single-process and vec-env because
the callback iterates the wrapped envs.

Rationale (Phase-3 hypothesis): starting on easy methods lets the policy
discover simple rules ("apply the highest-weight CSE") before it sees
harder methods where those rules have exceptions. Should reduce the
regression tail more than it improves the geomean, per the Phase-0
diagnostic prediction.

Usage:
    python scripts/curriculum_train.py \\
        --core_root <CR> --mch <MCH> --output_dir <OUT> \\
        --iterations 500000 --num_methods 400 --scan_limit 12000 \\
        --normalize-features --attention
"""
# pylint: disable=protected-access

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from jitml.method_context import MethodContext  # noqa: E402
from jitml.superpmi import MethodKind, SuperPmi, SuperPmiCache, SuperPmiContext  # noqa: E402
from jitml.constants import is_acceptable_for_cse, split_for_cse, curriculum_buckets  # noqa: E402

# Reuse the picking / cache-prime helpers from smoke_train.
from smoke_train import _pick_methods, _prime_cache  # noqa: E402


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core_root", required=True)
    parser.add_argument("--mch", required=True)
    parser.add_argument("--output_dir", required=True)
    parser.add_argument("--iterations", type=int, default=500_000)
    parser.add_argument("--num_methods", type=int, default=400)
    parser.add_argument("--scan_limit", type=int, default=12_000)
    parser.add_argument("--algorithm", default="PPO", choices=("PPO", "A2C"))
    parser.add_argument("--parallel", type=int, default=None)
    parser.add_argument("--normalize-features", action="store_true")
    parser.add_argument("--attention", action="store_true")
    parser.add_argument("--stages", type=int, default=4,
                        help="Number of curriculum stages (default 4: tier 1, 1+2, 1+2+3, all).")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    print(f"[1/6] scanning up to {args.scan_limit} methods for {args.num_methods} "
          f"CSE-eligible candidates (stratified)...")
    t0 = time.time()
    with SuperPmi(args.mch, args.core_root) as spmi:
        picked = _pick_methods(spmi, args.scan_limit, args.num_methods, stratified=True)
    print(f"      picked {len(picked)} methods in {time.time()-t0:.1f}s")

    if len(picked) < 4 * args.stages:
        print(f"FAIL: only found {len(picked)} methods, insufficient for {args.stages} tiers.",
              file=sys.stderr)
        return 1

    print("[2/6] priming heuristic baseline for the picked methods...")
    t0 = time.time()
    heuristics: List[MethodContext] = []
    with SuperPmi(args.mch, args.core_root) as spmi:
        for m in picked:
            h = spmi.jit_method(m.index, JitMetrics=1)
            if h is not None:
                heuristics.append(h)
    print(f"      {len(heuristics)} heuristics collected in {time.time()-t0:.1f}s")

    print("[3/6] priming per-mch cache JSON...")
    _prime_cache(args.mch, args.core_root, picked, heuristics)

    print(f"[4/6] partitioning picked methods into {args.stages} curriculum tiers...")
    # Bucket picked methods by candidate count.
    tiers = curriculum_buckets(picked)
    tier_ids = [[m.index for m in t] for t in tiers]
    print(f"      tier sizes: {[len(t) for t in tier_ids]}")

    # Build the cumulative training pool per stage. Stage k = union of
    # tiers[0..k]. Guarantees monotonically expanding pool.
    stage_pools: List[List[int]] = []
    cum: List[int] = []
    for t in tier_ids:
        cum = cum + t
        stage_pools.append(list(cum))
    # Trim to args.stages if fewer tiers were populated.
    if len(stage_pools) < args.stages:
        stage_pools = stage_pools + [stage_pools[-1]] * (args.stages - len(stage_pools))
    stage_pools = stage_pools[:args.stages]
    for i, p in enumerate(stage_pools):
        print(f"      stage {i}: {len(p)} methods "
              f"(candidate ranges through tier {min(i, len(tier_ids)-1)})")

    if not stage_pools[0]:
        print("FAIL: stage 0 has no methods; curriculum can't start.", file=sys.stderr)
        return 1

    print("[5/6] constructing JitCseEnv + PPO with curriculum callback...")
    from jitml import JitCseEnv, JitCseModel  # lazy-imports torch/SB3
    from jitml import NormalizeFeaturesWrapper
    from stable_baselines3.common.callbacks import BaseCallback
    ctx = SuperPmiContext(core_root=args.core_root, mch=args.mch)

    class CurriculumCallback(BaseCallback):
        """Expand env.methods at stage-boundary step thresholds.

        The env we care about is JitCseEnv itself (SB3 may wrap it in
        Monitor / VecEnv), so we walk each env and set the unwrapped
        env's .methods attribute.
        """

        def __init__(self, stage_pools: List[List[int]], total_steps: int, verbose: int = 1):
            super().__init__(verbose)
            self._stage_pools = stage_pools
            self._thresholds = [
                int(i * total_steps / len(stage_pools)) for i in range(len(stage_pools) + 1)
            ]
            self._current_stage = -1

        def _current_desired_stage(self) -> int:
            step = self.model.num_timesteps
            for i, t in enumerate(self._thresholds[1:], start=1):
                if step < t:
                    return i - 1
            return len(self._stage_pools) - 1

        def _apply_stage(self, stage: int) -> None:
            pool = self._stage_pools[stage]
            envs = self._safe_iter_envs()
            for env in envs:
                unwrapped = getattr(env, "unwrapped", env)
                if hasattr(unwrapped, "methods"):
                    unwrapped.methods = list(pool)
            if self.verbose:
                print(f"      [curriculum] step={self.model.num_timesteps} "
                      f"stage {self._current_stage} -> {stage}, pool={len(pool)} methods",
                      flush=True)
            self._current_stage = stage

        def _safe_iter_envs(self):
            """Return the underlying training envs (handles VecEnv + single)."""
            vec_env = self.model.get_env()
            if vec_env is None:
                return []
            # SB3 vec envs have .envs (DummyVecEnv) or .remotes (SubprocVecEnv).
            envs = getattr(vec_env, "envs", None)
            if envs:
                return envs
            # SubprocVecEnv doesn't expose envs; the mutation would need
            # env_method calls. Falling back to that.
            if hasattr(vec_env, "env_method"):
                # This is a no-op here; SubprocVecEnv would need a custom
                # env_method target. In practice this script is used with
                # parallel=None (single-process DummyVecEnv), so this
                # branch is fine as a placeholder.
                pass
            return []

        def _on_training_start(self) -> None:  # type: ignore[override]
            self._apply_stage(0)

        def _on_step(self) -> bool:  # type: ignore[override]
            desired = self._current_desired_stage()
            if desired != self._current_stage:
                self._apply_stage(desired)
            return True

    def make_env():
        env = JitCseEnv(ctx, methods=list(stage_pools[0]))
        if args.normalize_features:
            env = NormalizeFeaturesWrapper(env)
        return env

    model = JitCseModel(args.algorithm, use_attention=args.attention, make_env=make_env)

    print(f"[6/6] training {args.algorithm} for {args.iterations} iters with "
          f"{len(stage_pools)}-stage curriculum...")
    t0 = time.time()

    # We need to inject a callback but ``JitCseModel.train`` doesn't
    # accept one directly. Reach into its plumbing.
    # The cleanest hook is to call SB3 ourselves; but to avoid duplicating
    # ``train()``'s save_path/callback wiring, we construct SB3 manually.
    from stable_baselines3 import PPO, A2C
    from stable_baselines3.common.callbacks import CallbackList

    env = model.make_env() if hasattr(model, "make_env") and callable(model.make_env) else make_env()
    if not env:
        env = make_env()

    Alg = PPO if args.algorithm == "PPO" else A2C
    policy = "MultiInputPolicy"

    from jitml.attention_policy import make_attention_policy_kwargs
    policy_kwargs = make_attention_policy_kwargs() if args.attention else None

    kwargs = dict(policy=policy, env=env, device="auto", verbose=0,
                  tensorboard_log=os.path.join(args.output_dir, "logs"))
    if args.attention:
        kwargs["policy_kwargs"] = policy_kwargs
    if Alg is PPO:
        kwargs["ent_coef"] = 0.01

    sb3_model = Alg(**kwargs)

    # LogCallback (from jitml.machine_learning) for best-reward snapshots
    from jitml.machine_learning import LogCallback
    logcb = LogCallback(sb3_model, args.output_dir)
    curcb = CurriculumCallback(stage_pools, args.iterations)
    cb = CallbackList([logcb, curcb])

    try:
        sb3_model.learn(total_timesteps=args.iterations, callback=cb, progress_bar=False)
        save_path = os.path.join(args.output_dir, args.algorithm.lower() + ".zip")
        sb3_model.save(save_path)
    finally:
        env.close()

    elapsed = time.time() - t0
    print(f"OK: {args.algorithm} + curriculum trained {args.iterations} iters "
          f"in {elapsed:.1f}s; model saved to {save_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
