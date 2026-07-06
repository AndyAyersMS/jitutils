#!/usr/bin/python
"""Optuna-driven PPO hyperparameter sweep for jit-rl-cse-py.

Sweeps ``learning_rate``, ``n_steps``, ``batch_size``, ``gae_lambda``,
``clip_range`` and the MlpPolicy hidden-layer sizes. Each trial trains
a PPO model for ``--iterations`` steps and scores it by mean
``(heuristic_score - final_score) / heuristic_score`` on the training
episodes reported by ``LogCallback`` (positive = better than heuristic).

Usage:
    python scripts/sweep.py \\
        --core_root <PATH> --mch <MCH> \\
        --n_trials 20 --iterations 30000 --num_methods 20

Trial results are written to a SQLite study in the output directory
(``sweep.db``) so a Ctrl-C interruption is resumable.

The primed-cache trick from ``smoke_train.py`` is reused so this does
not require a full-MCH SuperPmiCache build.

Requires ``optuna`` from the ``[tune]`` optional dependency group:
    pip install -e .[tune]
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from typing import List

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

# Delay optuna import until after argparse so --help works without the extra.


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--core_root", required=True)
    parser.add_argument("--mch", required=True)
    parser.add_argument("--output_dir", required=True,
                        help="Directory for the Optuna study + per-trial artifacts.")
    parser.add_argument("--n_trials", type=int, default=20)
    parser.add_argument("--iterations", type=int, default=30_000,
                        help="Timesteps per trial (default 30k).")
    parser.add_argument("--num_methods", type=int, default=20)
    parser.add_argument("--scan_limit", type=int, default=400)
    parser.add_argument("--study_name", default="cse_ppo_sweep")
    parser.add_argument("--sampler", default="tpe", choices=("tpe", "random"))
    return parser.parse_args()


def _prime(args: argparse.Namespace) -> tuple[list[int], list[int]]:
    """Reuse the smoke_train primed-cache flow so we don't build a
    full-MCH SuperPmiCache. Returns (train_ids, test_ids)."""
    # Import lazily so --help works without extras.
    from jitml.superpmi import MethodKind, SuperPmi, SuperPmiCache  # noqa: F401
    from jitml.constants import is_acceptable_for_cse
    from smoke_train import _pick_methods, _prime_cache  # type: ignore

    with SuperPmi(args.mch, args.core_root) as spmi:
        picked = _pick_methods(spmi, args.scan_limit, args.num_methods)

    heuristics = []
    with SuperPmi(args.mch, args.core_root) as spmi:
        for m in picked:
            h = spmi.jit_method(m.index, JitMetrics=1)
            if h is not None:
                heuristics.append(h)

    _prime_cache(args.mch, args.core_root, picked, heuristics)

    test, train = SuperPmiCache.get_test_train_methods(args.mch, args.core_root)
    return train, test


def _score_from_callback(model_trainer, model) -> float:
    """Pull the mean 'result_vs_heuristic' recorded by LogCallback."""
    # Access the callback via the model_trainer's internal handle.
    # If LogCallback is not present (e.g. DQN), fall back to model.num_timesteps.
    cb = getattr(model_trainer, "_last_callback", None)
    if cb is None:
        return 0.0
    stats = getattr(cb, "_result_vs_heuristic", None)
    if not stats:
        return 0.0
    import numpy as np
    return float(np.mean(stats))


def _objective(trial, args: argparse.Namespace, train_ids: List[int]):
    """One Optuna trial: train PPO and return the mean vs-heuristic gain."""
    from jitml import JitCseEnv, JitCseModel, NormalizeFeaturesWrapper
    from jitml.superpmi import SuperPmiContext
    from stable_baselines3 import PPO

    learning_rate = trial.suggest_float("learning_rate", 1e-5, 1e-3, log=True)
    n_steps       = trial.suggest_categorical("n_steps", [512, 1024, 2048])
    batch_size    = trial.suggest_categorical("batch_size", [32, 64, 128, 256])
    gae_lambda    = trial.suggest_float("gae_lambda", 0.9, 0.999)
    clip_range    = trial.suggest_float("clip_range", 0.1, 0.4)
    net_width     = trial.suggest_categorical("net_width", [64, 128, 256])
    net_depth     = trial.suggest_categorical("net_depth", [2, 3])
    ent_coef      = trial.suggest_float("ent_coef", 1e-3, 1e-1, log=True)

    trial_dir = os.path.join(args.output_dir, f"trial_{trial.number:03d}")
    os.makedirs(trial_dir, exist_ok=True)

    ctx = SuperPmiContext(core_root=args.core_root, mch=args.mch)

    def make_env():
        env = JitCseEnv(ctx, methods=train_ids)
        return NormalizeFeaturesWrapper(env)

    env = make_env()
    try:
        net_arch = [net_width] * net_depth
        policy_kwargs = {"net_arch": net_arch}
        model = PPO(
            "MlpPolicy",
            env,
            learning_rate=learning_rate,
            n_steps=n_steps,
            batch_size=batch_size,
            gae_lambda=gae_lambda,
            clip_range=clip_range,
            ent_coef=ent_coef,
            policy_kwargs=policy_kwargs,
            tensorboard_log=os.path.join(trial_dir, "tb"),
            verbose=0,
        )
        model.learn(args.iterations, progress_bar=False)
        model.save(os.path.join(trial_dir, "ppo.zip"))

        # Score by evaluating a few deterministic rollouts.
        return _evaluate(model, ctx, train_ids)

    finally:
        env.close()


def _evaluate(model, ctx, method_ids: List[int]) -> float:
    """Deterministic-rollout evaluation over ``method_ids``. Returns the
    mean (heuristic - final) / heuristic; higher is better."""
    from jitml import JitCseEnv
    import numpy as np

    scores: list[float] = []
    env = JitCseEnv(ctx, methods=method_ids)
    try:
        for _ in method_ids:
            obs, info = env.reset()
            terminated = truncated = False
            while not (terminated or truncated):
                action, _ = model.predict(obs, deterministic=True)
                obs, _, terminated, truncated, info = env.step(int(action))
            if terminated and 'final_score' in info and 'heuristic_score' in info:
                h = info['heuristic_score']
                f = info['final_score']
                if h > 0:
                    scores.append((h - f) / h)
    finally:
        env.close()

    return float(np.mean(scores)) if scores else 0.0


def main() -> int:
    args = _parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    try:
        import optuna
    except ImportError:
        print("error: optuna is required. Install with: pip install -e .[tune]", file=sys.stderr)
        return 2

    print(f"[1/3] priming per-mch cache from {args.num_methods} methods...")
    t0 = time.time()
    train_ids, test_ids = _prime(args)
    print(f"      train={len(train_ids)} test={len(test_ids)} in {time.time()-t0:.1f}s")
    if not train_ids:
        print("FAIL: empty training set", file=sys.stderr)
        return 1

    print(f"[2/3] running {args.n_trials} Optuna trials, {args.iterations} iters each...")
    storage = f"sqlite:///{os.path.join(args.output_dir, 'sweep.db').replace(os.sep, '/')}"
    sampler = optuna.samplers.TPESampler() if args.sampler == "tpe" else optuna.samplers.RandomSampler()
    study = optuna.create_study(direction="maximize", study_name=args.study_name,
                                storage=storage, load_if_exists=True, sampler=sampler)
    study.optimize(lambda t: _objective(t, args, train_ids),
                   n_trials=args.n_trials, show_progress_bar=False)

    print("[3/3] best trial:")
    best = study.best_trial
    print(f"  score: {best.value:+.5f} (mean pct-improvement vs heuristic)")
    for k, v in best.params.items():
        print(f"    {k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
