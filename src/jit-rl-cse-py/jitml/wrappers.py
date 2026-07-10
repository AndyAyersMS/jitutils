"""A reward wrapper for the CSE environment that provides rewards based not just on the change in
performance score, but also on the quality of the CSE choices made."""

from typing import List, Optional, SupportsFloat
import gymnasium as gym
import numpy as np

from .method_context import MethodContext
from .jit_cse import JitCseEnv
from .superpmi import SuperPmi

OPTIMAL_BONUS = 0.05
SUBOPTIMAL_PENALTY = -0.01
NEUTRAL_PENALTY = -0.005

class OptimalCseWrapper(gym.Wrapper):
    """A wrapper for the CSE environment that provides rewards based not just on the change in
    performance score, but also on the quality of the CSE choices made."""
    def __init__(self, env : JitCseEnv):
        super().__init__(env)
        self.superpmi : SuperPmi = env.unwrapped.pmi_context.create_superpmi()
        self.superpmi.start()

    def step(self, action):
        """Steps the environment."""
        observation, reward, terminated, truncated, info = self.env.step(action)
        reward = self._get_reward(reward, info)
        return observation, reward, terminated, truncated, info

    def _get_reward(self, reward : SupportsFloat, info) -> SupportsFloat:
        # We'll let the parent class handle the reward in these cases.
        if info['truncated'] or not info['action_is_valid']:
            return reward

        m_idx = info['method_index']
        current = info['current']
        previous = info['previous']
        previous_score = previous.perf_score

        # Did we choose to end optimization?
        if info['action'] is None:
            all_cses = self._get_all_cses(m_idx, previous, None)
            best_perf_score = min(all_cses, key=lambda x: x.perf_score).perf_score if all_cses else np.inf

            if not np.isclose(best_perf_score, previous_score) and best_perf_score < previous_score:
                reward += SUBOPTIMAL_PENALTY

        # Otherwise we chose a CSE
        else:
            # We apply a tiny penalty for choosing a CSE that matches the previous score.  Choosing a CSE that
            # doesn't change the score still has a cost, but we don't want this penalty to be so high that the
            # agent avoids making choices.
            if np.isclose(current.perf_score, previous_score):
                reward += NEUTRAL_PENALTY

            # If we improved the performance score, give a bonus for choosing the best option out of all of them.
            elif current.perf_score < previous_score:
                # We improved the performance score, but was it the best choice?
                all_cses = self._get_all_cses(m_idx, previous, current.cses_chosen[-1])
                best_perf_score = min(all_cses, key=lambda x: x.perf_score).perf_score if all_cses else np.inf
                if np.isclose(best_perf_score, current.perf_score) or current.perf_score < best_perf_score:
                    reward += OPTIMAL_BONUS

        return reward

    def _get_all_cses(self, m_idx, previous : MethodContext, selected : Optional[int]) -> List[MethodContext]:
        # If we aren't given a current method, then no CSEs were applied.
        assert selected not in previous.cses_chosen

        all_cses = [self.superpmi.jit_method(m_idx, JitMetrics=1, JitRLHook=1,
                                                 JitRLHookCSEDecisions=previous.cses_chosen + [x.index])
                    for x in previous.cse_candidates
                    if x.index != selected and x.can_apply]

        all_cses = [x for x in all_cses if x is not None]
        return all_cses


class NormalizeFeaturesWrapper(gym.ObservationWrapper):
    """Normalize each observation column by its declared feature category.

    Reads the ``PER_CANDIDATE_SCHEMA`` and ``METHOD_SCHEMA`` from
    :mod:`jitml.jit_cse` to decide the per-column transform:

    * ``FEATURE_KIND_BOOL`` / ``FEATURE_KIND_ONEHOT``: identity
      (already in ``{0, 1}``).
    * ``FEATURE_KIND_COUNT``: ``log1p`` (compresses multi-order-of-
      magnitude counts like ``use_wt_cnt_x100`` into a small range).
    * ``FEATURE_KIND_LOG_X1000``: divide by 1000 (the JIT emits
      ``deMinimusAdj + log(max(1e-3, wt))`` scaled by 1000; dividing
      recovers the raw log value, typically 0..14).
    * ``FEATURE_KIND_RATIO_X1000``: divide by 1000 (the JIT emits a
      normalized ratio scaled by 1000; recovers [0, 1]).
    * ``FEATURE_KIND_ENUM_SMALL``: divide by 2 (small integer bucket
      in ``{0, 1, 2}``).

    Supports both the Dict observation space (candidates + method
    channels) currently produced by :class:`JitCseEnv` and the older
    flat Box observation space, in case a wrapper stack undoes the
    Dict grouping. The flat path preserves the legacy positional
    "everything after ``containable`` is a count" rule so pre-Tier-1
    smoke scripts keep working.
    """

    def __init__(self, env: JitCseEnv):
        super().__init__(env)

        # Lazy import to avoid a jit_cse<->wrappers circular import at
        # module import time.
        from .jit_cse import (
            PER_CANDIDATE_SCHEMA, METHOD_SCHEMA,
            FEATURE_KIND_BOOL, FEATURE_KIND_ONEHOT,
            FEATURE_KIND_COUNT, FEATURE_KIND_LOG_X1000,
            FEATURE_KIND_RATIO_X1000, FEATURE_KIND_ENUM_SMALL,
            _CODE_OPT_KIND_DIVISOR,
        )

        space = env.observation_space

        def _masks(schema):
            """Return (log1p_mask, scale_divisor) where log1p_mask is a
            bool ndarray for columns that get ``log1p``, and scale_divisor
            is a float ndarray giving the constant divisor for all
            columns (1.0 for identity/log1p columns; positive value for
            LOG_X1000/RATIO_X1000/ENUM_SMALL). The two are combined at
            observation time as ``log1p(max(0, x))`` where log1p_mask
            is set, else ``x / scale_divisor``."""
            n = len(schema)
            log1p_mask = np.zeros(n, dtype=bool)
            scale_divisor = np.ones(n, dtype=np.float32)
            for i, (_name, kind) in enumerate(schema):
                if kind == FEATURE_KIND_COUNT:
                    log1p_mask[i] = True
                elif kind == FEATURE_KIND_LOG_X1000:
                    scale_divisor[i] = 1000.0
                elif kind == FEATURE_KIND_RATIO_X1000:
                    scale_divisor[i] = 1000.0
                elif kind == FEATURE_KIND_ENUM_SMALL:
                    scale_divisor[i] = _CODE_OPT_KIND_DIVISOR
                elif kind in (FEATURE_KIND_BOOL, FEATURE_KIND_ONEHOT):
                    pass  # identity
                else:
                    raise ValueError(f"Unknown feature kind {kind!r} at slot {i}")
            return log1p_mask, scale_divisor

        if isinstance(space, gym.spaces.Dict):
            self._is_dict = True
            self._cand_log1p, self._cand_scale = _masks(PER_CANDIDATE_SCHEMA)
            self._method_log1p, self._method_scale = _masks(METHOD_SCHEMA)

            cand_space = space.spaces["candidates"]
            method_space = space.spaces["method"]
            dtype = cand_space.dtype
            high_c = cand_space.high.copy()
            high_c[:, self._cand_log1p] = np.array(20.0, dtype=dtype)  # log1p(~5e8) ~ 20
            high_m = method_space.high.copy()
            high_m[self._method_log1p] = np.array(20.0, dtype=dtype)
            self.observation_space = gym.spaces.Dict({
                "candidates": gym.spaces.Box(low=cand_space.low, high=high_c, dtype=dtype),
                "method":     gym.spaces.Box(low=method_space.low, high=high_m, dtype=dtype),
            })
        else:
            # Legacy flat-observation path. Preserve the pre-Tier-1
            # "everything after ``containable`` is a count" rule -- this
            # branch is only reached by legacy smoke scripts that stack
            # wrappers such that the Dict grouping was flattened.
            unwrapped = env.unwrapped
            columns = list(unwrapped.observation_columns)
            count_start = columns.index("containable") + 1
            mask = np.zeros(len(columns), dtype=bool)
            mask[count_start:] = True
            self._is_dict = False
            self._log1p_mask = mask

            dtype = space.dtype
            low = space.low.copy()
            high = space.high.copy()
            high[:, mask] = np.array(20.0, dtype=dtype)
            self.observation_space = gym.spaces.Box(low=low, high=high, dtype=dtype)

    def observation(self, observation):
        """Transforms the observation in place-safe."""
        if self._is_dict:
            dtype = self.observation_space.spaces["candidates"].dtype
            cand = np.asarray(observation["candidates"], dtype=dtype).copy()
            method = np.asarray(observation["method"], dtype=dtype).copy()

            # Divide by per-column scale (1.0 for identity, 1000.0 for
            # log_x1000/ratio_x1000, 2.0 for enum_small). Applied to
            # every column; count columns then get log1p on top of the
            # (no-op) divide-by-1.0.
            cand /= self._cand_scale
            method /= self._method_scale

            cand[:, self._cand_log1p] = np.log1p(np.maximum(cand[:, self._cand_log1p], 0.0))
            method[self._method_log1p] = np.log1p(np.maximum(method[self._method_log1p], 0.0))
            return {"candidates": cand, "method": method}

        out = np.asarray(observation, dtype=self.observation_space.dtype).copy()
        out[:, self._log1p_mask] = np.log1p(np.maximum(out[:, self._log1p_mask], 0.0))
        return out


class HardStopRewardWrapper(gym.Wrapper):
    """Reward-shaping wrapper for the "compulsive firing on A_nothing" pattern.

    Diagnosis: on test methods where the JIT's default heuristic decides to
    do nothing ("A_nothing" bucket, heur_score == no_cse_score), our
    attention-based policy trained with per-step delta-vs-previous reward
    still fires on 100% of them, costing >1% per method. The per-step
    reward has an asymmetry: applying the FIRST CSE often gives a small
    positive reward (the "hit and run" pattern), while overshoot only
    shows up as a per-step negative later. The policy learns "fire once
    and stop" as a modal strategy, which is wrong on the modal test A_nothing
    method.

    This wrapper replaces the per-step reward with a pure episode-end
    signal that directly aligns with the eval metric::

        reward = 0                                     for all non-terminal steps
        reward = scale * (heur - final) / heur         if final <= heur (improvement)
        reward = -asym_penalty * (final - heur) / heur if final >  heur (regression)

    With ``asym_penalty > scale`` (default 2×), the policy is discouraged
    from taking any action whose expected value straddles the heuristic —
    aligning training reward with the actual "beat heuristic" objective.

    Notes:
    * Stops on step 0 (no CSEs applied) get reward = 0 (same as heuristic).
      Under the previous per-step reward this was competitive with "fire
      once and hope"; under this wrapper the "hope" arm now has a strictly
      negative expected value whenever the applied CSE has a real chance
      of overshooting, so the policy should learn to stop.
    * Invalid/truncated episodes bypass the shaping (they never terminate
      cleanly, so ``final_score`` is unset).
    """

    def __init__(self, env: JitCseEnv, scale: float = 1.0, asym_penalty: float = 2.0):
        super().__init__(env)
        self._scale = float(scale)
        self._asym = float(asym_penalty)

    def step(self, action):
        observation, _base_reward, terminated, truncated, info = self.env.step(action)
        if not terminated:
            return observation, 0.0, terminated, truncated, info

        if 'final_score' not in info or 'heuristic_score' not in info:
            return observation, 0.0, terminated, truncated, info

        heur = info['heuristic_score']
        final = info['final_score']
        if heur <= 0:
            return observation, 0.0, terminated, truncated, info

        delta = (heur - final) / heur
        if delta >= 0:
            reward = self._scale * delta
        else:
            reward = self._asym * delta
        return observation, float(reward), terminated, truncated, info


class DeltaVsHeuristicRewardWrapper(gym.Wrapper):
    """Reward-shaping wrapper: give the agent a per-episode bonus based on
    how it performs relative to the JIT's built-in heuristic.

    Rewards each step normally (via the base env), then when the episode
    terminates adds a shaping term::

        (heuristic_score - final_score) / heuristic_score

    so improvements over the heuristic give a positive shaping term and
    regressions give a negative one. This is a much cheaper reward
    signal than :class:`OptimalCseWrapper` because it does not require
    re-JITting with every candidate CSE at every step.
    """

    def __init__(self, env: JitCseEnv, scale: float = 1.0):
        super().__init__(env)
        self._scale = float(scale)

    def step(self, action):
        observation, reward, terminated, truncated, info = self.env.step(action)
        if terminated and 'final_score' in info and 'heuristic_score' in info:
            heuristic = info['heuristic_score']
            final     = info['final_score']
            if heuristic > 0:
                # Positive when the model beats the heuristic.
                reward += self._scale * (heuristic - final) / heuristic
        return observation, reward, terminated, truncated, info


__all__ = [
    NormalizeFeaturesWrapper.__name__,
    OptimalCseWrapper.__name__,
    DeltaVsHeuristicRewardWrapper.__name__,
    HardStopRewardWrapper.__name__,
]

