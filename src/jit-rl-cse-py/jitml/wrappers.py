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
    """Apply ``log1p`` to count-like features in the observation.

    Rationale: the raw features emitted by ``CSE_HeuristicRLHook`` mix
    boolean / one-hot signals (already in a small range) with count-like
    features (``use_wt_cnt_x100`` can reach 5-figure values,
    ``cost_ex`` can reach the hundreds, etc.) that span multiple orders
    of magnitude. Feeding them directly to a neural policy hurts
    training because gradients explode. Applying ``log1p`` compresses
    each count into a small range without dataset-specific statistics.

    Supports both the Dict observation space (candidates + method
    channels) currently produced by :class:`JitCseEnv` and the older
    flat Box observation space, in case a wrapper stack undoes the
    Dict grouping.
    """

    def __init__(self, env: JitCseEnv):
        super().__init__(env)

        unwrapped = env.unwrapped
        space = env.observation_space

        if isinstance(space, gym.spaces.Dict):
            # Build a per-channel log1p mask.
            per_cand_cols = list(unwrapped.per_candidate_columns)
            cand_mask = np.zeros(len(per_cand_cols), dtype=bool)
            cand_mask[per_cand_cols.index("containable") + 1:] = True
            self._is_dict = True
            self._cand_mask = cand_mask
            # All method-level features are counts.
            self._method_mask = np.ones(len(unwrapped.method_columns), dtype=bool)

            cand_space = space.spaces["candidates"]
            method_space = space.spaces["method"]
            dtype = cand_space.dtype
            high_c = cand_space.high.copy()
            high_c[:, cand_mask] = np.array(20.0, dtype=dtype)  # log1p(~5e8) ~ 20
            high_m = method_space.high.copy()
            high_m[self._method_mask] = np.array(20.0, dtype=dtype)
            self.observation_space = gym.spaces.Dict({
                "candidates": gym.spaces.Box(low=cand_space.low, high=high_c, dtype=dtype),
                "method":     gym.spaces.Box(low=method_space.low, high=high_m, dtype=dtype),
            })
        else:
            # Legacy flat-observation path.
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
            cand[:, self._cand_mask] = np.log1p(np.maximum(cand[:, self._cand_mask], 0.0))
            method[self._method_mask] = np.log1p(np.maximum(method[self._method_mask], 0.0))
            return {"candidates": cand, "method": method}

        out = np.asarray(observation, dtype=self.observation_space.dtype).copy()
        out[:, self._log1p_mask] = np.log1p(np.maximum(out[:, self._log1p_mask], 0.0))
        return out


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
]

