"""A gymnasium environment for training RL to optimize the .Net JIT's CSE usage."""

from typing import Any, Dict, List, Optional
import gymnasium as gym
import numpy as np

from .method_context import JitType, MethodContext
from .superpmi import MethodKind, SuperPmi, SuperPmiCache, SuperPmiContext
from .constants import (INVALID_ACTION_PENALTY, INVALID_ACTION_LIMIT, MAX_CSE, is_acceptable_for_cse)

# Per-column feature category tags used by ``NormalizeFeaturesWrapper``
# to decide how to preprocess each observation slot.
#
#   BOOL             -- already in {0, 1}, no transform.
#   ONEHOT           -- already in {0, 1}, no transform (type one-hot).
#   COUNT            -- raw non-negative count, apply ``log1p``.
#   LOG_X1000        -- already log-scaled x1000 fixed-point (JIT emits
#                       ``deMinimusAdj + log(max(1e-3, wt))`` * 1000).
#                       Divide by 1000 to recover the log value, no log1p.
#   RATIO_X1000      -- already a 0..1000 fixed-point ratio. Divide by
#                       1000 to recover [0, 1], no log1p.
#   ENUM_SMALL       -- small integer bucket in {0, 1, 2}. Divide by 2.
FEATURE_KIND_BOOL         = "bool"
FEATURE_KIND_ONEHOT       = "onehot"
FEATURE_KIND_COUNT        = "count"
FEATURE_KIND_LOG_X1000    = "log_x1000"
FEATURE_KIND_RATIO_X1000  = "ratio_x1000"
FEATURE_KIND_ENUM_SMALL   = "enum_small"

# Per-candidate columns: (name, kind). Ordering here defines the row
# ordering of the ``candidates`` channel of the Dict observation.
PER_CANDIDATE_SCHEMA = [
    # One-hot type expansion (JitType 1..6 -> 6 slots).
    *[(f"type_{JitType(i).name.lower()}", FEATURE_KIND_ONEHOT) for i in range(1, 7)],
    # Boolean features.
    ("can_apply",                FEATURE_KIND_BOOL),
    ("live_across_call",         FEATURE_KIND_BOOL),
    ("const",                    FEATURE_KIND_BOOL),
    ("shared_const",             FEATURE_KIND_BOOL),
    ("make_cse",                 FEATURE_KIND_BOOL),
    ("has_call",                 FEATURE_KIND_BOOL),
    ("containable",              FEATURE_KIND_BOOL),
    ("const_and_live",           FEATURE_KIND_BOOL),
    ("const_and_min_cost",       FEATURE_KIND_BOOL),
    ("min_cost_and_live",        FEATURE_KIND_BOOL),
    ("containable_and_low_cost", FEATURE_KIND_BOOL),
    ("live_across_call_lsra",    FEATURE_KIND_BOOL),
    # Already-normalized already-log-scaled or ratio features.
    ("log_use_wt_x1000",         FEATURE_KIND_LOG_X1000),
    ("log_def_wt_x1000",         FEATURE_KIND_LOG_X1000),
    # Multiplicative log-interaction features from the JIT's parameterized
    # heuristic (features[18], [19]): log(useCount*useWtCnt) and
    # log(numLocalOccurrences*useWtCnt). These are dynamic-pressure
    # proxies that a neural net can't easily synthesize from raw
    # use_count + log_use_wt.
    ("log_use_cnt_x_wt_x1000",   FEATURE_KIND_LOG_X1000),
    ("log_local_occ_x_wt_x1000", FEATURE_KIND_LOG_X1000),
    ("block_spread_x1000_per_bb", FEATURE_KIND_RATIO_X1000),
    # Raw counts (get log1p'd).
    ("cost_ex",                  FEATURE_KIND_COUNT),
    ("cost_sz",                  FEATURE_KIND_COUNT),
    ("use_count",                FEATURE_KIND_COUNT),
    ("def_count",                FEATURE_KIND_COUNT),
    ("use_wt_cnt_x100",          FEATURE_KIND_COUNT),
    ("def_wt_cnt_x100",          FEATURE_KIND_COUNT),
    ("distinct_locals",          FEATURE_KIND_COUNT),
    ("local_occurrences",        FEATURE_KIND_COUNT),
    ("block_spread",             FEATURE_KIND_COUNT),
]

# Method-level columns. bb_count and the per-class enreg counts are the
# original 5; the trailing five are Tier-1 additions; the last two are
# the sequence-aware additions (add_cse_count, spill_at_weight_x1000);
# the FINAL two are PGO availability signals so a unified model trained
# on mixed PGO / non-PGO methods can condition on weight-source.
METHOD_SCHEMA = [
    ("bb_count",                  FEATURE_KIND_COUNT),
    ("enreg_count_int",           FEATURE_KIND_COUNT),
    ("enreg_count_float",         FEATURE_KIND_COUNT),
    ("enreg_count_simd",          FEATURE_KIND_COUNT),
    ("enreg_count_msk",           FEATURE_KIND_COUNT),
    ("aggressive_ref_cnt_x1000",  FEATURE_KIND_COUNT),
    ("moderate_ref_cnt_x1000",    FEATURE_KIND_COUNT),
    ("large_frame",               FEATURE_KIND_BOOL),
    ("huge_frame",                FEATURE_KIND_BOOL),
    ("code_opt_kind",             FEATURE_KIND_ENUM_SMALL),
    # Sequence-aware additions. add_cse_count is a raw sequence index
    # (0..MAX_CSE); log1p compresses it fine. spill_at_weight_x1000 is
    # already log-scaled x1000 fixed-point.
    ("add_cse_count",             FEATURE_KIND_COUNT),
    ("spill_at_weight_x1000",     FEATURE_KIND_LOG_X1000),
    # PGO availability signals. Both booleans emitted by the JIT for
    # every method. Default to 0 in older cached JSON that predates
    # the JitRLHookEmitEarly + PGO-signal patch.
    ("has_pgo_weights",           FEATURE_KIND_BOOL),
    ("has_pgo_dynamic",           FEATURE_KIND_BOOL),
    # ISA one-hot. Two booleans emitted by the JIT: is_x64, is_arm64.
    # Both zero for other targets (arm32, wasm, loongarch64, riscv64).
    # Default to 0 in cached JSON that predates the ISA-onehot patch.
    ("is_x64",                    FEATURE_KIND_BOOL),
    ("is_arm64",                  FEATURE_KIND_BOOL),
    # On-stack-replacement flag. True for Tier1-OSR methods (mid-loop
    # entry with locals inherited from the interpreter frame).
    # Default to 0 in cached JSON that predates the is_osr patch.
    ("is_osr",                    FEATURE_KIND_BOOL),
]

FEATURES_PER_CANDIDATE = len(PER_CANDIDATE_SCHEMA)   # 30
METHOD_LEVEL_FEATURES  = len(METHOD_SCHEMA)          # 10

# Legacy compat: some callers (notebooks, older scripts) still read
# ``FEATURES``. Keep it pointing at the per-candidate width.
FEATURES = FEATURES_PER_CANDIDATE

# Small-enum divisor (BLENDED=0, SMALL=1, FAST=2 -> divide by 2 to get
# [0, 1] range).
_CODE_OPT_KIND_DIVISOR = 2.0

# Scale up the reward to make it more meaningful.
REWARD_SCALE = 5.0

class JitCseEnv(gym.Env):
    """A gymnasium environment for CSE optimization selection in the JIT.

    Uses a Dict observation space with two channels:

    * ``candidates``: shape ``(MAX_CSE, FEATURES_PER_CANDIDATE)``. One
      row per (padded) candidate: one-hot type, booleans (base + Tier-1
      joint bools + LSRA-live), pre-normalized log-scale weights and
      ratio, and raw per-candidate counts.
    * ``method``: shape ``(METHOD_LEVEL_FEATURES,)``. Features that are
      constant across every candidate in the method: ``bb_count`` +
      per-register-class enreg counts + Tier-1 additions
      (``aggressive_ref_cnt_x1000``, ``moderate_ref_cnt_x1000``,
      ``large_frame``, ``huge_frame``, ``code_opt_kind``).

    Callers train against this env with an SB3 ``MultiInputPolicy``
    rather than ``MlpPolicy``; ``JitCseModel._create`` picks the right
    policy automatically based on the env's observation space.

    See :data:`PER_CANDIDATE_SCHEMA` and :data:`METHOD_SCHEMA` for the
    (name, kind) tuple that drives both the observation ordering and
    the ``NormalizeFeaturesWrapper`` normalization strategy.
    """

    per_candidate_columns : List[str] = [name for name, _ in PER_CANDIDATE_SCHEMA]
    method_columns        : List[str] = [name for name, _ in METHOD_SCHEMA]
    # Kept for anyone who still inspects a "flat" column list (e.g. legacy
    # notebooks). Equal to per_candidate_columns + method_columns.
    observation_columns   : List[str] = per_candidate_columns + method_columns

    def __init__(self, context : SuperPmiContext, methods : Optional[List[int]] = None, **kwargs):
        super().__init__(**kwargs)

        self.pmi_context = context
        self.methods = methods or context.training_methods
        if not self.methods:
            raise ValueError("No methods to train on.")

        self.__superpmi : SuperPmi = None
        self.__cache : SuperPmiCache = None
        self.action_space = gym.spaces.Discrete(MAX_CSE + 1)
        self.observation_space = gym.spaces.Dict({
            "candidates": gym.spaces.Box(
                low=np.zeros((MAX_CSE, FEATURES_PER_CANDIDATE), dtype=np.float32),
                high=np.ones((MAX_CSE, FEATURES_PER_CANDIDATE), dtype=np.float32),
                dtype=np.float32,
            ),
            "method": gym.spaces.Box(
                low=np.zeros((METHOD_LEVEL_FEATURES,), dtype=np.float32),
                high=np.ones((METHOD_LEVEL_FEATURES,), dtype=np.float32),
                dtype=np.float32,
            ),
        })

        self.last_info : Optional[Dict[str,object]] = None

    def __del__(self):
        self.close()

    def close(self):
        """Closes the environment and cleans up resources."""
        super().close()
        if self.__superpmi is not None:
            self.__superpmi.stop()
            self.__superpmi = None

    def reset(self, *, seed: int | None = None, options: dict[str, Any] | None = None):
        super().reset(seed=seed, options=options)
        self.last_info = None

        superpmi = self.__get_or_create_superpmi()

        failure_count = 0
        while True:
            index = self.__select_method()
            no_cse = self.__cache.jit_method(superpmi, index, MethodKind.NO_CSE)
            original_heuristic = self.__cache.jit_method(superpmi, index, MethodKind.HEURISTIC)
            if no_cse and original_heuristic:
                break

            failure_count += 1
            if failure_count > 512:
                raise ValueError("No valid methods found")

        observation = self.get_observation(no_cse)
        self.last_info = {
            'invalid_actions' : 0,
            'method_index' : index,
            'heuristic_method' : original_heuristic,
            'no_cse_method' : no_cse,
            'current' : no_cse,
            'total_reward' : 0.0,
            'observation' : observation,
            'action_is_valid' : None
        }

        return observation, self.last_info

    def step(self, action):
        # the last action is always to terminate
        if action == self.action_space.n - 1:
            action = None

        last_info = self.last_info
        if last_info is None:
            raise ValueError("Must call reset() before step()")

        info = last_info.copy()
        self.last_info = None

        # update action, ensure we have an up to date observation
        info['action'] = action
        del info['observation']

        # Note that we have not yet updated the info dictionary for previous and current, which means
        # info['current'] is the previous method at this point.  We do not update info's previous/current
        # until we are sure the method is JIT'ed successfully.
        previous = info['current']

        # Ensure the selected action is valid.
        info['action_is_valid'] = self._is_valid_action(action, previous)
        if info['action_is_valid']:
            current = self._jit_method_with_cleanup(info['method_index'], JitMetrics=1, JitRLHook=1,
                                    JitRLHookCSEDecisions=previous.cses_chosen + [action])

            if current is not None:
                observation = self.get_observation(current)
                truncated = False
                terminated = not current.cse_candidates or action is None
                reward = self.get_rewards(previous, current)

                info['previous'] = previous
                info['current'] = current

            else:
                # Don't set current or observation, as we should not be using them.
                observation = last_info['observation']
                truncated = True
                terminated = False
                reward = INVALID_ACTION_PENALTY

        else:
            # action was invalid
            info['invalid_actions'] += 1

            truncated = info['invalid_actions'] >= INVALID_ACTION_LIMIT
            terminated = False
            observation = last_info['observation']
            reward = INVALID_ACTION_PENALTY

        info['observation'] = observation
        info['total_reward'] += reward
        info['terminated'] = terminated
        info['truncated'] = truncated

        # These are reported only once, when the episode is done.
        if terminated:
            info['heuristic_score'] = info['heuristic_method'].perf_score
            info['no_cse_score'] = info['no_cse_method'].perf_score
            info['total_reward'] = info['total_reward']
            info['invalid_actions'] = info['invalid_actions']
            if 'current' in info:
                info['final_score'] = info['current'].perf_score

        self.last_info = info
        return observation, reward, terminated, truncated, info

    def get_rewards(self, prev_method : MethodContext, curr_method : MethodContext):
        """Returns the reward based on the change in performance score."""
        prev = prev_method.perf_score
        curr = curr_method.perf_score

        # should not happen
        if np.isclose(prev, 0.0):
            return 0.0

        return REWARD_SCALE * (prev - curr) / prev

    def _is_valid_action(self, action, method):
        # Stop ("None" action) is ALWAYS valid: the correct answer for a
        # non-trivial fraction of methods is to do zero CSEs (e.g. narrow
        # methods where any CSE hurts perf-score due to added spill/copy
        # cost). The previous behavior (require at least one CSE before
        # allowing terminate) systematically biased the policy toward
        # over-CSEing narrow methods -- diagnosed post-Campaign C when
        # 11/18 persistent worst-case eval methods were exactly this
        # pattern (heuristic did nothing, RL over-CSE'd).
        if action is None:
            return True

        candidate = method.cse_candidates[action] if action < len(method.cse_candidates) else None
        return candidate is not None and candidate.can_apply

    @classmethod
    def get_observation(cls, method : MethodContext, fill=True):
        """Builds the Dict observation for a method without normalizing.

        Returns a ``{'candidates': (MAX_CSE, FEATURES_PER_CANDIDATE),
        'method': (METHOD_LEVEL_FEATURES,)}`` numpy dict. Values are the
        raw JIT-emitted ints (as floats); ``NormalizeFeaturesWrapper``
        is responsible for applying the appropriate transform per
        column category (log1p for counts, /1000 for log-x1000 or
        ratio-x1000, /2 for the small code-opt-kind enum, identity for
        booleans and one-hot).

        The method-level channel holds features that are constant
        across every candidate of the method; they are read from the
        candidate list (bb_count, enreg counts) or the parent
        MethodContext (Tier-1 additions).
        """
        candidate_rows: List[List[float]] = []
        for cse in method.cse_candidates[:MAX_CSE]:
            row: List[float] = []

            # one-hot encode the type (JitType 1..6 -> six slots)
            one_hot = [0.0] * 6
            if 1 <= cse.type <= 6:
                one_hot[cse.type - 1] = 1.0
            row.extend(one_hot)

            # boolean features (base 7 + Tier-1 joints + LSRA-live)
            row.extend([
                float(cse.can_apply), float(cse.live_across_call), float(cse.const),
                float(cse.shared_const), float(cse.make_cse), float(cse.has_call),
                float(cse.containable),
                float(cse.const_and_live), float(cse.const_and_min_cost),
                float(cse.min_cost_and_live), float(cse.containable_and_low_cost),
                float(cse.live_across_call_lsra),
            ])

            # Already-normalized log-scale weights + interaction features + ratio.
            row.extend([
                float(cse.log_use_wt_x1000),
                float(cse.log_def_wt_x1000),
                float(cse.log_use_cnt_x_wt_x1000),
                float(cse.log_local_occ_x_wt_x1000),
                float(cse.block_spread_x1000_per_bb),
            ])

            # per-candidate scalar counts. The two weighted counts are
            # the JIT-emitted x100 fixed-point values; the observation
            # preserves that scale rather than dividing by 100 so the
            # wrapper can log1p them uniformly with the other counts.
            row.extend([
                float(cse.cost_ex), float(cse.cost_sz),
                float(cse.use_count), float(cse.def_count),
                float(cse.use_wt_cnt_x100), float(cse.def_wt_cnt_x100),
                float(cse.distinct_locals), float(cse.local_occurrences),
                float(cse.block_spread),
            ])

            candidate_rows.append(row)

        if fill:
            pad = [0.0] * FEATURES_PER_CANDIDATE
            while len(candidate_rows) < MAX_CSE:
                candidate_rows.append(pad)

        candidates = (np.vstack(candidate_rows) if candidate_rows
                      else np.zeros((MAX_CSE, FEATURES_PER_CANDIDATE))).astype(np.float32)

        # Method-level features: bb_count + per-class enreg counts +
        # Tier-1 additions. bb_count / enreg counts are per-candidate in
        # the JIT dump but identical across candidates; read from the
        # first candidate. The Tier-1 additions
        # (aggressive_ref_cnt / moderate_ref_cnt / *_frame /
        # code_opt_kind) live on MethodContext itself.
        if method.cse_candidates:
            first = method.cse_candidates[0]
            bb_count = first.bb_count
            e_int, e_flt, e_simd, e_msk = (
                first.enreg_count_int,
                first.enreg_count_float,
                first.enreg_count_simd,
                first.enreg_count_msk,
            )
        else:
            bb_count = 0
            e_int = e_flt = e_simd = e_msk = 0

        method_arr = np.array([
            bb_count, e_int, e_flt, e_simd, e_msk,
            method.aggressive_ref_cnt_x1000,
            method.moderate_ref_cnt_x1000,
            float(method.large_frame),
            float(method.huge_frame),
            method.code_opt_kind,
            method.add_cse_count,
            method.spill_at_weight_x1000,
            float(method.has_pgo_weights),
            float(method.has_pgo_dynamic),
            float(method.is_x64),
            float(method.is_arm64),
            float(method.is_osr),
        ], dtype=np.float32)

        return {"candidates": candidates, "method": method_arr}


    def _jit_method_with_cleanup(self, m_id, *args, **kwargs):
        """Jits a method, but if it fails, we remove it from future consideration.  Note that the
        SuperPmi class will retry before returning None, so we know this method is not going to work."""
        superpmi = self.__get_or_create_superpmi()

        result = superpmi.jit_method(m_id, retry=2, *args, **kwargs)
        if result is None:
            self.__remove_method(m_id)

        elif np.isclose(result.perf_score, 0.0):
            self.__remove_method(m_id)
            result = None

        return result

    def __select_method(self):
        if self.methods is None:
            superpmi = self.__get_or_create_superpmi()
            self.methods = [x.index for x in superpmi.enumerate_methods() if is_acceptable_for_cse(x)]

        return np.random.choice(self.methods)

    def __remove_method(self, index):
        if self.methods is None:
            return

        self.methods = [x for x in self.methods if x != index]

    def __get_or_create_superpmi(self):
        if self.__superpmi is None:
            self.__superpmi = self.pmi_context.create_superpmi()
            self.__cache = self.pmi_context.create_cache()
            self.__superpmi.start()

        return self.__superpmi

    def render(self) -> None:
        info = self.last_info
        if info is not None:
            print(f"{info['method_index']} heuristic_score: {info['heuristic_method'].perf_score} "
                  f"no_cse_score: {info['no_cse_method'].perf_score} choices:{info['current'].cses_chosen} "
                  f"invalid_count:{info['invalid_actions']} ({info['current'].name})")

__all__ = [JitCseEnv.__name__]
