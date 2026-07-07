"""A wrapper around the CSE_Candidate and MethodContext classes.  CseCandidate mirrors code in
src/coreclr/jit/optcse.cpp."""

from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

class JitType(Enum):
    """The type of a CSE candidate.  Mirrors CSE_HeuristicRLHook's enum."""
    OTHER : int = 0
    INT : int = 1
    LONG : int = 2
    FLOAT : int = 3
    DOUBLE : int = 4
    STRUCT : int = 5
    SIMD : int = 6

class CseCandidate(BaseModel):
    """A CSE candidate.  Mirrors CSE_Candidate features in CSE_HeuristicRLHook.cpp."""
    index : int
    applied : Optional[bool] = False
    viable : bool
    live_across_call : bool
    const : bool
    shared_const : bool
    make_cse : bool
    has_call : bool
    # ``containable`` is a coarse whitelist of GT_ADD/GT_NOT/GT_MUL/GT_LSH that
    # tries to signal "this expression can be folded into a downstream
    # containment slot (e.g. LEA) on x86/x64" -- not a precise containment
    # query. Treat as a hint, not a fact.
    containable : bool
    type : int
    cost_ex : int
    cost_sz : int
    use_count : int
    def_count : int
    # Weighted use/def counts are emitted as fixed-point ints at 100x
    # resolution (JIT weight_t is a double). Divide by 100.0 to recover
    # the real weight. Older JIT builds emit truncating ``use_wt_cnt`` /
    # ``def_wt_cnt`` int values instead; both are accepted for
    # backwards-compat and the effective value is exposed via the
    # ``use_wt_cnt`` / ``def_wt_cnt`` properties below.
    use_wt_cnt_x100 : int = 0
    def_wt_cnt_x100 : int = 0
    use_wt_cnt_legacy : Optional[int] = Field(default=None, alias="use_wt_cnt")
    def_wt_cnt_legacy : Optional[int] = Field(default=None, alias="def_wt_cnt")
    distinct_locals : int
    local_occurrences : int
    bb_count : int
    block_spread : int
    # Enregisterable local counts split by register class. Prior to
    # PR https://github.com/dotnet/runtime/pull/<TBD> these were a single
    # ``enreg_count`` field that lumped SIMD/mask registers under the
    # integer budget. Keep the legacy field as an optional int for
    # forward/backward compatibility with older JIT builds that only
    # emit one aggregate slot; new code should use the per-class fields.
    enreg_count_int   : int = 0
    enreg_count_float : int = 0
    enreg_count_simd  : int = 0
    enreg_count_msk   : int = 0
    enreg_count       : Optional[int] = None

    # Tier 1-2 features exposed by the JIT alongside the existing 22.
    # All default to 0 so cached JSON produced by older JIT builds still
    # loads. Newly-primed caches will populate them.
    #
    # * ``log_use_wt_x1000`` / ``log_def_wt_x1000``: weighted use/def
    #   counts on a log scale (deMinimusAdj + log(max(1e-3, wt))), x1000
    #   fixed-point. Non-negative. Recover as
    #   ``log_use_wt_x1000 / 1000.0`` which is ``log(max(1e-3, wt)/1e-3)``.
    # * ``const_and_live`` / ``const_and_min_cost`` / ``min_cost_and_live``
    #   / ``containable_and_low_cost``: joint booleans that the JIT's
    #   parameterized heuristic feature vector uses.
    # * ``live_across_call_lsra``: a strictly-more-precise version of
    #   ``live_across_call`` that walks the blocks between the CSE's
    #   min/max postorder positions and checks BBF_HAS_CALL.
    # * ``block_spread_x1000_per_bb``: ``block_spread`` normalized by
    #   ``bb_count``, at x1000 fixed-point (0..1000). Removes the "large
    #   vs small method" scale difference that raw ``block_spread``
    #   carries.
    log_use_wt_x1000            : int  = 0
    log_def_wt_x1000            : int  = 0
    const_and_live              : bool = False
    const_and_min_cost          : bool = False
    min_cost_and_live           : bool = False
    containable_and_low_cost    : bool = False
    live_across_call_lsra       : bool = False
    block_spread_x1000_per_bb   : int  = 0

    model_config = ConfigDict(populate_by_name=True)

    @property
    def use_wt_cnt(self) -> float:
        """Effective weighted use count as a float (recovers precision from x100 fixed-point)."""
        if self.use_wt_cnt_x100:
            return self.use_wt_cnt_x100 / 100.0
        return float(self.use_wt_cnt_legacy or 0)

    @property
    def def_wt_cnt(self) -> float:
        """Effective weighted def count as a float (recovers precision from x100 fixed-point)."""
        if self.def_wt_cnt_x100:
            return self.def_wt_cnt_x100 / 100.0
        return float(self.def_wt_cnt_legacy or 0)

    @field_validator('applied', 'viable', 'live_across_call', 'const', 'shared_const', 'make_cse', 'has_call',
                     'containable', 'const_and_live', 'const_and_min_cost', 'min_cost_and_live',
                     'containable_and_low_cost', 'live_across_call_lsra', mode='before')
    @classmethod
    def validate_bool(cls, v):
        """Validates that the value is a boolean or is a 0 or 1."""
        if isinstance(v, int) and v in [0, 1]:
            return bool(v)

        if isinstance(v, bool):
            return v

        raise ValidationError(f"Value must be either 1, 0, or a boolean, got {v}")

    @property
    def can_apply(self):
        """Returns True if the candidate is viable and not applied."""
        return self.viable and not self.applied

class MethodContext(BaseModel):
    """A superpmi method context."""
    index : int
    name : str
    hash : str
    total_bytes : int
    prolog_size : int
    instruction_count : int
    perf_score : float
    bytes_allocated : int
    num_cse : int
    num_cse_candidate : int
    # Optional: not emitted by CSE_HeuristicRLHook::DumpMetrics.
    heuristic : str = ""
    cses_chosen : List[int] = []
    cse_candidates : List[CseCandidate] = []
    # Method-level features surfaced by CSE_HeuristicRLHook via a new
    # ``method,<v1>,<v2>,...`` line. All default to 0 so older cached
    # JSON produced by pre-Tier-1 JIT builds still loads. See
    # ``CSE_HeuristicRLHook::s_methodFeatureNames`` for the ordering.
    #
    # * ``aggressive_ref_cnt_x1000`` / ``moderate_ref_cnt_x1000``: the
    #   promotion cutoffs the hand-tuned heuristic uses, at x1000
    #   fixed-point. Recover as ``value / 1000.0``.
    # * ``large_frame`` / ``huge_frame``: frame-size class flags.
    # * ``code_opt_kind``: 0/1/2 = BLENDED/SMALL/FAST from the JIT's
    #   Compiler::codeOptimize enum.
    aggressive_ref_cnt_x1000 : int  = 0
    moderate_ref_cnt_x1000   : int  = 0
    large_frame              : bool = False
    huge_frame               : bool = False
    code_opt_kind            : int  = 0

    def __str__(self):
        return f"{self.index}: {self.name}"

    # validate that perf_score is never negative:
    @field_validator('perf_score', mode='before')
    @classmethod
    def _validate_perf_score(cls, v):
        if v < 0:
            raise ValueError("perf_score must not be negative")
        return v

    @field_validator('large_frame', 'huge_frame', mode='before')
    @classmethod
    def _validate_frame_bool(cls, v):
        if isinstance(v, bool):
            return v
        if isinstance(v, int) and v in (0, 1):
            return bool(v)
        raise ValueError(f"Value must be either 1, 0, or a boolean, got {v}")

class CSEDecision(BaseModel):
    """A common format for storing the outcome of choosing a specific CSE decision."""
    method : MethodContext
    heuristic_perfscore : float
    no_cse_perfscore : float
    cse_perfscore : List[float | None]

__all__ = [
    CseCandidate.__name__,
    MethodContext.__name__,
    JitType.__name__
]
