"""Tests for the JitMetrics line parser in jitml.superpmi.SuperPmi.

These parse-only tests do not require a real SuperPMI binary or MCH file:
they exercise ``SuperPmi._parse_method_context`` directly against strings
representative of what today's JIT emits at
``src/coreclr/jit/codegencommon.cpp:2473``.
"""
# pylint: disable=protected-access

import os
import sys

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

# Import at module scope; the parser does not need superpmi/jit binaries to
# be present at construction time is not true, so we bypass __init__ in each
# test with SuperPmi.__new__.
from jitml.superpmi import SuperPmi  # noqa: E402


def _new_parser() -> SuperPmi:
    """Return a bare SuperPmi with only the parse-state fields initialized."""
    parser = SuperPmi.__new__(SuperPmi)
    parser._process = None               # type: ignore[attr-defined]
    parser._feature_names = None         # type: ignore[attr-defined]
    parser._method_feature_names = None  # type: ignore[attr-defined]
    return parser


# ---------------------------------------------------------------------------
# Sample lines (all lead with ';' in real JIT output; the parser accepts
# either form because the leading `;` and whitespace are ignored by the
# individual regexes).
# ---------------------------------------------------------------------------

STANDARD_LINE = (
    "; Total bytes of code 42, prolog size 4, PerfScore 12.50, instruction count 8, "
    "allocated bytes for code 42, num cse 1 num cand 2 Standard CSE Heuristic "
    "spmi index 1234 (MethodHash=deadbeef) for method Foo:Bar():int (Tier1)"
)

# 20-value feature payload = 1 (id) + 19 (legacy features); used to
# exercise the parser's tolerance for pre-M3 JIT builds that emit only a
# single lumped enreg_count.
RLHOOK_LEGACY_NO_FEATURENAMES = (
    "; Total bytes of code 42, prolog size 4, PerfScore 12.50, instruction count 8, "
    "allocated bytes for code 42, num cse 0 num cand 2 "
    "features #0,1,1,0,0,0,0,0,0,1,1,1,1,10,10,1,1,1,0,0 "
    "features #1,1,0,0,0,0,0,0,0,1,1,1,1,10,10,1,1,1,0,0 "
    "spmi index 4321 (MethodHash=cafebabe) for method Foo:Baz():int (Tier1)"
)

# 23-value feature payload = 1 (id) + 22 (M3 features: split enreg counts,
# and use_wt_cnt / def_wt_cnt scaled at 100x fixed-point precision).
RLHOOK_M3_WITH_FEATURE_NAMES_AND_SEQ = (
    "; Total bytes of code 42, prolog size 4, PerfScore 12.50, instruction count 8, "
    "allocated bytes for code 42, num cse 1 num cand 2 "
    "featureNames type,viable,live_across_call,const,shared_const,make_cse,has_call,"
    "containable,cost_ex,cost_sz,use_count,def_count,use_wt_cnt_x100,def_wt_cnt_x100,"
    "distinct_locals,local_occurrences,bb_count,block_spread,"
    "enreg_count_int,enreg_count_float,enreg_count_simd,enreg_count_msk "
    "features #0,1,1,0,0,0,0,0,0,1,1,1,1,125,50,1,1,1,0,3,1,0,0 "
    "features #1,1,0,0,0,0,0,0,0,1,1,1,1,125,50,1,1,1,0,3,1,0,0 "
    "seq 1 "
    "spmi index 4321 (MethodHash=cafebabe) for method Foo:Baz():int (Tier1)"
)


def test_parses_standard_heuristic():
    parser = _new_parser()
    ctx = parser._parse_method_context(STANDARD_LINE)
    assert ctx.index == 1234
    # The existing parser regex `for method ([^ ]+):` strips the trailing
    # return type by design; the captured name ends at the last colon-space.
    assert ctx.name == "Foo:Bar()"
    assert ctx.hash == "deadbeef"
    assert ctx.total_bytes == 42
    assert ctx.prolog_size == 4
    assert ctx.perf_score == 12.50
    assert ctx.bytes_allocated == 42
    assert ctx.num_cse == 1
    assert ctx.num_cse_candidate == 2
    # This is the key parser-drift fix: the heuristic name must not
    # swallow trailing metadata like `spmi index N` or `(MethodHash=...)`.
    assert ctx.heuristic == "Standard CSE Heuristic"
    assert ctx.cses_chosen == []
    assert ctx.cse_candidates == []


def test_parses_rlhook_no_featurenames_no_seq():
    parser = _new_parser()
    ctx = parser._parse_method_context(RLHOOK_LEGACY_NO_FEATURENAMES)
    # No heuristic name is emitted by CSE_HeuristicRLHook::DumpMetrics.
    assert ctx.heuristic == ""
    assert ctx.cses_chosen == []
    # Without a preceding featureNames line, we cannot decode candidates.
    assert ctx.cse_candidates == []


def test_parses_rlhook_with_featurenames_and_seq():
    parser = _new_parser()
    ctx = parser._parse_method_context(RLHOOK_M3_WITH_FEATURE_NAMES_AND_SEQ)
    assert ctx.heuristic == ""
    assert ctx.cses_chosen == [1]
    assert len(ctx.cse_candidates) == 2
    cand0, cand1 = ctx.cse_candidates
    assert cand0.index == 0
    assert cand0.type == 1
    assert cand0.viable is True
    assert cand0.applied is False
    # M3-format enreg counts land in the per-class fields, not the legacy slot.
    assert cand0.enreg_count_int   == 3
    assert cand0.enreg_count_float == 1
    assert cand0.enreg_count_simd  == 0
    assert cand0.enreg_count_msk   == 0
    assert cand0.enreg_count is None
    # M3-format x100 fixed-point weighted counts.
    assert cand0.use_wt_cnt_x100 == 125
    assert cand0.def_wt_cnt_x100 == 50
    assert cand0.use_wt_cnt_legacy is None
    assert cand0.def_wt_cnt_legacy is None
    # The .use_wt_cnt / .def_wt_cnt properties recover the true float weight.
    assert cand0.use_wt_cnt == 1.25
    assert cand0.def_wt_cnt == 0.50
    assert cand1.index == 1
    assert cand1.applied is True  # index 1 appears in `seq 1`


def test_feature_names_are_learned_and_cached():
    parser = _new_parser()
    # First call: emits M3-format featureNames, so we learn them.
    parser._parse_method_context(RLHOOK_M3_WITH_FEATURE_NAMES_AND_SEQ)
    assert parser._feature_names is not None
    assert parser._feature_names[0] == "id"
    assert "type" in parser._feature_names
    assert "enreg_count_int" in parser._feature_names
    assert "enreg_count_msk" in parser._feature_names

    # Second call: no featureNames in line, but we still decode candidates
    # using the cached names.
    ctx = parser._parse_method_context(RLHOOK_M3_WITH_FEATURE_NAMES_AND_SEQ)
    assert len(ctx.cse_candidates) == 2


def test_extract_heuristic_name_helper():
    # Direct unit test of the helper.
    extract = SuperPmi._extract_heuristic_name
    assert extract(STANDARD_LINE) == "Standard CSE Heuristic"
    assert extract(RLHOOK_LEGACY_NO_FEATURENAMES) == ""
    assert extract(RLHOOK_M3_WITH_FEATURE_NAMES_AND_SEQ) == ""

    # Multi-word heuristic names must be preserved intact.
    line = (
        "num cand 3 Aggressive Balanced CSE Heuristic "
        "spmi index 1 (MethodHash=0) for method X:Y():int (Tier1)"
    )
    assert extract(line) == "Aggressive Balanced CSE Heuristic"

    # No heuristic name and only spmi index following.
    line = "num cand 0 spmi index 5 (MethodHash=0) for method X:Y():int (Tier1)"
    assert extract(line) == ""


def test_legacy_enreg_count_field_still_accepted():
    """A legacy JIT that emits ``enreg_count`` (rather than the four split
    per-register-class fields) and truncating-int ``use_wt_cnt`` /
    ``def_wt_cnt`` (rather than x100 fixed-point) should still parse.
    Legacy values land in the compatibility fields and the effective
    weighted-count properties fall back to them."""
    line = (
        "; Total bytes of code 42, prolog size 4, PerfScore 12.50, instruction count 8, "
        "allocated bytes for code 42, num cse 0 num cand 1 "
        "featureNames type,viable,live_across_call,const,shared_const,make_cse,has_call,"
        "containable,cost_ex,cost_sz,use_count,def_count,use_wt_cnt,def_wt_cnt,"
        "distinct_locals,local_occurrences,bb_count,block_spread,enreg_count "
        "features #0,1,1,0,0,0,0,0,0,1,1,1,1,10,4,1,1,1,0,7 "
        "spmi index 42 (MethodHash=0) for method Foo:Bar():int (Tier1)"
    )
    parser = _new_parser()
    ctx = parser._parse_method_context(line)
    assert len(ctx.cse_candidates) == 1
    cand = ctx.cse_candidates[0]
    # Legacy enreg lump.
    assert cand.enreg_count == 7
    assert cand.enreg_count_int == 0
    assert cand.enreg_count_float == 0
    # Legacy truncating weighted counts.
    assert cand.use_wt_cnt_legacy == 10
    assert cand.def_wt_cnt_legacy == 4
    assert cand.use_wt_cnt_x100 == 0
    assert cand.def_wt_cnt_x100 == 0
    # Properties fall back to the legacy int values.
    assert cand.use_wt_cnt == 10.0
    assert cand.def_wt_cnt == 4.0


# 31-value feature payload = 1 (id) + 30 (Tier-1 features). Adds the
# 8 new per-candidate slots (log_use_wt_x1000, log_def_wt_x1000,
# 4 joint bools, live_across_call_lsra, block_spread_x1000_per_bb)
# and the new method-level line.
RLHOOK_TIER1_WITH_METHOD_LINE = (
    "; Total bytes of code 239, prolog size 32, PerfScore 148.00, instruction count 70, "
    "allocated bytes for code 239, num cse 0 num cand 2 "
    "featureNames type,viable,live_across_call,const,shared_const,make_cse,has_call,"
    "containable,cost_ex,cost_sz,use_count,def_count,use_wt_cnt_x100,def_wt_cnt_x100,"
    "distinct_locals,local_occurrences,bb_count,block_spread,"
    "enreg_count_int,enreg_count_float,enreg_count_simd,enreg_count_msk,"
    "log_use_wt_x1000,log_def_wt_x1000,const_and_live,const_and_min_cost,"
    "min_cost_and_live,containable_and_low_cost,live_across_call_lsra,"
    "block_spread_x1000_per_bb "
    "methodFeatureNames aggressive_ref_cnt_x1000,moderate_ref_cnt_x1000,large_frame,"
    "huge_frame,code_opt_kind "
    "method,50000,100000,0,0,0 "
    "features #1,2,1,1,1,0,0,0,0,3,10,1,1,40000,10000,0,0,7,2,10,0,0,0,"
    "12899,11513,1,0,0,0,1,286 "
    "features #2,2,1,1,0,0,0,0,0,2,3,1,1,40000,80000,1,1,7,1,10,0,0,0,"
    "12899,13592,0,0,1,0,1,143 "
    "spmi index 1 (MethodHash=df1777a5) for method System.AppContext:Setup(ptr,ptr,int,ptr) (FullOpts)"
)


def test_parses_tier1_line_with_method_features():
    """The Tier-1 JIT emits a `methodFeatureNames` header plus a `method`
    values line plus 30-value per-candidate feature vectors. All the new
    fields must decode into the pydantic model correctly."""
    parser = _new_parser()
    ctx = parser._parse_method_context(RLHOOK_TIER1_WITH_METHOD_LINE)

    # Method-level features (values captured from a real invocation --
    # 50/100 are the BB_UNITY_WEIGHT/2 and BB_UNITY_WEIGHT minimum floors).
    assert ctx.aggressive_ref_cnt_x1000 == 50000
    assert ctx.moderate_ref_cnt_x1000 == 100000
    assert ctx.large_frame is False
    assert ctx.huge_frame is False
    assert ctx.code_opt_kind == 0  # BLENDED_CODE

    # Per-candidate features: the 8 new ones must all decode.
    assert len(ctx.cse_candidates) == 2
    cand0 = ctx.cse_candidates[0]
    assert cand0.log_use_wt_x1000 == 12899
    assert cand0.log_def_wt_x1000 == 11513
    # (const=1, live=1) -> const_and_live=1; cost=3 -> not min_cost.
    assert cand0.const_and_live is True
    assert cand0.const_and_min_cost is False
    assert cand0.min_cost_and_live is False
    assert cand0.containable_and_low_cost is False
    assert cand0.live_across_call_lsra is True
    # block_spread=2, bb_count=7 -> round(2 * 1000 / 7) = 286
    assert cand0.block_spread_x1000_per_bb == 286

    cand1 = ctx.cse_candidates[1]
    # (const=1, cost=2 which is MIN_CSE_COST+1 -> not min_cost, but low_cost)
    # -> min_cost_and_live shows the JIT actually says 1 here (see raw dump);
    # trust the payload.
    assert cand1.min_cost_and_live is True


def test_method_feature_names_are_learned_and_cached():
    """The `methodFeatureNames` header should be captured the first time
    we see it, then reused on subsequent lines that only carry the
    `method,...` values."""
    parser = _new_parser()
    parser._parse_method_context(RLHOOK_TIER1_WITH_METHOD_LINE)
    assert parser._method_feature_names is not None
    assert "aggressive_ref_cnt_x1000" in parser._method_feature_names
    assert "code_opt_kind" in parser._method_feature_names

    # Second call reuses the cached names.
    ctx = parser._parse_method_context(RLHOOK_TIER1_WITH_METHOD_LINE)
    assert ctx.aggressive_ref_cnt_x1000 == 50000


def test_tier1_line_still_parses_without_method_line():
    """A JIT build that emits the new per-candidate features but not
    the `method,...` values line (e.g. mid-transition source tree)
    should still decode. Method-level fields fall back to defaults (0)."""
    # Same as RLHOOK_TIER1_WITH_METHOD_LINE but without the `method,...` chunk.
    line = RLHOOK_TIER1_WITH_METHOD_LINE.replace(
        "method,50000,100000,0,0,0 ", ""
    )
    parser = _new_parser()
    ctx = parser._parse_method_context(line)
    # Defaults preserve backward compat.
    assert ctx.aggressive_ref_cnt_x1000 == 0
    assert ctx.moderate_ref_cnt_x1000 == 0
    assert ctx.large_frame is False
    assert ctx.code_opt_kind == 0
    # Per-candidate features still decode.
    assert len(ctx.cse_candidates) == 2
    assert ctx.cse_candidates[0].log_use_wt_x1000 == 12899


def test_compile_mode_tag_extracted_when_present():
    """The trailing ``... (Tier1)`` marker on the SPMI line becomes
    ``MethodContext.compile_mode``. Empty when the marker is missing.
    """
    # STANDARD_LINE ends in ``(Tier1)`` -- should decode.
    parser = _new_parser()
    ctx = parser._parse_method_context(STANDARD_LINE)
    assert ctx.compile_mode == "Tier1"

    # A line with the newer FullOpts tag.
    parser = _new_parser()
    fullopts_line = STANDARD_LINE.replace("(Tier1)", "(FullOpts)")
    ctx = parser._parse_method_context(fullopts_line)
    assert ctx.compile_mode == "FullOpts"

    # Multi-word compile-mode tag ("Instrumented Tier1") -- must not be
    # truncated at whitespace inside the parens.
    parser = _new_parser()
    instr_line = STANDARD_LINE.replace("(Tier1)", "(Instrumented Tier1)")
    ctx = parser._parse_method_context(instr_line)
    assert ctx.compile_mode == "Instrumented Tier1"

    # Tier1-OSR (hyphenated tag).
    parser = _new_parser()
    osr_line = STANDARD_LINE.replace("(Tier1)", "(Tier1-OSR)")
    ctx = parser._parse_method_context(osr_line)
    assert ctx.compile_mode == "Tier1-OSR"

    # Line without a compile-mode marker: field defaults to empty.
    parser = _new_parser()
    no_tag_line = STANDARD_LINE.replace(" (Tier1)", "")
    ctx = parser._parse_method_context(no_tag_line)
    assert ctx.compile_mode == ""


def test_tier1_pgo_filter_helper():
    """``is_pgo_calibrated_tier1`` accepts regular Tier1 and Tier1-OSR
    only; everything else (Tier0, Instrumented Tier1, FullOpts,
    MinOpts, empty) is rejected. The user's chat 2026-07-07 explicitly
    excludes ``Instrumented Tier1`` because those methods are
    COLLECTING PGO data, not USING it, so their weights are still
    static estimates.
    """
    from jitml.constants import is_pgo_calibrated_tier1

    # Minimal MethodContext factory just for this filter test.
    def make(compile_mode: str):
        from jitml.method_context import MethodContext
        return MethodContext(
            index=1, name="X", hash="a", total_bytes=0, prolog_size=0,
            instruction_count=0, perf_score=1.0, bytes_allocated=0,
            num_cse=0, num_cse_candidate=0, compile_mode=compile_mode,
        )

    assert is_pgo_calibrated_tier1(make("Tier1")) is True
    assert is_pgo_calibrated_tier1(make("Tier1-OSR")) is True

    # Explicitly excluded compile modes.
    for excluded in ("Tier0", "Instrumented Tier0", "Instrumented Tier1",
                     "FullOpts", "MinOpts", "Tier0-FullOpts", ""):
        assert is_pgo_calibrated_tier1(make(excluded)) is False, \
            f"{excluded!r} must NOT pass the Tier1-PGO filter"
