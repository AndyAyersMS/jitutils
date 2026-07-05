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
    parser._process = None        # type: ignore[attr-defined]
    parser._feature_names = None  # type: ignore[attr-defined]
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

RLHOOK_NO_FEATURES_NO_DECISIONS = (
    "; Total bytes of code 42, prolog size 4, PerfScore 12.50, instruction count 8, "
    "allocated bytes for code 42, num cse 0 num cand 2 "
    "features #0,1,1,0,0,0,0,0,0,1,1,1,1,10,10,1,1,1,0,0 "
    "features #1,1,0,0,0,0,0,0,0,1,1,1,1,10,10,1,1,1,0,0 "
    "spmi index 4321 (MethodHash=cafebabe) for method Foo:Baz():int (Tier1)"
)

RLHOOK_WITH_FEATURE_NAMES_AND_SEQ = (
    "; Total bytes of code 42, prolog size 4, PerfScore 12.50, instruction count 8, "
    "allocated bytes for code 42, num cse 1 num cand 2 "
    "featureNames type,viable,live_across_call,const,shared_const,make_cse,has_call,"
    "containable,cost_ex,cost_sz,use_count,def_count,use_wt_cnt,def_wt_cnt,"
    "distinct_locals,local_occurrences,bb_count,block_spread,enreg_count "
    "features #0,1,1,0,0,0,0,0,0,1,1,1,1,10,10,1,1,1,0,0 "
    "features #1,1,0,0,0,0,0,0,0,1,1,1,1,10,10,1,1,1,0,0 "
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
    ctx = parser._parse_method_context(RLHOOK_NO_FEATURES_NO_DECISIONS)
    # No heuristic name is emitted by CSE_HeuristicRLHook::DumpMetrics.
    assert ctx.heuristic == ""
    assert ctx.cses_chosen == []
    # Without a preceding featureNames line, we cannot decode candidates.
    assert ctx.cse_candidates == []


def test_parses_rlhook_with_featurenames_and_seq():
    parser = _new_parser()
    ctx = parser._parse_method_context(RLHOOK_WITH_FEATURE_NAMES_AND_SEQ)
    assert ctx.heuristic == ""
    assert ctx.cses_chosen == [1]
    assert len(ctx.cse_candidates) == 2
    cand0, cand1 = ctx.cse_candidates
    assert cand0.index == 0
    assert cand0.type == 1
    assert cand0.viable is True
    assert cand0.applied is False
    assert cand1.index == 1
    assert cand1.applied is True  # index 1 appears in `seq 1`


def test_feature_names_are_learned_and_cached():
    parser = _new_parser()
    # First call: emits featureNames, so we learn them.
    parser._parse_method_context(RLHOOK_WITH_FEATURE_NAMES_AND_SEQ)
    assert parser._feature_names is not None
    assert parser._feature_names[0] == "id"
    assert "type" in parser._feature_names
    assert "enreg_count" in parser._feature_names

    # Second call: no featureNames in line, but we still decode candidates
    # using the cached names.
    ctx = parser._parse_method_context(RLHOOK_NO_FEATURES_NO_DECISIONS)
    assert len(ctx.cse_candidates) == 2


def test_extract_heuristic_name_helper():
    # Direct unit test of the helper.
    extract = SuperPmi._extract_heuristic_name
    assert extract(STANDARD_LINE) == "Standard CSE Heuristic"
    assert extract(RLHOOK_NO_FEATURES_NO_DECISIONS) == ""
    assert extract(RLHOOK_WITH_FEATURE_NAMES_AND_SEQ) == ""

    # Multi-word heuristic names must be preserved intact.
    line = (
        "num cand 3 Aggressive Balanced CSE Heuristic "
        "spmi index 1 (MethodHash=0) for method X:Y():int (Tier1)"
    )
    assert extract(line) == "Aggressive Balanced CSE Heuristic"

    # No heuristic name and only spmi index following.
    line = "num cand 0 spmi index 5 (MethodHash=0) for method X:Y():int (Tier1)"
    assert extract(line) == ""
