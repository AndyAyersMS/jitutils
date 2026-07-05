"""Common code for tests."""
# pylint: disable=all

import sys
import os
from typing import Iterable, List

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

from jitml import MethodContext, CseCandidate
from jitml.constants import MIN_CSE
from jitml.superpmi import MethodKind

def create_cses(n) -> List[CseCandidate]:
    cse_values = {
        "applied": False,
        "viable": True,
        "live_across_call": False,
        "const": False,
        "shared_const": False,
        "make_cse": False,
        "has_call": False,
        "containable": False,
        "type": 1,
        "cost_ex": 0,
        "cost_sz": 0,
        "use_count": 0,
        "def_count": 0,
        "use_wt_cnt": 0,
        "def_wt_cnt": 0,
        "distinct_locals": 0,
        "local_occurrences": 0,
        "bb_count": 0,
        "block_spread": 0,
        "enreg_count": 0
    }

    result = []
    for i in range(5):
        cse_values["index"] = i
        result.append(CseCandidate(**cse_values))

    return result

def create_method_contexts(n):
    result = []
    for i in range(5):
        result.append(MethodContext(index=i, name=f"method_{i}", hash=f"hash_{i}", total_bytes=0, prolog_size=0,
                                    instruction_count=0, perf_score=10.0, bytes_allocated=0, num_cse=0,
                                    num_cse_candidate=0, heuristic="heuristic", cses_chosen=[],
                                    cse_candidates=create_cses(MIN_CSE + i)))

    return result



METHOD_CONTEXTS = { x.index: x for x in create_method_contexts(5) }

class SuperPmiMock:
    def jit_method(self, m_id, retry=1, **kwargs):
        values = METHOD_CONTEXTS[m_id].model_dump()
        values['cse_candidates'] = create_cses(MIN_CSE + values['index'])

        if 'JitRLHookCSEDecisions' in kwargs:
            for idx in kwargs['JitRLHookCSEDecisions']:
                values['cse_candidates'][idx].applied = True
                even = idx % 2 == 0
                values['perf_score'] = values['perf_score'] + (-1 if even else 1)

        result = MethodContext(**values)
        return result

    def enumerate_methods(self) -> Iterable[MethodContext]:
        return METHOD_CONTEXTS.values()
    
    def start(self):
        pass

    def stop(self):
        pass

class SuperPmiCacheMock:
    def __init__(self, training_methods):
        self.training_methods = training_methods

    def jit_method(self, spmi, method_index : int, kind_or_cses : MethodKind | List[int]) -> MethodContext: 
        match kind_or_cses:
            case MethodKind.NO_CSE:
                return METHOD_CONTEXTS[method_index]
            case MethodKind.HEURISTIC:
                return spmi.jit_method(method_index, JitRLHookCSEDecisions=[2, 0])
            case list():
                return spmi.jit_method(method_index, JitRLHookCSEDecisions=kind_or_cses)
            case _:
                raise ValueError(f"Unknown kind {kind_or_cses}")

class SuperPmiContextMock:
    def __init__(self):
        self.training_methods = [x.index for x in METHOD_CONTEXTS.values()]

    def create_superpmi(self):
        return SuperPmiMock()
    
    def create_cache(self):
        return SuperPmiCacheMock(self.training_methods)
