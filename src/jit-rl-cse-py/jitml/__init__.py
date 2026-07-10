"""JIT Machine Learning (JITML) is a Python library for the .Net JIT's reinforcement learning algorithms.

Top-level symbols are re-exported here via ``__getattr__``-based lazy loading
so that lightweight consumers (parsing / replay only) can ``import
jitml.superpmi`` without pulling in torch and Stable-Baselines3.
"""
from typing import TYPE_CHECKING

from .method_context import MethodContext, CseCandidate, JitType
from .superpmi import SuperPmiContext, SuperPmi, SuperPmiCache, MethodKind

# Symbols that require the heavy ML/RL dependency stack (gymnasium, torch,
# stable-baselines3, ...) are exposed lazily. Accessing them triggers the
# corresponding submodule import.
_LAZY_EXPORTS = {
    "JitCseEnv":                ("jitml.jit_cse",         "JitCseEnv"),
    "JitCseModel":              ("jitml.machine_learning","JitCseModel"),
    "OptimalCseWrapper":        ("jitml.wrappers",        "OptimalCseWrapper"),
    "NormalizeFeaturesWrapper": ("jitml.wrappers",        "NormalizeFeaturesWrapper"),
    "DeltaVsHeuristicRewardWrapper": ("jitml.wrappers",   "DeltaVsHeuristicRewardWrapper"),
    "HardStopRewardWrapper":    ("jitml.wrappers",        "HardStopRewardWrapper"),
    "AttentionOverCandidatesExtractor": ("jitml.attention_policy", "AttentionOverCandidatesExtractor"),
    "make_attention_policy_kwargs":     ("jitml.attention_policy", "make_attention_policy_kwargs"),
    "get_individual_cse_perf":  ("jitml.cse_decisions",   "get_individual_cse_perf"),
    "get_multi_cse_perf":       ("jitml.cse_decisions",   "get_multi_cse_perf"),
}

def __getattr__(name):
    entry = _LAZY_EXPORTS.get(name)
    if entry is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attr = entry
    from importlib import import_module
    return getattr(import_module(module_name), attr)


if TYPE_CHECKING:  # help static analyzers see the lazy exports
    from .jit_cse import JitCseEnv
    from .machine_learning import JitCseModel
    from .wrappers import OptimalCseWrapper, NormalizeFeaturesWrapper, DeltaVsHeuristicRewardWrapper, HardStopRewardWrapper
    from .attention_policy import AttentionOverCandidatesExtractor, make_attention_policy_kwargs
    from .cse_decisions import get_individual_cse_perf, get_multi_cse_perf


__all__ = [
    "SuperPmi",
    "SuperPmiCache",
    "SuperPmiContext",
    "MethodKind",
    "JitCseEnv",
    "JitCseModel",
    "MethodContext",
    "CseCandidate",
    "JitType",
    "OptimalCseWrapper",
    "NormalizeFeaturesWrapper",
    "DeltaVsHeuristicRewardWrapper",
    "HardStopRewardWrapper",
    "AttentionOverCandidatesExtractor",
    "make_attention_policy_kwargs",
    "get_individual_cse_perf",
    "get_multi_cse_perf",
]
