"""Unit tests for CurriculumCallback in curriculum_train.py.

Doesn't require a real SPMI or JIT; verifies the step-threshold →
stage-index computation and the env-mutation dispatch across the SB3
wrapper stack.
"""
# pylint: disable=protected-access

import os
import sys
import types

import gymnasium as gym
import numpy as np
import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
# Also add the scripts dir so we can import curriculum_train as a module.
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.realpath(__file__))),
                                "scripts"))

torch = pytest.importorskip("torch")
sb3 = pytest.importorskip("stable_baselines3")


class _FakeInnerEnv:
    """Stands in for JitCseEnv.unwrapped -- exposes a mutable .methods list."""

    def __init__(self):
        self.methods = [-1]  # sentinel; callback should overwrite


class _FakeOuterEnv:
    """Stands in for the Monitor / wrapper layer -- has .unwrapped."""

    def __init__(self, inner):
        self.unwrapped = inner


class _FakeVecEnv:
    """Stands in for DummyVecEnv -- has .envs list."""

    def __init__(self, inner_envs):
        self.envs = inner_envs


class _FakeModel:
    """Stands in for the SB3 model -- has get_env()."""

    def __init__(self, vec_env):
        self._vec = vec_env
        self.num_timesteps = 0

    def get_env(self):
        return self._vec


def _make_callback(total_steps=1000, num_stages=4):
    from curriculum_train import main  # noqa: F401 -- import forces module load
    # Actually, CurriculumCallback is a nested class inside main(); reach for it
    # via the module's inspect-friendly path.
    import curriculum_train
    # The class is defined inside main(). Re-load main and grab it.
    src = open(curriculum_train.__file__, "r", encoding="utf-8").read()
    ns = {}
    # Execute just the CurriculumCallback definition. Extract the class block
    # from source using a lightweight regex.
    import re
    m = re.search(r"class CurriculumCallback\(BaseCallback\):.*?(?=\n    def make_env\()",
                  src, flags=re.DOTALL)
    assert m is not None, "could not locate CurriculumCallback class in curriculum_train.py"
    class_src = m.group(0)
    exec(  # noqa: S102 -- controlled test import of a known-good module
        "from stable_baselines3.common.callbacks import BaseCallback\n"
        "from typing import List\n"
        + class_src,
        ns,
    )
    Cb = ns["CurriculumCallback"]

    pools = [[1, 2, 3], [1, 2, 3, 4, 5], [1, 2, 3, 4, 5, 6, 7], list(range(1, 11))][:num_stages]
    inner = _FakeInnerEnv()
    outer = _FakeOuterEnv(inner)
    vec = _FakeVecEnv([outer])
    model = _FakeModel(vec)

    cb = Cb(pools, total_steps, verbose=0)
    # SB3 sets self.model on the callback via BaseCallback.init_callback; do
    # the same by hand.
    cb.model = model
    return cb, inner, pools


def test_stage_thresholds_match_evenly_divided_steps():
    cb, _, _ = _make_callback(total_steps=1000, num_stages=4)
    assert cb._thresholds == [0, 250, 500, 750, 1000]


def test_current_desired_stage_at_boundaries():
    cb, _, pools = _make_callback(total_steps=1000, num_stages=4)
    for step, expected in [
        (0, 0),
        (249, 0),
        (250, 1),
        (499, 1),
        (500, 2),
        (749, 2),
        (750, 3),
        (999, 3),
        (1_000_000, 3),  # far past total; clamps at last stage
    ]:
        cb.model.num_timesteps = step
        got = cb._current_desired_stage()
        assert got == expected, f"step={step} expected stage {expected} got {got}"


def test_on_training_start_applies_stage_0():
    cb, inner, pools = _make_callback(total_steps=1000, num_stages=4)
    assert inner.methods == [-1]  # sentinel
    cb._on_training_start()
    assert inner.methods == pools[0]


def test_on_step_advances_stages_at_boundaries():
    cb, inner, pools = _make_callback(total_steps=1000, num_stages=4)
    cb._on_training_start()  # stage 0
    assert inner.methods == pools[0]

    cb.model.num_timesteps = 100
    cb._on_step()
    assert inner.methods == pools[0], "should still be stage 0 before threshold 250"

    cb.model.num_timesteps = 250
    cb._on_step()
    assert inner.methods == pools[1]

    cb.model.num_timesteps = 500
    cb._on_step()
    assert inner.methods == pools[2]

    cb.model.num_timesteps = 750
    cb._on_step()
    assert inner.methods == pools[3]


def test_on_step_returns_true():
    cb, _, _ = _make_callback()
    cb.model.num_timesteps = 100
    assert cb._on_step() is True


def test_missing_get_env_is_tolerated():
    """A pathological case: model.get_env() returns None. Callback should
    not crash, just do nothing."""
    cb, _, pools = _make_callback()
    cb.model.get_env = lambda: None
    # Should not raise.
    cb._apply_stage(1)


def test_env_without_methods_is_tolerated():
    """If the underlying env doesn't have a .methods attribute, we skip it."""
    cb, inner, pools = _make_callback()
    outer_no_methods = types.SimpleNamespace(unwrapped=types.SimpleNamespace())
    cb.model.get_env = lambda: _FakeVecEnv([outer_no_methods, _FakeOuterEnv(inner)])
    cb._apply_stage(2)
    # inner had methods attribute so should be set to pools[2]
    assert inner.methods == pools[2]
