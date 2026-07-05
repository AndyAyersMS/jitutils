"""Tests for JitCseEnv."""
# pylint: disable=all

from common import SuperPmiContextMock, METHOD_CONTEXTS
from jitml import JitCseEnv

def create_env():
    context = SuperPmiContextMock()
    return JitCseEnv(context, context.training_methods)

def test_observation_space():
    env = create_env()
    obs, _ = env.reset()
    env.observation_space.contains(obs)

    obs, _, _, _, _ = env.step(0)
    env.observation_space.contains(obs)

    obs, _, _, _, _ = env.step(1)
    env.observation_space.contains(obs)

    env.close()
