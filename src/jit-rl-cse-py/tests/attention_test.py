"""Tests for AttentionOverCandidatesExtractor."""
# pylint: disable=protected-access

import os
import sys

import gymnasium as gym
import numpy as np
import pytest

sys.path.append(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))

torch = pytest.importorskip("torch")
_sb3 = pytest.importorskip("stable_baselines3")


def _dict_space(max_cse=16, per_cand=17, method_feats=5):
    return gym.spaces.Dict({
        "candidates": gym.spaces.Box(
            low=np.zeros((max_cse, per_cand), dtype=np.float32),
            high=np.ones((max_cse, per_cand), dtype=np.float32),
            dtype=np.float32,
        ),
        "method": gym.spaces.Box(
            low=np.zeros((method_feats,), dtype=np.float32),
            high=np.ones((method_feats,), dtype=np.float32),
            dtype=np.float32,
        ),
    })


def test_extractor_output_shape():
    from jitml.attention_policy import AttentionOverCandidatesExtractor

    space = _dict_space()
    extractor = AttentionOverCandidatesExtractor(space, features_dim=128, embed_dim=64, num_heads=4)

    batch = 3
    obs = {
        "candidates": torch.rand(batch, 16, 17),
        "method":     torch.rand(batch, 5),
    }
    out = extractor(obs)
    assert out.shape == (batch, 128)
    assert torch.all(torch.isfinite(out))


def test_extractor_is_permutation_equivariant_within_pool():
    """Because we mean-pool the per-candidate outputs of the attention
    layer, permuting the candidate dimension of the input should produce
    the same aggregated features (up to floating-point noise)."""
    from jitml.attention_policy import AttentionOverCandidatesExtractor

    space = _dict_space()
    extractor = AttentionOverCandidatesExtractor(space, features_dim=64, embed_dim=32, num_heads=4)
    extractor.eval()

    candidates = torch.rand(1, 16, 17)
    method = torch.rand(1, 5)
    baseline = extractor({"candidates": candidates, "method": method})

    perm = torch.randperm(16)
    shuffled = extractor({
        "candidates": candidates[:, perm, :],
        "method": method,
    })

    # Mean-pooling over the candidate axis makes the extractor
    # permutation-invariant up to numerical noise from the softmax
    # inside multi-head attention.
    assert torch.allclose(baseline, shuffled, atol=1e-4), \
        f"max diff {(baseline - shuffled).abs().max().item()}"


def test_extractor_rejects_non_dict_space():
    from jitml.attention_policy import AttentionOverCandidatesExtractor

    flat = gym.spaces.Box(low=np.zeros(10, dtype=np.float32),
                          high=np.ones(10, dtype=np.float32),
                          dtype=np.float32)
    with pytest.raises(TypeError):
        AttentionOverCandidatesExtractor(flat)


def test_extractor_rejects_bad_head_count():
    from jitml.attention_policy import AttentionOverCandidatesExtractor

    space = _dict_space()
    with pytest.raises(ValueError):
        AttentionOverCandidatesExtractor(space, features_dim=64, embed_dim=64, num_heads=7)
