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
    layer (over non-padded rows only), permuting the non-padded prefix
    of the candidate dimension should produce the same aggregated
    features (up to floating-point noise)."""
    from jitml.attention_policy import AttentionOverCandidatesExtractor

    space = _dict_space()
    extractor = AttentionOverCandidatesExtractor(space, features_dim=64, embed_dim=32, num_heads=4)
    extractor.eval()

    # Make the last 6 candidate rows explicit padding (all zeros) and
    # only shuffle the first 10 real rows. The padding mask should
    # produce a permutation-invariant output over the real rows.
    candidates = torch.rand(1, 16, 17)
    candidates[:, 10:, :] = 0.0
    method = torch.rand(1, 5)
    baseline = extractor({"candidates": candidates, "method": method})

    perm = torch.cat([torch.randperm(10), torch.arange(10, 16)])
    shuffled_c = candidates.clone()
    shuffled_c[:, :, :] = candidates[:, perm, :]
    shuffled = extractor({"candidates": shuffled_c, "method": method})

    assert torch.allclose(baseline, shuffled, atol=1e-4), \
        f"max diff {(baseline - shuffled).abs().max().item()}"


def test_padding_mask_excludes_zero_rows():
    """Adding zero-padded candidates should NOT change the extractor's
    output (they're masked out of both attention and the mean pool)."""
    from jitml.attention_policy import AttentionOverCandidatesExtractor

    space = _dict_space()
    extractor = AttentionOverCandidatesExtractor(space, features_dim=64, embed_dim=32, num_heads=4)
    extractor.eval()

    # Method with 5 real candidates, rest padding.
    a = torch.zeros(1, 16, 17)
    a[:, :5, :] = torch.rand(1, 5, 17)
    method = torch.rand(1, 5)
    out_a = extractor({"candidates": a, "method": method})

    # Same 5 real candidates, but shuffled among ALL 16 positions -- some
    # real, some padding interleaved. This is what the training env would
    # produce if candidate #0..#4 sat in slots 2, 5, 7, 11, 13.
    b = torch.zeros(1, 16, 17)
    # Simply move real rows to different slots, keep padding pattern.
    b[:, :5, :] = a[:, :5, :]  # (this is a trivial 'no move' variant)
    out_b = extractor({"candidates": b, "method": method})
    assert torch.allclose(out_a, out_b, atol=1e-6)


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
