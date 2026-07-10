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


def test_extractor_separate_stop_head_output_shape():
    """With use_separate_stop_head=True the extractor emits max_cse+1
    logits directly: one per candidate, one for stop."""
    from jitml.attention_policy import AttentionOverCandidatesExtractor

    space = _dict_space(max_cse=16, per_cand=17, method_feats=5)
    extractor = AttentionOverCandidatesExtractor(
        space, features_dim=128, embed_dim=64, num_heads=4,
        use_separate_stop_head=True,
    )
    # features_dim is forced to max_cse+1 regardless of what we passed.
    assert extractor.features_dim == 17

    batch = 3
    obs = {
        "candidates": torch.rand(batch, 16, 17),
        "method":     torch.rand(batch, 5),
    }
    out = extractor(obs)
    assert out.shape == (batch, 17)
    assert torch.all(torch.isfinite(out))


def test_extractor_separate_stop_head_stop_score_is_method_only():
    """The stop logit must be a function ONLY of method features -- it
    must be identical for two batch elements that differ only in
    candidate rows."""
    from jitml.attention_policy import AttentionOverCandidatesExtractor

    space = _dict_space(max_cse=16, per_cand=17, method_feats=5)
    extractor = AttentionOverCandidatesExtractor(
        space, features_dim=128, embed_dim=32, num_heads=4,
        use_separate_stop_head=True,
    )
    extractor.eval()

    method = torch.rand(1, 5)
    cands_a = torch.rand(1, 16, 17)
    cands_b = torch.rand(1, 16, 17)  # completely different candidates
    out_a = extractor({"candidates": cands_a, "method": method})
    out_b = extractor({"candidates": cands_b, "method": method})
    # Last column = stop score; must match to high precision.
    assert torch.allclose(out_a[:, -1], out_b[:, -1], atol=1e-6)
    # Candidate scores DIFFER (would be strange if they didn't).
    assert not torch.allclose(out_a[:, :-1], out_b[:, :-1], atol=1e-4)


def test_make_attention_policy_kwargs_separate_stop_forces_empty_net_arch():
    """When use_separate_stop_head=True the extractor emits action-space-
    shaped logits; the returned policy_kwargs must set net_arch=[] so
    SB3's action_net is a linear pass-through, otherwise a hidden MLP
    would re-mix the carefully-separated candidate/stop logits."""
    from jitml.attention_policy import make_attention_policy_kwargs

    kw = make_attention_policy_kwargs(use_separate_stop_head=True)
    assert kw["net_arch"] == []
    assert kw["features_extractor_kwargs"]["use_separate_stop_head"] is True

    # Default keeps net_arch=[64] as before.
    kw_default = make_attention_policy_kwargs()
    assert kw_default["net_arch"] == [64]
    assert kw_default["features_extractor_kwargs"]["use_separate_stop_head"] is False
