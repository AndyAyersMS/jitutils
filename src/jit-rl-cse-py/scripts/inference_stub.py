"""Pure-numpy inference for imitation v7, mirroring the C++ inference
we'll port into the JIT.

Two purposes:

1. Verification: produce byte-identical logits vs PyTorch on the
   same features. Guards the C++ port against subtle math bugs
   (LayerNorm epsilon, attention masking, ReLU vs GELU, etc.).

2. Reference implementation: every op is written as an explicit
   nested loop over fixed-size arrays, using only + - * / sqrt
   exp log. Trivially translatable to the JIT's C++ subset.

Model architecture (v7):

    Input:
      candidates : (MAX_CSE=32, FEATURES_PER_CANDIDATE=32) float32
                   -- feature-normalized (log1p/scaled per column)
      method     : (METHOD_FEATURES=12,)               float32

    padding_mask[i] := (row i of candidates is all zeros)
                       -- i.e. this is a padded slot beyond the
                       method's actual candidate count.

    Extractor:
      cand_emb = candidates @ W_cand_embed.T + b_cand_embed        (32 x 64)
      # TransformerEncoderLayer, norm_first=True, activation=ReLU:
      #   1. z = LayerNorm(cand_emb) using norm1 gamma/beta
      #   2. attn_out = MultiHeadSelfAttention(z, mask=padding_mask)
      #   3. x = cand_emb + attn_out                                 (residual)
      #   4. z = LayerNorm(x) using norm2 gamma/beta
      #   5. ffn = linear2(ReLU(linear1(z)))
      #   6. cand_post = x + ffn                                     (residual)
      cand_scores = cand_post @ W_cand_scorer.T + b_cand_scorer     (32 x 1)
      stop_score  = method @ W_stop_scorer.T + b_stop_scorer        (1,)
    Output: concat([cand_scores.squeeze(-1), stop_score])            (33,)

Notes on C++-friendliness:
* All tensor dims are compile-time constants.
* No STL: every intermediate is a fixed-size local array. In
  numpy we use np.zeros(...) with fixed shapes; in C++ this
  becomes plain stack-allocated ``float`` arrays.
* Attention uses a "sequence length" of MAX_CSE=32. Padding rows
  are masked from attention (via -inf logits) and treated as
  zero-participation.
* LayerNorm epsilon uses PyTorch's default 1e-5.
* Multi-head attention: the ``in_proj_weight`` is (3*E, E) storing
  Wq/Wk/Wv concatenated; we slice E rows at a time.

Usage::

    python scripts/inference_stub.py \\
        --checkpoint <run>/best_val.pt \\
        --config <run>/config.json \\
        --mch <mch>  --core_root <core_root> \\
        --limit 10
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, Tuple

import numpy as np
import torch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scripts.train_imitation import ImitationScorer, _NORMALIZER
from jitml.constants import MAX_CSE
from jitml.jit_cse import JitCseEnv
from jitml.superpmi import SuperPmi


# ----------------------------------------------------------------------
# Numpy-only ops (all written as explicit for-loops-in-spirit to make
# translation to the JIT's C++ subset trivial).
# ----------------------------------------------------------------------

def _linear(x: np.ndarray, w: np.ndarray, b: np.ndarray) -> np.ndarray:
    """y = x @ w.T + b. x: (..., in_dim); w: (out_dim, in_dim)."""
    # In C++: for i in 0..out_dim: y[i] = b[i]; for j in 0..in_dim: y[i] += x[j]*w[i][j]
    return x @ w.T + b


def _layer_norm(x: np.ndarray, gamma: np.ndarray, beta: np.ndarray,
                eps: float = 1e-5) -> np.ndarray:
    """Per-row LayerNorm over the last axis.
    x: (..., D); gamma/beta: (D,).
    Reduces mean & var over the last axis, applies gamma * (x - mean)/sqrt(var+eps) + beta.
    """
    mean = x.mean(axis=-1, keepdims=True)
    # Torch uses biased variance (divisor N, not N-1); numpy default is unbiased.
    var = x.var(axis=-1, keepdims=True, ddof=0)
    return gamma * (x - mean) / np.sqrt(var + eps) + beta


def _softmax_masked(logits: np.ndarray, mask: np.ndarray) -> np.ndarray:
    """Row-wise softmax over last axis, with mask (True = keep).

    logits: (..., S, S) or (..., S) attention scores.
    mask:   (..., S) True where the KEY is valid.
    Rows where all keys are masked are returned as zeros.
    """
    # Broadcast mask over the last axis of logits (the key axis).
    # Set masked positions to -inf so they contribute 0 to softmax.
    neg_inf = np.float32(-1e30)
    masked = np.where(mask, logits, neg_inf)
    # Numerically-stable softmax.
    m = masked.max(axis=-1, keepdims=True)
    # If every key is masked out, subtracting max gives 0 - (-1e30) = 1e30
    # which overflows exp. Detect and zero-out those rows explicitly.
    e = np.exp(masked - m)
    s = e.sum(axis=-1, keepdims=True)
    out = np.where(s > 0, e / np.where(s > 0, s, 1.0), 0.0)
    return out


def _multi_head_attention(
    x: np.ndarray,                # (S, E)
    in_proj_w: np.ndarray,        # (3E, E)
    in_proj_b: np.ndarray,        # (3E,)
    out_proj_w: np.ndarray,       # (E, E)
    out_proj_b: np.ndarray,       # (E,)
    num_heads: int,
    key_padding_mask: np.ndarray, # (S,) True = padding (KEY IS INVALID)
) -> np.ndarray:
    """Standard MHA (no attn_mask, key_padding_mask only, batch=1).

    PyTorch's key_padding_mask semantics: True = "should be masked
    out" (ignored). We flip to keep_mask internally.
    """
    S, E = x.shape
    head_dim = E // num_heads

    # In-projection: split into Q, K, V along the row axis (0..E, E..2E, 2E..3E).
    qkv = _linear(x, in_proj_w, in_proj_b)  # (S, 3E)
    q = qkv[:, 0:E]
    k = qkv[:, E:2*E]
    v = qkv[:, 2*E:3*E]

    # Reshape to (num_heads, S, head_dim)
    q = q.reshape(S, num_heads, head_dim).transpose(1, 0, 2)
    k = k.reshape(S, num_heads, head_dim).transpose(1, 0, 2)
    v = v.reshape(S, num_heads, head_dim).transpose(1, 0, 2)

    # Scores: (H, S, S) = q @ k.T / sqrt(head_dim)
    scores = np.einsum("hsd,htd->hst", q, k) / np.sqrt(head_dim)

    # Apply key padding mask: keep_mask is (S,) True = valid key.
    # Broadcast to (H, S, S): value depends only on KEY position, not query.
    keep_mask = ~key_padding_mask  # (S,)
    # broadcast to (1, 1, S)
    keep = np.broadcast_to(keep_mask[None, None, :], scores.shape)
    attn = _softmax_masked(scores, keep)

    # Weighted sum: (H, S, head_dim)
    out = np.einsum("hst,htd->hsd", attn, v)

    # Merge heads back to (S, E)
    out = out.transpose(1, 0, 2).reshape(S, E)

    # Output projection
    return _linear(out, out_proj_w, out_proj_b)


def _transformer_encoder_layer_prenorm_relu(
    x: np.ndarray,               # (S, E)
    norm1_w: np.ndarray, norm1_b: np.ndarray,
    norm2_w: np.ndarray, norm2_b: np.ndarray,
    in_proj_w: np.ndarray, in_proj_b: np.ndarray,
    out_proj_w: np.ndarray, out_proj_b: np.ndarray,
    linear1_w: np.ndarray, linear1_b: np.ndarray,
    linear2_w: np.ndarray, linear2_b: np.ndarray,
    num_heads: int,
    key_padding_mask: np.ndarray,  # (S,) True = padded
) -> np.ndarray:
    """Pre-norm transformer encoder layer with ReLU FFN activation.

    Order:
        z1 = LayerNorm(x, norm1)
        x  = x + MHA(z1)
        z2 = LayerNorm(x, norm2)
        x  = x + Linear2(ReLU(Linear1(z2)))
    """
    z1 = _layer_norm(x, norm1_w, norm1_b)
    attn = _multi_head_attention(z1, in_proj_w, in_proj_b,
                                 out_proj_w, out_proj_b,
                                 num_heads, key_padding_mask)
    x = x + attn
    z2 = _layer_norm(x, norm2_w, norm2_b)
    h = _linear(z2, linear1_w, linear1_b)
    h = np.maximum(h, 0.0)   # ReLU
    ffn = _linear(h, linear2_w, linear2_b)
    return x + ffn


def numpy_v7_forward(cands: np.ndarray, method: np.ndarray,
                     w: Dict[str, np.ndarray],
                     cfg: dict) -> np.ndarray:
    """Full v7 forward pass. Returns (MAX_CSE + 1,) logits."""
    # Padding mask: a row of ``cands`` is padding iff all-zeros.
    key_padding_mask = np.abs(cands).sum(axis=-1) == 0.0  # (MAX_CSE,)

    # 1. Candidate embedding
    cand_emb = _linear(cands, w["extractor.candidate_embed.weight"],
                       w["extractor.candidate_embed.bias"])

    # 2. Transformer encoder layer (single layer per config)
    cand_post = _transformer_encoder_layer_prenorm_relu(
        cand_emb,
        norm1_w=w["extractor.attn.layers.0.norm1.weight"],
        norm1_b=w["extractor.attn.layers.0.norm1.bias"],
        norm2_w=w["extractor.attn.layers.0.norm2.weight"],
        norm2_b=w["extractor.attn.layers.0.norm2.bias"],
        in_proj_w=w["extractor.attn.layers.0.self_attn.in_proj_weight"],
        in_proj_b=w["extractor.attn.layers.0.self_attn.in_proj_bias"],
        out_proj_w=w["extractor.attn.layers.0.self_attn.out_proj.weight"],
        out_proj_b=w["extractor.attn.layers.0.self_attn.out_proj.bias"],
        linear1_w=w["extractor.attn.layers.0.linear1.weight"],
        linear1_b=w["extractor.attn.layers.0.linear1.bias"],
        linear2_w=w["extractor.attn.layers.0.linear2.weight"],
        linear2_b=w["extractor.attn.layers.0.linear2.bias"],
        num_heads=cfg["num_heads"],
        key_padding_mask=key_padding_mask,
    )

    # 3. Candidate scorer: Linear(embed_dim -> 1) per row.
    cand_scores = _linear(cand_post,
                          w["extractor.candidate_scorer.weight"],
                          w["extractor.candidate_scorer.bias"]).squeeze(-1)

    # 4. Stop scorer: Linear(method_features -> 1) on RAW method features.
    stop_score = _linear(method,
                         w["extractor.stop_scorer.weight"],
                         w["extractor.stop_scorer.bias"])  # (1,)

    return np.concatenate([cand_scores, stop_score], axis=-1).astype(np.float32)


# ----------------------------------------------------------------------
# Verification: compare numpy stub vs PyTorch on real method observations.
# ----------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--checkpoint", required=True)
    ap.add_argument("--config", required=True)
    ap.add_argument("--mch", required=True)
    ap.add_argument("--core_root", required=True)
    ap.add_argument("--limit", type=int, default=10,
                    help="Number of methods to verify.")
    args = ap.parse_args()

    with open(args.config, encoding="utf-8") as f:
        cfg = json.load(f)

    # Load PyTorch model.
    device = torch.device("cpu")
    model = ImitationScorer(
        embed_dim=cfg["embed_dim"], num_heads=cfg["num_heads"],
        num_attn_layers=cfg["num_attn_layers"],
        dropout=cfg.get("dropout", 0.0),
    ).to(device).eval()
    sd = torch.load(args.checkpoint, map_location=device)
    model.load_state_dict(sd)

    # Load weights as numpy dict.
    npw = {k: v.detach().cpu().numpy().astype(np.float32) for k, v in sd.items()}

    print(f"Verifying numpy stub vs PyTorch on {args.limit} methods from {args.mch}...")
    max_err = 0.0
    n_checked = 0
    with SuperPmi(args.mch, args.core_root) as spmi:
        idx = 1
        while n_checked < args.limit:
            try:
                m = spmi.jit_method(idx, JitMetrics=1, JitRLHook=1,
                                    JitRLHookEmitFeatureNames=1,
                                    JitRLHookCSEDecisions=[])
            except Exception:
                idx += 1
                continue
            if m is None or not m.cse_candidates:
                idx += 1
                continue

            obs = JitCseEnv.get_observation(m)
            cands_n, method_n = _NORMALIZER.normalize(obs["candidates"], obs["method"])

            # PyTorch
            with torch.no_grad():
                cands_t = torch.from_numpy(cands_n.astype(np.float32)).unsqueeze(0)
                method_t = torch.from_numpy(method_n.astype(np.float32)).unsqueeze(0)
                pt_out = model(cands_t, method_t).squeeze(0).cpu().numpy()  # (MAX_CSE,)
                # Model.forward drops the last (stop) logit -- reproduce it manually
                # by calling the extractor directly.
                full_ext = model.extractor({"candidates": cands_t, "method": method_t}).squeeze(0).cpu().numpy()
                pt_full = full_ext  # (MAX_CSE + 1,)

            # Numpy
            np_full = numpy_v7_forward(cands_n.astype(np.float32),
                                       method_n.astype(np.float32),
                                       npw, cfg)

            err = np.abs(pt_full - np_full).max()
            max_err = max(max_err, err)
            n_checked += 1
            print(f"  method {idx:>4d}: max abs err = {err:.3e}  "
                  f"(pt range [{pt_full.min():+.3f}, {pt_full.max():+.3f}])")
            idx += 1

    print()
    print(f"Verified {n_checked} methods. Overall max abs error: {max_err:.3e}")
    if max_err < 1e-4:
        print("PASS: numpy stub reproduces PyTorch inference within float32 rounding.")
        return 0
    else:
        print(f"FAIL: err {max_err:.3e} exceeds tolerance 1e-4.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
