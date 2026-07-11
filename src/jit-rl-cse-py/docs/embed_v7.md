# Embedding Imitation v7 into the JIT

## Overview

Imitation v7 is a small transformer that predicts, for each CSE
candidate of a method, whether that candidate belongs to the
(near-)optimal CSE subset. Total 36,494 parameters. Inference is
one forward pass per method containing CSE candidates.

This document specifies how the model can be embedded into the .NET
JIT (`clrjit.dll`), following the existing pattern established by
`CSE_HeuristicParameterized::s_defaultParameters` (a baked-in table
of 25 doubles consumed by a linear model).

## Constraints of the JIT C++ subset

The JIT uses a restricted subset of C++:

- **No STL**: no `std::vector`, `std::string`, no dynamic containers.
- **No exceptions**, no RTTI.
- **No external math libraries** (no Eigen, ONNX Runtime, LibTorch).
- **Arena allocation** (`CompAllocator`) for anything non-stack.
- **Compile-time-known sizes** wherever possible.

Every operation in v7's forward pass reduces to basic float
arithmetic (`+`, `-`, `*`, `/`, `sqrt`, `exp`). No dependencies.

## Model architecture recap

```
Input:
  candidates : float32[MAX_CSE = 32][FEATURES_PER_CANDIDATE = 32]
               (feature-normalized: log1p on count columns, /1000 on
                log_x1000 / ratio_x1000 columns, /2 on enum-small,
                identity on booleans and one-hots)
  method     : float32[METHOD_FEATURES = 12]
               (same normalization scheme applied per method feature)

Layers (all trainable via imitation learning; frozen at deploy time):
  candidate_embed : Linear(32 -> 64)
  attention layer (1 layer, pre-norm, MHA + FFN):
    norm1  : LayerNorm(64)
    self-attn: MultiHead(embed_dim=64, num_heads=4, head_dim=16)
      in_proj  : Linear(64 -> 192)   # concatenated Wq/Wk/Wv
      out_proj : Linear(64 -> 64)
    norm2  : LayerNorm(64)
    FFN    : Linear(64 -> 128) + ReLU + Linear(128 -> 64)
  candidate_scorer : Linear(64 -> 1)   # applied per-candidate row
  stop_scorer      : Linear(12 -> 1)   # applied to raw method features

Output:
  logits : float32[MAX_CSE + 1]
    logits[0..32) -- per-candidate score
    logits[32]    -- stop score

Inference:
  probs  = sigmoid(logits)
  applied_subset = { i : probs[i] > threshold  and  candidate i is
                          viable  and  i < method's actual candidate count }
  If applied_subset is non-empty, apply those CSEs to the method.

Best threshold from testing: 0.30 (v7 on test.mch).
```

## Padding-mask handling

The model was trained on fixed-size `(MAX_CSE=32, FEATURES=32)` input
tensors. Methods with fewer than 32 candidates have zero-padded
trailing rows. Attention **must ignore these** or else pad-noise
influences non-pad candidate embeddings.

**Detection at inference**: a row is padding iff every feature is
zero. In C++:

```c++
bool isPadding[MAX_CSE];
for (int i = 0; i < MAX_CSE; ++i) {
    float s = 0.0f;
    for (int j = 0; j < FEATURES_PER_CANDIDATE; ++j) {
        s += fabsf(candidates[i][j]);
    }
    isPadding[i] = (s == 0.0f);
}
```

In self-attention, masked positions have their `scores[q][k]` set to
`-inf` before softmax so their softmax weight becomes zero and they
don't contribute to any output vector.

## Weights layout

`scripts/export_v7_weights.py` emits `v7_weights.h` with the same
tensor names as the PyTorch state_dict, sanitized to C identifiers
(`k_extractor_candidate_embed_weight`, etc.). All flat 1D
`const float[]` arrays. Total ~146KB in `.rdata`.

Existing precedent in the JIT: `CSE_HeuristicParameterized::s_defaultParameters`
is a `double[25]` — same idea, just tiny.

## Pseudo-C++ inference (JIT-subset compliant)

Every buffer below is a stack array of `float` with compile-time size.
No allocations. No STL. Directly transliterated from the
`scripts/inference_stub.py` reference (verified to match PyTorch to
<4e-6 across 10 sample methods).

```c++
namespace CseImitationV7 {

// Compile-time constants (from v7_weights.h)
constexpr int MAX_CSE                = 32;
constexpr int FEATURES_PER_CANDIDATE = 32;
constexpr int METHOD_FEATURES        = 12;
constexpr int EMBED_DIM              = 64;
constexpr int NUM_HEADS              = 4;
constexpr int HEAD_DIM               = 16;   // EMBED_DIM / NUM_HEADS
constexpr int FFN_HIDDEN             = 128;  // EMBED_DIM * 2
constexpr float LAYER_NORM_EPS       = 1e-5f;

// -------- Primitives --------

// y[i] = b[i] + sum_j x[j] * w[i][j]
static void Linear(const float* x, int inDim,
                   const float* w, const float* b,
                   float* y, int outDim) {
    for (int i = 0; i < outDim; ++i) {
        float s = b[i];
        for (int j = 0; j < inDim; ++j) {
            s += x[j] * w[i * inDim + j];
        }
        y[i] = s;
    }
}

// In-place row-wise LayerNorm (mean/var over the last dim).
static void LayerNorm(float* x, int rows, int dim,
                      const float* gamma, const float* beta) {
    for (int r = 0; r < rows; ++r) {
        float* row = x + r * dim;
        float sum = 0.0f;
        for (int i = 0; i < dim; ++i) sum += row[i];
        float mean = sum / dim;
        float ssq = 0.0f;
        for (int i = 0; i < dim; ++i) {
            float d = row[i] - mean;
            ssq += d * d;
        }
        float invStd = 1.0f / sqrtf(ssq / dim + LAYER_NORM_EPS);
        for (int i = 0; i < dim; ++i) {
            row[i] = gamma[i] * (row[i] - mean) * invStd + beta[i];
        }
    }
}

// -------- Attention (single layer, batch=1) --------

static void Attention(const float* input,          // [MAX_CSE][EMBED_DIM]
                      const bool* isPadding,
                      float* output) {             // [MAX_CSE][EMBED_DIM]
    // Buffers for Q, K, V (all [MAX_CSE][EMBED_DIM])
    float q[MAX_CSE * EMBED_DIM];
    float k[MAX_CSE * EMBED_DIM];
    float v[MAX_CSE * EMBED_DIM];

    // in_proj_w is [3*EMBED_DIM][EMBED_DIM]: rows 0..E->Wq, E..2E->Wk, 2E..3E->Wv.
    const float* wq = k_extractor_attn_layers_0_self_attn_in_proj_weight
                        + 0 * EMBED_DIM * EMBED_DIM;
    const float* wk = k_extractor_attn_layers_0_self_attn_in_proj_weight
                        + 1 * EMBED_DIM * EMBED_DIM;
    const float* wv = k_extractor_attn_layers_0_self_attn_in_proj_weight
                        + 2 * EMBED_DIM * EMBED_DIM;
    const float* bq = k_extractor_attn_layers_0_self_attn_in_proj_bias + 0;
    const float* bk = k_extractor_attn_layers_0_self_attn_in_proj_bias + EMBED_DIM;
    const float* bv = k_extractor_attn_layers_0_self_attn_in_proj_bias + 2 * EMBED_DIM;

    // Project each row.
    for (int t = 0; t < MAX_CSE; ++t) {
        Linear(input + t * EMBED_DIM, EMBED_DIM, wq, bq, q + t * EMBED_DIM, EMBED_DIM);
        Linear(input + t * EMBED_DIM, EMBED_DIM, wk, bk, k + t * EMBED_DIM, EMBED_DIM);
        Linear(input + t * EMBED_DIM, EMBED_DIM, wv, bv, v + t * EMBED_DIM, EMBED_DIM);
    }

    // Per-head scaled dot-product attention.
    const float scale = 1.0f / sqrtf((float)HEAD_DIM);
    float mha_out[MAX_CSE * EMBED_DIM] = {0};

    for (int h = 0; h < NUM_HEADS; ++h) {
        // Compute scores[s][t] = q[s, h*HD..(h+1)*HD] . k[t, h*HD..(h+1)*HD] * scale
        float scores[MAX_CSE * MAX_CSE];
        for (int s = 0; s < MAX_CSE; ++s) {
            for (int t = 0; t < MAX_CSE; ++t) {
                float dot = 0.0f;
                for (int d = 0; d < HEAD_DIM; ++d) {
                    dot += q[s * EMBED_DIM + h * HEAD_DIM + d]
                         * k[t * EMBED_DIM + h * HEAD_DIM + d];
                }
                scores[s * MAX_CSE + t] = isPadding[t]
                                            ? -1e30f
                                            : dot * scale;
            }
        }
        // Row-softmax + weighted sum over V rows.
        for (int s = 0; s < MAX_CSE; ++s) {
            // Find max for numerical stability.
            float m = -1e30f;
            for (int t = 0; t < MAX_CSE; ++t) {
                float sc = scores[s * MAX_CSE + t];
                if (sc > m) m = sc;
            }
            float sum = 0.0f;
            float weights[MAX_CSE];
            for (int t = 0; t < MAX_CSE; ++t) {
                float e = (scores[s * MAX_CSE + t] > -1e29f) ? expf(scores[s * MAX_CSE + t] - m) : 0.0f;
                weights[t] = e;
                sum += e;
            }
            // If entire row masked (shouldn't happen for real methods but be safe):
            if (sum <= 0.0f) continue;
            for (int t = 0; t < MAX_CSE; ++t) weights[t] /= sum;
            // Accumulate to head's slice of mha_out.
            for (int d = 0; d < HEAD_DIM; ++d) {
                float acc = 0.0f;
                for (int t = 0; t < MAX_CSE; ++t) {
                    acc += weights[t] * v[t * EMBED_DIM + h * HEAD_DIM + d];
                }
                mha_out[s * EMBED_DIM + h * HEAD_DIM + d] = acc;
            }
        }
    }

    // Output projection.
    for (int s = 0; s < MAX_CSE; ++s) {
        Linear(mha_out + s * EMBED_DIM, EMBED_DIM,
               k_extractor_attn_layers_0_self_attn_out_proj_weight,
               k_extractor_attn_layers_0_self_attn_out_proj_bias,
               output + s * EMBED_DIM, EMBED_DIM);
    }
}

// -------- Full forward pass --------

// Emit MAX_CSE + 1 logits into `outLogits`. Positive logit => prefer
// to apply that candidate; last logit is the stop score.
void Forward(const float candidates[MAX_CSE * FEATURES_PER_CANDIDATE],
             const float method[METHOD_FEATURES],
             float outLogits[MAX_CSE + 1]) {
    // Padding detection.
    bool isPadding[MAX_CSE];
    for (int i = 0; i < MAX_CSE; ++i) {
        float s = 0.0f;
        for (int j = 0; j < FEATURES_PER_CANDIDATE; ++j) {
            s += fabsf(candidates[i * FEATURES_PER_CANDIDATE + j]);
        }
        isPadding[i] = (s == 0.0f);
    }

    // 1. candidate_embed
    float embed[MAX_CSE * EMBED_DIM];
    for (int r = 0; r < MAX_CSE; ++r) {
        Linear(candidates + r * FEATURES_PER_CANDIDATE, FEATURES_PER_CANDIDATE,
               k_extractor_candidate_embed_weight,
               k_extractor_candidate_embed_bias,
               embed + r * EMBED_DIM, EMBED_DIM);
    }

    // 2. Encoder layer: pre-norm attention + pre-norm FFN with ReLU.
    float x[MAX_CSE * EMBED_DIM];
    for (int i = 0; i < MAX_CSE * EMBED_DIM; ++i) x[i] = embed[i];

    // Attention block.
    float z1[MAX_CSE * EMBED_DIM];
    for (int i = 0; i < MAX_CSE * EMBED_DIM; ++i) z1[i] = x[i];
    LayerNorm(z1, MAX_CSE, EMBED_DIM,
              k_extractor_attn_layers_0_norm1_weight,
              k_extractor_attn_layers_0_norm1_bias);

    float attn[MAX_CSE * EMBED_DIM];
    Attention(z1, isPadding, attn);
    for (int i = 0; i < MAX_CSE * EMBED_DIM; ++i) x[i] += attn[i];  // residual

    // FFN block.
    float z2[MAX_CSE * EMBED_DIM];
    for (int i = 0; i < MAX_CSE * EMBED_DIM; ++i) z2[i] = x[i];
    LayerNorm(z2, MAX_CSE, EMBED_DIM,
              k_extractor_attn_layers_0_norm2_weight,
              k_extractor_attn_layers_0_norm2_bias);

    for (int r = 0; r < MAX_CSE; ++r) {
        float hidden[FFN_HIDDEN];
        Linear(z2 + r * EMBED_DIM, EMBED_DIM,
               k_extractor_attn_layers_0_linear1_weight,
               k_extractor_attn_layers_0_linear1_bias,
               hidden, FFN_HIDDEN);
        for (int i = 0; i < FFN_HIDDEN; ++i) hidden[i] = hidden[i] > 0.0f ? hidden[i] : 0.0f;  // ReLU
        float ffn[EMBED_DIM];
        Linear(hidden, FFN_HIDDEN,
               k_extractor_attn_layers_0_linear2_weight,
               k_extractor_attn_layers_0_linear2_bias,
               ffn, EMBED_DIM);
        for (int d = 0; d < EMBED_DIM; ++d) {
            x[r * EMBED_DIM + d] += ffn[d];   // residual
        }
    }

    // 3. Per-candidate score.
    for (int r = 0; r < MAX_CSE; ++r) {
        float score[1];
        Linear(x + r * EMBED_DIM, EMBED_DIM,
               k_extractor_candidate_scorer_weight,
               k_extractor_candidate_scorer_bias,
               score, 1);
        outLogits[r] = score[0];
    }

    // 4. Stop score from raw method features.
    Linear(method, METHOD_FEATURES,
           k_extractor_stop_scorer_weight,
           k_extractor_stop_scorer_bias,
           outLogits + MAX_CSE, 1);
}

} // namespace CseImitationV7
```

## Feature normalization

The Python trainer applies `_FeatureNormalizer` before feeding inputs
to the model. The JIT must reproduce the same transforms. Per column
category (defined by `PER_CANDIDATE_SCHEMA` and `METHOD_SCHEMA` in
`jitml/jit_cse.py`):

| Kind | Transform | Reason |
|------|-----------|--------|
| BOOL | identity | already {0, 1} |
| ONEHOT | identity | already {0, 1} |
| COUNT | `log1p(max(0, x))` | compress multi-OoM counts |
| LOG_X1000 | `x / 1000` | JIT emits log*1000 scaled fixed-point |
| RATIO_X1000 | `x / 1000` | JIT emits ratio*1000 scaled fixed-point |
| ENUM_SMALL | `x / 2` | small integer bucket |

The JIT-side normalization can be a compile-time table of `(offset,
kind)` per feature column, applied in one pass before calling
`Forward`.

## Where this plugs in

Existing precedent:

- `src/coreclr/jit/optcse.cpp` line 2316: `CSE_HeuristicParameterized::s_defaultParameters`
  is the baked-in weights table for the linear "RL2020" parameterized heuristic.
- `src/coreclr/jit/optcse.cpp` line 2326: `CSE_HeuristicParameterized`
  constructor loads those weights, then `ConsiderCandidates` /
  `GreedyPolicy` (line 2437) applies them.

For v7 we would introduce a **new** parallel class,
`CSE_HeuristicImitation`, that:

1. Loads no learnable state (weights are baked in `v7_weights.h`).
2. Overrides `ConsiderCandidates` to:
   - Collect the same feature vectors that `CSE_HeuristicRLHook`
     currently emits over the streaming channel (see `optcse.h`
     line 259 for `CSE_HeuristicRLHook`, and the existing feature
     collection in `CSE_HeuristicParameterized::GetFeatures` +
     `GetStoppingFeatures`).
   - Normalize them (feature-kind table).
   - Call `CseImitationV7::Forward(candidates, method, logits)`.
   - Apply sigmoid > threshold on each viable candidate.
   - Apply CSEs for candidates above threshold via existing
     `PerformCSE` machinery.

Enabling the heuristic: gate on a new `JitConfig::JitCseImitationV7`
config flag (mirrors `JitConfig::JitRLCSEGreedy` for the parameterized
model). Set to 1 to use v7, else fall back to the default hand-crafted
heuristic.

## FLOPs / cost estimate

Per method with N ≤ 32 candidates:

- Candidate embedding: `MAX_CSE * (EMBED_DIM * FEATURES_PER_CANDIDATE)` = `32 * 64 * 32` = 65K ops
- LayerNorm x2: `2 * MAX_CSE * EMBED_DIM` = ~4K ops
- MHA (dominant):
  - In-proj (Wq/Wk/Wv): `3 * MAX_CSE * EMBED_DIM^2` = ~400K
  - Attention scores: `NUM_HEADS * MAX_CSE^2 * HEAD_DIM` = 65K
  - Softmax over `NUM_HEADS * MAX_CSE^2` = ~4K (with a few `expf`)
  - Weighted sum: `NUM_HEADS * MAX_CSE^2 * HEAD_DIM` = 65K
  - Out-proj: `MAX_CSE * EMBED_DIM^2` = 130K
- FFN: `MAX_CSE * (EMBED_DIM * FFN_HIDDEN + FFN_HIDDEN * EMBED_DIM)` = ~525K
- Scorers: `MAX_CSE * EMBED_DIM + METHOD_FEATURES` = ~2K

**Total: ~1.3M float ops per method.**

At 1 GFLOP/s (conservative for a JIT-compile-time budget), that's
1.3ms — but at modern L1-resident SIMD-friendly rates (10 GFLOP/s+),
well under 0.2ms. JIT compilation of a non-trivial method already
takes 1-100ms; the model is negligible.

**Memory**: ~144KB read-only weights in `.rdata`; ~16KB stack for
scratch buffers (dominated by `mha_out[MAX_CSE * EMBED_DIM]` +
attention scores). Well within kernel stack limits.

## Threshold selection

Empirical best on `test.mch` (434 acceptable methods):

| Threshold | vs_heur arith | b/s/w restricted |
|-----------|-------------:|------------------|
| 0.25 | -0.36% | 176/198/60 |
| **0.30** | **-0.390%** | **181/208/45** |
| 0.35 | -0.38% | 179/213/42 |
| 0.40 | -0.36% | 178/218/38 |
| 0.50 | -0.30% | 172/223/39 |

0.30 gives the best arith mean; 0.35+ gives slightly fewer losses at
some cost to wins. Ship with 0.30 as default; expose via
`JitConfig::JitCseImitationV7Threshold` for tuning.

## Deployment checklist

1. Copy `v7_weights.h` into `src/coreclr/jit/`.
2. Add `CSE_HeuristicImitation` class in `optcse.h` / `optcse.cpp`
   next to `CSE_HeuristicParameterized`.
3. Implement feature-collection + normalization to match
   `PER_CANDIDATE_SCHEMA` and `METHOD_SCHEMA`.
4. Wire `Forward` as the ChooseCandidates policy.
5. Add `JitCseImitationV7` config flag.
6. SPMI-based measurement:
   - `superpmi.py replay` with `JitCseImitationV7=1` vs baseline on
     the test.mch, verify perf-score delta matches our Python
     evaluation (should reproduce -0.390% arith, 181/208/45).
7. Real-benchmark measurement: run the dotnet/performance benchmarks
   identified in `docs/impacted_benchmarks.md` with and without
   the flag, confirm perf-score delta correlates with wall-clock.

## Verification

`scripts/inference_stub.py` verified the numpy port against PyTorch
on 10 test.mch methods: max abs error 3.8e-6 (float32 rounding noise).
The C++ port should reach the same tolerance since it uses identical
operations. Add a JIT-side unit test that runs `Forward` on a
canned input and compares against the expected numpy output baked
into the test.
