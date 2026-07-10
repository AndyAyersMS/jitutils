"""Supervised imitation-learning training for CSE selection.

Trains a per-candidate binary classifier that predicts, for each CSE
candidate of a method, whether that candidate belongs to the
(near-)optimal subset (produced by ``scripts/label_optimal.py``).

Key design choices:

* **SET prediction, not sequence.** Empirically confirmed on
  method 6 and method 100 that CSE ordering does not affect
  perf-score when applied via ``JitRLHookCSEDecisions``. So a single
  forward pass produces "for each candidate, is it in the optimal
  subset?" and we apply all "yes" candidates in one JIT call at
  evaluation time.

* **Per-candidate sigmoid + BCE loss.** Each viable candidate is one
  training sample. Non-viable candidates are masked out of the loss.
  Padding rows are also masked.

* **Reuses D7's architecture** (attention encoder + separate stop
  head). The candidate head's logits become the per-candidate
  scores; sigmoid gives P(in optimal subset). The stop head is
  unused for imitation (a subset representation doesn't need an
  explicit stop action -- "empty subset" is the equivalent).
  But we keep the head so we can transfer weights to/from the RL
  models built for the same architecture.

Usage::

    python scripts/train_imitation.py \\
        --core_root <path>/Core_Root \\
        --mch <train MCH> \\
        --labels <path to train.optimal.json> \\
        --output_dir <run dir> \\
        --iterations 20 --batch-size 64

The trainer writes ``model.pt`` (state_dict), ``config.json``
(hyperparams + feature schema), and ``train_curve.csv`` (per-epoch
loss + accuracy).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

import numpy as np
import torch
from torch import nn
from torch.utils.data import Dataset, DataLoader

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from jitml.attention_policy import AttentionOverCandidatesExtractor
from jitml.constants import MAX_CSE
from jitml.jit_cse import FEATURES_PER_CANDIDATE, METHOD_LEVEL_FEATURES, JitCseEnv
from jitml.superpmi import SuperPmi, SuperPmiCache
import gymnasium as gym


class _FeatureNormalizer:
    """Standalone feature normalizer that mirrors NormalizeFeaturesWrapper
    without needing a gym env. Applies the same per-column transforms:
    log1p for COUNT columns, /1000 for LOG_X1000 and RATIO_X1000, /2 for
    ENUM_SMALL, identity for BOOL and ONEHOT.
    """

    def __init__(self):
        from jitml.jit_cse import (
            PER_CANDIDATE_SCHEMA, METHOD_SCHEMA,
            FEATURE_KIND_BOOL, FEATURE_KIND_ONEHOT,
            FEATURE_KIND_COUNT, FEATURE_KIND_LOG_X1000,
            FEATURE_KIND_RATIO_X1000, FEATURE_KIND_ENUM_SMALL,
            _CODE_OPT_KIND_DIVISOR,
        )

        def masks(schema):
            n = len(schema)
            log1p_mask = np.zeros(n, dtype=bool)
            scale = np.ones(n, dtype=np.float32)
            for i, (_name, kind) in enumerate(schema):
                if kind == FEATURE_KIND_COUNT:
                    log1p_mask[i] = True
                elif kind == FEATURE_KIND_LOG_X1000:
                    scale[i] = 1000.0
                elif kind == FEATURE_KIND_RATIO_X1000:
                    scale[i] = 1000.0
                elif kind == FEATURE_KIND_ENUM_SMALL:
                    scale[i] = _CODE_OPT_KIND_DIVISOR
                elif kind in (FEATURE_KIND_BOOL, FEATURE_KIND_ONEHOT):
                    pass
                else:
                    raise ValueError(f"unknown feature kind {kind!r}")
            return log1p_mask, scale

        self._cand_log1p, self._cand_scale = masks(PER_CANDIDATE_SCHEMA)
        self._method_log1p, self._method_scale = masks(METHOD_SCHEMA)

    def normalize(self, cand: np.ndarray, method: np.ndarray
                  ) -> "tuple[np.ndarray, np.ndarray]":
        cand = cand.astype(np.float32).copy()
        method = method.astype(np.float32).copy()
        cand /= self._cand_scale
        method /= self._method_scale
        cand[:, self._cand_log1p] = np.log1p(np.maximum(cand[:, self._cand_log1p], 0.0))
        method[self._method_log1p] = np.log1p(np.maximum(method[self._method_log1p], 0.0))
        return cand, method


_NORMALIZER = _FeatureNormalizer()


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--core_root", required=True)
    p.add_argument("--mch", required=True,
                   help="MCH containing the methods labeled by --labels.")
    p.add_argument("--labels", required=True,
                   help="JSON produced by scripts/label_optimal.py.")
    p.add_argument("--output_dir", required=True)
    p.add_argument("--iterations", type=int, default=20,
                   help="Training epochs (default 20).")
    p.add_argument("--batch-size", type=int, default=64)
    p.add_argument("--lr", type=float, default=1e-3)
    p.add_argument("--embed-dim", type=int, default=64)
    p.add_argument("--num-heads", type=int, default=4)
    p.add_argument("--num-attn-layers", type=int, default=1)
    p.add_argument("--dropout", type=float, default=0.1,
                   help="Attention layer dropout (default 0.1). Higher than RL "
                        "training because supervised data is finite; guards against "
                        "overfit on the labeled pool.")
    p.add_argument("--pos-weight-cap", type=float, default=10.0,
                   help="Cap on per-batch positive-class up-weighting in BCE loss "
                        "(default 10.0). About 20-30% of viable candidates are in "
                        "the optimal subset on labeled sample, so pos-weight ~ 3-5 "
                        "at baseline. Cap prevents runaway on rare buckets.")
    p.add_argument("--val-fraction", type=float, default=0.1,
                   help="Fraction of labels held out for validation (default 0.1).")
    p.add_argument("--seed", type=int, default=42)
    return p.parse_args()


# ----------------------------------------------------------------------
# Dataset
# ----------------------------------------------------------------------

@dataclass
class Sample:
    """One (method) training sample.

    * ``candidates``: (MAX_CSE, FEATURES_PER_CANDIDATE) padded features
    * ``method``:     (METHOD_LEVEL_FEATURES,)
    * ``target``:     (MAX_CSE,) 1.0 for candidates in optimal subset, 0.0 else
    * ``mask``:       (MAX_CSE,) 1.0 for viable candidates (loss counted here), 0.0 else
    * ``method_id``:  int (for logging)
    """
    candidates: np.ndarray
    method: np.ndarray
    target: np.ndarray
    mask: np.ndarray
    method_id: int


def _build_sample(m, optimal_subset: List[int]) -> Sample:
    """Encode a MethodContext + its optimal_subset labels into a Sample.

    Features are normalized identically to NormalizeFeaturesWrapper so
    the trained model can also run on RL-trained env observations
    without re-normalization.
    """
    obs = JitCseEnv.get_observation(m)  # dict with 'candidates' + 'method'
    cands, method = _NORMALIZER.normalize(obs["candidates"], obs["method"])

    # Only the first ``min(len(m.cse_candidates), MAX_CSE)`` rows are real.
    n_slots = min(len(m.cse_candidates), MAX_CSE)
    mask = np.zeros(MAX_CSE, dtype=np.float32)
    target = np.zeros(MAX_CSE, dtype=np.float32)
    for i in range(n_slots):
        c = m.cse_candidates[i]
        if c.can_apply:
            mask[i] = 1.0
    for idx in optimal_subset:
        if 0 <= idx < MAX_CSE:
            target[idx] = 1.0

    return Sample(candidates=cands.astype(np.float32),
                  method=method.astype(np.float32),
                  target=target, mask=mask, method_id=m.index)


class LabeledMethodDataset(Dataset):
    """Loads features via SuperPmi + labels from label_optimal.json.

    Features are fetched at __init__ (batch JIT calls up-front) and
    cached in memory. Labels come from the JSON file.
    """

    def __init__(self, mch: str, core_root: str, labels_path: str,
                 include_ids: Optional[set] = None):
        with open(labels_path, encoding="utf-8") as f:
            all_labels = json.load(f)

        if include_ids is not None:
            all_labels = {k: v for k, v in all_labels.items() if int(k) in include_ids}

        self.samples: List[Sample] = []
        print(f"Loading features for {len(all_labels)} methods from {mch}...")
        t0 = time.time()
        with SuperPmi(mch, core_root) as spmi:
            for i, (mid_str, label) in enumerate(all_labels.items()):
                mid = int(mid_str)
                try:
                    m = spmi.jit_method(mid, JitMetrics=1, JitRLHook=1,
                                        JitRLHookEmitFeatureNames=1,
                                        JitRLHookCSEDecisions=[])
                except Exception:
                    continue
                if m is None:
                    continue
                self.samples.append(_build_sample(m, label["optimal_subset"]))
                if (i + 1) % 100 == 0:
                    print(f"  {i+1}/{len(all_labels)}  ({time.time()-t0:.0f}s)")
        print(f"  loaded {len(self.samples)} samples in {time.time()-t0:.0f}s")

    def __len__(self) -> int:
        return len(self.samples)

    def __getitem__(self, idx: int) -> Dict[str, torch.Tensor]:
        s = self.samples[idx]
        return {
            "candidates": torch.from_numpy(s.candidates),
            "method":     torch.from_numpy(s.method),
            "target":     torch.from_numpy(s.target),
            "mask":       torch.from_numpy(s.mask),
        }


# ----------------------------------------------------------------------
# Model
# ----------------------------------------------------------------------

class ImitationScorer(nn.Module):
    """Wraps AttentionOverCandidatesExtractor with a per-candidate BCE head.

    Uses use_separate_stop_head=True so the extractor emits
    (batch, MAX_CSE+1) logits directly. We ignore the last (stop) logit
    for imitation -- an empty subset is naturally represented by all
    per-candidate logits being negative.
    """

    def __init__(self, embed_dim: int = 64, num_heads: int = 4,
                 num_attn_layers: int = 1, dropout: float = 0.1):
        super().__init__()
        space = gym.spaces.Dict({
            "candidates": gym.spaces.Box(
                low=np.zeros((MAX_CSE, FEATURES_PER_CANDIDATE), dtype=np.float32),
                high=np.ones((MAX_CSE, FEATURES_PER_CANDIDATE), dtype=np.float32),
                dtype=np.float32,
            ),
            "method": gym.spaces.Box(
                low=np.zeros((METHOD_LEVEL_FEATURES,), dtype=np.float32),
                high=np.ones((METHOD_LEVEL_FEATURES,), dtype=np.float32),
                dtype=np.float32,
            ),
        })
        self.extractor = AttentionOverCandidatesExtractor(
            space, features_dim=MAX_CSE + 1, embed_dim=embed_dim,
            num_heads=num_heads, num_attn_layers=num_attn_layers,
            dropout=dropout, use_separate_stop_head=True,
        )

    def forward(self, cands: torch.Tensor, method: torch.Tensor) -> torch.Tensor:
        """Returns (batch, MAX_CSE) per-candidate logits (drops stop head)."""
        out = self.extractor({"candidates": cands, "method": method})
        return out[:, :-1]


# ----------------------------------------------------------------------
# Training loop
# ----------------------------------------------------------------------

def _split_train_val(dataset: LabeledMethodDataset, val_fraction: float, seed: int
                     ) -> Tuple[List[int], List[int]]:
    rng = np.random.default_rng(seed)
    n = len(dataset)
    idx = np.arange(n)
    rng.shuffle(idx)
    n_val = max(1, int(round(val_fraction * n)))
    return idx[n_val:].tolist(), idx[:n_val].tolist()


def _epoch(model: ImitationScorer, loader: DataLoader, optimizer: Optional,
           device: torch.device, pos_weight_cap: float) -> Dict[str, float]:
    """One training or eval epoch."""
    is_train = optimizer is not None
    model.train(is_train)
    total_loss = 0.0
    total_samples = 0
    total_positives = 0
    total_negatives = 0
    correct_at_50 = 0
    total_evaluated = 0

    for batch in loader:
        cands = batch["candidates"].to(device)
        method = batch["method"].to(device)
        target = batch["target"].to(device)
        mask = batch["mask"].to(device)

        # Per-batch positive weighting: BCE up-weights the positive
        # class inversely to its frequency so rare-positive batches
        # don't collapse to "predict 0 always".
        pos = (target * mask).sum().clamp(min=1.0)
        neg = ((1.0 - target) * mask).sum().clamp(min=1.0)
        pos_weight = torch.clamp(neg / pos, max=pos_weight_cap)

        logits = model(cands, method)
        # BCEWithLogits with per-batch pos_weight (scalar).
        bce = nn.functional.binary_cross_entropy_with_logits(
            logits, target, reduction="none", pos_weight=pos_weight,
        )
        # Sum over MAX_CSE dim, mask out non-viable rows.
        loss = (bce * mask).sum() / mask.sum().clamp(min=1.0)

        if is_train:
            optimizer.zero_grad()
            loss.backward()
            optimizer.step()

        # Metrics
        with torch.no_grad():
            preds = (torch.sigmoid(logits) > 0.5).float()
            correct = ((preds == target).float() * mask).sum().item()
            correct_at_50 += correct
            total_evaluated += mask.sum().item()
            total_positives += (target * mask).sum().item()
            total_negatives += ((1.0 - target) * mask).sum().item()

        total_loss += loss.item() * cands.size(0)
        total_samples += cands.size(0)

    return {
        "loss": total_loss / max(1, total_samples),
        "acc": correct_at_50 / max(1, total_evaluated),
        "pos_frac": total_positives / max(1, total_positives + total_negatives),
    }


def main() -> int:
    args = _parse_args()
    os.makedirs(args.output_dir, exist_ok=True)

    torch.manual_seed(args.seed)
    np.random.seed(args.seed)

    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Device: {device}")

    # 1. Load labels + features.
    dataset = LabeledMethodDataset(args.mch, args.core_root, args.labels)
    if len(dataset) < 20:
        print(f"FAIL: only {len(dataset)} samples usable; need >= 20.", file=sys.stderr)
        return 2

    train_idx, val_idx = _split_train_val(dataset, args.val_fraction, args.seed)
    print(f"Train: {len(train_idx)}  Val: {len(val_idx)}")

    train_loader = DataLoader(torch.utils.data.Subset(dataset, train_idx),
                              batch_size=args.batch_size, shuffle=True,
                              num_workers=0)
    val_loader = DataLoader(torch.utils.data.Subset(dataset, val_idx),
                            batch_size=args.batch_size, shuffle=False,
                            num_workers=0)

    # 2. Model + optimizer.
    model = ImitationScorer(embed_dim=args.embed_dim, num_heads=args.num_heads,
                            num_attn_layers=args.num_attn_layers,
                            dropout=args.dropout).to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)
    n_params = sum(p.numel() for p in model.parameters())
    print(f"Model params: {n_params}")

    # 3. Train.
    curve_path = os.path.join(args.output_dir, "train_curve.csv")
    with open(curve_path, "w", encoding="utf-8") as f:
        f.write("epoch,train_loss,train_acc,val_loss,val_acc,pos_frac\n")

    best_val_loss = float("inf")
    for epoch in range(args.iterations):
        t0 = time.time()
        train_metrics = _epoch(model, train_loader, optimizer, device,
                               args.pos_weight_cap)
        val_metrics = _epoch(model, val_loader, None, device, args.pos_weight_cap)
        print(f"epoch {epoch+1:>3d}/{args.iterations}  "
              f"train_loss={train_metrics['loss']:.4f} acc={train_metrics['acc']:.3f}  "
              f"val_loss={val_metrics['loss']:.4f} acc={val_metrics['acc']:.3f}  "
              f"({time.time()-t0:.1f}s)")

        with open(curve_path, "a", encoding="utf-8") as f:
            f.write(f"{epoch+1},{train_metrics['loss']:.6f},{train_metrics['acc']:.6f},"
                    f"{val_metrics['loss']:.6f},{val_metrics['acc']:.6f},"
                    f"{train_metrics['pos_frac']:.6f}\n")

        if val_metrics["loss"] < best_val_loss:
            best_val_loss = val_metrics["loss"]
            torch.save(model.state_dict(), os.path.join(args.output_dir, "best_val.pt"))

    torch.save(model.state_dict(), os.path.join(args.output_dir, "final.pt"))

    # 4. Save config for later inference.
    config = {
        "embed_dim": args.embed_dim,
        "num_heads": args.num_heads,
        "num_attn_layers": args.num_attn_layers,
        "dropout": args.dropout,
        "MAX_CSE": MAX_CSE,
        "FEATURES_PER_CANDIDATE": FEATURES_PER_CANDIDATE,
        "METHOD_LEVEL_FEATURES": METHOD_LEVEL_FEATURES,
        "n_train": len(train_idx),
        "n_val": len(val_idx),
        "n_params": n_params,
        "labels_file": args.labels,
    }
    with open(os.path.join(args.output_dir, "config.json"), "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)

    print(f"\nDone. Best val_loss={best_val_loss:.4f}")
    print(f"  Saved: {args.output_dir}/{{best_val.pt, final.pt, config.json, train_curve.csv}}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
