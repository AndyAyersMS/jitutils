# jit-rl-cse-py

A Reinforcement Learning gymnasium used to train a machine learning model
to drive the JIT's Common Subexpression Elimination (CSE) heuristic. It is
the Python-based revival of the older C# [MLCSE](../jit-rl-cse/README.md)
experiment, using [Stable-Baselines3](https://stable-baselines3.readthedocs.io/)
(PPO/A2C/DQN) as the RL package instead of a hand-crafted policy-gradient
implementation.

The environment drives the JIT via the generic
[`CSE_HeuristicRLHook`](https://github.com/dotnet/runtime/blob/main/src/coreclr/jit/optcse.cpp)
(`JitRLHook=1`), so it is not tied to any particular policy shape. Method
JITting is done in-process via `superpmi -streaming=stdin` for high
throughput.

**Status:** Under active revival. The initial import matches
[`leculver/jitml`](https://github.com/leculver/jitml) at commit
[`847191a`](https://github.com/leculver/jitml/commit/847191a) (Jun 2024).
See [PLAN](#status--roadmap) below for what's coming next. Original
authorship: Lee Culver (@leculver).

## Provenance

This subtree was imported from [`leculver/jitml`](https://github.com/leculver/jitml)
via `git subtree add --prefix=src/jit-rl-cse-py`. Original commit hashes are
preserved in `git log --follow` output for files under this directory.

That project was itself extracted from `src/coreclr/scripts/cse_ml/` in
[dotnet/runtime](https://github.com/dotnet/runtime), removed by
[dotnet/runtime#102270](https://github.com/dotnet/runtime/pull/102270).

## Requirements

- Windows or Linux (Ubuntu 22.04 / WSL2 recommended).
- Python 3.10 – 3.12. Python 3.13 is not yet officially supported by
  Stable-Baselines3.
- A local clone + Checked build of
  [dotnet/runtime](https://github.com/dotnet/runtime).

## Setup

### 1. Runtime setup

Follow the [dotnet/runtime workflow guide](https://github.com/dotnet/runtime/blob/main/docs/workflow/README.md)
to prepare a build environment, then build a Checked runtime:

```bash
# Linux/macOS
./build.sh -subset clr -c Checked
./build.sh -subset libs -c Release -rc Checked

# Windows
build.cmd -subset clr -c Checked
build.cmd -subset libs -c Release -rc Checked
```

Download SuperPMI data (a few GB):

```bash
python src/coreclr/scripts/superpmi.py download
```

MCH files are locked to the JIT-EE interface version. Always download
against the same runtime commit you are training with.

### 2. Python setup

Create a virtual environment and install:

```bash
python -m venv .venv
# Windows: .venv\Scripts\Activate.ps1
# Linux/macOS: source .venv/bin/activate

pip install -e .
# or, for development (includes pylint/pytest):
pip install -e .[dev]
```

If `pip install -e .` is not available (older pip), fall back to:

```bash
pip install -r requirements.txt
```

## Training a Model

This project uses SuperPMI to JIT methods without needing to load the runtime.  SuperPMI records data about methods in Method Contexts, stored in a .mch file under the `artifacts/spmi` folder.  To train a model, you need to specify the CORE_ROOT environment variable to point to the checked runtime we built above (or use the --core_root parameter) and specify a .mch file to use.  Here is an example:

```bash
python train.py ./model_output_path/ ~/git/dotnet/runtime/artifacts/[build]/[file].mch \
                --core_root ~/git/dotnet/runtime/artifacts/bin/coreclr/linux.x64.Checked/ \
                --iterations 5000000 --parallel 10
```

This will train a model and store it in `./model_output_path`.  Here are the command line options:

``` bash
usage: train.py [-h] [--core_root CORE_ROOT] [--parallel PARALLEL] [--iterations ITERATIONS] [--algorithm ALGORITHM]
                [--test-percent TEST_PERCENT] [--reward-optimal-cse] [--normalize-features] model_path mch
```

**algorithm** - PPO, A2C, or DQN.  PPO is the default and currently the only one that seems to converge to a solution.  Still working on getting A2C and DQN to work.

**iterations** - The number of iterations (individual CSE choices) to train on.  PPO builds a decent model at around 1 million iterations (the default).  It starts getting close to to the default CSE Heuristic at around 3-5 million iterations.

**parallel** - Use multiprocessing to train in parallel.  This specifies the number of processes (default is 1).

**test-percent** - What percentage of the .mch file to reserve for testing the model (default is .1, 10%).

**reward-optimal-cse** - Attempt to find the "optimal" choice at each iteration step and reward the model for picking the best option.  This does have a positive impact, but slows down training by 4x.

**normalize-features** - Performs normalization on features, currently causes the model to not train.  (So don't use it, still investigating why.)

## Evaluating a Model

Use `evaluate.py` to evaluate a model's performance.  Simply pass in the model path, `.mch` file, and CORE_ROOT used with train.py and it will list how many methods were improved or regressed by using the model versus the default heuristic.  Note that snapshots of the model are taken at regular intervals and this file will attempt to evaluate all of them.

# The Code

[jit_cse.py](jitml/jit_cse.py) - This contains the environment itself.  This is meant to produce the most basic observation space and rewards.  If you want to customize rewards, the features that the model uses, etc, you can create a gym wrapper that wraps the environment.

[wrappers.py](jitml/wrappers.py) - This is an example of modifying the gym environment.  `NormalizeFeaturesWrapper` is an example of a `gym.ObservationWrapper`.  It attempts to normalize all inputs to the model in the range of `[0, 1]`.  `OptimalCseWrapper` is a full `gym.Wrapper` that wraps the `step` function.  It enhances the default reward function to attempt to reward/punish the model for making the exact correct or incorrect decisions.

[machine_learning.py](jitml/machine_learning.py) - This file contains all of the machine learning implementation for this project.  We currently just use stable-baselines to implement PPO/A2C/DQN.  Additionally, we don't currently define our own neural network.  The neural network architecture is pre-defined by the `MlpPolicy` parameter when creating the reinforcement learning agent.  A custom neural network can be specified by building a [Custom Network Architecture](https://stable-baselines3.readthedocs.io/en/master/guide/custom_policy.html#custom-network-architecture).

[optcse.cpp](https://github.com/dotnet/runtime/blob/main/src/coreclr/jit/optcse.cpp) - This contains the implementation of `CSE_HeuristicRLHook` used to give the agent the ability to control CSE optimization choices.  Specifically `CSE_HeuristicRLHook::GetFeatures` and `CSE_HeuristicRLHook::s_featureNameAndType` are the raw feature building blocks used by `JitCseEnv` to build the observation that the model is trained on.

[method_context.py](jitml/method_context.py) - This contains the Python classes that mirror the features produced by `CSE_HeuristicRLHook`.  This needs to be kept in sync with optcse.cpp.

## Making Changes

Typically, most changes should be implemented as gym wrappers.  The `JitCseEnv` should be as basic and straight forward as possible.  `JitCseModel.train` provides a `wrappers` parameter that you can use to pass in your custom wrappers to test your changes.

## Testing Changes

Use Tensorboard to see live updates on how training is going:

``` bash
tensorboard --host 0.0.0.0 --logdir=./model_output_path/
```

Both A2C and PPO provide extra metrics on the Tensorboard to see if the model is properly training (DQN does not yet have this).  Here is an example of successful training (blue) vs a model that did not train (red):

![Tensorboard](img/training.png)

Typically, the `rollout/ep_rew_mean`, `results/vs_heuristic`, and `results/vs_no_cse` metrics should all trend upwards over time from a lower value if the model is learning.

Once you see that a model is training successfully, use `evaluate.py` to see how much better or worse it is over the baseline.

**NOTE:** The `results/` metrics are a rolling average of comparisons versus baseline since the last metric datapoint was emitted.  This metric crossing 0 into the positive does not necessarily mean that the model is performing better than the baseline heuristic in a general sense.  Only that it did better on the small subset of training functions it just recently attempted to optimize.  Whether or not the model actually performs better than baseline is left to `evaluate.py` after it is finished training.

## SuperPMI

SuperPMI is used to do the work of JIT'ing functions.  You do not need to use it directly.  However, if you need to test the JIT'ing of a method:

```bash
superpmi libclrjit.so -v q -streaming stdin {mch}
```

Then use the format `[method_id]!JitMetrics=1!Var1=Value1!Var2=Value2` to jit methods.  For example:

```
123!JitMetrics=1              <= JIT the method in the normal way
123!JitMetrics=1!JitRLHook=1  <= Use the reinforcement learning hook

123!JitMetrics=1!JitRLHook=1!JitRLHookCSEDecisions=2,3,1  <= Enable CSE 2, 3, then 1 when JIT'ing
```

## Pylint

Please run `pylint *.py jitml/` before checkin and clean up any warnings
(no need to run it on the tests). It's ok to silence warnings with
`# pylint: disable=...` if it makes more sense to do that than clean up
what it's complaining about.

## Status / roadmap

This subtree is being revived. The initial import is unmodified from
`leculver/jitml`. Planned work, in rough order:

**M1 — Bring-up**

- [x] Import as a git subtree of `leculver/jitml` under jitutils.
- [ ] Modernize Python deps (Python 3.12, pydantic v2, SB3 2.4+,
  gymnasium 1.0).
- [ ] Verify `JitRLHook=1` streaming-SPMI round-trip against the current
  JIT.
- [ ] Fix any parser drift for new `JitMetrics` fields added since 2024.
- [ ] End-to-end smoke train + smoke evaluate.

**M2 — Evaluation harness**

- [ ] Refactor `evaluate.py`: greedy-policy CSV, aggregate summary.
- [ ] Deterministic train/test split.
- [ ] Optional matplotlib plots.
- [ ] Plumb code size, prolog size, and JIT time as passive metrics.

**M3 — Feature / interface refresh**

- [ ] Audit the 19 `CSE_HeuristicRLHook` features vs. today's JIT.
- [ ] Split `enreg_count` into per-register-class counts
  ([optcse.h:246](https://github.com/dotnet/runtime/blob/main/src/coreclr/jit/optcse.h#L246)).
- [ ] Review the `containable` feature.
- [ ] Repoint the stale `optcse.cpp:3149` path comment at this directory.

**M4 — Feature engineering / rewards / hyperparameters**

- [ ] Fix feature normalization ([jitml#1](https://github.com/leculver/jitml/issues/1)).
- [ ] Reward shaping (delta-from-heuristic, delta-from-best-of-N random).
- [ ] Curriculum by CSE-candidate count.
- [ ] PPO hyperparameter sweep (Optuna).
- [ ] Attention-over-candidates architecture
  ([jitml#8](https://github.com/leculver/jitml/issues/8)).
- [ ] Head-to-head vs. the current heuristic on multiple MCH files.

## References

- Original C# MLCSE and RL background:
  [../jit-rl-cse/README.md](../jit-rl-cse/README.md)
- JIT-side hook: `CSE_HeuristicRLHook` in
  [`src/coreclr/jit/optcse.cpp`](https://github.com/dotnet/runtime/blob/main/src/coreclr/jit/optcse.cpp)
- Upstream project (dormant since Jun 2024):
  [`leculver/jitml`](https://github.com/leculver/jitml)

