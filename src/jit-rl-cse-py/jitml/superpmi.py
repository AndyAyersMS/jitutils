"""Functions for interacting with SuperPmi."""

from concurrent.futures import ThreadPoolExecutor
from enum import Enum
import json
import os
import queue
import subprocess
import re
import sys
import tempfile
import threading
import time
from typing import Dict, Iterable, List
from pydantic import BaseModel, field_validator
import tqdm

from .constants import split_for_cse
from .method_context import MethodContext


def _atomic_write_json(path: str, obj) -> None:
    """Write JSON atomically: write to a tempfile in the same directory,
    then ``os.replace`` onto ``path``. ``os.replace`` is atomic on both
    POSIX and Windows (when source and destination are on the same
    filesystem), so concurrent readers never observe a partial file.

    Multiple concurrent writers may still race on the final rename; on
    Windows ``os.replace`` can transiently raise ``PermissionError``
    if the destination is momentarily held by another process. We
    retry a few times with a short backoff; if all attempts fail we
    swallow the error (the caller's next call to
    :func:`os.path.exists` will still succeed because a rival writer
    has already produced a complete file).
    """
    import time
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=directory)
    wrote_ok = False
    try:
        with os.fdopen(fd, "w", encoding="utf8") as f:
            json.dump(obj, f)
        for attempt in range(5):
            try:
                os.replace(tmp, path)
                wrote_ok = True
                break
            except PermissionError:
                time.sleep(0.05 * (attempt + 1))
    finally:
        if not wrote_ok:
            try:
                os.unlink(tmp)
            except OSError:
                pass

# We cannot pass a SuperPmi class across process boundaries.  So we need to create a context object that can be
# serialized and deserialized.
class SuperPmiContext(BaseModel):
    """Information about how to construct a SuperPmi object.  This tells us where to find CLR's CORE_ROOT with
    the superpmi and jit, and which .mch file to use.  Additionally, it tells us which methods to use for training
    and testing."""
    core_root : str
    mch : str

    def __repr__(self):
        return f"SuperPmiContext(core_root={self.core_root}, mch={self.mch})"

    @field_validator('core_root', 'mch', mode='before')
    @classmethod
    def _validate_path(cls, v):
        if not os.path.exists(v):
            raise FileNotFoundError(f"{v} does not exist.")

        return v

    def create_superpmi(self) -> 'SuperPmi':
        """Creates a SuperPmi object."""
        return SuperPmi(self.mch, self.core_root)

    def create_cache(self) -> 'SuperPmiCache':
        """Creates a SuperPmiCache object."""
        return SuperPmiCache(self.mch, self.core_root)

class SuperPmi:
    """Controls one instance of superpmi.

    Includes several client-side safeguards against JIT/SPMI crashes and
    hangs (which are rare but do happen -- e.g. streaming mode is not
    fully robust when JitRLHook + JitCSEMask combinations are used on
    specific methods):

    * **Per-request timeout** via a background reader thread: each
      ``jit_method`` call waits at most ``REQUEST_TIMEOUT`` seconds
      for the JIT to respond. If the deadline passes we kill spmi,
      restart, and return None -- turning hangs into recoverable
      failures the caller can skip past.
    * **EOF detection**: an empty read (superpmi crashed without a
      done sentinel) is treated as failure and triggers restart.
    * **Consecutive-restart cap**: if the same call fails
      ``MAX_CONSECUTIVE_RESTARTS`` times in a row we give up on it and
      return None (rather than looping forever restarting spmi).
    * **Clean stop()**: explicit stdin close before terminate() to
      prevent Python's GC from raising OSError on the buffered writer
      when the pipe is broken.
    """

    # Per-request wall-clock timeout (seconds). Chosen generous enough
    # for the widest MCMC-labeling calls (~500 JIT compiles worth of
    # cumulative superpmi work) but tight enough to catch true hangs.
    REQUEST_TIMEOUT = 60.0
    # If a single method fails to complete this many attempts in a row
    # (each attempt spawns a fresh spmi), give up on it entirely.
    MAX_CONSECUTIVE_RESTARTS = 3

    def __init__(self, mch : str, core_root : str, jit_path : str | None = None):
        """Constructor.
        core_root is the path to the coreclr build, usually at [repo]/artifiacts/bin/coreclr/[arch]/.
        jit_path, if provided, overrides the default clrjit.dll/libclrjit.so from core_root.
        Use this to point at a cross-JIT (e.g. clrjit_universal_arm64_x64.dll).
        verbosity is the verbosity level of the superpmi process. Default is 'q'."""
        self._process = None
        self._stdout_queue: "queue.Queue | None" = None
        self._stdout_thread: "threading.Thread | None" = None
        self._feature_names = None
        self._method_feature_names = None
        self.mch = mch
        self.core_root = core_root

        if os.name == 'nt':
            self.superpmi_path = os.path.join(core_root, 'superpmi.exe')
            default_jit = os.path.join(core_root, 'clrjit.dll')
        else:
            self.superpmi_path = os.path.join(core_root, 'superpmi')
            default_jit = os.path.join(core_root, 'libclrjit.so')
        self.jit_path = jit_path if jit_path is not None else default_jit

        if not os.path.exists(self.mch):
            raise FileNotFoundError(f"mch {self.mch} does not exist.")

        if not os.path.exists(self.superpmi_path):
            raise FileNotFoundError(f"superpmi {self.superpmi_path} does not exist.")

        if not os.path.exists(self.jit_path):
            raise FileNotFoundError(f"jit {self.jit_path} does not exist.")

    def __del__(self):
        # Guard against partially-initialized instances (e.g. tests that use
        # SuperPmi.__new__ to bypass the constructor) so __del__ never raises.
        try:
            self.stop()
        except AttributeError:
            pass

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()

    def jit_method(self, method_or_id : int | MethodContext, retry=1,
                    timeout=None, **options) -> MethodContext:
        """Attempts to jit the method, and retries if it fails up to "retry" times.

        ``timeout`` (seconds) overrides :attr:`REQUEST_TIMEOUT` for this
        call. On timeout the caller sees ``None`` and the underlying
        superpmi process is killed and restarted so the next call gets
        a fresh interpreter.

        Consecutive failures on the *same call* are capped at
        :attr:`MAX_CONSECUTIVE_RESTARTS` even if the caller sets a very
        high ``retry`` -- this prevents an infinite restart storm when
        a specific method reliably crashes the JIT.
        """
        if retry < 1:
            raise ValueError("retry must be greater than 0.")

        capped_retry = min(retry, self.MAX_CONSECUTIVE_RESTARTS)
        for attempt in range(capped_retry):
            result = self.__jit_method(method_or_id, timeout=timeout, **options)
            if result is not None:
                return result
            # __jit_method already killed the process on failure.
            # Cold-restart a fresh spmi before the next attempt.
            self._safe_stop()
            self.start()

        return None

    def __jit_method(self, method_or_id : int | MethodContext,
                     timeout=None, **options) -> MethodContext:
        """Jits the method given by id or MethodContext.

        Returns None if the call times out, hits EOF, or the process
        crashes -- these are recoverable failures. The caller
        (:meth:`jit_method`) will restart spmi and retry.
        """
        if timeout is None:
            timeout = self.REQUEST_TIMEOUT

        process = self._process
        if process is None:
            raise ValueError("SuperPmi process is not running.  Use a 'with' statement.")

        if isinstance(method_or_id, MethodContext):
            method_or_id = method_or_id.index

        if "JitMetrics" not in options:
            options["JitMetrics"] = 1

        if self._feature_names is None and "JitRLHook" in options:
            options['JitRLHookEmitFeatureNames'] = 1

        torun = f"{method_or_id}!"
        torun += "!".join(self.__translate_options(options))

        # If a prior request already killed the process, restart before
        # this attempt. process.poll() returns None while running, a
        # returncode when terminated.
        if process.poll() is not None:
            self._safe_stop()
            process = self.start()

        try:
            process.stdin.write(f"{torun}\n".encode('utf-8'))
            process.stdin.flush()
        except (OSError, ValueError):
            # Pipe broken -- spmi died. Return None so caller can
            # restart and retry.
            self._safe_stop()
            return None

        result = None
        output = ""

        # Read stdout via the background reader thread's queue, with
        # a deadline. If the deadline expires we treat it as a hang
        # and kill spmi.
        deadline = time.monotonic() + timeout
        while not output.startswith('[streaming] Done.'):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                # Hang: kill the process. Caller will restart.
                print(f"jit_method timeout after {timeout:.1f}s "
                      f"(method={method_or_id}) -- killing spmi",
                      file=sys.stderr)
                self._safe_stop()
                return None
            q = self._stdout_queue
            if q is None:
                # start() wasn't called or stop() ran during another
                # thread -- shouldn't happen, but be defensive.
                return None
            try:
                line = q.get(timeout=remaining)
            except queue.Empty:
                # Should have hit the deadline check first; treat as
                # timeout defensively.
                self._safe_stop()
                return None
            if line is None:
                # EOF sentinel from reader thread -- spmi closed stdout.
                # Treat as failure so caller can restart.
                return None
            output = line.decode('utf-8').strip()
            if output.startswith(';'):
                try:
                    result = self._parse_method_context(output)
                except (ValueError, KeyError, IndexError) as exc:
                    # Malformed output from spmi (known streaming bug on
                    # certain methods -- see prior investigation notes).
                    # Don't leave spmi in a corrupted state where the
                    # next call would read stale/garbled data. Kill it
                    # and let the caller restart.
                    print(f"jit_method parse failure "
                          f"(method={method_or_id}): {type(exc).__name__}: {exc}",
                          file=sys.stderr)
                    self._safe_stop()
                    return None

        assert result is None or result.index == method_or_id
        return result

    def _safe_stop(self) -> None:
        """Terminate the current process without raising. Idempotent."""
        try:
            self.stop()
        except Exception:  # noqa: BLE001
            pass

    def __translate_options(self, options:Dict[str,object]) -> List[str]:
        result = []
        for key, value in options.items():
            if not isinstance(value, list):
                result.append(f"{key}={value}")
            else:
                result.append(f"{key}={','.join(str(x) for x in value)}")

        return result

    def enumerate_methods(self, **options) -> Iterable[MethodContext]:
        """List all methods in the mch file."""

        if "JitMetrics" not in options:
            options["JitMetrics"] = 1

        if "JitRLHook" in options and self._feature_names is None:
            options['JitRLHookEmitFeatureNames'] = 1

        params = [self.superpmi_path, self.jit_path, self.mch, '-v', 'q']
        for option in self.__translate_options(options):
            params.extend(['-jitoption', option])

        try:
            # pylint: disable=consider-using-with
            process = subprocess.Popen(params, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            for line in process.stdout:
                line = line.decode('utf-8').strip()
                if line.startswith(';'):
                    yield self._parse_method_context(line)

        finally:
            if process.poll():
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()

    # Compiled regexes shared across parses in streaming mode.
    _RE_INDEX             = re.compile(r'spmi index (\d+)')
    _RE_NAME              = re.compile(r'for method ([^ ]+):')
    _RE_HASH              = re.compile(r'MethodHash=([0-9a-f]+)')
    _RE_TOTAL_BYTES       = re.compile(r'Total bytes of code (\d+)')
    _RE_PROLOG_SIZE       = re.compile(r'prolog size (\d+)')
    _RE_INSTR_COUNT       = re.compile(r'instruction count (\d+)')
    _RE_PERF_SCORE        = re.compile(r'PerfScore ([0-9.]+)')
    _RE_BYTES_ALLOCATED   = re.compile(r'allocated bytes for code (\d+)')
    _RE_NUM_CSE           = re.compile(r'num cse (\d+)')
    _RE_NUM_CAND          = re.compile(r'num cand (\d+)')
    # Everything after "num cand N ": may contain a heuristic name, then
    # optional " featureNames ...", " methodFeatureNames ...",
    # " method,...", " features #<idx>,...", " seq n,n,...", and always
    # ends with " spmi index N (MethodHash=...) for method ...".
    _RE_POST_NUM_CAND     = re.compile(r'num cand \d+(.*)$')
    _RE_SEQ               = re.compile(r'seq ([0-9,]+)(?= spmi index )')
    _RE_FEATURE_CANDIDATE = re.compile(r'features #([0-9,]+)')
    _RE_FEATURE_NAMES     = re.compile(r'featureNames ([^ ]+)')
    _RE_METHOD_FEATURE_NAMES = re.compile(r'methodFeatureNames ([^ ]+)')
    # Method-level feature values: leading ' method,<v1>,<v2>,...' up to
    # the next space or end of line. Uses a lookahead so the trailing
    # ' features #...' / ' seq ...' / ' spmi index ...' tokens don't get
    # slurped into the value list.
    _RE_METHOD_FEATURES   = re.compile(r' method,([0-9,\-]+)(?=(?: features #| seq | spmi index ))')
    # The compile-mode tag at the very end of the line, in parens after
    # the fully-qualified method name. Common values:
    #   Tier0 / Tier0-FullOpts / Instrumented Tier0
    #   Tier1 / Tier1-OSR / Instrumented Tier1
    #   FullOpts / MinOpts
    _RE_COMPILE_MODE      = re.compile(r'for method [^ ]+ \(([^)]+)\)\s*$')

    # Tail markers, in order they may appear after the heuristic name.
    _POST_NUM_CAND_TAIL_MARKERS = (
        ' featureNames ',
        ' methodFeatureNames ',
        ' method,',
        ' features #',
        ' seq ',
        ' spmi index ',
    )

    def _parse_method_context(self, line:str) -> MethodContext:
        # Discover the feature names header the first time we see it.
        if self._feature_names is None:
            fn_match = self._RE_FEATURE_NAMES.search(line)
            if fn_match is not None:
                self._feature_names = fn_match.group(1).split(',')
                # Slot 0 in the `features #idx,...` payload is the CSE index
                # (dumped as %i after the '#'). Prepend a sentinel so
                # positional slots line up with `_feature_names`.
                self._feature_names.insert(0, 'id')

        # Discover the method-level feature names header the first time
        # we see it. Optional; older JIT builds do not emit this.
        if self._method_feature_names is None:
            mfn_match = self._RE_METHOD_FEATURE_NAMES.search(line)
            if mfn_match is not None:
                self._method_feature_names = mfn_match.group(1).split(',')

        properties = {}
        properties['index']             = int(self._RE_INDEX.search(line).group(1))
        properties['name']              = self._RE_NAME.search(line).group(1)
        properties['hash']              = self._RE_HASH.search(line).group(1)
        properties['total_bytes']       = int(self._RE_TOTAL_BYTES.search(line).group(1))
        properties['prolog_size']       = int(self._RE_PROLOG_SIZE.search(line).group(1))
        properties['instruction_count'] = int(self._RE_INSTR_COUNT.search(line).group(1))
        properties['perf_score']        = float(self._RE_PERF_SCORE.search(line).group(1))
        properties['bytes_allocated']   = int(self._RE_BYTES_ALLOCATED.search(line).group(1))
        properties['num_cse']           = int(self._RE_NUM_CSE.search(line).group(1))
        properties['num_cse_candidate'] = int(self._RE_NUM_CAND.search(line).group(1))
        properties['heuristic']         = self._extract_heuristic_name(line)

        # Compile-mode tag from the trailing ``... (Tier1)`` marker. Used
        # to filter for methods that actually run CSE (Tier1, Tier1-OSR,
        # Instrumented Tier1, FullOpts) and to drop the ones that don't
        # (Tier0, MinOpts). Optional -- defaults to empty string if
        # missing (very old JIT dumps or missing marker).
        cm_match = self._RE_COMPILE_MODE.search(line)
        if cm_match is not None:
            properties['compile_mode'] = cm_match.group(1)

        # Method-level feature values (optional -- only present when the
        # JIT is invoked with a JitRLHook that supports the ``method``
        # line). If we have positional names, zip them with the payload
        # and add each recognized key directly to ``properties`` so the
        # pydantic MethodContext gets them.
        mf_match = self._RE_METHOD_FEATURES.search(line)
        if mf_match is not None and self._method_feature_names is not None:
            values = mf_match.group(1).split(',')
            for name, value in zip(self._method_feature_names, values):
                properties[name] = int(value)

        seq = self._RE_SEQ.search(line)
        if seq is not None:
            properties['cses_chosen'] = [int(x) for x in seq.group(1).split(',')]
        else:
            properties['cses_chosen'] = []

        cse_candidates = None
        if self._feature_names is not None:
            # e.g. `features #032,3,10,3,3,150,150,1,1,0,0,0,0,0,0,37`
            candidates = self._RE_FEATURE_CANDIDATE.findall(line)
            if candidates:
                cse_candidates = [{self._feature_names[i]: int(x) for i, x in enumerate(candidate.split(','))}
                                  for candidate in candidates]

                for i, candidate in enumerate(cse_candidates):
                    candidate['index'] = i
                    if i in properties['cses_chosen']:
                        candidate['applied'] = True

        properties['cse_candidates'] = cse_candidates if cse_candidates is not None else []

        return MethodContext(**properties)

    @classmethod
    def _extract_heuristic_name(cls, line: str) -> str:
        """Extract the heuristic-name blob emitted between ``num cand N`` and the
        first known trailing marker (featureNames / features / seq / spmi index).

        When ``JitRLHook=1`` is active, ``CSE_HeuristicRLHook::DumpMetrics`` does
        not emit the heuristic name, so this returns the empty string. When a
        classic heuristic is active, this returns a value like
        ``"Aggressive CSE Heuristic"`` or ``"Standard CSE Heuristic"``.
        """
        match = cls._RE_POST_NUM_CAND.search(line)
        if match is None:
            return ""

        rest = match.group(1)
        positions = [rest.find(marker) for marker in cls._POST_NUM_CAND_TAIL_MARKERS if marker in rest]
        cutoff = min(positions) if positions else len(rest)
        return rest[:cutoff].strip()

    def start(self):
        """Starts and returns the superpmi process."""
        if self._process is None:
            # pylint: disable=consider-using-with
            params = [self.superpmi_path, self.jit_path, '-streaming', 'stdin', self.mch, '-v', 'q']
            self._process = subprocess.Popen(
                params, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            )
            # Background reader thread pipes stdout lines into a queue
            # so jit_method can read with a timeout (Windows lacks
            # ``select`` on pipes, so this is the portable way to
            # implement per-request deadlines).
            self._stdout_queue = queue.Queue()
            self._stdout_thread = threading.Thread(
                target=self._reader_loop,
                args=(self._process.stdout, self._stdout_queue),
                daemon=True,
            )
            self._stdout_thread.start()

        return self._process

    @staticmethod
    def _reader_loop(pipe, out_queue: "queue.Queue") -> None:
        """Read raw bytes-lines from ``pipe`` and put them on ``out_queue``.

        Puts ``None`` on the queue when the pipe closes (EOF) so
        consumers can distinguish "waiting" from "no more data".
        """
        try:
            for line in iter(pipe.readline, b''):
                out_queue.put(line)
        except (OSError, ValueError):
            # Pipe closed / process gone. Fall through to sentinel.
            pass
        out_queue.put(None)

    def stop(self):
        """Closes the superpmi process. Idempotent and non-raising.

        Called both proactively (context manager exit) and reactively
        (after a timeout or crash). Ordering matters:

        1. Detach ``self._process`` immediately so concurrent callers
           see no live process.
        2. Close stdin first so the subprocess sees EOF and can exit
           cleanly. We do this BEFORE ``terminate()`` so Python's GC
           later doesn't try to flush a broken pipe.
        3. Terminate + wait a couple seconds, then kill if needed.
        4. Drain the reader thread by pushing an EOF sentinel.
        """
        if self._process is None:
            return
        proc, self._process = self._process, None
        self._stdout_queue = None
        self._stdout_thread = None  # daemon thread exits when pipe closes

        # 1. Best-effort quit request.
        try:
            if proc.stdin is not None and not proc.stdin.closed:
                try:
                    proc.stdin.write(b"quit\n")
                    proc.stdin.flush()
                except (OSError, ValueError):
                    pass
        except Exception:  # noqa: BLE001
            pass

        # 2. Explicit stdin close so Python's GC doesn't later try to
        # flush a broken pipe (which raises OSError [Errno 22]
        # asynchronously and pollutes stderr).
        try:
            if proc.stdin is not None:
                proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            if proc.stdout is not None:
                proc.stdout.close()
        except (OSError, ValueError):
            pass

        # 3. Terminate, waiting up to 2 sec; kill if unresponsive.
        try:
            proc.terminate()
        except OSError:
            pass
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            try:
                proc.kill()
                proc.wait(timeout=2)
            except Exception:  # noqa: BLE001
                pass
        except Exception:  # noqa: BLE001
            pass

class MethodKind(Enum):
    """The kind of method perf-score to compare against.

    * ``NO_CSE``: the JIT compiles the method with zero CSEs applied.
      Baseline "what would this method score without CSE at all".
    * ``HEURISTIC``: the JIT's default hand-tuned ``CSE_Heuristic``
      (no config settings). This is the "beat the baseline" target.
    * ``RL2020``: the JIT's built-in linear parameterized heuristic
      (``CSE_HeuristicParameterized``) running in greedy mode with
      ``s_defaultParameters`` -- i.e. the 2020 PolicyGradient-trained
      RL model whose parameter vector ships in the JIT source. See
      ``optcse.cpp:2314`` for the training run summary. Enabled via
      ``JitRLCSEGreedy=1``. Useful as a stronger comparison point
      than the hand-tuned default.
    """
    UNKNOWN   = 0
    NO_CSE    = 1
    HEURISTIC = 2
    RL2020    = 3

class SuperPmiCache:
    """A wrapper around superpmi that caches results to file."""
    test_methods : List[MethodContext]
    train_methods : List[MethodContext]

    def __init__(self, mch : str, core_root : str):
        self.mch = mch
        self.core_root = core_root

        with ThreadPoolExecutor() as executor:
            future_no_cse = executor.submit(self._load_all_methods, MethodKind.NO_CSE)
            future_heuristic = executor.submit(self._load_all_methods, MethodKind.HEURISTIC)

            self.no_cse = future_no_cse.result()
            self.heuristic = future_heuristic.result()

        # ``rl2020`` is populated lazily via ``jit_method(..., MethodKind.RL2020)``
        # (or via ``_load_all_methods`` on demand). Priming it eagerly would
        # double the SuperPMI startup cost, and most callers only need the
        # HEURISTIC baseline.
        self.rl2020 : Dict[int, MethodContext] = {}

        self.test_methods, self.train_methods = self._get_test_train()

    @property
    def all_methods(self) -> List[MethodContext]:
        """Gets all methods."""
        return self.no_cse.keys() & self.heuristic.keys()

    def _get_test_train(self):
        split_file = SuperPmiCache._get_split_file(self.mch)
        if os.path.exists(split_file):
            try:
                with open(split_file, 'r', encoding="utf8") as f:
                    return json.load(f)
            except json.JSONDecodeError:
                os.remove(split_file)

        test, train = split_for_cse(self.no_cse.values(), test_percent=0.1)
        test = [x.index for x in test]
        train = [x.index for x in train]
        _atomic_write_json(split_file, [test, train])

        return test, train

    @staticmethod
    def _get_split_file(mch):
        return f"{mch}.test_train.json"

    @staticmethod
    def _get_cache_file(mch, kind):
        return f"{mch}.{kind.name.lower()}.json"

    @staticmethod
    def _get_single_cse_file(mch):
        return f"{mch}.single_cse.json"

    def __repr__(self):
        # We don't want to print out the entire cache.
        return f"SpmiMethodCache(no_cse={len(self.no_cse)}, heuristic={len(self.heuristic)})"

    @staticmethod
    def exists(mch : str) -> bool:
        """Returns True if the cache file exists."""
        return os.path.exists(SuperPmiCache._get_cache_file(mch, MethodKind.NO_CSE)) and \
                os.path.exists(SuperPmiCache._get_cache_file(mch, MethodKind.HEURISTIC)) and \
                os.path.exists(SuperPmiCache._get_split_file(mch))

    @staticmethod
    def get_test_train_methods(mch : str, core_root : str) -> List[int]:
        """Loads the test methods from file."""
        split_file = SuperPmiCache._get_split_file(mch)
        if os.path.exists(split_file):
            with open(split_file, 'r', encoding="utf8") as f:
                return json.load(f)

        # The constructor caches the result
        cache = SuperPmiCache(mch, core_root)
        return cache.test_methods, cache.train_methods

    def jit_method(self, spmi : SuperPmi, method_index : int, kind_or_cses : MethodKind | List[int]) -> MethodContext:
        """Gets the perf score for the specified kind of method."""
        if isinstance(kind_or_cses, list) and len(kind_or_cses) == 0:
            kind_or_cses = MethodKind.NO_CSE

        if isinstance(method_index, MethodContext):
            method_index = method_index.index

        if isinstance(kind_or_cses, MethodKind):
            method = self._get_cache(kind_or_cses).get(method_index, None)
            if method:
                return method

        match kind_or_cses:
            case MethodKind.NO_CSE:
                result = spmi.jit_method(method_index, JitMetrics=1, JitRLHook=1, JitRLHookCSEDecisions=[])
                self.no_cse[method_index] = result
                return result

            case MethodKind.HEURISTIC:
                result = spmi.jit_method(method_index, JitMetrics=1)
                self.heuristic[method_index] = result
                return result

            case MethodKind.RL2020:
                # CSE_HeuristicParameterized in greedy mode, using the
                # 2020-trained s_defaultParameters that ship in the JIT.
                result = spmi.jit_method(method_index, JitMetrics=1, JitRLCSEGreedy=1)
                self.rl2020[method_index] = result
                return result

            case list() as indices:
                return spmi.jit_method(method_index, JitMetrics=1, JitRLHook=1, JitRLHookCSEDecisions=indices)

            case _:
                raise ValueError("kind must be a known kind.")

    def get_cse_perfscores(self, spmi : SuperPmi, progress_bar : bool = True) -> Dict[int, List[float]]:
        """Gets the perf scores for all single CSE decisions."""
        filename = SuperPmiCache._get_single_cse_file(self.mch)

        if os.path.exists(filename):
            with open(filename, 'r', encoding="utf8") as f:
                return json.load(f)

        if progress_bar:
            print("Caching single CSE decisions, this will take a while...")

        has_cses = [x for x in self.no_cse.values()
                    if x.cse_candidates and any(x for x in x.cse_candidates if x.can_apply)]

        result = {}
        progress = tqdm.tqdm(total=sum(len(x.cse_candidates) for x in has_cses)) if progress_bar else has_cses
        for method in has_cses:
            scores = [None] * len(method.cse_candidates)
            for cse in method.cse_candidates:
                if cse.can_apply:
                    single = spmi.jit_method(method.index, JitMetrics=1, JitRLHook=1,
                                             JitRLHookCSEDecisions=[cse.index])
                    if single:
                        scores[cse.index] = single.perf_score

            if any(scores):
                result[method.index] = scores

            progress.update(len(method.cse_candidates))

        progress.close()
        _atomic_write_json(filename, result)

        return result

    def _load_all_methods(self, kind : MethodKind) -> Dict[int, MethodContext]:
        """Loads the cache from file."""
        if kind == MethodKind.UNKNOWN:
            raise ValueError("kind must be a known kind.")

        filename = SuperPmiCache._get_cache_file(self.mch, kind)
        if os.path.exists(filename):
            # pylint: disable=broad-exception-caught

            try:
                result = {}
                with open(filename, 'r', encoding="utf8") as f:
                    data = json.load(f)

                    for d in data:
                        method = MethodContext(**d)
                        result[method.index] = method

                    return result

            except Exception as e:
                del result
                print(f"Error loading {filename}: {e}")
                print(f"Deleting {filename} and re-creating cache.")
                os.remove(filename)

        jit_flags = {}
        jit_flags['JitMetrics'] = 1
        match kind:
            case MethodKind.NO_CSE:
                jit_flags['JitRLHook'] = 1
                jit_flags['JitRLHookCSEDecisions'] = []

            case MethodKind.HEURISTIC:
                jit_flags['JitMetrics'] = 1

            case MethodKind.RL2020:
                # Greedy parameterized heuristic (uses s_defaultParameters).
                jit_flags['JitRLCSEGreedy'] = 1

            case _:
                raise ValueError("kind must be a known kind.")

        result = {}
        with SuperPmi(self.mch, self.core_root) as spmi:
            for method in spmi.enumerate_methods(**jit_flags):
                result[method.index] = method

        # Emit using aliases so the on-disk JSON schema matches the
        # JIT-emitted feature names (``use_wt_cnt``, ``def_wt_cnt``)
        # rather than the internal ``_legacy`` suffixed field names.
        # Old jitml v1 cache files use the alias names and are still
        # loaded via pydantic's ``populate_by_name=True``.
        _atomic_write_json(filename, [m.model_dump(by_alias=True) for m in result.values()])

        return result

    def _get_cache(self, kind : MethodKind) -> Dict[int, MethodContext]:
        """Gets the cache for the specified kind."""
        if kind == MethodKind.NO_CSE:
            return self.no_cse
        if kind == MethodKind.HEURISTIC:
            return self.heuristic
        if kind == MethodKind.RL2020:
            return self.rl2020
        raise ValueError("kind must be a known kind.")

__all__ = [
    SuperPmiContext.__name__,
    SuperPmi.__name__,
    SuperPmiCache.__name__,
]
