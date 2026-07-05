"""Functions for interacting with SuperPmi."""

from concurrent.futures import ThreadPoolExecutor
from enum import Enum
import json
import os
import subprocess
import re
from typing import Dict, Iterable, List
from pydantic import BaseModel, field_validator
import tqdm

from .constants import split_for_cse
from .method_context import MethodContext

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
    """Controls one instance of superpmi."""
    def __init__(self, mch : str, core_root : str):
        """Constructor.
        core_root is the path to the coreclr build, usually at [repo]/artifiacts/bin/coreclr/[arch]/.
        verbosity is the verbosity level of the superpmi process. Default is 'q'."""
        self._process = None
        self._feature_names = None
        self.mch = mch
        self.core_root = core_root

        if os.name == 'nt':
            self.superpmi_path = os.path.join(core_root, 'superpmi.exe')
            self.jit_path = os.path.join(core_root, 'clrjit.dll')
        else:
            self.superpmi_path = os.path.join(core_root, 'superpmi')
            self.jit_path = os.path.join(core_root, 'libclrjit.so')

        if not os.path.exists(self.mch):
            raise FileNotFoundError(f"mch {self.mch} does not exist.")

        if not os.path.exists(self.superpmi_path):
            raise FileNotFoundError(f"superpmi {self.superpmi_path} does not exist.")

        if not os.path.exists(self.jit_path):
            raise FileNotFoundError(f"jit {self.jit_path} does not exist.")

    def __del__(self):
        self.stop()

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *_):
        self.stop()

    def jit_method(self, method_or_id : int | MethodContext, retry=1, **options) -> MethodContext:
        """Attempts to jit the method, and retries if it fails up to "retry" times."""
        if retry < 1:
            raise ValueError("retry must be greater than 0.")

        for _ in range(retry):
            result = self.__jit_method(method_or_id, **options)
            if result is not None:
                return result

            self.stop()
            self.start()

        return None

    def __jit_method(self, method_or_id : int | MethodContext, **options) -> MethodContext:
        """Jits the method given by id or MethodContext."""
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

        if not process.poll():
            self.stop()
            process = self.start()

        process.stdin.write(f"{torun}\n".encode('utf-8'))
        process.stdin.flush()

        result = None
        output = ""

        while not output.startswith('[streaming] Done.'):
            output = process.stdout.readline().decode('utf-8').strip()
            if output.startswith(';'):
                result = self._parse_method_context(output)

        assert result is None or result.index == method_or_id
        return result

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

    def _parse_method_context(self, line:str) -> MethodContext:
        if self._feature_names is None:
            # find featureNames in line
            feature_names_header = 'featureNames '
            start = line.find(feature_names_header)
            stop = line.find(' ', start + len(feature_names_header))
            if start > 0:
                self._feature_names = line[start + len(feature_names_header):stop].split(',')
                self._feature_names.insert(0, 'id')

        properties = {}
        properties['index'] = int(re.search(r'spmi index (\d+)', line).group(1))
        properties['name'] = re.search(r'for method ([^ ]+):', line).group(1)
        properties['hash'] = re.search(r'MethodHash=([0-9a-f]+)', line).group(1)
        properties['total_bytes'] = int(re.search(r'Total bytes of code (\d+)', line).group(1))
        properties['prolog_size'] = int(re.search(r'prolog size (\d+)', line).group(1))
        properties['instruction_count'] = int(re.search(r'instruction count (\d+)', line).group(1))
        properties['perf_score'] = float(re.search(r'PerfScore ([0-9.]+)', line).group(1))
        properties['bytes_allocated'] = int(re.search(r'allocated bytes for code (\d+)', line).group(1))
        properties['num_cse'] = int(re.search(r'num cse (\d+)', line).group(1))
        properties['num_cse_candidate'] = int(re.search(r'num cand (\d+)', line).group(1))
        properties['heuristic'] = re.search(r'num cand \d+ (.+) ', line).group(1)

        seq = re.search(r'seq ([0-9,]+) spmi', line)
        if seq is not None:
            properties['cses_chosen'] = [int(x) for x in seq.group(1).split(',')]
        else:
            properties['cses_chosen'] = []

        cse_candidates = None
        if self._feature_names is not None:
            # features CSE #032,3,10,3,3,150,150,1,1,0,0,0,0,0,0,37
            candidates = re.findall(r'features #([0-9,]+)', line)
            if candidates is not None:
                cse_candidates = [{self._feature_names[i]: int(x) for i, x in enumerate(candidate.split(','))}
                                  for candidate in candidates]

                for i, candidate in enumerate(cse_candidates):
                    candidate['index'] = i
                    if i in properties['cses_chosen']:
                        candidate['applied'] = True

        properties['cse_candidates'] = cse_candidates if cse_candidates is not None else []

        return MethodContext(**properties)

    def start(self):
        """Starts and returns the superpmi process."""
        if self._process is None:
            # pylint: disable=consider-using-with
            params = [self.superpmi_path, self.jit_path, '-streaming', 'stdin', self.mch, '-v', 'q']
            self._process = subprocess.Popen(params, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

        return self._process

    def stop(self):
        """Closes the superpmi process."""
        if self._process is not None:
            self._process.stdin.write(b"quit\n")
            self._process.terminate()
            self._process = None

class MethodKind(Enum):
    """The kind of method."""
    UNKNOWN = 0
    NO_CSE = 1
    HEURISTIC = 2

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
        with open(split_file, 'w', encoding="utf8") as f:
            json.dump([test, train], f)

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
        with open(filename, 'w', encoding="utf8") as f:
            json.dump(result, f)

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

            case _:
                raise ValueError("kind must be a known kind.")

        result = {}
        with SuperPmi(self.mch, self.core_root) as spmi:
            for method in spmi.enumerate_methods(**jit_flags):
                result[method.index] = method

        with open(filename, 'w', encoding="utf8") as f:
            json.dump([m.dict() for m in result.values()], f)

        return result

    def _get_cache(self, kind : MethodKind) -> Dict[int, MethodContext]:
        """Gets the cache for the specified kind."""
        if kind == MethodKind.UNKNOWN:
            raise ValueError("kind must be a known kind.")

        return self.no_cse if kind == MethodKind.NO_CSE else self.heuristic

__all__ = [
    SuperPmiContext.__name__,
    SuperPmi.__name__,
    SuperPmiCache.__name__,
]
