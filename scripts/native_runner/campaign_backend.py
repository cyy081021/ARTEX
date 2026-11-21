"""Explicit Docker/AFL native-campaign backend adapter (T4b-2).

This module is intentionally *not* part of any production factory.  It is
constructed explicitly by a caller (or by a test) and receives every external
boundary through its constructor: the Docker executable, the ``Popen``/``run``
implementations, the monotonic clock, and the temporary-directory provider.
Nothing here is selected by an environment variable and importing the module
never starts Docker.

The adapter owns exactly the processes/containers/staging directory it records
in its ledger.  It never kills by process name and never deletes a container by
name alone: removal requires an inspect of the exact container id with the
expected task/campaign/attempt/fence/owner labels, followed by an inspect that
proves the object is gone.  Any daemon error, timeout, label mismatch or
unreaped process keeps the attempt in an explicit unknown/hold state.

Only synthetic ``Popen``/``run`` fakes and self-created temp files are used by
the unit tests; the real Docker/AFL path is deliberately NOT RUN.
"""
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from .campaign import (
    CLEANUP_OWNERSHIP_RUNNING,
    CLEANUP_OWNERSHIP_TERMINATED,
    CLEANUP_OWNERSHIP_UNKNOWN,
    CampaignBackend,
    CampaignBackendTimeout,
    CampaignCancelled,
    CampaignPaused,
    validate_resource_plan,
    validate_creation_seal,
    resource_plan_digest,
)
from .elf import inspect_elf
from .fuzz import (
    AFL_FUZZ,
    AFL_SHOWMAP,
    MAX_OUTPUT_DISK,
    SUPERVISOR,
    SUPERVISOR_LIB,
    TOOL_RE,
    coverage_edges_data,
    decode_candidate,
    docker_environment,
    parse_stats,
    regular_bytes,
    remove_staging,
)

OWNER = "artex-native-campaign"
DOCKER_MANAGEMENT_TIMEOUT = 3.0
CLEANUP_HARD_TIMEOUT = 60.0
MAX_ARTIFACT = 64 * 1024 * 1024
MAX_CHECKPOINT_ENTRIES = 512
MAX_CHECKPOINT_BYTES = 1024 * 1024
MAX_CHECKPOINT_ITEM = 4096
MAX_SCAN_ENTRIES = 2048
MAX_SCAN_DEPTH = 3
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_SCAN_SECONDS = 1.0
MAX_PROCESS_OUTPUT = 2 * 1024 * 1024
MAX_HELP_OUTPUT = 64 * 1024
MAX_MANAGEMENT_OUTPUT = 256 * 1024
MAX_CONTAINERS = 8
_DOCKER_ENV = docker_environment
_LABEL_KEYS = (
    "artex.task_id", "artex.campaign_id", "artex.attempt_id",
    "artex.fencing_token", "artex.owner",
)
_SAFE_CANDIDATE = re.compile(r"^(?:id:|id_)[A-Za-z0-9._:-]{1,200}$")
_IMAGE_ID = re.compile(r"^sha256:[0-9a-f]{64}$")

# Private campaign supervisor.  The old fuzz.SUPERVISOR behavior is deliberately
# untouched.  This supervisor owns the AFL child process group and responds to a
# fixed SIGUSR1 pause request by stopping/joining that group before collecting
# the already-written tmpfs corpus.  A valid payload is therefore evidence that
# the in-container writer stopped; Docker CLI exit alone is not such evidence.
PAUSE_SUPERVISOR = SUPERVISOR_LIB + r'''
import signal, time
_pause_state = {"requested": False}
def _on_pause(signum, frame):
    _pause_state["requested"] = True

def collect(path, count, total, crashes=False, root=OUT_ROOT):
    if not os.path.exists(path):
        return [], False, 0
    safe_dir(path, root)
    end = time.monotonic() + 1.0
    names, truncated = [], False
    with os.scandir(path) as entries:
        for entry in entries:
            if len(names) >= 2048 or time.monotonic() >= end:
                truncated = True
                break
            names.append(entry.name)
    # Sort only the bounded prefix, never materialize the whole directory.
    items, seen, used = [], set(), 0
    for name in sorted(names):
        if time.monotonic() >= end or len(items) >= count:
            truncated = True
            break
        child = os.path.join(path, name)
        st = os.lstat(child)
        if linked(child):
            raise ValueError("linked candidate output entry")
        if stat.S_ISDIR(st.st_mode) or name == "README.txt":
            continue
        if not (name.startswith("id:") or name.startswith("id_")) or not stat.S_ISREG(st.st_mode):
            raise ValueError("invalid candidate output entry")
        if st.st_size > MAX_FILE or used + st.st_size > total:
            truncated = True
            continue
        data = read_regular(child, MAX_FILE, root=root)
        digest = __import__("hashlib").sha256(data).hexdigest()
        if digest in seen:
            continue
        seen.add(digest)
        used += len(data)
        items.append({"name": name, "sha256": digest,
                      "data_base64": base64.b64encode(data).decode("ascii")})
    return items, truncated, used


def _collect_findings(max_crashes, root=OUT_ROOT, pause_handled=False):
    result = {"exit": 0, "findings": False, "queue": [], "crashes": [],
              "stats_base64": None, "truncated": False,
              "pause_handled": bool(pause_handled), "writes_stopped": True}
    base = os.path.join(root, "findings", "default")
    if not os.path.exists(base):
        return result
    safe_dir(base, root)
    result["findings"] = True
    queue_dir = os.path.join(base, "queue")
    crash_dir = os.path.join(base, "crashes")
    if os.path.exists(queue_dir):
        safe_dir(queue_dir, root)
        result["queue"], qcut, _ = collect(queue_dir, MAX_CORPUS,
                                           MAX_CORPUS_BYTES, root=root)
    else:
        qcut = False
    if os.path.exists(crash_dir):
        safe_dir(crash_dir, root)
        result["crashes"], ccut, _ = collect(crash_dir, max_crashes,
                                              max_crashes * MAX_FILE,
                                              crashes=True, root=root)
    else:
        ccut = False
    result["truncated"] = bool(qcut or ccut)
    stats = os.path.join(base, "fuzzer_stats")
    if os.path.exists(stats):
        result["stats_base64"] = base64.b64encode(
            read_regular(stats, MAX_STATS, root=root)).decode("ascii")
    return result

def _group_writers(pgid, deadline):
    # Linux container /proc supplies group membership and stopped/zombie state.
    # Failure or excessive enumeration is unknown, never proof of quiescence.
    writers = []
    with os.scandir("/proc") as entries:
        for index, entry in enumerate(entries):
            if index >= 8192 or time.monotonic() >= deadline:
                raise ValueError("process-group proof exceeded its bound")
            if not entry.name.isdigit():
                continue
            try:
                with open(os.path.join(entry.path, "stat"), "r") as source:
                    raw = source.read(4097)
                if len(raw) > 4096:
                    raise ValueError("oversized process status")
                fields = raw[raw.rfind(")") + 2:].split()
                if int(fields[2]) == pgid and fields[0] not in ("T", "t", "Z", "X"):
                    writers.append(int(entry.name))
            except FileNotFoundError:
                continue
    return writers


def _stop_group(process, deadline=None):
    # Freeze the entire owned group before collecting, including descendants
    # that ignore TERM or outlive the leader. One total budget, not 2+2 seconds.
    deadline = time.monotonic() + 2.0 if deadline is None else deadline
    try:
        os.killpg(process.pid, signal.SIGSTOP)
    except ProcessLookupError:
        process.wait(timeout=max(0.0, deadline - time.monotonic()))
        return
    while _group_writers(process.pid, deadline):
        if time.monotonic() >= deadline:
            raise ValueError("process group did not stop")
        time.sleep(min(0.005, max(0.0, deadline - time.monotonic())))
    # The group is quiescent. Kill all members, not merely a leader that may
    # already have exited; zombies cannot write. Reap our direct child.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=max(0.0, deadline - time.monotonic()))
    if _group_writers(process.pid, deadline):
        raise ValueError("process group resumed writing")


def _fuzz_pause(command, max_crashes, root=OUT_ROOT):
    signal.signal(signal.SIGUSR1, _on_pause)
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                               stdout=subprocess.DEVNULL,
                               stderr=subprocess.DEVNULL,
                               start_new_session=True)
    try:
        while process.poll() is None:
            if _pause_state["requested"]:
                _stop_group(process)
                result = _collect_findings(max_crashes, root, True)
                result["exit"] = 0
                return result
            time.sleep(0.01)
        _stop_group(process)
        result = _collect_findings(max_crashes, root, False)
        result["exit"] = process.returncode or 0
        return result
    finally:
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(2)
            except Exception:
                pass

try:
    mode = sys.argv[1]
    max_crashes = int(sys.argv[2])
    command = sys.argv[3:]
    if mode != "fuzz-pause":
        raise ValueError("unsupported campaign supervisor mode")
    result = _fuzz_pause(command, max_crashes)
    raw = json.dumps(result, separators=(",", ":"))
    if len(raw.encode("utf-8")) > MAX_JSON:
        raise ValueError("supervisor response too large")
    sys.stdout.write(raw)
    sys.stdout.flush()
except Exception as exc:
    try:
        sys.stdout.write(json.dumps({"error": str(exc)[:512]},
                                    separators=(",", ":")))
        sys.stdout.flush()
    except Exception:
        pass
    sys.exit(2)
'''


class CampaignBackendError(RuntimeError):
    """A bounded backend failure that must not be reported as success."""


class CampaignOwnershipUnknown(CampaignBackendError):
    """The adapter cannot prove that it still owns (or has stopped) a resource."""


def _is_link(st):
    return bool(stat.S_ISLNK(st.st_mode)
                or (getattr(st, "st_file_attributes", 0) & 0x400))


def _ordered_seeds(seeds):
    """Write benign corpus entries before known-crashing ones.

    `seed-00` is what the standalone instrumentation probe feeds to the target. A
    resumed campaign's checkpoint can legitimately contain crash candidates, and probing
    with one of those makes afl-showmap exit non-zero, which reads as "target rejected".
    Ordering is stable: non-crash entries first, then crash entries, each in place.
    """
    if not isinstance(seeds, list):
        return []
    benign = [item for item in seeds if item.get("source_type") != "crash"]
    crashing = [item for item in seeds if item.get("source_type") == "crash"]
    return benign + crashing


def _text(value):
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _remaining(deadline, clock):
    if deadline is None:
        return None
    return max(0.0, float(deadline) - clock())


def _absolute_deadline(value, now, default):
    """Accept a float, a tiny deadline object, or a mapping; never re-derive it.

    ``CampaignRunner`` converts the wire's absolute execution/envelope
    timestamps to a monotonic ``CampaignDeadline`` exactly once.  This helper
    only extracts the earliest already-monotonic value; it does not add any
    relative duration of its own.
    """
    if value is None:
        return now + max(0.0, float(default))
    if isinstance(value, bool):
        raise ValueError("deadline must not be a boolean")
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, dict):
        candidates = [value.get(key) for key in
                      ("execution", "execution_deadline", "work", "deadline", "expires")]
    else:
        candidates = [getattr(value, key, None) for key in
                      ("execution", "execution_deadline", "work", "deadline", "expires")]
    values = [float(item) for item in candidates
              if isinstance(item, (int, float)) and not isinstance(item, bool)]
    if not values:
        raise ValueError("deadline context has no monotonic deadline")
    return min(values)


def _expected_labels(request):
    return {
        "artex.task_id": str(request["task_id"]),
        "artex.campaign_id": str(request["campaign_id"]),
        "artex.attempt_id": str(request["attempt_id"]),
        "artex.fencing_token": str(request["fencing_token"]),
        "artex.owner": OWNER,
    }


def _nonce(request):
    # The Go manager's plannedResources uses nonce "<attempt>-<fencing>" and
    # names the container "artex-campaign-<campaign>-<attempt>-<nonce>".
    return "%d-%d" % (request["attempt_id"], request["fencing_token"])


def _base_container_name(request):
    return "artex-campaign-%d-%d-%s" % (
        request["campaign_id"], request["attempt_id"], _nonce(request))


class _OutputBudget:
    """Shared stdout+stderr byte budget for one management process."""

    def __init__(self, total):
        self.total = max(0, int(total))
        self.remaining = self.total
        self.truncated = False
        self._lock = threading.Lock()

    def take(self, requested):
        if requested <= 0:
            return 0
        with self._lock:
            allowed = min(requested, max(0, self.remaining))
            self.remaining -= allowed
            if allowed < requested:
                self.truncated = True
            return allowed


class _OutputReader:
    """Bounded pipe reader; always drains, never allocates past ``limit``."""

    def __init__(self, stream, limit, budget=None):
        self.stream = stream
        self.limit = max(0, int(limit))
        self.budget = budget
        self.data = bytearray()
        self.truncated = False
        self.error = None
        self.done = threading.Event()
        self._lock = threading.Lock()
        self.thread = threading.Thread(
            target=self._run, name="artex-campaign-reader", daemon=True)
        self.thread.start()

    def _run(self):
        try:
            while True:
                block = self.stream.read(4096)
                if not block:
                    break
                if isinstance(block, str):
                    block = block.encode("utf-8", "replace")
                with self._lock:
                    if self.budget is not None:
                        allowed = self.budget.take(len(block))
                        if allowed:
                            self.data.extend(block[:allowed])
                        if self.budget.truncated:
                            self.truncated = True
                    else:
                        room = self.limit - len(self.data)
                        if room > 0:
                            self.data.extend(block[:room])
                        if len(block) > max(0, room):
                            self.truncated = True
        except Exception as exc:  # noqa: BLE001 - closed pipes are normal-ish
            self.error = str(exc)[:512]
        finally:
            self.done.set()

    def join(self, timeout):
        if timeout > 0:
            self.thread.join(timeout)
        return self.done.is_set()

    def snapshot(self):
        with self._lock:
            return bytes(self.data), bool(self.truncated)

    def close(self):
        try:
            self.stream.close()
        except Exception:
            pass


class _OwnedProcess:
    """A single Popen handle plus its two bounded reader threads."""

    def __init__(self, process, stdin_handle=None, output_limit=MAX_PROCESS_OUTPUT,
                 output_budget=None):
        self.process = process
        self.stdin_handle = stdin_handle
        self.stdout = self.stderr = None
        try:
            self.stdout = _OutputReader(getattr(process, "stdout", None),
                                        output_limit, budget=output_budget)
            self.stderr = _OutputReader(getattr(process, "stderr", None),
                                        output_limit, budget=output_budget)
        except BaseException:
            # Creation transferred ownership already. A failed second reader
            # must not orphan the process or the first reader.
            if self.poll() is None:
                self._call("kill")
            while self.poll() is None:
                self._call("wait", 0.05)
                time.sleep(0.005)
            self._call("wait", 0.0)
            for reader in (self.stdout, self.stderr):
                if reader is not None:
                    reader.thread.join()
            for stream in (getattr(process, "stdout", None),
                           getattr(process, "stderr", None), stdin_handle):
                if stream is not None:
                    try:
                        stream.close()
                    except Exception:
                        pass
            raise
        self.stopped = False
        self.pause_requested = False

    def poll(self):
        try:
            return self.process.poll()
        except Exception:
            return None

    def _call(self, name, timeout=None):
        function = getattr(self.process, name, None)
        if function is None:
            return None
        try:
            if timeout is None:
                return function()
            return function(timeout=timeout)
        except TypeError:
            try:
                return function(timeout)
            except Exception:
                return None
        except Exception:
            return None

    def stop(self, deadline, clock):
        remaining = _remaining(deadline, clock)
        if remaining is None:
            remaining = 1.0
        if self.poll() is None and remaining > 0:
            self._call("terminate")
            self._call("wait", min(0.5, remaining))
        remaining = _remaining(deadline, clock)
        if self.poll() is None and (remaining is None or remaining > 0):
            self._call("kill")
            self._call("wait", min(0.5, max(0.0, remaining or 0.5)))
        if self.stdin_handle is not None:
            try:
                self.stdin_handle.close()
            except Exception:
                pass
        # Close pipes after the process is signalled so readers can observe EOF.
        self.stdout.close()
        self.stderr.close()
        joined = True
        remaining = _remaining(deadline, clock)
        for reader in (self.stdout, self.stderr):
            if not reader.join(0.0 if remaining is not None else 0.5):
                remaining = _remaining(deadline, clock)
                if remaining is not None and remaining <= 0:
                    joined = False
                else:
                    joined = reader.join(min(0.5, remaining if remaining is not None else 0.5)) and joined
        self.stopped = self.poll() is not None and joined
        return self.stopped

    def finished(self):
        return (self.poll() is not None and self.stdout.done.is_set()
                and self.stderr.done.is_set())

    def wait(self, deadline, clock, control):
        """Wait for exit or a cooperative control/deadline boundary."""
        while True:
            code = self.poll()
            if code is not None:
                return "exited", code
            if control is not None:
                action, _ = control.snapshot()
                if action is not None:
                    self.stop(deadline, clock)
                    return action, None
            remaining = _remaining(deadline, clock)
            if remaining is not None and remaining <= 0:
                self.stop(deadline, clock)
                return "timeout", None
            if self.stdout.truncated or self.stderr.truncated:
                self.stop(deadline, clock)
                return "limited", None
            time.sleep(min(0.02, remaining if remaining is not None else 0.02))

    def wait_with_pause(self, deadline, clock, control, pause_handler):
        """Wait while forwarding pause once, without treating CLI exit as proof."""
        while True:
            code = self.poll()
            if code is not None:
                return "exited", code
            if control is not None:
                action, _ = control.snapshot()
                if action == "cancel":
                    self.stop(deadline, clock)
                    return "cancel", None
                if action == "pause" and not self.pause_requested:
                    if pause_handler():
                        self.pause_requested = True
                        continue
                    self.stop(deadline, clock)
                    return "pause_unconfirmed", None
            remaining = _remaining(deadline, clock)
            if remaining is not None and remaining <= 0:
                self.stop(deadline, clock)
                return "timeout", None
            if self.stdout.truncated or self.stderr.truncated:
                self.stop(deadline, clock)
                return "limited", None
            time.sleep(min(0.02, remaining if remaining is not None else 0.02))

    def drain(self, timeout):
        joined = True
        for reader in (self.stdout, self.stderr):
            joined = reader.join(max(0.0, timeout)) and joined
        out, out_cut = self.stdout.snapshot()
        err, err_cut = self.stderr.snapshot()
        return out, err, out_cut or err_cut, joined


class DockerCampaignBackend(CampaignBackend):
    """A real Docker/AFL adapter with explicit dependency injection.

    Parameters are fixed for the lifetime of the adapter:
      * ``docker``: the Docker executable path/name (never a shell string);
      * ``popen``/``run``: process boundaries used for long-running containers
        and bounded management commands;
      * ``clock``: monotonic clock used for every deadline;
      * ``temp_root``: the only root under which this adapter creates staging;
      * ``mkdtemp``: safe unique-directory provider (defaults to tempfile).
    """

    def __init__(self, docker="docker", popen=subprocess.Popen, run=subprocess.run,
                 clock=time.monotonic, temp_root=None, mkdtemp=tempfile.mkdtemp,
                 environment=None, cleanup_hard_timeout=CLEANUP_HARD_TIMEOUT,
                 management_timeout=DOCKER_MANAGEMENT_TIMEOUT,
                 ownership_snapshot=None):
        if not isinstance(docker, str) or not docker or "\x00" in docker:
            raise ValueError("docker executable must be a fixed non-empty string")
        if not isinstance(cleanup_hard_timeout, (int, float)) or isinstance(cleanup_hard_timeout, bool):
            raise ValueError("cleanup_hard_timeout must be numeric")
        if not 0 < cleanup_hard_timeout <= CLEANUP_HARD_TIMEOUT:
            raise ValueError("cleanup_hard_timeout is out of bounds")
        self.docker = docker
        self.popen = popen
        self.run = run
        self.clock = clock
        self.mkdtemp = mkdtemp
        self.environment = _DOCKER_ENV if environment is None else environment
        self.cleanup_hard_timeout = float(cleanup_hard_timeout)
        self.management_timeout = min(
            DOCKER_MANAGEMENT_TIMEOUT, max(0.0, float(management_timeout)))
        self.temp_root = self._validate_temp_root(temp_root)
        self._temp_root_real = os.path.realpath(str(self.temp_root))
        self._lock = threading.RLock()
        self._bind_lock = threading.Lock()
        self._closed = False
        self._closing = threading.Event()
        self._stop_requested = False
        self._cleanup_started = False
        self._cleanup_report = None
        self._cleanup_verified = False
        self._ownership = CLEANUP_OWNERSHIP_UNKNOWN
        self._records = []
        self._processes = []
        self._staging = None
        self._staging_prefix = None
        self._identity = None
        self._request = None
        self._checkpoint_memory = []
        self._checkpoint_truncated = False
        self._result = None
        self._started = False
        self._snapshot_hint = ownership_snapshot
        self._management_lock = threading.Lock()
        self._management = {}
        self._management_seq = 0

    @property
    def staging(self):
        """The exact self-created staging directory, or None."""
        with self._lock:
            return self._staging

    # ----- constructor/validation helpers ---------------------------------
    @staticmethod
    def _validate_temp_root(temp_root):
        if temp_root is None:
            temp_root = tempfile.gettempdir()
        try:
            path = Path(temp_root)
            if not path.is_absolute():
                raise ValueError("temporary root must be absolute")
            st = path.lstat()
            if _is_link(st) or not stat.S_ISDIR(st.st_mode):
                raise ValueError("temporary root must be a real directory")
            return path
        except OSError as exc:
            raise ValueError("temporary root is unavailable") from exc

    def _bind(self, request):
        if not isinstance(request, dict):
            raise ValueError("campaign backend request must be an object")
        identity = (request.get("task_id"), request.get("campaign_id"),
                    request.get("attempt_id"), request.get("fencing_token"))
        with self._bind_lock:
            if self._identity is None:
                self._identity = identity
                self._request = request
            elif self._identity != identity:
                raise CampaignBackendError("backend is bound to a different attempt")
            return identity

    def _check_open_locked(self):
        if self._closed or self._closing.is_set():
            raise CampaignBackendError("campaign backend is closed for this attempt")
        if self._stop_requested:
            raise CampaignBackendError("campaign backend stop was requested")

    def _check_deadline(self, deadline, label):
        remaining = _remaining(deadline, self.clock)
        if remaining is not None and remaining <= 0:
            raise CampaignBackendTimeout(label + " exceeded the shared deadline")

    def _require_request(self):
        with self._lock:
            if self._request is None:
                raise CampaignBackendError("campaign backend is not bound to an attempt")
            return self._request

    # ----- bounded command helpers ----------------------------------------
    def _command_timeout(self, deadline, requested=None):
        remaining = _remaining(deadline, self.clock)
        if remaining is None:
            return min(self.management_timeout,
                       requested if requested is not None else self.management_timeout)
        if remaining <= 0:
            return 0.0
        limit = self.management_timeout if requested is None else min(
            float(requested), self.management_timeout)
        return min(limit, remaining)

    def _docker_env(self):
        environment = self.environment
        if callable(environment):
            return environment()
        return dict(environment or {})

    @staticmethod
    def _payload_size(value):
        if value is None:
            return 0
        if isinstance(value, (bytes, bytearray)):
            return len(value)
        return len(str(value).encode("utf-8", "replace"))

    def _register_management(self, argv, injected):
        with self._management_lock:
            self._management_seq += 1
            record = {
                "id": self._management_seq, "argv": list(argv),
                "injected": bool(injected), "active": True,
                "done": threading.Event(), "cancel": threading.Event(), "handle": None,
                "result": None, "error": None,
            }
            self._management[record["id"]] = record
            return record

    def _finish_management(self, record):
        with self._management_lock:
            record["active"] = False
            self._management.pop(record["id"], None)
        record["done"].set()

    def _management_pending(self):
        with self._management_lock:
            return list(self._management.values())

    def _stop_management(self, deadline):
        records = self._management_pending()
        for record in records:
            record["cancel"].set()
        for record in records:
            record["done"].wait(max(0.0, _remaining(deadline, self.clock) or 0.0))
        return not self._management_pending()

    def _run_command(self, argv, deadline, requested=None):
        timeout = self._command_timeout(deadline, requested)
        if timeout <= 0:
            raise CampaignBackendTimeout("no remaining budget for Docker management command")
        # One absolute command deadline includes creation, execution and reading.
        end = self.clock() + timeout
        if deadline is not None:
            end = min(end, deadline)
        record = self._register_management(argv, injected=self.run is not subprocess.run)

        def own_call():
            try:
                if record["injected"]:
                    # Legacy test boundary. Same deadline/ownership wrapper as
                    # Popen; an uncooperative injected call remains owned.
                    result = self.run(argv, capture_output=True,
                                      timeout=max(0.0, end - self.clock()),
                                      env=self._docker_env())
                else:
                    result = self._execute_management(argv, end, record)
                if record["cancel"].is_set() or self.clock() >= end:
                    raise CampaignBackendTimeout("Docker management command timed out")
                if result is None:
                    raise CampaignOwnershipUnknown("Docker management command returned no result")
                if (self._payload_size(getattr(result, "stdout", None)) +
                        self._payload_size(getattr(result, "stderr", None)) > MAX_MANAGEMENT_OUTPUT):
                    raise CampaignOwnershipUnknown("Docker management response exceeded its bound")
                record["result"] = result
            except BaseException as exc:
                record["error"] = exc
            finally:
                self._finish_management(record)

        threading.Thread(target=own_call, name="artex-campaign-management",
                         daemon=True).start()
        if not record["done"].wait(max(0.0, end - self.clock())):
            record["cancel"].set()
            raise CampaignBackendTimeout("Docker management command timed out")
        error = record["error"]
        if error is not None:
            if isinstance(error, (CampaignBackendTimeout, subprocess.TimeoutExpired)):
                raise CampaignBackendTimeout("Docker management command timed out") from error
            raise CampaignOwnershipUnknown("Docker management command failed: " + str(error)[:256]) from error
        return record["result"]

    def _execute_management(self, argv, end, record):
        # This single owner handles even a Popen that returns AFTER the caller
        # timed out. Caller timeout is not proof of cleanup. No detached starter
        # or second cleanup owner competes for this process.
        process = self.popen(argv, stdin=subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             bufsize=0, env=self._docker_env())
        handle = _OwnedProcess(process, output_limit=MAX_MANAGEMENT_OUTPUT,
                               output_budget=_OutputBudget(MAX_MANAGEMENT_OUTPUT))
        record["handle"] = handle
        try:
            while not handle.finished():
                if record["cancel"].is_set() or self.clock() >= end:
                    raise CampaignBackendTimeout("Docker management command timed out")
                if handle.stdout.budget.truncated:
                    raise CampaignOwnershipUnknown("Docker management response exceeded its bound")
                time.sleep(min(0.005, max(0.0, end - self.clock())))
            out, err, cut, joined = handle.drain(0.0)
            if cut or not joined:
                raise CampaignOwnershipUnknown("Docker management response exceeded its bound")
            return subprocess.CompletedProcess(argv, handle.poll(), out, err)
        finally:
            # Reaping may outlive the public deadline; the ledger remains active
            # until it actually ends. It never extends the caller's wait.
            if handle.poll() is None:
                handle._call("kill")
            while handle.poll() is None:
                handle._call("wait", 0.05)
                time.sleep(0.005)
            handle._call("wait", 0.0)
            for reader in (handle.stdout, handle.stderr):
                reader.thread.join()
                reader.close()

    @staticmethod
    def _returncode(result):
        value = getattr(result, "returncode", None)
        return value if isinstance(value, int) and not isinstance(value, bool) else None

    @classmethod
    def _stdout(cls, result):
        return _text(getattr(result, "stdout", b""))

    @classmethod
    def _stderr(cls, result):
        return _text(getattr(result, "stderr", b""))

    @classmethod
    def _absent_result(cls, result, target):
        # Exact one-target Docker errors only. A mixed daemon error or another
        # missing object's name is not evidence that this CID is absent.
        if cls._returncode(result) in (None, 0) or cls._stdout(result).strip():
            return False
        message = cls._stderr(result).strip()
        pattern = r"(?:Error: |Error response from daemon: )?No such (?:object|container): " + re.escape(target)
        return re.fullmatch(pattern, message, re.IGNORECASE) is not None

    # ----- command construction -------------------------------------------
    def _labels(self):
        request = self._require_request()
        return _expected_labels(request)

    def build_command(self, name, entrypoint, args, stdin=False):
        """Build the fixed Docker argv; no shell and no caller-supplied argv."""
        request = self._require_request()
        labels = _expected_labels(request)
        stage = str(self._staging)
        cmd = [self.docker, "run", "--pull=never"]
        if stdin:
            cmd.append("-i")
        cmd.extend(["--name", name])
        for key in _LABEL_KEYS:
            cmd.extend(["--label", "%s=%s" % (key, labels[key])])
        cmd.extend([
            "--network=none", "--read-only", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--user=65534:65534",
            "--cpus=1", "--memory=512m", "--pids-limit=128",
            "--ulimit", "core=0", "--ulimit", "nofile=256:256",
            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m,nr_inodes=2048",
            "--tmpfs", "/work/out:rw,nosuid,nodev,noexec,size=64m,nr_inodes=2048,mode=1777",
            "--mount", "type=bind,src=%s,dst=/work/sample,readonly" % (Path(stage) / "sample"),
            "--mount", "type=bind,src=%s,dst=/work/seeds,readonly" % (Path(stage) / "seeds"),
            "--workdir=/work", "--log-driver=none",
            "--env", "AFL_NO_UI=1", "--env", "AFL_SKIP_CPUFREQ=1",
            "--env", "AFL_NO_AFFINITY=1", "--env", "AFL_QUIET=1",
            "--env", "AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1",
            "--entrypoint", entrypoint, request["profile"]["image"],
        ])
        cmd.extend(list(args))
        return cmd

    def _container_name(self, suffix=""):
        base = _base_container_name(self._require_request())
        return base if not suffix else base + "-" + suffix

    # ----- staging / artifact ---------------------------------------------
    def _open_planned_root(self, plan):
        if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
            raise CampaignBackendError("planned staging requires POSIX nofollow support")
        root = plan["staging_root"]
        if root != str(self.temp_root) or root != self._temp_root_real:
            raise CampaignBackendError("resource plan differs from configured staging root")
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        fd = os.open("/", flags)
        try:
            parts = root.split("/")[1:]
            for index, part in enumerate(parts):
                next_fd = os.open(part, flags, dir_fd=fd)
                os.close(fd)
                fd = next_fd
                st = os.fstat(fd)
                private = index == len(parts) - 1
                if (st.st_uid not in (0, os.geteuid())
                        or (private and (st.st_uid != os.geteuid() or st.st_mode & 0o077))
                        or (not private and st.st_mode & 0o022
                            and not st.st_mode & stat.S_ISVTX)):
                    raise CampaignBackendError("staging root ancestry is not trusted/private")
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _create_planned_staging(self, request):
        plan = validate_resource_plan(request["resource_plan"], request)
        fd = self._open_planned_root(plan)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        try:
            # Existing directories are never adopted.
            os.mkdir(plan["staging_basename"], 0o700, dir_fd=fd)
            child = os.open(plan["staging_basename"], flags, dir_fd=fd)
            try:
                st = os.fstat(child)
                if st.st_uid != os.geteuid() or st.st_mode & 0o077:
                    raise CampaignBackendError("planned staging is not private")
            finally:
                os.close(child)
            return str(Path(plan["staging_root"]) / plan["staging_basename"])
        finally:
            os.close(fd)

    def _ensure_staging(self, request, deadline):
        with self._lock:
            if self._staging is not None:
                try:
                    st = self._staging.lstat()
                except OSError as exc:
                    raise CampaignBackendError("staging disappeared") from exc
                if _is_link(st) or not stat.S_ISDIR(st.st_mode):
                    raise CampaignBackendError("staging is not a real directory")
                return self._staging
            self._check_open_locked()
            prefix = "artex-campaign-%d-%d-%s-" % (
                request["campaign_id"], request["attempt_id"], _nonce(request))
            if request.get("resource_plan") is not None:
                path = self._create_planned_staging(request)
            else:
                try:
                    path = self.mkdtemp(prefix=prefix, dir=str(self.temp_root))
                except TypeError:
                    path = self.mkdtemp(prefix=prefix)
                except Exception as exc:
                    raise CampaignBackendError("cannot create staging: " + str(exc)[:256]) from exc
            if not isinstance(path, (str, os.PathLike)):
                raise CampaignBackendError("staging provider returned an invalid path")
            candidate = Path(path)
            if not candidate.is_absolute():
                raise CampaignBackendError("staging path is not absolute")
            parent = os.path.realpath(str(candidate.parent))
            if parent != self._temp_root_real:
                raise CampaignBackendError("staging escaped the trusted temp root")
            basename = candidate.name
            if not basename.startswith(prefix):
                raise CampaignBackendError("staging nonce prefix does not match")
            st = candidate.lstat()
            if _is_link(st) or not stat.S_ISDIR(st.st_mode):
                raise CampaignBackendError("staging is not a real directory")
            self._staging = candidate
            self._staging_prefix = prefix
            return candidate

    def _verify_artifact(self, request):
        path = request.get("artifact_path")
        if not isinstance(path, str) or not path:
            raise ValueError("artifact_path is required")
        data = regular_bytes(path, MAX_ARTIFACT)
        digest = hashlib.sha256(data).hexdigest()
        if digest != request["sha256"]:
            raise ValueError("artifact SHA-256 mismatch")
        return data

    def _write_staging(self, request, data, deadline):
        stage = self._ensure_staging(request, deadline)
        try:
            st = stage.lstat()
            if _is_link(st) or not stat.S_ISDIR(st.st_mode):
                raise CampaignBackendError("staging is not a real directory")
        except OSError as exc:
            raise CampaignBackendError("staging disappeared") from exc
        sample = stage / "sample"
        seeds = stage / "seeds"
        try:
            for child in (sample, seeds):
                try:
                    info = child.lstat()
                except FileNotFoundError:
                    continue
                if _is_link(info):
                    raise CampaignBackendError("staging child is a link")
                if child == seeds and not stat.S_ISDIR(info.st_mode):
                    raise CampaignBackendError("staging seeds child is not safe")
                if child == sample:
                    raise CampaignBackendError("staging sample already exists")
            if seeds.exists():
                raise CampaignBackendError("staging seeds already exist")
            seeds.mkdir(mode=0o755)
            sample.write_bytes(data)
            sample.chmod(0o555)
            # Architecture is verified from the bytes actually written after the
            # hash check, so a changed/link artifact cannot be executed.
            meta = inspect_elf(sample)
            if meta["type_name"] not in ("ET_EXEC", "ET_DYN") or meta["sha256"] != request["sha256"]:
                raise ValueError("target must be a Linux x86-64 executable")
            for index, item in enumerate(_ordered_seeds(request["seeds"])):
                seed = seeds / ("seed-%02d" % index)
                seed.write_bytes(item["data"])
                seed.chmod(0o444)
        except Exception:
            self._remove_staging(None)
            raise
        return stage

    def _verify_image(self, request, deadline):
        profile = request["profile"]
        image = profile.get("image")
        image_id = profile.get("image_id")
        if not isinstance(image, str) or not _IMAGE_ID.match(image):
            raise ValueError("profile.image must be an immutable sha256 digest")
        if not isinstance(image_id, str) or not _IMAGE_ID.match(image_id):
            raise ValueError("profile.image_id must be an immutable sha256 digest")
        if image_id != image:
            raise ValueError("profile.image_id does not match the immutable image")
        argv = [self.docker, "image", "inspect", "--format", "{{.Id}}", image]
        result = self._run_command(argv, deadline)
        if self._returncode(result) != 0:
            raise ValueError("immutable image inspect failed")
        actual = self._stdout(result).strip()
        if actual != image_id:
            raise ValueError("image_id does not match the immutable image")
        return image_id

    # ----- owned process/container ledger ----------------------------------
    def _spawn(self, name, entrypoint, args, deadline, stdin_handle=None,
               stdin_stream=False):
        """Register intent, then start exactly one recorded Docker CLI process.

        The ledger lock is deliberately released across the external Popen so a
        blocked creation cannot hold stop/cleanup/status/ownership. The returned
        handle is attached under the lock and remains owned even when closing
        started while the create was in flight.
        """
        command = self.build_command(name, entrypoint, args, stdin=stdin_stream)
        with self._lock:
            self._check_open_locked()
            record = {
                "name": name, "id": None, "labels": _expected_labels(self._request),
                "process": None, "removed": False, "started": False,
                "failed": "", "stage": entrypoint, "writes_stopped": False,
                "state": "creating", "pause_requested": False,
            }
            if any(item["name"] == name for item in self._records):
                raise CampaignBackendError("container name was already admitted")
            if len(self._records) >= MAX_CONTAINERS:
                raise CampaignBackendError("owned container ledger is full")
            self._records.append(record)
        try:
            process = self.popen(
                command,
                stdin=stdin_handle if stdin_handle is not None else subprocess.DEVNULL,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=0,
                env=self._docker_env())
        except Exception as exc:  # noqa: BLE001
            with self._lock:
                record["failed"] = str(exc)[:256]
                record["state"] = "failed"
            raise CampaignBackendError("cannot start owned container") from exc
        handle = _OwnedProcess(process, stdin_handle=stdin_handle)
        with self._lock:
            record["process"] = handle
            record["started"] = True
            record["state"] = "running"
            self._processes.append(handle)
            self._started = True
            stop_after = (self._closing.is_set() or self._closed
                          or self._stop_requested)
        if stop_after:
            # A cleanup/stop that raced this create must still own the late
            # handle; keep the ledger entry and stop only this recorded PID.
            handle.stop(deadline, self.clock)
            raise CampaignBackendError("cleanup/stop closed backend during container create")
        # Resolve the exact id immediately. Failure keeps the id unknown; cleanup
        # will still refuse to remove anything it cannot inspect by id.
        try:
            object_id = self._resolve_container_id(name, deadline)
            with self._lock:
                record["id"] = object_id
        except Exception:
            pass
        return record

    def _resolve_container_id(self, name, deadline):
        result = self._run_command(
            [self.docker, "inspect", "--format", "{{.Id}}", name], deadline)
        if self._returncode(result) == 0:
            value = self._stdout(result).strip()
            if value:
                return value
        return None

    def _inspect_container(self, object_id, record, deadline):
        result = self._run_command(
            [self.docker, "inspect", "--format", "{{json .}}", object_id], deadline)
        if self._returncode(result) == 0:
            try:
                info = json.loads(self._stdout(result))
            except Exception:
                return "unknown", "container inspect returned malformed JSON"
            if not isinstance(info, dict):
                return "unknown", "container inspect returned no object"
            actual_id = info.get("Id")
            if actual_id != object_id:
                return "unknown", "container id changed during inspect"
            labels = {}
            config = info.get("Config")
            if isinstance(config, dict) and isinstance(config.get("Labels"), dict):
                labels = config["Labels"]
            expected = record.get("labels") or _expected_labels(self._request)
            for key in _LABEL_KEYS:
                if labels.get(key) != expected.get(key):
                    return "mismatch", "container labels do not match the attempt"
            name = info.get("Name")
            if not isinstance(name, str) or name != "/" + record.get("name", ""):
                return "mismatch", "container name does not match the ledger"
            # Retain positive identity evidence through later removal. Only
            # full immutable Docker IDs qualify for a creation seal; ordinary
            # legacy cleanup still performs its existing exact-ID checks.
            if isinstance(actual_id, str) and re.fullmatch(r"[0-9a-f]{64}", actual_id):
                with self._lock:
                    record["verified_creation_id"] = actual_id
            return "present", info
        if self._absent_result(result, object_id):
            return "absent", "container is absent"
        return "unknown", "container inspect failed: " + (
            self._stderr(result) or self._stdout(result))[:256]

    def _remove_container(self, record, deadline):
        with self._lock:
            if record.get("removed"):
                return True
        object_id = record.get("id")
        if object_id is None:
            # A create intent whose id was never resolved is not deleted by
            # name. Resolve by name once and inspect the resulting exact id.
            try:
                object_id = self._resolve_container_id(record["name"], deadline)
            except Exception:
                object_id = None
            if object_id is None:
                # No exact CID means creation remains unresolved. A failed or
                # reaped CLI plus a missing name does not prove the daemon has
                # no pending create; errors are not absence either. Retain the
                # intent and hold instead of manufacturing cleanup evidence.
                record["last_error"] = "container creation has no resolved id"
                return False
            with self._lock:
                record["id"] = object_id
        try:
            status, detail = self._inspect_container(object_id, record, deadline)
        except Exception as exc:  # noqa: BLE001 - timeout/daemon stays unknown
            record["last_error"] = str(exc)[:256]
            return False
        if status == "absent":
            with self._lock:
                record["removed"] = True
            return True
        if status != "present":
            record["last_error"] = detail
            return False
        try:
            result = self._run_command(
                [self.docker, "rm", "-f", object_id], deadline)
        except CampaignBackendTimeout:
            return False
        except Exception:
            return False
        # Even a successful rm is not proof: inspect the exact id again.
        try:
            check = self._run_command(
                [self.docker, "inspect", "--format", "{{json .}}", object_id], deadline)
        except Exception:
            return False
        if self._returncode(check) == 0:
            record["last_error"] = "container still exists after removal"
            return False
        if not self._absent_result(check, object_id):
            record["last_error"] = "container absence could not be confirmed"
            return False
        with self._lock:
            record["removed"] = True
        return True

    def _stop_owned(self, deadline):
        with self._lock:
            handles = list(self._processes)
            creating = any(record.get("state") == "creating"
                           for record in self._records)
        stopped = True
        for handle in handles:
            result = handle.stop(deadline, self.clock)
            stopped = result and stopped
        return stopped and not creating

    def _mark_record_stopped(self, record):
        with self._lock:
            if record is not None:
                record["writes_stopped"] = True

    def _request_pause(self, record, deadline):
        """Ask the exact owned container to stop its in-container AFL writer.

        Only the fixed SIGUSR1 signal is sent to the exact inspected id after
        task/campaign/attempt/fence/owner labels are verified. A successful
        signal command is not itself proof that writes stopped; the supervisor's
        later payload is.
        """
        if not isinstance(record, dict):
            return False
        object_id = record.get("id")
        if not object_id:
            # The id is resolved once at spawn time and stays empty when that inspect
            # races container registration. Resolve it lazily here so a pause can still
            # signal its own container; the ledger name is ours and the labels are
            # verified by _inspect_container below.
            try:
                object_id = self._resolve_container_id(record.get("name"), deadline)
            except Exception:
                return False
            if not object_id:
                return False
            with self._lock:
                record["id"] = object_id
        try:
            status, info = self._inspect_container(object_id, record, deadline)
        except Exception:
            return False
        if status != "present" or not isinstance(info, dict):
            return False
        state = info.get("State")
        if not isinstance(state, dict) or state.get("Running") is not True:
            return False
        try:
            result = self._run_command(
                [self.docker, "kill", "--signal=USR1", object_id], deadline)
        except Exception:
            return False
        if self._returncode(result) != 0:
            return False
        with self._lock:
            record["pause_requested"] = True
        return True

    # ----- version/showmap/fuzz stages ------------------------------------
    def _stage_check(self, control):
        if control is None:
            return
        action, _ = control.snapshot()
        if action == "cancel":
            raise CampaignCancelled("cancel")
        if action == "pause":
            raise CampaignPaused("pause")

    def _run_help(self, request, control, deadline, entrypoint, expected_tool):
        if _remaining(deadline, self.clock) is not None and _remaining(deadline, self.clock) <= 0:
            raise CampaignBackendTimeout("deadline exhausted before tool probe")
        self._stage_check(control)
        name = self._container_name("help-" + expected_tool.rsplit("/", 1)[-1])
        record = self._spawn(name, entrypoint, ["-h"], deadline)
        handle = record["process"]
        state, code = handle.wait(deadline, self.clock, control)
        self._mark_record_stopped(record)
        if state == "cancel":
            raise CampaignCancelled("cancel")
        if state == "pause":
            raise CampaignPaused("pause")
        if state == "timeout":
            raise CampaignBackendTimeout("tool help probe exceeded the execution deadline")
        if state == "limited":
            raise CampaignBackendError("tool help output exceeded the bounded limit")
        remaining = _remaining(deadline, self.clock)
        out, err, cut, joined = handle.drain(0.2 if remaining is None else min(0.2, remaining))
        if not joined:
            raise CampaignOwnershipUnknown("tool help reader did not exit")
        if cut or len(out) + len(err) > MAX_HELP_OUTPUT:
            raise CampaignBackendError("tool help output exceeded the bounded limit")
        text = (out + b"\n" + err).decode("utf-8", "replace")
        # The help container is a transient owned resource; remove it now (and
        # re-check at final cleanup if the daemon cannot prove absence).
        try:
            if not self._remove_container(record, deadline):
                record["last_error"] = "tool help container cleanup unverified"
        except Exception:
            record["last_error"] = "tool help container cleanup unverified"
        if code is None:
            raise CampaignBackendError("tool help probe did not exit")
        return text

    def _probe_versions(self, request, control, deadline):
        fuzz_text = self._run_help(request, control, deadline, AFL_FUZZ, "afl-fuzz")
        required = ("-V seconds", "-E execs", "-G maxlength", "-i dir", "-o dir",
                    "-m megs", "-t msec")
        if not re.search(r"afl-fuzz\+\+", fuzz_text) or not all(
                item in fuzz_text for item in required):
            raise CampaignBackendError("afl-fuzz lacks a required bounded-campaign option")
        showmap_text = self._run_help(request, control, deadline, AFL_SHOWMAP, "afl-showmap")
        if not re.search(r"afl-showmap\+\+", showmap_text) or not all(
                item in showmap_text for item in ("-o file", "-q", "-m megs", "-t msec")):
            raise CampaignBackendError("afl-showmap lacks a required bounded-probe option")
        fuzz_version = TOOL_RE.search(fuzz_text)
        showmap_version = TOOL_RE.search(showmap_text)
        if not fuzz_version or not showmap_version:
            raise CampaignBackendError("AFL tool versions are unavailable")
        return {
            "afl_version": fuzz_version.group(1),
            "showmap_version": showmap_version.group(1),
            "options_verified": True,
        }

    def _seed_stdin(self, request, stream):
        seed = Path(self._staging) / "seeds" / "seed-00"
        try:
            return seed.open(stream)
        except Exception as exc:  # noqa: BLE001
            raise CampaignBackendError("cannot open staging seed") from exc

    def _probe_showmap(self, request, control, deadline):
        self._stage_check(control)
        seed_args = ["/work/seeds/seed-00" if item == "{input}" else item
                     for item in request["argv"]]
        args = ["-q", "-m", "256", "-t", "500", "-o", "/work/out/probe.map",
                "--", "/work/sample", *seed_args]
        name = self._container_name("probe")
        stdin_stream = request["input_mode"] == "stdin"
        stdin_handle = self._seed_stdin(request, "rb") if stdin_stream else None
        supervisor_args = ["-c", SUPERVISOR, "showmap", str(request["max_crashes"]),
                           AFL_SHOWMAP, *args]
        try:
            record = self._spawn(
                name, "/usr/bin/python3", supervisor_args, deadline,
                stdin_handle=stdin_handle, stdin_stream=stdin_stream)
            handle = record["process"]
            state, code = handle.wait(deadline, self.clock, control)
            self._mark_record_stopped(record)
        finally:
            if stdin_handle is not None:
                try:
                    stdin_handle.close()
                except Exception:
                    pass
        if state == "cancel":
            raise CampaignCancelled("cancel")
        if state == "pause":
            raise CampaignPaused("pause")
        if state == "timeout":
            raise CampaignBackendTimeout("instrumentation probe exceeded the execution deadline")
        if state == "limited":
            raise CampaignBackendError("instrumentation probe output exceeded the bounded limit")
        remaining = _remaining(deadline, self.clock)
        out, err, cut, joined = handle.drain(0.2 if remaining is None else min(0.2, remaining))
        if not joined:
            raise CampaignOwnershipUnknown("instrumentation probe reader did not exit")
        if cut:
            raise CampaignBackendError("instrumentation probe output exceeded the bounded limit")
        try:
            if not self._remove_container(record, deadline):
                record["last_error"] = "probe container cleanup unverified"
        except Exception:
            record["last_error"] = "probe container cleanup unverified"
        try:
            payload = json.loads(out.decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001
            raise CampaignBackendError("instrumentation probe returned no bounded payload") from exc
        if not isinstance(payload, dict) or payload.get("error"):
            raise CampaignBackendError("instrumentation probe failed")
        if payload.get("exit") != 0:
            raise CampaignBackendError("AFL instrumentation probe rejected the target")
        encoded = payload.get("probe_map_base64")
        if not isinstance(encoded, str):
            raise CampaignBackendError("instrumentation probe produced no map")
        try:
            data = base64.b64decode(encoded, validate=True)
        except Exception as exc:  # noqa: BLE001
            raise CampaignBackendError("probe map is not canonical base64") from exc
        if base64.b64encode(data).decode("ascii") != encoded:
            raise CampaignBackendError("probe map is not canonical base64")
        edges = coverage_edges_data(data)
        if edges <= 0:
            raise CampaignBackendError("no AFL instrumentation edges were observed")
        return edges

    def _worker_args(self, request, deadline):
        remaining = _remaining(deadline, self.clock)
        if remaining is None or remaining < 1.0:
            raise CampaignBackendTimeout("no bounded AFL window remains")
        seconds = max(1, int(remaining))
        # Validated file-mode argv uses exactly one whole {input}; AFL consumes
        # that input through its @@ placeholder. stdin mode has no placeholder.
        argv = ["@@" if item == "{input}" else item for item in request["argv"]]
        return ["-i", "/work/seeds", "-o", "/work/out/findings",
                "-V", str(seconds), "-E", str(max(1, request["max_executions"] - 1)),
                "-m", "256", "-t", "500", "-G", "4096", "-D",
                "--", "/work/sample", *argv]

    def _payload_object(self, output):
        if not output:
            return None
        if len(output) > MAX_PROCESS_OUTPUT:
            raise CampaignBackendError("AFL supervisor response exceeded the process bound")
        try:
            payload = json.loads(output.decode("utf-8", "replace"))
        except Exception as exc:  # noqa: BLE001
            raise CampaignBackendError("AFL supervisor returned malformed JSON") from exc
        if not isinstance(payload, dict):
            raise CampaignBackendError("AFL supervisor returned no object")
        if payload.get("error"):
            raise CampaignBackendError(
                "AFL supervisor failed: " + str(payload.get("error"))[:256])
        return payload

    def _payload_candidates(self, payload):
        stats = {}
        observed = 0
        candidates = []
        truncated = False
        if isinstance(payload, dict):
            raw_stats = payload.get("stats_base64")
            if isinstance(raw_stats, str):
                try:
                    stats_data = base64.b64decode(raw_stats, validate=True)
                except Exception:  # noqa: BLE001
                    stats_data = b""
                try:
                    stats = parse_stats(stats_data)
                except Exception:
                    stats = {}
                observed = stats.get("execs_done", 0)
            queue = payload.get("queue")
            crashes = payload.get("crashes")
            if isinstance(queue, list) and isinstance(crashes, list):
                if len(queue) > MAX_CHECKPOINT_ENTRIES or len(crashes) > MAX_CHECKPOINT_ENTRIES:
                    truncated = True
                for source_type, items in (("queue", queue), ("crash", crashes)):
                    for index, item in enumerate(items):
                        if not isinstance(item, dict):
                            raise CampaignBackendError("supervisor candidate is not an object")
                        try:
                            data = decode_candidate(item)
                        except Exception as exc:  # noqa: BLE001
                            raise CampaignBackendError(
                                "supervisor candidate is invalid") from exc
                        name = item.get("name")
                        source_ref = name if isinstance(name, str) and _SAFE_CANDIDATE.match(
                            name) else "id:%06d" % index
                        candidates.append({
                            "data": data, "source_type": source_type,
                            "source_ref": source_ref,
                        })
            if payload.get("truncated") is True:
                truncated = True
        kept, cut = self._bound_entries(candidates)
        with self._lock:
            self._checkpoint_memory = kept
            self._checkpoint_truncated = bool(truncated or cut)
        return stats, observed, candidates, bool(truncated or cut)

    def _run_worker(self, request, control, deadline):
        self._stage_check(control)
        name = self._container_name()
        args = self._worker_args(request, deadline)
        # Private campaign supervisor: it owns the AFL child process group and
        # can stop that group on SIGUSR1, then collect the already-written tmpfs
        # corpus. The old fuzz.SUPERVISOR behavior is untouched.
        supervisor_args = ["-c", PAUSE_SUPERVISOR, "fuzz-pause",
                           str(request["max_crashes"]), AFL_FUZZ, *args]
        record = self._spawn(name, "/usr/bin/python3", supervisor_args, deadline)
        handle = record["process"]
        if hasattr(handle, "wait_with_pause"):
            state, code = handle.wait_with_pause(
                deadline, self.clock, control,
                lambda: self._request_pause(record, deadline))
        else:
            state, code = handle.wait(deadline, self.clock, control)
            if state == "pause":
                if not self._request_pause(record, deadline):
                    handle.stop(deadline, self.clock)
                    raise CampaignPaused("pause not confirmed")
                state_after, code_after = handle.wait(deadline, self.clock, control)
                if state_after in ("pause", "pause_unconfirmed"):
                    handle.stop(deadline, self.clock)
                    raise CampaignPaused("pause not confirmed")
                state, code = state_after, code_after
        if state in ("pause", "pause_unconfirmed"):
            raise CampaignPaused("pause not confirmed")
        if state == "cancel":
            raise CampaignCancelled("cancel")
        if state == "timeout":
            raise CampaignBackendTimeout("AFL worker exceeded the execution deadline")
        if state == "limited":
            raise CampaignBackendError("AFL worker output exceeded the bounded limit")
        remaining = _remaining(deadline, self.clock)
        out, err, cut, joined = handle.drain(0.2 if remaining is None else min(0.2, remaining))
        if not joined:
            raise CampaignOwnershipUnknown("AFL worker reader did not exit")
        if cut:
            raise CampaignBackendError("AFL worker output exceeded the bounded limit")
        paused = bool(record.get("pause_requested")
                      or getattr(handle, "pause_requested", False))
        if paused:
            # A valid payload is the only pause evidence accepted. CLI exit or
            # a "pause" return alone never marks the writer stopped.
            try:
                payload = self._payload_object(out)
                if (not isinstance(payload, dict)
                        or payload.get("pause_handled") is not True
                        or payload.get("writes_stopped") is not True):
                    raise CampaignBackendError("pause supervisor did not confirm stopped writes")
                self._payload_candidates(payload)
            except Exception as exc:  # noqa: BLE001
                raise CampaignPaused("pause evidence invalid: " + str(exc)[:256]) from exc
            self._mark_record_stopped(record)
            raise CampaignPaused("paused")
        try:
            if not self._remove_container(record, deadline):
                record["last_error"] = "AFL worker container cleanup unverified"
        except Exception:
            record["last_error"] = "AFL worker container cleanup unverified"
        if code is None:
            raise CampaignBackendError("AFL worker did not exit")
        self._last_worker_record = record
        return code, out

    # ----- execute ---------------------------------------------------------
    def execute(self, request, control, deadline=None):
        self._bind(request)
        with self._lock:
            self._check_open_locked()
        now = self.clock()
        work = _absolute_deadline(deadline, now, request["cleanup_reserve_ms"] / 1000.0)
        with self._lock:
            self._check_open_locked()
        # 1. Artifact hash/architecture before any Docker command. The hash is
        #    checked first so a mismatch is rejected with zero commands.
        self._check_deadline(work, "artifact validation")
        data = self._verify_artifact(request)
        self._check_deadline(work, "artifact validation")
        with self._lock:
            self._check_open_locked()
        # 2. Immutable image identity before staging or containers.
        self._verify_image(request, work)
        # 3. Staging (self-created, nonce-named, no caller path).
        self._check_deadline(work, "staging")
        self._write_staging(request, data, work)
        self._check_deadline(work, "staging")
        # 4. Fixed version/options probe, consuming the same deadline.
        tool = self._probe_versions(request, control, work)
        self._check_deadline(work, "version probe")
        # 5. showmap instrumentation probe, same deadline.
        probe_edges = self._probe_showmap(request, control, work)
        self._check_deadline(work, "instrumentation probe")
        # 6. Exactly one AFL worker, same deadline.
        code, output = self._run_worker(request, control, work)
        result = self._parse_worker_result(
            request, output, code, tool, probe_edges,
            record=getattr(self, "_last_worker_record", None))
        with self._lock:
            self._result = result
            self._ownership = CLEANUP_OWNERSHIP_RUNNING
        return result

    def _parse_worker_result(self, request, output, code, tool, probe_edges,
                             record=None):
        payload = self._payload_object(output)
        stats, observed, candidates, truncated = self._payload_candidates(payload)
        state = "completed" if code == 0 else "failed"
        reason = None
        if state == "completed" and payload is None:
            state, reason = "failed", "no campaign evidence"
        if state == "completed" and payload is not None:
            if payload.get("findings") is not True and not candidates:
                state, reason = "failed", "no campaign evidence"
        if state == "completed" and truncated:
            state, reason = "failed", "campaign output exceeded bounds"
        if record is not None:
            self._mark_record_stopped(record)
        manifest = {
            "engine": "afl++",
            "artifact_sha256": request["sha256"],
            "image": request["profile"]["image"],
            "image_id": request["profile"]["image_id"],
            "input_mode": request["input_mode"],
            "afl_version": tool.get("afl_version"),
            "showmap_version": tool.get("showmap_version"),
            "options_verified": bool(tool.get("options_verified")),
            "probe_edges": probe_edges,
            "probe_executions": 1 if probe_edges else 0,
            "output_disk_limit_bytes": MAX_OUTPUT_DISK,
            "single_worker": True,
        }
        return {
            "target_state": state, "reason": reason, "manifest": manifest,
            "stats": stats, "observed_execs": observed,
            "observed_execs_trusted": False, "candidate_only": True,
            "authority": "candidate-only", "truncated": bool(truncated),
            "limited": bool(truncated),
            "cleanup": {"owned_process_terminated": False,
                        "container_removed": False, "staging_removed": False},
        }

    # ----- checkpoint ------------------------------------------------------
    @staticmethod
    def _bound_entries(entries):
        kept = []
        seen = set()
        total = 0
        truncated = False
        for item in entries:
            data = item["data"]
            if not isinstance(data, (bytes, bytearray)) or not 1 <= len(data) <= MAX_CHECKPOINT_ITEM:
                raise ValueError("checkpoint entry data is invalid")
            source_type = item.get("source_type")
            if source_type not in ("seed", "queue", "crash", "import"):
                raise ValueError("checkpoint entry source_type is invalid")
            source_ref = item.get("source_ref")
            if (not isinstance(source_ref, str) or not source_ref
                    or len(source_ref) > 256 or "\\" in source_ref
                    or source_ref.startswith("/") or "\x00" in source_ref):
                raise ValueError("checkpoint source_ref is not a bounded relative name")
            for character in source_ref:
                code = ord(character)
                if code < 0x20 or code == 0x7f or 0xd800 <= code <= 0xdfff:
                    raise ValueError("checkpoint source_ref has a control/surrogate")
            if (len(source_ref) >= 2 and source_ref[0].isascii()
                    and source_ref[0].isalpha() and source_ref[1] == ":"):
                raise ValueError("checkpoint source_ref must not be a drive path")
            if any(part in ("", ".", "..") for part in source_ref.split("/")):
                raise ValueError("checkpoint source_ref traversal is not allowed")
            digest = hashlib.sha256(data).hexdigest()
            key = (digest, len(data))
            if key in seen:
                continue
            if len(kept) >= MAX_CHECKPOINT_ENTRIES or total + len(data) > MAX_CHECKPOINT_BYTES:
                truncated = True
                break
            seen.add(key)
            total += len(data)
            kept.append({"data": bytes(data),
                         "source_type": source_type,
                         "source_ref": source_ref})
        return kept, truncated

    def _scan_checkpoint_tree(self, deadline):
        stage = self._staging
        if stage is None:
            return [], False
        root = Path(stage) / "collect"
        try:
            st = root.lstat()
        except FileNotFoundError:
            return [], False
        except OSError:
            raise ValueError("checkpoint collector is inaccessible")
        if _is_link(st) or not stat.S_ISDIR(st.st_mode):
            raise ValueError("checkpoint collector is not a real directory")
        end = self.clock() + MAX_SCAN_SECONDS
        if deadline is not None:
            end = min(end, deadline)
        entries = []
        total = 0
        scan_bytes = 0
        count = 0
        truncated = False
        stack = [(root, 0, ())]
        while stack:
            directory, depth, relative = stack.pop()
            if self.clock() >= end:
                truncated = True
                break
            if depth > MAX_SCAN_DEPTH:
                raise ValueError("checkpoint collector is too deep")
            try:
                iterator = os.scandir(directory)
            except OSError as exc:
                raise ValueError("checkpoint collector cannot be enumerated") from exc
            with iterator:
                for child in iterator:
                    count += 1
                    if count > MAX_SCAN_ENTRIES:
                        truncated = True
                        break
                    if self.clock() >= end:
                        truncated = True
                        break
                    try:
                        info = child.stat(follow_symlinks=False)
                    except OSError as exc:
                        raise ValueError("checkpoint entry disappeared") from exc
                    if _is_link(info):
                        raise ValueError("linked checkpoint entry rejected")
                    parts = relative + (child.name,)
                    if stat.S_ISDIR(info.st_mode):
                        if len(parts) > 2 or parts[0] not in ("queue", "crashes"):
                            raise ValueError("unexpected checkpoint directory")
                        stack.append((Path(child.path), depth + 1, parts))
                        continue
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError("special checkpoint entry rejected")
                    if getattr(info, "st_nlink", 1) > 1:
                        raise ValueError("hard-linked checkpoint entry rejected")
                    if len(parts) != 2 or parts[0] not in ("queue", "crashes"):
                        raise ValueError("unexpected checkpoint file")
                    if not _SAFE_CANDIDATE.match(parts[1]):
                        raise ValueError("malicious checkpoint name rejected")
                    if info.st_size < 1 or info.st_size > MAX_CHECKPOINT_ITEM:
                        truncated = True
                        continue
                    if (len(entries) >= MAX_CHECKPOINT_ENTRIES
                            or total + info.st_size > MAX_CHECKPOINT_BYTES
                            or scan_bytes + info.st_size > MAX_SCAN_BYTES):
                        truncated = True
                        break
                    data = regular_bytes(Path(child.path), MAX_CHECKPOINT_ITEM)
                    scan_bytes += len(data)
                    entries.append({
                        "data": data,
                        "source_type": "queue" if parts[0] == "queue" else "crash",
                        "source_ref": parts[1],
                    })
                    total += len(data)
            if truncated:
                break
        return entries, truncated

    def checkpoint(self, request, deadline=None):
        self._bind(request)
        now = self.clock()
        end = _absolute_deadline(deadline, now, MAX_SCAN_SECONDS)
        if self._management_pending():
            raise CampaignBackendError("checkpoint refused while management is in flight")
        with self._lock:
            handles = list(self._processes)
            records = list(self._records)
            if any(record.get("state") == "creating" for record in records):
                raise CampaignBackendError("checkpoint refused during container creation")
            if any(not handle.finished() for handle in handles):
                raise CampaignBackendError("checkpoint refused while owned writer is live")
            if any(record.get("started") and not record.get("removed")
                   and not record.get("writes_stopped") for record in records):
                raise CampaignBackendError("checkpoint refused before owned writes stopped")
            memory = list(self._checkpoint_memory)
            truncated = self._checkpoint_truncated
        try:
            scanned, scan_cut = self._scan_checkpoint_tree(end)
        except ValueError:
            raise
        entries = scanned + memory
        if not entries:
            for index, seed in enumerate(request["seeds"]):
                entries.append({"data": seed["data"], "source_type": "seed",
                                "source_ref": "seed:%d" % index})
        kept, cut = self._bound_entries(entries)
        with self._lock:
            self._checkpoint_truncated = bool(truncated or scan_cut or cut)
        return kept

    # ----- cleanup / stop / ownership -------------------------------------
    def _safe_staging(self, path):
        try:
            candidate = Path(path)
            if not candidate.is_absolute():
                return False
            parent = os.path.realpath(str(candidate.parent))
            if parent != self._temp_root_real:
                return False
            if self._staging_prefix:
                prefix = self._staging_prefix
            elif self._request is not None:
                prefix = "artex-campaign-%d-%d-%s-" % (
                    self._request["campaign_id"], self._request["attempt_id"],
                    _nonce(self._request))
            else:
                return False
            if not candidate.name.startswith(prefix):
                return False
            st = candidate.lstat()
            return not _is_link(st) and stat.S_ISDIR(st.st_mode)
        except (OSError, ValueError):
            return False

    def _trusted_staging_path(self, path, extra_root=None):
        try:
            candidate = Path(path)
            if not candidate.is_absolute():
                return False
            allowed = {self._temp_root_real,
                       os.path.realpath(tempfile.gettempdir())}
            if isinstance(extra_root, str) and os.path.isabs(extra_root):
                allowed.add(os.path.realpath(extra_root))
            parent = os.path.realpath(str(candidate.parent))
            if parent not in allowed:
                return False
            if self._staging_prefix:
                prefix = self._staging_prefix
            elif self._request is not None:
                prefix = "artex-campaign-%d-%d-%s-" % (
                    self._request["campaign_id"], self._request["attempt_id"],
                    _nonce(self._request))
            else:
                return False
            return candidate.name.startswith(prefix)
        except (OSError, ValueError):
            return False

    def _remove_staging(self, deadline):
        with self._lock:
            stage = self._staging
        if stage is None:
            return True
        if deadline is not None and _remaining(deadline, self.clock) is not None \
                and _remaining(deadline, self.clock) <= 0:
            return False
        if not self._safe_staging(stage):
            return False
        try:
            removed = remove_staging(stage)
        except Exception:
            removed = False
        return bool(removed and not stage.exists() and not stage.is_symlink())

    def cleanup(self, request, deadline=None):
        self._bind(request)
        now = self.clock()
        hard = min(self.cleanup_hard_timeout,
                   float(request.get("cleanup_hard_timeout_ms", 60000)) / 1000.0)
        end = _absolute_deadline(deadline, now, hard)
        end = min(end, now + hard)
        # Refuse new creation immediately; then take the ledger lock with the
        # same hard deadline so a blocked Popen/start cannot hang cleanup.
        self._closing.set()
        self._closed = True
        remaining = _remaining(end, self.clock)
        acquired = self._lock.acquire(timeout=max(0.0, remaining or 0.0))
        if not acquired:
            report = self._cleanup_report_for(False, False, False,
                                              ["cleanup_timeout"], True)
            self._ownership = CLEANUP_OWNERSHIP_UNKNOWN
            return report
        try:
            if self._cleanup_verified and self._cleanup_report is not None:
                return dict(self._cleanup_report)
            self._cleanup_started = True
        finally:
            self._lock.release()
        if end <= self.clock():
            report = self._cleanup_report_for(False, False, False, ["cleanup_timeout"], True)
            with self._lock:
                self._ownership = CLEANUP_OWNERSHIP_UNKNOWN
            return report
        stopped_owned = self._stop_owned(end)
        stopped_mgmt = self._stop_management(end)
        pending = self._management_pending()
        with self._lock:
            creating = any(record.get("state") == "creating"
                           for record in self._records)
        if not stopped_owned or not stopped_mgmt or pending or creating:
            errors = []
            if not stopped_owned or creating:
                errors.append("owned_process_not_terminated")
            if not stopped_mgmt or pending:
                errors.append("management_not_terminated")
            report = self._cleanup_report_for(False, False, False, errors, False)
            self._ownership = CLEANUP_OWNERSHIP_UNKNOWN
            return report
        with self._lock:
            records = list(self._records)
        container_ok = True
        container_reports = []
        for record in records:
            removed = self._remove_container(record, end)
            container_ok = removed and container_ok
            container_reports.append({
                "name": record.get("name"),
                "state": "absent" if removed else "unknown",
                "labels_match": True if removed else False,
            })
        staging_ok = self._remove_staging(end)
        errors = []
        if not container_ok:
            errors.append("container_absence_unverified")
        if not staging_ok:
            errors.append("staging_removal_unverified")
        report = {
            "owned_process_terminated": bool(stopped_owned and stopped_mgmt),
            "container_removed": bool(container_ok),
            "staging_removed": bool(staging_ok),
            "containers": container_reports[:MAX_CONTAINERS],
            "staging": {"present": not staging_ok, "removed": bool(staging_ok)},
            "errors": errors,
            "hard_timeout": False,
        }
        verified = bool(stopped_owned and stopped_mgmt and container_ok
                        and staging_ok and not errors)
        with self._lock:
            self._cleanup_report = report
            self._cleanup_verified = verified
            self._ownership = (CLEANUP_OWNERSHIP_TERMINATED if verified
                               else CLEANUP_OWNERSHIP_UNKNOWN)
        return report

    def _cleanup_report_for(self, stopped, containers, staging, errors, hard):
        return {
            "owned_process_terminated": bool(stopped),
            "container_removed": bool(containers),
            "staging_removed": bool(staging),
            "containers": [],
            "staging": {"present": not staging, "removed": bool(staging)},
            "errors": list(errors),
            "hard_timeout": bool(hard),
        }

    def _container_settled(self, record, deadline):
        """Prove an owned container is gone without deleting it."""
        if record.get("removed"):
            return True
        object_id = record.get("id")
        if object_id is None:
            try:
                object_id = self._resolve_container_id(record.get("name"), deadline)
            except Exception:
                return False
            if object_id is None:
                return False
            with self._lock:
                record["id"] = object_id
        try:
            status, _ = self._inspect_container(object_id, record, deadline)
        except Exception:
            return False
        return status == "absent"

    def stop(self, request, timeout, deadline=None):
        self._bind(request)
        now = self.clock()
        limit = max(0.0, float(timeout))
        end = now + limit
        if deadline is not None:
            end = min(end, _absolute_deadline(deadline, now, limit))
        if end <= self.clock():
            return False
        acquired = self._lock.acquire(timeout=max(0.0, end - self.clock()))
        if not acquired:
            return False
        try:
            self._stop_requested = True
        finally:
            self._lock.release()
        if not self._stop_owned(end):
            return False
        if not self._stop_management(end):
            return False
        with self._lock:
            records = list(self._records)
            creating = any(record.get("state") == "creating"
                           for record in records)
        if creating:
            return False
        for record in records:
            if not self._container_settled(record, end):
                return False
        return True

    def ownership(self, request):
        self._bind(request)
        acquired = self._lock.acquire(timeout=0.1)
        if not acquired:
            return CLEANUP_OWNERSHIP_RUNNING
        try:
            handles = list(self._processes)
            records = list(self._records)
            cleaned = self._cleanup_verified
            staging = self._staging
            started = self._started
        finally:
            self._lock.release()
        if self._management_pending():
            return CLEANUP_OWNERSHIP_RUNNING
        if any(record.get("state") == "creating" for record in records):
            return CLEANUP_OWNERSHIP_RUNNING
        live = any(not handle.finished() for handle in handles)
        if live:
            return CLEANUP_OWNERSHIP_RUNNING
        if any(not record.get("removed") for record in records):
            return CLEANUP_OWNERSHIP_RUNNING if started else CLEANUP_OWNERSHIP_UNKNOWN
        if staging is not None and staging.exists():
            return CLEANUP_OWNERSHIP_RUNNING
        if cleaned:
            return CLEANUP_OWNERSHIP_TERMINATED
        if started:
            return CLEANUP_OWNERSHIP_UNKNOWN
        return CLEANUP_OWNERSHIP_UNKNOWN

    def status(self, request):
        self._bind(request)
        acquired = self._lock.acquire(timeout=0.1)
        if not acquired:
            return {"state": "unknown", "ownership": CLEANUP_OWNERSHIP_RUNNING,
                    "containers": -1, "processes": -1, "management": -1}
        try:
            with self._management_lock:
                management_count = len(self._management)
            return {
                "state": "cleaned" if self._cleanup_verified else (
                    "cleaning" if self._cleanup_started else (
                        "running" if self._started else "idle")),
                "ownership": self._ownership,
                "containers": len(self._records),
                "processes": len(self._processes),
                "management": management_count,
            }
        finally:
            self._lock.release()

    # ----- cleanup probe ---------------------------------------------------
    def close_creation_resources(self):
        """Close admission and return proven IDs, or no evidence.

        This is not a durable seal or cleanup authorization. The caller must
        still bind these resources and staging to the server's stored plan.
        A reaped CLI or absent name never fills in missing positive evidence.
        """
        with self._lock:
            self._closing.set()
            if not self._records or self._management_pending():
                return None
            if any(not handle.finished() for handle in self._processes):
                return None
            resources = []
            for record in self._records:
                object_id = record.get("id")
                handle = record.get("process")
                if (record.get("state") == "creating" or handle is None
                        or not handle.finished()
                        or not isinstance(object_id, str)
                        or re.fullmatch(r"[0-9a-f]{64}", object_id) is None
                        or record.get("verified_creation_id") != object_id):
                    return None
                resources.append({"name": record["name"], "id": object_id,
                                  "labels": dict(record.get("labels") or {})})
            return resources

    def creation_seal(self, request):
        plan = request.get("resource_plan")
        if plan is None:
            return None
        validate_resource_plan(plan, request)
        resources = self.close_creation_resources()
        if resources is None:
            return None
        with self._lock:
            if (self._staging is None or str(self.temp_root) != plan["staging_root"]
                    or str(self._staging) != str(Path(plan["staging_root"]) / plan["staging_basename"])):
                return None
            expected = _expected_labels(request)
            if any(item["name"] not in plan["container_names"] or item["labels"] != expected
                   for item in resources):
                return None
            return {"version": 1, "task_id": request["task_id"],
                    "campaign_id": request["campaign_id"], "attempt_id": request["attempt_id"],
                    "fencing_token": request["fencing_token"], "plan_sha256": resource_plan_digest(plan),
                    "staging_basename": plan["staging_basename"], "containers": resources}

    def ownership_snapshot(self, request=None):
        if request is not None:
            self._bind(request)
        with self._lock:
            if self._request is None:
                return None
            if not self._records and self._staging is None:
                # No trusted nonce/staging record exists in this process; never
                # claim absence by guessing a path or an empty resource set.
                return None
            request = self._request
            return {
                "trusted": True,
                "task_id": request["task_id"],
                "campaign_id": request["campaign_id"],
                "attempt_id": request["attempt_id"],
                "fencing_token": request["fencing_token"],
                "temp_root": str(self.temp_root),
                "containers": [
                    {"name": record["name"], "id": record.get("id"),
                     "labels": dict(record.get("labels") or {})}
                    for record in self._records
                ],
                "staging": str(self._staging) if self._staging is not None else None,
            }

    @staticmethod
    def _snapshot_identity_ok(snapshot, request):
        return (isinstance(snapshot, dict) and snapshot.get("trusted") is True
                and snapshot.get("task_id") == request["task_id"]
                and snapshot.get("campaign_id") == request["campaign_id"]
                and snapshot.get("attempt_id") == request["attempt_id"]
                and snapshot.get("fencing_token") == request["fencing_token"])

    def _probe_staging(self, snapshot, request, deadline):
        path = snapshot.get("staging")
        if path is None:
            return True, {"present": False, "removed": True}
        if (not isinstance(path, str)
                or not self._trusted_staging_path(path, snapshot.get("temp_root"))):
            return False, {"present": True, "removed": False}
        candidate = Path(path)
        try:
            st = candidate.lstat()
        except FileNotFoundError:
            return True, {"present": False, "removed": True}
        except OSError:
            return False, {"present": True, "removed": False}
        if _is_link(st) or not stat.S_ISDIR(st.st_mode):
            return False, {"present": True, "removed": False}
        removed = self._remove_probe_staging(path, snapshot.get("temp_root"))
        return removed, {"present": not removed, "removed": removed}

    def _remove_probe_staging(self, path, extra_root):
        try:
            stage = Path(path)
            if not self._trusted_staging_path(stage, extra_root):
                return False
            removed = remove_staging(stage)
            return bool(removed and not stage.exists() and not stage.is_symlink())
        except Exception:
            return False

    def _discover_sealed_containers(self, request, seal, deadline):
        command = [self.docker, "ps", "-a", "-q", "--no-trunc"]
        for key, value in sorted(_expected_labels(request).items()):
            command.extend(["--filter", "label=" + key + "=" + value])
        result = self._run_command(command, deadline)
        if self._returncode(result) != 0 or self._stderr(result).strip():
            raise CampaignOwnershipUnknown("container discovery failed")
        output = self._stdout(result).strip()
        ids = output.splitlines() if output else []
        allowed = {item["id"] for item in seal["containers"]}
        if (len(ids) > 8 or len(set(ids)) != len(ids)
                or any(re.fullmatch(r"[0-9a-f]{64}", value) is None or value not in allowed
                       for value in ids)):
            raise CampaignOwnershipUnknown("container discovery exceeds the sealed resource set")
        return ids

    def _remove_planned_staging(self, plan, deadline):
        root_fd = self._open_planned_root(plan)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        count = [0]
        def remove_dir(parent, name, depth):
            self._check_deadline(deadline, "sealed staging cleanup")
            if depth > 8:
                raise CampaignOwnershipUnknown("staging depth exceeds cleanup bound")
            fd = os.open(name, flags, dir_fd=parent)
            try:
                original = os.fstat(fd)
                # The private top-level capability contains read-only 0755
                # seed directories bind-mounted for container UID 65534.
                # Nested directories may be traversable, never writable by
                # group/other users; do not chmod the real execution layout.
                forbidden = 0o077 if depth == 0 else 0o022
                if original.st_uid != os.geteuid() or original.st_mode & forbidden:
                    raise CampaignOwnershipUnknown("staging directory permissions are unsafe")
                with os.scandir(fd) as entries:
                    for entry in entries:
                        self._check_deadline(deadline, "sealed staging cleanup")
                        count[0] += 1
                        if count[0] > MAX_SCAN_ENTRIES:
                            raise CampaignOwnershipUnknown("staging entries exceed cleanup bound")
                        info = os.stat(entry.name, dir_fd=fd, follow_symlinks=False)
                        if stat.S_ISDIR(info.st_mode):
                            remove_dir(fd, entry.name, depth + 1)
                        elif (stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                              and info.st_uid == os.geteuid()):
                            os.unlink(entry.name, dir_fd=fd)
                        else:
                            raise CampaignOwnershipUnknown("staging contains an unsafe node")
                current = os.stat(name, dir_fd=parent, follow_symlinks=False)
                if (current.st_dev, current.st_ino) != (original.st_dev, original.st_ino):
                    raise CampaignOwnershipUnknown("staging directory identity changed")
                os.rmdir(name, dir_fd=parent)
            finally:
                os.close(fd)
        try:
            try:
                os.stat(plan["staging_basename"], dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                return True
            remove_dir(root_fd, plan["staging_basename"], 0)
            try:
                os.stat(plan["staging_basename"], dir_fd=root_fd, follow_symlinks=False)
            except FileNotFoundError:
                return True
            return False
        finally:
            os.close(root_fd)

    def _probe_sealed_cleanup(self, request, deadline):
        started = self.clock()
        plan = validate_resource_plan(request["resource_plan"], request)
        seal = validate_creation_seal(request["creation_seal"], plan, request)
        self._closing.set()
        report = {"cleanup_verified": False, "containers": [],
                  "staging": {"present": True, "removed": False}, "errors": [],
                  "hard_timeout": False, "elapsed_ms": 0,
                  "plan_sha256": seal["plan_sha256"], "staging_basename": plan["staging_basename"]}
        try:
            # Verify the configured private root before any Docker side effect.
            root_fd = self._open_planned_root(plan)
            os.close(root_fd)
            with self._lock:
                pending_create = any(item.get("state") == "creating" for item in self._records)
                live_process = any(not item.finished() for item in self._processes)
            if self._management_pending() or pending_create or live_process:
                raise CampaignOwnershipUnknown("cleanup still has live owners")
            self._discover_sealed_containers(request, seal, deadline)
            for item in seal["containers"]:
                record = dict(item, removed=False, process=None, failed="")
                removed = self._remove_container(record, deadline)
                report["containers"].append({"name": item["name"], "id": item["id"],
                    "state": "absent" if removed else "unknown", "labels_match": removed})
                if not removed:
                    raise CampaignOwnershipUnknown("sealed container absence unverified")
            if self._discover_sealed_containers(request, seal, deadline):
                raise CampaignOwnershipUnknown("sealed containers remain after cleanup")
            if not self._remove_planned_staging(plan, deadline):
                raise CampaignOwnershipUnknown("sealed staging absence unverified")
            if self._management_pending():
                raise CampaignOwnershipUnknown("cleanup management ownership unresolved")
            self._check_deadline(deadline, "sealed cleanup verification")
            report["staging"] = {"present": False, "removed": True}
            report["cleanup_verified"] = True
        except Exception as exc:
            report["errors"] = [str(exc)[:256]]
            report["hard_timeout"] = isinstance(exc, CampaignBackendTimeout)
        report["elapsed_ms"] = max(0, int((self.clock() - started) * 1000))
        return report

    def probe_cleanup(self, request, timeout, ownership_snapshot=None):
        self._bind(request)
        now = self.clock()
        limit = min(float(timeout), CLEANUP_HARD_TIMEOUT)
        end = now + max(0.0, limit)
        if "resource_plan" in request or "creation_seal" in request:
            if "resource_plan" not in request or "creation_seal" not in request:
                raise CampaignOwnershipUnknown("sealed cleanup requires plan and seal")
            return self._probe_sealed_cleanup(request, end)
        if self._management_pending():
            return {
                "cleanup_verified": False,
                "containers": [],
                "staging": {"present": True, "removed": False},
                "errors": ["management_unknown"],
                "hard_timeout": False,
                "elapsed_ms": 0,
            }
        with self._lock:
            creating = any(record.get("state") == "creating"
                           for record in self._records)
        if creating:
            return {
                "cleanup_verified": False,
                "containers": [],
                "staging": {"present": True, "removed": False},
                "errors": ["creation_unknown"],
                "hard_timeout": False,
                "elapsed_ms": 0,
            }
        snapshot = ownership_snapshot
        if snapshot is None:
            snapshot = self._snapshot_hint
        if snapshot is None:
            snapshot = self.ownership_snapshot()
        if not self._snapshot_identity_ok(snapshot, request):
            return {
                "cleanup_verified": False,
                "containers": [],
                "staging": {"present": True, "removed": False},
                "errors": ["ownership_unknown"],
                "hard_timeout": False,
                "elapsed_ms": 0,
            }
        if end <= now:
            return {
                "cleanup_verified": False,
                "containers": [],
                "staging": {"present": True, "removed": False},
                "errors": ["cleanup_timeout"],
                "hard_timeout": True,
                "elapsed_ms": 0,
            }
        errors = []
        container_reports = []
        all_ok = True
        raw_containers = snapshot.get("containers")
        if not isinstance(raw_containers, list) or len(raw_containers) > MAX_CONTAINERS:
            errors.append("ownership containers are invalid")
            raw_containers = []
            all_ok = False
        expected = _expected_labels(request)
        for item in raw_containers:
            if not isinstance(item, dict):
                errors.append("ownership container is invalid")
                all_ok = False
                continue
            name = item.get("name")
            object_id = item.get("id")
            labels = item.get("labels")
            if not isinstance(labels, dict) or not labels:
                labels = expected
            elif any(labels.get(key) != expected[key] for key in _LABEL_KEYS):
                errors.append("ownership labels do not match the attempt")
                all_ok = False
                container_reports.append({"name": name, "state": "unknown",
                                          "labels_match": False})
                continue
            if not isinstance(name, str) or not name or not isinstance(object_id, str) or not object_id:
                errors.append("ownership container lacks a trusted id")
                all_ok = False
                container_reports.append({"name": name, "state": "unknown",
                                          "labels_match": False})
                continue
            record = {"name": name, "id": object_id, "labels": labels,
                      "removed": False, "process": None, "failed": ""}
            # The probe has no process/target capability; only inspect/remove.
            removed = self._remove_container(record, end)
            all_ok = removed and all_ok
            container_reports.append({
                "name": name,
                "state": "absent" if removed else "unknown",
                "labels_match": True if removed else False,
            })
        staging_ok, staging = self._probe_staging(snapshot, request, end)
        all_ok = all_ok and staging_ok
        if not container_reports and not staging_ok and not errors:
            errors.append("staging_removal_unverified")
        if not container_reports and not errors and snapshot.get("staging") is None:
            # A trusted snapshot that explicitly records no resources proves
            # absence without guessing any path.
            all_ok = True
        if not all_ok and not errors:
            errors.append("cleanup_unverified")
        return {
            "cleanup_verified": bool(all_ok and not errors),
            "containers": container_reports,
            "staging": staging,
            "errors": errors[:32],
            "hard_timeout": False,
            "elapsed_ms": max(0, int((self.clock() - now) * 1000)),
        }


# Explicit aliases for callers/tests that use a descriptive engine name.  There
# is deliberately no module-level factory and no serve_campaign default wiring.
DockerAflCampaignBackend = DockerCampaignBackend
NativeDockerCampaignBackend = DockerCampaignBackend
