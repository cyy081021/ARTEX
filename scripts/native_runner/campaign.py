"""T4b-1 native campaign protocol/control kernel.

This module is deliberately backend-neutral. It validates the strict campaign
start/control wire, runs an injectable backend, enforces the bounded execution
and lease deadlines, and emits one bounded final frame. No Docker, AFL, GDB or
real target is started here. The production default backend is explicitly
unavailable: only tests inject a synthetic backend, and a missing backend never
claims execution or verified cleanup.
"""
import base64
import collections
import datetime
import hashlib
import inspect
import json
import posixpath
import threading
import time

from .protocol import MAX_FRAME

MAX_SEEDS = 32
MAX_SEED = 4096
MAX_SEED_TOTAL = 65536
MAX_ARGV = 64
MAX_CHECKPOINT_ENTRIES = 512
MAX_CHECKPOINT_BYTES = 1024 * 1024
MAX_CHECKPOINT_CHUNK_ENTRIES = 32
MAX_CHECKPOINT_CHUNK_BYTES = 512 * 1024
MAX_FINAL = 256 * 1024
MAX_ERRORS = 32
MAX_ERROR = 512
MAX_CONTAINERS = 64
# Attempt-lifetime control ledger. The bound covers the 900s maximum attempt at
# a conservative multi-control-per-second rate, but is strict: once full, new
# request ids fail closed instead of evicting old ids (which would make a replay
# look like a fresh command and re-apply side effects).
MAX_CONTROL_CACHE = 4096
CHECKPOINT_SOURCE_TYPES = frozenset(("seed", "queue", "crash", "import"))
_ASCII_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_CANONICAL_JSON_ESCAPES = {
    '"': '\\"', "\\": "\\\\", "\b": "\\b", "\f": "\\f",
    "\n": "\\n", "\r": "\\r", "\t": "\\t",
}
CLEANUP_OWNERSHIP_TERMINATED = "terminated"
CLEANUP_OWNERSHIP_RUNNING = "running"
CLEANUP_OWNERSHIP_UNKNOWN = "unknown"

START_FIELDS = {
    "operation", "task_id", "request_id", "campaign_id", "attempt_id",
    "attempt_no", "fencing_token", "lease_owner", "lease_instance", "lease_ms", "lease_deadline",
    "artifact_path", "sha256", "argv", "input_mode", "seeds", "max_executions",
    "max_crashes", "attempt_budget_ms", "execution_window_ms",
    "execution_deadline", "envelope_deadline", "cleanup_reserve_ms",
    "cleanup_hard_timeout_ms", "profile", "resource_plan",
}
PROFILE_FIELDS = {
    "image", "image_id", "fuzz_enabled", "enabled", "network",
    "read_only_root", "max_duration_ms",
}
SEED_FIELDS = {"sha256", "data_base64", "source_type", "source_ref"}
CLEANUP_PROBE_FIELDS = {
    "operation", "request_id", "task_id", "campaign_id", "attempt_id",
    "fencing_token",
}
CONTROL_FIELDS = {
    "heartbeat": {"request_id", "action", "lease_ms", "lease_deadline"},
    "pause": {"request_id", "action", "reason"},
    "cancel": {"request_id", "action", "reason"},
    "status": {"request_id", "action"},
}
CLEANUP_KEYS = ("owned_process_terminated", "container_removed", "staging_removed")
FINAL_STATES = {"completed", "failed", "cancelled", "paused", "interrupted", "timeout"}


class CampaignBackendUnavailable(RuntimeError):
    pass


class CampaignBackendTimeout(TimeoutError):
    pass


class CampaignCancelled(Exception):
    pass


class CampaignPaused(Exception):
    pass


def _object_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _no_constant(value):
    raise ValueError("non-finite JSON number")


def strict_json_object(raw):
    if isinstance(raw, bytes):
        raw = raw.decode("utf-8")
    value = json.loads(raw, object_pairs_hook=_object_pairs, parse_constant=_no_constant)
    if not isinstance(value, dict):
        raise ValueError("frame must be a JSON object")
    return value


def read_campaign_frame(stream):
    """Independent strict JSONL reader; never changes protocol.read_frame."""
    line = stream.readline(MAX_FRAME + 1)
    if not line:
        return None
    newline = b"\n" if isinstance(line, bytes) else "\n"
    if len(line) > MAX_FRAME or not line.endswith(newline):
        raise ValueError("protocol frame exceeds 1048576 bytes or is unterminated")
    return strict_json_object(line)


def _require_fields(value, allowed, required, label):
    if not isinstance(value, dict):
        raise ValueError(label + " must be an object")
    if set(value) - allowed:
        raise ValueError(label + " has an unknown field")
    missing = required - set(value)
    if missing:
        raise ValueError(label + " is missing a required field")


def _string(value, label, maximum, allow_empty=False):
    if not isinstance(value, str) or len(value) > maximum or "\x00" in value:
        raise ValueError(label + " is invalid")
    if not allow_empty and not value:
        raise ValueError(label + " is empty")
    return value


def _integer(value, low, high, label):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ValueError(label + " is outside allowed bounds")
    return value


def _digest(value, label):
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(label + " must be a lowercase SHA-256")
    if any(ch not in "0123456789abcdef" for ch in value):
        raise ValueError(label + " must be a lowercase SHA-256")
    return value


def _source_type(value, label):
    if not isinstance(value, str) or value not in CHECKPOINT_SOURCE_TYPES:
        raise ValueError(label + " source_type must be seed/queue/crash/import")
    return value


def _source_ref(value, label):
    """Validate a bounded, task-relative source name without touching the path.

    Only a relative logical name is accepted. POSIX absolute names, Windows
    drive-absolute/UNC names, backslash aliases, NUL/C0/DEL controls, lone
    surrogates, empty/`.`/`..` components and over-long values are rejected.
    """
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError(label + " source_ref is invalid")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(label + " source_ref is not valid UTF-8") from exc
    for ch in value:
        code = ord(ch)
        if code < 0x20 or code == 0x7f or 0xd800 <= code <= 0xdfff:
            raise ValueError(label + " source_ref has a control/surrogate character")
    if "\\" in value or value.startswith("/"):
        raise ValueError(label + " source_ref must be a relative name")
    if len(value) >= 2 and value[0] in _ASCII_LETTERS and value[1] == ":":
        raise ValueError(label + " source_ref must not be a drive path")
    for part in value.split("/"):
        if part in ("", ".", ".."):
            raise ValueError(label + " source_ref traversal is not allowed")
    return value


def _canonical_string(value):
    if not isinstance(value, str):
        raise ValueError("canonical JSON string must be text")
    out = ['"']
    for ch in value:
        code = ord(ch)
        if 0xd800 <= code <= 0xdfff:
            raise ValueError("canonical JSON string has a lone surrogate")
        escaped = _CANONICAL_JSON_ESCAPES.get(ch)
        if escaped is not None:
            out.append(escaped)
        elif code < 0x20:
            out.append("\\u%04x" % code)
        else:
            # Valid non-ASCII UTF-8 is emitted verbatim (no HTML escaping and
            # no U+2028/U+2029 escaping) so Go and Python hash identical bytes.
            out.append(ch)
    out.append('"')
    return "".join(out)


def _canonical_json(value):
    if isinstance(value, dict):
        parts = []
        for key in sorted(value, key=lambda item: item.encode("utf-8")):
            parts.append(_canonical_string(key) + ":" + _canonical_json(value[key]))
        return "{" + ",".join(parts) + "}"
    if isinstance(value, list):
        return "[" + ",".join(_canonical_json(item) for item in value) + "]"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return _canonical_string(value)
    raise ValueError("unsupported canonical JSON value")


def _parse_deadline(value, label):
    _string(value, label, 64)
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError(label + " is not RFC3339") from exc
    if parsed.tzinfo is None:
        raise ValueError(label + " must carry a timezone")
    return parsed.timestamp()


def _canonical_seed(seed, label):
    if not isinstance(seed, dict) or set(seed) - SEED_FIELDS or not {"sha256", "data_base64"} <= set(seed):
        raise ValueError(label + " has invalid fields")
    encoded = seed["data_base64"]
    if not isinstance(encoded, str):
        raise ValueError(label + " is not base64")
    try:
        data = base64.b64decode(encoded, validate=True)
    except Exception as exc:
        raise ValueError(label + " is not canonical base64") from exc
    if base64.b64encode(data).decode("ascii") != encoded:
        raise ValueError(label + " is not canonical base64")
    if not 1 <= len(data) <= MAX_SEED:
        raise ValueError(label + " is empty or too large")
    expected = _digest(seed["sha256"], label + " sha256")
    if hashlib.sha256(data).hexdigest() != expected:
        raise ValueError(label + " hash does not match its bytes")
    source_type = seed.get("source_type", "")
    source_ref = seed.get("source_ref", "")
    if not isinstance(source_type, str) or len(source_type) > 64 or "\x00" in source_type:
        raise ValueError(label + " source_type is invalid")
    if not isinstance(source_ref, str) or len(source_ref) > 256 or "\x00" in source_ref:
        raise ValueError(label + " source_ref is invalid")
    return {"sha256": expected, "data": data, "source_type": source_type, "source_ref": source_ref}


def _validate_argv(argv, input_mode):
    if not isinstance(argv, list) or len(argv) > MAX_ARGV:
        raise ValueError("argv must have at most 64 entries")
    for arg in argv:
        if not isinstance(arg, str) or len(arg) > 4096 or "\x00" in arg:
            raise ValueError("invalid target argv")
        if "@@" in arg:
            raise ValueError("target argv may not contain @@")
        if "{input}" in arg and arg != "{input}":
            raise ValueError("input placeholder must be a whole argument")
    if input_mode == "file":
        if argv.count("{input}") != 1:
            raise ValueError("file mode requires exactly one whole input placeholder")
    elif "{input}" in argv:
        raise ValueError("stdin mode may not use an input placeholder")
    return list(argv)


def validate_resource_plan(plan, identity):
    fields = {"version", "task_id", "campaign_id", "attempt_id", "fencing_token",
              "staging_root", "staging_basename", "container_names"}
    _require_fields(plan, fields, fields, "resource plan")
    _integer(plan["version"], 1, 1, "resource plan version")
    for key in ("task_id", "campaign_id", "attempt_id", "fencing_token"):
        _integer(plan[key], 1, 1 << 62, "resource plan " + key)
        if plan[key] != identity[key]:
            raise ValueError("resource plan identity mismatch")
    root = _string(plan["staging_root"], "resource plan staging root", 4096)
    if (not root.startswith("/") or root.startswith("//") or root == "/"
            or posixpath.normpath(root) != root or any(ch in root for ch in "\\\r\n")):
        raise ValueError("resource plan requires a canonical absolute POSIX private root")
    base = "artex-campaign-%d-%d-%d-%d" % (
        plan["campaign_id"], plan["attempt_id"], plan["attempt_id"], plan["fencing_token"])
    names = [base, base + "-help-afl-fuzz", base + "-help-afl-showmap", base + "-probe"]
    if plan["container_names"] != names or plan["staging_basename"] != base + "-stage":
        raise ValueError("resource plan names mismatch")
    return dict(plan, container_names=list(names))


def resource_plan_digest(plan):
    validate_resource_plan(plan, plan)
    body = [plan["version"], plan["task_id"], plan["campaign_id"],
            plan["attempt_id"], plan["fencing_token"], plan["staging_root"],
            plan["staging_basename"], plan["container_names"]]
    return hashlib.sha256(_canonical_json(body).encode("utf-8")).hexdigest()


def validate_creation_seal(seal, plan, identity):
    validate_resource_plan(plan, identity)
    fields = {"version", "task_id", "campaign_id", "attempt_id", "fencing_token",
              "plan_sha256", "staging_basename", "containers"}
    _require_fields(seal, fields, fields, "creation seal")
    _integer(seal["version"], 1, 1, "creation seal version")
    for key in ("task_id", "campaign_id", "attempt_id", "fencing_token"):
        _integer(seal[key], 1, 1 << 62, "creation seal " + key)
        if seal[key] != identity[key]:
            raise ValueError("creation seal identity mismatch")
    if (seal["plan_sha256"] != resource_plan_digest(plan)
            or seal["staging_basename"] != plan["staging_basename"]):
        raise ValueError("creation seal plan mismatch")
    containers = seal["containers"]
    if not isinstance(containers, list) or not 1 <= len(containers) <= 4:
        raise ValueError("creation seal container set is invalid")
    labels = {"artex." + key: str(identity[key]) for key in
              ("task_id", "campaign_id", "attempt_id", "fencing_token")}
    labels["artex.owner"] = "artex-native-campaign"
    names, ids, copied = set(), set(), []
    for item in containers:
        _require_fields(item, {"name", "id", "labels"}, {"name", "id", "labels"}, "sealed container")
        name, object_id = item["name"], item["id"]
        if (not isinstance(name, str) or name not in plan["container_names"]
                or name in names or not _digest_ok(object_id) or object_id in ids
                or item["labels"] != labels):
            raise ValueError("sealed container identity mismatch")
        names.add(name)
        ids.add(object_id)
        copied.append({"name": name, "id": object_id, "labels": dict(labels)})
    return dict(seal, containers=copied)


def validate_campaign_start(first):
    _require_fields(first, START_FIELDS, {
        "operation", "task_id", "request_id", "campaign_id", "attempt_id",
        "attempt_no", "fencing_token", "lease_ms", "lease_deadline", "artifact_path", "sha256",
        "input_mode", "seeds", "attempt_budget_ms", "execution_window_ms",
        "execution_deadline", "envelope_deadline", "cleanup_reserve_ms", "profile",
    }, "campaign start")
    if first.get("operation") != "campaign":
        raise ValueError("expected campaign operation")
    request_id = _string(first.get("request_id"), "request_id", 128)
    task_id = _integer(first.get("task_id"), 1, 1 << 62, "task_id")
    campaign_id = _integer(first.get("campaign_id"), 1, 1 << 62, "campaign_id")
    attempt_id = _integer(first.get("attempt_id"), 1, 1 << 62, "attempt_id")
    attempt_no = _integer(first.get("attempt_no"), 1, 1 << 31, "attempt_no")
    fencing = _integer(first.get("fencing_token"), 1, 1 << 62, "fencing_token")
    lease_owner = _string(first.get("lease_owner", ""), "lease_owner", 128, allow_empty=True)
    lease_instance = _string(first.get("lease_instance", ""), "lease_instance", 128, allow_empty=True)
    lease_ms = _integer(first.get("lease_ms", 30000), 1000, 120000, "lease_ms")
    artifact = _string(first.get("artifact_path"), "artifact_path", 4096)
    if any(ch in artifact for ch in "\r\n,"):
        raise ValueError("artifact_path contains a forbidden character")
    sha = _digest(first.get("sha256"), "sha256")
    input_mode = first.get("input_mode")
    if input_mode not in ("stdin", "file"):
        raise ValueError("input_mode must be stdin or file")
    argv = _validate_argv(first.get("argv", []), input_mode)
    profile = first.get("profile")
    _require_fields(profile, PROFILE_FIELDS, PROFILE_FIELDS, "profile")
    image = _string(profile.get("image"), "profile.image", 128)
    if not image.startswith("sha256:") or not _digest_ok(image[7:]):
        raise ValueError("profile.image must be an immutable sha256 digest")
    image_id = _string(profile.get("image_id"), "profile.image_id", 256)
    if profile.get("fuzz_enabled") is not True:
        raise ValueError("profile.fuzz_enabled must be true")
    if profile.get("enabled") is not True:
        raise ValueError("profile is disabled")
    if profile.get("network") not in (None, "none"):
        raise ValueError("campaign profile cannot request a network")
    if profile.get("read_only_root") is not True:
        raise ValueError("campaign profile root must be read-only")
    max_duration = _integer(profile.get("max_duration_ms"), 1000, 900000, "profile.max_duration_ms")
    seeds = first.get("seeds")
    if not isinstance(seeds, list) or not 1 <= len(seeds) <= MAX_SEEDS:
        raise ValueError("seeds must have 1..32 entries")
    decoded = []
    total = 0
    for index, seed in enumerate(seeds):
        item = _canonical_seed(seed, "seed[%d]" % index)
        total += len(item["data"])
        if total > MAX_SEED_TOTAL:
            raise ValueError("seed total exceeds 65536 bytes")
        decoded.append(item)
    budget = _integer(first.get("attempt_budget_ms"), 6000, 900000, "attempt_budget_ms")
    window = _integer(first.get("execution_window_ms"), 1000, budget - 5000, "execution_window_ms")
    if window > max_duration:
        raise ValueError("execution_window_ms exceeds the profile limit")
    execution_ts = _parse_deadline(first.get("execution_deadline"), "execution_deadline")
    envelope_ts = _parse_deadline(first.get("envelope_deadline"), "envelope_deadline")
    lease_ts = _parse_deadline(first.get("lease_deadline"), "lease_deadline")
    if lease_ts > execution_ts:
        raise ValueError("lease_deadline is after execution_deadline")
    if execution_ts > envelope_ts:
        raise ValueError("execution_deadline is after envelope_deadline")
    cleanup_reserve = _integer(first.get("cleanup_reserve_ms", 0), 0, 60000, "cleanup_reserve_ms")
    cleanup_hard = _integer(first.get("cleanup_hard_timeout_ms", 60000), 1000, 60000,
                            "cleanup_hard_timeout_ms")
    max_executions = _integer(first.get("max_executions", 1000000), 1, 1000000, "max_executions")
    max_crashes = _integer(first.get("max_crashes", 4), 1, 8, "max_crashes")
    resource_plan = None
    if "resource_plan" in first:
        resource_plan = validate_resource_plan(first["resource_plan"], first)
    return {
        "operation": "campaign", "request_id": request_id, "task_id": task_id,
        "campaign_id": campaign_id, "attempt_id": attempt_id, "attempt_no": attempt_no,
        "fencing_token": fencing, "lease_owner": lease_owner, "lease_instance": lease_instance,
        "lease_ms": lease_ms, "lease_deadline": first["lease_deadline"], "lease_ts": lease_ts, "artifact_path": artifact, "sha256": sha, "argv": argv,
        "input_mode": input_mode, "seeds": decoded, "max_executions": max_executions,
        "max_crashes": max_crashes, "attempt_budget_ms": budget,
        "execution_window_ms": window, "execution_deadline": first.get("execution_deadline"),
        "envelope_deadline": first.get("envelope_deadline"),
        "execution_ts": execution_ts, "envelope_ts": envelope_ts,
        "cleanup_reserve_ms": cleanup_reserve, "cleanup_hard_timeout_ms": cleanup_hard,
        "profile": dict(profile), "resource_plan": resource_plan,
    }


def _digest_ok(value):
    return isinstance(value, str) and len(value) == 64 and all(ch in "0123456789abcdef" for ch in value)


def validate_cleanup_probe(first):
    _require_fields(first, CLEANUP_PROBE_FIELDS | {"resource_plan", "creation_seal"},
                    CLEANUP_PROBE_FIELDS, "cleanup probe")
    if first.get("operation") != "campaign_cleanup_probe":
        raise ValueError("expected campaign_cleanup_probe operation")
    request = {
        "operation": "campaign_cleanup_probe",
        "request_id": _string(first.get("request_id"), "request_id", 128),
        "task_id": _integer(first.get("task_id"), 1, 1 << 62, "task_id"),
        "campaign_id": _integer(first.get("campaign_id"), 1, 1 << 62, "campaign_id"),
        "attempt_id": _integer(first.get("attempt_id"), 1, 1 << 62, "attempt_id"),
        "fencing_token": _integer(first.get("fencing_token"), 1, 1 << 62, "fencing_token"),
    }
    if "resource_plan" in first or "creation_seal" in first:
        if "resource_plan" not in first or "creation_seal" not in first:
            raise ValueError("sealed cleanup requires both plan and seal")
        request["resource_plan"] = validate_resource_plan(first["resource_plan"], request)
        request["creation_seal"] = validate_creation_seal(
            first["creation_seal"], request["resource_plan"], request)
    return request



def _frame(request, kind, observation):
    return {
        "request_id": request["request_id"],
        "task_id": request["task_id"],
        "campaign_id": request["campaign_id"],
        "attempt_id": request["attempt_id"],
        "fencing_token": request["fencing_token"],
        "kind": kind,
        "observation": observation,
    }


class CampaignControl:
    """Cancel dominates pause; both are advisory until the backend returns."""

    def __init__(self):
        self._lock = threading.Lock()
        self._pause = threading.Event()
        self._cancel = threading.Event()
        self._reason = ""

    def request(self, action, reason=""):
        with self._lock:
            if action == "cancel":
                self._cancel.set()
                self._pause.set()
                self._reason = reason
            elif action == "pause" and not self._cancel.is_set():
                self._pause.set()
                self._reason = reason

    def snapshot(self):
        with self._lock:
            if self._cancel.is_set():
                return "cancel", self._reason
            if self._pause.is_set():
                return "pause", self._reason
            return None, ""

    def wait(self, timeout):
        end = time.monotonic() + max(0.0, timeout)
        while True:
            action, _ = self.snapshot()
            if action:
                return action
            if time.monotonic() >= end:
                return None
            time.sleep(min(0.02, max(0.001, end - time.monotonic())))

    def raise_if_requested(self):
        action, reason = self.snapshot()
        if action == "cancel":
            raise CampaignCancelled(reason)
        if action == "pause":
            raise CampaignPaused(reason)


class CampaignBackend:
    """Explicit backend interface. Only tests provide a synthetic implementation."""

    def execute(self, request, control):
        raise NotImplementedError

    def checkpoint(self, request):
        raise NotImplementedError

    def cleanup(self, request):
        raise NotImplementedError

    def status(self, request):
        return {}

    def probe_cleanup(self, request, timeout):
        raise NotImplementedError

    def stop(self, request, timeout):
        """Cooperatively stop owned work within timeout.

        Returns True only when the backend confirms its owned process/worker has
        terminated. The default is an explicit unknown failure, never a fake
        success merely because a daemon thread returned.
        """
        return False

    def ownership(self, request):
        """Report explicit ownership: terminated, running or unknown.

        A real backend must override this. The default unknown keeps cleanup
        unverified rather than inferring success from a timeout wrapper.
        """
        return CLEANUP_OWNERSHIP_UNKNOWN


class UnavailableCampaignBackend(CampaignBackend):
    message = "real native campaign backend is not configured"

    def execute(self, request, control):
        raise CampaignBackendUnavailable(self.message)

    def checkpoint(self, request):
        raise CampaignBackendUnavailable(self.message)

    def cleanup(self, request):
        raise CampaignBackendUnavailable(self.message)

    def status(self, request):
        return {"state": "unavailable"}

    def probe_cleanup(self, request, timeout):
        raise CampaignBackendUnavailable(self.message)


def _bounded_call(function, timeout, label):
    box = {}
    done = threading.Event()

    def run():
        try:
            box["value"] = function()
        except BaseException as exc:  # noqa: BLE001 - surfaced below
            box["error"] = exc
        finally:
            done.set()

    threading.Thread(target=run, name="artex-campaign-" + label, daemon=True).start()
    if not done.wait(max(0.0, timeout)):
        raise CampaignBackendTimeout(label + " timed out")
    if "error" in box:
        raise box["error"]
    return box.get("value")


def _error_text(exc, limit=MAX_ERROR):
    text = type(exc).__name__
    message = str(exc)
    if message:
        text += ": " + message
    return text[:limit]


class CampaignDeadline:
    """The one monotonic conversion of the wire's absolute deadlines.

    ``CampaignRunner`` builds this exactly once per attempt; the backend must
    consume these values rather than adding a relative duration per phase.
    """

    __slots__ = ("execution", "envelope", "started")

    def __init__(self, execution, envelope, started):
        self.execution = float(execution)
        self.envelope = float(envelope)
        self.started = float(started)

    def remaining(self, clock=time.monotonic):
        return max(0.0, min(self.execution, self.envelope) - clock())


def _accepts_deadline(method):
    """Return True only when the backend explicitly accepts a deadline.

    This keeps the T4b-1 synthetic backends (which do not know about the new
    context) working unchanged, while the real adapter receives the same
    monotonic deadline once. A signature lookup failure is treated as "no".
    """
    try:
        parameters = inspect.signature(method).parameters
    except (TypeError, ValueError):
        return False
    return ("deadline" in parameters
            or any(item.kind == inspect.Parameter.VAR_KEYWORD
                   for item in parameters.values()))


def _call_backend(method, *args, deadline=None):
    if deadline is not None and _accepts_deadline(method):
        return method(*args, deadline=deadline)
    return method(*args)


class CampaignRunner:
    def __init__(self, request, backend=None, clock=time.monotonic, phase_hook=None,
                 stop_grace=1.0, pause_grace=0.3, cleanup_timeout=60.0,
                 pause_confirm_timeout=8.0):
        self.request = request
        self.backend = backend or UnavailableCampaignBackend()
        self.clock = clock
        self.phase_hook = phase_hook
        self.stop_grace = max(0.0, stop_grace)
        self.pause_grace = max(0.0, pause_grace)
        self.cleanup_timeout = max(0.0, cleanup_timeout)
        # Bounded extra wait for a pause to be confirmed by the backend before the
        # checkpoint is taken; a live writer makes the checkpoint refuse.
        self.pause_confirm_timeout = max(self.stop_grace, pause_confirm_timeout)
        self.control = CampaignControl()
        self._emit = None
        self._emit_lock = threading.RLock()
        self._finalizing = False
        self._stop = threading.Event()
        self._worker_done = threading.Event()
        self._worker_stop_failed = ""
        self._control_cache = collections.OrderedDict()
        self._control_cache_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._state = {
            "result": None, "error": None, "protocol": None, "eof": False,
            "lease_expired": False, "deadline": None, "lease": 0.0,
        }
        now = self.clock()
        wall_now = time.time()
        # Stable shared UTC with the DB/manager is a deployment prerequisite.
        # One anchor is reused for all renewals; wire/ACK delay never adds TTL.
        self._wall_anchor = wall_now
        self._mono_anchor = now
        # Convert the absolute wire deadlines to monotonic exactly once. The
        # attempt budget is a wall-clock envelope too; no phase gets a fresh
        # relative duration.
        budget_remaining = request["attempt_budget_ms"] / 1000.0
        envelope_remaining = min(request["envelope_ts"] - wall_now, budget_remaining)
        execution_remaining = min(request["execution_ts"] - wall_now, envelope_remaining)
        self._envelope_deadline = now + max(0.0, envelope_remaining)
        self._execution_deadline = now + max(0.0, execution_remaining)
        self.deadline = CampaignDeadline(
            self._execution_deadline, self._envelope_deadline, now)
        self._lease_deadline = min(now + (request["lease_ts"] - wall_now), self._execution_deadline)
        self._state["lease"] = self._lease_deadline

    def _emit_frame(self, request, kind, observation):
        frame = _frame(request, kind, observation)
        with self._emit_lock:
            self._emit(frame)

    def phase(self, name):
        self._emit_frame(self.request, "event", {
            "event": "phase", "phase": name,
            "attempt_id": self.request["attempt_id"],
        })
        if self.phase_hook is not None:
            self.phase_hook(name, self.control)

    def _record(self, **values):
        with self._state_lock:
            self._state.update(values)

    def _read_controls(self, inp):
        try:
            while not self._stop.is_set():
                frame = read_campaign_frame(inp)
                if frame is None:
                    self._record(eof=True)
                    self.control.request("cancel", "eof")
                    return
                self._handle_control(frame)
        except Exception as exc:  # protocol errors fail closed
            with self._state_lock:
                if self._state["protocol"] is None:
                    self._state["protocol"] = "protocol_violation: " + _error_text(exc)
            self.control.request("cancel", "protocol_violation")

    @staticmethod
    def _control_fingerprint(action, frame):
        # The fingerprint includes both the action and every action payload so a
        # reused request_id with different content is a protocol violation.
        if action == "heartbeat":
            payload = (frame.get("lease_ms"), frame.get("lease_deadline"))
        elif action in ("pause", "cancel"):
            payload = frame.get("reason", "")
        else:
            payload = None
        return action, payload

    def _cache_control(self, request_id, fingerprint, observation):
        with self._control_cache_lock:
            self._control_cache[request_id] = (fingerprint, dict(observation))

    def _handle_control(self, frame):
        action = frame.get("action")
        if action not in CONTROL_FIELDS:
            raise ValueError("unknown control action")
        _require_fields(frame, CONTROL_FIELDS[action], {"request_id", "action"}, "control")
        request_id = _string(frame.get("request_id"), "control request_id", 128)
        fingerprint = self._control_fingerprint(action, frame)
        # The emit lock makes control handling and the single finalization
        # boundary total: a control either takes effect/emits its ACK before the
        # final frame, or observes _finalizing and has no side effect at all.
        with self._emit_lock:
            if self._finalizing:
                return
            with self._control_cache_lock:
                cached = self._control_cache.get(request_id)
            if cached is not None:
                cached_fingerprint, observation = cached
                if cached_fingerprint != fingerprint:
                    raise ValueError("control request_id reused with different content")
                self._emit_control_result(request_id, observation=observation)
                return
            with self._control_cache_lock:
                if len(self._control_cache) >= MAX_CONTROL_CACHE:
                    raise ValueError("control request ledger is full")
            if action == "heartbeat":
                _integer(frame.get("lease_ms"), 1000, 120000, "heartbeat lease_ms")
                lease_ts = _parse_deadline(frame.get("lease_deadline"), "heartbeat lease_deadline")
                if lease_ts > self.request["execution_ts"]:
                    raise ValueError("heartbeat lease_deadline exceeds execution_deadline")
                proposed = self._mono_anchor + (lease_ts - self._wall_anchor)
                now = self.clock()
                # Check the current lease and update it under one lock. A replay
                # never reaches this branch because it is served from the cache.
                with self._state_lock:
                    expired = self._state["lease_expired"] or now >= self._lease_deadline
                    if expired:
                        self._state["lease_expired"] = True
                    deadline_hit = now >= self._execution_deadline
                    request_expired = now >= proposed
                    if not expired and not deadline_hit and not request_expired:
                        # Do not acknowledge stale/out-of-order authority by
                        # retaining a later cutoff than this request permits.
                        self._lease_deadline = proposed
                        self._state["lease"] = proposed
                if expired or deadline_hit or request_expired:
                    self.control.request(
                        "cancel", "lease_expired" if expired or request_expired else "execution_deadline")
                    observation = {"action": action, "accepted": False,
                                   "detail": "heartbeat rejected after deadline"}
                else:
                    observation = {"action": action, "accepted": True,
                                   "lease_deadline": frame["lease_deadline"]}
                self._cache_control(request_id, fingerprint, observation)
                self._emit_control_result(request_id, observation=observation)
                return
            reason = ""
            if action in ("pause", "cancel"):
                reason = _string(frame.get("reason", ""), "control reason", 512,
                                 allow_empty=True)
            self.control.request(action, reason)
            observation = {"action": action, "accepted": True}
            self._cache_control(request_id, fingerprint, observation)
            self._emit_control_result(request_id, observation=observation)

    def _emit_control_result(self, request_id, action=None, accepted=True, detail="",
                             lease_deadline=None, observation=None):
        if observation is None:
            observation = {"action": action, "accepted": bool(accepted)}
            if detail:
                observation["detail"] = detail
            if lease_deadline:
                observation["lease_deadline"] = lease_deadline
        frame = _frame({**self.request, "request_id": request_id}, "result", observation)
        # No control result may appear after the single final frame. Holding the
        # same lock across the flag check and write makes the ordering total.
        with self._emit_lock:
            if self._finalizing:
                return False
            self._emit(frame)
            return True

    def _checkpoint_entries(self, result):
        """Validate checkpoint input and retain only a bounded unique prefix.

        Raw items and the fallback seeds share one path: validate each
        data/metadata item, derive ``(sha256, length)``, deduplicate by keeping
        the first source metadata, and retain unique entries only while the
        512-entry/1 MiB limits still hold. The first unique overflow locks
        ``truncated`` and the accepted prefix; later items are still validated
        but no new hash/object bytes are retained, so a later small item cannot
        backfill the sequence and the seen set stays bounded. Object bytes are
        copied only for retained entries, never for the whole input.
        """
        raw = None
        if isinstance(result, dict):
            raw = result.get("checkpoint")
        if raw is None:
            raw = []
        if not isinstance(raw, list):
            raise ValueError("checkpoint must be a list")

        entries = []
        seen = set()
        total = 0
        truncated = False
        overflowed = False
        missing = object()

        def retain(digest, data, length, source_type, source_ref):
            nonlocal total, truncated, overflowed
            if overflowed:
                return
            key = (digest, length)
            if key in seen:
                # Keep the first source_type/source_ref for this object.
                return
            if (len(entries) >= MAX_CHECKPOINT_ENTRIES
                    or total + length > MAX_CHECKPOINT_BYTES):
                truncated = True
                overflowed = True
                return
            seen.add(key)
            entries.append({
                "sha256": digest, "length": length, "data": bytes(data),
                "source_type": source_type, "source_ref": source_ref,
            })
            total += length

        def accept(data, source_type, source_ref, declared_sha=missing,
                   declared_length=missing):
            if not isinstance(data, (bytes, bytearray)) or not 1 <= len(data) <= MAX_SEED:
                raise ValueError("checkpoint entry data is invalid")
            length = len(data)
            digest = hashlib.sha256(data).hexdigest()
            if declared_sha is not missing:
                if _digest(declared_sha, "checkpoint entry sha256") != digest:
                    raise ValueError("checkpoint entry sha256 does not match its bytes")
            if declared_length is not missing:
                if _integer(declared_length, 1, MAX_SEED,
                            "checkpoint entry length") != length:
                    raise ValueError("checkpoint entry length does not match its bytes")
            source_type = _source_type(source_type, "checkpoint")
            source_ref = _source_ref(source_ref, "checkpoint")
            retain(digest, data, length, source_type, source_ref)

        if raw:
            for index, item in enumerate(raw):
                if isinstance(item, dict):
                    unknown = set(item) - {"data", "source_type", "source_ref",
                                           "sha256", "length"}
                    if unknown:
                        raise ValueError("checkpoint entry has unknown metadata")
                    accept(
                        item.get("data"),
                        item.get("source_type", "queue"),
                        item.get("source_ref", "id:%06d" % index),
                        item.get("sha256", missing),
                        item.get("length", missing),
                    )
                else:
                    accept(item, "queue", "id:%06d" % index)
        else:
            for index, seed in enumerate(self.request["seeds"]):
                accept(seed["data"], "seed", "seed:%d" % index)

        if not entries:
            raise ValueError("checkpoint is empty")
        return entries, truncated

    def _checkpoint_manifest(self, entries):
        """Return the exact taskbook section 3.3 canonical manifest bytes."""
        task_id = self.request["task_id"]
        records = []
        for entry in entries:
            sha256 = entry["sha256"]
            records.append({
                "sha256": sha256,
                "length": entry["length"],
                "storage_key": "tasks/%d/reverse/campaigns/objects/sha256/%s/%s"
                               % (task_id, sha256[:2], sha256),
                "source_type": entry["source_type"],
                "source_ref": entry["source_ref"],
            })
        records.sort(key=lambda item: (item["source_type"], item["storage_key"],
                                       item["sha256"], item["length"]))
        manifest = {
            "format_version": 1,
            "campaign_id": self.request["campaign_id"],
            "attempt_id": self.request["attempt_id"],
            "entries": records,
        }
        return _canonical_json(manifest).encode("utf-8")

    def _emit_checkpoint(self, entries):
        encoded = []
        for entry in entries:
            data = entry["data"]
            encoded.append({
                "sha256": entry["sha256"],
                "length": entry["length"],
                "data_base64": base64.b64encode(data).decode("ascii"),
                "source_type": entry["source_type"],
                "source_ref": entry["source_ref"],
            })
        manifest = hashlib.sha256(self._checkpoint_manifest(entries))
        chunks = []
        current = []
        current_bytes = 0
        for item in encoded:
            if current and (len(current) >= MAX_CHECKPOINT_CHUNK_ENTRIES
                            or current_bytes + item["length"] > MAX_CHECKPOINT_CHUNK_BYTES):
                chunks.append(current)
                current, current_bytes = [], 0
            current.append(item)
            current_bytes += item["length"]
        if current:
            chunks.append(current)
        for seq, chunk in enumerate(chunks):
            self._emit_frame(self.request, "event", {
                "event": "checkpoint_chunk",
                "checkpoint_seq": seq,
                "entries": chunk,
                "more": seq + 1 < len(chunks),
            })
        return {
            "format_version": 1,
            "entry_count": len(encoded),
            "total_bytes": sum(item["length"] for item in encoded),
            "truncated": bool(self.request.get("_checkpoint_truncated", False)),
            "manifest_sha256": manifest.hexdigest(),
        }

    def _run_worker(self):
        try:
            now = self.clock()
            if now >= self._execution_deadline:
                self._record(deadline="execution_deadline")
                self.control.request("cancel", "execution_deadline")
                raise CampaignCancelled("execution_deadline")
            if now >= self._lease_deadline:
                self._record(lease_expired=True)
                self.control.request("cancel", "lease_expired")
                raise CampaignCancelled("lease_expired")
            result = _call_backend(self.backend.execute, self.request, self.control,
                                   deadline=self.deadline)
            if not isinstance(result, dict):
                raise ValueError("backend returned no result object")
            self._record(result=result)
        except CampaignCancelled as exc:
            self._record(result={"target_state": "cancelled", "reason": str(exc)})
        except CampaignPaused as exc:
            self._record(result={"target_state": "paused", "reason": str(exc)})
        except BaseException as exc:  # noqa: BLE001 - converted to a bounded final
            self._record(error=_error_text(exc))
        finally:
            self._worker_done.set()

    def _cleanup(self, request, deadline):
        remaining = max(0.0, deadline - time.monotonic())
        if remaining <= 0:
            return {key: False for key in CLEANUP_KEYS}, "cleanup_timeout"
        try:
            value = _bounded_call(
                lambda: _call_backend(self.backend.cleanup, request,
                                      deadline=deadline),
                remaining, "cleanup")
            if not isinstance(value, dict):
                raise ValueError("cleanup returned no object")
            triple = {key: value.get(key) is True for key in CLEANUP_KEYS}
            if not all(triple.values()):
                return triple, "cleanup triple is not fully confirmed"
            return triple, ""
        except CampaignBackendTimeout:
            return {key: False for key in CLEANUP_KEYS}, "cleanup_timeout"
        except BaseException as exc:  # noqa: BLE001
            return {key: False for key in CLEANUP_KEYS}, "cleanup_error: " + _error_text(exc)

    def _bounded_stop(self, deadline):
        """Ask the backend to stop owned work; never waits past the cleanup deadline."""
        if self._worker_done.is_set():
            return True, ""
        remaining = max(0.0, deadline - time.monotonic())
        if remaining <= 0:
            return False, "cleanup_timeout"
        timeout = min(self.stop_grace, remaining)
        try:
            stopped = _bounded_call(
                lambda: _call_backend(self.backend.stop, self.request, timeout,
                                      deadline=deadline),
                timeout, "stop")
        except CampaignBackendTimeout:
            return False, "worker_stop_timeout"
        except BaseException as exc:  # noqa: BLE001
            return False, "backend_stop_error: " + _error_text(exc)
        if stopped is True:
            return True, ""
        return False, "worker_stop_failed"

    def _ownership(self):
        try:
            value = self.backend.ownership(self.request)
        except BaseException as exc:  # noqa: BLE001
            return CLEANUP_OWNERSHIP_UNKNOWN, "ownership_error: " + _error_text(exc)
        if value in (CLEANUP_OWNERSHIP_TERMINATED, CLEANUP_OWNERSHIP_RUNNING,
                     CLEANUP_OWNERSHIP_UNKNOWN):
            return value, ""
        return CLEANUP_OWNERSHIP_UNKNOWN, "ownership_unknown"

    def _final_observation(self, request, target, reason, result, checkpoint, cleanup,
                           cleanup_error, extra_errors):
        triple, cleanup_error = cleanup
        verified = all(triple.values())
        errors = list(extra_errors)
        if cleanup_error and cleanup_error not in errors:
            errors.append(cleanup_error[:MAX_ERROR])
        if target == "paused" and checkpoint is None:
            target, reason = "failed", "checkpoint_invalid"
        manifest = {
            "engine": "afl++", "artifact_sha256": request["sha256"],
            "image": request["profile"]["image"], "image_id": request["profile"]["image_id"],
            "input_mode": request["input_mode"], "afl_version": "", "showmap_version": "",
            "options_verified": False, "probe_edges": 0, "probe_executions": 0,
            "output_disk_limit_bytes": 0, "single_worker": True,
        }
        stats = {}
        observed = 0
        if isinstance(result, dict):
            candidate = result.get("manifest")
            if isinstance(candidate, dict):
                for key in manifest:
                    if key in candidate:
                        manifest[key] = candidate[key]
            manifest["artifact_sha256"] = request["sha256"]
            manifest["image"] = request["profile"]["image"]
            manifest["image_id"] = request["profile"]["image_id"]
            manifest["input_mode"] = request["input_mode"]
            if isinstance(result.get("stats"), dict):
                stats = result["stats"]
            try:
                observed = int(result.get("observed_execs", stats.get("execs_done", 0)))
            except (TypeError, ValueError):
                observed = 0
        elapsed = max(0, int((self.clock() - self._started) * 1000))
        budget = {
            "reserved_ms": request["attempt_budget_ms"], "charged_ms": elapsed,
            "actual_elapsed_ms": elapsed, "cleanup_overrun_ms": 0,
            "observed_execs": observed, "observed_execs_trusted": False,
            "budget_overrun": elapsed > request["attempt_budget_ms"],
        }
        observation = {
            "target_state": target, "phase": "finalize", "manifest": manifest,
            "stats": stats, "cleanup": triple, "cleanup_verified": verified,
            "cleanup_hold": {"resource_hold": not verified,
                             "hold_reason": None if verified else (cleanup_error[:MAX_ERROR] or "cleanup_unverified")},
            "budget": budget, "errors": errors[:MAX_ERRORS],
            "truncated": False, "limited": False, "reason": reason[:512],
            "candidate_only": True, "authority": "candidate-only",
        }
        if checkpoint is not None:
            observation["checkpoint"] = checkpoint
        return observation

    def _bound_final(self, observation):
        raw = json.dumps(observation, separators=(",", ":"), ensure_ascii=True)
        if len(raw.encode("utf-8")) <= MAX_FINAL:
            return observation
        observation = dict(observation)
        observation.pop("manifest", None)
        observation["stats"] = {}
        observation["truncated"] = True
        observation["limited"] = True
        return observation

    @staticmethod
    def _apply_final_cancel(target, reason, action, action_reason):
        # Cancel is evaluated once at the single finalization boundary. It wins
        # over a stale completed/paused/backend-error outcome, but not over the
        # transport/lease/protocol reasons that already terminated execution.
        if action == "cancel" and target not in ("timeout", "interrupted"):
            if not (target == "failed" and reason == "protocol_violation"):
                return "cancelled", action_reason or "cancelled"
        return target, reason

    def run(self, inp, emit):
        self._emit = emit
        self._started = self.clock()
        worker = threading.Thread(target=self._run_worker, name="artex-campaign-worker", daemon=True)
        reader = threading.Thread(target=self._read_controls, args=(inp,),
                                  name="artex-campaign-controls", daemon=True)
        worker.start()
        reader.start()
        try:
            while not self._worker_done.is_set():
                with self._state_lock:
                    protocol = self._state["protocol"]
                    lease_expired = self._state["lease_expired"]
                    lease_deadline = self._lease_deadline
                action, _ = self.control.snapshot()
                now = self.clock()
                if protocol is not None:
                    break
                if now >= self._execution_deadline:
                    self._record(deadline="execution_deadline")
                    self.control.request("cancel", "execution_deadline")
                    break
                if not lease_expired and now >= lease_deadline:
                    self._record(lease_expired=True)
                    self.control.request("cancel", "lease_expired")
                    break
                if action is not None:
                    # Pausing must wait for the backend to actually stop owned writes:
                    # the checkpoint below is refused while a writer is still live, and
                    # a real container takes longer than the generic stop grace to halt
                    # and hand back its already-written corpus. The wait stays bounded by
                    # the cleanup budget so a hung worker cannot extend the envelope.
                    if action == "pause":
                        self._worker_done.wait(
                            max(self.stop_grace,
                                min(self.pause_confirm_timeout, self.cleanup_timeout)))
                    else:
                        self._worker_done.wait(self.stop_grace)
                    break
                self._worker_done.wait(min(0.02, max(0.001, self._execution_deadline - now)))
            if not self._worker_done.is_set():
                self._worker_done.wait(self.stop_grace)
            # The control reader deliberately keeps running through checkpoint,
            # cleanup and the final boundary. It is only stopped after the final
            # frame has been published (or on an unexpected exception).
            with self._state_lock:
                protocol = self._state["protocol"]
                error = self._state["error"]
                result = self._state["result"]
                lease_expired = self._state["lease_expired"]
                deadline = self._state["deadline"]
            action, action_reason = self.control.snapshot()
            errors = []
            if protocol is not None:
                target, reason = "failed", "protocol_violation"
                errors.append(protocol[:MAX_ERROR])
            elif lease_expired:
                target, reason = "interrupted", "lease_expired"
            elif deadline is not None:
                target, reason = "timeout", deadline
            elif action == "cancel":
                target, reason = "cancelled", action_reason or "cancelled"
            elif action == "pause":
                target, reason = "paused", action_reason or "paused"
            elif error is not None:
                target, reason = "failed", "backend_error"
                errors.append(error[:MAX_ERROR])
            elif isinstance(result, dict) and result.get("target_state"):
                target = result["target_state"]
                if target not in FINAL_STATES:
                    target, reason = "failed", "invalid_target_state"
                else:
                    reason = str(result.get("reason") or target)[:512]
            else:
                target, reason = "failed", "backend_error"
            if action == "cancel":
                target, reason = self._apply_final_cancel(
                    target, reason, action, action_reason)
            checkpoint = None
            if target == "paused":
                # A pause ACK is only receipt. Allow a short, bounded escalation
                # window so a cancel that arrives while pausing wins before the
                # checkpoint is emitted.
                settle_end = time.monotonic() + self.pause_grace
                while time.monotonic() < settle_end and self.control.snapshot()[0] != "cancel":
                    time.sleep(0.01)
                self.phase("checkpointing")
                action_now, action_now_reason = self.control.snapshot()
                if action_now == "cancel":
                    target, reason = "cancelled", action_now_reason or "cancelled"
                else:
                    # A checkpoint is refused while any owned writer is still live, so a
                    # worker that has not finished on its own is stopped first. A
                    # supervisor-confirmed pause already collected the corpus and marked
                    # its record stopped, in which case this is a no-op.
                    if not self._worker_done.is_set():
                        self._bounded_stop(time.monotonic() + min(5.0, self.cleanup_timeout))
                        self._worker_done.wait(min(5.0, self.cleanup_timeout))
                    try:
                        if not isinstance(result, dict) or result.get("checkpoint") is None:
                            extra = _bounded_call(
                                lambda: _call_backend(
                                    self.backend.checkpoint, self.request,
                                    deadline=self.deadline),
                                self.cleanup_timeout, "checkpoint")
                            if extra is not None:
                                result = dict(result or {})
                                result["checkpoint"] = extra
                        entries, truncated = self._checkpoint_entries(result)
                        self.request["_checkpoint_truncated"] = truncated
                        checkpoint = self._emit_checkpoint(entries)
                    except BaseException as exc:  # noqa: BLE001
                        target, reason = "failed", "checkpoint_invalid"
                        errors.append("checkpoint: " + _error_text(exc))
                    action_now, action_now_reason = self.control.snapshot()
                    if action_now == "cancel":
                        target, reason = "cancelled", action_now_reason or "cancelled"
            self.phase("finalize")
            # One cleanup budget covers bounded stop and backend.cleanup; it is
            # never restarted per phase. A bounded stop failure is retained as a
            # hold unless the worker subsequently proves termination.
            cleanup_limit = min(self.cleanup_timeout,
                                self.request["cleanup_hard_timeout_ms"] / 1000.0)
            cleanup_deadline = time.monotonic() + cleanup_limit
            stopped, stop_error = self._bounded_stop(cleanup_deadline)
            if not stopped:
                self._worker_stop_failed = stop_error or "worker_stop_failed"
            cleanup = self._cleanup(self.request, cleanup_deadline)
            with self._emit_lock:
                # Single finalization boundary: latest cancel, explicit backend
                # ownership and cleanup facts are all evaluated here. Once
                # _finalizing is set under this lock, no control ACK can follow.
                action_now, action_now_reason = self.control.snapshot()
                target, reason = self._apply_final_cancel(
                    target, reason, action_now, action_now_reason)
                triple, cleanup_error = cleanup
                ownership, ownership_error = self._ownership()
                worker_finished = self._worker_done.is_set()
                if ownership != CLEANUP_OWNERSHIP_TERMINATED or not worker_finished:
                    triple = dict(triple)
                    triple["owned_process_terminated"] = False
                    if not worker_finished:
                        cleanup_error = (self._worker_stop_failed
                                         or "owned_process_still_running")
                    elif not cleanup_error:
                        cleanup_error = ownership_error or ("owned_process_" + ownership)
                if target == "paused" and checkpoint is None:
                    target, reason = "failed", "checkpoint_invalid"
                observation = self._final_observation(
                    self.request, target, reason, result, checkpoint,
                    (triple, cleanup_error), "", errors)
                if worker_finished and self.request.get("resource_plan") is not None:
                    seal_provider = getattr(self.backend, "creation_seal", None)
                    if callable(seal_provider):
                        try:
                            seal = seal_provider(self.request)
                            if seal is not None:
                                observation["creation_seal"] = seal
                        except Exception:
                            # Missing proof is never repaired from cleanup or
                            # a successfully delivered final frame.
                            pass
                observation = self._bound_final(observation)
                self._finalizing = True
                self._emit(_frame(self.request, "final", observation))
            return 0
        finally:
            self._stop.set()


def _invalid_final(first, emit, error):
    if not isinstance(first, dict):
        first = {}
    observation = {
        "target_state": "failed", "phase": "startup",
        "errors": [("invalid campaign start: " + _error_text(error))[:MAX_ERROR]],
        "cleanup": {key: False for key in CLEANUP_KEYS},
        "cleanup_verified": False,
        "cleanup_hold": {"resource_hold": True, "hold_reason": "invalid_start_frame"},
        "manifest": {}, "stats": {}, "budget": {}, "truncated": False,
        "limited": False, "reason": "protocol_violation", "candidate_only": True,
        "authority": "candidate-only",
    }
    frame = {
        "request_id": first.get("request_id") if isinstance(first.get("request_id"), str) else "invalid-campaign",
        "kind": "final", "observation": observation,
    }
    for key in ("task_id", "campaign_id", "attempt_id", "fencing_token"):
        if isinstance(first.get(key), int) and not isinstance(first.get(key), bool) and first[key] > 0:
            frame[key] = first[key]
    try:
        emit(frame)
    except Exception:
        pass


def serve_campaign(first, inp, emit, backend=None, first_raw=None, phase_hook=None,
                   stop_grace=1.0, pause_grace=0.3, cleanup_timeout=60.0):
    try:
        if first_raw is not None:
            parsed = strict_json_object(first_raw)
            if parsed != first:
                raise ValueError("first frame changed during strict decoding")
            first = parsed
        request = validate_campaign_start(first)
    except Exception as exc:
        _invalid_final(first, emit, exc)
        return 2
    runner = CampaignRunner(request, backend=backend, phase_hook=phase_hook,
                            stop_grace=stop_grace, pause_grace=pause_grace,
                            cleanup_timeout=cleanup_timeout)
    return runner.run(inp, emit)


def _sanitize_cleanup_report(report, request=None):
    errors = []
    containers = []
    staging = {"present": True, "removed": False}
    hard_timeout = False
    claimed = False
    if isinstance(report, dict):
        claimed = report.get("cleanup_verified") is True
        hard_timeout = report.get("hard_timeout") is True
        raw_staging = report.get("staging")
        if isinstance(raw_staging, dict):
            staging = {"present": raw_staging.get("present") is not False,
                       "removed": raw_staging.get("removed") is True}
        else:
            errors.append("cleanup staging is missing")
        raw_containers = report.get("containers")
        if isinstance(raw_containers, list) and len(raw_containers) <= MAX_CONTAINERS:
            for item in raw_containers:
                if not isinstance(item, dict):
                    errors.append("cleanup container entry is invalid")
                    continue
                name = item.get("name")
                state = item.get("state")
                labels = item.get("labels_match")
                if not isinstance(name, str) or len(name) > 256:
                    errors.append("cleanup container name is invalid")
                    continue
                if not isinstance(state, str) or len(state) > 32:
                    errors.append("cleanup container state is invalid")
                    continue
                entry = {"name": name, "state": state, "labels_match": labels is True}
                if request is not None and "resource_plan" in request:
                    object_id = item.get("id")
                    if not _digest_ok(object_id):
                        errors.append("cleanup container id is invalid")
                    entry["id"] = object_id if _digest_ok(object_id) else ""
                containers.append(entry)
        else:
            errors.append("cleanup containers are invalid")
        raw_errors = report.get("errors")
        if isinstance(raw_errors, list):
            for item in raw_errors[:MAX_ERRORS]:
                if not isinstance(item, str):
                    errors.append("cleanup error entry is invalid")
                else:
                    errors.append(item[:MAX_ERROR])
        else:
            errors.append("cleanup errors are invalid")
    else:
        errors.append("cleanup backend returned no report")
    binding = {}
    if request is not None and "resource_plan" in request:
        plan, seal = request["resource_plan"], request["creation_seal"]
        expected = {(item["name"], item["id"]) for item in seal["containers"]}
        actual = {(item["name"], item.get("id")) for item in containers}
        if (not isinstance(report, dict) or report.get("plan_sha256") != seal["plan_sha256"]
                or report.get("staging_basename") != plan["staging_basename"]
                or actual != expected or len(containers) != len(expected)):
            errors.append("cleanup does not cover the sealed resource set")
        binding = {"plan_sha256": seal["plan_sha256"],
                   "staging_basename": plan["staging_basename"]}
    verified = (
        claimed and not hard_timeout and not errors
        and not staging["present"] and staging["removed"]
        and all(item["state"] in ("absent", "removed") and item["labels_match"]
                for item in containers)
    )
    return dict(binding, **{
        "cleanup_verified": bool(verified),
        "containers": containers,
        "staging": staging,
        "errors": errors[:MAX_ERRORS],
        "hard_timeout": bool(hard_timeout),
        "elapsed_ms": 0,
    })


def serve_cleanup_probe(first, emit, backend=None, first_raw=None, timeout=60.0):
    try:
        if first_raw is not None:
            parsed = strict_json_object(first_raw)
            if parsed != first:
                raise ValueError("first frame changed during strict decoding")
            first = parsed
        request = validate_cleanup_probe(first)
    except Exception as exc:
        _invalid_final(first, emit, exc)
        return 2
    backend = backend or UnavailableCampaignBackend()
    try:
        report = _bounded_call(lambda: backend.probe_cleanup(request, timeout),
                               timeout, "cleanup_probe")
    except CampaignBackendTimeout:
        report = {"cleanup_verified": False, "containers": [],
                  "staging": {"present": True, "removed": False},
                  "errors": ["cleanup_timeout"], "hard_timeout": True}
    except BaseException as exc:  # noqa: BLE001 - explicit unknown, never verified
        report = {"cleanup_verified": False, "containers": [],
                  "staging": {"present": True, "removed": False},
                  "errors": ["cleanup_error: " + _error_text(exc)], "hard_timeout": False}
    sanitized = _sanitize_cleanup_report(report, request)
    emit(_frame(request, "final", sanitized))
    return 0 if sanitized["cleanup_verified"] else 1
