"""Deterministic, synthetic tests for the T4b-2 Docker/AFL backend adapter.

No real Docker, AFL, GDB, target or network is used. Management and group
regressions also use explicitly reaped benign local subprocesses; staging lives only under a test-owned temp
root.  The real Docker path remains NOT RUN.
"""
import ast
import ctypes
import signal
import pathlib
from unittest import mock
from . import campaign_backend as mod
import base64
import hashlib
import io
import json
import os
import stat
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import patch

from .campaign import (CampaignControl, validate_campaign_start, validate_cleanup_probe,
                       _sanitize_cleanup_report, serve_cleanup_probe)
from .campaign_backend import (
    MAX_CHECKPOINT_BYTES,
    MAX_CHECKPOINT_ENTRIES,
    MAX_HELP_OUTPUT,
    MAX_SCAN_ENTRIES,
    CampaignBackendError,
    CampaignOwnershipUnknown,
    DockerAflCampaignBackend,
    DockerCampaignBackend,
)

IMAGE = "sha256:" + "a" * 64
OTHER_IMAGE = "sha256:" + "b" * 64
SEED = b"Z"
SEED_SHA = hashlib.sha256(SEED).hexdigest()


def elf64():
    b = bytearray(120)
    b[:7] = b"\x7fELF\x02\x01\x01"
    struct.pack_into("<HHI", b, 16, 2, 62, 1)
    struct.pack_into("<Q", b, 32, 64)
    struct.pack_into("<HHH", b, 52, 64, 56, 1)
    struct.pack_into("<IIQQQQQQ", b, 64, 1, 5, 0, 0x400000, 0x400000, len(b), len(b), 0x1000)
    return bytes(b)


def iso(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + seconds))


class Clock:
    def __init__(self, now=1000.0):
        self.now = float(now)
        self._lock = threading.Lock()

    def __call__(self):
        with self._lock:
            return self.now

    def advance(self, seconds):
        with self._lock:
            self.now += float(seconds)
            return self.now


class Result:
    def __init__(self, returncode=0, stdout=b"", stderr=b""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def _b64(data):
    return base64.b64encode(data).decode("ascii")


class FakeProc:
    def __init__(self, code=0, stdout=b"", stderr=b"", block=None,
                 stubborn=None, stdin=None):
        self.code = code
        self._out = stdout
        self._err = stderr
        self.block = block
        self.stubborn = stubborn
        self.terminated = threading.Event()
        self.released = threading.Event()
        if block is None:
            self.released.set()
        self.stdin = stdin if stdin is not None else io.BytesIO()
        if stubborn is not None:
            self.stdout = stubborn
        else:
            self.stdout = io.BytesIO(stdout)
        self.stderr = io.BytesIO(stderr)
        self.returncode = code

    def poll(self):
        if self.terminated.is_set():
            return self.returncode if self.returncode != 0 else -15
        if not self.released.is_set():
            return None
        return self.code

    def wait(self, timeout=None):
        if self.terminated.is_set() or self.released.is_set():
            return self.poll()
        if not self.released.wait(timeout):
            raise subprocess.TimeoutExpired("fake", timeout)
        return self.poll()

    def terminate(self):
        self.terminated.set()
        self.released.set()
        if self.returncode == 0:
            self.returncode = -15

    def kill(self):
        self.terminate()
        self.returncode = -9


class StubbornStream:
    """A stream whose read never returns and whose close does nothing."""

    def __init__(self):
        self.release = threading.Event()

    def read(self, _size=-1):
        self.release.wait()
        return b""

    def close(self):
        return None


class PauseProc:
    """A worker process that exits only after the fixed pause signal."""

    def __init__(self, payload):
        self.stdout = io.BytesIO(payload)
        self.stderr = io.BytesIO()
        self.stdin = io.BytesIO()
        self.signalled = threading.Event()
        self.returncode = 0

    def poll(self):
        return self.returncode if self.signalled.is_set() else None

    def wait(self, timeout=None):
        if not self.signalled.wait(timeout):
            raise subprocess.TimeoutExpired("pause-fake", timeout)
        return self.returncode

    def terminate(self):
        self.signalled.set()

    def kill(self):
        self.signalled.set()


class StubbornProc:
    """A management process whose reader cannot be joined within a deadline."""

    def __init__(self):
        self.stdout = StubbornStream()
        self.stderr = io.BytesIO()
        self.stdin = io.BytesIO()
        self.returncode = 0

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        return self.returncode

    def terminate(self):
        return None

    def kill(self):
        return None


class FakeDocker:
    def __init__(self, image_id=IMAGE):
        self.image_id = image_id
        self.lock = threading.RLock()
        self.runs = []
        self.popens = []
        self.rm_calls = []
        self.containers = {}
        self.counter = 0
        self.daemon_error = False
        self.wrong_labels = False
        self.keep_after_rm = False
        self.fail_image = False
        self.huge_inspect = False
        self.block_worker = False
        self.pause_worker = False
        self.flood_worker = False
        self.stubborn_worker = False
        self.pause_event = threading.Event()
        self.kill_calls = []
        self.pause_process = None
        self.run_delay = 0.0
        self.run_deadlines = []
        self.popen_gate = None
        self.popen_entered = threading.Event()
        self.popen_envs = []
        self.worker_release = threading.Event()
        self.worker_started = threading.Event()
        self.worker_process = None
        self.stubborn_stream = None
        self.flood_process = None
        self._closed = False

    def _labels(self, argv):
        labels = {}
        for index, item in enumerate(argv):
            if item == "--label" and index + 1 < len(argv):
                key, _, value = argv[index + 1].partition("=")
                labels[key] = value
        return labels

    def _name(self, argv):
        try:
            return argv[argv.index("--name") + 1]
        except (ValueError, IndexError):
            return None

    def _find(self, value):
        with self.lock:
            if value in self.containers:
                return self.containers[value]
            for record in self.containers.values():
                if record["id"] == value:
                    return record
            return None

    def _no_such(self, value):
        return Result(1, b"", ("Error: No such object: %s" % value).encode())

    def run(self, argv, **kwargs):
        with self.lock:
            self.runs.append(list(argv))
            self.run_deadlines.append(kwargs.get("timeout"))
        if self.run_delay:
            time.sleep(self.run_delay)
        if self.daemon_error:
            return Result(1, b"", b"Cannot connect to the Docker daemon")
        if len(argv) >= 2 and argv[1] == "kill":
            self.kill_calls.append(list(argv))
            if self.pause_process is not None:
                self.pause_process.signalled.set()
            self.pause_event.set()
            return Result(0, b"", b"")
        if len(argv) >= 2 and argv[1] == "image":
            if self.fail_image:
                return Result(1, b"", b"image not found")
            return Result(0, (self.image_id + "\n").encode())
        if len(argv) >= 2 and argv[1] == "inspect":
            fmt = argv[3] if len(argv) > 3 else ""
            target = argv[4] if len(argv) > 4 else ""
            record = self._find(target)
            if record is None:
                return self._no_such(target)
            if fmt == "{{.Id}}":
                return Result(0, (record["id"] + "\n").encode())
            if self.huge_inspect:
                return Result(0, json.dumps({
                    "Id": record["id"], "Name": "/" + record["name"],
                    "Config": {"Labels": record["labels"]},
                    "Padding": "x" * (4 * 1024 * 1024),
                }).encode())
            labels = dict(record["labels"])
            if self.wrong_labels:
                labels["artex.owner"] = "wrong-owner"
            payload = {
                "Id": record["id"], "Name": "/" + record["name"],
                "Config": {"Labels": labels},
                "State": {"Running": record.get("running", False),
                          "Status": "running" if record.get("running") else "exited"},
            }
            return Result(0, json.dumps(payload).encode())
        if len(argv) >= 2 and argv[1] == "rm":
            target = argv[-1]
            with self.lock:
                self.rm_calls.append(target)
                record = self._find(target)
                if record is None:
                    return self._no_such(target)
                if not self.keep_after_rm:
                    record["removed"] = True
                    self.containers.pop(record["name"], None)
            return Result(0, b"", b"")
        return Result(1, b"", b"unsupported fake docker command")

    def _register(self, argv):
        name = self._name(argv)
        with self.lock:
            self.counter += 1
            record = {"name": name, "id": "cid-%d" % self.counter,
                      "labels": self._labels(argv), "running": True,
                      "removed": False}
            self.containers[name] = record
        return record

    def _role(self, argv):
        joined = " ".join(argv)
        if "--entrypoint" in argv:
            entry = argv[argv.index("--entrypoint") + 1]
            if entry == "/usr/bin/afl-fuzz":
                return "help-fuzz"
            if entry == "/usr/bin/afl-showmap":
                return "help-showmap"
        if "-c" in argv:
            script = argv[argv.index("-c") + 1]
            if "SUPERVISOR" in script or "def showmap" in script:
                if "showmap" in argv:
                    return "showmap"
                if "fuzz" in argv:
                    return "worker"
        return "worker"

    def popen(self, argv, **kwargs):
        with self.lock:
            self.popens.append(list(argv))
            self.popen_envs.append(kwargs.get("env"))
        if self.popen_gate is not None:
            self.popen_entered.set()
            if not self.popen_gate.wait(2):
                raise RuntimeError("popen gate was not released")
        record = self._register(argv)
        role = self._role(argv)
        if role == "help-fuzz":
            text = (b"afl-fuzz++4.04c\n-V seconds\n-E execs\n-G maxlength\n"
                    b"-i dir\n-o dir\n-m megs\n-t msec\n")
            return FakeProc(0, text)
        if role == "help-showmap":
            text = b"afl-showmap++4.04c\n-o file\n-q\n-m megs\n-t msec\n"
            return FakeProc(0, text)
        if role == "showmap":
            payload = {"exit": 0, "probe_map_base64": _b64(b"1:1\n2:2\n3:3")}
            return FakeProc(0, json.dumps(payload).encode())
        payload = {
            "exit": 0, "findings": True,
            "queue": [{"name": "id:000000", "sha256": hashlib.sha256(b"Q").hexdigest(),
                       "data_base64": _b64(b"Q")}],
            "crashes": [{"name": "id:000001", "sha256": hashlib.sha256(b"C").hexdigest(),
                         "data_base64": _b64(b"C")}],
            "stats_base64": _b64(b"execs_done:17\nsaved_crashes:1\n"),
            "truncated": False, "writes_stopped": True, "pause_handled": False,
        }
        if self.pause_worker:
            pause_payload = dict(payload, pause_handled=True, writes_stopped=True)
            pause_payload["queue"] = [{
                "name": "id:000007", "sha256": hashlib.sha256(b"P").hexdigest(),
                "data_base64": _b64(b"P")}]
            pause_payload["crashes"] = []
            process = PauseProc(json.dumps(pause_payload).encode())
            self.pause_process = process
            self.worker_process = process
            self.worker_started.set()
            return process
        if self.flood_worker:
            return FakeProc(0, b"x" * (2 * 1024 * 1024 + 4096))
        if self.stubborn_worker:
            self.stubborn_stream = StubbornStream()
            return FakeProc(0, b"", stubborn=self.stubborn_stream)
        if self.block_worker:
            process = FakeProc(0, json.dumps(payload).encode(),
                               block=self.worker_release)
            self.worker_process = process
            self.worker_started.set()
            return process
        return FakeProc(0, json.dumps(payload).encode())


def raw_frame(artifact, *, sha256=None, image_id=IMAGE, **overrides):
    frame = {
        "operation": "campaign", "task_id": 7,
        "request_id": "campaign-42-attempt-8", "campaign_id": 42,
        "attempt_id": 8, "attempt_no": 2, "fencing_token": 9001,
        "lease_owner": "owner", "lease_instance": "instance", "lease_ms": 30000, "lease_deadline": iso(20),
        "artifact_path": str(artifact), "sha256": sha256 or hashlib.sha256(elf64()).hexdigest(),
        "argv": [], "input_mode": "stdin",
        "seeds": [{"sha256": SEED_SHA, "data_base64": _b64(SEED)}],
        "max_executions": 1000, "max_crashes": 4,
        "attempt_budget_ms": 60000, "execution_window_ms": 55000,
        "execution_deadline": iso(30), "envelope_deadline": iso(60),
        "cleanup_reserve_ms": 5000, "cleanup_hard_timeout_ms": 2000,
        "profile": {
            "image": IMAGE, "image_id": image_id, "fuzz_enabled": True,
            "enabled": True, "network": "none", "read_only_root": True,
            "max_duration_ms": 900000,
        },
    }
    frame.update(overrides)
    return frame


def request(artifact, *, sha256=None, image_id=IMAGE, **overrides):
    return validate_campaign_start(raw_frame(
        artifact, sha256=sha256, image_id=image_id, **overrides))


def probe_request():
    return {
        "operation": "campaign_cleanup_probe", "request_id": "cleanup-42-8",
        "task_id": 7, "campaign_id": 42, "attempt_id": 8, "fencing_token": 9001,
    }


class BackendHarness(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="artex-t4b2-")
        self.root = Path(self.temp.name)
        self.artifact = self.root / "fixture.elf"
        self.artifact.write_bytes(elf64())
        self.fake = FakeDocker()
        self.backend = DockerCampaignBackend(
            docker="/usr/bin/fake-docker", popen=self.fake.popen,
            run=self.fake.run, clock=time.monotonic, temp_root=self.root)
        self.request = request(self.artifact)
        self.control = CampaignControl()

    def tearDown(self):
        self.fake.worker_release.set()
        if self.fake.stubborn_stream is not None:
            self.fake.stubborn_stream.release.set()
        self.temp.cleanup()

    def execute(self, deadline=10.0):
        return self.backend.execute(self.request, self.control,
                                    deadline=time.monotonic() + deadline)

    def cleanup(self, deadline=3.0):
        return self.backend.cleanup(self.request, deadline=time.monotonic() + deadline)


class CommandAndIsolationTests(BackendHarness):
    def test_success_builds_fixed_isolated_command_and_reports_candidate_only(self):
        result = self.execute()
        self.assertEqual(result["target_state"], "completed")
        self.assertEqual(result["manifest"]["image_id"], IMAGE)
        self.assertTrue(result["manifest"]["options_verified"])
        self.assertEqual(result["manifest"]["probe_edges"], 3)
        self.assertEqual(result["stats"]["execs_done"], 17)
        self.assertFalse(result["observed_execs_trusted"])
        self.assertTrue(result["candidate_only"])
        self.assertNotIn("findings", result)  # candidate-only, never a Finding
        self.assertEqual(self.fake.runs[0][1], "image")
        self.assertTrue(self.fake.popens)
        worker_cmd = self.fake.popens[-1]
        self.assertEqual(worker_cmd[0], "/usr/bin/fake-docker")
        self.assertIn("run", worker_cmd)
        for flag in ("--pull=never", "--network=none", "--read-only",
                     "--cap-drop=ALL", "--security-opt=no-new-privileges",
                     "--user=65534:65534", "--cpus=1", "--memory=512m",
                     "--pids-limit=128"):
            self.assertIn(flag, worker_cmd)
        self.assertIn("/work/out:rw,nosuid,nodev,noexec,size=64m,nr_inodes=2048,mode=1777",
                      worker_cmd)
        labels = self.fake._labels(worker_cmd)
        self.assertEqual(labels["artex.task_id"], "7")
        self.assertEqual(labels["artex.campaign_id"], "42")
        self.assertEqual(labels["artex.attempt_id"], "8")
        self.assertEqual(labels["artex.fencing_token"], "9001")
        self.assertEqual(labels["artex.owner"], "artex-native-campaign")
        self.assertEqual(worker_cmd[worker_cmd.index("--name") + 1],
                         "artex-campaign-42-8-8-9001")
        self.assertIn("--entrypoint", worker_cmd)
        self.assertEqual(worker_cmd[worker_cmd.index("--entrypoint") + 1],
                         "/usr/bin/python3")
        self.assertNotIn("shell", " ".join(worker_cmd).lower())
        self.assertIn("sample", " ".join(worker_cmd))
        self.assertIn("seeds", " ".join(worker_cmd))
        cleanup = self.cleanup()
        self.assertTrue(cleanup["owned_process_terminated"])
        self.assertTrue(cleanup["container_removed"])
        self.assertTrue(cleanup["staging_removed"])
        self.assertFalse(self.backend._staging.exists())

    def test_checkpoint_returns_supervisor_candidates_and_seed_fallback(self):
        self.execute()
        entries = self.backend.checkpoint(self.request, deadline=time.monotonic() + 2)
        self.assertEqual(len(entries), 2)
        self.assertEqual({item["source_type"] for item in entries}, {"queue", "crash"})
        self.assertEqual(self.cleanup()["container_removed"], True)

    def test_artifact_mismatch_is_rejected_before_any_command(self):
        bad = request(self.artifact, sha256="c" * 64)
        with self.assertRaises(ValueError):
            self.backend.execute(bad, self.control, deadline=time.monotonic() + 5)
        self.assertEqual(self.fake.runs, [])
        self.assertEqual(self.fake.popens, [])
        self.assertIsNone(self.backend._staging)

    def test_immutable_image_id_mismatch_rejected_before_containers(self):
        frame = request(self.artifact, image_id=OTHER_IMAGE)
        with self.assertRaises(ValueError):
            self.backend.execute(frame, self.control, deadline=time.monotonic() + 5)
        self.assertEqual(self.fake.popens, [])
        self.assertEqual(self.fake.runs, [])

    def test_image_daemon_failure_rejected_before_containers(self):
        self.fake.fail_image = True
        with self.assertRaises(ValueError):
            self.execute()
        self.assertEqual(self.fake.popens, [])


class DeadlineTests(BackendHarness):
    def test_management_commands_never_exceed_remaining_or_three_seconds(self):
        deadline = time.monotonic() + 7.0
        self.backend.execute(self.request, self.control, deadline=deadline)
        self.assertTrue(self.fake.run_deadlines)
        for value in self.fake.run_deadlines:
            self.assertLessEqual(value, 3.0)
        self.cleanup()

    def test_expired_deadline_starts_no_worker(self):
        self.execute()
        self.cleanup()
        fake = FakeDocker()
        backend = DockerCampaignBackend(
            docker="/usr/bin/fake-docker", popen=fake.popen, run=fake.run,
            clock=time.monotonic, temp_root=self.root)
        with self.assertRaises(Exception):
            backend.execute(self.request, self.control, deadline=time.monotonic() - 1)
        self.assertEqual(fake.popens, [])

    def test_stages_consume_one_deadline_and_do_not_reset_it(self):
        clock = Clock()
        fake = FakeDocker()
        backend = DockerCampaignBackend(
            docker="/usr/bin/fake-docker", popen=fake.popen, run=fake.run,
            clock=clock, temp_root=self.root)
        deadline = clock() + 15.0
        # Advance the shared clock during each management command to model
        # validation/staging/probe work consuming the same envelope.
        original_run = fake.run

        def slow_run(argv, **kwargs):
            if len(argv) > 1 and (argv[1] == "image"
                                  or (argv[1] == "inspect" and "{{.Id}}" in argv)):
                clock.advance(2.0)
            return original_run(argv, **kwargs)

        fake.run = slow_run
        backend.run = slow_run
        result = backend.execute(self.request, self.control, deadline=deadline)
        self.assertEqual(result["target_state"], "completed")
        worker = fake.popens[-1]
        seconds = int(worker[worker.index("-V") + 1])
        self.assertLessEqual(seconds, 7)
        self.assertGreaterEqual(seconds, 1)
        self.assertTrue(all(value is not None and value <= 3.0
                            for value in fake.run_deadlines))
        backend.cleanup(self.request, deadline=clock() + 2.0)


class ManagementExecutorTests(unittest.TestCase):
    def test_stdout_and_stderr_flood_is_capped_while_reading(self):
        with tempfile.TemporaryDirectory(prefix="artex-mgmt-") as root:
            backend = DockerCampaignBackend(temp_root=root)
            script = (
                "import sys;"
                "sys.stdout.buffer.write(b'x'*(16*1024*1024));"
                "sys.stdout.buffer.flush();"
                "sys.stderr.buffer.write(b'y'*(4*1024*1024));"
                "sys.stderr.buffer.flush()"
            )
            tracemalloc.start()
            try:
                with self.assertRaises(Exception):
                    backend._run_command(
                        [sys.executable, "-c", script],
                        time.monotonic() + 3)
                peak = tracemalloc.get_traced_memory()[1]
            finally:
                tracemalloc.stop()
            self.assertLess(peak, 4 * 1024 * 1024)
            self.assertFalse(backend._management_pending())

    def test_unreaped_management_reader_keeps_ownership_until_release(self):
        with tempfile.TemporaryDirectory(prefix="artex-mgmt-") as root:
            process = StubbornProc()
            backend = DockerCampaignBackend(
                popen=lambda *a, **k: process, temp_root=root)
            deadline = time.monotonic() + 0.1
            with self.assertRaises(Exception):
                backend._run_command(["fake-docker", "inspect", "x"], deadline)
            self.assertTrue(backend._management_pending())
            request = {"task_id": 7, "campaign_id": 42,
                       "attempt_id": 8, "fencing_token": 9001,
                       "cleanup_hard_timeout_ms": 1000}
            self.assertFalse(backend.stop(request, 0.02,
                                          deadline=time.monotonic() + 0.03))
            report = backend.cleanup(request, deadline=time.monotonic() + 0.03)
            self.assertFalse(all(report[key] is True for key in
                                 ("owned_process_terminated", "container_removed",
                                  "staging_removed")))
            self.assertNotEqual(backend.ownership(request), "terminated")
            process.stdout.release.set()
            # Actual reader completion can now be observed; this still cannot
            # become a verified cleanup without the normal cleanup path.
            settle = time.monotonic() + 1
            while time.monotonic() < settle:
                if not backend._management_pending():
                    break
                time.sleep(0.01)
            self.assertFalse(backend._management_pending())
            self.assertNotEqual(backend.ownership(request), "terminated")

    def test_file_input_placeholder_becomes_afl_at(self):
        with tempfile.TemporaryDirectory(prefix="artex-mgmt-") as root:
            artifact = Path(root) / "fixture.elf"
            artifact.write_bytes(elf64())
            req = request(artifact, input_mode="file",
                          argv=["--input", "{input}"])
            backend = DockerCampaignBackend(temp_root=root)
            args = backend._worker_args(req, time.monotonic() + 10)
            self.assertEqual(args[args.index("--") + 1:],
                             ["/work/sample", "--input", "@@"])


class PauseCancelTests(BackendHarness):
    def test_pause_stops_worker_then_checkpoint_then_cleanup(self):
        self.fake.pause_worker = True
        box = {}

        def run():
            try:
                box["result"] = self.backend.execute(
                    self.request, self.control, deadline=time.monotonic() + 5)
            except Exception as exc:  # noqa: BLE001
                box["error"] = exc

        thread = threading.Thread(target=run)
        thread.start()
        try:
            self.assertTrue(self.fake.worker_started.wait(2))
            self.control.request("pause", "paused")
            thread.join(3)
            self.assertFalse(thread.is_alive())
            from .campaign import CampaignPaused
            self.assertIsInstance(box.get("error"), CampaignPaused)
            self.assertTrue(self.fake.kill_calls)
            expected_id = self.fake.containers[
                "artex-campaign-42-8-8-9001"]["id"]
            self.assertEqual(self.fake.kill_calls[0][-1], expected_id)
            self.assertIn("--signal=USR1", self.fake.kill_calls[0])
            entries = self.backend.checkpoint(self.request,
                                              deadline=time.monotonic() + 2)
            self.assertEqual([item["data"] for item in entries], [b"P"])
            cleanup = self.cleanup()
            self.assertTrue(cleanup["owned_process_terminated"])
        finally:
            thread.join(3)

    def test_cancel_preempts_pause(self):
        self.fake.block_worker = True
        box = {}

        def run():
            try:
                self.backend.execute(self.request, self.control,
                                     deadline=time.monotonic() + 5)
            except Exception as exc:  # noqa: BLE001
                box["error"] = exc

        thread = threading.Thread(target=run)
        thread.start()
        try:
            self.assertTrue(self.fake.worker_started.wait(2))
            self.control.request("pause", "pause")
            self.control.request("cancel", "cancel")
            thread.join(3)
            self.assertFalse(thread.is_alive())
            from .campaign import CampaignCancelled
            self.assertIsInstance(box.get("error"), CampaignCancelled)
            self.assertTrue(self.fake.worker_process.terminated.is_set())
        finally:
            self.fake.worker_release.set()
            thread.join(3)


class ResourcePlanTests(BackendHarness):
    def plan(self, root):
        base = "artex-campaign-42-8-8-9001"
        return {"version": 1, "task_id": 7, "campaign_id": 42, "attempt_id": 8,
                "fencing_token": 9001, "staging_root": root,
                "staging_basename": base + "-stage",
                "container_names": [base, base + "-help-afl-fuzz",
                                    base + "-help-afl-showmap", base + "-probe"]}

    def test_canonical_resource_plan_and_hard_rejection(self):
        plan = self.plan('/var/tmp/\u79cd\u5b50"<&>\u2028')
        self.assertEqual(mod.resource_plan_digest(plan),
                         "6626f527fc725c14fb8785b331b9b5ba8dafe9ee953dd26dd74d2c6e9da3189f")
        self.assertEqual(mod.resource_plan_digest(dict(reversed(list(plan.items())))),
                         mod.resource_plan_digest(plan))
        for bad in (None, {}, dict(plan, version=2), dict(plan, task_id=8),
                    dict(plan, staging_root="/tmp/a\\b"), dict(plan, unknown=True)):
            with self.subTest(plan=bad), self.assertRaises(ValueError):
                validate_campaign_start(raw_frame(self.artifact, resource_plan=bad))

    @unittest.skipUnless(os.name == "posix", "private fd-relative staging requires POSIX")
    def test_private_planned_stage_is_exclusive_and_root_bound(self):
        os.chmod(self.root, 0o700)
        self.request["resource_plan"] = self.plan(str(self.root))
        # The fixture identity is asserted rather than weakening plan binding.
        for key in ("task_id", "campaign_id", "attempt_id", "fencing_token"):
            self.assertEqual(self.request[key], self.request["resource_plan"][key])
        stage = self.backend._ensure_staging(self.request, time.monotonic() + 1)
        self.assertEqual(stage.name, self.request["resource_plan"]["staging_basename"])
        other = DockerCampaignBackend(temp_root=self.root)
        with self.assertRaises(FileExistsError):
            other._ensure_staging(self.request, time.monotonic() + 1)
        altered = dict(self.request)
        altered["resource_plan"] = self.plan(str(self.root) + "/different")
        with self.assertRaises(CampaignBackendError):
            DockerCampaignBackend(temp_root=self.root)._ensure_staging(altered, time.monotonic() + 1)

    @unittest.skipUnless(os.name == "posix", "private fd-relative staging requires POSIX")
    def test_complete_backend_creation_seal_is_plan_bound(self):
        os.chmod(self.root, 0o700)
        self.request["resource_plan"] = self.plan(str(self.root))
        original = self.fake.popen
        def full_id_popen(*args, **kwargs):
            proc = original(*args, **kwargs)
            for name, record in self.fake.containers.items():
                record["id"] = hashlib.sha256(name.encode()).hexdigest()
            return proc
        self.backend.popen = full_id_popen
        self.execute()
        self.cleanup()
        seal = self.backend.creation_seal(self.request)
        self.assertIsNotNone(seal)
        self.assertEqual(seal["plan_sha256"], mod.resource_plan_digest(self.request["resource_plan"]))
        self.assertEqual(len(seal["containers"]), len(self.backend._records))
        self.assertTrue(all(len(item["id"]) == 64 for item in seal["containers"]))
        with self.assertRaises(CampaignBackendError):
            self.backend._check_open_locked()
        self.backend._records[0]["verified_creation_id"] = None
        self.assertIsNone(self.backend.creation_seal(self.request))

    @unittest.skipUnless(os.name == "posix", "private fd-relative staging requires POSIX")
    def test_planned_stage_rejects_nonprivate_root(self):
        os.chmod(self.root, 0o755)
        self.request["resource_plan"] = self.plan(str(self.root))
        with self.assertRaises(CampaignBackendError):
            self.backend._ensure_staging(self.request, time.monotonic() + 1)
        self.assertFalse((self.root / self.request["resource_plan"]["staging_basename"]).exists())


@unittest.skipUnless(os.name == "posix", "sealed staging cleanup requires POSIX")
class SealedProbeTests(BackendHarness):
    def sealed_request(self):
        os.chmod(self.root, 0o700)
        plan = ResourcePlanTests.plan(self, str(self.root))
        labels = mod._expected_labels(self.request)
        entries = [{"name": name, "id": hashlib.sha256(name.encode()).hexdigest(),
                    "labels": dict(labels)} for name in plan["container_names"]]
        for item in entries:
            self.fake.containers[item["name"]] = dict(item, running=True)
        stage = self.root / plan["staging_basename"]
        stage.mkdir(mode=0o700)
        (stage / "fixture").write_bytes(b"owned")
        seal = {"version": 1, "task_id": 7, "campaign_id": 42, "attempt_id": 8,
                "fencing_token": 9001, "plan_sha256": mod.resource_plan_digest(plan),
                "staging_basename": plan["staging_basename"], "containers": entries}
        original = self.fake.run
        def run(argv, **kwargs):
            if argv[1] == "ps":
                self.assertIn("--no-trunc", argv)
                self.assertEqual(argv.count("--filter"), 5)
                if self.fake.daemon_error:
                    return Result(1, b"", b"Cannot connect to daemon")
                ids = getattr(self, "discovered_ids", None)
                if ids is None:
                    ids = [item["id"] for item in self.fake.containers.values()]
                return Result(0, "\n".join(ids).encode())
            return original(argv, **kwargs)
        self.backend.run = run
        return validate_cleanup_probe(dict(probe_request(), resource_plan=plan, creation_seal=seal))

    def test_sealed_probe_removes_exact_complete_set_and_stage(self):
        request = self.sealed_request()
        frames = []
        result = serve_cleanup_probe(request, frames.append, backend=self.backend, timeout=3)
        self.assertEqual(result, 0)
        report = frames[-1]["observation"]
        self.assertTrue(report["cleanup_verified"])
        expected = {item["id"] for item in request["creation_seal"]["containers"]}
        self.assertEqual(set(self.fake.rm_calls), expected)
        self.assertEqual({item["id"] for item in report["containers"]}, expected)
        self.assertEqual(report["plan_sha256"], request["creation_seal"]["plan_sha256"])
        self.assertFalse((self.root / request["resource_plan"]["staging_basename"]).exists())

    def test_sealed_cleanup_accepts_actual_write_staging_layout(self):
        request = self.sealed_request()
        stage = self.root / request["resource_plan"]["staging_basename"]
        (stage / "fixture").unlink()
        stage.rmdir()
        self.request["resource_plan"] = request["resource_plan"]
        self.backend._write_staging(self.request, elf64(), time.monotonic() + 2)
        self.assertEqual(stat.S_IMODE(stage.stat().st_mode), 0o700)
        self.assertEqual(stat.S_IMODE((stage / "seeds").stat().st_mode), 0o755)
        report = self.backend.probe_cleanup(request, 2)
        self.assertTrue(report["cleanup_verified"], report)
        self.assertFalse(stage.exists())

    def test_sealed_final_filesystem_operation_cannot_overrun_deadline(self):
        request = self.sealed_request()
        now = [10.0]
        self.backend.clock = lambda: now[0]
        original = self.backend._remove_planned_staging
        def late_remove(plan, deadline):
            result = original(plan, deadline)
            now[0] = deadline + 0.1
            return result
        with mock.patch.object(self.backend, "_remove_planned_staging", side_effect=late_remove):
            report = self.backend.probe_cleanup(request, 1)
        self.assertFalse(report["cleanup_verified"])
        self.assertTrue(report["hard_timeout"])

    def test_sealed_discovery_extra_or_overflow_never_deletes(self):
        request = self.sealed_request()
        for ids in (["f" * 64], [format(i, "064x") for i in range(9)]):
            self.discovered_ids = ids
            report = self.backend.probe_cleanup(request, 1)
            self.assertFalse(report["cleanup_verified"])
            self.assertEqual(self.fake.rm_calls, [])

    def test_sealed_label_mismatch_never_deletes(self):
        request = self.sealed_request()
        self.fake.wrong_labels = True
        report = self.backend.probe_cleanup(request, 1)
        self.assertFalse(report["cleanup_verified"])
        self.assertEqual(self.fake.rm_calls, [])

    def test_sealed_stage_symlink_is_not_followed(self):
        request = self.sealed_request()
        outside = self.root / "outside"
        outside.write_bytes(b"preserve")
        stage = self.root / request["resource_plan"]["staging_basename"]
        (stage / "escape").symlink_to(outside)
        report = self.backend.probe_cleanup(request, 1)
        self.assertFalse(report["cleanup_verified"])
        self.assertEqual(outside.read_bytes(), b"preserve")
        self.assertTrue(stage.exists())

    def test_sealed_stage_scan_limit_stays_unknown(self):
        request = self.sealed_request()
        stage = self.root / request["resource_plan"]["staging_basename"]
        for i in range(3):
            (stage / str(i)).write_bytes(b"x")
        with mock.patch.object(mod, "MAX_SCAN_ENTRIES", 2):
            report = self.backend.probe_cleanup(request, 1)
        self.assertFalse(report["cleanup_verified"])
        self.assertTrue(stage.exists())

    def test_sealed_pending_creator_stays_unknown(self):
        request = self.sealed_request()
        self.backend._records.append({"state": "creating"})
        report = self.backend.probe_cleanup(request, 1)
        self.assertFalse(report["cleanup_verified"])
        self.assertEqual(self.fake.rm_calls, [])

    def test_sealed_protocol_and_report_cannot_downgrade(self):
        request = self.sealed_request()
        missing = dict(request)
        missing.pop("creation_seal")
        with self.assertRaises(ValueError):
            validate_cleanup_probe(missing)
        report = {"cleanup_verified": True, "errors": [], "hard_timeout": False,
                  "staging": {"present": False, "removed": True},
                  "plan_sha256": request["creation_seal"]["plan_sha256"],
                  "staging_basename": request["resource_plan"]["staging_basename"],
                  "containers": [{"name": request["creation_seal"]["containers"][0]["name"],
                                  "id": request["creation_seal"]["containers"][0]["id"],
                                  "state": "absent", "labels_match": True}]}
        self.assertFalse(_sanitize_cleanup_report(report, request)["cleanup_verified"])


class CleanupOwnershipTests(BackendHarness):
    def test_creation_resources_require_positive_complete_identity(self):
        self.backend._request = self.request
        object_id = "d" * 64
        handle = mock.Mock()
        handle.finished.return_value = True
        record = {"name": "owned", "id": object_id,
                  "labels": mod._expected_labels(self.request),
                  "process": handle, "state": "running", "removed": False}
        self.backend._records.append(record)
        self.backend._processes.append(handle)
        self.assertIsNone(self.backend.close_creation_resources())
        with self.assertRaises(CampaignBackendError):
            self.backend._check_open_locked()
        info = {"Id": object_id, "Name": "/owned",
                "Config": {"Labels": dict(record["labels"])}}
        with mock.patch.object(self.backend, "_run_command",
                               return_value=Result(0, json.dumps(info).encode())):
            status, _ = self.backend._inspect_container(
                object_id, record, time.monotonic() + 1)
        self.assertEqual(status, "present")
        resources = self.backend.close_creation_resources()
        self.assertEqual(resources[0]["id"], object_id)
        record["removed"] = True
        self.assertEqual(self.backend.close_creation_resources(), resources)
        handle.finished.return_value = False
        self.assertIsNone(self.backend.close_creation_resources())
        handle.finished.return_value = True
        record["state"] = "creating"
        self.assertIsNone(self.backend.close_creation_resources())

    def test_inspect_missing_name_never_records_creation_evidence(self):
        self.backend._request = self.request
        object_id = "e" * 64
        record = {"name": "owned", "id": object_id,
                  "labels": mod._expected_labels(self.request)}
        info = {"Id": object_id, "Config": {"Labels": record["labels"]}}
        with mock.patch.object(self.backend, "_run_command",
                               return_value=Result(0, json.dumps(info).encode())):
            status, _ = self.backend._inspect_container(
                object_id, record, time.monotonic() + 1)
        self.assertEqual(status, "mismatch")
        self.assertNotIn("verified_creation_id", record)

    def test_absence_requires_exact_target_and_complete_error(self):
        target = "a" * 64
        self.assertTrue(self.backend._absent_result(Result(1, b"", ("Error: No such object: " + target).encode()), target))
        for message in ("Error: No such object: " + "b" * 64,
                        "Cannot connect to daemon\nError: No such object: " + target,
                        "Error: No such object: " + target + "\npermission denied"):
            self.assertFalse(self.backend._absent_result(Result(1, b"", message.encode()), target))
        self.assertFalse(self.backend._absent_result(Result(1, b"partial", ("Error: No such object: " + target).encode()), target))

    def test_failed_cli_without_cid_never_proves_cleanup(self):
        # Both a daemon error and explicit name absence leave a potentially
        # accepted/late daemon create unresolved, even after the CLI exits.
        self.backend._request = self.request
        for daemon_error in (False, True):
            with self.subTest(daemon_error=daemon_error):
                self.fake.daemon_error = daemon_error
                record = {"name": "unresolved-create", "id": None,
                          "process": FakeProc(code=1), "failed": "CLI failed",
                          "removed": False}
                self.assertFalse(self.backend._remove_container(
                    record, time.monotonic() + 1.0))
                self.assertFalse(record["removed"])
                self.assertEqual(self.fake.rm_calls, [])


    def test_wrong_label_is_never_deleted(self):
        self.fake.keep_after_rm = True
        self.execute()
        self.fake.wrong_labels = True
        before = len(self.fake.rm_calls)
        report = self.cleanup()
        self.assertFalse(report["container_removed"])
        self.assertEqual(len(self.fake.rm_calls), before)
        self.assertNotEqual(self.backend.ownership(self.request), "terminated")

    def test_daemon_error_keeps_hold(self):
        self.fake.keep_after_rm = True
        self.execute()
        self.fake.daemon_error = True
        before = len(self.fake.rm_calls)
        report = self.cleanup()
        self.assertFalse(report["container_removed"])
        self.assertEqual(len(self.fake.rm_calls), before)
        self.assertNotEqual(self.backend.ownership(self.request), "terminated")

    def test_cli_exited_but_container_still_present_is_not_removed(self):
        self.fake.keep_after_rm = True
        self.execute()
        report = self.cleanup()
        self.assertFalse(report["container_removed"])
        self.assertNotEqual(self.backend.ownership(self.request), "terminated")

    def test_blocking_management_command_is_bounded_and_unknown(self):
        self.fake.keep_after_rm = True
        self.execute()
        self.fake.run_delay = 0.8
        started = time.monotonic()
        report = self.backend.cleanup(self.request, deadline=time.monotonic() + 0.15)
        elapsed = time.monotonic() - started
        self.assertFalse(report["container_removed"])
        self.assertLess(elapsed, 1.0)

    def test_reader_that_never_exits_keeps_unknown(self):
        self.fake.stubborn_worker = True
        with self.assertRaises(CampaignOwnershipUnknown):
            self.execute(deadline=3.0)
        report = self.cleanup(deadline=0.2)
        self.assertFalse(report["owned_process_terminated"])
        self.assertNotEqual(self.backend.ownership(self.request), "terminated")

    def test_flooded_worker_output_is_bounded_and_not_success(self):
        self.fake.flood_worker = True
        with self.assertRaises(CampaignBackendError):
            self.execute(deadline=3.0)
        self.cleanup()

    def test_cleanup_after_verified_is_idempotent_and_closed(self):
        self.execute()
        first = self.cleanup()
        self.assertTrue(first["container_removed"])
        popens = len(self.fake.popens)
        second = self.cleanup()
        self.assertEqual(first, second)
        with self.assertRaises(CampaignBackendError):
            self.backend.execute(self.request, self.control,
                                 deadline=time.monotonic() + 5)
        self.assertEqual(len(self.fake.popens), popens)

    def test_late_create_during_cleanup_timeout_is_stopped_and_not_verified(self):
        self.fake.popen_gate = threading.Event()
        box = {}

        def run():
            try:
                self.backend.execute(self.request, self.control,
                                     deadline=time.monotonic() + 5)
            except Exception as exc:  # noqa: BLE001
                box["error"] = exc

        thread = threading.Thread(target=run)
        thread.start()
        try:
            self.assertTrue(self.fake.popen_entered.wait(2))
            started = time.monotonic()
            report = self.backend.cleanup(self.request,
                                          deadline=time.monotonic() + 0.2)
            elapsed = time.monotonic() - started
            self.assertFalse(report["container_removed"])
            self.assertLess(elapsed, 1.0)
            self.fake.popen_gate.set()
            thread.join(2)
            self.assertFalse(thread.is_alive())
            self.assertIsInstance(box.get("error"), CampaignBackendError)
            self.assertNotEqual(self.backend.ownership(self.request), "terminated")
        finally:
            self.fake.popen_gate.set()
            thread.join(3)

    def test_management_environment_is_a_mapping_not_a_callable(self):
        self.execute()
        self.assertTrue(self.fake.popen_envs)
        for environment in self.fake.popen_envs:
            self.assertIsInstance(environment, dict)

    def test_stop_does_not_confirm_live_container_from_cli_exit(self):
        self.fake.keep_after_rm = True
        self.execute()
        self.assertFalse(self.backend.stop(self.request, 0.5,
                                           deadline=time.monotonic() + 1))

    def test_checkpoint_refuses_a_live_owned_writer(self):
        self.backend._bind(self.request)
        self.backend._records.append({
            "name": "artex-campaign-42-8-8-9001", "id": "cid-live",
            "labels": {}, "process": None, "removed": False, "started": True,
            "failed": "", "writes_stopped": False,
        })
        with self.assertRaises(CampaignBackendError):
            self.backend.checkpoint(self.request, deadline=time.monotonic() + 1)

    def test_oversized_management_response_cannot_authorize_deletion(self):
        self.fake.keep_after_rm = True
        self.execute()
        self.fake.huge_inspect = True
        snapshot = self.backend.ownership_snapshot()
        before = len(self.fake.rm_calls)
        report = self.backend.probe_cleanup(
            probe_request(), 1, ownership_snapshot=snapshot)
        self.assertFalse(report["cleanup_verified"])
        self.assertEqual(len(self.fake.rm_calls), before)

    def test_concurrent_stop_and_cleanup_are_bounded_and_join(self):
        self.fake.block_worker = True
        started = threading.Event()

        def run():
            try:
                self.backend.execute(self.request, self.control,
                                     deadline=time.monotonic() + 5)
            except Exception:
                pass
            finally:
                started.set()

        thread = threading.Thread(target=run)
        thread.start()
        self.assertTrue(self.fake.worker_started.wait(2))
        stop_box = {}
        clean_box = {}

        def stop():
            stop_box["value"] = self.backend.stop(self.request, 0.1,
                                                  deadline=time.monotonic() + 0.2)

        def cleanup():
            clean_box["value"] = self.backend.cleanup(
                self.request, deadline=time.monotonic() + 1.0)

        s = threading.Thread(target=stop)
        c = threading.Thread(target=cleanup)
        s.start()
        c.start()
        s.join(2)
        c.join(2)
        self.assertFalse(s.is_alive())
        self.assertFalse(c.is_alive())
        self.assertIn("value", stop_box)
        self.assertIn("value", clean_box)
        self.fake.worker_release.set()
        started.wait(2)
        thread.join(3)
        self.assertFalse(thread.is_alive())


class ProbeTests(BackendHarness):
    def test_probe_without_trusted_snapshot_is_unknown_and_never_executes(self):
        report = self.backend.probe_cleanup(probe_request(), 2)
        self.assertFalse(report["cleanup_verified"])
        self.assertEqual(report["containers"], [])
        self.assertFalse(report["staging"]["removed"])
        self.assertEqual(self.fake.popens, [])
        self.assertEqual(self.fake.runs, [])

    def test_probe_with_snapshot_uses_exact_id_and_labels_without_new_container(self):
        self.fake.keep_after_rm = True
        self.execute()
        snapshot = self.backend.ownership_snapshot()
        self.fake.keep_after_rm = False
        popens = len(self.fake.popens)
        report = self.backend.probe_cleanup(
            probe_request(), 2, ownership_snapshot=snapshot)
        self.assertTrue(report["cleanup_verified"])
        self.assertEqual(len(self.fake.popens), popens)
        self.assertTrue(self.fake.rm_calls)
        self.assertTrue(self.backend._staging is None or not self.backend._staging.exists())

    def test_probe_mismatched_labels_does_not_delete(self):
        self.fake.keep_after_rm = True
        self.execute()
        snapshot = self.backend.ownership_snapshot()
        self.fake.wrong_labels = True
        before = len(self.fake.rm_calls)
        report = self.backend.probe_cleanup(
            probe_request(), 2, ownership_snapshot=snapshot)
        self.assertFalse(report["cleanup_verified"])
        self.assertEqual(len(self.fake.rm_calls), before)

    def test_probe_rejects_untrusted_or_outside_staging(self):
        snapshot = {
            "trusted": True, "task_id": 7, "campaign_id": 42,
            "attempt_id": 8, "fencing_token": 9001,
            "containers": [], "staging": "/etc/passwd",
        }
        report = self.backend.probe_cleanup(
            probe_request(), 2, ownership_snapshot=snapshot)
        self.assertFalse(report["cleanup_verified"])
        self.assertFalse(report["staging"]["removed"])

    def test_probe_without_snapshot_for_other_attempt_is_unknown(self):
        self.execute()
        other = dict(probe_request(), attempt_id=9)
        fresh = DockerCampaignBackend(
            docker="/usr/bin/fake-docker", popen=self.fake.popen,
            run=self.fake.run, clock=time.monotonic, temp_root=self.root)
        report = fresh.probe_cleanup(other, 2)
        self.assertFalse(report["cleanup_verified"])


class CheckpointSafetyTests(BackendHarness):
    def _collect(self):
        self.execute()
        self.assertIsNotNone(self.backend._staging)
        collect = Path(self.backend._staging) / "collect"
        (collect / "queue").mkdir(parents=True)
        (collect / "crashes").mkdir(parents=True)
        return collect

    def test_scan_returns_relative_entries_and_dedups(self):
        collect = self._collect()
        (collect / "queue" / "id:000000").write_bytes(b"A")
        (collect / "crashes" / "id:000001").write_bytes(b"B")
        entries = self.backend.checkpoint(self.request, deadline=time.monotonic() + 2)
        self.assertEqual({item["source_type"] for item in entries}, {"queue", "crash"})
        self.assertTrue(all(not item["source_ref"].startswith("/") for item in entries))
        # A duplicate object from a later source keeps the first source.
        before = len(entries)
        (collect / "crashes" / "id:000002").write_bytes(b"A")
        entries = self.backend.checkpoint(self.request, deadline=time.monotonic() + 2)
        self.assertEqual(len(entries), before)

    def test_symlink_is_rejected(self):
        collect = self._collect()
        outside = self.root / "outside"
        outside.write_bytes(b"secret")
        link = collect / "queue" / "id:000002"
        try:
            link.symlink_to(outside)
        except OSError as exc:
            self.skipTest("symlink unavailable: " + str(exc))
        with self.assertRaises(ValueError):
            self.backend.checkpoint(self.request, deadline=time.monotonic() + 2)

    def test_hardlink_is_rejected(self):
        collect = self._collect()
        source = collect / "queue" / "id:000003"
        source.write_bytes(b"hard")
        link = collect / "queue" / "id:000004"
        try:
            os.link(source, link)
        except OSError as exc:
            self.skipTest("hardlink unavailable: " + str(exc))
        with self.assertRaises(ValueError):
            self.backend.checkpoint(self.request, deadline=time.monotonic() + 2)

    def test_malicious_and_absolute_names_rejected(self):
        collect = self._collect()
        (collect / "queue" / "evil name").write_bytes(b"x")
        with self.assertRaises(ValueError):
            self.backend.checkpoint(self.request, deadline=time.monotonic() + 2)
        with self.assertRaises(ValueError):
            self.backend._bound_entries([{
                "data": b"x", "source_type": "queue",
                "source_ref": "/etc/passwd"}])
        with self.assertRaises(ValueError):
            self.backend._bound_entries([{
                "data": b"x", "source_type": "queue",
                "source_ref": "../outside"}])

    def test_enumeration_file_and_byte_caps_are_explicit(self):
        collect = self._collect()
        for index in range(MAX_SCAN_ENTRIES + 1):
            (collect / "queue" / ("id:%06d" % index)).write_bytes(b"x")
        with patch("scripts.native_runner.campaign_backend.MAX_SCAN_ENTRIES", 8):
            entries = self.backend.checkpoint(self.request,
                                              deadline=time.monotonic() + 2)
        self.assertLessEqual(len(entries), 8)
        # Per-file and total caps never retain an oversized object.
        for child in (collect / "queue").iterdir():
            child.unlink()
        (collect / "queue" / "id:000000").write_bytes(b"x" * 4097)
        entries = self.backend.checkpoint(self.request, deadline=time.monotonic() + 2)
        self.assertTrue(all(item["data"] != b"x" * 4097 for item in entries))
        with patch("scripts.native_runner.campaign_backend.MAX_CHECKPOINT_BYTES", 3):
            (collect / "queue" / "id:000000").write_bytes(b"AAAA")
            (collect / "queue" / "id:000001").write_bytes(b"BBBB")
            entries = self.backend.checkpoint(self.request,
                                              deadline=time.monotonic() + 2)
        self.assertTrue(all(len(item["data"]) <= 3 for item in entries))

    def test_checkpoint_falls_back_to_seeds_when_no_output(self):
        self.execute()
        self.backend._checkpoint_memory = []
        self.backend._checkpoint_truncated = False
        entries = self.backend.checkpoint(self.request, deadline=time.monotonic() + 2)
        self.assertTrue(entries)
        self.assertTrue(all(item["source_type"] == "seed" for item in entries))


class CampaignRunnerIntegrationTests(BackendHarness):
    def test_runner_final_has_candidate_only_and_verified_cleanup(self):
        from .campaign import serve_campaign

        frames = []

        class Controls:
            def readline(self, _limit=-1):
                return ""

        code = serve_campaign(raw_frame(self.artifact), Controls(), frames.append,
                              backend=self.backend)
        self.assertEqual(code, 0)
        final = [frame for frame in frames if frame.get("kind") == "final"][-1]
        self.assertTrue(final["observation"]["cleanup_verified"])
        self.assertEqual(final["observation"]["cleanup"], {
            "owned_process_terminated": True, "container_removed": True,
            "staging_removed": True})
        self.assertTrue(final["observation"]["candidate_only"])


def supervisor_namespace():
    tree=ast.parse(mod.PAUSE_SUPERVISOR)
    # Exclude only top-level executable entrypoint try, retaining real helpers.
    tree.body=[n for n in tree.body if isinstance(n,(ast.Import,ast.ImportFrom,ast.FunctionDef,ast.Assign,ast.ClassDef))]
    ns={};exec(compile(tree,'<independent-supervisor-definitions>','exec'),ns);return ns
class ProductionLifecycleRegressionTests(unittest.TestCase):
    def test_management_per_command_cap(self):
        children=[]
        def popen(*a,**kw):
            p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(.2)'],**kw);children.append(p);return p
        b=mod.DockerCampaignBackend(popen=popen,management_timeout=.03)
        start=time.monotonic()
        try:
            with self.assertRaises(mod.CampaignBackendTimeout):
                b._run_command(['fake-management'],start+.5)
            elapsed=time.monotonic()-start
            self.assertLess(elapsed,.15,'30ms command cap was replaced by 500ms overall deadline')
        finally:
            for p in children:
                if p.poll() is None:p.kill()
                p.wait(timeout=2)
                for s in (p.stdout,p.stderr):
                    if s:s.close()
    def test_late_start_automatically_stops_and_reaps(self):
        entered=threading.Event();release=threading.Event();created=threading.Event();children=[]
        def popen(*a,**kw):
            entered.set();release.wait()
            p=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)'],**kw)
            children.append(p);created.set();return p
        b=mod.DockerCampaignBackend(popen=popen,management_timeout=.03)
        try:
            with self.assertRaises(mod.CampaignBackendTimeout):b._run_command(['fake-management'],time.monotonic()+.2)
            self.assertTrue(entered.is_set());release.set();self.assertTrue(created.wait(1))
            # No further cleanup call: timed-out starter must hand late resources
            # to a completion owner rather than await an unspecified future call.
            until=time.monotonic()+.6
            while time.monotonic()<until and children[0].poll() is None:time.sleep(.01)
            self.assertIsNotNone(children[0].poll(),'late management child remains alive after the initiating call timed out')
        finally:
            release.set();created.wait(1)
            for p in children:
                if p.poll() is None:p.kill()
                p.wait(timeout=2)
                for s in (p.stdout,p.stderr):
                    if s:s.close()
            b._stop_management(time.monotonic()+.3)
    @unittest.skipUnless(sys.platform == "linux", "Linux process-group proof")
    def test_pause_group_descendant_writer_stopped_before_return(self):
        # Adopt our deliberately orphaned benign writer so finally can reap it.
        libc=ctypes.CDLL(None,use_errno=True)
        previous = ctypes.c_int()
        self.assertEqual(libc.prctl(37, ctypes.byref(previous), 0, 0, 0), 0)
        self.assertEqual(libc.prctl(36,1,0,0,0),0)
        self.addCleanup(lambda: self.assertEqual(libc.prctl(36, previous.value, 0, 0, 0), 0))
        ns=supervisor_namespace();leader=None;child=None;pgid=None
        with tempfile.TemporaryDirectory(prefix='artex-owned-pause-audit-') as tmp:
            marker=pathlib.Path(tmp)/'counter'
            childcode="import signal,time,pathlib,sys;signal.signal(signal.SIGTERM,signal.SIG_IGN);p=pathlib.Path(sys.argv[1]);i=0\nwhile True:\n i+=1;p.write_text(str(i));time.sleep(.01)"
            leadercode="import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c',sys.argv[1],sys.argv[2]]); print(p.pid,flush=True); time.sleep(30)"
            try:
                leader=subprocess.Popen([sys.executable,'-c',leadercode,childcode,str(marker)],start_new_session=True,stdout=subprocess.PIPE,text=True)
                pgid=leader.pid;self.assertEqual(os.getpgid(leader.pid),pgid)
                child=int(leader.stdout.readline())
                until=time.monotonic()+1
                while not marker.exists() and time.monotonic()<until:time.sleep(.01)
                self.assertTrue(marker.exists())
                ns['_stop_group'](leader)
                before=marker.read_text();time.sleep(.08);after=marker.read_text()
                self.assertEqual(before,after,'same-group child ignored TERM and continued writing after _stop_group returned')
            finally:
                # Only the uniquely created process group above is signalled.
                if pgid is not None:
                    try:os.killpg(pgid,signal.SIGKILL)
                    except ProcessLookupError:pass
                if leader is not None:
                    leader.wait(timeout=2)
                    if leader.stdout:leader.stdout.close()
                if child is not None:
                    end=time.monotonic()+2
                    while time.monotonic()<end:
                        try:
                            got,_=os.waitpid(child,os.WNOHANG)
                            if got==child:break
                        except ChildProcessError:break
                        time.sleep(.01)
                    else:raise AssertionError('owned child was not reaped')
    def test_private_supervisor_collector_enumeration_bounded(self):
        ns=supervisor_namespace()
        class Entry:
            name='id:000001'
        class InfiniteEnough:
            def __iter__(self):
                for _ in range(4096):yield Entry()
                raise AssertionError('private supervisor collected entire oversized directory before applying count cap')
            def __enter__(self):return self
            def __exit__(self,*a):return False
        with tempfile.TemporaryDirectory(prefix='artex-collector-audit-') as tmp:
            with mock.patch.object(ns['os'],'scandir',return_value=InfiniteEnough()):
                try:ns['collect'](tmp,1,4096,root=tmp)
                except AssertionError:raise
                except (ValueError,OSError):pass

    def test_reader_initialization_failure_reaps_process(self):
        children = []
        real_reader = mod._OutputReader
        reads = []
        def popen(*args, **kwargs):
            process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], **kwargs)
            children.append(process)
            return process
        def reader(*args, **kwargs):
            if reads:
                raise RuntimeError("synthetic second reader creation failure")
            value = real_reader(*args, **kwargs)
            reads.append(value)
            return value
        backend = mod.DockerCampaignBackend(popen=popen)
        try:
            with mock.patch.object(mod, "_OutputReader", side_effect=reader):
                with self.assertRaises(mod.CampaignOwnershipUnknown):
                    backend._run_command(["fake-management"], time.monotonic() + 2)
            self.assertFalse(backend._management_pending())
            self.assertIsNotNone(children[0].poll())
            self.assertFalse(reads[0].thread.is_alive())
            self.assertTrue(children[0].stdout.closed)
            self.assertTrue(children[0].stderr.closed)
        finally:
            for process in children:
                if process.poll() is None:
                    process.kill()
                process.wait(timeout=2)
            backend._stop_management(time.monotonic() + .3)


if __name__ == "__main__":
    unittest.main()
