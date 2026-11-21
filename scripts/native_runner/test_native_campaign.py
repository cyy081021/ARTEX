import base64
import datetime
import hashlib
import io
import json
import queue
import threading
import time
import tracemalloc
import unittest

from .campaign import (
    MAX_CONTROL_CACHE,
    CampaignBackend,
    CampaignBackendTimeout,
    CampaignCancelled,
    CampaignPaused,
    CampaignRunner,
    serve_campaign,
    serve_cleanup_probe,
    strict_json_object,
    validate_campaign_start,
)
from .main import serve

SEED = b"Z"
SEED_SHA = hashlib.sha256(SEED).hexdigest()
IMAGE = "sha256:" + "a" * 64


def iso(seconds_from_now):
    return datetime.datetime.fromtimestamp(
        time.time() + seconds_from_now, datetime.timezone.utc
    ).isoformat().replace("+00:00", "Z")


def start_frame(**overrides):
    now = time.time()
    frame = {
        "operation": "campaign",
        "task_id": 7,
        "request_id": "campaign-42-attempt-8",
        "campaign_id": 42,
        "attempt_id": 8,
        "attempt_no": 2,
        "fencing_token": 9001,
        "lease_owner": "owner",
        "lease_instance": "instance",
        "lease_ms": 30000,
        "artifact_path": "/tmp/synthetic-fixture.elf",
        "sha256": SEED_SHA,
        "argv": [],
        "input_mode": "stdin",
        "seeds": [{"sha256": SEED_SHA, "data_base64": base64.b64encode(SEED).decode("ascii")}],
        "max_executions": 1000,
        "max_crashes": 4,
        "attempt_budget_ms": 60000,
        "execution_window_ms": 55000,
        "execution_deadline": iso(30),
        "envelope_deadline": iso(60),
        "cleanup_reserve_ms": 5000,
        "cleanup_hard_timeout_ms": 60000,
        "profile": {
            "image": IMAGE, "image_id": IMAGE, "fuzz_enabled": True,
            "enabled": True, "network": "none", "read_only_root": True,
            "max_duration_ms": 900000,
        },
    }
    frame.update(overrides)
    if "lease_deadline" not in overrides:
        try:
            execution = datetime.datetime.fromisoformat(frame["execution_deadline"].replace("Z", "+00:00")).timestamp()
            frame["lease_deadline"] = datetime.datetime.fromtimestamp(min(now + float(frame["lease_ms"]) / 1000, execution), datetime.timezone.utc).isoformat().replace("+00:00", "Z")
        except (ValueError, TypeError):
            frame["lease_deadline"] = iso(1)
    return frame


def probe_frame(**overrides):
    frame = {
        "operation": "campaign_cleanup_probe", "request_id": "cleanup-42-8",
        "task_id": 7, "campaign_id": 42, "attempt_id": 8, "fencing_token": 9001,
    }
    frame.update(overrides)
    return frame


class Capture:
    def __init__(self):
        self.frames = []
        self._lock = threading.Lock()

    def emit(self, frame):
        with self._lock:
            self.frames.append(frame)

    def of_kind(self, kind):
        with self._lock:
            return [frame for frame in self.frames if frame.get("kind") == kind]

    def final(self):
        finals = self.of_kind("final")
        return finals[-1] if finals else None


class ControlStream:
    """A blocking text stream whose controls a test can feed deterministically."""

    def __init__(self):
        self._queue = queue.Queue()

    def feed(self, value):
        self._queue.put(json.dumps(value, separators=(",", ":")) + "\n")

    def feed_raw(self, value):
        self._queue.put(value)

    def close(self):
        self._queue.put(None)

    def readline(self, _limit=-1):
        value = self._queue.get()
        if value is None:
            return ""
        return value


class SyntheticBackend(CampaignBackend):
    def __init__(self, result=None, checkpoint=None, cleanup=None, probe=None,
                 probe_delay=0.0):
        self.entered = threading.Event()
        self.release = threading.Event()
        self.result = result or {"target_state": "completed", "stats": {"execs_done": 3}}
        self.checkpoint_entries = checkpoint
        self.cleanup_result = cleanup or {
            "owned_process_terminated": True,
            "container_removed": True,
            "staging_removed": True,
        }
        self.probe = probe
        self.probe_delay = probe_delay
        self.probe_calls = 0
        self.execute_calls = 0
        self.execute_finished = threading.Event()

    def execute(self, request, control):
        self.execute_calls += 1
        self.entered.set()
        try:
            while not self.release.is_set():
                action = control.wait(0.01)
                if action == "cancel":
                    raise CampaignCancelled("cancel")
                if action == "pause":
                    raise CampaignPaused("pause")
            return dict(self.result)
        finally:
            self.execute_finished.set()

    def stop(self, request, timeout):
        # Cooperative fake: the control signal is the stop contract. We never
        # declare termination just because a timeout wrapper returned.
        return self.execute_finished.wait(max(0.0, min(float(timeout), 1.0)))

    def ownership(self, request):
        if self.execute_finished.is_set():
            return "terminated"
        return "running"

    def checkpoint(self, request):
        return self.checkpoint_entries

    def cleanup(self, request):
        return dict(self.cleanup_result)

    def status(self, request):
        return {"state": "running"}

    def probe_cleanup(self, request, timeout):
        self.probe_calls += 1
        if self.probe_delay:
            time.sleep(self.probe_delay)
        if self.probe is None:
            return {
                "cleanup_verified": True,
                "containers": [{
                    "name": "artex-campaign-42-8-synthetic",
                    "state": "absent", "labels_match": True,
                }],
                "staging": {"present": False, "removed": True},
                "errors": [], "hard_timeout": False, "elapsed_ms": 1,
            }
        if isinstance(self.probe, BaseException):
            raise self.probe
        return dict(self.probe)


def run_campaign(frame, backend=None, controls=None, timeout=5.0, **kwargs):
    capture = Capture()
    result = {}

    def target():
        result["rc"] = serve_campaign(frame, controls or ControlStream(), capture.emit,
                                      backend=backend, **kwargs)

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, capture, result


def wait_for_final(capture, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        final = capture.final()
        if final is not None:
            return final
        time.sleep(0.01)
    raise AssertionError("no final frame")


class CampaignStartValidationTests(unittest.TestCase):
    def test_valid_start_normalizes_bounded_fields(self):
        request = validate_campaign_start(start_frame())
        self.assertEqual(request["task_id"], 7)
        self.assertEqual(request["seeds"][0]["data"], SEED)
        self.assertEqual(request["lease_ms"], 30000)

    def test_duplicate_keys_rejected(self):
        raw = json.dumps(start_frame())
        raw = raw[:-1] + ',"request_id":"duplicate"}'
        parsed = json.loads(raw)
        capture = Capture()
        rc = serve_campaign(parsed, ControlStream(), capture.emit, first_raw=raw)
        self.assertEqual(rc, 2)
        final = capture.final()
        self.assertEqual(final["observation"]["target_state"], "failed")
        self.assertIn("duplicate JSON key", final["observation"]["errors"][0])

    def test_unknown_start_field_rejected(self):
        frame = start_frame()
        frame["unexpected"] = True
        with self.assertRaises(ValueError):
            validate_campaign_start(frame)

    def test_bool_is_not_an_integer(self):
        frame = start_frame(lease_ms=True)
        with self.assertRaises(ValueError):
            validate_campaign_start(frame)
        frame = start_frame(attempt_budget_ms=True)
        with self.assertRaises(ValueError):
            validate_campaign_start(frame)

    def test_seed_canonical_hash_size_and_total(self):
        cases = []
        frame = start_frame()
        frame["seeds"][0]["data_base64"] = "Wg"
        cases.append(frame)
        frame = start_frame()
        frame["seeds"][0]["sha256"] = "0" * 64
        cases.append(frame)
        frame = start_frame()
        data = b"x" * 4097
        frame["seeds"] = [{
            "sha256": hashlib.sha256(data).hexdigest(),
            "data_base64": base64.b64encode(data).decode("ascii"),
        }]
        cases.append(frame)
        frame = start_frame()
        data = b"x" * 4096
        frame["seeds"] = [{
            "sha256": hashlib.sha256(data).hexdigest(),
            "data_base64": base64.b64encode(data).decode("ascii"),
        }] * 17
        cases.append(frame)
        frame = start_frame()
        frame["seeds"] = []
        cases.append(frame)
        for case in cases:
            with self.assertRaises(ValueError):
                validate_campaign_start(case)

    def test_execution_after_envelope_rejected(self):
        frame = start_frame(execution_deadline=iso(70), envelope_deadline=iso(60))
        with self.assertRaises(ValueError):
            validate_campaign_start(frame)


class CampaignKernelTests(unittest.TestCase):
    def test_normal_final_and_bounded_checkpoint_free_path(self):
        backend = SyntheticBackend()
        backend.release.set()
        thread, capture, _ = run_campaign(start_frame(), backend)
        thread.join(5)
        self.assertFalse(thread.is_alive())
        final = capture.final()
        self.assertEqual(final["observation"]["target_state"], "completed")
        self.assertTrue(final["observation"]["cleanup_verified"])
        self.assertFalse(final["observation"]["cleanup_hold"]["resource_hold"])
        self.assertEqual(len(capture.of_kind("final")), 1)
        self.assertEqual(len(capture.of_kind("result")), 0)
        self.assertEqual(capture.frames[-1]["kind"], "final")

    def test_no_control_result_is_emitted_after_final(self):
        backend = SyntheticBackend()
        controls = ControlStream()
        thread, capture, _ = run_campaign(start_frame(), backend, controls)
        self.assertTrue(backend.entered.wait(2))
        for index in range(50):
            controls.feed({"request_id": "hb-%d" % index, "action": "heartbeat",
                           "lease_ms": 30000, "lease_deadline": iso(20)})
        backend.release.set()
        wait_for_final(capture)
        controls.close()
        thread.join(5)
        self.assertEqual(capture.frames[-1]["kind"], "final")
        self.assertEqual(len(capture.of_kind("final")), 1)

    def test_unavailable_backend_fails_closed(self):
        thread, capture, _ = run_campaign(start_frame())
        thread.join(5)
        final = capture.final()
        self.assertEqual(final["observation"]["target_state"], "failed")
        self.assertFalse(final["observation"]["cleanup_verified"])
        self.assertTrue(final["observation"]["cleanup_hold"]["resource_hold"])
        self.assertTrue(any("not configured" in error for error in final["observation"]["errors"]))

    def test_pause_emits_bounded_chunks_and_summary(self):
        backend = SyntheticBackend()
        controls = ControlStream()
        thread, capture, _ = run_campaign(start_frame(), backend, controls)
        self.assertTrue(backend.entered.wait(2))
        controls.feed({"request_id": "pause-1", "action": "pause", "reason": "test"})
        final = wait_for_final(capture)
        controls.close()
        thread.join(5)
        observation = final["observation"]
        self.assertEqual(observation["target_state"], "paused")
        self.assertTrue(observation["cleanup_verified"])
        checkpoint = observation["checkpoint"]
        self.assertEqual(checkpoint["format_version"], 1)
        chunks = [frame for frame in capture.frames
                  if frame.get("kind") == "event"
                  and frame["observation"].get("event") == "checkpoint_chunk"]
        self.assertGreaterEqual(len(chunks), 1)
        self.assertEqual([chunk["observation"]["checkpoint_seq"] for chunk in chunks],
                         list(range(len(chunks))))
        self.assertFalse(chunks[-1]["observation"]["more"])
        self.assertEqual(sum(len(chunk["observation"]["entries"]) for chunk in chunks),
                         checkpoint["entry_count"])
        ack = capture.of_kind("result")[0]
        self.assertEqual(ack["request_id"], "pause-1")
        self.assertTrue(ack["observation"]["accepted"])

    def test_pause_then_cancel_cancel_wins(self):
        backend = SyntheticBackend()
        controls = ControlStream()
        thread, capture, _ = run_campaign(start_frame(), backend, controls)
        self.assertTrue(backend.entered.wait(2))
        controls.feed({"request_id": "pause-1", "action": "pause", "reason": "pause"})
        time.sleep(0.1)
        controls.feed({"request_id": "cancel-1", "action": "cancel", "reason": "cancel"})
        final = wait_for_final(capture)
        controls.close()
        thread.join(5)
        self.assertEqual(final["observation"]["target_state"], "cancelled")
        self.assertTrue(final["observation"]["cleanup_verified"])
        self.assertEqual(len(capture.of_kind("result")), 2)

    def test_pause_hook_cancel_is_honoured_at_checkpoint_and_finalize(self):
        for phase in ("checkpointing", "finalize"):
            with self.subTest(phase=phase):
                backend = SyntheticBackend()
                controls = ControlStream()
                cancelled = {"done": False}

                def hook(name, control, phase=phase):
                    if name == phase and not cancelled["done"]:
                        cancelled["done"] = True
                        control.request("pause", "late pause")
                        control.request("cancel", "late cancel")

                thread, capture, _ = run_campaign(start_frame(), backend, controls,
                                                  phase_hook=hook)
                self.assertTrue(backend.entered.wait(2))
                controls.feed({"request_id": "pause-1", "action": "pause"})
                final = wait_for_final(capture)
                controls.close()
                thread.join(5)
                self.assertEqual(final["observation"]["target_state"], "cancelled")

    def test_backend_error_fails_and_attempts_cleanup(self):
        class FailingBackend(SyntheticBackend):
            def execute(self, request, control):
                raise RuntimeError("synthetic backend failure")

        backend = FailingBackend()
        thread, capture, _ = run_campaign(start_frame(), backend)
        thread.join(5)
        final = capture.final()["observation"]
        self.assertEqual(final["target_state"], "failed")
        self.assertTrue(any("synthetic backend failure" in error for error in final["errors"]))

    def test_cancel_then_pause_cancel_wins(self):
        backend = SyntheticBackend()
        controls = ControlStream()
        thread, capture, _ = run_campaign(start_frame(), backend, controls)
        self.assertTrue(backend.entered.wait(2))
        controls.feed({"request_id": "cancel-1", "action": "cancel", "reason": "cancel"})
        controls.feed({"request_id": "pause-1", "action": "pause", "reason": "late"})
        final = wait_for_final(capture)
        controls.close()
        thread.join(5)
        self.assertEqual(final["observation"]["target_state"], "cancelled")

    def test_eof_is_cancel_and_cleans_up(self):
        backend = SyntheticBackend()
        controls = ControlStream()
        controls.close()
        thread, capture, _ = run_campaign(start_frame(), backend, controls)
        thread.join(5)
        final = capture.final()
        self.assertEqual(final["observation"]["target_state"], "cancelled")
        self.assertTrue(final["observation"]["cleanup_verified"])

    def test_unknown_control_action_fails_protocol(self):
        backend = SyntheticBackend()
        controls = ControlStream()
        thread, capture, _ = run_campaign(start_frame(), backend, controls)
        self.assertTrue(backend.entered.wait(2))
        controls.feed({"request_id": "bad-1", "action": "bogus"})
        final = wait_for_final(capture)
        controls.close()
        thread.join(5)
        self.assertEqual(final["observation"]["target_state"], "failed")
        self.assertEqual(final["observation"]["reason"], "protocol_violation")
        self.assertTrue(any("protocol_violation" in error for error in final["observation"]["errors"]))

    def test_duplicate_control_key_and_bool_lease_rejected(self):
        backend = SyntheticBackend()
        controls = ControlStream()
        thread, capture, _ = run_campaign(start_frame(), backend, controls)
        self.assertTrue(backend.entered.wait(2))
        controls.feed_raw('{"request_id":"hb-1","action":"heartbeat","lease_ms":1000,"lease_ms":2000}\n')
        final = wait_for_final(capture)
        controls.close()
        thread.join(5)
        self.assertEqual(final["observation"]["reason"], "protocol_violation")

    def test_heartbeat_renews_lease_without_extending_budget(self):
        backend = SyntheticBackend()
        controls = ControlStream()
        frame = start_frame(lease_ms=1000)
        thread, capture, _ = run_campaign(frame, backend, controls)
        self.assertTrue(backend.entered.wait(2))
        for index in range(4):
            controls.feed({"request_id": "hb-%d" % index, "action": "heartbeat",
                           "lease_ms": 1000, "lease_deadline": iso(1)})
            time.sleep(0.2)
        controls.feed({"request_id": "cancel-1", "action": "cancel", "reason": "done"})
        final = wait_for_final(capture)
        controls.close()
        thread.join(5)
        self.assertEqual(final["observation"]["target_state"], "cancelled")
        self.assertFalse(any("lease_expired" == final["observation"]["reason"] for _ in [0]))

    def test_lease_expiry_stops_and_is_interrupted(self):
        backend = SyntheticBackend()
        controls = ControlStream()
        frame = start_frame(lease_ms=1000, execution_deadline=iso(30), envelope_deadline=iso(60))
        thread, capture, _ = run_campaign(frame, backend, controls)
        final = wait_for_final(capture, timeout=4)
        controls.close()
        thread.join(5)
        self.assertEqual(final["observation"]["target_state"], "interrupted")
        self.assertEqual(final["observation"]["reason"], "lease_expired")
        self.assertTrue(final["observation"]["cleanup_verified"])

    def test_execution_deadline_is_not_extended_by_heartbeat(self):
        backend = SyntheticBackend()
        controls = ControlStream()
        frame = start_frame(lease_ms=120000, execution_deadline=iso(0.8), envelope_deadline=iso(30))
        thread, capture, _ = run_campaign(frame, backend, controls)
        self.assertTrue(backend.entered.wait(2))
        controls.feed({"request_id": "hb-1", "action": "heartbeat", "lease_ms": 120000, "lease_deadline": frame["execution_deadline"]})
        time.sleep(0.15)
        heartbeats = [frame for frame in capture.of_kind("result")]
        self.assertTrue(heartbeats)
        self.assertTrue(heartbeats[0]["observation"]["accepted"])
        started = time.monotonic()
        final = wait_for_final(capture, timeout=4)
        controls.close()
        thread.join(5)
        self.assertEqual(final["observation"]["target_state"], "timeout")
        self.assertLess(time.monotonic() - started, 3)

    def test_cleanup_unverified_keeps_hold_and_never_claims_success(self):
        backend = SyntheticBackend(cleanup={
            "owned_process_terminated": True,
            "container_removed": False,
            "staging_removed": True,
        })
        backend.release.set()
        thread, capture, _ = run_campaign(start_frame(), backend)
        thread.join(5)
        final = capture.final()["observation"]
        self.assertFalse(final["cleanup_verified"])
        self.assertTrue(final["cleanup_hold"]["resource_hold"])

    def test_checkpoint_truncates_at_hard_limits(self):
        # Unique payloads: duplicates are deduplicated before the hard limits,
        # so they must not be used here to manufacture truncation.
        entries = [{"data": index.to_bytes(4, "big"), "source_type": "queue",
                    "source_ref": "id:%06d" % index} for index in range(600)]
        backend = SyntheticBackend(checkpoint=entries)
        controls = ControlStream()
        thread, capture, _ = run_campaign(start_frame(), backend, controls)
        self.assertTrue(backend.entered.wait(2))
        controls.feed({"request_id": "pause-1", "action": "pause"})
        final = wait_for_final(capture)
        controls.close()
        thread.join(5)
        checkpoint = final["observation"]["checkpoint"]
        self.assertLessEqual(checkpoint["entry_count"], 512)
        self.assertLessEqual(checkpoint["total_bytes"], 1024 * 1024)
        self.assertTrue(checkpoint["truncated"])
        chunks = [frame for frame in capture.frames
                  if frame.get("kind") == "event"
                  and frame["observation"].get("event") == "checkpoint_chunk"]
        self.assertEqual([chunk["observation"]["checkpoint_seq"] for chunk in chunks],
                         list(range(len(chunks))))
        self.assertFalse(chunks[-1]["observation"]["more"])

    def test_heartbeat_replay_is_cached_and_does_not_extend_lease_again(self):
        now = [10.0]
        runner = CampaignRunner(validate_campaign_start(start_frame()),
                                clock=lambda: now[0])
        runner._emit = lambda frame: None
        frame = {"request_id": "audit-hb", "action": "heartbeat", "lease_ms": 10000, "lease_deadline": iso(10)}
        runner._handle_control(frame)
        deadline = runner._lease_deadline
        now[0] += 1
        runner._handle_control(frame)
        self.assertEqual(runner._lease_deadline, deadline)

    def test_control_ledger_is_bounded_and_rejects_changed_payload(self):
        runner = CampaignRunner(validate_campaign_start(start_frame()))
        runner._emit = lambda frame: None
        runner._handle_control(
            {"request_id": "same-id", "action": "pause", "reason": "first"})
        with self.assertRaises(ValueError):
            runner._handle_control(
                {"request_id": "same-id", "action": "cancel", "reason": "first"})
        with self.assertRaises(ValueError):
            runner._handle_control(
                {"request_id": "same-id", "action": "pause", "reason": "changed"})
        for index in range(MAX_CONTROL_CACHE - 1):
            runner._handle_control(
                {"request_id": "status-%d" % index, "action": "status"})
        self.assertEqual(len(runner._control_cache), MAX_CONTROL_CACHE)
        with self.assertRaises(ValueError):
            runner._handle_control(
                {"request_id": "status-overflow", "action": "status"})
        # The full ledger still replays the original request id without
        # re-applying its side effect.
        runner._handle_control(
            {"request_id": "same-id", "action": "pause", "reason": "first"})
        with self.assertRaises(ValueError):
            runner._handle_control(
                {"request_id": "same-id", "action": "pause", "reason": "changed"})

    def test_cache_pressure_cannot_reexecute_heartbeat(self):
        now = [10.0]
        runner = CampaignRunner(validate_campaign_start(start_frame()),
                                clock=lambda: now[0])
        runner._emit = lambda frame: None
        heartbeat = {"request_id": "pressure-hb", "action": "heartbeat",
                     "lease_ms": 10000, "lease_deadline": iso(10)}
        runner._handle_control(heartbeat)
        original = runner._lease_deadline
        for index in range(MAX_CONTROL_CACHE + 1):
            try:
                runner._handle_control(
                    {"request_id": "pressure-status-%d" % index, "action": "status"})
            except ValueError:
                break
        now[0] += 1
        try:
            runner._handle_control(heartbeat)
        except ValueError:
            pass
        self.assertEqual(runner._lease_deadline, original)

    def test_cancel_on_live_control_stream_during_cleanup_wins(self):
        class BlockingCleanupBackend(SyntheticBackend):
            def __init__(self):
                super().__init__()
                self.cleanup_entered = threading.Event()
                self.cleanup_release = threading.Event()

            def cleanup(self, request):
                self.cleanup_entered.set()
                self.cleanup_release.wait(2)
                return super().cleanup(request)

        backend = BlockingCleanupBackend()
        backend.release.set()
        controls = ControlStream()
        thread, capture, _ = run_campaign(start_frame(), backend, controls)
        try:
            self.assertTrue(backend.cleanup_entered.wait(2))
            controls.feed({"request_id": "cleanup-cancel", "action": "cancel",
                           "reason": "during-cleanup"})
            deadline = time.monotonic() + 2
            acknowledged = False
            while time.monotonic() < deadline:
                if any(frame.get("request_id") == "cleanup-cancel"
                       for frame in capture.of_kind("result")):
                    acknowledged = True
                    break
                time.sleep(0.01)
            self.assertTrue(acknowledged, "cleanup cancel ACK was not emitted")
            backend.cleanup_release.set()
            final = wait_for_final(capture)
            self.assertEqual(final["observation"]["target_state"], "cancelled")
            self.assertEqual(capture.frames[-1]["kind"], "final")
        finally:
            backend.cleanup_release.set()
            controls.close()
            thread.join(5)

    def test_cleanup_cannot_verify_while_owned_worker_is_alive(self):
        release = threading.Event()

        class BlockingExecuteBackend(SyntheticBackend):
            def execute(self, request, control):
                self.entered.set()
                release.wait(2)
                return {"target_state": "completed"}

        backend = BlockingExecuteBackend()
        controls = ControlStream()
        controls.close()
        thread, capture, _ = run_campaign(start_frame(), backend, controls,
                                          stop_grace=0.005)
        try:
            final = wait_for_final(capture)
            self.assertFalse(backend.execute_finished.is_set())
            self.assertFalse(final["observation"]["cleanup_verified"])
            self.assertTrue(final["observation"]["cleanup_hold"]["resource_hold"])
        finally:
            release.set()
            thread.join(5)

    def checkpoint_runner(self, **overrides):
        runner = CampaignRunner(validate_campaign_start(start_frame(**overrides)))
        runner._emit = lambda frame: None
        return runner

    def test_checkpoint_canonical_manifest_golden_vectors(self):
        vectors = [
            (b"A", "id:000001",
             "d02af0268ce4c25e13663a13cf22902e1e06d30d46c10902bd7dff660b5101ff"),
            (b"B", "中文队列",
             "e035727544257f97ba9055a898f962381778fd45f1e3b66e0b1d5b5e4e79b000"),
            (b"C", 'a"b',
             "19ebabfacd8723961de70f9fd80c88b3e0c1f69e37b16c51ad2ae91354558391"),
            (b"D", "a<&>b",
             "69263c88f2af26ade70dd0d7a0fef8538f1d59c495d72a767f9a99a433dd72e6"),
            (b"E", "line\u2028sep",
             "38e8c47b5840600a58579e26dd85189295af91ded4fe4e7d6ea6362d64fd958b"),
            (b"F", "para\u2029sep",
             "2d1e8ccf69cc44667d5f12b50d58160cbbf6912553ffd7bcd22e518be72a94dc"),
        ]
        for data, source_ref, digest in vectors:
            with self.subTest(source_ref=source_ref):
                runner = self.checkpoint_runner()
                entries, _ = runner._checkpoint_entries({"checkpoint": [{
                    "data": data, "source_type": "queue", "source_ref": source_ref,
                }]})
                self.assertEqual(runner._emit_checkpoint(entries)["manifest_sha256"], digest)

    def test_checkpoint_manifest_bytes_are_unicode_exact(self):
        runner = self.checkpoint_runner()
        entries, _ = runner._checkpoint_entries({"checkpoint": [{
            "data": b"A", "source_type": "queue", "source_ref": "id:000001",
        }]})
        expected = (
            '{"attempt_id":8,"campaign_id":42,"entries":[{"length":1,'
            '"sha256":"559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd",'
            '"source_ref":"id:000001","source_type":"queue","storage_key":'
            '"tasks/7/reverse/campaigns/objects/sha256/55/'
            '559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd"}],'
            '"format_version":1}'
        )
        self.assertEqual(runner._checkpoint_manifest(entries).decode("utf-8"), expected)
        for source_ref in ("中文队列", 'a"b', "a<&>b", "line\u2028sep", "para\u2029sep"):
            entries, _ = runner._checkpoint_entries({"checkpoint": [{
                "data": b"Z", "source_type": "queue", "source_ref": source_ref,
            }]})
            raw = runner._checkpoint_manifest(entries).decode("utf-8")
            if source_ref == 'a"b':
                encoded_ref = '"source_ref":"a\\"b"'
            else:
                encoded_ref = '"source_ref":' + json.dumps(
                    source_ref, ensure_ascii=False)
            self.assertIn(encoded_ref, raw)
            self.assertNotIn("\\u003c", raw)
            self.assertNotIn("\\u003e", raw)
            self.assertNotIn("\\u0026", raw)

    def test_checkpoint_dedup_keeps_first_source_and_counts_unique_bytes(self):
        entries, truncated = self.checkpoint_runner()._checkpoint_entries({
            "checkpoint": [
                {"data": b"Z", "source_type": "queue", "source_ref": "id:000001"},
                {"data": b"Z", "source_type": "crash", "source_ref": "id:999999"},
                {"data": b"Y", "source_type": "import", "source_ref": "batch/one"},
            ],
        })
        self.assertFalse(truncated)
        self.assertEqual(len(entries), 2)
        self.assertEqual(entries[0]["source_type"], "queue")
        self.assertEqual(entries[0]["source_ref"], "id:000001")
        self.assertEqual(entries[1]["source_type"], "import")
        summary = self.checkpoint_runner()._emit_checkpoint(entries)
        self.assertEqual(summary["entry_count"], 2)
        self.assertEqual(summary["total_bytes"], 2)

    def test_checkpoint_dedup_before_capacity_limits(self):
        unique = [{"data": index.to_bytes(2, "big"), "source_type": "queue",
                   "source_ref": "id:%06d" % index} for index in range(512)]
        duplicates = [{"data": index.to_bytes(2, "big"), "source_type": "crash",
                       "source_ref": "dup:%d" % index} for index in range(10)]
        interleaved = []
        for index, item in enumerate(unique):
            interleaved.append(item)
            if index < len(duplicates):
                interleaved.append(duplicates[index])
        entries, truncated = self.checkpoint_runner()._checkpoint_entries(
            {"checkpoint": interleaved})
        self.assertEqual(len(entries), 512)
        self.assertFalse(truncated)
        self.assertEqual(sum(entry["length"] for entry in entries), 1024)
        # A 513th unique entry is truncated after dedup, not before.
        entries, truncated = self.checkpoint_runner()._checkpoint_entries(
            {"checkpoint": interleaved + [{"data": (999).to_bytes(2, "big"),
                                           "source_type": "queue",
                                           "source_ref": "id:000999"}]})
        self.assertEqual(len(entries), 512)
        self.assertTrue(truncated)

    def test_checkpoint_total_bytes_limit_applies_after_dedup(self):
        entries = [{"data": index.to_bytes(2, "big") + b"x" * 4094,
                    "source_type": "queue", "source_ref": "id:%06d" % index}
                   for index in range(300)]
        bounded, truncated = self.checkpoint_runner()._checkpoint_entries(
            {"checkpoint": entries})
        self.assertTrue(truncated)
        self.assertEqual(len(bounded), 256)
        self.assertEqual(sum(entry["length"] for entry in bounded), 1024 * 1024)

    def test_checkpoint_manifest_order_independent_but_id_bound(self):
        first = {"data": b"Z", "source_type": "queue", "source_ref": "id:000001"}
        second = {"data": b"Y", "source_type": "crash", "source_ref": "id:000002"}
        runner_a = self.checkpoint_runner()
        runner_b = self.checkpoint_runner()
        entries_a, _ = runner_a._checkpoint_entries({"checkpoint": [first, second]})
        entries_b, _ = runner_b._checkpoint_entries({"checkpoint": [second, first]})
        digest_a = runner_a._emit_checkpoint(entries_a)["manifest_sha256"]
        digest_b = runner_b._emit_checkpoint(entries_b)["manifest_sha256"]
        self.assertEqual(digest_a, digest_b)
        for overrides in ({"campaign_id": 43}, {"attempt_id": 9}, {"task_id": 9}):
            runner_c = self.checkpoint_runner(**overrides)
            entries_c, _ = runner_c._checkpoint_entries({"checkpoint": [first, second]})
            self.assertNotEqual(
                runner_c._emit_checkpoint(entries_c)["manifest_sha256"], digest_a)

    def test_checkpoint_source_ref_rejects_host_and_unsafe_names(self):
        rejected = [
            "", "/tmp/private/entry", "C:/private/entry", "C:relative", "C:\\private\\entry",
            "\\\\server\\share\\entry", "//server/share/entry", "queue\\id:000001",
            "../private/entry", "queue/../private", "queue/./entry", "id:\x00",
            "id:\x01", "id:\x7f", "line\u2028sep/../../x", "\ud800", "x" * 257,
        ]
        for source_ref in rejected:
            with self.subTest(source_ref=repr(source_ref)):
                with self.assertRaises(ValueError):
                    self.checkpoint_runner()._checkpoint_entries({"checkpoint": [{
                        "data": b"Z", "source_type": "queue", "source_ref": source_ref,
                    }]})
        for source_ref in ("id:000001", "queue/id:000001", "中文队列", 'a"b', "a<&>b",
                           "line\u2028sep", "para\u2029sep"):
            with self.subTest(allowed=repr(source_ref)):
                entries, _ = self.checkpoint_runner()._checkpoint_entries({
                    "checkpoint": [{"data": b"Z", "source_type": "queue",
                                    "source_ref": source_ref}]})
                self.assertEqual(entries[0]["source_ref"], source_ref)

    def test_checkpoint_source_type_and_metadata_strictness(self):
        for source_type in ("", "arbitrary", "QUEUE", "queue "):
            with self.subTest(source_type=source_type):
                with self.assertRaises(ValueError):
                    self.checkpoint_runner()._checkpoint_entries({"checkpoint": [{
                        "data": b"Z", "source_type": source_type, "source_ref": "id:1",
                    }]})
        for item in (
            {"data": b"Z", "source_type": "queue", "source_ref": "id:1",
             "sha256": "0" * 64},
            {"data": b"Z", "source_type": "queue", "source_ref": "id:1", "length": 2},
            {"data": b"Z", "source_type": "queue", "source_ref": "id:1", "extra": 1},
            {"data": b"", "source_type": "queue", "source_ref": "id:1"},
            {"data": "Z", "source_type": "queue", "source_ref": "id:1"},
        ):
            with self.subTest(item=item):
                with self.assertRaises(ValueError):
                    self.checkpoint_runner()._checkpoint_entries({"checkpoint": [item]})

    def test_checkpoint_fallback_initial_seeds_are_marked_seed(self):
        runner = self.checkpoint_runner()
        entries, truncated = runner._checkpoint_entries({"checkpoint": []})
        self.assertFalse(truncated)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["source_type"], "seed")
        self.assertEqual(entries[0]["source_ref"], "seed:0")
        self.assertIn(b'"source_type":"seed"', runner._checkpoint_manifest(entries))

    def test_checkpoint_fallback_duplicate_seeds_share_dedup_contract(self):
        frame = start_frame()
        frame["seeds"] = [frame["seeds"][0], dict(frame["seeds"][0])]
        runner = CampaignRunner(validate_campaign_start(frame))
        runner._emit = lambda frame: None
        entries, truncated = runner._checkpoint_entries({})
        self.assertFalse(truncated)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["source_type"], "seed")
        self.assertEqual(entries[0]["source_ref"], "seed:0")

    def test_checkpoint_prefix_is_locked_after_first_unique_overflow(self):
        prefix = [{"data": index.to_bytes(2, "big") + b"x" * 4094,
                   "source_type": "queue", "source_ref": "id:%06d" % index}
                  for index in range(255)]
        prefix.append({"data": (255).to_bytes(4, "big") + b"y" * 4088,
                       "source_type": "queue", "source_ref": "id:000255"})
        # The full prefix is 1,048,572 bytes: a 4096-byte entry overflows, but a
        # later 1-byte entry would fit if the implementation backfilled.
        overflow = {"data": b"z" * 4096, "source_type": "queue",
                    "source_ref": "id:000256"}
        small = {"data": b"q", "source_type": "queue", "source_ref": "id:000257"}
        entries, truncated = self.checkpoint_runner()._checkpoint_entries(
            {"checkpoint": prefix + [overflow, small]})
        self.assertTrue(truncated)
        self.assertEqual(len(entries), 256)
        self.assertEqual(sum(entry["length"] for entry in entries), 1048572)
        self.assertNotIn(small["data"], [entry["data"] for entry in entries])

    def test_checkpoint_intermediary_memory_is_bounded(self):
        runner = self.checkpoint_runner()
        raw = [{"data": bytearray(index.to_bytes(4, "big") + b"x" * 4092),
                "source_type": "queue", "source_ref": "id:%06d" % index}
               for index in range(5000)]
        tracemalloc.start()
        try:
            entries, truncated = runner._checkpoint_entries({"checkpoint": raw})
            peak = tracemalloc.get_traced_memory()[1]
        finally:
            tracemalloc.stop()
        self.assertTrue(truncated)
        self.assertEqual(sum(entry["length"] for entry in entries), 1024 * 1024)
        self.assertLess(peak, 4 * 1024 * 1024)


class CleanupProbeTests(unittest.TestCase):
    def run_probe(self, backend, timeout=5.0):
        capture = Capture()
        rc = serve_cleanup_probe(probe_frame(), capture.emit, backend=backend, timeout=timeout)
        return rc, capture.final()["observation"]

    def test_verified_probe(self):
        rc, report = self.run_probe(SyntheticBackend())
        self.assertEqual(rc, 0)
        self.assertTrue(report["cleanup_verified"])
        self.assertEqual(report["containers"][0]["state"], "absent")

    def test_mismatched_labels_and_unknown_state_not_verified(self):
        for container in (
            {"name": "artex-campaign-42-8-x", "state": "absent", "labels_match": False},
            {"name": "artex-campaign-42-8-x", "state": "unknown", "labels_match": True},
        ):
            backend = SyntheticBackend(probe={
                "cleanup_verified": True, "containers": [container],
                "staging": {"present": False, "removed": True},
                "errors": [], "hard_timeout": False, "elapsed_ms": 1,
            })
            rc, report = self.run_probe(backend)
            self.assertEqual(rc, 1)
            self.assertFalse(report["cleanup_verified"])

    def test_timeout_and_unavailable_are_unknown(self):
        backend = SyntheticBackend(probe_delay=0.3)
        rc, report = self.run_probe(backend, timeout=0.05)
        self.assertEqual(rc, 1)
        self.assertFalse(report["cleanup_verified"])
        self.assertTrue(report["hard_timeout"])
        rc, report = self.run_probe(SyntheticBackend(probe=CampaignBackendTimeout("slow")))
        self.assertEqual(rc, 1)
        self.assertFalse(report["cleanup_verified"])
        rc, report = self.run_probe(None)
        self.assertEqual(rc, 1)
        self.assertFalse(report["cleanup_verified"])
        self.assertTrue(any("not configured" in error for error in report["errors"]))

    def test_probe_does_not_execute_target(self):
        backend = SyntheticBackend()
        self.run_probe(backend)
        self.assertEqual(backend.execute_calls, 0)
        self.assertEqual(backend.probe_calls, 1)


class MainDispatchTests(unittest.TestCase):
    def _dispatch(self, frame):
        controls = ControlStream()
        controls.feed_raw(json.dumps(frame, separators=(",", ":")) + "\n")
        output = io.StringIO()
        result = {}

        def target():
            result["rc"] = serve(controls, output)

        thread = threading.Thread(target=target, daemon=True)
        thread.start()
        deadline = time.monotonic() + 5
        final = None
        while time.monotonic() < deadline:
            frames = [json.loads(line) for line in output.getvalue().splitlines() if line]
            finals = [item for item in frames if item.get("kind") == "final"]
            if finals:
                final = finals[-1]
                break
            time.sleep(0.01)
        controls.close()
        thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertIsNotNone(final)
        return result.get("rc"), final

    def test_campaign_dispatch_reaches_kernel(self):
        rc, final = self._dispatch(start_frame())
        self.assertEqual(rc, 0)
        self.assertEqual(final["observation"]["target_state"], "failed")

    def test_cleanup_probe_dispatch_reaches_kernel(self):
        rc, final = self._dispatch(probe_frame())
        self.assertEqual(rc, 1)
        self.assertFalse(final["observation"]["cleanup_verified"])

    def test_strict_json_object_rejects_duplicate_keys(self):
        with self.assertRaises(ValueError):
            strict_json_object('{"a":1,"a":2}')



class AbsoluteLeaseTests(unittest.TestCase):
    def make_runner(self):
        now = [100.0]
        runner = CampaignRunner(validate_campaign_start(start_frame()), clock=lambda: now[0])
        emitted = []
        runner._emit = emitted.append
        return runner, now, emitted

    def deadline(self, runner, delta):
        return datetime.datetime.fromtimestamp(runner._wall_anchor + delta, datetime.timezone.utc).isoformat().replace("+00:00", "Z")

    def test_delayed_heartbeat_has_only_original_remaining_time(self):
        runner, now, emitted = self.make_runner()
        frame = {"request_id": "delayed", "action": "heartbeat", "lease_ms": 10000,
                 "lease_deadline": self.deadline(runner, 10)}
        now[0] += 4
        runner._handle_control(frame)
        self.assertAlmostEqual(runner._lease_deadline, 110, places=5)
        self.assertEqual(emitted[-1]["observation"]["lease_deadline"], frame["lease_deadline"])
        now[0] += 2
        runner._handle_control(frame)
        self.assertAlmostEqual(runner._lease_deadline, 110, places=5)
        with self.assertRaises(ValueError):
            runner._handle_control({**frame, "lease_deadline": self.deadline(runner, 11)})

    def test_expired_request_or_old_lease_never_renews(self):
        for mode in ("request", "old_lease"):
            runner, now, emitted = self.make_runner()
            before = runner._lease_deadline
            if mode == "request":
                now[0] += 11
                requested = self.deadline(runner, 10)
            else:
                runner._lease_deadline = now[0] - 1
                before = runner._lease_deadline
                requested = self.deadline(runner, 10)
            runner._handle_control({"request_id": mode, "action": "heartbeat", "lease_ms": 10000,
                                    "lease_deadline": requested})
            self.assertFalse(emitted[-1]["observation"]["accepted"])
            self.assertEqual(runner._lease_deadline, before)

    def test_missing_absolute_field_has_no_relative_fallback(self):
        frame = start_frame()
        del frame["lease_deadline"]
        with self.assertRaises(ValueError):
            validate_campaign_start(frame)
        runner, _, _ = self.make_runner()
        with self.assertRaises(ValueError):
            runner._handle_control({"request_id": "missing", "action": "heartbeat", "lease_ms": 10000})

    def test_initial_delayed_expired_lease_never_executes_backend(self):
        backend = SyntheticBackend()
        controls = ControlStream()
        thread, capture, _ = run_campaign(start_frame(lease_deadline=iso(-1)), backend, controls)
        final = wait_for_final(capture)
        controls.close()
        thread.join(5)
        self.assertFalse(backend.entered.is_set())
        self.assertEqual(final["observation"]["reason"], "lease_expired")
        self.assertEqual(final["observation"]["target_state"], "interrupted")

if __name__ == "__main__":
    unittest.main()
