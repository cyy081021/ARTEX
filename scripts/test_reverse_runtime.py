"""Mock-only tests for the persistent Android runner protocol."""
from __future__ import annotations

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import queue
import sys
import tempfile
import threading
import time
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
RUNTIME_PATH = Path(__file__).with_name('reverse_runtime.py')
SPEC = importlib.util.spec_from_file_location('reverse_runtime_under_test', RUNTIME_PATH)
runtime = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(runtime)


class FakeScript:
    def __init__(self, state):
        self.state = state
        self.callbacks = {}

    def set_log_handler(self, callback):
        self.state['log_handler'] = callback

    def on(self, name, callback):
        self.callbacks[name] = callback

    def load(self):
        self.state['script_loads'] += 1
        self.callbacks['message']({'type': 'send', 'payload': 'fixture'}, None)

    def unload(self):
        self.state['unloads'] += 1


class FakeSession:
    def __init__(self, state):
        self.state = state
        self.is_detached = False

    def create_script(self, _source):
        self.state['script_creates'] += 1
        return FakeScript(self.state)

    def detach(self):
        self.state['detaches'] += 1


class FakeDevice:
    def __init__(self, state):
        self.state = state
        self.session = FakeSession(state)

    def on(self, *_args):
        pass

    def spawn(self, _program):
        self.state['spawns'] += 1
        return 4815

    def attach(self, _pid):
        self.state['attaches'] += 1
        return self.session

    def resume(self, _pid):
        pass

    def kill(self, _pid):
        self.state['kills'] += 1


class DelayedEOF:
    """Yield the request, then hold EOF long enough for the session deadline."""
    def __init__(self, request):
        self.request = request
        self.first = True

    def reconfigure(self, **_kwargs):
        pass

    def __iter__(self):
        return self

    def readline(self):
        self.first = False
        return self.request

    def __next__(self):
        if self.first:
            self.first = False
            return self.request
        time.sleep(.35)
        raise StopIteration


class CancelDuringInstall:
    def __init__(self, request, install_started):
        self.request = request
        self.install_started = install_started
        self.sent = False

    def reconfigure(self, **_kwargs):
        pass

    def readline(self):
        return self.request

    def __iter__(self):
        return self

    def __next__(self):
        if self.sent:
            raise StopIteration
        if not self.install_started.wait(3):
            raise AssertionError('mock install did not start')
        self.sent = True
        return json.dumps({'cancel': True}) + '\n'


class ReverseRuntimeSessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='artex-reverse-test-')
        self.addCleanup(self.temp.cleanup)
        self.artifact = Path(self.temp.name) / 'sample.apk'
        self.artifact.write_bytes(b'mock-apk-fixture')
        self.digest = hashlib.sha256(self.artifact.read_bytes()).hexdigest()
        self.state = {'spawns': 0, 'attaches': 0, 'script_creates': 0,
                      'script_loads': 0, 'unloads': 0, 'detaches': 0,
                      'kills': 0, 'adb': []}

    def fake_frida(self):
        device = FakeDevice(self.state)
        frida = types.ModuleType('frida')
        frida.__version__ = 'mock'
        frida.InvalidOperationError = type('InvalidOperationError', (Exception,), {})
        frida.ProcessNotFoundError = type('ProcessNotFoundError', (Exception,), {})
        frida.get_device = lambda *_args, **_kwargs: device
        return frida

    def fake_subprocess(self, argv, **_kwargs):
        argv = list(argv)
        self.state['adb'].append(argv)
        if 'dump' in argv and 'badging' in argv:
            return types.SimpleNamespace(stdout=b"package: name='org.example.fixture' versionCode='1'\n", returncode=0)
        if 'getprop' in argv:
            data = b'1\n'
        elif 'list' in argv and 'packages' in argv:
            data = b'package:org.example.fixture\n' if self.state.get('package_installed') else b''
        elif 'uninstall' in argv:
            self.state['package_installed'] = False
            data = b'Success\n'
        elif 'dumpsys' in argv and 'window' in argv:
            # Modern Android only includes focus in the full window dump.
            data = (b'Window #0 org.example.fixture/.MainActivity\n' if 'windows' in argv else
                    b'mCurrentFocus=Window{1 u0 org.example.fixture/.MainActivity}\n')
        elif 'wm' in argv and 'size' in argv:
            data = b'Physical size: 1080x1920\n'
        elif 'cat' in argv:
            data = b'<hierarchy rotation="0" />'
        elif 'screencap' in argv:
            data = b'\x89PNG\r\n\x1a\nfixture'
        elif 'uiautomator' in argv:
            data = b'UI hierchary dumped to: fixture\n'
        elif any(word in argv for word in ('tap', 'text', 'keyevent', 'swipe', 'monkey')):
            data = b''
        else:
            data = b''
        return types.SimpleNamespace(stdout=data, returncode=0)

    def fake_popen(self, argv, **_kwargs):
        owner = self

        class Process:
            def __init__(self):
                self.argv = list(argv)
                self.returncode = None
                self.terminated = False
                if 'install' in self.argv:
                    owner.state['adb'].append(self.argv)
                    owner.state['install_started'].set()

            def communicate(self, timeout=None):
                if 'install' in self.argv and owner.state.get('slow_install') and not self.terminated:
                    time.sleep(min(timeout or .01, .03))
                    raise runtime.subprocess.TimeoutExpired(self.argv, timeout)
                if self.returncode is None:
                    result = owner.fake_subprocess(self.argv)
                    if 'install' in self.argv:
                        owner.state['package_installed'] = True
                    self.returncode = result.returncode
                    return result.stdout, b''
                return b'', b''

            def terminate(self):
                self.terminated = True
                self.returncode = -15
                # Simulate Package Manager committing just before adb exits.
                if 'install' in self.argv:
                    owner.state['package_installed'] = True

            def kill(self):
                self.terminate()

        return Process()

    def make_request(self, operation='session', duration_ms=4000):
        return {
            'operation': operation,
            'artifact_path': str(self.artifact),
            'sha256': self.digest,
            'script': 'send("fixture");',
            'profile': {
                'platform': 'android', 'adb': '/mock/adb', 'adb_port': 5038,
                'adb_serial': '127.0.0.1:5585', 'aapt': '/mock/aapt',
                'allow_package_install': True, 'device_id': 'local',
            },
            'package_name': 'org.example.fixture',
            'duration_ms': duration_ms,
        }

    def test_snapshot_cleanup_failure_is_reported(self):
        def run(argv, **kwargs):
            if 'rm' in argv:
                return types.SimpleNamespace(stdout=b'', returncode=1)
            return self.fake_subprocess(argv, **kwargs)
        profile = self.make_request()['profile']
        with mock.patch.object(runtime.subprocess, 'run', side_effect=run):
            with self.assertRaisesRegex(RuntimeError, 'temporary file cleanup failed'):
                runtime.android_session_action('android_snapshot', {}, profile, 'org.example.fixture')
        self.assertFalse(any('screencap' in argv for argv in self.state['adb']))

    def run_main(self, commands, duration_ms=4000, operation='session', delayed_eof=False,
                 cancel_during_install=False):
        def terminate_fake_process(process):
            # In-memory children have no OS pid/process group on either host.
            process.terminate()
            return process.communicate(timeout=1)
        request = self.make_request(operation, duration_ms)
        payload = json.dumps(request) + '\n' + ''.join(json.dumps(item) + '\n' for item in commands)
        self.state['install_started'] = threading.Event()
        self.state['slow_install'] = cancel_during_install
        if cancel_during_install:
            fake_stdin = CancelDuringInstall(json.dumps(request) + '\n', self.state['install_started'])
        else:
            fake_stdin = DelayedEOF(json.dumps(request) + '\n') if delayed_eof else io.TextIOWrapper(io.BytesIO(payload.encode()), encoding='utf-8')
        fake_stdout = io.TextIOWrapper(io.BytesIO(), encoding='utf-8')
        with mock.patch.dict(sys.modules, {'frida': self.fake_frida()}), \
             mock.patch.object(sys, 'stdin', fake_stdin), \
             mock.patch.object(sys, 'stdout', fake_stdout), \
             mock.patch.object(runtime.subprocess, 'run', side_effect=self.fake_subprocess), \
             mock.patch.object(runtime.subprocess, 'Popen', side_effect=self.fake_popen), \
             mock.patch.object(runtime, '_terminate_process_tree', side_effect=terminate_fake_process):
            runtime.main()
            fake_stdout.flush()
            output = fake_stdout.buffer.getvalue().decode('utf-8')
        return [json.loads(line) for line in output.splitlines() if line]

    def test_session_reuses_one_attach_and_captures_android_snapshot(self):
        frames = self.run_main([
            {'request_id': 'snap', 'action': 'android_snapshot', 'step_id': 's1'},
            {'request_id': 'tap', 'action': 'android_tap', 'step_id': 's2', 'x': 9, 'y': 11},
            {'request_id': 'read', 'action': 'read'},
            {'request_id': 'stop-1', 'action': 'stop'},
        ])
        self.assertEqual([f['kind'] for f in frames], ['ready', 'step', 'step', 'step', 'final'])
        self.assertEqual((self.state['spawns'], self.state['attaches'], self.state['script_creates']), (1, 1, 1))
        snapshot = frames[1]['observation']
        self.assertIn('<hierarchy', snapshot['ui_xml'])
        self.assertTrue(snapshot['screenshot_base64'].startswith('iVBOR'))
        self.assertEqual(snapshot['messages'][0]['message']['payload'], 'fixture')
        for frame in frames[:-1]:
            self.assertEqual(frame['observation']['platform'], 'android')
            self.assertEqual(frame['observation']['artifact_sha256'], self.digest)
            self.assertEqual(frame['observation']['script_sha256'], hashlib.sha256(b'send("fixture");').hexdigest())
            self.assertEqual(frame['observation']['version'], 'mock')
        self.assertEqual(snapshot['step_id'], 's1')
        self.assertEqual(frames[-1]['request_id'], 'stop-1')
        self.assertEqual(frames[-1]['observation']['reason'], 'stop')
        self.assertTrue(frames[-1]['observation']['cleanup']['session_detached'])
        self.assertTrue(frames[-1]['observation']['cleanup']['package_removed'])

    def test_timeout_eof_and_cancel_all_reach_cleanup(self):
        timeout = self.run_main([], duration_ms=100, delayed_eof=True)
        self.assertEqual(timeout[-1]['observation']['reason'], 'timeout')
        self.assertTrue(timeout[-1]['observation']['cleanup']['session_detached'])
        eof = self.run_main([], duration_ms=4000)
        self.assertEqual(eof[-1]['observation']['reason'], 'cancelled')
        self.assertTrue(eof[-1]['observation']['cleanup']['session_detached'])
        cancel = self.run_main([{'request_id': 'cancel-1', 'action': 'cancel'}])
        self.assertEqual(cancel[-1]['request_id'], 'final')
        self.assertEqual(cancel[-1]['observation']['reason'], 'cancelled')
        self.assertTrue(cancel[-1]['observation']['cleanup']['package_removed'])

    def test_cancel_during_install_terminates_adb_and_cleans_committed_package(self):
        frames = self.run_main([], cancel_during_install=True)
        self.assertEqual(frames[-1]['kind'], 'final')
        self.assertEqual(frames[-1]['observation']['reason'], 'cancelled')
        self.assertTrue(any('install' in call for call in self.state['adb']))
        self.assertTrue(any('uninstall' in call for call in self.state['adb']))
        self.assertFalse(self.state.get('package_installed', False))
        self.assertTrue(frames[-1]['observation']['cleanup']['package_removed'])
        self.assertFalse(frames[-1]['observation']['errors'])

    def test_rejects_shell_text_without_executing_input_and_preserves_observe(self):
        frames = self.run_main([{'request_id': 'bad', 'action': 'android_input', 'text': 'safe;rejected'},
                                {'request_id': 'stop', 'action': 'stop'}])
        self.assertIn('safe ASCII', frames[1]['observation']['error'])
        self.assertFalse(any('input' in call and 'text' in call for call in self.state['adb']))
        old = self.run_main([{'cancel': True}], duration_ms=3000, operation='observe')
        self.assertEqual(len(old), 1)
        self.assertNotIn('kind', old[0])
        self.assertTrue(old[0]['cleanup']['session_detached'])


class SessionLoopUnitTests(unittest.TestCase):
    def test_parameter_rejection_and_each_termination_reason(self):
        def run(commands, duration=100, cancelled=None):
            q = queue.Queue()
            for command in commands:
                q.put(command)
            calls, frames = [], []
            done = cancelled or threading.Event()
            reason, final_id = runtime.run_session_command_loop(
                duration, q, done, lambda action, params: calls.append((action, params)) or {'seen': action},
                emit=lambda rid, kind, observation: frames.append((rid, kind, observation)),
                identity={'platform': 'android', 'artifact_sha256': 'a' * 64,
                          'script_sha256': 'b' * 64, 'version': 'mock'})
            return reason, final_id, calls, frames

        reason, final_id, calls, frames = run([
            {'request_id': 'one', 'action': 'android_tap', 'x': 1, 'y': 2},
            {'request_id': 'bad', 'action': 'android_tap', 'x': 1, 'y': 2, 'cmd': 'bad'},
            {'request_id': 'stop', 'action': 'stop'},
        ])
        self.assertEqual(reason, 'stop')
        self.assertEqual(final_id, 'stop')
        self.assertEqual([action for action, _ in calls if action != 'read'], ['android_tap'])
        self.assertIn('unsupported command fields', frames[2][2]['error'])
        reason, _, _, _ = run([])
        self.assertEqual(reason, 'timeout')
        reason, final_id, _, _ = run([{'request_id': 'cancel', 'action': 'cancel'}])
        self.assertEqual((reason, final_id), ('cancelled', 'final'))
        reason, _, _, _ = run([None])
        self.assertEqual(reason, 'cancelled')
        _, _, _, numeric_id_frames = run([
            {'request_id': '4d3f9a', 'action': 'read'},
            {'request_id': 'stop', 'action': 'stop'},
        ])
        self.assertEqual(numeric_id_frames[1][2]['step_id'], '4d3f9a')
        self.assertEqual(numeric_id_frames[1][2]['script_sha256'], 'b' * 64)


if __name__ == '__main__':
    unittest.main()
