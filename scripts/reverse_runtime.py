#!/usr/bin/env python3
"""One owned Frida observation per process, on Linux, Windows or an Android lab.

The ARTEX parent supplies one JSON request on stdin and keeps stdin open. A
second {"cancel":true} line, EOF or termination requests cleanup. No shell is
used. This is process instrumentation, not an operating-system sandbox.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import base64
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone


ANDROID_KEYS = frozenset({
    'KEYCODE_BACK', 'KEYCODE_HOME', 'KEYCODE_ENTER', 'KEYCODE_DEL',
    'KEYCODE_TAB', 'KEYCODE_ESCAPE', 'KEYCODE_SPACE', 'KEYCODE_MENU',
    'KEYCODE_APP_SWITCH', 'KEYCODE_DPAD_UP', 'KEYCODE_DPAD_DOWN',
    'KEYCODE_DPAD_LEFT', 'KEYCODE_DPAD_RIGHT', 'KEYCODE_DPAD_CENTER',
    'KEYCODE_PAGE_UP', 'KEYCODE_PAGE_DOWN', 'KEYCODE_MOVE_HOME', 'KEYCODE_MOVE_END',
})
ANDROID_TEXT = re.compile(r'^[A-Za-z0-9 .,!?@:_+\-]{1,256}$')
SESSION_PROTOCOL = False


class RuntimeCancelled(Exception):
    pass


def _terminate_process_tree(process):
    """Best-effort termination for one child process and its private group."""
    try:
        if os.name == 'nt':
            process.terminate()
        else:
            os.killpg(process.pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        try:
            process.terminate()
        except OSError:
            pass
    try:
        return process.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        try:
            if os.name == 'nt':
                process.kill()
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except (OSError, ProcessLookupError):
            try:
                process.kill()
            except OSError:
                pass
        try:
            return process.communicate(timeout=2)
        except subprocess.TimeoutExpired as exc:
            raise RuntimeError('runtime subprocess termination could not be confirmed') from exc


def _run_cancellable_process(command, timeout, cancelled=None):
    if cancelled is not None and cancelled.is_set():
        raise RuntimeCancelled('runtime operation cancelled')
    kwargs = {'stdout': subprocess.PIPE, 'stderr': subprocess.PIPE}
    if os.name == 'nt':
        kwargs['creationflags'] = getattr(subprocess, 'CREATE_NEW_PROCESS_GROUP', 0x00000200)
    else:
        kwargs['start_new_session'] = True
    process = subprocess.Popen(command, **kwargs)
    deadline = time.monotonic() + timeout
    while True:
        if cancelled is not None and cancelled.is_set():
            _terminate_process_tree(process)
            raise RuntimeCancelled('runtime operation cancelled')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _terminate_process_tree(process)
            raise TimeoutError('runtime subprocess exceeded its deadline')
        try:
            stdout, stderr = process.communicate(timeout=min(.1, remaining))
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        except subprocess.TimeoutExpired:
            continue


def emit_session(request_id, kind, observation):
    payload = {'request_id': request_id, 'kind': kind,
               'observation': observation}
    encoded = json.dumps(payload, ensure_ascii=False)
    if len(encoded.encode('utf-8')) > 8 * 1024 * 1024:
        identity = {key: observation[key] for key in
                    ('platform', 'artifact_sha256', 'script_sha256', 'version')
                    if key in observation}
        payload['observation'] = {**identity,
                                  'error': 'session response exceeds 8 MiB limit'}
        encoded = json.dumps(payload, ensure_ascii=False)
    print(encoded, flush=True)


def run_session_command_loop(duration_ms, command_queue, cancelled, handle_action,
                             emit=emit_session, monotonic=time.monotonic,
                             is_detached=lambda: False, identity=None):
    """Run the line-oriented session protocol without owning Frida itself."""
    identity = identity or {}
    emit('start', 'ready', {**identity, 'status': 'ready', 'duration_ms': duration_ms})
    deadline = monotonic() + duration_ms / 1000
    step_number = 0
    reason = 'timeout'
    final_request_id = 'final'
    while True:
        if cancelled.is_set():
            reason = 'cancelled'
            break
        try:
            if is_detached():
                reason = 'detached'
                break
        except Exception:
            reason = 'detached'
            break
        remaining = deadline - monotonic()
        if remaining <= 0:
            reason = 'timeout'
            break
        try:
            command = command_queue.get(timeout=min(remaining, .1))
        except queue.Empty:
            continue
        if command is None:
            reason = 'cancelled'
            cancelled.set()
            break
        if not isinstance(command, dict):
            emit('invalid', 'step', {**identity, 'error': 'command must be a JSON object'})
            continue
        request_id = command.get('request_id')
        if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
            request_id = 'invalid'
        action = command.get('action')
        if command.get('cancel') is True or action == 'cancel':
            reason, final_request_id = 'cancelled', 'final'
            cancelled.set()
            break
        if action == 'stop':
            reason, final_request_id = 'stop', request_id
            break
        step_number += 1
        step_id = command.get('step_id')
        if step_id is None:
            step_id = request_id
        elif not isinstance(step_id, str) or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_.:-]{0,79}', step_id):
            step_id = f'step-{step_number}'
        parameters = {key: value for key, value in command.items()
                      if key not in ('request_id', 'action', 'step_id')}
        started = monotonic()
        timestamp = datetime.now(timezone.utc).isoformat()
        try:
            allowed = {
                'wait': {'ms'}, 'read': set(), 'android_snapshot': set(),
                'android_tap': {'x', 'y'}, 'android_input': {'text'},
                'android_key': {'key'}, 'android_swipe': {'x1', 'y1', 'x2', 'y2', 'ms'},
                'android_launch': set(),
            }.get(action, set())
            unexpected = set(parameters) - allowed
            if unexpected:
                raise ValueError('unsupported command fields: ' + ', '.join(sorted(unexpected)))
            if action == 'wait':
                wait_ms = command.get('ms', 0)
                if not isinstance(wait_ms, int) or isinstance(wait_ms, bool) or not 0 <= wait_ms <= 5000:
                    raise ValueError('wait ms must be an integer from 0 to 5000')
                cancelled.wait(min(wait_ms / 1000, max(0, deadline - monotonic())))
                value = handle_action('read', {})
                value['waited_ms'] = round((monotonic() - started) * 1000)
            elif action == 'read':
                value = handle_action('read', parameters)
            elif action in {'android_snapshot', 'android_tap', 'android_input',
                            'android_key', 'android_swipe', 'android_launch'}:
                value = handle_action(action, parameters)
            else:
                raise ValueError('unsupported session action')
            step = {'step_id': step_id, 'time_utc': timestamp, 'action': action, 'parameters': parameters,
                    'elapsed_ms': round((monotonic() - started) * 1000)}
            if isinstance(value, dict):
                step.update(value)
            else:
                step['result'] = value
        except Exception as exc:
            step = {'step_id': step_id, 'time_utc': timestamp, 'action': action, 'parameters': parameters,
                    'elapsed_ms': round((monotonic() - started) * 1000),
                    'error': str(exc)[:300]}
            try:
                step.update(handle_action('read', {}))
            except Exception:
                pass
        emit(request_id, 'step', {**identity, **step})
    return reason, final_request_id


def android_session_action(action, params, profile, package_name):
    """Perform only fixed-argv operations against this run's owned package."""
    serial = profile['adb_serial']
    adb_path = profile['adb']
    port = str(profile.get('adb_port', 5037))

    def adb_bytes(*args, deadline=None):
        timeout = 5.0 if deadline is None else min(5.0, deadline - time.monotonic())
        if timeout <= 0:
            raise TimeoutError('Android action exceeded its 5 second budget')
        result = subprocess.run([adb_path, '-P', port, '-s', serial, *args],
                                capture_output=True, timeout=timeout, check=False)
        if result.returncode:
            raise RuntimeError('Android lab action failed')
        return result.stdout

    def foreground(deadline=None):
        # Android 15 omits display focus from the "windows" subcommand.
        raw = adb_bytes('shell', 'dumpsys', 'window', deadline=deadline)
        text = raw.decode('utf-8', 'replace')
        focuses = re.findall(r'mCurrentFocus=([^\r\n]+)', text)
        if not focuses:
            focuses = re.findall(r'mFocusedApp=([^\r\n]+)', text)
        if not any(re.search(r'\b' + re.escape(package_name) + r'/', item) for item in focuses):
            raise ValueError('refused: the owned sample package is not foreground')

    def size(deadline=None):
        text = adb_bytes('shell', 'wm', 'size', deadline=deadline).decode('ascii', 'replace')
        matches = re.findall(r'(?:Physical|Override) size:\s*(\d+)x(\d+)', text)
        if not matches:
            raise ValueError('could not read Android display bounds')
        return tuple(map(int, matches[-1]))

    if action == 'read':
        return {'messages': [], 'output': []}
    if not package_name or not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', package_name):
        raise ValueError('owned Android package identity is unavailable')
    if action == 'android_launch':
        output = adb_bytes('shell', 'monkey', '-p', package_name,
                           '-c', 'android.intent.category.LAUNCHER', '1')
        if b'No activities found' in output:
            raise RuntimeError('the owned package has no default launcher activity')
        return {'launched_package': package_name}
    deadline = time.monotonic() + 5.0
    if action == 'android_snapshot':
        foreground(deadline)
        name = 'artex-session-' + uuid.uuid4().hex + '.xml'
        remote_path = '/data/local/tmp/' + name
        try:
            adb_bytes('shell', 'uiautomator', 'dump', remote_path, deadline=deadline)
            xml = adb_bytes('exec-out', 'cat', remote_path, deadline=deadline)
        finally:
            try:
                adb_bytes('shell', 'rm', '-f', remote_path)
            except Exception as exc:
                raise RuntimeError('Android UI snapshot temporary file cleanup failed: ' + remote_path) from exc
        if len(xml) > 1_048_576:
            raise ValueError('Android UI XML exceeds 1 MiB')
        png = adb_bytes('exec-out', 'screencap', '-p', deadline=deadline)
        if len(png) > 4 * 1024 * 1024:
            raise ValueError('Android screenshot exceeds 4 MiB')
        return {'ui_xml': xml.decode('utf-8', 'replace'),
                'screenshot_base64': base64.b64encode(png).decode('ascii'),
                'screenshot_bytes': len(png),
                'screenshot_sha256': hashlib.sha256(png).hexdigest()}
    foreground(deadline)
    width, height = size(deadline)
    if action == 'android_tap':
        x, y = params.get('x'), params.get('y')
        if any(not isinstance(v, int) or isinstance(v, bool) for v in (x, y)) or not (0 <= x < width and 0 <= y < height):
            raise ValueError('tap coordinates must be integer pixels inside the owned device display')
        adb_bytes('shell', 'input', 'tap', str(x), str(y), deadline=deadline)
        return {'tapped': {'x': x, 'y': y}}
    if action == 'android_input':
        text = params.get('text')
        if not isinstance(text, str) or not ANDROID_TEXT.fullmatch(text):
            raise ValueError('text must be 1-256 safe ASCII letters, digits, spaces, or .,!?@:_+-; Unicode and shell metacharacters are unsupported')
        encoded = text.replace(' ', '%s')
        adb_bytes('shell', 'input', 'text', encoded, deadline=deadline)
        return {'input_characters': len(text), 'unicode_supported': False}
    if action == 'android_key':
        key = params.get('key')
        if not isinstance(key, str) or key not in ANDROID_KEYS:
            raise ValueError('key is not in the Android key allowlist')
        adb_bytes('shell', 'input', 'keyevent', key, deadline=deadline)
        return {'key': key}
    if action == 'android_swipe':
        coords = [params.get(key) for key in ('x1', 'y1', 'x2', 'y2')]
        ms = params.get('ms', 300)
        if any(not isinstance(v, int) or isinstance(v, bool) for v in coords) or any(not (0 <= x < width and 0 <= y < height) for x, y in (coords[:2], coords[2:])):
            raise ValueError('swipe coordinates must be integer pixels inside the owned device display')
        if not isinstance(ms, int) or isinstance(ms, bool) or not 1 <= ms <= 5000:
            raise ValueError('swipe ms must be an integer from 1 to 5000')
        adb_bytes('shell', 'input', 'swipe', *(str(v) for v in coords), str(ms), deadline=deadline)
        return {'swipe': coords, 'duration_ms': ms}
    raise ValueError('unsupported Android session action')


def main():
    global SESSION_PROTOCOL
    # MCP/control JSON is UTF-8 on every host, including Windows launched by
    # a WSL parent whose paths contain non-ASCII characters.
    sys.stdin.reconfigure(encoding='utf-8')
    sys.stdout.reconfigure(encoding='utf-8')
    request = json.loads(sys.stdin.readline())
    profile = request.get('profile', {})
    operation = request.get('operation', 'observe')
    SESSION_PROTOCOL = operation == 'session'
    if profile.get('python_module_dir'):
        sys.path.insert(0, profile['python_module_dir'])
    import frida
    platform = profile['platform']
    if platform not in ('linux', 'windows', 'android'):
        raise ValueError('unsupported runtime platform')
    if platform != 'android' and (platform == 'windows') != (sys.platform == 'win32'):
        raise ValueError('runtime profile does not match the runner host')
    if operation not in ('doctor', 'observe', 'session'):
        raise ValueError('unsupported reverse runtime operation')
    if operation == 'session' and platform != 'android':
        raise ValueError('persistent Android sessions require an Android runtime profile')
    if request.get('operation') == 'doctor':
        if platform == 'android':
            if not profile.get('allow_package_install') or not profile.get('remote_is_lab'):
                raise ValueError('Android observation requires an explicitly configured lab')
            for field in ('adb', 'aapt'):
                if not Path(profile[field]).is_file(): raise ValueError('Android bridge tools are missing')
            state = subprocess.run([profile['adb'], '-P', str(profile.get('adb_port', 5037)), '-s', profile['adb_serial'], 'get-state'], capture_output=True, timeout=8, check=True)
            if state.stdout.strip() != b'device': raise ValueError('Android lab is not connected')
            remote = profile['remote']
            device = frida.get_device_manager().add_remote_device(remote['address'], **{k: v for k, v in remote.items() if k != 'address'})
            try: device.query_system_parameters()
            finally: frida.get_device_manager().remove_remote_device(profile['remote']['address'])
        print(json.dumps({'available': True, 'engine': 'frida', 'version': frida.__version__, 'host_platform': sys.platform, 'platform': platform}))
        return
    artifact = Path(request['artifact_path']).resolve(strict=True)
    with artifact.open('rb') as artifact_file:
        digest = hashlib.file_digest(artifact_file, 'sha256').hexdigest()
    if digest != request['sha256']:
        raise ValueError('artifact SHA256 changed before runtime admission')
    source = request.get('script', '')
    if not source.strip() or len(source.encode()) > 128 * 1024:
        raise ValueError('provide a nonempty instrumentation script up to 128 KiB')
    session_identity = {
        'platform': platform,
        'artifact_sha256': digest,
        'script_sha256': hashlib.sha256(source.encode()).hexdigest(),
        'version': frida.__version__,
    }
    if operation == 'session':
        duration = request.get('duration_ms', 3000)
        if not isinstance(duration, int) or isinstance(duration, bool) or not 100 <= duration <= 900000:
            raise ValueError('session duration_ms must be an integer from 100 to 900000')
    else:
        duration = max(100, min(int(request.get('duration_ms', 3000)), 60000))
    cancelled = threading.Event()
    commands = queue.Queue()
    def check_cancelled():
        if cancelled.is_set():
            raise RuntimeCancelled('runtime operation cancelled')

    def control():
        cancel_on_exit = True
        for line in sys.stdin:
            try:
                command = json.loads(line)
            except ValueError:
                if operation == 'session': commands.put({'request_id': 'invalid', 'action': 'invalid'})
                else: cancelled.set()
                break
            if operation == 'session':
                commands.put(command)
                if isinstance(command, dict) and (command.get('action') in ('stop', 'cancel') or command.get('cancel') is True):
                    if command.get('action') == 'stop' and command.get('cancel') is not True:
                        cancel_on_exit = False
                    else:
                        cancelled.set()
                    break
            elif isinstance(command, dict) and command.get('cancel'):
                break
        if operation == 'session':
            if cancel_on_exit:
                cancelled.set()
            commands.put(None)
        else:
            cancelled.set()
    threading.Thread(target=control, daemon=True).start()
    for name in ('SIGTERM', 'SIGINT', 'SIGBREAK'):
        if hasattr(signal, name): signal.signal(getattr(signal, name), lambda *_: cancelled.set())
    messages, output, errors = [], [], []
    lock = threading.Lock()
    captured = 0
    truncated = False
    def bounded(bucket, value):
        nonlocal captured, truncated
        text = json.dumps(value, ensure_ascii=False)
        with lock:
            if len(messages) + len(output) >= 1000 or captured + len(text.encode()) > 2 * 1024 * 1024:
                truncated = True
                return
            captured += len(text.encode())
            bucket.append(value)
    remote = profile.get('remote')
    if remote:
        if not profile.get('remote_is_lab'):
            raise ValueError('remote instrumentation requires an explicitly configured lab profile')
        device = frida.get_device_manager().add_remote_device(remote['address'], **{k: v for k, v in remote.items() if k != 'address'})
    else:
        device = frida.get_device(profile.get('device_id', 'local'), timeout=10)
    pid = session = script = None
    phase = 'prepare'
    installed = False
    package_cleanup_owned = False
    package = None
    session_reason = 'error'
    session_final_id = 'start'
    session_ready = False
    cleanup = {'script_unloaded': False, 'session_detached': False, 'owned_process_terminated': False, 'package_removed': False, 'staging_removed': False}
    started = time.monotonic()
    def adb(*args, timeout=40, cancellable=True):
        command = [profile['adb'], '-P', str(profile.get('adb_port', 5037)), '-s', profile['adb_serial'], *args]
        check_cancelled() if cancellable else None
        result = _run_cancellable_process(command, timeout, cancelled if cancellable else None)
        if result.returncode: raise RuntimeError('Android lab bridge operation failed')
        check_cancelled() if cancellable else None
        return result.stdout.decode('utf-8', 'replace')
    with tempfile.TemporaryDirectory(prefix='artex-observe-', dir=profile.get('workspace'), ignore_cleanup_errors=True) as stage:
        copied = Path(stage) / ('sample' + artifact.suffix)
        shutil.copyfile(artifact, copied)
        copied.chmod(0o700)
        try:
            check_cancelled()
            if platform == 'android':
                if not profile.get('allow_package_install') or adb('shell', 'getprop', 'ro.kernel.qemu').strip() != '1':
                    raise ValueError('automatic APK observation requires an opted-in emulator profile')
                check_cancelled()
                package = request.get('package_name', '')
                if not re.fullmatch(r'[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+', package):
                    raise ValueError('an exact Android package name is required')
                check_cancelled()
                badging_result = _run_cancellable_process([profile['aapt'], 'dump', 'badging', str(copied)], 20, cancelled)
                if badging_result.returncode:
                    raise RuntimeError('Android package metadata inspection failed')
                badging = badging_result.stdout.decode()
                check_cancelled()
                if not re.search(r"^package: name='" + re.escape(package) + r"'", badging, re.M):
                    raise ValueError('Android package does not match the uploaded artifact')
                if adb('shell', 'pm', 'list', 'packages', package).strip():
                    raise ValueError('package already exists in this lab; use a fresh emulator, no existing app is overwritten')
                check_cancelled()
                # The package was just confirmed absent. From this point cleanup
                # owns only this package, even if the adb client is cancelled
                # before it can report whether Package Manager committed install.
                package_cleanup_owned = True
                adb('install', '--no-streaming', str(copied), timeout=40)
                installed = True
                check_cancelled()
                if profile.get('java_interpreter'):
                    # A per-package setting, applied only to this newly installed
                    # sample. Avoids AOT inlining hiding Java method callbacks.
                    check_cancelled()
                    adb('shell', 'cmd', 'package', 'compile', '-m', 'verify', '-f', package)
                    check_cancelled()
                program = package
            else:
                program = str(copied)
            def on_output(observed_pid, fd, data):
                if observed_pid == pid and data:
                    bounded(output, {'fd': fd, 'text': bytes(data[:16384]).decode('utf-8', 'replace')})
            device.on('output', on_output)
            argv = request.get('argv', [])
            if argv is None: argv = []
            if not isinstance(argv, list) or not all(isinstance(x, str) and '\0' not in x for x in argv):
                raise ValueError('argv must be a string array')
            check_cancelled()
            phase = 'spawn'
            pid = device.spawn(program) if platform == 'android' else device.spawn([program, *argv], stdio='pipe')
            check_cancelled()
            phase = 'attach'
            session = device.attach(pid)
            check_cancelled()
            loaded_source = source
            if platform == 'android' and profile.get('java_bridge_module'):
                bridge = Path(profile['java_bridge_module']).resolve(strict=True)
                entry = Path(stage) / 'observation.js'
                entry.write_text('import Java from ' + json.dumps(str(bridge)) + ';\nglobalThis.Java = Java;\n' + source, encoding='utf-8')
                check_cancelled()
                phase = 'compile-java-bridge'
                loaded_source = frida.Compiler().build(str(entry), project_root=stage)
                check_cancelled()
            check_cancelled()
            phase = 'create-script'
            script = session.create_script(loaded_source)
            # Frida's default console handler writes to stdout and corrupts the
            # runner's single JSON response. Keep logs inside bounded evidence.
            script.set_log_handler(lambda level, text: bounded(messages, {
                'elapsed_ms': round((time.monotonic() - started) * 1000),
                'message': {'type': 'log', 'level': level, 'payload': text}}))
            def on_message(message, data):
                if message.get('type') == 'error': errors.append('instrumentation script reported an error')
                bounded(messages, {'elapsed_ms': round((time.monotonic() - started) * 1000), 'message': message,
                                   'data_sha256': hashlib.sha256(data).hexdigest() if data else None})
            script.on('message', on_message)
            check_cancelled()
            phase = 'load-script'
            script.load()
            check_cancelled()
            phase = 'resume'
            device.resume(pid)
            check_cancelled()
            phase = 'observe'
            if operation == 'session':
                session_ready = True
                message_cursor = 0
                output_cursor = 0
                def session_emit(request_id, kind, observation):
                    emit_session(request_id, kind, observation)
                def handle_action(action, params):
                    nonlocal message_cursor, output_cursor
                    if action == 'read':
                        value = {}
                    else:
                        if not installed:
                            raise ValueError('Android controls require this run to own the installed package')
                        value = android_session_action(action, params, profile, package)
                    with lock:
                        new_messages = messages[message_cursor:]
                        new_output = output[output_cursor:]
                        message_cursor = len(messages)
                        output_cursor = len(output)
                    if isinstance(value, dict):
                        return {**value, 'messages': new_messages, 'output': new_output}
                    return {'result': value, 'messages': new_messages, 'output': new_output}
                session_reason, session_final_id = run_session_command_loop(
                    duration, commands, cancelled, handle_action,
                    emit=session_emit,
                    is_detached=lambda: bool(session.is_detached),
                    identity=session_identity)
            else:
                end = time.monotonic() + duration / 1000
                while time.monotonic() < end and not cancelled.wait(.05):
                    if session.is_detached: break
        except RuntimeCancelled:
            if operation == 'session':
                session_reason = 'cancelled'
                session_final_id = 'final'
        except Exception as exc:
            errors.append('observation failed at ' + phase + ': ' + type(exc).__name__)
            if operation == 'session':
                session_reason = 'cancelled' if cancelled.is_set() else 'error'
                session_final_id = 'final' if cancelled.is_set() else ('final' if session_ready else 'start')
        finally:
            if script:
                try: script.unload(); cleanup['script_unloaded'] = True
                except frida.InvalidOperationError: cleanup['script_unloaded'] = True
                except Exception: errors.append('script cleanup failed')
            if session:
                try: session.detach(); cleanup['session_detached'] = True
                except frida.InvalidOperationError: cleanup['session_detached'] = True
                except Exception: errors.append('session cleanup failed')
            if pid:
                try: device.kill(pid); cleanup['owned_process_terminated'] = True
                except frida.ProcessNotFoundError: cleanup['owned_process_terminated'] = True
                except Exception: errors.append('owned process cleanup failed')
            if package_cleanup_owned:
                try:
                    cleanup_deadline = time.monotonic() + 8
                    def cleanup_adb(*args):
                        remaining = cleanup_deadline - time.monotonic()
                        if remaining <= 0:
                            raise TimeoutError('owned package cleanup exceeded its 8 second budget')
                        return adb(*args, timeout=min(5, remaining), cancellable=False)
                    packages = cleanup_adb('shell', 'pm', 'list', 'packages', package).splitlines()
                    if 'package:' + package in packages:
                        cleanup_adb('uninstall', package)
                        packages = cleanup_adb('shell', 'pm', 'list', 'packages', package).splitlines()
                        if 'package:' + package in packages:
                            errors.append('owned lab package cleanup could not be confirmed')
                        else:
                            cleanup['package_removed'] = True
                    else:
                        # The install command may have been cancelled before
                        # Package Manager committed it; absence is clean.
                        cleanup['package_removed'] = True
                except Exception:
                    errors.append('owned lab package cleanup failed')
            if remote:
                try: frida.get_device_manager().remove_remote_device(remote['address'])
                except Exception: errors.append('remote connection cleanup failed')
            # Windows process termination can return before the image mapping is
            # released. Only retry removal of this run's own staged image.
            if sys.platform == 'win32' and cleanup['owned_process_terminated']:
                for attempt in range(50):
                    try: copied.unlink(missing_ok=True); break
                    except PermissionError: time.sleep(.1)
    # Absence means there was no corresponding resource to clean; this does not
    # assert that a force-killed runner completed cleanup.
    if script is None:
        cleanup['script_unloaded'] = True
    if session is None:
        cleanup['session_detached'] = True
    if pid is None:
        cleanup['owned_process_terminated'] = True
    if platform == 'android' and not package_cleanup_owned:
        cleanup['package_removed'] = True
    cleanup['staging_removed'] = not Path(stage).exists()
    if not cleanup['staging_removed']: errors.append('owned staging cleanup failed')
    result = {'engine': 'frida', 'version': frida.__version__, 'platform': platform, 'artifact_sha256': digest,
              'script_sha256': hashlib.sha256(source.encode()).hexdigest(), 'messages': messages, 'output': output,
              'duration_ms': round((time.monotonic() - started) * 1000), 'cancelled': cancelled.is_set(),
              'truncated': truncated, 'cleanup': cleanup, 'errors': errors,
              'limitations': ['Observations cover only this sample, instrumentation script and observation window.',
                              'The configured runtime uses the host permissions; process separation is not a sandbox.'],
              'runtime_settings': {'java_interpreter': bool(profile.get('java_interpreter'))}}
    if operation == 'session':
        result.update({'reason': session_reason})
        emit_session(session_final_id, 'final', result)
    else:
        print(json.dumps(result, ensure_ascii=False), flush=True)


if __name__ == '__main__':
    try: main()
    except Exception as exc:
        # Never reflect remote tokens, full process arguments or connection strings.
        if SESSION_PROTOCOL:
            emit_session('start', 'final', {'reason': 'error', 'error': type(exc).__name__,
                                            'message': str(exc)[:300]})
        else:
            print(json.dumps({'error': type(exc).__name__, 'message': str(exc)[:300]}), flush=True)
        raise SystemExit(1)
