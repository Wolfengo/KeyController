#!/usr/bin/python3
"""Clipboard boundary regressions with synthetic producers, never a real clipboard."""

import importlib.util
from contextlib import contextmanager
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "plugin/clipboard.py"
spec = importlib.util.spec_from_file_location("clipboard", HELPER)
clipboard = importlib.util.module_from_spec(spec)
sys.dont_write_bytecode = True
spec.loader.exec_module(clipboard)


def producer(code):
    return [sys.executable, "-I", "-c", code]


def read(code, **options):
    return clipboard.read_clipboard(producer(code), environment={}, **options)


def bootstrap(code):
    # Override only the in-process test seam; production CLI accepts no argv.
    return producer(
        "import importlib.util,sys;sys.dont_write_bytecode=True;"
        f"s=importlib.util.spec_from_file_location('clipboard',{str(HELPER)!r});"
        "m=importlib.util.module_from_spec(s);s.loader.exec_module(m);"
        "original=m.read_clipboard;"
        f"m.read_wayland_clipboard=lambda environment:original({producer(code)!r},environment={{}});"
        "m.clipboard_environment=lambda:{};sys.argv=['clipboard.py'];"
        "raise SystemExit(m.main())"
    )


def wait_for_file(path):
    end = time.monotonic() + 2
    while time.monotonic() < end:
        if path.exists() and path.read_text():
            return int(path.read_text())
        time.sleep(0.01)
    raise AssertionError("synthetic producer did not start")


def running(pid):
    try:
        # Orphaned children may briefly await init's reaper after SIGKILL.
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
    except (FileNotFoundError, ProcessLookupError):
        return False


@contextmanager
def _socket_pair():
    left, right = socket.socketpair()
    try:
        yield left, right
    finally:
        left.close()
        right.close()


class ClipboardTests(unittest.TestCase):
    def assert_error(self, expected, code, **options):
        with self.assertRaises(clipboard.ClipboardError) as error:
            read(code, **options)
        self.assertEqual(error.exception.code, expected)

    def test_small_complete_utf8_text(self):
        self.assertEqual(read("import os;os.write(1,'Ключ café 🔑'.encode())"), "Ключ café 🔑")

    def test_empty_text_is_valid(self):
        self.assertEqual(read("pass"), "")

    def test_byte_limit_allows_utf8_boundary(self):
        # Astral characters consume two UTF-16 units, as they do in QML.
        self.assertEqual(len(read("import os;os.write(1,('🔑'*2048).encode())")), 2048)

    def test_utf16_character_limit(self):
        self.assert_error("clipboard_too_large", "import os;os.write(1,('🔑'*2049).encode())")
        self.assert_error("clipboard_too_large", "import os;os.write(1,b'a'*4097)")

    def test_accepts_exact_search_limit(self):
        self.assertEqual(len(read("import os;os.write(1,b'a'*4096)")), 4096)

    def test_oversize_producer_is_stopped_without_draining(self):
        started = time.monotonic()
        self.assert_error("clipboard_too_large", "import os\nwhile True: os.write(1,b'x'*4096)")
        self.assertLess(time.monotonic() - started, 1)

    def test_exact_byte_limit_still_obeys_character_limit(self):
        self.assert_error("clipboard_too_large", "import os;os.write(1,b'x'*16384)")

    def test_invalid_utf8_and_binary_data_are_rejected(self):
        for data in (b"\xff", b"abc\0def", b"\xc0\x80", b"\xed\xa0\x80"):
            with self.subTest(data=data):
                self.assert_error("clipboard_invalid_text", f"import os;os.write(1,{data!r})")

    def test_multiline_controls_and_direction_overrides_are_rejected(self):
        for text in ("a\nb", "a\rb", "a\tb", "a\x1bb", "a\u2028b", "a\u2029b", "a\u202eb"):
            with self.subTest(text=repr(text)):
                self.assert_error("clipboard_invalid_text", f"import os;os.write(1,{text!r}.encode())")

    def test_split_utf8_sequences_are_decoded_after_complete_read(self):
        self.assertEqual(read("import os,time;os.write(1,b'\\xd0');time.sleep(.02);os.write(1,b'\\x9a')"), "К")

    def test_slow_trickle_uses_one_total_deadline(self):
        started = time.monotonic()
        self.assert_error("clipboard_timeout", "import os,time\nwhile True: os.write(1,b'x');time.sleep(.02)", timeout=0.15)
        self.assertLess(time.monotonic() - started, 0.6)

    def test_silent_producer_times_out(self):
        self.assert_error("clipboard_timeout", "import time;time.sleep(10)", timeout=0.1)

    def test_eof_does_not_bypass_process_deadline(self):
        self.assert_error("clipboard_timeout", "import os,time;os.close(1);time.sleep(10)", timeout=0.1)

    def test_nonzero_exit_discards_complete_text(self):
        self.assert_error("clipboard_unavailable", "import os;os.write(1,b'private text');os._exit(1)")

    def test_signalled_exit_discards_text(self):
        self.assert_error("clipboard_unavailable", "import os,signal;os.write(1,b'private text');os.kill(os.getpid(),signal.SIGKILL)")

    def test_missing_executable_is_a_stable_error(self):
        with self.assertRaises(clipboard.ClipboardError) as error:
            clipboard.read_clipboard(["/nonexistent/keycontroller-clipboard-test"], environment={})
        self.assertEqual(error.exception.code, "clipboard_unavailable")

    def test_pre_cancelled_request_spawns_nothing(self):
        with patch.object(clipboard.subprocess, "Popen") as spawn:
            with self.assertRaises(clipboard.ClipboardError) as error:
                read("pass", cancelled=lambda: True)
        self.assertEqual(error.exception.code, "clipboard_cancelled")
        spawn.assert_not_called()

    def test_runtime_cancellation_reaps_child(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "pid"
            code = f"import os,time;open({str(marker)!r},'w').write(str(os.getpid()));time.sleep(10)"
            self.assert_error("clipboard_cancelled", code, cancelled=marker.exists)
            self.assertFalse(Path(f"/proc/{int(marker.read_text())}").exists())

    def test_timeout_kills_descendants_in_process_group(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "pid"
            code = ("import os,time\nif os.fork()==0:\n"
                    f" open({str(marker)!r},'w').write(str(os.getpid()))\n"
                    " time.sleep(10)\nelse:\n time.sleep(10)")
            self.assert_error("clipboard_timeout", code, timeout=0.2)
            pid = int(marker.read_text())
            end = time.monotonic() + 1
            while running(pid) and time.monotonic() < end:
                time.sleep(0.01)
            self.assertFalse(running(pid))

    def test_cli_cancellation_has_no_partial_text_or_stderr(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "pid"
            code = (f"import os,time;open({str(marker)!r},'w').write(str(os.getpid()));"
                    "os.write(1,b'PRIVATE_PARTIAL');os.write(2,b'PRIVATE_ERROR');time.sleep(10)")
            child = subprocess.Popen(bootstrap(code), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                pid = wait_for_file(marker)
                child.send_signal(signal.SIGTERM)
                stdout, stderr = child.communicate(timeout=1)
                self.assertEqual(json.loads(stdout), {"ok": False, "error_code": "clipboard_cancelled"})
                self.assertEqual(stderr, b"")
                self.assertFalse(Path(f"/proc/{pid}").exists())
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()

    def test_helper_sigkill_also_kills_producer(self):
        with tempfile.TemporaryDirectory() as directory:
            marker = Path(directory) / "pid"
            code = ("import os,time\nif os.fork()==0:\n"
                    f" open({str(marker)!r},'w').write(str(os.getpid()))\n"
                    " time.sleep(10)\nelse:\n time.sleep(10)")
            child = subprocess.Popen(bootstrap(code), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                pid = wait_for_file(marker)
                child.kill()
                child.communicate(timeout=1)
                end = time.monotonic() + 1
                while running(pid) and time.monotonic() < end:
                    time.sleep(0.01)
                self.assertFalse(running(pid))
            finally:
                if child.poll() is None:
                    child.kill()
                    child.wait()

    def test_cli_error_never_emits_input(self):
        result = subprocess.run(bootstrap("import os;os.write(1,b'PRIVATE\\x00PARTIAL')"),
                                capture_output=True, timeout=3, check=False)
        self.assertEqual(json.loads(result.stdout), {"ok": False, "error_code": "clipboard_invalid_text"})
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.returncode, 1)

    def test_cli_success_is_bounded_utf8_json(self):
        result = subprocess.run(bootstrap("import os;os.write(1,('鍵'*4096).encode())"),
                                capture_output=True, timeout=3, check=False)
        self.assertEqual(json.loads(result.stdout), {"ok": True, "text": "鍵" * 4096})
        self.assertLessEqual(len(result.stdout), clipboard.MAX_BYTES + 64)
        self.assertEqual(result.stderr, b"")
        self.assertEqual(result.returncode, 0)

    def test_real_cli_rejects_arguments_without_accessing_clipboard(self):
        result = subprocess.run([sys.executable, "-I", str(HELPER), "--command", "anything"],
                                capture_output=True, timeout=3, check=False)
        self.assertEqual(json.loads(result.stdout), {"ok": False, "error_code": "clipboard_invalid_request"})
        self.assertEqual(result.stderr, b"")

    def test_child_resource_and_descriptor_boundaries(self):
        read_fd, write_fd = os.pipe()
        os.set_inheritable(write_fd, True)
        try:
            code = ("import os,resource,json;"
                    f"fd={write_fd};"
                    "core=resource.getrlimit(resource.RLIMIT_CORE);"
                    "memory=resource.getrlimit(resource.RLIMIT_AS);"
                    "cpu=resource.getrlimit(resource.RLIMIT_CPU);"
                    "status=open('/proc/self/status').read();"
                    "print(json.dumps([core,memory,cpu,'NoNewPrivs:\\t1' in status]),end='')")
            result = json.loads(read(code))
            self.assertEqual(result, [[0, 0], [clipboard.CHILD_MEMORY] * 2, [3, 3], True])
            self.assertEqual(read(f"import os\ntry: os.fstat({write_fd});print('open',end='')\nexcept OSError: print('closed',end='')"), "closed")
        finally:
            os.close(read_fd)
            os.close(write_fd)

    def test_environment_drops_unrelated_variables(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.dict(os.environ, {"XDG_RUNTIME_DIR": directory, "WAYLAND_DISPLAY": "wayland-1",
                                         "LD_PRELOAD": "private", "PYTHONPATH": "private",
                                         "WAYLAND_SOCKET": "100", "SECRET": "private"}, clear=True):
                self.assertEqual(clipboard.clipboard_environment(), {
                    "PATH": "/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                    "XDG_RUNTIME_DIR": directory, "WAYLAND_DISPLAY": "wayland-1"})

    def test_invalid_environment_fails_without_spawning(self):
        for display in ("../other", ".", "..", "wayland\x00", "x" * 4097):
            with tempfile.TemporaryDirectory() as directory:
                with patch.object(clipboard.os, "environ", {"XDG_RUNTIME_DIR": directory, "WAYLAND_DISPLAY": display}):
                    with self.assertRaises(clipboard.ClipboardError):
                        clipboard.clipboard_environment()

    def test_untrusted_hardening_library_cannot_be_loaded(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory) / "harden.so"
            candidate.write_text("untrusted placeholder")
            with patch.object(clipboard, "HARDEN_LIBRARY", str(candidate)):
                with self.assertRaises(clipboard.ClipboardError) as error:
                    clipboard._trusted_hardening_library()
            self.assertEqual(error.exception.code, "clipboard_security_unavailable")

    def test_stage_rejects_missing_preload_without_transferring_data(self):
        with _socket_pair() as (connection, peer):
            peer.sendall(b"PRIVATE_CLIPBOARD")
            # The external process has no fd3 or compositor path. If the
            # constructor does not run, it cannot obtain the clipboard socket.
            code = "import os\ntry: os.read(3,1);os.write(1,b'UNSAFE')\nexcept OSError: pass"
            with self.assertRaises(clipboard.ClipboardError) as error:
                clipboard.read_clipboard(producer(code), environment={}, wayland_connection=connection)
            self.assertEqual(error.exception.code, "clipboard_security_unavailable")
            self.assertEqual(connection.recv(64), b"PRIVATE_CLIPBOARD")

    def test_old_stage_protocol_receives_no_clipboard_handle(self):
        with _socket_pair() as (connection, peer):
            peer.sendall(b"PRIVATE_CLIPBOARD")
            code = "import os,time;os.write(30,b'R');time.sleep(10)"
            with self.assertRaises(clipboard.ClipboardError) as error:
                clipboard.read_clipboard(producer(code), environment={}, wayland_connection=connection)
            self.assertEqual(error.exception.code, "clipboard_security_unavailable")
            self.assertEqual(connection.recv(64), b"PRIVATE_CLIPBOARD")

    def test_stage_handshake_shares_read_deadline(self):
        with _socket_pair() as (connection, _peer):
            started = time.monotonic()
            with self.assertRaises(clipboard.ClipboardError) as error:
                clipboard.read_clipboard(producer("import time;time.sleep(10)"), environment={},
                                         timeout=0.1, wayland_connection=connection)
            self.assertEqual(error.exception.code, "clipboard_timeout")
            self.assertLess(time.monotonic() - started, 0.5)

    def test_fork_failure_does_not_close_callers_socket(self):
        with _socket_pair() as (connection, _peer):
            with patch.object(clipboard.os, "fork", side_effect=OSError("synthetic failure")):
                with self.assertRaises(clipboard.ClipboardError) as error:
                    clipboard.read_clipboard(producer("pass"), environment={}, wayland_connection=connection)
            self.assertEqual(error.exception.code, "clipboard_unavailable")
            self.assertGreaterEqual(os.fstat(connection.fileno()).st_mode, 0)


class NativeClipboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="keycontroller-clipboard-test-")
        cls.addClassCleanup(cls.directory.cleanup)
        directory = Path(cls.directory.name)
        cls.library = directory / "harden.so"
        cls.producer = directory / "synthetic-producer"
        source = directory / "producer.c"
        source.write_text(r'''
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    if (!strcmp(argv[1], "inspect")) {
        struct rlimit core;
        if (getrlimit(RLIMIT_CORE, &core)) return 3;
        char output[128];
        int size = snprintf(output, sizeof output, "[%d,%ld,%ld,%d,%d,%d]",
            prctl(PR_GET_DUMPABLE), (long)core.rlim_cur, (long)core.rlim_max,
            prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0),
            !!(fcntl(3,F_GETFD)&FD_CLOEXEC), !!(fcntl(4,F_GETFD)&FD_CLOEXEC));
        if (write(1,output,size)!=size || write(4,"S",1)!=1) return 4;
        return 0;
    }
    if (!strcmp(argv[1], "partial")) { write(1,"PRIVATE",7); return 0; }
    if (!strcmp(argv[1], "double-status")) { write(4,"SS",2); return 0; }
    if (!strcmp(argv[1], "empty")) { write(4,"S",1); return 0; }
    if (!strcmp(argv[1], "late-status")) { close(1); sleep(10); return 0; }
    if (!strcmp(argv[1], "exec")) { execl("/usr/bin/true","true",NULL); return 5; }
    if (strcmp(argv[1], "relay")) return 6;
    if (dup2(3,0)<0) return 7;
    pid_t pid=fork();
    if (pid<0) return 8;
    if (!pid) { execlp("cat","cat",NULL); _exit(9); }
    // Reproduce original wl-paste's ignored child exit status.
    waitpid(pid,NULL,0);
    return 0;
}
''')
        for command in (["/usr/bin/cc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
                         str(ROOT / "src/harden.c"), "-o", str(cls.library)],
                        ["/usr/bin/cc", "-O2", "-Wall", "-Wextra", "-Werror",
                         str(source), "-o", str(cls.producer)]):
            result = subprocess.run(command, capture_output=True, timeout=30, check=False)
            if result.returncode:
                raise AssertionError("synthetic native fixture did not compile: " + result.stderr.decode())

    def run_native(self, mode, value=b"", **options):
        with _socket_pair() as (connection, peer):
            if value:
                peer.sendall(value)
            peer.shutdown(socket.SHUT_WR)
            return clipboard.read_clipboard(
                [str(self.producer), mode], wayland_connection=connection,
                environment={"PATH": "/usr/bin", "LD_PRELOAD": str(self.library),
                             "SSH_KEYS_HARDEN_STAGE": "1", "SSH_KEYS_INTERNAL_CLIPBOARD": "1",
                             "WAYLAND_SOCKET": "3"}, **options)

    def test_constructor_protects_before_receiving_descriptors(self):
        self.assertEqual(json.loads(self.run_native("inspect")), [0, 0, 0, 1, 1, 1])

    def test_complete_relay_and_empty_selection(self):
        self.assertEqual(self.run_native("relay", "Ключ 🔑".encode()), "Ключ 🔑")
        self.assertEqual(self.run_native("relay"), "")

    def test_relay_overflow_cannot_become_empty_or_partial_success(self):
        with self.assertRaises(clipboard.ClipboardError) as error:
            self.run_native("relay", b"x" * 16385)
        self.assertEqual(error.exception.code, "clipboard_unavailable")

    def test_clean_parent_exit_without_relay_completion_is_rejected(self):
        with self.assertRaises(clipboard.ClipboardError) as error:
            self.run_native("partial")
        self.assertEqual(error.exception.code, "clipboard_unavailable")

    def test_status_pipe_accepts_exactly_one_marker(self):
        self.assertEqual(self.run_native("empty"), "")
        with self.assertRaises(clipboard.ClipboardError) as error:
            self.run_native("double-status")
        self.assertEqual(error.exception.code, "clipboard_unavailable")

    def test_status_pipe_uses_whole_deadline(self):
        with self.assertRaises(clipboard.ClipboardError) as error:
            self.run_native("late-status", timeout=0.1)
        self.assertEqual(error.exception.code, "clipboard_timeout")

    def test_unexpected_exec_fails_closed_before_reading(self):
        with self.assertRaises(clipboard.ClipboardError) as error:
            self.run_native("exec", b"PRIVATE")
        self.assertEqual(error.exception.code, "clipboard_unavailable")

    def test_reserved_gate_descriptor_does_not_replace_parent_descriptor(self):
        descriptors = []
        try:
            while not descriptors or descriptors[-1] < 32:
                descriptors.append(os.open("/dev/null", os.O_RDONLY))
            before = os.fstat(30)
            self.assertEqual(self.run_native("relay", b"safe"), "safe")
            self.assertEqual(os.fstat(30), before)
        finally:
            for fd in descriptors:
                os.close(fd)


if __name__ == "__main__":
    unittest.main()
