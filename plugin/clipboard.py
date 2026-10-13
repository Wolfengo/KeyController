#!/usr/bin/python3
"""One explicit, bounded Wayland clipboard read for the key search field.

The CLI has no arguments and never watches the clipboard. Only a successful,
complete, single-line text read reaches stdout; errors contain stable codes.
"""

import array
import ctypes
import fcntl
import json
import os
import re
import resource
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time
import unicodedata


PASTE_COMMAND = ("/usr/bin/wl-paste", "--no-newline", "--type", "text")
MAX_BYTES = 16384
MAX_UTF16_UNITS = 4096
TIMEOUT = 2.0
CHILD_MEMORY = 128 * 1024 * 1024
HARDEN_LIBRARY = "/usr/lib/ssh-keys/harden.so"
_cancelled = False
_libc = ctypes.CDLL(None, use_errno=True)
_libc.prctl.argtypes = [ctypes.c_int, *([ctypes.c_ulong] * 4)]
_libc.prctl.restype = ctypes.c_int


class ClipboardError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _prctl(option, value):
    if _libc.prctl(option, value, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "process protection failed")


def _cancel(_signum, _frame):
    global _cancelled
    _cancelled = True


def protect_process():
    """Fail closed before obtaining clipboard content, including on parent exit."""
    parent = os.getppid()
    signal.signal(signal.SIGTERM, _cancel)
    signal.signal(signal.SIGINT, _cancel)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    _prctl(4, 0)  # PR_SET_DUMPABLE
    _prctl(38, 1)  # PR_SET_NO_NEW_PRIVS
    _prctl(1, signal.SIGTERM)  # PR_SET_PDEATHSIG
    if os.getppid() != parent or parent == 1:
        _cancel(None, None)


def clipboard_environment():
    """Keep only the local compositor connection, never arbitrary child settings."""
    runtime = os.environ.get("XDG_RUNTIME_DIR", "")
    display = os.environ.get("WAYLAND_DISPLAY", "wayland-0")
    if (not runtime.startswith("/") or len(runtime) > 4096 or "\0" in runtime
            or not display or len(display) > 4096 or "\0" in display
            or (not display.startswith("/")
                and (not re.fullmatch(r"[A-Za-z0-9_.-]{1,255}", display)
                     or display in (".", "..")))):
        raise ClipboardError("clipboard_unavailable")
    try:
        info = os.stat(runtime, follow_symlinks=False)
    except OSError:
        raise ClipboardError("clipboard_unavailable") from None
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or info.st_mode & 0o022):
        raise ClipboardError("clipboard_unavailable")
    return {"PATH": "/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
            "XDG_RUNTIME_DIR": runtime, "WAYLAND_DISPLAY": display}


def _trusted_hardening_library():
    # A system-owned constructor is already supplied by the native package.
    # Never load a library from the plugin checkout or an environment override.
    parts = HARDEN_LIBRARY.split("/")[1:]
    path = ""
    for index, part in enumerate(parts):
        path += "/" + part
        try:
            info = os.stat(path, follow_symlinks=False)
        except OSError:
            raise ClipboardError("clipboard_security_unavailable") from None
        valid_type = stat.S_ISREG(info.st_mode) if index == len(parts) - 1 else stat.S_ISDIR(info.st_mode)
        if not valid_type or info.st_uid != 0 or info.st_mode & 0o022:
            raise ClipboardError("clipboard_security_unavailable")
    return HARDEN_LIBRARY


def read_wayland_clipboard(environment):
    deadline = time.monotonic() + TIMEOUT
    library = _trusted_hardening_library()
    display = environment["WAYLAND_DISPLAY"]
    path = display if display.startswith("/") else os.path.join(environment["XDG_RUNTIME_DIR"], display)
    child_environment = {"PATH": "/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                         "LD_PRELOAD": library, "SSH_KEYS_HARDEN_STAGE": "1",
                         "SSH_KEYS_INTERNAL_CLIPBOARD": "1", "WAYLAND_SOCKET": "3"}
    if _cancelled:
        raise ClipboardError("clipboard_cancelled")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(max(0.001, deadline - time.monotonic()))
            connection.connect(path)
            connection.setblocking(True)
            return read_clipboard(environment=child_environment, deadline=deadline,
                                  wayland_connection=connection)
    except TimeoutError:
        raise ClipboardError("clipboard_timeout") from None
    except OSError:
        raise ClipboardError("clipboard_unavailable") from None


def _protect_child(parent, death_signal=signal.SIGKILL):
    # This runs in a freshly forked, single-threaded helper before exec.
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (CHILD_MEMORY, CHILD_MEMORY))
    resource.setrlimit(resource.RLIMIT_CPU, (3, 3))
    _prctl(4, 0)  # PR_SET_DUMPABLE; post-exec constructor reapplies it.
    _prctl(38, 1)  # PR_SET_NO_NEW_PRIVS
    _prctl(1, death_signal)
    if os.getppid() != parent:
        os.kill(os.getpid(), death_signal)


def _kill_group(_signum, _frame):
    os.killpg(os.getpgrp(), signal.SIGKILL)


class _Producer:
    def __init__(self, pid, fd):
        self.pid = pid
        self.stdout = os.fdopen(fd, "rb")

    def wait(self, timeout):
        deadline = time.monotonic() + timeout
        while True:
            pid, status = os.waitpid(self.pid, os.WNOHANG)
            if pid:
                return os.waitstatus_to_exitcode(status)
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(PASTE_COMMAND, timeout)
            time.sleep(0.005)


def _spawn_producer(command, environment, gate=None, discard_fds=()):
    # wl-paste forks cat to stream the offer. A group supervisor must remain
    # alive: PDEATHSIG on wl-paste alone would leave cat blocked if this helper
    # were killed. This small child has no command parser or clipboard reader.
    read_fd, write_fd = os.pipe2(os.O_CLOEXEC)
    parent = os.getpid()
    try:
        pid = os.fork()
    except OSError:
        os.close(read_fd)
        os.close(write_fd)
        raise
    if pid:
        os.close(write_fd)
        return _Producer(pid, read_fd)
    try:
        os.close(read_fd)
        for fd in discard_fds:
            os.close(fd)
        os.setsid()
        signal.signal(signal.SIGTERM, _kill_group)
        signal.signal(signal.SIGINT, _kill_group)
        _protect_child(parent, signal.SIGTERM)
        supervisor = os.getpid()
        inherited = ()
        if gate is not None:
            # Only the startup gate survives exec; the Wayland socket is not
            # passed until the post-exec constructor confirms nondumpability.
            # Duplicate above the reserved slot before touching descriptor 30.
            safe_output = fcntl.fcntl(write_fd, fcntl.F_DUPFD_CLOEXEC, 64)
            safe_gate = fcntl.fcntl(gate.fileno(), fcntl.F_DUPFD_CLOEXEC, 64)
            os.close(write_fd)
            write_fd = safe_output
            os.dup2(safe_gate, 30, inheritable=True)
            os.close(safe_gate)
            inherited = (30,)
        process = subprocess.Popen(
            command, stdin=subprocess.DEVNULL, stdout=write_fd,
            stderr=subprocess.DEVNULL, env=environment, close_fds=True,
            pass_fds=inherited,
            preexec_fn=lambda: _protect_child(supervisor),
        )
        if gate is not None:
            os.close(30)
            if gate.fileno() != 30:
                gate.close()
        os.close(write_fd)
        status = process.wait()
        os._exit(status if status >= 0 else 128 - status)
    except BaseException:
        os._exit(1)


def _stop_child(process):
    # No poll()/wait() precedes this call: even an exited child still reserves
    # its PID, so a recycled unrelated process group cannot be killed here.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        # Cancellation may race the supervisor's setsid(). Stop it before it
        # can spawn, then cover a group created between the two kill calls.
        try:
            os.kill(process.pid, signal.SIGKILL)
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    finally:
        if process.stdout is not None:
            process.stdout.close()
        try:
            process.wait(timeout=0.25)
        except subprocess.TimeoutExpired:
            # SIGKILL has already been delivered. Do not block the UI forever
            # on an OS process stuck in an uninterruptible kernel operation.
            pass


def _validate_text(data):
    try:
        value = data.decode("utf-8", errors="strict")
    except UnicodeError:
        raise ClipboardError("clipboard_invalid_text") from None
    if any(unicodedata.category(char) in ("Cc", "Cf", "Zl", "Zp") for char in value):
        raise ClipboardError("clipboard_invalid_text")
    if len(value.encode("utf-16-le")) // 2 > MAX_UTF16_UNITS:
        raise ClipboardError("clipboard_too_large")
    return value


def read_clipboard(command=PASTE_COMMAND, *, environment=None, timeout=TIMEOUT,
                   cancelled=lambda: _cancelled, deadline=None, wayland_connection=None):
    """Internal argv injection is for synthetic tests; the CLI cannot set argv."""
    deadline = time.monotonic() + timeout if deadline is None else deadline
    if cancelled():
        raise ClipboardError("clipboard_cancelled")
    gate_parent = gate_child = None
    status_read = status_write = None
    if wayland_connection is not None:
        gate_parent, gate_child = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        status_read, status_write = os.pipe2(os.O_CLOEXEC)
    try:
        discarded = () if gate_parent is None else (
            gate_parent.fileno(), wayland_connection.fileno(), status_read, status_write)
        process = _spawn_producer(command, environment, gate_child, discarded)
    except (OSError, subprocess.SubprocessError):
        if gate_parent is not None:
            gate_parent.close()
            gate_child.close()
            os.close(status_read)
            os.close(status_write)
        raise ClipboardError("clipboard_unavailable") from None
    try:
        if gate_parent is not None:
            gate_child.close()
            while True:
                if cancelled():
                    raise ClipboardError("clipboard_cancelled")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ClipboardError("clipboard_timeout")
                gate_parent.settimeout(min(0.05, remaining))
                try:
                    ready = gate_parent.recv(1)
                except TimeoutError:
                    continue
                # C confirms support for the no-exec clipboard relay. Older
                # hardening libraries send R and receive no Wayland handle.
                if ready != b"C":
                    raise ClipboardError("clipboard_security_unavailable")
                break
            destinations = array.array("i", [3, 4])
            descriptors = array.array("i", [wayland_connection.fileno(), status_write])
            if gate_parent.sendmsg([destinations], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, descriptors)]) != len(destinations.tobytes()):
                raise ClipboardError("clipboard_security_unavailable")
            os.close(status_write)
            status_write = None
            gate_parent.close()
        data = bytearray()
        status = bytearray()
        os.set_blocking(process.stdout.fileno(), False)
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ, "text")
            if status_read is not None:
                os.set_blocking(status_read, False)
                selector.register(status_read, selectors.EVENT_READ, "status")
            eof = False
            status_eof = status_read is None
            while True:
                if cancelled():
                    raise ClipboardError("clipboard_cancelled")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ClipboardError("clipboard_timeout")
                if eof and status_eof:
                    if status_read is not None and status != b"S":
                        raise ClipboardError("clipboard_unavailable")
                    # WNOWAIT preserves the PID until group cleanup, including
                    # if a broken producer leaves descendants behind.
                    result = os.waitid(os.P_PID, process.pid,
                                       os.WEXITED | os.WNOHANG | os.WNOWAIT)
                    if result is not None:
                        if result.si_code != os.CLD_EXITED or result.si_status != 0:
                            raise ClipboardError("clipboard_unavailable")
                        return _validate_text(data)
                    time.sleep(min(remaining, 0.01))
                    continue
                events = selector.select(min(remaining, 0.05))
                if not events:
                    continue
                for event, _mask in events:
                    if event.data == "status":
                        try:
                            chunk = os.read(status_read, 2 - len(status))
                        except BlockingIOError:
                            continue
                        if not chunk:
                            status_eof = True
                            selector.unregister(status_read)
                        else:
                            status.extend(chunk)
                            if status != b"S":
                                raise ClipboardError("clipboard_unavailable")
                        continue
                    try:
                        chunk = os.read(process.stdout.fileno(), min(4096, MAX_BYTES + 1 - len(data)))
                    except BlockingIOError:
                        continue
                    if not chunk:
                        eof = True
                        selector.unregister(process.stdout)
                        continue
                    data.extend(chunk)
                    if len(data) > MAX_BYTES:
                        raise ClipboardError("clipboard_too_large")
    except OSError:
        raise ClipboardError("clipboard_unavailable") from None
    finally:
        if gate_parent is not None:
            gate_parent.close()
        if status_read is not None:
            os.close(status_read)
        if status_write is not None:
            os.close(status_write)
        _stop_child(process)


def main():
    try:
        protect_process()
        if len(sys.argv) != 1:
            raise ClipboardError("clipboard_invalid_request")
        value = read_wayland_clipboard(clipboard_environment())
        if _cancelled:
            raise ClipboardError("clipboard_cancelled")
        result = {"ok": True, "text": value}
    except ClipboardError as error:
        result = {"ok": False, "error_code": error.code}
    except (OSError, ValueError):
        result = {"ok": False, "error_code": "clipboard_security_unavailable"}
    try:
        sys.stdout.buffer.write((json.dumps(result, ensure_ascii=False,
                                           separators=(",", ":")) + "\n").encode("utf-8"))
        sys.stdout.buffer.flush()
    except (BrokenPipeError, OSError):
        return 1
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
