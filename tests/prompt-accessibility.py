#!/usr/bin/env python3
"""Exercise actual AT-SPI export on a private bus; never use the desktop bus."""
import ast
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import tempfile
import time


def ready_line(process, timeout=5):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        if not selector.select(timeout):
            raise RuntimeError("private accessibility process did not become ready")
        return process.stdout.readline().strip()


def run(fixture, listener):
    with tempfile.TemporaryDirectory(prefix="ssh-keys-private-a11y-") as temporary:
        runtime = Path(temporary)
        environment = {"PATH": "/usr/bin", "HOME": temporary, "LANG": "C.UTF-8",
                       "XDG_RUNTIME_DIR": temporary, "TMPDIR": temporary,
                       "QT_QPA_PLATFORM": "offscreen"}
        processes = []
        try:
            bus = subprocess.Popen([
                "/usr/bin/dbus-daemon", "--session", "--nofork",
                "--address=unix:path=" + str(runtime / "bus"), "--print-address=1"],
                env=environment, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, start_new_session=True)
            processes.append(bus)
            address = ready_line(bus)
            if not address.startswith("unix:path=" + str(runtime / "bus")):
                raise RuntimeError("unexpected private session-bus address")
            environment["DBUS_SESSION_BUS_ADDRESS"] = address

            def call(*arguments):
                return subprocess.check_output([
                    "/usr/bin/gdbus", "call", "--session", "--dest", "org.a11y.Bus",
                    "--object-path", "/org/a11y/bus", *arguments], env=environment,
                    text=True, stderr=subprocess.DEVNULL, timeout=5)

            accessibility = ast.literal_eval(call("--method", "org.a11y.Bus.GetAddress"))[0]
            if not accessibility.startswith("unix:path=" + temporary + "/"):
                raise RuntimeError("accessibility bus escaped the private runtime")
            call("--method", "org.freedesktop.DBus.Properties.Set", "org.a11y.Status",
                 "ScreenReaderEnabled", "<true>")
            # The isolated session has no systemd user manager. Start its own
            # registry explicitly instead of relying on broker activation.
            registry = subprocess.Popen(["/usr/lib/at-spi2-registryd"],
                env=dict(environment, AT_SPI_BUS_ADDRESS=accessibility),
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(registry)
            time.sleep(0.3)
            for variant in ("raw-control", "fixed-pass", "fixed-confirm", "event-guard"):
                observer = subprocess.Popen([listener], env=environment,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                processes.append(observer)
                if ready_line(observer) != "listener_ready=1":
                    raise RuntimeError("private AT-SPI listener registration failed")
                result = subprocess.run([fixture, variant],
                    env=dict(environment, SSH_KEYS_AUDIT_SESSION_RUNTIME=temporary,
                             SSH_KEYS_AUDIT_A11Y_BUS_ADDRESS=accessibility),
                    capture_output=True, text=True, timeout=7)
                observed, errors = observer.communicate(timeout=5)
                if result.returncode or observer.returncode:
                    safe_status = "; ".join(line for line in result.stdout.splitlines()
                        if re.fullmatch(r"(?:session_bus_connected=[01] dbus_env_set=[01]|synthetic_input_correct=[01]|accessibility_bridge_active=[01]|input_matches=[01] input_length=\d+ field_focused=[01])", line))
                    raise RuntimeError(f"accessibility fixture failed: {variant}; fixture_exit={result.returncode}; observer_exit={observer.returncode}; {safe_status}")
                control = variant == "raw-control"
                expected_connected = control or variant == "event-guard"
                expected_bus = f"session_bus_connected={int(expected_connected)} dbus_env_set={int(not control)}"
                expected_active = f"accessibility_bridge_active={int(expected_connected)}"
                if (expected_bus not in result.stdout or expected_active not in result.stdout
                        or "synthetic_input_correct=1" not in result.stdout):
                    raise RuntimeError("private bus or typing control failed: " + variant)
                match = re.search(r"a11y_text_events=(\d+) inserted_marker=(\d) removed_marker=(\d)", observed)
                if not match:
                    raise RuntimeError("missing private accessibility observation")
                count, inserted, removed = map(int, match.groups())
                if control:
                    if not (count > 0 and inserted and removed):
                        raise RuntimeError("old Password widget positive control did not export events")
                elif count or inserted or removed:
                    raise RuntimeError("protected password escaped through AT-SPI")
                print(f"{variant}: text_events={count} inserted_marker={inserted} removed_marker={removed}", flush=True)
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    if process is bus:
                        os.killpg(process.pid, signal.SIGTERM)
                    else:
                        process.terminate()
                    try:
                        process.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait()


if __name__ == "__main__":
    if len(sys.argv) != 3:
        raise SystemExit("usage: prompt-accessibility.py FIXTURE LISTENER")
    run(str(Path(sys.argv[1]).resolve()), str(Path(sys.argv[2]).resolve()))
