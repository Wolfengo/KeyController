#!/usr/bin/python3
"""Real ClipboardPaste/Process integration with fake text and no display server.

Requires Quickshell, Qt Quick Controls and QtTest. Production QML is staged
unchanged beside a synthetic clipboard.py; no real wl-paste, key API, desktop
clipboard, secrets, or system package operations are used.
"""

import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parent.parent
SCENARIOS = (
    "success", "nonzero", "stale_text", "stale_cursor", "stale_selection",
    "stale_focus", "focus_cancel", "close_panel", "destroy_editor",
    "destroy_paste", "timeout",
)
FAKE_PROVIDER = '''import json, os, signal, sys, time
from pathlib import Path
root = Path(__file__).resolve().parent.parent
events = root / "events.jsonl"
def record(event):
    with events.open("a") as output:
        output.write(json.dumps({"event": event, "pid": os.getpid()}) + "\\n")
def terminate(signum, frame):
    record("terminated")
    # Deliberately return success with already-written JSON after cancellation.
    # A late successful exit must not restore a stale pending paste.
    raise SystemExit(0)
signal.signal(signal.SIGTERM, terminate)
record("started")
print(json.dumps({"ok": True, "text": "PASTE"}), flush=True)
print("KEYCONTROLLER_SYNTHETIC_STDERR_MUST_STAY_PRIVATE", file=sys.stderr, flush=True)
deadline = time.monotonic() + 10
while (root / "release").read_text() != "finish":
    if time.monotonic() >= deadline:
        record("fixture_timeout")
        raise SystemExit(99)
    time.sleep(.01)
record("finished")
raise SystemExit(7 if os.environ["KEYCONTROLLER_PASTE_TEST_CASE"] == "nonzero" else 0)
'''
TEXT_FIELD_STUB = '''import QtQuick
import QtQuick.Controls as Controls
Controls.TextField {
  property color foreground: "white"
  property color accent: "cyan"
  property color selectionTint: "steelblue"
  property bool password: false
  property real horizontalPadding: 8
  property real verticalPadding: 4
  property bool hasCursor: false
  color: foreground
  selectionColor: selectionTint
  font.pixelSize: 16
}
'''


def running(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(") ", 1)[1][0] != "Z"
    except FileNotFoundError:
        return False


def run_scenario(executable, scenario):
    with tempfile.TemporaryDirectory(prefix="keycontroller-paste-integration-") as directory:
        stage = Path(directory)
        (stage / "plugin").mkdir()
        (stage / "Ui").mkdir()
        (stage / "runtime").mkdir(mode=0o700)
        (stage / "cache").mkdir()
        (stage / "events.jsonl").write_text("")
        (stage / "release").write_text("")
        shutil.copyfile(ROOT / "tests/clipboard-paste.qml", stage / "shell.qml")
        for name in ("SearchInput.qml", "ClipboardPaste.qml"):
            shutil.copyfile(ROOT / "plugin" / name, stage / "plugin" / name)
        (stage / "plugin/clipboard.py").write_text(FAKE_PROVIDER)
        (stage / "Ui/qmldir").write_text("module qs.Ui\nTextField 1.0 TextField.qml\n")
        (stage / "Ui/TextField.qml").write_text(TEXT_FIELD_STUB)
        environment = {
            "PATH": "/usr/bin:/bin", "HOME": str(stage),
            "XDG_RUNTIME_DIR": str(stage / "runtime"), "XDG_CACHE_HOME": str(stage / "cache"),
            "QT_QPA_PLATFORM": "offscreen", "QT_QUICK_BACKEND": "software",
            "QT_QUICK_CONTROLS_STYLE": "Basic", "QT_QPA_PLATFORMTHEME": "",
            "QT_STYLE_OVERRIDE": "Fusion", "QML_DISABLE_DISK_CACHE": "1", "LC_ALL": "C.UTF-8",
            "KEYCONTROLLER_PASTE_TEST_CASE": scenario,
            "KEYCONTROLLER_PASTE_TEST_EVENTS": str(stage / "events.jsonl"),
            "KEYCONTROLLER_PASTE_TEST_RELEASE": str(stage / "release"),
        }
        process = subprocess.Popen(
            [executable, "--path", str(stage / "shell.qml"), "--no-color"], env=environment,
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, start_new_session=True, close_fds=True,
        )
        try:
            output, _ = process.communicate(timeout=12)
        except BaseException:
            os.killpg(process.pid, signal.SIGKILL)
            process.communicate()
            raise
        events = [json.loads(line) for line in (stage / "events.jsonl").read_text().splitlines()]
        end = time.monotonic() + 1
        while any(running(event["pid"]) for event in events) and time.monotonic() < end:
            time.sleep(.01)
        try:
            assert process.returncode == 0, output
            assert "CLIPBOARD_PASTE_REGRESSION_OK" in output, output
            assert "CLIPBOARD_PASTE_REGRESSION_FAILED" not in output, output
            assert "KEYCONTROLLER_SYNTHETIC_STDERR_MUST_STAY_PRIVATE" not in output, output
            assert sum(event["event"] == "started" for event in events) == 1, events
            assert not any(running(event["pid"]) for event in events), events
            assert not any(event["event"] == "fixture_timeout" for event in events), events
        finally:
            for event in events:
                if running(event["pid"]):
                    os.kill(event["pid"], signal.SIGKILL)
        print(f"PASS clipboard paste integration: {scenario}")


def main():
    executable = shutil.which("quickshell")
    if not executable:
        raise SystemExit("clipboard-paste.py requires the original Quickshell executable")
    for scenario in SCENARIOS:
        run_scenario(executable, scenario)
    print(f"CLIPBOARD_PASTE_INTEGRATION_OK: {len(SCENARIOS)} scenarios")


if __name__ == "__main__":
    main()
