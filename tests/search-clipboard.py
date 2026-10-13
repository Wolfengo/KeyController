#!/usr/bin/python3
"""Isolated native Qt clipboard regression; never accesses the desktop clipboard.

Runs the actual plugin/SearchInput.qml with the real Qt Quick Controls TextField.
The staging wrapper substitutes only qs.Ui's theme properties because a standalone
QQmlEngine cannot load Quickshell's process-owned theme singletons. The C++ test
forces the offscreen platform before constructing QGuiApplication and supplies
only synthetic QMimeData; it does not connect to Wayland/X11 or execute wl-paste.
"""

import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    root = Path(__file__).resolve().parent.parent
    if len(sys.argv) != 2:
        raise SystemExit("usage: search-clipboard.py /path/to/search-clipboard-test")
    executable = Path(sys.argv[1]).resolve()
    with tempfile.TemporaryDirectory(prefix="keycontroller-search-clipboard-") as directory:
        stage = Path(directory)
        (stage / "plugin").mkdir()
        (stage / "qs/Ui").mkdir(parents=True)
        (stage / "runtime").mkdir(mode=0o700)
        shutil.copyfile(root / "plugin/SearchInput.qml", stage / "plugin/SearchInput.qml")
        shutil.copyfile(root / "tests/search-clipboard.qml", stage / "fixture.qml")
        (stage / "qs/Ui/qmldir").write_text("module qs.Ui\nTextField 1.0 TextField.qml\n")
        (stage / "qs/Ui/TextField.qml").write_text("""import QtQuick
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
""")
        env = {
            "PATH": "/usr/bin:/bin",
            "HOME": str(stage),
            "XDG_RUNTIME_DIR": str(stage / "runtime"),
            "QT_QPA_PLATFORM": "offscreen",
            "QT_QUICK_BACKEND": "software",
            "QT_QUICK_CONTROLS_STYLE": "Basic",
            "QT_QPA_PLATFORMTHEME": "",
            "QT_STYLE_OVERRIDE": "Fusion",
            "QML_DISABLE_DISK_CACHE": "1",
            "LC_ALL": "C.UTF-8",
        }
        # The same isolated harness can be run with a separately installed Qt
        # prefix, including Qt 6.12 CI, without importing desktop environment.
        for name in ("LD_LIBRARY_PATH", "QT_PLUGIN_PATH", "QML2_IMPORT_PATH", "QML_IMPORT_PATH"):
            if name in os.environ:
                env[name] = os.environ[name]
        result = subprocess.run(
            [str(executable), str(stage / "fixture.qml")], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=25,
            stdin=subprocess.DEVNULL, close_fds=True, check=False,
        )
        print(result.stdout, end="")
        return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
