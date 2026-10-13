#!/usr/bin/python3
"""Original wl-paste, isolated synthetic Wayland server, no desktop clipboard."""
import importlib.util
from pathlib import Path
import shlex
import socket
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROTOCOL = Path("/usr/share/qt6/wayland/protocols/wlr-data-control/wlr-data-control-unstable-v1.xml")
spec = importlib.util.spec_from_file_location("clipboard", ROOT / "plugin/clipboard.py")
clipboard = importlib.util.module_from_spec(spec)
sys.dont_write_bytecode = True
spec.loader.exec_module(clipboard)


class OriginalWaylandClipboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.directory = tempfile.TemporaryDirectory(prefix="keycontroller-wayland-clipboard-")
        cls.addClassCleanup(cls.directory.cleanup)
        cls.work = Path(cls.directory.name)
        cls.server = cls.work / "server"
        cls.library = cls.work / "harden.so"
        for command in (
            ["/usr/bin/wayland-scanner", "server-header", str(PROTOCOL), str(cls.work / "data-control-server.h")],
            ["/usr/bin/wayland-scanner", "private-code", str(PROTOCOL), str(cls.work / "data-control.c")],
            ["/usr/bin/cc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror",
             str(ROOT / "src/harden.c"), "-o", str(cls.library)],
        ):
            cls.compile(command)
        flags = subprocess.check_output(["/usr/bin/pkg-config", "--cflags", "--libs", "wayland-server"],
                                        text=True, timeout=10)
        cls.compile(["/usr/bin/cc", "-O2", "-Wall", "-Wextra", "-Werror", "-I", str(cls.work),
                     str(ROOT / "tests/clipboard-wayland.c"), str(cls.work / "data-control.c"),
                     "-o", str(cls.server), *shlex.split(flags)])

    @staticmethod
    def compile(command):
        result = subprocess.run(command, capture_output=True, timeout=30, check=False)
        if result.returncode:
            raise AssertionError("synthetic Wayland fixture failed to build: " + result.stderr.decode())

    def original_paste(self, mode, **options):
        client, server = socket.socketpair()
        marker = self.work / (mode + ".received")
        process = subprocess.Popen([str(self.server), str(server.fileno()), mode, str(marker)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL, pass_fds=(server.fileno(),),
                                   env={"PATH": "/usr/bin"})
        server.close()
        try:
            if mode == "cancel":
                options["cancelled"] = marker.exists
            return clipboard.read_clipboard(
                clipboard.PASTE_COMMAND, environment={
                    "PATH": "/usr/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                    "LD_PRELOAD": str(self.library), "SSH_KEYS_HARDEN_STAGE": "1",
                    "SSH_KEYS_INTERNAL_CLIPBOARD": "1", "WAYLAND_SOCKET": "3",
                }, wayland_connection=client, **options)
        finally:
            client.close()
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=1)

    def test_original_wl_paste_receives_utf8_through_protected_gate(self):
        self.assertEqual(self.original_paste("normal"), "KeyController test 🔑")
        self.assertTrue((self.work / "normal.received").exists())

    def test_original_wl_paste_does_not_accept_oversize_prefix(self):
        with self.assertRaises(clipboard.ClipboardError) as error:
            self.original_paste("oversize")
        self.assertEqual(error.exception.code, "clipboard_unavailable")
        self.assertTrue((self.work / "oversize.received").exists())

    def test_original_wl_paste_trickle_uses_total_deadline(self):
        started = time.monotonic()
        with self.assertRaises(clipboard.ClipboardError) as error:
            self.original_paste("trickle", timeout=0.25)
        self.assertEqual(error.exception.code, "clipboard_timeout")
        self.assertLess(time.monotonic() - started, 0.8)
        self.assertTrue((self.work / "trickle.received").exists())

    def test_original_wl_paste_cancels_after_requesting_offer(self):
        with self.assertRaises(clipboard.ClipboardError) as error:
            self.original_paste("cancel")
        self.assertEqual(error.exception.code, "clipboard_cancelled")
        self.assertTrue((self.work / "cancel.received").exists())


if __name__ == "__main__":
    unittest.main()
