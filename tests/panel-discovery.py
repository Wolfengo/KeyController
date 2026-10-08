#!/usr/bin/python3
"""First-discovery consent through synthetic metadata; never reads real SSH keys."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='keycontroller-discovery-test-') as directory:
    staging = Path(directory)
    shutil.copyfile(root / 'tests/panel-discovery.qml', staging / 'shell.qml')
    (staging / 'plugin').symlink_to(root / 'plugin', target_is_directory=True)
    for module in ('Ui', 'Commons', 'services'):
        (staging / module).symlink_to(Path('/usr/share/omarchy/shell') / module,
                                    target_is_directory=True)
    fixture = staging / 'reply.py'
    fixture.write_text('import sys,time\ntime.sleep(float(sys.argv[2]))\nprint(sys.argv[1])\n')
    env = dict(os.environ, QT_QPA_PLATFORM='wayland', QT_QPA_PLATFORMTHEME='',
               QT_STYLE_OVERRIDE='Fusion', SSH_KEYS_TEST_REPLY=str(fixture))
    result = subprocess.run(['quickshell', '--path', str(staging / 'shell.qml'), '--no-color'],
                            env=env, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=25)
    print(result.stdout, end='')
    if (result.returncode or 'KEYCONTROLLER_DISCOVERY_REGRESSION_OK' not in result.stdout
            or 'DISCOVERY_REGRESSION_FAILED' in result.stdout):
        raise SystemExit(1)
