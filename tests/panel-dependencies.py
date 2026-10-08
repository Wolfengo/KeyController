#!/usr/bin/python3
"""Missing-dependency gate and install button; no real packages, keys or API."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='keycontroller-dependency-ui-') as directory:
    staging = Path(directory)
    shutil.copyfile(root / 'tests/panel-dependencies.qml', staging / 'shell.qml')
    (staging / 'plugin').symlink_to(root / 'plugin', target_is_directory=True)
    for module in ('Ui', 'Commons', 'services'):
        (staging / module).symlink_to(Path('/usr/share/omarchy/shell') / module,
                                     target_is_directory=True)
    env = dict(os.environ, QT_QPA_PLATFORM='wayland', QT_QPA_PLATFORMTHEME='',
               QT_STYLE_OVERRIDE='Fusion')
    try:
        result = subprocess.run(['quickshell', '--path', str(staging / 'shell.qml'), '--no-color'],
                                env=env, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=20)
    except subprocess.TimeoutExpired as error:
        print((error.stdout or b'').decode(errors='replace'))
        raise
    print(result.stdout, end='')
    if (result.returncode or 'KEYCONTROLLER_DEPENDENCIES_REGRESSION_OK' not in result.stdout
            or 'DEPENDENCIES_REGRESSION_FAILED' in result.stdout):
        raise SystemExit(1)
