#!/usr/bin/python3
"""Capture main/candidate/settings UI with artificial keys and no system API."""
import argparse
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--output', type=Path, default=root / 'build/design-preview')
parser.add_argument('--language', choices=('ru', 'en'), default='ru')
options = parser.parse_args()
output = options.output.resolve()
output.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='ssh-keys-design-test-') as directory:
    staging = Path(directory)
    shutil.copyfile(root / 'tests/panel-design.qml', staging / 'shell.qml')
    (staging / 'plugin').symlink_to(root / 'plugin', target_is_directory=True)
    for module in ('Ui', 'Commons', 'services'):
        (staging / module).symlink_to(Path('/usr/share/omarchy/shell') / module, target_is_directory=True)
    env = dict(os.environ, QT_QPA_PLATFORM='wayland', QT_QPA_PLATFORMTHEME='', QT_STYLE_OVERRIDE='Fusion', SSH_KEYS_DESIGN_OUTPUT=str(output), SSH_KEYS_DESIGN_LANGUAGE=options.language)
    result = subprocess.run(['quickshell', '--path', str(staging / 'shell.qml'), '--no-color'], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=12)
    print(result.stdout, end='')
    if result.returncode or 'SSH_KEYS_DESIGN_REGRESSION_OK' not in result.stdout or 'DESIGN_REGRESSION_FAILED' in result.stdout:
        raise SystemExit(1)
    for state in ('main', 'candidates', 'key-details', 'discovery'):
        image = output / (state + '.png')
        if not image.is_file() or image.stat().st_size == 0:
            raise SystemExit(f'Missing visual capture: {image}')
