#!/usr/bin/python3
"""Optional Wayland RU/EN metadata/Qt fallback regression, artificial API only."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='ssh-keys-locale-test-') as directory:
    staging = Path(directory)
    shutil.copyfile(root / 'tests/panel-locale.qml', staging / 'shell.qml')
    (staging / 'plugin').symlink_to(root / 'plugin', target_is_directory=True)
    for module in ('Ui', 'Commons', 'services'):
        (staging / module).symlink_to(Path('/usr/share/omarchy/shell') / module,
                                     target_is_directory=True)
    fixture = staging / 'reply.py'
    fixture.write_text('import sys\nprint(sys.argv[1])\n')
    for locale, expected in [('ru_RU.UTF-8', 'ru'), ('en_US.UTF-8', 'en'), ('de_DE.UTF-8', 'en')]:
        env = dict(os.environ, QT_QPA_PLATFORM='wayland', QT_QPA_PLATFORMTHEME='',
                   QT_STYLE_OVERRIDE='Fusion', SSH_KEYS_TEST_REPLY=str(fixture),
                   LANG=locale, LC_ALL=locale, SSH_KEYS_EXPECT_LANGUAGE=expected)
        result = subprocess.run(['quickshell', '--path', str(staging / 'shell.qml'), '--no-color'],
                                env=env, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, timeout=15)
        print(result.stdout, end='')
        if (result.returncode or 'SSH_KEYS_LOCALE_REGRESSION_OK' not in result.stdout
                or 'LOCALE_REGRESSION_FAILED' in result.stdout):
            raise SystemExit(1)
