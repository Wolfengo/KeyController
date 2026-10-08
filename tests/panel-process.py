#!/usr/bin/python3
"""Optional seven-second Wayland process/collector regression; fake API only."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

root = Path(__file__).resolve().parent.parent
reply = {
    'api_version': 1, 'state': 'ready', 'error_code': None, 'key_id': None,
    'request_id': None, 'expires_at': None, 'active_request': None, 'scanned': True, 'scan_root': '/test/.ssh', 'scan_requires_consent': False,
    'session_available': True, 'ui_language': 'ru',
    'global_rules': {'lifetime_seconds': 0, 'revoke_on_sleep': False},
    'keys': [{
        'key_id': 'SHA256:ui-test', 'name': 'UI PROCESS TEST — artificial key',
        'path': '/test/.ssh/key', 'fingerprint': 'SHA256:ui-test', 'algorithm': 'ssh-ed25519',
        'encrypted': True, 'unavailable': None, 'unencrypted_copies': [],
        'state': 'locked', 'bound': False, 'mode': 'password', 'inherits': True,
        'rules': {'lifetime_seconds': 0},
    }],
}
with tempfile.TemporaryDirectory(prefix='ssh-keys-process-test-') as directory:
    staging = Path(directory)
    shutil.copyfile(root / 'tests/panel-process.qml', staging / 'shell.qml')
    (staging / 'plugin').symlink_to(root / 'plugin', target_is_directory=True)
    for module in ('Ui', 'Commons', 'services'):
        (staging / module).symlink_to(Path('/usr/share/omarchy/shell') / module, target_is_directory=True)
    fixture = staging / 'reply.py'
    fixture.write_text('print(' + repr(json.dumps(reply)) + ')\n')
    env = dict(os.environ, QT_QPA_PLATFORM='wayland', QT_QPA_PLATFORMTHEME='', QT_STYLE_OVERRIDE='Fusion', SSH_KEYS_TEST_REPLY=str(fixture))
    result = subprocess.run(['quickshell', '--path', str(staging / 'shell.qml'), '--no-color'], env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=12)
    print(result.stdout, end='')
    if result.returncode or 'SSH_KEYS_PROCESS_REGRESSION_OK' not in result.stdout or 'PROCESS_REGRESSION_FAILED' in result.stdout:
        raise SystemExit(1)
