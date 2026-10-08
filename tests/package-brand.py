"""Package lifecycle regression using real fixture symlinks, mocked systemctl.

The staged hook points only at a temporary enablement directory. stat's UID
answer alone is mocked so non-root build users can model root-owned symlinks;
the real filesystem supplies types, modes, link targets and directory contents.
No real services or system enablement links are accessed or changed.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / 'packaging/keycontroller.install'
TARGET = '/usr/lib/systemd/system/ssh-keysd@.service'
MOCK = '''#!/usr/bin/python3
import json
import os
from pathlib import Path
import sys
args = sys.argv[1:]
with Path(os.environ['KC_TEST_LOG']).open('a') as stream:
    stream.write(json.dumps(args) + '\\n')
if args[0] == os.environ.get('KC_TEST_FAIL_COMMAND'):
    print('mock systemctl failure', file=sys.stderr)
    raise SystemExit(1)
if args[0] == 'is-enabled':
    state = json.loads(os.environ['KC_TEST_STATES']).get(args[1], 'enabled')
    print(state)
    raise SystemExit(0 if state in ('enabled', 'enabled-runtime') else 1)
elif args[0] == 'start' and args[1] == os.environ.get('KC_TEST_FAIL_UNIT'):
    print('mock start failure', file=sys.stderr)
    raise SystemExit(1)
elif args[0] not in ('daemon-reload', 'start', 'try-restart'):
    raise SystemExit('Unexpected mock command: ' + repr(args))
'''
STAT_MOCK = '''#!/usr/bin/python3
import os
import sys
if sys.argv[1:3] == ['-c', '%u']:
    print(os.environ['KC_TEST_OWNER'])
else:
    os.execv('/usr/bin/stat', ['/usr/bin/stat', *sys.argv[1:]])
'''


class PackageRenameTests(unittest.TestCase):
    def hook(self, links=None, action='post_install', fail_command='', fail_unit='',
             states=None, directory_state='present', owner='0'):
        with tempfile.TemporaryDirectory(prefix='keycontroller-package-test-') as temporary:
            root = Path(temporary)
            directory = root / 'multi-user.target.wants'
            if directory_state != 'missing':
                directory.mkdir(mode=0o755)
                if directory_state == 'writable':
                    directory.chmod(0o777)
                for unit, target in (links or {}).items():
                    link = directory / unit
                    if target is None:
                        link.write_text('not a symlink')
                    else:
                        link.symlink_to(target)
                if directory_state == 'symlink':
                    directory.rename(root / 'elsewhere')
                    directory.symlink_to(root / 'elsewhere')
            for name, content in [('systemctl', MOCK), ('stat', STAT_MOCK)]:
                binary = root / name
                binary.write_text(content)
                binary.chmod(0o755)
            staged = root / 'package.install'
            staged.write_text(HOOK.read_text().replace(
                '/etc/systemd/system/multi-user.target.wants', str(directory)).replace(
                '/usr/bin/stat', str(root / 'stat')))
            log = root / 'commands.jsonl'
            environment = dict(os.environ, PATH=str(root) + ':/usr/bin',
                KC_TEST_LOG=str(log), KC_TEST_FAIL_COMMAND=fail_command,
                KC_TEST_FAIL_UNIT=fail_unit, KC_TEST_STATES=json.dumps(states or {}),
                KC_TEST_OWNER=owner)
            result = subprocess.run(
                ['/usr/bin/bash', '-c', 'source "$1"; "$2"',
                 'package-hook-test', str(staged), action],
                env=environment, text=True, capture_output=True, timeout=10)
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            return result, calls

    def test_fresh_install_does_not_create_or_start_instances(self):
        for state in ('missing', 'present'):
            with self.subTest(state=state):
                result, calls = self.hook(directory_state=state)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(calls, [['daemon-reload']])

    def test_template_instances_are_discovered_from_persistent_links(self):
        result, calls = self.hook({'ssh-keysd@1000.service': TARGET,
                                  'ssh-keysd@1001.service': TARGET,
                                  'unrelated.service': '/other.service'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [['daemon-reload'],
            ['is-enabled', 'ssh-keysd@1000.service'],
            ['is-enabled', 'ssh-keysd@1001.service'],
            ['start', 'ssh-keysd@1000.service'], ['start', 'ssh-keysd@1001.service']])

    def test_invalid_names_never_partially_start_instances(self):
        invalid = ('0', '999', '01000', '4294967295', '99999999999999999999', '', '$(id)')
        for uid in invalid:
            with self.subTest(uid=uid):
                result, calls = self.hook({'ssh-keysd@1000.service': TARGET,
                                          f'ssh-keysd@{uid}.service': TARGET})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('services were not restored', result.stderr)
                self.assertFalse(any(call[0] == 'start' for call in calls))

    def test_unexpected_target_or_regular_file_is_refused(self):
        for target in ('/tmp/ssh-keysd@.service', '/dev/null', None):
            with self.subTest(target=target):
                result, calls = self.hook({'ssh-keysd@1000.service': target})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('unexpected enabled-helper link', result.stderr)
                self.assertEqual(calls, [['daemon-reload']])

    def test_untrusted_enablement_directory_is_refused(self):
        for state, owner in [('writable', '0'), ('symlink', '0'), ('present', '1000')]:
            with self.subTest(state=state, owner=owner):
                result, calls = self.hook({'ssh-keysd@1000.service': TARGET},
                                          directory_state=state, owner=owner)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('unsafe persistent enablement directory', result.stderr)
                self.assertEqual(calls, [['daemon-reload']])

    def test_nonpersistent_or_disabled_state_is_never_started(self):
        for state in ('disabled', 'masked', 'enabled-runtime', 'enabled\nstatic'):
            with self.subTest(state=state):
                result, calls = self.hook({'ssh-keysd@1000.service': TARGET},
                    states={'ssh-keysd@1000.service': state})
                self.assertNotEqual(result.returncode, 0)
                self.assertIn('could not confirm persistent enablement', result.stderr)
                self.assertFalse(any(call[0] == 'start' for call in calls))

    def test_query_failure_is_visible_and_does_not_start_instances(self):
        result, calls = self.hook({'ssh-keysd@1000.service': TARGET}, fail_command='is-enabled')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('could not confirm persistent enablement', result.stderr)
        self.assertEqual(calls, [['daemon-reload'], ['is-enabled', 'ssh-keysd@1000.service']])

    def test_reload_failure_stops_before_discovery(self):
        result, calls = self.hook(fail_command='daemon-reload')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('systemd reload failed', result.stderr)
        self.assertEqual(calls, [['daemon-reload']])

    def test_failed_start_is_visible_but_other_validated_users_are_restored(self):
        result, calls = self.hook({'ssh-keysd@1000.service': TARGET,
                                  'ssh-keysd@1001.service': TARGET},
                                 fail_unit='ssh-keysd@1000.service')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('could not restore ssh-keysd@1000.service', result.stderr)
        self.assertEqual(calls[-2:], [['start', 'ssh-keysd@1000.service'],
                                      ['start', 'ssh-keysd@1001.service']])

    def test_upgrade_retains_try_restart_without_starting_inactive_users(self):
        result, calls = self.hook(action='post_upgrade')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(calls, [['daemon-reload'], ['try-restart', 'ssh-keysd@*.service']])

    def test_upgrade_stops_after_reload_failure(self):
        result, calls = self.hook(action='post_upgrade', fail_command='daemon-reload')
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls, [['daemon-reload']])

    def test_upgrade_restart_failure_is_reported(self):
        result, calls = self.hook(action='post_upgrade', fail_command='try-restart')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('mock systemctl failure', result.stderr)
        self.assertEqual(calls[-1], ['try-restart', 'ssh-keysd@*.service'])


if __name__ == '__main__':
    unittest.main()
