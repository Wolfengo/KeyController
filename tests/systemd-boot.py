"""Exercise the cold-boot transaction without starting any services.

systemd-analyze verify and restarting an already running service do not expose
all cycles through basic.target/sockets.target. Use systemd's actual test-mode
transaction planner with isolated unit and generator directories instead.
"""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = Path('/usr/lib/systemd/systemd')
UID = 1000
SOCKET = f'ssh-keys-agent@{UID}.socket'
HELPER = f'ssh-keysd@{UID}.service'


class BootTransactionTests(unittest.TestCase):
    def transaction(self, restore_socket_defaults=False):
        self.assertTrue(SYSTEMD.is_file(), 'systemd is required for boot regression tests')
        with tempfile.TemporaryDirectory(prefix='ssh-keys-boot-test-') as directory:
            root = Path(directory)
            units = root / 'units'
            generators = root / 'empty-generators'
            units.mkdir()
            generators.mkdir()
            for name in ('ssh-keysd@.service', 'ssh-keys-agent@.socket',
                         'ssh-keys-agent@.service', 'ssh-keys-agent-failed@.service'):
                content = (ROOT / 'packaging' / name).read_text()
                # Test only unit ordering; a clean package build need not have
                # the helper installed yet. No ExecStart is executed in --test.
                content = re.sub(r'^ExecStart=.*$', 'ExecStart=/usr/bin/true',
                                 content, flags=re.MULTILINE)
                if name.endswith('.socket') and restore_socket_defaults:
                    self.assertIn('DefaultDependencies=no', content)
                    content = content.replace('DefaultDependencies=no',
                                              'DefaultDependencies=yes')
                (units / name).write_text(content)
            fixtures = {
                'ssh-keys-test.target': (
                    '[Unit]\nDefaultDependencies=no\n'
                    'Requires=multi-user.target\nAfter=multi-user.target\n'),
                'multi-user.target': (
                    '[Unit]\nRequires=basic.target\nAfter=basic.target\n'
                    f'Wants={HELPER}\n'),
                'basic.target': (
                    '[Unit]\nDefaultDependencies=no\n'
                    'Requires=sysinit.target sockets.target\n'
                    'After=sysinit.target sockets.target\n'),
                'sysinit.target': '[Unit]\nDefaultDependencies=no\n',
                'sockets.target': '[Unit]\nDefaultDependencies=no\n',
                'shutdown.target': '[Unit]\nDefaultDependencies=no\n',
                'systemd-logind.service': (
                    '[Service]\nType=oneshot\nExecStart=/usr/bin/true\n'
                    'StandardOutput=null\n'),
                'systemd-journald.socket': (
                    '[Socket]\nListenStream=/run/ssh-keys-test-journal.socket\n'),
                'systemd-journald.service': (
                    '[Service]\nExecStart=/usr/bin/true\nStandardOutput=null\n'),
            }
            for name, content in fixtures.items():
                (units / name).write_text(content)
            environment = os.environ.copy()
            environment.update({
                'LC_ALL': 'C',
                'SYSTEMD_UNIT_PATH': str(units),
                'SYSTEMD_GENERATOR_PATH': str(generators),
                'SYSTEMD_ENVIRONMENT_GENERATOR_PATH': str(generators),
                'SYSTEMD_LOG_LEVEL': 'info',
                'SYSTEMD_LOG_COLOR': '0',
                'SYSTEMD_PAGER': 'cat',
            })
            result = subprocess.run(
                [str(SYSTEMD), '--test', '--system', '--unit=ssh-keys-test.target',
                 '--no-pager'], env=environment, capture_output=True, text=True,
                timeout=20)
        self.assertEqual(result.returncode, 0, result.stderr)
        # A deleted Wants= job can still give exit status zero. Inspect both
        # the cycle diagnostic and the actual planned actions.
        actions = set(re.findall(r'Action: (\S+) -> start', result.stdout))
        return actions, result.stderr

    def test_boot_keeps_helper_and_socket_start_jobs(self):
        actions, diagnostics = self.transaction()
        self.assertNotIn('ordering cycle', diagnostics)
        self.assertNotIn('deleted to break', diagnostics)
        for unit in (HELPER, SOCKET, 'systemd-logind.service', 'basic.target', 'sockets.target',
                     'sysinit.target', 'multi-user.target'):
            self.assertIn(unit, actions, diagnostics)

    def test_default_socket_ordering_reproduces_original_boot_failure(self):
        actions, diagnostics = self.transaction(restore_socket_defaults=True)
        self.assertIn('ordering cycle', diagnostics)
        self.assertIn(f'{SOCKET}/start', diagnostics)
        self.assertIn(f'{HELPER}/start', diagnostics)
        # The planner may break the same cycle at the socket or another job
        # (e.g. logind), depending on traversal order. The regression is the
        # cycle and loss of a start job, not which particular job is removed.
        removed = re.findall(r'Job (\S+)/start deleted to break ordering cycle', diagnostics)
        self.assertTrue(removed, diagnostics)
        for unit in removed:
            self.assertNotIn(unit, actions, diagnostics)


if __name__ == '__main__':
    unittest.main()
