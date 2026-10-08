"""Plan the real sleep dependency graph; never start services or suspend."""
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SYSTEMD = Path('/usr/lib/systemd/systemd')
SERVICES = ('systemd-suspend.service', 'systemd-hibernate.service',
            'systemd-hybrid-sleep.service', 'systemd-suspend-then-hibernate.service')


class SleepGraphTests(unittest.TestCase):
    def transaction(self, service, linked=True):
        with tempfile.TemporaryDirectory(prefix='ssh-keys-sleep-graph-') as directory:
            directory = Path(directory)
            units = directory / 'units'
            generators = directory / 'generators'
            units.mkdir()
            generators.mkdir()
            content = (ROOT / 'packaging/ssh-keys-sleep.service').read_text()
            self.assertIn('Before=sleep.target', content)
            self.assertIn('StopWhenUnneeded=yes', content)
            self.assertIn('RemainAfterExit=yes', content)
            self.assertIn('RequiredBy=sleep.target', content)
            self.assertIn('RuntimeDirectoryPreserve=yes', content)
            content = re.sub(r'^Exec(?:Start|Stop)=.*$', 'ExecStart=/usr/bin/true', content, flags=re.MULTILINE)
            (units / 'ssh-keys-sleep.service').write_text(content)
            if linked:
                (units / 'sleep.target.requires').mkdir()
                (units / 'sleep.target.requires/ssh-keys-sleep.service').symlink_to('../ssh-keys-sleep.service')
            # Only disposable graph fixtures; no writes to live unit paths.
            for name in ('sleep.target', service):
                original = Path('/usr/lib/systemd/system', name).read_text()
                if name == service:
                    self.assertIn('Requires=sleep.target', original)
                    self.assertIn('After=sleep.target', original)
                    original = re.sub(r'^ExecStart=.*$', 'ExecStart=/usr/bin/true', original, flags=re.MULTILINE)
                (units / name).write_text(original)
            for name in ('basic.target', 'sysinit.target', 'shutdown.target'):
                (units / name).write_text('[Unit]\nDefaultDependencies=no\n')
            (units / 'test.target').write_text(f'[Unit]\nDefaultDependencies=no\nRequires={service}\nAfter={service}\n')
            environment = dict(os.environ, SYSTEMD_UNIT_PATH=str(units), SYSTEMD_GENERATOR_PATH=str(generators),
                               SYSTEMD_ENVIRONMENT_GENERATOR_PATH=str(generators), SYSTEMD_LOG_LEVEL='info',
                               SYSTEMD_LOG_COLOR='0', SYSTEMD_PAGER='cat', LC_ALL='C')
            result = subprocess.run([str(SYSTEMD), '--test', '--system', '--unit=test.target', '--no-pager'],
                                    env=environment, capture_output=True, text=True, timeout=20)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('ordering cycle', result.stderr)
            self.assertNotIn('deleted to break', result.stderr)
            actions = set(re.findall(r'Action: (\S+) -> start', result.stdout))
            self.assertTrue({'sleep.target', service} <= actions, result.stderr + result.stdout)
            return actions

    def test_each_original_sleep_path_requires_our_preparation(self):
        for service in SERVICES:
            with self.subTest(service=service):
                self.assertIn('ssh-keys-sleep.service', self.transaction(service))

    def test_missing_dependency_reproduces_unprotected_sleep_graph(self):
        for service in SERVICES:
            with self.subTest(service=service):
                self.assertNotIn('ssh-keys-sleep.service', self.transaction(service, linked=False))


if __name__ == '__main__':
    unittest.main()
