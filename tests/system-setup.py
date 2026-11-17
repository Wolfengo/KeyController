"""Activation boundary tests with NSS/system commands replaced by fixtures.

No polkit authentication, root service change or real user lookup is performed.
The production helper runs against a real temporary home directory; every child
command is intercepted. Policy assertions verify the packaged default contract,
not the behavior of site-specific polkit rules or a live logind session.
"""
from contextlib import ExitStack
import importlib.machinery
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader(
    'keycontroller_system_setup', str(ROOT / 'scripts/ssh-keys-system-setup'))
spec = importlib.util.spec_from_loader(loader.name, loader)
setup = importlib.util.module_from_spec(spec)
loader.exec_module(setup)

CHANGES = [
    ['/usr/bin/systemd-creds', 'setup'],
    ['/usr/bin/systemctl', 'daemon-reload'],
    ['/usr/bin/systemctl', 'enable', '--now', 'ssh-keysd@1000.service'],
]


class ActivationTests(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.home = Path(self.stack.enter_context(tempfile.TemporaryDirectory()))
        self.environment = {}
        self.stack.enter_context(patch.dict(setup.os.environ, self.environment, clear=True))
        self.stack.enter_context(patch.object(setup.os, 'geteuid', return_value=0))
        self.lookup = self.stack.enter_context(patch.object(
            setup.pwd, 'getpwuid', return_value=SimpleNamespace(pw_dir=str(self.home))))
        self.calls = []
        self.failure = None
        self.stack.enter_context(patch.object(setup.subprocess, 'run', side_effect=self.command))

    def command(self, args, **kwargs):
        self.calls.append((args, kwargs))
        if args == self.failure:
            raise subprocess.CalledProcessError(1, args)
        if args in CHANGES:
            return SimpleNamespace(returncode=0)
        self.fail('Unexpected system command: ' + repr(args))

    def invoke(self, *arguments):
        with patch('sys.argv', ['system-setup', *arguments]):
            setup.main()

    def test_authorized_pkexec_caller_can_enable_only_its_instance(self):
        setup.os.environ['PKEXEC_UID'] = '1000'
        self.invoke('enable', '1000')
        self.assertEqual([args for args, _ in self.calls], CHANGES)
        self.assertTrue(all(options == {'check': True} for _, options in self.calls))
        self.lookup.assert_called_once_with(1000)

    def test_explicit_root_administration_does_not_require_a_desktop_session(self):
        for origin in (None, '0'):
            with self.subTest(origin=origin):
                self.calls.clear()
                setup.os.environ.clear()
                if origin is not None:
                    setup.os.environ['PKEXEC_UID'] = origin
                self.invoke('enable', '1000')
                self.assertEqual([args for args, _ in self.calls], CHANGES)

    def test_pkexec_cannot_enable_another_users_instance(self):
        setup.os.environ['PKEXEC_UID'] = '1001'
        with self.assertRaisesRegex(SystemExit, 'calling desktop user'):
            self.invoke('enable', '1000')
        self.lookup.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_invalid_caller_identity_is_never_treated_as_direct_root(self):
        for caller in ('', '00', '+0', ' 0', '-1', '999', '01000', '+1000',
                       '4294967295', '999999999999999999999', 'desktop'):
            with self.subTest(caller=caller):
                setup.os.environ['PKEXEC_UID'] = caller
                with self.assertRaisesRegex(SystemExit, 'desktop UID'):
                    self.invoke('enable', '1000')
                self.assertEqual(self.calls, [])
                self.lookup.assert_not_called()

    def test_invalid_targets_and_arguments_never_reach_system_commands(self):
        for arguments in ([], ['enable'], ['disable', '1000'],
                          ['enable', '1000', 'extra'], ['enable', '0'],
                          ['enable', '999'], ['enable', '01000'], ['enable', '+1000'],
                          ['enable', '4294967295'], ['enable', '99999999999999999999'],
                          ['enable', '1000;id'], ['enable', '１０００']):
            with self.subTest(arguments=arguments):
                with self.assertRaises(SystemExit):
                    self.invoke(*arguments)
                self.lookup.assert_not_called()
                self.assertEqual(self.calls, [])

    def test_unprivileged_direct_execution_is_refused(self):
        with patch.object(setup.os, 'geteuid', return_value=1000):
            with self.assertRaisesRegex(SystemExit, 'usage:'):
                self.invoke('enable', '1000')
        self.lookup.assert_not_called()
        self.assertEqual(self.calls, [])

    def test_unknown_target_is_reported_without_system_changes(self):
        self.lookup.side_effect = KeyError(1000)
        with self.assertRaisesRegex(SystemExit, 'Unknown desktop user'):
            self.invoke('enable', '1000')
        self.assertEqual(self.calls, [])

    def test_home_must_be_an_existing_absolute_directory(self):
        file = self.home / 'file'
        file.write_text('fixture')
        for home in ('relative/home', str(file), str(self.home / 'missing')):
            with self.subTest(home=home):
                self.lookup.return_value = SimpleNamespace(pw_dir=home)
                with self.assertRaisesRegex(SystemExit, 'Missing user home'):
                    self.invoke('enable', '1000')
                self.assertEqual(self.calls, [])

    def test_session_environment_neither_selects_user_nor_overrides_caller_identity(self):
        setup.os.environ.update(PKEXEC_UID='1000', XDG_SESSION_ID='untrusted',
                                XDG_SESSION_TYPE='wayland', USER='other-user',
                                HOME='/another/home', SUDO_UID='1001')
        self.invoke('enable', '1000')
        self.assertEqual([args for args, _ in self.calls], CHANGES)
        self.lookup.assert_called_once_with(1000)
        self.calls.clear()
        with self.assertRaisesRegex(SystemExit, 'calling desktop user'):
            self.invoke('enable', '1001')
        self.assertEqual(self.calls, [])

    def test_command_failure_stops_the_activation_sequence(self):
        for index, command in enumerate(CHANGES):
            with self.subTest(command=command):
                self.calls.clear()
                self.failure = command
                with self.assertRaises(subprocess.CalledProcessError):
                    self.invoke('enable', '1000')
                self.assertEqual([args for args, _ in self.calls], CHANGES[:index + 1])


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = ET.parse(ROOT / 'packaging/org.omarchy.keycontroller.policy').getroot()
        self.actions = self.policy.findall('action')

    def test_only_one_named_activation_action_is_declared(self):
        self.assertEqual(self.policy.tag, 'policyconfig')
        self.assertEqual(len(self.actions), 1)
        self.assertEqual(self.actions[0].get('id'), 'org.omarchy.keycontroller.setup')
        annotations = {item.get('key'): item.text for item in self.actions[0].findall('annotate')}
        self.assertEqual(annotations, {
            'org.freedesktop.policykit.exec.path': '/usr/lib/ssh-keys/system-setup',
            'org.freedesktop.policykit.exec.argv1': 'enable',
        })

    def test_defaults_require_fresh_admin_authentication_on_active_local_sessions(self):
        defaults = self.actions[0].find('defaults')
        self.assertEqual({entry.tag: entry.text for entry in defaults}, {
            'allow_any': 'no', 'allow_inactive': 'no', 'allow_active': 'auth_admin'})

    def test_confirmation_explains_activation_in_both_supported_languages(self):
        messages = self.actions[0].findall('message')
        self.assertEqual({item.get('{http://www.w3.org/XML/1998/namespace}lang', 'en')
                          for item in messages}, {'en', 'ru'})
        self.assertTrue(all('KeyController' in item.text for item in messages))

    def test_package_installs_policy_and_runs_this_suite(self):
        recipe = (ROOT / 'packaging/PKGBUILD').read_text()
        self.assertIn('install -Dm644 packaging/org.omarchy.keycontroller.policy '
                      '"$pkgdir/usr/share/polkit-1/actions/org.omarchy.keycontroller.policy"', recipe)
        self.assertIn('python tests/system-setup.py', recipe)
        self.assertEqual((ROOT / 'scripts/ssh-keys-system-setup').read_text().splitlines()[0],
                         '#!/usr/bin/python3 -I')


if __name__ == '__main__':
    unittest.main()
