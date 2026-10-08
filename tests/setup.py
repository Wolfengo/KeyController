import importlib.machinery
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import call, patch

root = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('setup', str(root / 'scripts/keycontroller-setup'))
spec = importlib.util.spec_from_loader(loader.name, loader)
setup = importlib.util.module_from_spec(spec)
loader.exec_module(setup)
loader = importlib.machinery.SourceFileLoader('system_setup', str(root / 'scripts/ssh-keys-system-setup'))
spec = importlib.util.spec_from_loader(loader.name, loader)
system_setup = importlib.util.module_from_spec(spec)
loader.exec_module(system_setup)


class SetupTests(unittest.TestCase):
    def setUp(self):
        # Tests must not discover the workstation's clients or custom paths.
        self.environment = patch.dict(setup.os.environ, {'CODEX_HOME': '', 'XDG_CONFIG_HOME': ''})
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.executables = patch.object(setup.shutil, 'which', return_value=None)
        self.executables.start()
        self.addCleanup(self.executables.stop)

    def skill_fixture(self, directory):
        home, share = Path(directory) / 'home', Path(directory) / 'package'
        home.mkdir()
        skill = share / 'skills/keycontroller'
        skill.mkdir(parents=True)
        (skill / 'SKILL.md').write_text((root / 'skills/keycontroller/SKILL.md').read_text())
        return home, share, skill

    def test_agent_skill_links_installed_clients_and_tracks_package_updates(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, skill = self.skill_fixture(directory)
            parents = [home / name for name in ('.codex', '.claude', '.config/opencode', '.agents')]
            for parent in parents:
                parent.mkdir(parents=True)
            with patch.object(setup, 'SHARE', share), patch.object(setup.shutil, 'copytree', side_effect=AssertionError('instructions must link to package originals')):
                before = setup.agent_skills(home)
                self.assertEqual([entry['status'] for entry in before['clients']], ['missing'] * 4)
                self.assertFalse(any((parent / 'skills').exists() for parent in parents))
                result = setup.agent_skills(home, install=True)
                self.assertTrue(result['ready'])
                self.assertEqual([entry['status'] for entry in result['clients']], ['installed'] * 4)
                targets = [parent / 'skills/keycontroller' for parent in parents]
                original = [target.lstat() for target in targets]
                again = setup.agent_skills(home, install=True)
                self.assertEqual([entry['status'] for entry in again['clients']], ['linked'] * 4)
                for target, metadata in zip(targets, original):
                    self.assertTrue(target.is_symlink())
                    self.assertEqual(target.resolve(), skill)
                    self.assertEqual(target.lstat().st_ino, metadata.st_ino)
                    self.assertEqual(target.lstat().st_mtime_ns, metadata.st_mtime_ns)
                replacement = skill / 'SKILL.md.new'
                replacement.write_text('updated original packaged instructions\n')
                replacement.replace(skill / 'SKILL.md')
                for target in targets:
                    self.assertEqual((target / 'SKILL.md').read_text(), 'updated original packaged instructions\n')
            self.assertFalse(list(home.rglob('AGENTS.md')))
            self.assertFalse((home / '.ssh').exists())

    def test_agent_skill_detects_executables_before_first_client_run(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, _ = self.skill_fixture(directory)
            with patch.object(setup, 'SHARE', share), patch.object(setup.shutil, 'which', side_effect=lambda command: '/usr/bin/' + command if command in ('codex', 'claude', 'opencode') else None):
                result = setup.agent_skills(home, install=True)
            self.assertTrue(result['ready'])
            self.assertEqual({entry['client'] for entry in result['clients']}, {'Codex', 'Claude Code', 'OpenCode'})
            self.assertFalse((home / '.agents').exists())

    def test_agent_skill_respects_custom_codex_and_xdg_directories(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, _ = self.skill_fixture(directory)
            codex, config = home / 'custom-codex', home / 'custom-config'
            codex.mkdir()
            (config / 'opencode').mkdir(parents=True)
            with patch.object(setup, 'SHARE', share), patch.dict(setup.os.environ, {'CODEX_HOME': str(codex), 'XDG_CONFIG_HOME': str(config)}):
                result = setup.agent_skills(home, install=True)
            self.assertTrue(result['ready'])
            self.assertEqual({entry['path'] for entry in result['clients']}, {str(codex / 'skills/keycontroller'), str(config / 'opencode/skills/keycontroller')})
            self.assertFalse((home / '.codex').exists())
            self.assertFalse((home / '.config').exists())

    def test_agent_skill_preserves_existing_files_directories_and_unknown_links(self):
        for kind in ('file', 'directory', 'symlink', 'dangling'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                home, share, _ = self.skill_fixture(directory)
                target = home / '.codex/skills/keycontroller'
                target.parent.mkdir(parents=True)
                if kind == 'file':
                    target.write_text('user-owned instructions')
                elif kind == 'directory':
                    target.mkdir()
                    (target / 'SKILL.md').write_text('user-owned instructions')
                else:
                    other = home / 'other-instructions'
                    if kind == 'symlink':
                        other.mkdir()
                        (other / 'SKILL.md').write_text('user-owned instructions')
                    target.symlink_to(other, target_is_directory=True)
                before = target.lstat()
                with patch.object(setup, 'SHARE', share):
                    result = setup.agent_skills(home, install=True)
                self.assertFalse(result['ready'])
                self.assertEqual(result['clients'][0]['status'], 'conflict')
                self.assertEqual(target.lstat().st_ino, before.st_ino)
                self.assertEqual(target.lstat().st_mtime_ns, before.st_mtime_ns)
                if kind in ('directory', 'symlink'):
                    self.assertEqual((target / 'SKILL.md').read_text(), 'user-owned instructions')
                elif kind == 'file':
                    self.assertEqual(target.read_text(), 'user-owned instructions')

    def test_agent_skill_concurrent_entry_wins_and_missing_package_creates_no_links(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, skill = self.skill_fixture(directory)
            client = home / '.codex'
            client.mkdir()
            target = client / 'skills/keycontroller'
            def race(path, *args, **kwargs):
                path.write_text('concurrent user instructions')
                raise FileExistsError()
            with patch.object(setup, 'SHARE', share), patch.object(setup.Path, 'symlink_to', race):
                result = setup.agent_skills(home, install=True)
            self.assertEqual(result['clients'][0]['status'], 'conflict')
            self.assertEqual(target.read_text(), 'concurrent user instructions')
            target.unlink()
            target.parent.rmdir()
            (skill / 'SKILL.md').unlink()
            with patch.object(setup, 'SHARE', share):
                result = setup.agent_skills(home, install=True)
            self.assertFalse(result['ready'])
            self.assertEqual(result['clients'][0]['reason'], 'package_skill_missing')
            self.assertFalse(target.parent.exists())

    def test_agent_skill_only_cli_does_not_touch_desktop_ssh_or_client_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, _ = self.skill_fixture(directory)
            client = home / '.codex'
            client.mkdir()
            permissions = client / 'config.toml'
            permissions.write_text('# original client permissions\n')
            project = home / 'project'
            project.mkdir()
            instructions = project / 'AGENTS.md'
            instructions.write_text('original project instructions\n')
            output = io.StringIO()
            with patch('sys.argv', ['keycontroller-setup', '--install-agent-skills', '--json']), patch.object(setup.Path, 'home', return_value=home), patch.object(setup, 'SHARE', share), patch.object(setup.os, 'geteuid', return_value=1000), patch.object(setup, 'ssh_configs', side_effect=AssertionError('must not inspect SSH configuration')), patch.object(setup, 'require_unlocked_session', side_effect=AssertionError('skill linking does not change desktop integration')), patch.object(setup.subprocess, 'run', side_effect=AssertionError('must not run clients, services or privileged commands')), patch('sys.stdout', output):
                setup.main()
            result = json.loads(output.getvalue())
            self.assertTrue(result['ready'])
            self.assertEqual(result['clients'][0]['status'], 'installed')
            self.assertEqual(permissions.read_text(), '# original client permissions\n')
            self.assertEqual(instructions.read_text(), 'original project instructions\n')
            self.assertFalse((home / '.ssh').exists())
            self.assertFalse((home / '.config').exists())
            self.assertFalse((home / '.local').exists())

    def test_agent_skill_cli_reports_conflict_and_failed_exit_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, _ = self.skill_fixture(directory)
            target = home / '.codex/skills/keycontroller'
            target.parent.mkdir(parents=True)
            target.write_text('retain me')
            output = io.StringIO()
            with patch('sys.argv', ['keycontroller-setup', '--install-agent-skills', '--json']), patch.object(setup.Path, 'home', return_value=home), patch.object(setup, 'SHARE', share), patch.object(setup.os, 'geteuid', return_value=1000), patch('sys.stdout', output):
                with self.assertRaises(SystemExit) as stopped:
                    setup.main()
            self.assertEqual(stopped.exception.code, 1)
            self.assertEqual(json.loads(output.getvalue())['clients'][0]['status'], 'conflict')
            self.assertEqual(target.read_text(), 'retain me')

    def test_agent_skill_brand_migration_removes_only_exact_old_packaged_links(self):
        for kind in ('packaged', 'unknown_link', 'directory'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                home, share, skill = self.skill_fixture(directory)
                target = home / '.codex/skills/keycontroller'
                legacy = target.with_name('ssh-keys')
                legacy.parent.mkdir(parents=True)
                if kind == 'directory':
                    legacy.mkdir()
                    (legacy / 'SKILL.md').write_text('old custom instructions')
                else:
                    destination = setup.LEGACY_SHARE / 'skills/ssh-keys' if kind == 'packaged' else home / 'custom-old-skill'
                    legacy.symlink_to(destination, target_is_directory=True)
                with patch.object(setup, 'SHARE', share):
                    result = setup.agent_skills(home, install=True)
                self.assertTrue(result['ready'])
                self.assertEqual(target.resolve(), skill)
                if kind == 'packaged':
                    self.assertEqual(result['clients'][0]['legacy_status'], 'migrated')
                    self.assertFalse(legacy.is_symlink())
                else:
                    self.assertEqual(result['clients'][0]['legacy_status'], 'conflict_retained')
                    self.assertTrue(legacy.exists() or legacy.is_symlink())

    def test_agent_skill_brand_conflict_retains_both_existing_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, _ = self.skill_fixture(directory)
            target = home / '.codex/skills/keycontroller'
            target.parent.mkdir(parents=True)
            target.write_text('new custom instructions')
            legacy = target.with_name('ssh-keys')
            legacy.symlink_to(setup.LEGACY_SHARE / 'skills/ssh-keys', target_is_directory=True)
            with patch.object(setup, 'SHARE', share):
                result = setup.agent_skills(home, install=True)
            self.assertFalse(result['ready'])
            self.assertEqual(result['clients'][0]['status'], 'conflict')
            self.assertTrue(legacy.is_symlink())
            self.assertEqual(target.read_text(), 'new custom instructions')

    def brand_fixture(self, directory):
        home, share, source, new, _ = self.widget_fixture(directory)
        skill = share / 'skills/keycontroller'
        skill.mkdir(parents=True)
        (skill / 'SKILL.md').write_text((root / 'skills/keycontroller/SKILL.md').read_text())
        shell_path = home / '.config/omarchy/shell.json'
        shell_path.parent.mkdir(parents=True)
        shell = {'bar': {'layout': {'right': [{'id': 'omarchy.tray'}, {'id': setup.LEGACY_PLUGIN_ID, 'custom': {'value': 7}}, {'id': 'omarchy.audio'}]}},
                 'plugins': [{'id': 'io.github.sirjul1337.lock-explorer', 'design': 'card'}, {'id': setup.LEGACY_PLUGIN_ID, 'keep': ['one', 'two']}],
                 'disabledPlugins': ['omarchy.lock'], 'idle': {'lock': 300}}
        shell_path.write_text(json.dumps(shell))
        old = new.with_name(setup.LEGACY_PLUGIN_ID)
        old.parent.mkdir(parents=True)
        old.symlink_to(setup.LEGACY_SHARE / 'plugin', target_is_directory=True)
        prompt = home / '.config/hypr/hyprland.lua'
        old_include = ('dofile(' + json.dumps(str(setup.LEGACY_SHARE / 'keycontroller-hyprland.lua')) + ')').encode()
        prompt.write_bytes(prompt.read_bytes() + b'\n' + setup.PROMPT_BEGIN + b'\n' + old_include + b'\n' + setup.PROMPT_END + b'\n')
        return home, share, source, new, old, shell_path, shell, prompt

    def test_brand_migration_preserves_settings_position_and_updates_original_links(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, source, new, old, shell_path, original, prompt = self.brand_fixture(directory)
            before_shell, before_prompt = shell_path.read_bytes(), prompt.read_bytes()
            ssh = home / '.ssh/config'
            ssh.parent.mkdir()
            ssh.write_text('Host *\n IdentityAgent /run/ssh-keys/1000/agent.sock\n')
            with patch.object(setup, 'SHARE', share), patch.object(setup, 'require_unlocked_session'), patch.object(setup, 'reload_hyprland') as reload, patch.object(setup, 'ssh_configs', side_effect=AssertionError('brand migration must not inspect SSH')), patch.object(setup.subprocess, 'run', side_effect=AssertionError('brand migration must not change agents or services')):
                setup.migrate_brand(home)
                result = json.loads(shell_path.read_bytes())
                expected = json.loads(before_shell)
                expected['bar']['layout']['right'][1]['id'] = setup.PLUGIN_ID
                expected['plugins'][1]['id'] = setup.PLUGIN_ID
                self.assertEqual(result, expected)
                self.assertFalse(old.is_symlink())
                self.assertEqual(new.resolve(), source)
                self.assertNotIn(str(setup.LEGACY_SHARE).encode(), prompt.read_bytes())
                self.assertIn(str(share / 'keycontroller-hyprland.lua').encode(), prompt.read_bytes())
                self.assertEqual(ssh.read_text(), 'Host *\n IdentityAgent /run/ssh-keys/1000/agent.sock\n')
                backup = next((home / '.local/state/ssh-keys').glob('brand-*'))
                self.assertEqual((backup / 'shell.json').read_bytes(), before_shell)
                self.assertEqual((backup / '.config/hypr/hyprland.lua').read_bytes(), before_prompt)
                self.assertEqual((backup / 'shell.json').stat().st_mode & 0o777, 0o600)
                before_new, before_json, before_lua = new.lstat(), shell_path.stat(), prompt.stat()
                setup.migrate_brand(home)
                self.assertEqual(new.lstat().st_ino, before_new.st_ino)
                self.assertEqual(shell_path.stat().st_ino, before_json.st_ino)
                self.assertEqual(prompt.stat().st_ino, before_lua.st_ino)
                self.assertEqual(len(list(backup.parent.iterdir())), 1)
                reload.assert_called_once_with()

    def test_brand_migration_locked_or_changed_session_preserves_config_and_old_link(self):
        for kind in ('locked', 'concurrent_edit'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                home, share, _, new, old, shell_path, _, prompt = self.brand_fixture(directory)
                before_shell, before_prompt = shell_path.read_bytes(), prompt.read_bytes()
                def session(uid):
                    if kind == 'locked':
                        raise RuntimeError('locked')
                    shell_path.write_bytes(before_shell + b'\n')
                with patch.object(setup, 'SHARE', share), patch.object(setup, 'require_unlocked_session', side_effect=session):
                    with self.assertRaisesRegex(RuntimeError, 'locked|changed during migration'):
                        setup.migrate_brand(home)
                self.assertTrue(old.is_symlink())
                self.assertFalse(new.is_symlink())
                self.assertEqual(shell_path.read_bytes(), before_shell if kind == 'locked' else before_shell + b'\n')
                self.assertEqual(prompt.read_bytes(), before_prompt)
                self.assertFalse((home / '.local').exists())

    def test_brand_migration_handles_removed_legacy_package_with_dangling_link(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(setup, 'LEGACY_SHARE', Path(directory) / 'removed-old-package'):
                home, share, source, new, old, _, _, _ = self.brand_fixture(directory)
                self.assertTrue(old.is_symlink())
                self.assertFalse(old.exists())
                with patch.object(setup, 'SHARE', share), patch.object(setup, 'require_unlocked_session'), patch.object(setup, 'reload_hyprland'):
                    setup.migrate_brand(home)
                self.assertEqual(new.resolve(), source)
                self.assertFalse(old.is_symlink())

    def test_apply_with_old_widget_refuses_duplicate_brand_entries_before_mutating(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, _, new, old, shell_path, _, prompt = self.brand_fixture(directory)
            before_shell, before_prompt = shell_path.read_bytes(), prompt.read_bytes()
            with patch('sys.argv', ['keycontroller-setup', '--apply']), patch.object(setup.Path, 'home', return_value=home), patch.object(setup, 'SHARE', share), patch.object(setup.os, 'geteuid', return_value=1000), patch.object(setup.subprocess, 'run', side_effect=AssertionError('must migrate before any service/UI changes')):
                with self.assertRaisesRegex(RuntimeError, '--migrate-brand'):
                    setup.main()
            self.assertTrue(old.is_symlink())
            self.assertFalse(new.is_symlink())
            self.assertEqual(shell_path.read_bytes(), before_shell)
            self.assertEqual(prompt.read_bytes(), before_prompt)
            self.assertFalse((home / '.local').exists())

    def test_brand_migration_preserves_unknown_old_widget_and_conflicting_new_settings(self):
        for kind in ('old_directory', 'old_link', 'new_settings'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                home, share, _, new, old, shell_path, shell, prompt = self.brand_fixture(directory)
                if kind == 'new_settings':
                    shell['bar']['layout']['right'].append({'id': setup.PLUGIN_ID, 'custom': {'value': 8}})
                    shell_path.write_text(json.dumps(shell))
                else:
                    old.unlink()
                    if kind == 'old_directory':
                        old.mkdir()
                        (old / 'custom.txt').write_text('retain')
                    else:
                        old.symlink_to(home / 'unknown-plugin', target_is_directory=True)
                before_shell, before_prompt, before_old = shell_path.read_bytes(), prompt.read_bytes(), old.lstat()
                with patch.object(setup, 'SHARE', share), patch.object(setup, 'require_unlocked_session'):
                    with self.assertRaisesRegex(RuntimeError, 'retained for review'):
                        setup.migrate_brand(home)
                self.assertFalse(new.is_symlink())
                self.assertEqual(old.lstat().st_ino, before_old.st_ino)
                self.assertEqual(shell_path.read_bytes(), before_shell)
                self.assertEqual(prompt.read_bytes(), before_prompt)
                self.assertFalse((home / '.local').exists())

    def test_brand_shell_removes_identical_duplicates_without_moving_old_entry(self):
        old, new = setup.LEGACY_PLUGIN_ID, setup.PLUGIN_ID
        shell = {'bar': {'centerAnchor': old, 'layout': {'left': [{'id': new}], 'right': [{'id': 'tray'}, {'id': old}, {'id': 'audio'}]}},
                 'plugins': [{'id': old, 'setting': True}, {'id': new, 'setting': True}, {'id': 'omarchy.lock'}],
                 'disabledPlugins': [old, new, 'unrelated'], 'cloneSourceRestores': [old, new]}
        result = setup.brand_shell_config(shell)
        self.assertEqual(result['bar']['layout']['left'], [])
        self.assertEqual(result['bar']['layout']['right'], [{'id': 'tray'}, {'id': new}, {'id': 'audio'}])
        self.assertEqual(result['plugins'], [{'id': new, 'setting': True}, {'id': 'omarchy.lock'}])
        self.assertEqual(result['disabledPlugins'], [new, 'unrelated'])
        self.assertEqual(result['cloneSourceRestores'], [new])
        self.assertEqual(result['bar']['centerAnchor'], new)
        self.assertEqual(shell['plugins'][0]['id'], old)

    def prompt_fixture(self, home, share):
        config = home / '.config/hypr/hyprland.lua'
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_bytes(b'-- user bytes and spacing  \r\nlocal original = true')
        share.mkdir(parents=True, exist_ok=True)
        (share / 'keycontroller-hyprland.lua').write_bytes((root / 'packaging/keycontroller-hyprland.lua').read_bytes())
        return config

    def widget_fixture(self, directory):
        home = Path(directory) / 'home'
        share = Path(directory) / 'package'
        source = share / 'plugin'
        source.mkdir(parents=True)
        self.prompt_fixture(home, share)
        (source / 'manifest.json').write_text(json.dumps({'id': setup.PLUGIN_ID}))
        (source / 'Panel.qml').write_text('property int revision: 1\n')
        (source / 'icon.svg').write_text('<svg>original asset one</svg>\n')
        target = home / '.config/omarchy/plugins' / setup.PLUGIN_ID
        backup = home / '.local/state/ssh-keys/widget-backup'
        return home, share, source, target, backup

    def test_widget_package_updates_reach_live_link_without_repeated_setup(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, source, target, backup = self.widget_fixture(directory)
            with patch.object(setup, 'SHARE', share):
                self.assertEqual(setup.preflight_widget_link(home), 'missing')
                self.assertTrue(setup.link_widget(home, backup))
            self.assertTrue(target.is_symlink())
            self.assertEqual(target.resolve(), source)
            self.assertFalse(backup.exists())
            # Atomic replacement models a package manager replacing each file.
            for name, updated in [('Panel.qml', 'property int revision: 2\n'),
                                  ('icon.svg', '<svg>updated package asset two</svg>\n')]:
                replacement = source / (name + '.new')
                replacement.write_text(updated)
                replacement.replace(source / name)
                self.assertEqual((target / name).read_text(), updated)

    def test_widget_link_is_idempotent_without_creating_backup(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, source, target, backup = self.widget_fixture(directory)
            target.parent.mkdir(parents=True)
            target.symlink_to(source, target_is_directory=True)
            before = target.lstat()
            with patch.object(setup, 'SHARE', share):
                self.assertEqual(setup.preflight_widget_link(home), 'linked')
                self.assertFalse(setup.link_widget(home, backup))
            self.assertEqual(target.lstat().st_ino, before.st_ino)
            self.assertEqual(target.lstat().st_mtime_ns, before.st_mtime_ns)
            self.assertFalse(backup.exists())

    def test_widget_owned_directory_and_git_updates_are_preserved(self):
        for git_metadata in ('directory', 'file', 'absent'):
            with self.subTest(git_metadata=git_metadata), tempfile.TemporaryDirectory() as directory:
                home, share, source, target, backup = self.widget_fixture(directory)
                target.mkdir(parents=True)
                (target / 'manifest.json').write_text(json.dumps({'id': setup.PLUGIN_ID}))
                (target / 'Panel.qml').write_text('user-edited widget\n')
                if git_metadata == 'directory':
                    (target / '.git/hooks').mkdir(parents=True)
                    (target / '.git/config').write_text('[remote "origin"]\nurl = https://example.invalid/keycontroller.git\n')
                    (target / '.git/hooks/post-checkout').write_text('must not execute\n')
                elif git_metadata == 'file':
                    (target / '.git').write_text('gitdir: /external/worktree/metadata\n')
                before = {path.relative_to(target): path.read_bytes()
                          for path in target.rglob('*') if path.is_file()}
                old_inode = target.stat().st_ino
                with patch.object(setup, 'SHARE', share), \
                        patch.object(setup.shutil, 'copytree', side_effect=AssertionError('widget source must never be copied')), \
                        patch.object(setup.subprocess, 'run', side_effect=AssertionError('must not execute Git or checkout code')):
                    self.assertEqual(setup.preflight_widget_link(home), 'directory')
                    self.assertFalse(setup.link_widget(home, backup))
                self.assertFalse(target.is_symlink())
                self.assertEqual(target.stat().st_ino, old_inode)
                self.assertFalse(backup.exists())
                self.assertEqual({path.relative_to(target): path.read_bytes()
                                  for path in target.rglob('*') if path.is_file()}, before)
                # A later upstream update continues to replace the active
                # checkout files; package widget changes cannot supersede it.
                replacement = target / 'Panel.qml.new'
                replacement.write_text('updated upstream widget\n')
                replacement.replace(target / 'Panel.qml')
                (source / 'Panel.qml').write_text('different packaged widget\n')
                with patch.object(setup, 'SHARE', share):
                    self.assertFalse(setup.link_widget(home, backup))
                self.assertEqual((target / 'Panel.qml').read_text(), 'updated upstream widget\n')

    def test_widget_unknown_symlinks_files_and_foreign_manifests_are_retained(self):
        for kind in ('symlink', 'dangling', 'file', 'foreign', 'missing_manifest', 'symlink_manifest'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                home, share, _, target, backup = self.widget_fixture(directory)
                target.parent.mkdir(parents=True)
                other = Path(directory) / 'unrelated'
                if kind in ('symlink', 'dangling'):
                    if kind == 'symlink':
                        other.mkdir()
                    target.symlink_to(other, target_is_directory=True)
                elif kind == 'file':
                    target.write_text('unrelated data')
                else:
                    target.mkdir()
                    if kind == 'foreign':
                        (target / 'manifest.json').write_text(json.dumps({'id': 'unrelated.plugin'}))
                    elif kind == 'symlink_manifest':
                        other.write_text(json.dumps({'id': setup.PLUGIN_ID}))
                        (target / 'manifest.json').symlink_to(other)
                before = target.lstat()
                with patch.object(setup, 'SHARE', share):
                    with self.assertRaises(RuntimeError):
                        setup.link_widget(home, backup)
                self.assertEqual(target.lstat().st_ino, before.st_ino)
                self.assertFalse(backup.exists())

    def test_widget_link_failure_retains_concurrently_created_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, _, target, backup = self.widget_fixture(directory)
            original_symlink = setup.Path.symlink_to
            def concurrent_entry(path, *args, **kwargs):
                self.assertEqual(path, target)
                path.mkdir()
                (path / 'custom.txt').write_text('preserve concurrent entry')
                return original_symlink(path, *args, **kwargs)
            with patch.object(setup, 'SHARE', share), patch.object(setup.Path, 'symlink_to', concurrent_entry):
                with self.assertRaisesRegex(RuntimeError, 'existing files were retained'):
                    setup.link_widget(home, backup)
            self.assertFalse(target.is_symlink())
            self.assertEqual((target / 'custom.txt').read_text(), 'preserve concurrent entry')
            self.assertFalse(backup.exists())


    def test_capture_rule_scope_includes_protection_and_disables_fade_snapshot(self):
        rule = (root / 'packaging/keycontroller-hyprland.lua').read_text()
        self.assertIn('namespace = "^keycontroller-prompt$"', rule)
        self.assertIn('no_screen_share = true', rule)
        self.assertIn('no_anim = true', rule)
        self.assertEqual(rule.count('hl.layer_rule('), 1)

    def test_prompt_include_preserves_bytes_backup_and_package_updates(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory) / 'home'
            share = Path(directory) / 'package'
            config = self.prompt_fixture(home, share)
            before = config.read_bytes()
            backup = home / '.local/state/ssh-keys/capture-test'
            with patch.object(setup, 'SHARE', share):
                self.assertTrue(setup.protect_prompt(home, backup))
                after = config.read_bytes()
                self.assertTrue(after.startswith(before + b'\n'))
                self.assertEqual((backup / '.config/hypr/hyprland.lua').read_bytes(), before)
                self.assertEqual((backup / '.config/hypr/hyprland.lua').stat().st_mode & 0o777, 0o600)
                self.assertIn(('dofile(' + json.dumps(str(share / 'keycontroller-hyprland.lua')) + ')').encode(), after)
                self.assertNotIn(b'no_screen_share', after)
                original_stat = config.stat()
                self.assertFalse(setup.protect_prompt(home, backup / 'again'))
                self.assertFalse((backup / 'again').exists())
                self.assertEqual(config.stat().st_ino, original_stat.st_ino)
                self.assertEqual(config.stat().st_mtime_ns, original_stat.st_mtime_ns)
                # The include still names the package original after a package update.
                replacement = share / 'rule.new'
                replacement.write_text('-- new package revision\n')
                replacement.replace(share / 'keycontroller-hyprland.lua')
                self.assertEqual(setup.prompt_config_plan(home)[-1], after)
                self.assertEqual(config.read_bytes(), after)

    def test_prompt_malformed_managed_blocks_are_never_rewritten(self):
        malformed = [setup.PROMPT_BEGIN, setup.PROMPT_END,
                     setup.PROMPT_END + b'\n' + setup.PROMPT_BEGIN,
                     setup.PROMPT_BEGIN + b'\ncustom()\n' + setup.PROMPT_END + b'\n']
        with tempfile.TemporaryDirectory() as directory:
            home, share = Path(directory) / 'home', Path(directory) / 'package'
            config = self.prompt_fixture(home, share)
            with patch.object(setup, 'SHARE', share):
                canonical = setup.prompt_config_plan(home)[-1]
                malformed.extend([canonical + canonical, b'-- prefix ' + canonical[canonical.index(setup.PROMPT_BEGIN):]])
                for data in malformed:
                    with self.subTest(data=data):
                        config.write_bytes(data)
                        with self.assertRaisesRegex(RuntimeError, 'Malformed'):
                            setup.protect_prompt(home, home / 'backup')
                        self.assertEqual(config.read_bytes(), data)
                        self.assertFalse((home / 'backup').exists())

    def test_prompt_missing_symlinks_and_hardlinks_fail_without_mutation(self):
        for kind in ('missing', 'symlink', 'hardlink', 'directory', 'parent_symlink'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                home, share = Path(directory) / 'home', Path(directory) / 'package'
                config = self.prompt_fixture(home, share)
                before = config.read_bytes()
                other = home / 'original.lua'
                if kind == 'hardlink':
                    setup.os.link(config, other)
                elif kind == 'parent_symlink':
                    config.parent.rename(home / 'real-hypr')
                    config.parent.symlink_to(home / 'real-hypr', target_is_directory=True)
                else:
                    config.unlink()
                    if kind == 'symlink':
                        other.write_bytes(before)
                        config.symlink_to(other)
                    if kind == 'directory':
                        config.mkdir()
                with patch.object(setup, 'SHARE', share):
                    with self.assertRaises(RuntimeError):
                        setup.protect_prompt(home, home / 'backup')
                self.assertFalse((home / 'backup').exists())
                if other.exists():
                    self.assertEqual(other.read_bytes(), before)

    def test_prompt_replace_failure_and_concurrent_edit_preserve_config(self):
        for kind in ('write_failure', 'concurrent_edit'):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                home, share = Path(directory) / 'home', Path(directory) / 'package'
                config = self.prompt_fixture(home, share)
                with patch.object(setup, 'SHARE', share):
                    plan = setup.prompt_config_plan(home)
                    before = config.read_bytes()
                    if kind == 'concurrent_edit':
                        config.write_bytes(b'-- concurrent edit\n')
                        before = config.read_bytes()
                        with self.assertRaisesRegex(RuntimeError, 'changed during setup'):
                            setup.protect_prompt(home, home / 'backup', plan)
                    else:
                        with patch.object(setup.os, 'replace', side_effect=OSError('simulated failure')):
                            with self.assertRaisesRegex(RuntimeError, 'configuration was retained'):
                                setup.protect_prompt(home, home / 'backup', plan)
                    self.assertEqual(config.read_bytes(), before)
                    self.assertFalse(list(config.parent.glob('.keycontroller-capture-*')))

    def test_protect_prompt_action_is_narrow_and_reload_errors_are_visible(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share = Path(directory) / 'home', Path(directory) / 'package'
            self.prompt_fixture(home, share)
            seen = []
            def run(command, **kwargs):
                seen.append(command)
                self.assertIn(command, [['hyprctl', 'reload'], ['hyprctl', 'configerrors']])
                return SimpleNamespace(stdout='', returncode=0)
            with patch('sys.argv', ['keycontroller-setup', '--protect-prompt']), patch.object(setup.Path, 'home', return_value=home), patch.object(setup, 'SHARE', share), patch.object(setup.os, 'geteuid', return_value=1000), patch.object(setup, 'require_unlocked_session'), patch.object(setup, 'ssh_configs', side_effect=AssertionError('must not inspect SSH configuration')), patch.object(setup.subprocess, 'run', side_effect=run):
                setup.main()
            self.assertEqual(seen, [['hyprctl', 'reload'], ['hyprctl', 'configerrors']])
            self.assertFalse((home / '.ssh').exists())
            self.assertFalse((home / '.config/omarchy').exists())
            with patch.object(setup.subprocess, 'run', return_value=SimpleNamespace(stdout='error in user configuration\n')):
                with self.assertRaisesRegex(RuntimeError, 'configuration errors'):
                    setup.reload_hyprland()

    def test_check_with_prompt_rule_has_no_writes_or_runtime_queries(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share = Path(directory) / 'home', Path(directory) / 'package'
            config = self.prompt_fixture(home, share)
            before = config.read_bytes()
            with patch('sys.argv', ['keycontroller-setup', '--check']), patch.object(setup.Path, 'home', return_value=home), patch.object(setup, 'SHARE', share), patch.object(setup.os, 'geteuid', return_value=1000), patch.object(setup.subprocess, 'run', side_effect=AssertionError('read-only check must not query runtime')):
                setup.main()
            self.assertEqual(config.read_bytes(), before)
            self.assertFalse((home / '.local').exists())

    def test_include_preserves_explicit_host_context(self):
        with tempfile.TemporaryDirectory() as path:
            home = Path(path)
            (home / '.ssh').mkdir()
            (home / '.ssh/config').write_text('Host special\n IdentityAgent /custom/socket\nHost *\n Include nested.conf\n')
            (home / '.ssh/nested.conf').write_text('Host *\n IdentityAgent /run/user/%i/ssh-agent.socket\n')
            configs = setup.ssh_configs(home)
            self.assertEqual(len(configs), 2)
            entries = [e for _, _, items in configs for e in items]
            self.assertIn((1, '/custom/socket', ('host', 'special')), entries)
            self.assertIn((1, '/run/user/%i/ssh-agent.socket', ('host', '*')), entries)

    def test_check_succeeds_without_any_lock_api_or_desktop_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / '.config/omarchy/shell.json'
            config.parent.mkdir(parents=True)
            config.write_text(json.dumps({'plugins': [{'id': 'omarchy.lock'}]}))
            before = config.read_bytes()
            with patch('sys.argv', ['keycontroller-setup', '--check']), patch.object(setup.Path, 'home', return_value=home), patch.object(setup.os, 'geteuid', return_value=1000), patch.object(setup.subprocess, 'run', side_effect=AssertionError('read-only check must not invoke lock IPC or system commands')) as run:
                setup.main()
                run.assert_not_called()
            self.assertEqual(config.read_bytes(), before)
            self.assertFalse((home / '.local/state/ssh-keys').exists())
            self.assertFalse((home / '.config/omarchy/plugins').exists())

    def test_apply_works_with_stock_lock_status_and_without_hook_api(self):
        with tempfile.TemporaryDirectory() as directory:
            home, share, package, target, _ = self.widget_fixture(directory)
            config = home / '.config/omarchy/shell.json'
            config.parent.mkdir(parents=True)
            original = {'plugins': [{'id': 'omarchy.lock', 'nested': {'keep': True}}],
                        'disabledPlugins': ['io.github.sirjul1337.lock-explorer'],
                        'idle': {'lock': 300}}
            config.write_text(json.dumps(original))
            seen = []
            def run(command, **kwargs):
                seen.append(command)
                if command[:3] == ['/usr/bin/loginctl', 'show-user', str(setup.os.getuid())]:
                    return SimpleNamespace(stdout='1\n', returncode=0)
                if command[:3] == ['/usr/bin/loginctl', 'show-session', '1']:
                    return SimpleNamespace(stdout=f'User={setup.os.getuid()}\nActive=yes\nRemote=no\nType=wayland\nLockedHint=no\n', returncode=0)
                if command == ['omarchy-shell', 'lock', 'status']:
                    return SimpleNamespace(stdout=json.dumps({'locked': False, 'requested': False, 'secure': False}), returncode=0)
                if command[0] in ('pkexec', 'systemctl', 'hyprctl'):
                    return SimpleNamespace(stdout='', returncode=0)
                raise AssertionError(f'Unexpected command; no lock hook API exists: {command}')
            with patch('sys.argv', ['keycontroller-setup', '--apply']), patch.object(setup.Path, 'home', return_value=home), patch.object(setup, 'SHARE', share), patch.object(setup.os, 'geteuid', return_value=1000), patch.object(setup.subprocess, 'run', side_effect=run):
                setup.main()
            configured = json.loads(config.read_text())
            self.assertEqual(configured['plugins'], original['plugins'])
            self.assertEqual(configured['disabledPlugins'], original['disabledPlugins'])
            self.assertEqual(configured['idle'], original['idle'])
            self.assertTrue(target.is_symlink())
            self.assertEqual(target.resolve(), package)
            self.assertEqual([command for command in seen if command[0] == 'omarchy-shell'],
                             [['omarchy-shell', 'lock', 'status']] * 2)
            self.assertEqual({path.name for path in target.parent.iterdir()}, {setup.PLUGIN_ID})
            receipt = home / '.local/state/keycontroller/setup.json'
            self.assertEqual(json.loads(receipt.read_text()),
                             {'schema_version': 1, 'uid': setup.os.getuid(), 'complete': True})
            self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)

    def test_apply_preserves_checkout_position_and_settings_in_each_bar_section(self):
        for section in ('left', 'center', 'right'):
            with self.subTest(section=section), tempfile.TemporaryDirectory() as directory:
                home, share, _, target, _ = self.widget_fixture(directory)
                (target / '.git').mkdir(parents=True)
                (target / '.git/config').write_text('[remote "origin"]\nurl = https://github.com/Wolfengo/KeyController\n')
                (target / 'manifest.json').write_text(json.dumps({'id': setup.PLUGIN_ID}))
                (target / 'Panel.qml').write_text('upstream checkout widget\n')
                config = home / '.config/omarchy/shell.json'
                original = {'plugins': [{'id': setup.PLUGIN_ID, 'settings': {'retained': True}}],
                            'bar': {'layout': {name: [{'id': 'before.' + name}, {'id': 'after.' + name}]
                                               for name in ('left', 'center', 'right')}},
                            'disabledPlugins': ['unrelated.plugin']}
                original['bar']['layout'][section].insert(1, {'id': setup.PLUGIN_ID, 'width': 24, 'settings': {'custom': 'value'}})
                config.write_text(json.dumps(original))
                with patch('sys.argv', ['keycontroller-setup', '--apply']), \
                        patch.object(setup.Path, 'home', return_value=home), \
                        patch.object(setup, 'SHARE', share), \
                        patch.object(setup.os, 'geteuid', return_value=1000), \
                        patch.object(setup, 'require_unlocked_session'), \
                        patch.object(setup.subprocess, 'run', return_value=SimpleNamespace(stdout='', returncode=0)):
                    setup.main()
                self.assertEqual(json.loads(config.read_text()), original)
                self.assertFalse(target.is_symlink())
                self.assertEqual((target / 'Panel.qml').read_text(), 'upstream checkout widget\n')
                self.assertTrue((target / '.git/config').is_file())

    def test_failed_apply_keeps_incomplete_receipt_after_service_or_reload_failure(self):
        for failure in ('enable', 'reload'):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                home, share, _, _, _ = self.widget_fixture(directory)
                config = home / '.config/omarchy/shell.json'
                config.parent.mkdir(parents=True)
                config.write_text('{}')
                receipt = home / '.local/state/keycontroller/setup.json'
                receipt.parent.mkdir(parents=True)
                receipt.write_text(json.dumps({'schema_version': 1, 'uid': setup.os.getuid(), 'complete': True}))
                incomplete = {'schema_version': 1, 'uid': setup.os.getuid(), 'complete': False}
                def run(command, **kwargs):
                    self.assertEqual(json.loads(receipt.read_text()), incomplete)
                    if command[0] == 'pkexec' and failure == 'enable':
                        raise setup.subprocess.CalledProcessError(1, command)
                    return SimpleNamespace(stdout='', returncode=0)
                def reload():
                    self.assertEqual(json.loads(receipt.read_text()), incomplete)
                    raise RuntimeError('simulated reload failure')
                with patch('sys.argv', ['keycontroller-setup', '--apply']), \
                        patch.object(setup.Path, 'home', return_value=home), \
                        patch.object(setup, 'SHARE', share), \
                        patch.object(setup.os, 'geteuid', return_value=1000), \
                        patch.object(setup, 'require_unlocked_session'), \
                        patch.object(setup.subprocess, 'run', side_effect=run), \
                        patch.object(setup, 'reload_hyprland', side_effect=reload):
                    with self.assertRaises((RuntimeError, setup.subprocess.CalledProcessError)):
                        setup.main()
                self.assertEqual(json.loads(receipt.read_text()), incomplete)
                self.assertEqual(receipt.stat().st_mode & 0o777, 0o600)

    def test_managed_block_is_idempotent(self):
        text = 'Host custom\n IdentityAgent /explicit\n'
        once = setup.managed(text, 'Host *\n IdentityAgent /managed')
        self.assertEqual(setup.managed(once, 'Host *\n IdentityAgent /managed'), once)
        self.assertIn('IdentityAgent /explicit', once)

    def test_apply_without_hooks_preserves_original_explorer_provider(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            share = home / 'package'
            (share / 'plugin').mkdir(parents=True)
            (share / 'plugin/manifest.json').write_text(json.dumps({'id': setup.PLUGIN_ID}))
            self.prompt_fixture(home, share)
            config = home / '.config/omarchy/shell.json'
            config.parent.mkdir(parents=True)
            original = {'plugins': [{'id': 'io.github.sirjul1337.lock-explorer', 'design': 'card', 'nested': {'keep': True}}],
                        'disabledPlugins': ['omarchy.lock', 'unrelated.plugin'],
                        'cloneSourceRestores': ['io.github.sirjul1337.lock-explorer']}
            config.write_text(json.dumps(original))
            source = config.parent / 'plugins/io.github.sirjul1337.lock-explorer'
            (source / '.git').mkdir(parents=True)
            (source / 'Service.qml').write_text('original service fixture')
            with patch('sys.argv', ['keycontroller-setup', '--apply']), patch.object(setup.Path, 'home', return_value=home), patch.object(setup, 'SHARE', share), patch.object(setup.os, 'geteuid', return_value=1000), patch.object(setup, 'require_unlocked_session'), patch.object(setup.subprocess, 'run'):
                setup.main()
            result = json.loads(config.read_text())
            self.assertEqual(result['plugins'], original['plugins'])
            self.assertEqual(result['disabledPlugins'], original['disabledPlugins'])
            self.assertEqual(result['cloneSourceRestores'], original['cloneSourceRestores'])
            self.assertEqual((source / 'Service.qml').read_text(), 'original service fixture')
            self.assertTrue((source / '.git').is_dir())
            self.assertEqual({p.name for p in source.parent.iterdir()}, {source.name, setup.PLUGIN_ID})

    def test_shared_include_keeps_explicit_scope(self):
        with tempfile.TemporaryDirectory() as path:
            home = Path(path)
            (home / '.ssh').mkdir()
            (home / '.ssh/config').write_text('Host special\n Include nested.conf\nHost *\n Include nested.conf\n')
            (home / '.ssh/nested.conf').write_text('Host *\n IdentityAgent /run/user/%i/ssh-agent.socket\n')
            entries = [e for _, _, items in setup.ssh_configs(home) for e in items]
            self.assertEqual(len(entries), 1)
            self.assertNotEqual(entries[0][2], ('host', '*'))

    def test_lock_check_uses_shell_even_if_logind_says_unlocked(self):
        outputs = [SimpleNamespace(stdout='1\n'), SimpleNamespace(stdout='User=1000\nActive=yes\nRemote=no\nType=wayland\nLockedHint=no\n'), SimpleNamespace(stdout=json.dumps({'locked': True, 'requested': True, 'secure': True}))]
        with patch.object(setup.subprocess, 'run', side_effect=outputs):
            with self.assertRaisesRegex(RuntimeError, 'Omarchy lock'):
                setup.require_unlocked_session(1000)

    def test_apply_rechecks_lock_and_preserves_concurrent_config_changes(self):
        for race in ('locked', 'edited'):
            with self.subTest(race=race), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                share = home / 'package'
                (share / 'plugin').mkdir(parents=True)
                (share / 'plugin/manifest.json').write_text(json.dumps({'id': setup.PLUGIN_ID}))
                self.prompt_fixture(home, share)
                config = home / '.config/omarchy/shell.json'
                config.parent.mkdir(parents=True)
                before = json.dumps({'plugins': [{'id': 'omarchy.lock'}]}).encode()
                after = json.dumps({'plugins': [{'id': 'omarchy.lock', 'changed_by_user': True}]}).encode()
                config.write_bytes(before)
                def run(command, **kwargs):
                    self.assertEqual(command[0], 'pkexec')
                    if race == 'edited':
                        config.write_bytes(after)
                    return SimpleNamespace(returncode=0)
                unlocked = [None, RuntimeError('The Omarchy lock is active')] if race == 'locked' else [None, None]
                with patch('sys.argv', ['keycontroller-setup', '--apply']), patch.object(setup.Path, 'home', return_value=home), patch.object(setup, 'SHARE', share), patch.object(setup.os, 'geteuid', return_value=1000), patch.object(setup, 'require_unlocked_session', side_effect=unlocked), patch.object(setup.subprocess, 'run', side_effect=run):
                    with self.assertRaisesRegex(RuntimeError, 'Omarchy lock|configuration changed'):
                        setup.main()
                self.assertEqual(config.read_bytes(), after if race == 'edited' else before)
                self.assertFalse((home / '.config/omarchy/plugins').exists())

    def test_lock_check_refuses_logind_locked_without_querying_shell(self):
        outputs = [SimpleNamespace(stdout='1\n'), SimpleNamespace(stdout='User=1000\nActive=yes\nRemote=no\nType=wayland\nLockedHint=yes\n')]
        with patch.object(setup.subprocess, 'run', side_effect=outputs) as run:
            with self.assertRaisesRegex(RuntimeError, 'Unlock'):
                setup.require_unlocked_session(1000)
            self.assertEqual(run.call_count, 2)

    def test_lock_check_uses_repeated_loginctl_properties(self):
        outputs = [SimpleNamespace(stdout='1\n'), SimpleNamespace(stdout='User=1000\nActive=yes\nRemote=no\nType=wayland\nLockedHint=no\n'), SimpleNamespace(stdout=json.dumps({'locked': False, 'requested': False, 'secure': False, 'pending': False, 'sessionLocked': False, 'authenticating': False}))]
        with patch.object(setup.subprocess, 'run', side_effect=outputs) as run:
            setup.require_unlocked_session(1000)
            self.assertEqual(run.call_args_list[1].args[0], ['/usr/bin/loginctl', 'show-session', '1', '--property=User', '--property=Active', '--property=Remote', '--property=Type', '--property=LockedHint'])

    def test_root_setup_enables_only_the_requested_user_helper(self):
        with tempfile.TemporaryDirectory() as directory:
            user = SimpleNamespace(pw_dir=directory)
            with patch('sys.argv', ['system-setup', 'enable', '1000']), patch.object(system_setup.os, 'geteuid', return_value=0), patch.object(system_setup.pwd, 'getpwuid', return_value=user) as lookup, patch.object(system_setup.subprocess, 'run') as run:
                system_setup.main()
            lookup.assert_called_once_with(1000)
            self.assertEqual(run.call_args_list, [
                call(['/usr/bin/systemd-creds', 'setup'], check=True),
                call(['/usr/bin/systemctl', 'daemon-reload'], check=True),
                call(['/usr/bin/systemctl', 'enable', '--now', 'ssh-keysd@1000.service'], check=True),
            ])

    def test_root_setup_rejects_unprivileged_or_unknown_actions(self):
        for euid, arguments in ((1000, ['enable', '1000']), (0, []), (0, ['unknown-action', '1000']), (0, ['enable', '1000', 'extra'])):
            with self.subTest(euid=euid, arguments=arguments), patch('sys.argv', ['system-setup', *arguments]), patch.object(system_setup.os, 'geteuid', return_value=euid), patch.object(system_setup.pwd, 'getpwuid') as lookup, patch.object(system_setup.subprocess, 'run') as run:
                with self.assertRaisesRegex(SystemExit, 'usage:'):
                    system_setup.main()
                lookup.assert_not_called()
                run.assert_not_called()

    def test_root_setup_requires_canonical_desktop_uid(self):
        for uid in ('0', '999', '-1000', '+1000', '01000', ' 1000', 'desktop'):
            with self.subTest(uid=uid), patch('sys.argv', ['system-setup', 'enable', uid]), patch.object(system_setup.os, 'geteuid', return_value=0), patch.object(system_setup.pwd, 'getpwuid') as lookup, patch.object(system_setup.subprocess, 'run') as run:
                with self.assertRaisesRegex(SystemExit, 'local non-root desktop UID'):
                    system_setup.main()
                lookup.assert_not_called()
                run.assert_not_called()

    def test_root_setup_rejects_missing_user_home_before_system_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            user = SimpleNamespace(pw_dir=str(Path(directory) / 'missing'))
            with patch('sys.argv', ['system-setup', 'enable', '1000']), patch.object(system_setup.os, 'geteuid', return_value=0), patch.object(system_setup.pwd, 'getpwuid', return_value=user), patch.object(system_setup.subprocess, 'run') as run:
                with self.assertRaisesRegex(SystemExit, 'Missing user home'):
                    system_setup.main()
                run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
