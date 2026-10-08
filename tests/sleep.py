"""Synthetic sleep coordination: private files and fake manager/IPC only."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('sleep_coordinator', str(ROOT / 'scripts/ssh-keys-sleep'))
spec = importlib.util.spec_from_loader(loader.name, loader)
sleep = importlib.util.module_from_spec(spec)
loader.exec_module(sleep)


class FakeManager:
    def __init__(self, users):
        self.users = users
        self.events = []
        self.stop_error = False
        self.awake = True

    def snapshot(self):
        return ({uid for uid, row in self.users.items() if row['active']},
                {uid for uid, row in self.users.items() if row['active'] and row['helper']})

    def stop(self, users):
        self.events.append(('stop', set(users)))
        if self.stop_error:
            raise sleep.SleepError('agent_stop_unconfirmed')
        for uid in users:
            if uid in self.users:
                self.users[uid]['active'] = False
                self.users[uid]['loaded'] = False

    def start(self, users):
        self.events.append(('start', set(users)))
        for uid in users:
            self.users[uid]['active'] = True
            self.users[uid]['helper'] = True
            self.users[uid]['loaded'] = False

    def require_awake(self):
        if not self.awake:
            raise sleep.SleepError('sleep_transition_active')


def user(revoke=True, helper=True):
    return {'revoke': revoke, 'helper': helper, 'active': True, 'loaded': True, 'worker': True}


class SleepTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix='ssh-keys-sleep-test-')
        self.addCleanup(self.directory.cleanup)
        self.state = sleep.State(Path(self.directory.name) / 'state', owner=os.getuid())
        self.state.__enter__()
        self.addCleanup(self.state.__exit__)
        self.manager = FakeManager({1000: user(), 1001: user(False)})
        self.calls = []

    def ipc(self, uid, action):
        self.calls.append((uid, action))
        active = (self.state.directory / 'active').exists()
        self.assertEqual(active, action == 'sleep.prepare')
        row = self.manager.users[uid]
        self.assertTrue(row['active'])
        if action == 'sleep.prepare':
            row['worker'] = False
        return row['revoke']

    def coordinator(self, call=None):
        return sleep.Coordinator(self.state, self.manager, call or self.ipc)

    def test_precedes_sleep_fences_all_but_preserves_opt_out_then_resumes_empty(self):
        coordinator = self.coordinator()
        self.assertEqual(coordinator.prepare(), 'prepared')
        self.assertTrue((self.state.directory / 'active').exists())
        self.assertEqual(set(self.calls), {(1000, 'sleep.prepare'), (1001, 'sleep.prepare')})
        self.assertEqual(self.manager.events, [('stop', {1000})])
        self.assertFalse(self.manager.users[1000]['loaded'])
        self.assertTrue(self.manager.users[1001]['loaded'])
        self.assertFalse(any(row['worker'] for row in self.manager.users.values()))
        self.assertEqual(coordinator.resume(), 'resumed')
        self.assertIsNone(self.state.load())
        self.assertEqual(self.manager.events[-1], ('start', {1000}))
        self.assertFalse(self.manager.users[1000]['loaded'])
        self.assertTrue(self.manager.users[1001]['loaded'])
        self.assertIn((1001, 'sleep.resume'), self.calls)

    def test_unavailable_or_orphan_agent_is_stopped_without_starting_new_helpers(self):
        self.manager.users[2000] = user(helper=False)
        def unavailable(uid, action):
            raise OSError('disposable IPC failure')
        coordinator = self.coordinator(unavailable)
        coordinator.prepare()
        self.assertEqual(self.manager.events[-1], ('stop', {1000, 1001, 2000}))
        coordinator.resume()
        self.assertEqual(self.manager.events[-1], ('start', {1000, 1001}))
        self.assertFalse(self.manager.users[2000]['active'])

    def test_stop_failure_leaves_restart_intent_and_persistent_fence(self):
        self.manager.stop_error = True
        coordinator = self.coordinator()
        with self.assertRaisesRegex(sleep.SleepError, 'agent_stop_unconfirmed'):
            coordinator.prepare()
        self.assertTrue((self.state.directory / 'active').is_file())
        self.assertEqual(self.state.load()['stopped'], [1000])
        self.assertTrue(self.manager.users[1000]['loaded'])
        self.manager.stop_error = False
        self.assertEqual(coordinator.resume(recover=True), 'recovered')
        self.assertFalse(any(row['loaded'] for row in self.manager.users.values()))
        self.assertIsNone(self.state.load())

    def test_crash_after_marker_release_retains_recoverable_resume_record(self):
        coordinator = self.coordinator()
        coordinator.prepare()
        self.state.release()
        self.assertFalse((self.state.directory / 'active').exists())
        self.assertTrue((self.state.directory / 'resuming').is_file())
        # A fresh coordinator reads the old record and empties uncertain agents.
        self.coordinator().resume(recover=True)
        self.assertIsNone(self.state.load())
        self.assertEqual(self.manager.events[-1], ('start', {1000, 1001}))
        self.assertFalse(any(row['loaded'] for row in self.manager.users.values()))

    def test_recovery_refuses_active_sleep_or_pending_transition(self):
        coordinator = self.coordinator()
        coordinator.prepare()
        before = list(self.manager.events)
        self.manager.awake = False
        with self.assertRaisesRegex(sleep.SleepError, 'sleep_transition_active'):
            coordinator.resume(recover=True)
        self.assertTrue((self.state.directory / 'active').exists())
        self.assertEqual(self.manager.events, before)

    def test_failed_resume_persists_restart_intent_before_stopping_helper(self):
        coordinator = self.coordinator()
        coordinator.prepare()
        def fail_resume(uid, action):
            if action == 'sleep.resume':
                raise OSError('disposable failure')
            return self.ipc(uid, action)
        self.manager.stop_error = True
        with self.assertRaisesRegex(sleep.SleepError, 'agent_stop_unconfirmed'):
            self.coordinator(fail_resume).resume()
        self.assertFalse((self.state.directory / 'active').exists())
        self.assertEqual(self.state.load()['stopped'], [1000, 1001])
        self.manager.stop_error = False
        self.coordinator().resume(recover=True)
        self.assertEqual(self.manager.events[-1], ('start', {1000, 1001}))

    def test_incomplete_prepare_needs_verified_recovery_not_plain_resume(self):
        self.manager.stop_error = True
        with self.assertRaises(sleep.SleepError):
            self.coordinator().prepare()
        with self.assertRaisesRegex(sleep.SleepError, 'sleep_recovery_required'):
            self.coordinator().resume()
        self.assertTrue((self.state.directory / 'active').is_file())

    def test_new_prepare_does_not_replay_stale_restart_intent_for_opt_out(self):
        coordinator = self.coordinator()
        coordinator.prepare()
        self.state.release()
        # Previous resume restored the helper but died before journal cleanup.
        self.manager.start({1000})
        self.manager.users[1000]['revoke'] = False
        self.manager.users[1000]['loaded'] = True
        coordinator.prepare()
        self.assertEqual(self.state.load()['stopped'], [])
        coordinator.resume()
        self.assertTrue(self.manager.users[1000]['loaded'])

    def test_removal_stops_helpers_even_with_malformed_journal(self):
        (self.state.directory / 'active').write_text('{}')
        (self.state.directory / 'active').chmod(0o600)
        self.coordinator().remove()
        self.assertFalse(any(row['active'] for row in self.manager.users.values()))
        self.assertIsNone(self.state.load())

    def test_explicit_recovery_handles_malformed_owned_journal_safely(self):
        (self.state.directory / 'active').write_text('{}')
        (self.state.directory / 'active').chmod(0o600)
        self.coordinator().resume(recover=True)
        self.assertIsNone(self.state.load())
        self.assertEqual(self.manager.events, [('stop', {1000, 1001}), ('start', {1000, 1001})])
        self.assertFalse(any(row['loaded'] for row in self.manager.users.values()))

    def test_new_helper_after_snapshot_is_resumed_without_unplanned_restart(self):
        coordinator = self.coordinator()
        coordinator.prepare()
        # A helper started under the marker has an empty agent. Production
        # proxy marker checks are exercised by the Rust agent regressions.
        self.manager.users[2000] = user()
        self.manager.users[2000]['loaded'] = False
        self.manager.users[2000]['worker'] = False
        coordinator.resume()
        self.assertIn((2000, 'sleep.resume'), self.calls)
        self.assertNotIn((2000, 'sleep.prepare'), self.calls)
        self.assertEqual(self.manager.events[-1], ('start', {1000}))
        self.assertFalse(self.manager.users[2000]['loaded'])

    def test_stopped_unit_requires_empty_descendant_cgroup(self):
        cgroups = Path(self.directory.name) / 'cgroups'
        group = cgroups / 'disposable.scope'
        group.mkdir(parents=True)
        events = group / 'cgroup.events'
        manager = sleep.Manager(cgroup_root=cgroups)
        manager.run = lambda *args, **kwargs: ''
        rows = {name: {'ActiveState': 'failed', 'MainPID': '0', 'ControlPID': '0',
                       'ControlGroup': '/disposable.scope', 'Job': ''}
                for name in sleep.units_for(1000)}
        manager.show = lambda _: rows
        events.write_text('populated 1\nfrozen 0\n')
        with self.assertRaisesRegex(sleep.SleepError, 'agent_stop_unconfirmed'):
            manager.stop({1000})
        events.write_text('populated 0\nfrozen 0\n')
        manager.stop({1000})
        events.write_text('frozen 0\n')
        with self.assertRaisesRegex(sleep.SleepError, 'agent_stop_unconfirmed'):
            manager.stop({1000})
        events.unlink()
        group.rmdir()
        manager.stop({1000})

    def test_package_removal_stops_all_and_never_restarts(self):
        coordinator = self.coordinator()
        coordinator.prepare()
        coordinator.remove()
        self.assertIsNone(self.state.load())
        self.assertFalse(any(row['active'] for row in self.manager.users.values()))
        self.assertFalse(any(event[0] == 'start' for event in self.manager.events))

    def test_malformed_marker_or_symlink_is_never_trusted(self):
        path = self.state.directory / 'active'
        for value in ('{}', '{"version":1,"helpers":[true],"stopped":[],"prepared":false}',
                      '{"version":1,"helpers":[1000],"stopped":[1001],"prepared":false}'):
            path.write_text(value)
            path.chmod(0o600)
            with self.assertRaisesRegex(sleep.SleepError, 'invalid_sleep_state'):
                self.state.load()
        path.unlink()
        outside = Path(self.directory.name) / 'outside'
        outside.write_text('retained')
        path.symlink_to(outside)
        with self.assertRaisesRegex(sleep.SleepError, 'unsafe_sleep_state'):
            self.state.load()
        self.assertEqual(outside.read_text(), 'retained')

    def test_strict_unit_selection(self):
        for unit in ('ssh-keysd@1000.service', 'ssh-keys-agent@1000.socket'):
            self.assertEqual(sleep.uid_of(unit), 1000)
        for unit in ('ssh-keysd@0.service', 'ssh-keysd@01.service', 'ssh-keysd@4294967295.service',
                     'ssh-keysd@1000.service;false', 'unrelated@1000.service'):
            with self.assertRaises(sleep.SleepError):
                sleep.uid_of(unit)

    def test_manager_checks_pending_jobs_and_live_processes_after_stop(self):
        manager = sleep.Manager()
        calls = []
        manager.run = lambda *args, **kwargs: calls.append(args) or ''
        rows = {name: {'ActiveState': 'inactive', 'MainPID': '0', 'ControlPID': '0', 'Job': ''}
                for name in sleep.units_for(1000)}
        manager.show = lambda _: rows
        manager.stop({1000})
        for field, value in [('ActiveState', 'deactivating'), ('MainPID', '1234'), ('ControlPID', '4321'), ('Job', '123')]:
            row = rows[sleep.units_for(1000)[0]]
            prior = row[field]
            row[field] = value
            with self.assertRaisesRegex(sleep.SleepError, 'agent_stop_unconfirmed'):
                manager.stop({1000})
            row[field] = prior


if __name__ == '__main__':
    unittest.main()
