import contextlib
import fcntl
import importlib.util
import io
import json
import os
from pathlib import Path
import pty
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("dependencies", ROOT / "plugin/dependencies.py")
dependencies = importlib.util.module_from_spec(spec)
old_dont_write_bytecode = sys.dont_write_bytecode
sys.dont_write_bytecode = True
spec.loader.exec_module(dependencies)
sys.dont_write_bytecode = old_dont_write_bytecode


def result(code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


class PackageDatabase:
    def __init__(self, missing=(), packages=None):
        self.missing = set(missing)
        self.packages = packages or {}
        self.repositories = ["core", "extra", "omarchy"]
        self.signatures = {None: "PackageRequired\nPackageTrustedOnly\nDatabaseOptional\nDatabaseTrustedOnly\n"}
        self.comparison = 1
        self.calls = []

    def __call__(self, command):
        self.calls.append(command)
        if command[:2] == [dependencies.PACMAN, "-T"]:
            missing = [item for item in command[2:] if item in self.missing]
            return result(127 if missing else 0, "".join(item + "\n" for item in missing))
        if command[:2] == [dependencies.PACMAN, "-Si"]:
            name = command[2]
            if name not in self.packages:
                return result(1, stderr="error: package was not found\n")
            repository, version = self.packages[name]
            return result(stdout=f"Repository      : {repository}\nName            : {name}\nVersion         : {version}\n\n")
        if command == [dependencies.PACMAN_CONF, "--repo-list"]:
            return result(stdout="\n".join(self.repositories) + "\n")
        if command == [dependencies.PACMAN_CONF, "SigLevel"]:
            return result(stdout=self.signatures[None])
        if command[0] == dependencies.PACMAN_CONF and command[1] == "--repo":
            return result(stdout=self.signatures.get(command[2], ""))
        if command[0] == dependencies.VERCMP:
            return result(stdout=str(self.comparison) + "\n")
        if command[:2] == [dependencies.SYSTEMCTL, "is-enabled"]:
            return result(stdout="enabled\n")
        raise AssertionError("Unexpected package command: " + repr(command))


class Tty(io.StringIO):
    def isatty(self):
        return True


class DependencyTests(unittest.TestCase):
    def setUp(self):
        self.patches = [patch.object(dependencies.os, "geteuid", return_value=1000),
                        patch.object(dependencies, "system_language", return_value="en"),
                        patch.object(dependencies, "setup_receipt_complete", return_value=True),
                        patch.object(dependencies, "legacy_widget_state", return_value="absent"),
                        patch.object(dependencies, "installation_running", return_value=False)]
        for mock in self.patches:
            mock.start()
            self.addCleanup(mock.stop)

    def check(self, database):
        with patch.object(dependencies, "query", side_effect=database):
            return dependencies.check_dependencies()

    def test_ready_checks_all_versions_and_does_not_need_repository_access(self):
        database = PackageDatabase()
        status = self.check(database)
        self.assertEqual(status["state"], "ready")
        self.assertEqual(status["missing"], [])
        self.assertEqual(database.calls[0], [dependencies.PACMAN, "-T", *dependencies.REQUIREMENTS])
        self.assertEqual(len(database.calls), 3)
        self.assertFalse(status["setup_required"])

    def test_fingerprint_package_is_optional(self):
        status = self.check(PackageDatabase(missing=["fprintd"]))
        self.assertEqual(status["state"], "ready")
        self.assertEqual(status["optional"]["fprintd"], {"installed": False})
        self.assertNotIn("fprintd", dependencies.REQUIREMENTS)

    def test_missing_original_packages_keep_resolved_repository_and_version(self):
        database = PackageDatabase(["qt6-wayland", "layer-shell-qt>=6.6"],
                                   {"qt6-wayland": ("extra", "6.11.2-1"),
                                    "layer-shell-qt": ("omarchy", "6.7.4-2")})
        status = self.check(database)
        self.assertEqual(status["state"], "missing")
        self.assertFalse(status["setup_required"])
        self.assertTrue(status["installable"])
        self.assertEqual(dependencies.installation_targets(status),
                         ["extra/qt6-wayland", "omarchy/layer-shell-qt"])
        self.assertIn([dependencies.VERCMP, "6.7.4-2", "6.6"], database.calls)

    def test_unpublished_helper_does_not_invent_repository_or_download(self):
        database = PackageDatabase([dependencies.HELPER_REQUIREMENT])
        status = self.check(database)
        self.assertEqual(status["state"], "missing")
        self.assertFalse(status["installable"])
        self.assertEqual(status["missing"][0]["reason"], "repository_unavailable")
        self.assertIsNone(status["missing"][0]["repository"])
        with self.assertRaisesRegex(dependencies.DependencyError, "dependencies_not_installable"):
            dependencies.installation_targets(status)

    def test_old_repository_version_is_explicit_and_not_installable(self):
        database = PackageDatabase([dependencies.HELPER_REQUIREMENT],
                                   {"keycontroller": ("omarchy", "0.1.0-21")})
        database.comparison = -1
        status = self.check(database)
        self.assertFalse(status["installable"])
        self.assertEqual(status["missing"][0]["reason"], "repository_version_too_old")

    def test_signature_requirement_honors_repository_override(self):
        for policy in ("PackageOptional", "PackageNever", "PackageTrustAll"):
            with self.subTest(policy=policy):
                database = PackageDatabase(["qt6-svg"], {"qt6-svg": ("extra", "6.11.2-1")})
                database.signatures["extra"] = policy
                status = self.check(database)
                self.assertFalse(status["installable"])
                self.assertEqual(status["state"], "error")
                self.assertEqual(status["error_code"], "repository_signatures_disabled")

    def test_unsigned_global_policy_can_be_tightened_by_repository(self):
        database = PackageDatabase(["qt6-svg"], {"qt6-svg": ("extra", "6.11.2-1")})
        database.signatures[None] = "PackageOptional PackageTrustedOnly DatabaseOptional"
        for repo in database.repositories:
            database.signatures[repo] = "PackageRequired"
        self.assertTrue(self.check(database)["installable"])

    def test_signed_third_party_repo_blocks_installation_and_transitive_resolution(self):
        database = PackageDatabase(["qt6-svg"], {"qt6-svg": ("extra", "6.11.2-1")})
        database.repositories.append("custom-signed")
        status = self.check(database)
        self.assertEqual(status["state"], "error")
        self.assertEqual(status["error_code"], "unsupported_repositories")
        self.assertFalse(status["installable"])

    def test_unsigned_other_official_repo_blocks_transitive_resolution(self):
        database = PackageDatabase(["qt6-svg"], {"qt6-svg": ("extra", "6.11.2-1")})
        database.signatures["omarchy"] = "PackageOptional"
        status = self.check(database)
        self.assertEqual(status["error_code"], "repository_signatures_disabled")
        self.assertFalse(status["installable"])

    def test_installed_dependencies_allow_setup_without_repository_policy(self):
        database = PackageDatabase()
        database.repositories.append("custom-signed")
        database.signatures["omarchy"] = "PackageNever"
        status = self.check(database)
        self.assertEqual(status["state"], "ready")
        self.assertFalse(any(call[0] == dependencies.PACMAN_CONF for call in database.calls))

    def test_repository_metadata_cannot_inject_targets_or_terminal_escapes(self):
        for repository, version in [("extra;evil", "1"), ("foreign", "1"),
                                    ("extra", "1\x1b[0m"), ("extra", "--config=/tmp/evil")]:
            with self.subTest(repository=repository, version=version):
                status = self.check(PackageDatabase(["qt6-svg"], {"qt6-svg": (repository, version)}))
                self.assertEqual(status["state"], "error")
                self.assertEqual(status["error_code"], "package_metadata_invalid")

    def test_malformed_or_unexpected_pacman_output_is_not_echoed(self):
        for code, output in [(0, "qt6-svg\n"), (127, ""), (127, "evil\n"),
                             (127, "qt6-svg\nqt6-svg\n"), (1, "test-secret\n")]:
            with self.subTest(code=code, output=output):
                with patch.object(dependencies, "query", return_value=result(code, output, "test-secret")):
                    status = dependencies.check_dependencies()
                self.assertEqual(status["state"], "error")
                self.assertNotIn("test-secret", json.dumps(status))

    def test_query_timeout_returns_stable_error(self):
        with patch.object(dependencies.subprocess, "run", side_effect=subprocess.TimeoutExpired(["test-secret"], 8)):
            status = dependencies.check_dependencies()
        self.assertEqual(status["error_code"], "package_check_timeout")
        self.assertNotIn("test-secret", json.dumps(status))

    def test_query_uses_absolute_binary_sanitized_environment_and_no_shell(self):
        with patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            dependencies.query([dependencies.PACMAN, "-T", "python"])
        arguments, options = run.call_args
        self.assertEqual(arguments[0][0], "/usr/bin/pacman")
        self.assertEqual(options["env"], {"PATH": "/usr/bin", "LANG": "C", "LC_ALL": "C"})
        self.assertTrue(options["close_fds"])
        self.assertEqual(options["timeout"], 8)
        self.assertNotIn("shell", options)

    def test_root_check_never_touches_package_manager(self):
        with patch.object(dependencies.os, "geteuid", return_value=0), patch.object(dependencies, "query") as query:
            status = dependencies.check_dependencies()
        self.assertEqual(status["error_code"], "root_not_allowed")
        query.assert_not_called()

    def test_install_targets_reject_forged_requirements_and_repository_operands(self):
        base = {"name": "qt6-svg", "requirement": "qt6-svg", "available": True, "repository": "extra"}
        for updates in [{"name": "-y"}, {"requirement": "evil"}, {"repository": "-y"},
                        {"repository": "extra;evil"}, {"repository": "custom-signed"}, {"available": False}]:
            with self.subTest(updates=updates):
                item = dict(base, **updates)
                with self.assertRaises(dependencies.DependencyError):
                    dependencies.installation_targets({"state": "missing", "installable": True, "missing": [item]})

    def test_cli_rejects_package_operands_json_install_and_unknown_modes(self):
        for arguments in [["--install", "evil"], ["--install", "--json"],
                          ["--check", "--install"], ["--check", "--repo", "evil"],
                          ["--setup", "evil"], ["--setup", "--install"], ["--setup", "--json"],
                          ["--wizard", "evil"], ["--wizard", "--json"], ["--wizard", "--install"],
                          ["--wizard", "--setup"]]:
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    dependencies.main(arguments)

    def test_system_language_does_not_evaluate_shell_or_match_language_prefixes(self):
        cases = [("LANG=ru_RU.UTF-8\n", "ru"),
                 ('LANG="ru-RU" # system\n', "ru"),
                 ("LANG=en_US.UTF-8\nLC_MESSAGES='ru_RU.UTF-8'\n", "ru"),
                 ("LANG=ru\nLC_MESSAGES=C.UTF-8\n", "en"),
                 ("LANG=$(printf ru)\n", "en"),
                 ("LANG=russian\n", "en"),
                 ("LANG=ru\ninvalid line\n", "en")]
        for source, expected in cases:
            with self.subTest(source=source):
                self.assertEqual(dependencies.parse_language(source), expected)


class LockTests(unittest.TestCase):
    def test_real_flock_reports_busy_and_releases_after_checker(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "lock"
            with patch.object(dependencies, "lock_path", return_value=path):
                self.assertFalse(dependencies.installation_running())
                self.assertFalse(path.exists())
                with dependencies.installation_lock():
                    self.assertTrue(dependencies.installation_running())
                    with self.assertRaisesRegex(dependencies.DependencyError, "installation_busy"):
                        with dependencies.installation_lock():
                            pass
                self.assertFalse(dependencies.installation_running())
                with dependencies.installation_lock():
                    pass

    def test_lock_refuses_symlinks_hardlinks_and_open_permissions(self):
        for kind in ("symlink", "hardlink", "public"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / "lock"
                other = Path(directory) / "other"
                other.write_text("unchanged")
                other.chmod(0o600)
                if kind == "symlink":
                    path.symlink_to(other)
                elif kind == "hardlink":
                    os.link(other, path)
                else:
                    path.write_text("")
                    path.chmod(0o644)
                with patch.object(dependencies, "lock_path", return_value=path):
                    with self.assertRaisesRegex(dependencies.DependencyError, "install_lock_unavailable"):
                        with dependencies.installation_lock():
                            self.fail("Unsafe lock must never be acquired")
                self.assertEqual(other.read_text(), "unchanged")


class SetupStatusTests(unittest.TestCase):
    def test_enabled_helper_is_ready_but_disabled_missing_and_runtime_need_setup(self):
        for state, code, expected in [("enabled", 0, False), ("disabled", 1, True),
                                       ("not-found", 4, True), ("enabled-runtime", 0, True)]:
            with self.subTest(state=state), \
                    patch.object(dependencies, "query", return_value=result(code, state + "\n")) as query, \
                    patch.object(dependencies, "setup_receipt_complete", return_value=True), \
                    patch.object(dependencies, "legacy_widget_state", return_value="absent"):
                status = dependencies.setup_status()
            self.assertEqual(status, {"setup_required": expected, "migration_required": False})
            self.assertEqual(query.call_args.args[0], ["/usr/bin/systemctl", "is-enabled", f"ssh-keysd@{os.getuid()}.service"])

    def test_enabled_helper_after_partial_setup_still_requires_setup(self):
        with patch.object(dependencies, "query", return_value=result(stdout="enabled\n")), \
                patch.object(dependencies, "setup_receipt_complete", return_value=False), \
                patch.object(dependencies, "legacy_widget_state", return_value="absent"):
            self.assertTrue(dependencies.setup_status()["setup_required"])

    def test_receipt_requires_completed_current_user_and_supported_schema(self):
        valid = {"schema_version": 1, "uid": os.getuid(), "complete": True}
        cases = [(valid, True), (dict(valid, complete=False), False),
                 (dict(valid, complete=1), False), (dict(valid, uid=os.getuid() + 1), False),
                 (dict(valid, schema_version=True), False), (dict(valid, extra=True), False),
                 ({}, False), ([], False)]
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(dependencies.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=directory)):
            path = Path(directory) / ".local/state/keycontroller/setup.json"
            self.assertFalse(dependencies.setup_receipt_complete())
            path.parent.mkdir(parents=True)
            for payload, expected in cases:
                with self.subTest(payload=payload):
                    path.write_text(json.dumps(payload))
                    path.chmod(0o600)
                    self.assertEqual(dependencies.setup_receipt_complete(), expected)
            for data in (b"{invalid", b"\xff", b" " * 4097):
                path.write_bytes(data)
                self.assertFalse(dependencies.setup_receipt_complete())

    def test_receipt_rejects_links_nonregular_files_and_public_permissions(self):
        for kind in ("symlink", "hardlink", "fifo", "public"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory, \
                    patch.object(dependencies.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=directory)):
                path = Path(directory) / ".local/state/keycontroller/setup.json"
                path.parent.mkdir(parents=True)
                other = Path(directory) / "other"
                payload = json.dumps({"schema_version": 1, "uid": os.getuid(), "complete": True})
                other.write_text(payload)
                other.chmod(0o600)
                if kind == "symlink":
                    path.symlink_to(other)
                elif kind == "hardlink":
                    os.link(other, path)
                elif kind == "fifo":
                    os.mkfifo(path, 0o600)
                else:
                    path.write_text(payload)
                    path.chmod(0o644)
                self.assertFalse(dependencies.setup_receipt_complete())
                self.assertEqual(other.read_text(), payload)

    def test_systemd_failures_and_masked_units_are_not_guessed_as_initial_setup(self):
        for state, code in [("", 1), ("masked", 1), ("static", 0), ("enabled", 1), ("test-secret", 0)]:
            with self.subTest(state=state), patch.object(dependencies, "query", return_value=result(code, state)):
                with self.assertRaisesRegex(dependencies.DependencyError, "setup_status_unavailable"):
                    dependencies.setup_status()

    def test_exact_managed_legacy_link_needs_migration_even_for_enabled_helper(self):
        with patch.object(dependencies, "query", return_value=result(stdout="enabled\n")), \
                patch.object(dependencies, "legacy_widget_state", return_value="managed"):
            self.assertEqual(dependencies.setup_status(), {"setup_required": True, "migration_required": True})

    def test_legacy_detection_recognizes_only_exact_packaged_symlink_and_retains_others(self):
        for kind, expected in [("absent", "absent"), ("packaged", "managed"),
                               ("foreign", "conflict"), ("directory", "conflict"), ("file", "conflict")]:
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / ".config/omarchy/plugins" / dependencies.LEGACY_PLUGIN_ID
                path.parent.mkdir(parents=True)
                if kind == "packaged":
                    path.symlink_to(dependencies.LEGACY_PLUGIN_TARGET)
                elif kind == "foreign":
                    path.symlink_to("/tmp/unrelated-plugin")
                elif kind == "directory":
                    path.mkdir()
                elif kind == "file":
                    path.write_text("preserve")
                with patch.object(dependencies.pwd, "getpwuid", return_value=SimpleNamespace(pw_dir=directory)):
                    self.assertEqual(dependencies.legacy_widget_state(), expected)
                self.assertEqual(path.exists() or path.is_symlink(), kind != "absent")


class InstallationTests(unittest.TestCase):
    def setUp(self):
        self.terminal = Tty()
        self.patches = [patch.object(dependencies.os, "geteuid", return_value=1000),
                        patch.object(dependencies, "system_language", return_value="en"),
                        patch.object(dependencies, "installation_lock", side_effect=lambda: contextlib.nullcontext()),
                        patch.object(dependencies.sys, "stdin", Tty("\n")),
                        patch.object(dependencies.sys, "stdout", self.terminal),
                        patch.object(dependencies.sys, "stderr", self.terminal)]
        for mock in self.patches:
            mock.start()
            self.addCleanup(mock.stop)
        self.ready = {"state": "ready", "setup_required": False, "migration_required": False}
        self.missing = {"state": "missing", "installable": True,
                        "missing": [{"name": "qt6-svg", "requirement": "qt6-svg", "repository": "extra",
                                     "available": True, "reason": None}]}

    def test_install_rechecks_then_verifies_and_links_agent_skills_without_apply(self):
        with patch.object(dependencies, "check_dependencies", side_effect=[self.missing, self.ready]) as check, \
                patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            self.assertEqual(dependencies.install_dependencies(), 0)
        self.assertEqual(check.call_count, 2)
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            ["/usr/bin/sudo", "/usr/bin/pacman", "-S", "--needed", "--", "extra/qt6-svg"],
            ["/usr/bin/keycontroller-setup", "--install-agent-skills"]])
        for call in run.call_args_list:
            self.assertNotIn("shell", call.kwargs)
            self.assertNotIn("--noconfirm", call.args[0])
            self.assertNotIn("--apply", call.args[0])

    def test_another_install_already_finished_skips_package_transaction(self):
        with patch.object(dependencies, "check_dependencies", return_value=self.ready), \
                patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            self.assertEqual(dependencies.install_dependencies(), 0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], [dependencies.SETUP, "--install-agent-skills"])

    def test_custom_agent_config_paths_reach_only_unprivileged_skill_linker(self):
        paths = {"CODEX_HOME": "/tmp/custom codex", "XDG_CONFIG_HOME": "/tmp/custom config"}
        with patch.dict(dependencies.os.environ, paths), \
                patch.object(dependencies, "check_dependencies", side_effect=[self.missing, self.ready]), \
                patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            self.assertEqual(dependencies.install_dependencies(), 0)
        package_call, setup_call = run.call_args_list
        self.assertEqual(package_call.args[0][0], dependencies.SUDO)
        self.assertEqual(setup_call.args[0][0], dependencies.SETUP)
        for variable, expected in paths.items():
            self.assertNotIn(variable, package_call.kwargs["env"])
            self.assertEqual(setup_call.kwargs["env"][variable], expected)

    def test_empty_custom_agent_paths_do_not_override_linker_defaults(self):
        with patch.dict(dependencies.os.environ, {"CODEX_HOME": "", "XDG_CONFIG_HOME": ""}), \
                patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            dependencies.link_agent_skills("en")
        self.assertNotIn("CODEX_HOME", run.call_args.kwargs["env"])
        self.assertNotIn("XDG_CONFIG_HOME", run.call_args.kwargs["env"])

    def test_failed_transaction_does_not_claim_success_or_run_setup(self):
        with patch.object(dependencies, "check_dependencies", return_value=self.missing), \
                patch.object(dependencies.subprocess, "run", return_value=result(1)) as run:
            self.assertEqual(dependencies.install_dependencies(), 1)
        self.assertEqual(run.call_count, 1)
        self.assertIn("package_install_failed", self.terminal.getvalue())

    def test_successful_pacman_exit_with_missing_requirements_is_a_failure(self):
        with patch.object(dependencies, "check_dependencies", return_value=self.missing), \
                patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            self.assertEqual(dependencies.install_dependencies(), 1)
        self.assertEqual(run.call_count, 1)
        self.assertIn("dependencies_still_missing", self.terminal.getvalue())

    def test_missing_repository_blocks_sudo(self):
        self.missing["installable"] = False
        self.missing["missing"][0].update(available=False, reason="repository_unavailable", repository=None)
        with patch.object(dependencies, "check_dependencies", return_value=self.missing), \
                patch.object(dependencies.subprocess, "run") as run:
            self.assertEqual(dependencies.install_dependencies(), 1)
        run.assert_not_called()

    def test_install_requires_visible_terminal_and_never_runs_as_root(self):
        for root, tty in [(False, False), (True, True)]:
            with self.subTest(root=root, tty=tty), \
                    patch.object(dependencies.os, "geteuid", return_value=0 if root else 1000), \
                    patch.object(dependencies.sys, "stdin", Tty("\n") if tty else io.StringIO()), \
                    patch.object(dependencies.subprocess, "run") as run:
                self.assertEqual(dependencies.install_dependencies(), 1)
            run.assert_not_called()

    def test_link_failure_is_reported_separately_after_installed_packages(self):
        with patch.object(dependencies, "check_dependencies", return_value=self.ready), \
                patch.object(dependencies.subprocess, "run", return_value=result(1)):
            self.assertEqual(dependencies.install_dependencies(), 1)
        self.assertIn("agent_skills_failed", self.terminal.getvalue())

    def test_package_install_does_not_implicitly_apply_initial_configuration(self):
        setup_required = dict(self.ready, setup_required=True)
        with patch.object(dependencies, "check_dependencies", side_effect=[self.missing, setup_required]), \
                patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            self.assertEqual(dependencies.install_dependencies(), 0)
        self.assertEqual(run.call_count, 2)
        self.assertEqual(run.call_args.args[0], [dependencies.SETUP, "--install-agent-skills"])

    def test_explicit_setup_applies_initial_configuration_and_preserves_graphical_session(self):
        setup_required = dict(self.ready, setup_required=True)
        session = {"XDG_RUNTIME_DIR": "/run/user/1000", "WAYLAND_DISPLAY": "wayland-1",
                   "HYPRLAND_INSTANCE_SIGNATURE": "example-instance", "DBUS_SESSION_BUS_ADDRESS": "unix:path=/run/user/1000/bus"}
        with patch.dict(dependencies.os.environ, session), \
                patch.object(dependencies, "check_dependencies", side_effect=[setup_required, self.ready]) as check, \
                patch.object(dependencies, "legacy_widget_state", return_value="absent"), \
                patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            self.assertEqual(dependencies.configure_integration(), 0)
        self.assertEqual(check.call_count, 2)
        self.assertEqual(run.call_args.args[0], [dependencies.SETUP, "--apply"])
        for variable, expected in session.items():
            self.assertEqual(run.call_args.kwargs["env"][variable], expected)

    def test_explicit_setup_uses_migration_without_apply_over_existing_integration(self):
        migration_required = dict(self.ready, setup_required=True, migration_required=True)
        with patch.object(dependencies, "check_dependencies", side_effect=[migration_required, self.ready]), \
                patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            self.assertEqual(dependencies.configure_integration(), 0)
        self.assertEqual(run.call_count, 1)
        self.assertEqual(run.call_args.args[0], [dependencies.SETUP, "--migrate-brand"])

    def test_explicit_setup_refuses_unknown_legacy_widget_without_apply(self):
        setup_required = dict(self.ready, setup_required=True)
        with patch.object(dependencies, "check_dependencies", return_value=setup_required), \
                patch.object(dependencies, "legacy_widget_state", return_value="conflict"), \
                patch.object(dependencies.subprocess, "run") as run:
            self.assertEqual(dependencies.configure_integration(), 1)
        run.assert_not_called()
        self.assertIn("legacy_widget_conflict", self.terminal.getvalue())

    def test_setup_is_idempotent_and_rejects_missing_dependencies(self):
        for status, expected in [(self.ready, 0), (self.missing, 1)]:
            with self.subTest(status=status), \
                    patch.object(dependencies, "check_dependencies", return_value=status), \
                    patch.object(dependencies.subprocess, "run") as run:
                self.assertEqual(dependencies.configure_integration(), expected)
            run.assert_not_called()

    def test_setup_verification_does_not_claim_success_for_disabled_service(self):
        setup_required = dict(self.ready, setup_required=True)
        with patch.object(dependencies, "check_dependencies", return_value=setup_required), \
                patch.object(dependencies, "legacy_widget_state", return_value="absent"), \
                patch.object(dependencies.subprocess, "run", return_value=result()):
            self.assertEqual(dependencies.configure_integration(), 1)
        self.assertIn("setup_incomplete", self.terminal.getvalue())


class WizardTests(unittest.TestCase):
    setUp = InstallationTests.setUp

    def test_one_lock_covers_packages_verification_setup_and_final_verification(self):
        events = []
        locked = False
        @contextlib.contextmanager
        def lock():
            nonlocal locked
            self.assertFalse(locked)
            locked = True
            events.append("lock")
            yield
            events.append("release")
            locked = False
        statuses = iter([self.missing, dict(self.ready, setup_required=True), self.ready, self.ready])
        def check(**kwargs):
            self.assertTrue(locked)
            self.assertEqual(kwargs, {"include_installing": False})
            events.append("check")
            return next(statuses)
        def run(command, **kwargs):
            self.assertTrue(locked)
            self.assertTrue(kwargs["close_fds"])
            self.assertNotIn("shell", kwargs)
            events.append("install" if command[0] == dependencies.SUDO else
                          "skills" if command[1] == "--install-agent-skills" else "setup")
            return result()
        with patch.object(dependencies, "installation_lock", side_effect=lock), \
                patch.object(dependencies, "check_dependencies", side_effect=check), \
                patch.object(dependencies, "legacy_widget_state", return_value="absent"), \
                patch.object(dependencies.subprocess, "run", side_effect=run) as calls:
            self.assertEqual(dependencies.setup_wizard(), 0)
        self.assertEqual(events, ["lock", "check", "install", "check", "setup", "check", "skills", "check", "release"])
        self.assertEqual([call.args[0] for call in calls.call_args_list], [
            [dependencies.SUDO, dependencies.PACMAN, "-S", "--needed", "--", "extra/qt6-svg"],
            [dependencies.SETUP, "--apply"], [dependencies.SETUP, "--install-agent-skills"]])
        output = self.terminal.getvalue()
        self.assertLess(output.index("primary SSH agent"), output.index("1/3"))
        self.assertLess(output.index("1/3"), output.index("2/3"))
        self.assertLess(output.index("2/3"), output.index("3/3"))
        self.assertIn("Log out and log back in", output)
        self.assertIn("Press Enter", output)

    def test_cli_dispatches_only_literal_wizard_mode(self):
        with patch.object(dependencies, "setup_wizard", return_value=0) as wizard:
            self.assertEqual(dependencies.main(["--wizard"]), 0)
        wizard.assert_called_once_with()

    def test_all_installed_but_unconfigured_goes_directly_to_setup(self):
        with patch.object(dependencies, "check_dependencies", side_effect=[
                    dict(self.ready, setup_required=True), self.ready, self.ready]), \
                patch.object(dependencies, "legacy_widget_state", return_value="absent"), \
                patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            self.assertEqual(dependencies.setup_wizard(), 0)
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            [dependencies.SETUP, "--apply"], [dependencies.SETUP, "--install-agent-skills"]])

    def test_completed_setup_only_refreshes_agent_instructions(self):
        with patch.object(dependencies, "check_dependencies", return_value=self.ready), \
                patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            self.assertEqual(dependencies.setup_wizard(), 0)
        self.assertEqual([call.args[0] for call in run.call_args_list], [[dependencies.SETUP, "--install-agent-skills"]])

    def test_unpublished_helper_blocks_all_side_effects(self):
        self.missing["installable"] = False
        self.missing["missing"][0].update(name="keycontroller", requirement=dependencies.HELPER_REQUIREMENT,
                                         available=False, repository=None, reason="repository_unavailable")
        with patch.object(dependencies, "check_dependencies", return_value=self.missing), \
                patch.object(dependencies.subprocess, "run") as run:
            self.assertEqual(dependencies.setup_wizard(), 1)
        run.assert_not_called()
        self.assertIn("Wait for publication", self.terminal.getvalue())
        self.assertNotIn("KeyController is ready.", self.terminal.getvalue())

    def test_repository_policy_blocks_wizard_and_legacy_install_before_any_child(self):
        for action in (dependencies.setup_wizard, dependencies.install_dependencies):
            for reason in ("unsupported_repositories", "repository_signatures_disabled"):
                database = PackageDatabase(["qt6-svg"], {"qt6-svg": ("extra", "6.11.2-1")})
                if reason == "unsupported_repositories":
                    database.repositories.append("custom-signed")
                else:
                    database.signatures["omarchy"] = "PackageOptional"
                with self.subTest(action=action.__name__, reason=reason), \
                        patch.object(dependencies, "query", side_effect=database), \
                        patch.object(dependencies.subprocess, "run") as run:
                    self.assertEqual(action(), 1)
                run.assert_not_called()
        self.assertNotIn("KeyController is ready.", self.terminal.getvalue())

    def test_cancelled_failed_or_interrupted_install_never_configures(self):
        for outcome in (result(1), result(130), OSError("no process"), KeyboardInterrupt()):
            with self.subTest(outcome=outcome), \
                    patch.object(dependencies, "check_dependencies", return_value=self.missing) as check, \
                    patch.object(dependencies.subprocess, "run", side_effect=[outcome]) as run:
                self.assertEqual(dependencies.setup_wizard(), 1)
                self.assertEqual(check.call_count, 1)
                self.assertEqual(run.call_count, 1)
                self.assertEqual(run.call_args.args[0][0], dependencies.SUDO)
        self.assertNotIn("KeyController is ready.", self.terminal.getvalue())

    def test_package_exit_zero_without_verified_install_does_not_setup(self):
        with patch.object(dependencies, "check_dependencies", return_value=self.missing), \
                patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            self.assertEqual(dependencies.setup_wizard(), 1)
        self.assertEqual(run.call_count, 1)
        self.assertIn("dependencies_still_missing", self.terminal.getvalue())

    def test_failed_native_setup_is_not_retried_or_reported_ready(self):
        for outcome in (result(1), result(130), OSError("no process"), KeyboardInterrupt()):
            with self.subTest(outcome=outcome), \
                    patch.object(dependencies, "check_dependencies", return_value=dict(self.ready, setup_required=True)), \
                    patch.object(dependencies, "legacy_widget_state", return_value="absent"), \
                    patch.object(dependencies.subprocess, "run", side_effect=[outcome]) as run:
                self.assertEqual(dependencies.setup_wizard(), 1)
                self.assertEqual(run.call_count, 1)
        self.assertNotIn("KeyController is ready.", self.terminal.getvalue())

    def test_zero_setup_exit_requires_complete_receipt_and_enablement(self):
        for status in [dict(self.ready, setup_required=True), dict(self.ready, migration_required=True), self.missing]:
            with self.subTest(status=status), \
                    patch.object(dependencies, "check_dependencies", side_effect=[dict(self.ready, setup_required=True), status]), \
                    patch.object(dependencies, "legacy_widget_state", return_value="absent"), \
                    patch.object(dependencies.subprocess, "run", return_value=result()):
                self.assertEqual(dependencies.setup_wizard(), 1)
        self.assertNotIn("KeyController is ready.", self.terminal.getvalue())

    def test_incomplete_agent_instructions_after_apply_are_reported_before_success(self):
        with patch.object(dependencies, "check_dependencies", side_effect=[
                    dict(self.ready, setup_required=True), self.ready]), \
                patch.object(dependencies, "legacy_widget_state", return_value="absent"), \
                patch.object(dependencies.subprocess, "run", side_effect=[result(), result(1)]) as run:
            self.assertEqual(dependencies.setup_wizard(), 1)
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            [dependencies.SETUP, "--apply"], [dependencies.SETUP, "--install-agent-skills"]])
        self.assertIn("agent_skills_failed", self.terminal.getvalue())
        self.assertNotIn("KeyController is ready.", self.terminal.getvalue())

    def test_duplicate_wizard_stops_before_metadata_or_any_child(self):
        with patch.object(dependencies, "installation_lock", side_effect=dependencies.DependencyError("installation_busy")), \
                patch.object(dependencies, "check_dependencies") as check, \
                patch.object(dependencies.subprocess, "run") as run:
            self.assertEqual(dependencies.setup_wizard(), 1)
        check.assert_not_called()
        run.assert_not_called()
        self.assertIn("installation_busy", self.terminal.getvalue())

    def test_wizard_never_runs_as_root_or_without_a_visible_terminal(self):
        for root, tty in [(True, True), (False, False)]:
            with self.subTest(root=root, tty=tty), \
                    patch.object(dependencies.os, "geteuid", return_value=0 if root else 1000), \
                    patch.object(dependencies.sys, "stdin", Tty("\n") if tty else io.StringIO()), \
                    patch.object(dependencies, "check_dependencies") as check, \
                    patch.object(dependencies.subprocess, "run") as run:
                self.assertEqual(dependencies.setup_wizard(), 1)
            check.assert_not_called()
            run.assert_not_called()

    def test_migration_only_does_not_repeat_completed_initial_setup(self):
        for setup_required in (True, False):
            with self.subTest(setup_required=setup_required), \
                    patch.object(dependencies, "check_dependencies", side_effect=[
                        dict(self.ready, setup_required=setup_required, migration_required=True), self.ready, self.ready]), \
                    patch.object(dependencies.subprocess, "run", return_value=result()) as run:
                self.assertEqual(dependencies.setup_wizard(), 0)
            self.assertEqual([call.args[0] for call in run.call_args_list], [
                [dependencies.SETUP, "--migrate-brand"], [dependencies.SETUP, "--install-agent-skills"]])

    def test_migration_then_incomplete_receipt_is_completed_once_after_fresh_check(self):
        with patch.object(dependencies, "check_dependencies", side_effect=[
                    dict(self.ready, setup_required=True, migration_required=True),
                    dict(self.ready, setup_required=True), self.ready, self.ready]), \
                patch.object(dependencies, "legacy_widget_state", return_value="absent") as legacy, \
                patch.object(dependencies.subprocess, "run", return_value=result()) as run:
            self.assertEqual(dependencies.setup_wizard(), 0)
        legacy.assert_called_once_with()
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            [dependencies.SETUP, "--migrate-brand"], [dependencies.SETUP, "--apply"],
            [dependencies.SETUP, "--install-agent-skills"]])
        self.assertIn("configure the managed SSH agent", self.terminal.getvalue())

    def test_migration_that_keeps_legacy_state_never_runs_apply(self):
        for status, legacy in [(dict(self.ready, setup_required=True, migration_required=True), "managed"),
                               (dict(self.ready, setup_required=True), "conflict")]:
            with self.subTest(status=status, legacy=legacy), \
                    patch.object(dependencies, "check_dependencies", side_effect=[
                        dict(self.ready, setup_required=True, migration_required=True), status]), \
                    patch.object(dependencies, "legacy_widget_state", return_value=legacy), \
                    patch.object(dependencies.subprocess, "run", return_value=result()) as run:
                self.assertEqual(dependencies.setup_wizard(), 1)
                self.assertEqual([call.args[0] for call in run.call_args_list], [[dependencies.SETUP, "--migrate-brand"]])

    def test_final_verification_can_fail_after_previous_success(self):
        with patch.object(dependencies, "check_dependencies", side_effect=[self.ready, dict(self.ready, setup_required=True)]), \
                patch.object(dependencies.subprocess, "run", return_value=result()):
            self.assertEqual(dependencies.setup_wizard(), 1)
        self.assertIn("setup_incomplete", self.terminal.getvalue())
        self.assertNotIn("KeyController is ready.", self.terminal.getvalue())

    def test_russian_wizard_phases_and_scope_are_visible(self):
        with patch.object(dependencies, "system_language", return_value="ru"), \
                patch.object(dependencies, "check_dependencies", return_value=self.ready), \
                patch.object(dependencies.subprocess, "run", return_value=result()):
            self.assertEqual(dependencies.setup_wizard(), 0)
        self.assertIn("резервной копии", self.terminal.getvalue())
        self.assertIn("3/3 — Проверка результата", self.terminal.getvalue())
        self.assertIn("Выйдите из сеанса и войдите снова", self.terminal.getvalue())


class ShellBootstrapTests(unittest.TestCase):
    def fixture(self, directory, installed=False, signature="PackageRequired", repository="extra"):
        directory = Path(directory)
        pacman = directory / "pacman"
        pacman.write_text("#!/bin/sh\ncase \"$1\" in\n-T) [ \"$2\" = python ] || exit 0; " + ("exit 0" if installed else "printf 'python\\n'; exit 127")
                          + f";;\n-Si) printf 'Repository      : {repository}\\nName            : python\\nVersion         : 3.14.0-1\\n';;\nesac\n")
        pacman.chmod(0o700)
        config = directory / "pacman-conf"
        config.write_text("#!/bin/sh\ncase \"$1\" in\n--repo-list) printf 'core\\nextra\\nomarchy\\n';;\n"
                          + f"SigLevel) printf '{signature}\\nPackageTrustedOnly\\n';;\nesac\n")
        config.chmod(0o700)
        launcher = directory / "dependencies"
        source = (ROOT / "plugin/dependencies").read_text()
        source = source.replace("PYTHON=/usr/bin/python3", "PYTHON=" + str(directory / "absent-python"))
        source = source.replace("PACMAN=/usr/bin/pacman", "PACMAN=" + str(pacman))
        source = source.replace("PACMAN_CONF=/usr/bin/pacman-conf", "PACMAN_CONF=" + str(config))
        launcher.write_text(source)
        return launcher

    def test_missing_python_reports_only_bootstrap_package_and_incomplete_list(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = self.fixture(directory)
            process = subprocess.run(["/bin/sh", str(launcher), "--check", "--json"], capture_output=True, text=True)
        status = json.loads(process.stdout)
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertEqual(status["state"], "missing")
        self.assertEqual(status["error_code"], "python_required")
        self.assertFalse(status["complete"])
        self.assertTrue(status["installable"])
        self.assertEqual([item["name"] for item in status["missing"]], ["python"])

    def test_missing_interpreter_for_installed_package_is_not_reinstalled_blindly(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = self.fixture(directory, installed=True)
            process = subprocess.run(["/bin/sh", str(launcher), "--check", "--json"], capture_output=True, text=True)
        self.assertEqual(process.returncode, 1)
        self.assertEqual(json.loads(process.stdout)["error_code"], "python_unavailable")

    def test_bootstrap_respects_signatures_and_rejects_repository_injection(self):
        for signature, repository, expected in [("PackageOptional", "extra", "error"),
                                                 ("PackageRequired", "extra;evil", "error")]:
            with self.subTest(signature=signature, repository=repository), tempfile.TemporaryDirectory() as directory:
                launcher = self.fixture(directory, signature=signature, repository=repository)
                process = subprocess.run(["/bin/sh", str(launcher), "--check", "--json"], capture_output=True, text=True)
            status = json.loads(process.stdout)
            self.assertEqual(status["state"], expected)
            self.assertFalse(status["installable"])

    def test_bootstrap_cannot_install_without_interactive_terminal(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher = self.fixture(directory)
            process = subprocess.run(["/bin/sh", str(launcher), "--install"], capture_output=True, text=True)
        self.assertEqual(process.returncode, 1)
        self.assertIn("interactive_terminal_required", process.stderr)

    def test_bootstrap_installs_only_python_in_original_visible_pacman_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            launcher = self.fixture(directory)
            python = directory / "absent-python"
            pacman = directory / "pacman"
            pacman.write_text("#!/bin/sh\ncase \"$1\" in\n"
                              + f"-T) [ -x '{python}' ] && exit 0; printf 'python\\n'; exit 127;;\n"
                              + "-Si) printf 'Repository : extra\\nName : python\\nVersion : 3.14.0-1\\n';;\n"
                              + f"-S) printf '#!/bin/sh\\nexit 99\\n' > '{python}'; chmod 700 '{python}';;\nesac\n")
            sudo = directory / "sudo"
            invocation = directory / "invocation"
            sudo.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > '{invocation}'\nexec \"$@\"\n")
            sudo.chmod(0o700)
            source = launcher.read_text().replace("SUDO=/usr/bin/sudo", "SUDO=" + str(sudo))
            source = source.replace("runtime=/run/user/$uid", "runtime=" + str(directory))
            launcher.write_text(source)
            master, slave = pty.openpty()
            try:
                # A real terminal is necessary for the gate; every package
                # operation itself is redirected to disposable fake binaries.
                process = subprocess.Popen(["/bin/sh", str(launcher), "--install"],
                                           stdin=slave, stdout=slave, stderr=slave)
                os.write(master, b"\n")
                self.assertEqual(process.wait(timeout=5), 0)
            finally:
                if "process" in locals() and process.poll() is None:
                    process.kill()
                    process.wait()
                os.close(master)
                os.close(slave)
            self.assertEqual(invocation.read_text().splitlines(),
                             [str(pacman), "-S", "--needed", "--", "extra/python"])
            # Python would exit 99 if called: remaining dependencies are only
            # checked/installed after the panel has shown their complete list.
            self.assertTrue(python.exists())


class WizardBootstrapTests(unittest.TestCase):
    def fixture(self, directory, helper="available", outcome=0, completion=0):
        directory = Path(directory)
        python = directory / "bootstrap-python"
        events = directory / "events"
        argv = directory / "argv"
        payload = directory / "python-payload"
        lock = directory / "keycontroller-dependencies.lock"
        payload.write_text(f"""#!/usr/bin/python3
import fcntl, json, os, sys
with open({str(events)!r}, 'a') as stream:
    stream.write('python-wizard\\n')
with open({str(argv)!r}, 'w') as stream:
    json.dump(sys.argv[1:], stream)
try:
    os.fstat(9)
except OSError:
    pass
else:
    sys.exit(91)
with open({str(lock)!r}, 'r') as stream:
    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
sys.exit({completion})
""")
        payload.chmod(0o700)
        pacman = directory / "pacman"
        pacman.write_text(f"""#!/bin/sh
printf '%s\\n' "$*" >> '{events}'
case "$1" in
    -T)
        if [ "$2" = python ]; then
            [ -x '{python}' ] && exit 0
            printf 'python\\n'; exit 127
        fi
        if [ "$2" = 'keycontroller>=0.1.1-1' ]; then
            {'exit 0' if helper == 'installed' else "printf 'keycontroller>=0.1.1-1\\n'; exit 127"}
        fi
        exit 2 ;;
    -Si)
        if [ "$2" = python ]; then
            printf 'Repository : extra\\nName : python\\nVersion : 3.14.0-1\\n'
        elif [ "$2" = keycontroller ]; then
            {'exit 1' if helper == 'absent' else "printf 'Repository : omarchy\\nName : keycontroller\\nVersion : 0.1.1-1\\n'"}
        else exit 2; fi ;;
    -S)
        [ {outcome} = 0 ] || exit {outcome}
        cp '{payload}' '{python}'; chmod 700 '{python}' ;;
    *) exit 2 ;;
esac
""")
        pacman.chmod(0o700)
        config = directory / "pacman-conf"
        override = "[ \"$2\" != omarchy ] || printf 'PackageOptional\\n'" if helper == "unsigned" else ":"
        config.write_text(f"""#!/bin/sh
case "$1" in
    --repo-list) printf 'core\\nextra\\nomarchy\\n' ;;
    SigLevel) printf 'PackageRequired\\nPackageTrustedOnly\\n' ;;
    --repo) {override} ;;
esac
""")
        config.chmod(0o700)
        vercmp = directory / "vercmp"
        vercmp.write_text("#!/bin/sh\n" + ("printf '%s\\n' -1\n" if helper == "old" else "printf '0\\n'\n"))
        vercmp.chmod(0o700)
        sudo = directory / "sudo"
        sudo.write_text(f"#!/bin/sh\nprintf 'sudo\\n' >> '{events}'\nexec \"$@\"\n")
        sudo.chmod(0o700)
        source = (ROOT / "plugin/dependencies").read_text()
        for name, executable in [("PYTHON", python), ("PACMAN", pacman), ("PACMAN_CONF", config),
                                  ("VERCMP", vercmp), ("SUDO", sudo)]:
            source = re.sub(r"^" + name + r"=.*$", name + "=" + str(executable), source, flags=re.M)
        source = source.replace("runtime=/run/user/$uid", "runtime=" + str(directory))
        launcher = directory / "dependencies"
        launcher.write_text(source)
        return launcher, events, argv

    def run_wizard(self, launcher, mode="--wizard"):
        master, slave = pty.openpty()
        process = None
        try:
            process = subprocess.Popen(["/bin/sh", str(launcher), mode],
                                       stdin=slave, stdout=slave, stderr=slave)
            os.write(master, b"\n")
            return process.wait(timeout=5)
        finally:
            if process is not None and process.poll() is None:
                process.kill()
                process.wait()
            os.close(master)
            os.close(slave)

    def test_partial_check_includes_helper_and_blocks_unavailable_combined_install(self):
        for helper, available in [("available", True), ("absent", False), ("old", False)]:
            with self.subTest(helper=helper), tempfile.TemporaryDirectory() as directory:
                launcher, events, argv = self.fixture(directory, helper=helper)
                process = subprocess.run(["/bin/sh", str(launcher), "--check", "--json"],
                                         capture_output=True, text=True)
                self.assertEqual(process.returncode, 0, process.stderr)
                status = json.loads(process.stdout)
                self.assertFalse(status["complete"])
                self.assertEqual(status["installable"], available)
                self.assertEqual([item["name"] for item in status["missing"]], ["python", "keycontroller"])
                self.assertEqual(status["missing"][0]["repository"], "extra")
                self.assertTrue(status["missing"][0]["available"])
                self.assertEqual(status["missing"][1]["available"], available)
                self.assertEqual(status["missing"][1]["requirement"], dependencies.HELPER_REQUIREMENT)
                self.assertNotIn("sudo", events.read_text().splitlines())
                self.assertFalse(argv.exists())

    def test_repository_policy_blocks_check_wizard_and_legacy_python_bootstrap(self):
        for policy in ("third-party", "unsigned-other-repo"):
            with self.subTest(policy=policy), tempfile.TemporaryDirectory() as directory:
                helper = "unsigned" if policy == "unsigned-other-repo" else "available"
                launcher, events, argv = self.fixture(directory, helper=helper)
                if policy == "third-party":
                    config = Path(directory) / "pacman-conf"
                    config.write_text(config.read_text().replace("--repo-list) printf '",
                                                                "--repo-list) printf 'custom-signed\\n"))
                process = subprocess.run(["/bin/sh", str(launcher), "--check", "--json"],
                                         capture_output=True, text=True)
                self.assertEqual(process.returncode, 1, process.stderr)
                status = json.loads(process.stdout)
                self.assertEqual(status["state"], "error")
                expected = "unsupported_repositories" if policy == "third-party" else "repository_signatures_disabled"
                self.assertEqual(status["error_code"], expected)
                self.assertFalse(status["installable"])
                for mode in ("--wizard", "--install"):
                    self.assertEqual(self.run_wizard(launcher, mode), 1)
                self.assertNotIn("sudo", events.read_text().splitlines())
                self.assertFalse(argv.exists())

    def test_signed_python_bootstrap_continues_in_same_terminal_and_releases_fd9(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher, events, argv = self.fixture(directory)
            self.assertEqual(self.run_wizard(launcher), 0)
            invocations = events.read_text().splitlines()
            self.assertEqual(invocations.count("sudo"), 1)
            self.assertEqual([entry for entry in invocations if entry.startswith("-S ")], ["-S --needed -- extra/python"])
            self.assertEqual(invocations[-1], "python-wizard")
            self.assertLess(invocations.index("-Si keycontroller"), invocations.index("sudo"))
            self.assertEqual(json.loads(argv.read_text()), ["-I", str(Path(directory) / "dependencies.py"), "--wizard"])

    def test_missing_unsigned_or_old_helper_blocks_even_python_install(self):
        for helper in ("absent", "unsigned", "old"):
            with self.subTest(helper=helper), tempfile.TemporaryDirectory() as directory:
                launcher, events, argv = self.fixture(directory, helper=helper)
                self.assertEqual(self.run_wizard(launcher), 1)
                self.assertNotIn("sudo", events.read_text().splitlines())
                self.assertFalse(argv.exists())

    def test_failed_or_cancelled_python_transaction_never_executes_wizard(self):
        for outcome in (1, 130):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as directory:
                launcher, events, argv = self.fixture(directory, outcome=outcome)
                self.assertEqual(self.run_wizard(launcher), 1)
                self.assertEqual(events.read_text().splitlines().count("sudo"), 1)
                self.assertFalse(argv.exists())

    def test_successful_transaction_without_interpreter_cannot_continue(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher, events, argv = self.fixture(directory)
            pacman = Path(directory) / "pacman"
            source = pacman.read_text()
            source = re.sub(r"        cp .*chmod 700 .* ;;", "        : ;;", source)
            pacman.write_text(source)
            self.assertEqual(self.run_wizard(launcher), 1)
            self.assertEqual(events.read_text().splitlines().count("sudo"), 1)
            self.assertFalse(argv.exists())

    def test_exec_preserves_nonzero_wizard_result(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher, events, argv = self.fixture(directory, helper="installed", completion=7)
            self.assertEqual(self.run_wizard(launcher), 7)
            self.assertNotIn("-Si keycontroller", events.read_text().splitlines())
            self.assertTrue(argv.exists())

    def test_session_and_custom_config_reach_only_unprivileged_handoff(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            launcher, events, argv = self.fixture(directory)
            sudo = directory / "sudo"
            privileged = directory / "privileged-env"
            handoff = directory / "handoff-env"
            sudo.write_text(sudo.read_text().replace('exec "$@"',
                f"printf '%s\\n' \"${{WAYLAND_DISPLAY-unset}}\" \"${{CODEX_HOME-unset}}\" > '{privileged}'\nexec \"$@\""))
            payload = directory / "python-payload"
            payload.write_text(payload.read_text().replace("sys.exit(0)",
                f"with open({str(handoff)!r}, 'w') as stream:\n"
                "    json.dump([os.environ.get('WAYLAND_DISPLAY'), os.environ.get('CODEX_HOME')], stream)\n"
                "sys.exit(0)"))
            with patch.dict(os.environ, {"WAYLAND_DISPLAY": "test-wayland", "CODEX_HOME": "/tmp/test-codex"}):
                self.assertEqual(self.run_wizard(launcher), 0)
            self.assertEqual(privileged.read_text().splitlines(), ["unset", "unset"])
            self.assertEqual(json.loads(handoff.read_text()), ["test-wayland", "/tmp/test-codex"])

    def test_duplicate_bootstrap_never_starts_transaction(self):
        with tempfile.TemporaryDirectory() as directory:
            launcher, events, argv = self.fixture(directory)
            lock = Path(directory) / "keycontroller-dependencies.lock"
            lock.touch(mode=0o600)
            with lock.open() as lease:
                fcntl.flock(lease, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self.assertEqual(self.run_wizard(launcher), 1)
            self.assertNotIn("sudo", events.read_text().splitlines())
            self.assertFalse(argv.exists())


if __name__ == "__main__":
    unittest.main()
