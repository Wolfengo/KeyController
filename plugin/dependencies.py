#!/usr/bin/python3
"""Public package metadata only; no daemon, credentials, keys, or network API.

Install the original packages from the user's configured, signature-enforcing
pacman repositories. A plugin may never select arbitrary packages or run itself
as root. The package manager retains its visible transaction confirmation.
"""

import argparse
from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import pwd
import re
import stat
import subprocess
import sys


HELPER_REQUIREMENT = "keycontroller>=0.1.1-1"
REQUIREMENTS = (
    HELPER_REQUIREMENT, "openssh>=10.5p1", "qt6-base", "qt6-svg",
    "qt6-wayland", "layer-shell-qt>=6.6", "systemd", "pam", "python", "polkit",
)
PACMAN = "/usr/bin/pacman"
PACMAN_CONF = "/usr/bin/pacman-conf"
VERCMP = "/usr/bin/vercmp"
SUDO = "/usr/bin/sudo"
SETUP = "/usr/bin/keycontroller-setup"
SYSTEMCTL = "/usr/bin/systemctl"
LEGACY_PLUGIN_ID = "org.omarchy.ssh-keys"
LEGACY_PLUGIN_TARGET = "/usr/share/ssh-keys/plugin"
QUERY_TIMEOUT = 8
QUERY_ENV = {"PATH": "/usr/bin", "LANG": "C", "LC_ALL": "C"}
SAFE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.+-]*\Z")
SAFE_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9:+._~\-]*\Z")
OFFICIAL_REPOSITORIES = frozenset(("core", "extra", "multilib", "omarchy"))


class DependencyError(Exception):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def query(command):
    try:
        result = subprocess.run(command, capture_output=True, text=True,
                                env=QUERY_ENV, timeout=QUERY_TIMEOUT,
                                close_fds=True, check=False)
    except subprocess.TimeoutExpired:
        raise DependencyError("package_check_timeout") from None
    except (OSError, UnicodeError):
        raise DependencyError("package_manager_unavailable") from None
    if len(result.stdout) + len(result.stderr) > 1024 * 1024:
        raise DependencyError("package_metadata_invalid")
    return result


def system_language(path=Path("/etc/locale.conf")):
    """Same trusted system locale source as the helper, without executing it."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "r", encoding="utf-8") as stream:
            before = os.fstat(stream.fileno())
            if (not stat.S_ISREG(before.st_mode) or before.st_uid != 0
                    or before.st_mode & 0o022 or before.st_size > 16384):
                return "en"
            text = stream.read(16385)
            if len(text.encode("utf-8")) > 16384:
                return "en"
            after = os.fstat(stream.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                    after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                return "en"
        return parse_language(text)
    except (OSError, UnicodeError):
        return "en"


def parse_language(text):
    values = {}
    assignment = re.compile(
        r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"
        r"(?:\"([^\"$`\\\x00]*)\"|'([^'$`\\\x00]*)'|([^\s'\"$`\\#\x00]*))"
        r"(?:\s+#.*|\s*)\Z")
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        match = assignment.fullmatch(line)
        if not match:
            return "en"
        values[match[1]] = next(value for value in match.groups()[1:] if value is not None)
    locale = values.get("LC_MESSAGES") or values.get("LANG", "")
    if not re.fullmatch(r"[A-Za-z0-9_.@-]{0,128}", locale):
        return "en"
    return "ru" if re.split(r"[_\-.@]", locale)[0].lower() == "ru" else "en"


def lock_path():
    return Path("/run/user") / str(os.getuid()) / "keycontroller-dependencies.lock"


@contextmanager
def installation_lock(create=True):
    path = lock_path()
    fd = None
    try:
        parent = path.parent.stat()
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or parent.st_mode & 0o077):
            raise DependencyError("install_lock_unavailable")
        flags = os.O_RDWR | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
        if create:
            flags |= os.O_CREAT
        try:
            fd = os.open(path, flags, 0o600)
        except FileNotFoundError:
            if not create:
                yield False
                return
            raise
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                or info.st_mode & 0o077 or info.st_nlink != 1):
            raise DependencyError("install_lock_unavailable")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DependencyError("installation_busy") from None
        yield True
    except OSError:
        raise DependencyError("install_lock_unavailable") from None
    finally:
        if fd is not None:
            os.close(fd)


def installation_running():
    try:
        with installation_lock(create=False):
            return False
    except DependencyError as error:
        # An unavailable graphical runtime should not conceal package status.
        return error.code == "installation_busy"


def missing_requirements(requirements):
    result = query([PACMAN, "-T", *requirements])
    if result.returncode not in (0, 127):
        raise DependencyError("package_check_failed")
    missing = result.stdout.splitlines()
    if (len(set(missing)) != len(missing) or any(item not in requirements for item in missing)
            or (result.returncode == 0 and missing)
            or (result.returncode == 127 and not missing)):
        raise DependencyError("package_metadata_invalid")
    return [requirement for requirement in requirements if requirement in missing]


def configured_repositories():
    result = query([PACMAN_CONF, "--repo-list"])
    repositories = result.stdout.splitlines()
    if (result.returncode or len(repositories) != len(set(repositories))
            or any(not SAFE_NAME.fullmatch(repo) for repo in repositories)):
        raise DependencyError("repository_config_invalid")
    # Pacman also resolves transitive dependencies from enabled repositories.
    # Restrict the complete configuration, not only our explicit targets.
    if any(repo not in OFFICIAL_REPOSITORIES for repo in repositories):
        raise DependencyError("unsupported_repositories")
    if any(not signatures_required(repo) for repo in repositories):
        raise DependencyError("repository_signatures_disabled")
    return repositories


def signatures_required(repository):
    tokens = []
    for command in ([PACMAN_CONF, "SigLevel"],
                    [PACMAN_CONF, "--repo", repository, "SigLevel"]):
        result = query(command)
        if result.returncode:
            raise DependencyError("repository_config_invalid")
        tokens.extend(result.stdout.split())
    required, trusted = False, False
    for token in tokens:
        if token in ("Required", "PackageRequired"):
            required = True
        elif token in ("Optional", "Never", "PackageOptional", "PackageNever"):
            required = False
        elif token in ("TrustedOnly", "PackageTrustedOnly"):
            trusted = True
        elif token in ("TrustAll", "PackageTrustAll"):
            trusted = False
        elif not token.startswith("Database"):
            raise DependencyError("repository_config_invalid")
    return required and trusted


def repository_candidate(requirement, repositories):
    name, _, minimum = requirement.partition(">=")
    item = {"name": name, "requirement": requirement, "repository": None,
            "available": False, "reason": "repository_unavailable"}
    # Name resolution is pacman's own configured repository priority. It is
    # intentionally not overridden by a preferred third-party download source.
    result = query([PACMAN, "-Si", name])
    if result.returncode:
        if result.returncode == 1 and not result.stdout.strip():
            return item
        raise DependencyError("package_metadata_invalid")
    fields = {}
    for line in result.stdout.splitlines():
        if not line.strip() and fields:
            break
        field, separator, value = line.partition(":")
        if separator and field.strip() in ("Name", "Repository", "Version"):
            if field.strip() in fields:
                raise DependencyError("package_metadata_invalid")
            fields[field.strip()] = value.strip()
    repository, version = fields.get("Repository"), fields.get("Version", "")
    if (fields.get("Name") != name or repository not in repositories
            or not SAFE_VERSION.fullmatch(version)):
        raise DependencyError("package_metadata_invalid")
    item["repository"] = repository
    if not signatures_required(repository):
        item["reason"] = "repository_signatures_disabled"
        return item
    if minimum:
        result = query([VERCMP, version, minimum])
        if result.returncode or not re.fullmatch(r"-?\d+\n?", result.stdout):
            raise DependencyError("package_metadata_invalid")
        if int(result.stdout) < 0:
            item["reason"] = "repository_version_too_old"
            return item
    item.update(available=True, reason=None)
    return item


def legacy_widget_state():
    home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    path = home / ".config/omarchy/plugins" / LEGACY_PLUGIN_ID
    try:
        info = path.lstat()
        if stat.S_ISLNK(info.st_mode) and os.readlink(path) == LEGACY_PLUGIN_TARGET:
            return "managed"
        return "conflict"
    except FileNotFoundError:
        return "absent"
    except OSError:
        raise DependencyError("setup_status_unavailable") from None


def setup_receipt_complete():
    """Nonsecret installation progress; never used to authorize key access."""
    try:
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
        path = home / ".local/state/keycontroller/setup.json"
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1 or metadata.st_mode & 0o077
                    or metadata.st_size > 4096):
                return False
            data = stream.read(4097)
        if len(data) > 4096:
            return False
        receipt = json.loads(data)
        return (isinstance(receipt, dict)
                and set(receipt) == {"schema_version", "uid", "complete"}
                and type(receipt["schema_version"]) is int and receipt["schema_version"] == 1
                and type(receipt["uid"]) is int and receipt["uid"] == os.getuid()
                and receipt["complete"] is True)
    except (OSError, ValueError, KeyError, UnicodeError):
        return False


def setup_status():
    """Read systemd enablement and setup progress, never keys or SSH files."""
    try:
        result = query([SYSTEMCTL, "is-enabled", f"ssh-keysd@{os.getuid()}.service"])
    except DependencyError:
        raise DependencyError("setup_status_unavailable") from None
    value = result.stdout.strip()
    if value == "enabled" and result.returncode == 0:
        required = not setup_receipt_complete()
    elif (value == "enabled-runtime" and result.returncode == 0
          or value == "disabled" and result.returncode == 1
          or value == "not-found" and result.returncode in (1, 4)):
        required = True
    else:
        # A masked or unexpected unit is an administrator/configuration issue,
        # not evidence that a fresh setup may safely overwrite existing work.
        raise DependencyError("setup_status_unavailable")
    migration = legacy_widget_state() == "managed"
    return {"setup_required": required or migration, "migration_required": migration}


def check_dependencies(include_installing=True):
    status = {"schema_version": 1, "state": "error", "ui_language": system_language(),
              "missing": [], "optional": {}, "complete": True, "installable": False,
              "setup_required": False, "migration_required": False,
              "installing": installation_running() if include_installing else False,
              "error_code": None}
    try:
        if os.geteuid() == 0:
            raise DependencyError("root_not_allowed")
        missing = missing_requirements(REQUIREMENTS)
        status["optional"] = {"fprintd": {"installed": not missing_requirements(("fprintd",))}}
        if not missing:
            status.update(setup_status())
            status["state"] = "ready"
            return status
        repositories = configured_repositories()
        status["missing"] = [repository_candidate(item, repositories) for item in missing]
        status["state"] = "missing"
        status["installable"] = all(item["available"] for item in status["missing"])
    except DependencyError as error:
        status["error_code"] = error.code
    return status


def installation_targets(status):
    """Defence in depth: no API/CLI/environment-supplied package operands."""
    if status["state"] != "missing" or not status["installable"]:
        raise DependencyError("dependencies_not_installable")
    targets = []
    for item in status["missing"]:
        if (item["requirement"] not in REQUIREMENTS
                or item["name"] != item["requirement"].partition(">=")[0]
                or not item["available"] or item["repository"] not in OFFICIAL_REPOSITORIES):
            raise DependencyError("package_metadata_invalid")
        target = item["repository"] + "/" + item["name"]
        if target in targets:
            raise DependencyError("package_metadata_invalid")
        targets.append(target)
    if not targets:
        raise DependencyError("package_metadata_invalid")
    return targets


MESSAGES = {
    "wizard_intro": ("KeyController: установка и настройка", "KeyController: install and set up"),
    "wizard_scope": (
        "Будут установлены недостающие пакеты из подключённых репозиториев и настроен основной SSH-агент. Изменяемые настройки сохраняются в резервной копии; явные исключения IdentityAgent сохраняются. Инструкции для установленных ИИ-агентов будут подключены.",
        "Missing packages will be installed from configured repositories and the primary SSH agent will be configured. Changed settings are backed up; explicit IdentityAgent exceptions are preserved. Instructions for installed AI agents will be linked."),
    "wizard_packages": ("1/3 — Проверка и установка пакетов", "1/3 — Check and install packages"),
    "wizard_setup": ("2/3 — Настройка интеграции", "2/3 — Set up desktop integration"),
    "wizard_verify": ("3/3 — Проверка результата", "3/3 — Verify the result"),
    "wizard_complete": ("KeyController готов к работе.", "KeyController is ready."),
    "relogin": (
        "Выйдите из сеанса и войдите снова, чтобы все приложения использовали настроенный SSH-агент. Выход не выполняется автоматически.",
        "Log out and log back in so all applications use the configured SSH agent. You will not be logged out automatically."),
    "dependencies_not_installable": (
        "Нужные пакеты пока недоступны в подключённых репозиториях с доверенными подписями. Дождитесь их публикации или обновите систему штатным способом.",
        "Required packages are not yet available from configured repositories with trusted signatures. Wait for publication or update the system using its normal updater."),
    "unsupported_repositories": (
        "Автоматическая установка поддерживает только стандартные репозитории Omarchy/Arch: core, extra, multilib, omarchy. Настройки репозиториев не изменяются.",
        "Automatic installation supports only the default Omarchy/Arch repositories: core, extra, multilib, omarchy. Repository configuration is not changed."),
    "intro": ("KeyController: установка недостающих пакетов", "KeyController: install missing packages"),
    "confirmation": (
        "Pacman покажет полный список, включая зависимости, и запросит подтверждение. Обновление всей системы не запускается.",
        "Pacman will show the full transaction, including dependencies, and ask for confirmation. No full system upgrade is started."),
    "ready": ("Все необходимые пакеты установлены.", "All required packages are installed."),
    "skills": ("Инструкции для установленных ИИ-агентов подключены.", "Instructions for installed AI agents are linked."),
    "setup": (
        "При первой установке настройте агент командой: keycontroller-setup --apply",
        "On first installation, configure the agent with: keycontroller-setup --apply"),
    "configured": ("KeyController настроен.", "KeyController is configured."),
    "setup_intro": ("KeyController: настройка управляемого SSH-агента", "KeyController: configure the managed SSH agent"),
    "migration_intro": ("KeyController: перенос существующей интеграции", "KeyController: migrate the existing integration"),
    "failure": ("Операция не завершена", "Operation did not complete"),
    "hold": ("Нажмите Enter, чтобы закрыть окно…", "Press Enter to close this window…"),
    "repository_unavailable": ("пакет отсутствует в подключённых репозиториях", "package is absent from configured repositories"),
    "repository_version_too_old": ("в индексе репозитория нет нужной версии; обновите систему штатным способом", "repository index has no suitable version; update the system using its normal updater"),
    "repository_signatures_disabled": (
        "Все подключённые репозитории должны требовать доверенные подписи пакетов.",
        "Every configured repository must require trusted package signatures."),
}


def message(key, language):
    return MESSAGES.get(key, (key, key))[0 if language == "ru" else 1]


def interactive_env():
    account = pwd.getpwuid(os.getuid())
    environment = dict(QUERY_ENV, HOME=account.pw_dir, USER=account.pw_name,
                       LOGNAME=account.pw_name)
    # TERM is terminal presentation only, never a command or a package operand.
    term = os.environ.get("TERM", "")
    if re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", term):
        environment["TERM"] = term
    return environment


def user_setup_env(include_session=False):
    # These paths belong only to the unprivileged per-user skill linker. Do
    # not add them to interactive_env(), which also reaches sudo/pacman.
    environment = interactive_env()
    for variable in ("CODEX_HOME", "XDG_CONFIG_HOME"):
        if os.environ.get(variable):
            environment[variable] = os.environ[variable]
    if include_session:
        for variable in ("XDG_RUNTIME_DIR", "WAYLAND_DISPLAY", "HYPRLAND_INSTANCE_SIGNATURE",
                         "DBUS_SESSION_BUS_ADDRESS", "XDG_SESSION_ID", "XDG_SESSION_TYPE",
                         "XDG_CURRENT_DESKTOP", "XDG_SESSION_DESKTOP", "DISPLAY", "XAUTHORITY"):
            if os.environ.get(variable):
                environment[variable] = os.environ[variable]
    return environment


def link_agent_skills(language):
    try:
        result = subprocess.run([SETUP, "--install-agent-skills"], env=user_setup_env(),
                                close_fds=True, timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise DependencyError("agent_skills_failed") from None
    if result.returncode:
        raise DependencyError("agent_skills_failed")
    print(message("skills", language))


def checked_dependencies():
    status = check_dependencies(include_installing=False)
    if status["state"] == "error":
        raise DependencyError(status["error_code"])
    return status


def install_packages(status, language):
    """Called only while the caller owns installation_lock()."""
    if status["state"] == "missing":
        for item in status["missing"]:
            source = item["repository"] or "—"
            print("  " + item["requirement"] + " [" + source + "]")
            if item["reason"]:
                print("    " + message(item["reason"], language))
        # Validate the complete transaction before any package or setup effect.
        targets = installation_targets(status)
        print(message("confirmation", language), flush=True)
        try:
            result = subprocess.run([SUDO, PACMAN, "-S", "--needed", "--", *targets],
                                    env=interactive_env(), close_fds=True, check=False)
        except OSError:
            raise DependencyError("package_install_failed") from None
        if result.returncode:
            raise DependencyError("package_install_failed")
        status = checked_dependencies()
        if status["state"] != "ready":
            raise DependencyError("dependencies_still_missing")
    print(message("ready", language))
    return status


def run_user_setup(action, language):
    label = "migration_intro" if action == "--migrate-brand" else "setup_intro"
    print(message(label, language), flush=True)
    try:
        result = subprocess.run([SETUP, action], env=user_setup_env(include_session=True),
                                close_fds=True, check=False)
    except OSError:
        raise DependencyError("setup_failed") from None
    if result.returncode:
        raise DependencyError("setup_failed")
    return checked_dependencies()


def configure_user(status, language, finish_migration=False):
    """Use only the installed per-user setup program, never sudo plugin code."""
    if status["state"] != "ready":
        raise DependencyError("dependencies_still_missing")
    changed = bool(status["setup_required"] or status["migration_required"])
    if changed:
        if status["migration_required"]:
            status = run_user_setup("--migrate-brand", language)
            if finish_migration and status["state"] == "ready" and not status["migration_required"]:
                # Older integration can predate the completion receipt. Finish
                # explicitly requested initial setup after safe brand migration.
                if status["setup_required"]:
                    if legacy_widget_state() != "absent":
                        raise DependencyError("legacy_widget_conflict")
                    status = run_user_setup("--apply", language)
        else:
            # Existing legacy directories/custom links need human review.
            if legacy_widget_state() != "absent":
                raise DependencyError("legacy_widget_conflict")
            status = run_user_setup("--apply", language)
        if (status["state"] != "ready" or status["setup_required"]
                or status["migration_required"]):
            raise DependencyError("setup_incomplete")
    return changed


def hold_terminal(language):
    if sys.stdin.isatty() and sys.stdout.isatty():
        try:
            input(message("hold", language))
        except (EOFError, KeyboardInterrupt):
            pass


def interactive_operation(operation, hold_success=False):
    language = system_language()
    try:
        if os.geteuid() == 0:
            raise DependencyError("root_not_allowed")
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise DependencyError("interactive_terminal_required")
        with installation_lock():
            operation(checked_dependencies(), language)
        if hold_success:
            hold_terminal(language)
        return 0
    except (DependencyError, KeyboardInterrupt) as error:
        code = error.code if isinstance(error, DependencyError) else "installation_cancelled"
        print(message("failure", language) + " (" + code + ").", file=sys.stderr)
        if code in MESSAGES:
            print(message(code, language), file=sys.stderr)
        hold_terminal(language)
        return 1


def install_dependencies():
    """Compatibility action: install packages and agent instructions only."""
    def install(status, language):
        print(message("intro", language))
        install_packages(status, language)
        link_agent_skills(language)
        print(message("setup", language))
    return interactive_operation(install)


def configure_integration():
    """Compatibility action: explicit setup without installing packages."""
    def configure(status, language):
        configure_user(status, language)
        print(message("configured", language))
    return interactive_operation(configure)


def setup_wizard():
    """The combined visible UI action explicitly authorizes per-user setup."""
    def wizard(status, language):
        print(message("wizard_intro", language))
        print(message("wizard_scope", language), flush=True)
        print(message("wizard_packages", language), flush=True)
        status = install_packages(status, language)
        print(message("wizard_setup", language), flush=True)
        configure_user(status, language, finish_migration=True)
        # Also verify instructions after --apply: older packaged setup versions
        # report skill conflicts without failing their desktop setup action.
        # This is idempotent and retains user-owned conflicting instructions.
        link_agent_skills(language)
        print(message("wizard_verify", language), flush=True)
        verified = checked_dependencies()
        if (verified["state"] != "ready" or verified["setup_required"]
                or verified["migration_required"]):
            raise DependencyError("setup_incomplete")
        print(message("wizard_complete", language))
        print(message("relogin", language), flush=True)
    return interactive_operation(wizard, hold_success=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--check", action="store_true")
    mode.add_argument("--install", action="store_true")
    mode.add_argument("--setup", action="store_true")
    mode.add_argument("--wizard", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    if args.install or args.setup or args.wizard:
        if args.json:
            parser.error("--install, --setup and --wizard require a visible terminal, not --json")
        if args.wizard:
            return setup_wizard()
        return configure_integration() if args.setup else install_dependencies()
    status = check_dependencies()
    print(json.dumps(status, ensure_ascii=False))
    return 0 if status["state"] != "error" else 1


if __name__ == "__main__":
    sys.exit(main())
