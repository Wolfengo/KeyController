# Installation review

KeyController has a user-installed Omarchy widget and a separately packaged native service. Updating the widget cannot replace the installed privileged helper. This page describes installation; the [runtime privilege inventory](privileges.md) and [security model](security.md) cover key access.

## Before making changes

From the plugin checkout, inspect the package and setup plan:

```sh
sh plugin/dependencies --dry-run
sh plugin/dependencies --dry-run --json
```

With a compatible system package installed, inspect desktop setup directly:

```sh
keycontroller-setup --dry-run --json
```

Preview reads local package metadata and relevant configuration. It reports paths, intended actions and blockers without printing configuration contents or discovering SSH keys. It does not install packages, authorize a privileged action, create backups or receipts, change services, or reload the desktop. Missing Python, pending package installation, an older installed setup helper or required legacy migration leaves the preview explicitly incomplete; no setup runs to fill the gap. Dependency preview exits 0 only for a complete plan with passed prerequisites; blocked or incomplete plans exit 1. A preview is a snapshot, not authorization: installation rechecks conditions and Pacman shows the final package transaction for confirmation.

## What installation changes

| Step | Authority and scope |
|---|---|
| Install the widget | Omarchy's plugin manager maintains its checkout in the user's plugin directory. KeyController preserves that checkout and its update mechanism. If no widget exists, desktop setup links to the package-owned widget. |
| Install missing packages | A visible terminal runs `sudo /usr/bin/pacman -S --needed -- …` with fixed required package names and validated repository prefixes. Only configured `core`, `extra`, `multilib` and `omarchy` repositories with required trusted package signatures are accepted. No AUR, downloaded release installer, repository addition or signature bypass. Pacman resolves dependencies and installs package hooks as root. |
| Enable the service | The named Polkit action `org.omarchy.keycontroller.setup` authorizes the package-owned `/usr/lib/ssh-keys/system-setup enable UID`. It initializes systemd's credential key, reloads unit definitions and enables `ssh-keysd@UID.service`. It accepts no arbitrary command or unit name. Defaults require fresh administrator authorization from an active session and deny other sessions. An ordinary `pkexec` caller can enable only their own UID; direct root administration remains possible. |
| Configure the desktop | The unprivileged setup tool connects the managed agent through SSH configuration, the user environment and supported shell/Hyprland settings. It preserves explicit host-specific `IdentityAgent` exceptions, adds the widget and the package-owned capture-rule include, then reloads Hyprland. Conflicting shared configuration stops setup for review. |
| Add AI instructions | Setup links the packaged skill for detected clients. Existing conflicting skills, project `AGENTS.md` files and client permissions are preserved. |

Modified configuration receives private backups under `~/.local/state/ssh-keys/setup-*`; a nonsecret completion receipt is written under `~/.local/state/keycontroller/`. Setup neither encrypts nor copies SSH key files. It does not copy or replace the selected lockscreen or other third-party implementations. [Removal instructions](setup.md#removal) explain restoring configuration without discarding later edits; installation is not an atomic transaction with automatic rollback.

## Trust and availability

The root service is an authorization and credential broker, not merely a sleep hook. It protects biometric bindings and policy, verifies the local session and controls managed-agent operations. Moving it wholesale into a user service would change that trust boundary. The original OpenSSH agent runs as the desktop user; other processes of that user can use loaded keys. The public API returns request results, not passphrases or private keys. Release provenance and checksums do not establish a security audit or replace package signatures.

The [system package submission](https://github.com/omacom/omarchy-pkgs/pull/857) and [marketplace installation review](https://github.com/omacom/omarchy-plugin-marketplace/issues/11356) are separate decisions. Until a suitable package is available in the allowed repositories, the wizard reports that it is unavailable. Marketplace verification of a listing does not itself remove **Manual setup** or approve installation with one command.
