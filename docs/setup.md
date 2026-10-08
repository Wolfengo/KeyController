# Setup and reference

[Back to KeyController](../README.md)

## Installation

The widget and system helper are separate components. Installing or updating a plugin cannot replace privileged code: the helper must be installed through the system package manager.

Install the widget through Omarchy:

```sh
omarchy plugin add https://github.com/Wolfengo/KeyController.git --enable
```

The widget requires the separate `keycontroller` system package. Catalogue listing does not add that package to Pacman repositories. Until a signed repository provides it, build the reviewed source below or install a release package for your architecture from [GitHub Releases](https://github.com/Wolfengo/KeyController/releases). The dependency button cannot install a package absent from the configured repositories.

To build from source, use a separate working checkout outside the live plugin directory. This keeps generated build files out of the plugin's watched tree:

```sh
git clone https://github.com/Wolfengo/KeyController.git
cd KeyController
```

Review the source, then build an Arch package from this checkout:

```sh
scripts/package-source
cd dist
makepkg -s
sudo pacman -U ./keycontroller-*.pkg.tar.zst
keycontroller-setup --check
keycontroller-setup --apply
```

Run setup as the desktop user in an unlocked local session. It connects the managed agent as the primary agent, preserves explicit host-specific `IdentityAgent` exceptions, installs the widget and links the packaged agent instructions. Configuration changes have private backups; private key files are not backed up or changed by setup. Sign out and back in so existing applications receive the new agent environment.

The public agent socket is `/run/ssh-keys/UID/agent.sock`, and the helper service is `ssh-keysd@UID.service`. These private identifiers are retained for installation compatibility. Setup preserves an existing KeyController checkout and its bar position. Update a Git-installed widget with `omarchy plugin update org.omarchy.keycontroller`; update the privileged helper separately through its package. If no widget exists, setup creates a link to `/usr/share/keycontroller/plugin`, which then receives widget updates through the package manager. Restart the shell with `omarchy restart shell` after QML updates, while the screen is unlocked.

Widget version `0.2.1` and system package version `0.1.0-24` are maintained separately; API v1 is their compatibility boundary. Setup records completion only after all configuration steps and the Hyprland reload succeed. If setup was interrupted, use **Set up KeyController** again or rerun `keycontroller-setup --apply`; an enabled service alone does not count as completed setup.

For Omarchy plugin distribution, the repository's root `manifest.json` points to `plugin/Panel.qml`. The source packaging script also produces a standalone widget archive under `dist/`. The widget checks runtime dependencies and shows **Install packages** with the missing requirements when needed. Installation uses Pacman and the system's configured signed repositories, including Omarchy where available; it does not add repositories, use AUR or download installer scripts. If a required package is unavailable in those repositories, install a reviewed release package first. A first installation then offers **Set up KeyController** before enabling key controls.

Required runtime packages are `keycontroller>=0.1.0-24`, `openssh>=10.5p1`, `qt6-base`, `qt6-svg`, `qt6-wayland`, `layer-shell-qt>=6.6`, `systemd`, `pam`, `python` and `polkit`. Linux 6.5 or newer, an active local Hyprland/logind session and Yama `kernel.yama.ptrace_scope` of 1, 2 or 3 are required. Fingerprint use additionally requires `fprintd`, a system-enrolled fingerprint and TPM2. Passphrase unlocking remains available without biometric hardware.

## Agent and script access

```sh
kctrl capabilities --json
kctrl keys list --json
kctrl keys unlock --key '<key-id>' --interactive --reason 'Continue the authorized SSH operation' --json
kctrl requests status '<request-id>' --json
```

Use the returned request ID to wait for completion; `pending` is not successful access. An already loaded key returns immediately without extending its lifetime. Scripts cannot submit passphrases, bind keys, encrypt files or change policy through the public API.

The package includes a [skill](../skills/keycontroller/SKILL.md), CLI help and [API reference](api.md). Setup links the skill for detected Codex, Claude Code, OpenCode and existing `.agents` clients without editing project `AGENTS.md` files or client permissions. To install only these links, run:

```sh
keycontroller-setup --install-agent-skills --json
```

For an existing `ssh-keys` package installation, `keycontroller` retains its private storage, socket, service and PAM identifiers. Run `keycontroller-setup --migrate-brand` in the unlocked desktop to migrate the widget ID, position/settings, capture-rule include and agent-skill links, then restart the shell. This leaves SSH configuration and biometric bindings intact. If the widget then requests initial setup, run `keycontroller-setup --apply` to validate and complete configuration with the current package.

## System integration

KeyController uses the original system OpenSSH, systemd, Qt, PAM and fprintd packages. Its own systemd units, PAM policy and Hyprland capture rule are separate integration files. It does not copy, patch or replace a lockscreen, compositor or other third-party implementation.

Optional sleep revocation is provided by a required service before the original systemd `sleep.target`. It fences new loads, cancels pending operations and stops opted-in managed agents before sleep. After wake, stopped agents return empty. If safe preparation cannot be confirmed, standard systemd sleep fails. Removing the widget does not remove this system-package policy; uninstalling the package removes its own services and dependency. After a failed transition, an administrator can recover while awake with `pkexec /usr/lib/ssh-keys/sleep-coordinator recover`; recovery empties managed agents before lifting the fence.

The prompt's package-owned Hyprland rule masks its layer in supported compositor captures and disables closing animations. `keycontroller-setup --protect-prompt` installs only this integration. Capture protection has an output-startup/resizing limitation and does not provide isolation from the same desktop account; read the [security design](security.md) before relying on it.

## Removal

To remove only the widget, run `omarchy plugin remove org.omarchy.keycontroller` in an unlocked desktop. This leaves the system helper, managed agent, keys and optional sleep policy installed. Save any local edits before deleting a Git-installed widget.

For complete removal:

1. Stop and disable your helper while the package is still installed:
   ```sh
   sudo systemctl disable --now "ssh-keysd@$(id -u).service"
   ```
   This closes managed-agent access; established SSH connections remain alive. Remove the widget with the command above.
2. Restore your chosen SSH agent configuration using the backups reported by setup under `~/.local/state/ssh-keys/setup-*`. Compare and merge those files; replacing an entire old backup may discard later personal edits. Remove the `SSH Keys managed agent` blocks from `~/.ssh/config` and `~/.bashrc`. Also restore any catch-all `IdentityAgent` directives setup changed in included SSH configuration files; retain unrelated host exceptions.
3. Remove `~/.config/environment.d/90-ssh-keys.conf` only if it still contains solely KeyController's `SSH_AUTH_SOCK` assignment. Restore the previous agent's `hl.env("SSH_AUTH_SOCK", ...)` entry in `~/.config/hypr/autostart.lua`. Remove only the `KeyController capture protection` block from `~/.config/hypr/hyprland.lua` **before** uninstalling the package, then run `hyprctl reload` and `hyprctl configerrors`.
4. Remove KeyController skill links from configured AI-client skill directories only when `readlink` points to `/usr/share/keycontroller/skills/keycontroller`. Preserve user-authored skills and other links. Remove the nonsecret setup receipt `~/.local/state/keycontroller/setup.json`.
5. On a shared machine, finish the per-user cleanup for all configured users before removing the system-wide package:
   ```sh
   sudo pacman -R keycontroller
   ```
   Its removal hook stops managed services and removes its sleep integration. Sign out and back in after restoring your previous agent environment.

No private SSH key file is deleted by these steps. User configuration backups and root-only settings/encrypted bindings under `/var/lib/ssh-keys/UID` are retained for deliberate administrator review; package removal does not silently purge them.

## Development

Build dependencies are listed in [PKGBUILD](../packaging/PKGBUILD). Tests use disposable keys and synthetic input. Hardware authentication and installed-session behavior also require validation on the target system.

```sh
cargo build --release --locked
cargo test --locked
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

The package's `check()` function runs the Rust, Qt and Python regression suites. `scripts/package-source` creates the source archive, its checksum-pinned PKGBUILD and the standalone widget archive.
