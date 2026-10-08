# Privileged components and reduction plan

The main service is not just a sleep hook. `ssh-keysd@UID.service` currently runs
as root and coordinates authorization, protected state, desktop-session checks,
managed-agent access and short-lived workers. Its children drop to the desktop
UID for the Qt prompt, file inspection, key encryption and OpenSSH tools. The
original OpenSSH agent also runs as that UID.

The separate sleep coordinator is a root oneshot. It reads coordination metadata,
fences new loads and controls only the managed helper/agent/socket unit names.
It does not read key files or stored passphrases. An empty `CapabilityBoundingSet`
does not turn UID 0 into an unprivileged identity: the coordinator intentionally
uses systemd's management interface as root.

## Current authority and evidence

| Authority | Current operation | Relevant implementation |
|---|---|---|
| Root-only persistent state | Settings, inventory and encrypted biometric bindings under `/var/lib/ssh-keys/UID` | `src/server.rs`: `serve`, `save`, binding commit; `src/worker.rs`: `credential` |
| `CAP_SETUID`, `CAP_SETGID` | Clear supplementary groups and launch prompt/file tasks as the owner | `src/process.rs`: `descriptors`; `src/worker.rs`: `unprivileged` |
| `CAP_CHOWN`, `CAP_FOWNER` | Transfer public socket ownership and then set permissions | `src/platform.rs`: `own_socket` |
| `CAP_DAC_OVERRIDE` | Root-side access across user-owned runtime/session paths; exact necessity must be traced | `src/platform.rs`: `connect_display`, `display_socket` |
| `CAP_SYS_PTRACE` | Cross-UID `/proc/PID/exe` inspection used in compositor identity checks; no direct `ptrace()` call | `src/platform.rs`: `verified_process` |
| `CAP_KILL` | Cancel/reap worker groups containing both root and owner-UID descendants | `src/server.rs`: `cancel_active`; `src/worker.rs`: cancellation watcher |
| `/home` writable in service sandbox | Descendant owner-UID task may atomically encrypt an existing SSH key | `src/worker.rs`: `file_task`; `src/keys.rs`: `Snapshot` |
| Root system-bus access | logind/controller verification, fingerprint PAM, managed-agent restart | `src/platform.rs`, `src/worker.rs`, `scripts/ssh-keys-sleep` |
| Protected agent backend | Root-side proxy serializes additions/revocations and fences stale workers | `src/agent.rs`: `proxy_at`; `src/server.rs`: `revoke`, `prepare_sleep` |

This is a source-based inventory, not proof that each capability is minimal.
The production service's capability bounds and `/home` exception have not been
reduced speculatively. Reducing Linux capabilities alone also does not remove
UID 0 authority over other root-authorized interfaces such as systemd.

## Next reduction milestones

1. Trace each operation on a disposable system with the capability removed,
   including normal and failure paths. Socket permission order/systemd-created
   sockets may remove the need for `CAP_FOWNER` or `CAP_CHOWN`; this must be tested
   with existing socket ownership and restart races before claiming removal.
2. Separate filesystem mutation workers from the long-lived root service's
   writable mounts. Grant a short-lived owner-UID worker access to that user's
   validated SSH directory instead of granting the entire service `/home` write
   access. A plain `ReadWritePaths=/home/%i` is incorrect (`%i` is a numeric UID),
   and `%h` in the root service is not the desktop user's home. NSS-derived homes,
   symlinks, nested keys and atomic replacement require explicit handling.
3. Separate ordinary agent packet forwarding and request parsing from the small
   privileged authorization/credential broker. The broker must independently
   verify UID, session, key identity and operation; it cannot trust a caller's
   assertion that authentication occurred. Use fixed operations and private
   descriptor handoffs rather than arbitrary commands, paths or mutable sockets.
4. Restrict each root worker's authority to its role and lifetime. Preserve the
   encrypted root-only credential boundary, fresh PAM authentication before
   decrypting, safe credential-name binding, Yama/non-dumpable bootstrap,
   descriptor allowlists, cancellation generations and fail-closed sleep fencing.

Changing the main service to `User=UID` or moving credentials into ordinary
user-readable state is not a safe shortcut. The existing root supervisor ancestry
also protects the secret-free exec bootstrap from unrelated same-UID ptrace;
a replacement design must retain or independently replace that guarantee.

Required acceptance coverage: foreign UID and SSH-origin requests, substituted
Wayland endpoints, fresh PAM/TPM success/refusal, loader crashes, descriptor/core
exposure, late completion after cancellation, service restarts, concurrent manual
agent mutation, suspend/hibernate/aborted sleep, and per-user home layouts. Hardware
and full systemd tests cannot be replaced by parser/unit checks alone.
