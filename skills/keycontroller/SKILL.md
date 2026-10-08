---
name: keycontroller
description: Request access to a locked local SSH key through KeyController for an authorized SSH or Git operation. Use when the managed agent needs a key unlocked; excludes key generation, file encryption, biometric enrollment, and changes to access rules.
---

Use `kctrl` to obtain the key state. Secrets and fingerprint checks belong to the separate KeyController window; never request a passphrase in chat or pass one through a tool.

1. Read `kctrl capabilities --json` and `kctrl keys list --json`. Require API version 1. Match the key needed by the original SSH/Git operation by its public fingerprint; ask if the intended key is ambiguous. Do not try unrelated keys.
2. Check `kctrl keys status --key '<key-id>' --json`. If `state` is `unlocked`, continue without requesting another unlock. This does not extend its lifetime.
3. If locked, invoke **once**:
   ```bash
   kctrl keys unlock --key '<key-id>' --interactive --reason 'Explain the authorized SSH operation briefly' --json
   ```
   The protected window uses the method already selected in the widget. Fingerprint scanning starts automatically when that window appears, including for CLI requests; the user still supplies a fresh successful fingerprint. Password mode requires entering the SSH-key passphrase and submitting with Enter or Unlock. Opening the window alone does not mean the key is unlocked. The AI must not supply or simulate user input, a fingerprint or a passphrase.
4. `pending` (exit code 3) means waiting, not success. Poll `kctrl requests status '<request-id>' --json` at intervals of 2–5 seconds for at most two minutes. Stop polling when the request is terminal. Do not issue a new unlock while waiting. If the user cancels the underlying task, cancel its outstanding request with `kctrl requests cancel '<request-id>' --json`.
5. Continue only on `unlocked`. Stop after denial, cancellation, expiry, `busy`, cooldown, or another error; report the result without opening another window. A later explicit user instruction can authorize a new attempt.
6. Retry the original SSH/Git operation only when its repetition is safe. For a possibly completed remote write, deployment, or non-idempotent command, establish its state before retrying. Key access does not authorize additional remote actions.

The unlocked key is available through the user's ordinary managed OpenSSH agent, including to other local processes. Revocation leaves existing SSH connections alive. Preserve the original task scope, host configuration and explicit `IdentityAgent` exceptions. Do not change AI-client permissions, project `AGENTS.md`, SSH rules, key files, or biometric bindings to work around an unsuccessful request.

Run `kctrl --help` for command syntax. The installed protocol reference is `/usr/share/doc/keycontroller/api.md`.
