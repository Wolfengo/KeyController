use crate::{
    Error, Result,
    keys::{self, Key, Snapshot},
    platform::User,
    process,
    state::Rules,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    ffi::{CString, c_char, c_int, c_void},
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::{fd::AsRawFd, unix::net::UnixStream},
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

#[derive(Clone, Serialize, Deserialize)]
pub struct Job {
    pub user: User,
    pub operation: String,
    pub key: Option<Key>,
    pub request_id: String,
    pub reason: String,
    pub caller: String,
    pub rules: Rules,
    pub fingerprint_mode: bool,
    pub bound: bool,
    pub wayland: String,
    #[serde(default)]
    pub display: Option<crate::platform::DisplayIdentity>,
    #[serde(default)]
    pub value: Value,
}
#[derive(Deserialize, Zeroize, ZeroizeOnDrop)]
#[serde(deny_unknown_fields)]
struct Answer {
    consent: bool,
    mode: String,
    passphrase: String,
    confirmation: String,
}
pub fn credential_path(user: &User, id: &str) -> std::path::PathBuf {
    user.state_dir()
        .join(format!("{}.cred", credential_name(user, id)))
}
fn credential_name(user: &User, id: &str) -> String {
    format!("ssh-key-{}-{:x}", user.uid, Sha256::digest(id.as_bytes()))
}
pub fn file_task(job: &Job, pass: &[u8]) -> Result<Value> {
    if unsafe { libc::geteuid() } != job.user.uid || job.user.uid == 0 {
        return Err(Error("wrong_user"));
    }
    let root = job.user.home.join(".ssh");
    if job.operation == "scan" {
        return Ok(json!({"keys":keys::scan(&root,job.user.uid)?}));
    }
    let key = job.key.as_ref().ok_or(Error("key_not_found"))?;
    let mut snap = Snapshot::open(&root, &key.path, job.user.uid, job.operation == "encrypt")?;
    if snap.header.fingerprint != key.id {
        return Err(Error("file_conflict"));
    }
    match job.operation.as_str() {
        "inspect" => return Ok(json!({"encrypted":snap.header.encrypted})),
        "verify" => snap.verify(pass)?,
        "encrypt" => {
            let bytes = snap.encrypted_copy(pass)?;
            snap.replace(&bytes)?;
            let inventory = keys::scan(&root, job.user.uid).map_err(|_| Error("partial_commit"))?;
            return Ok(json!({"ok":true,"committed":true,"keys":inventory}));
        }
        "load" => {
            if !snap.header.encrypted {
                return Err(Error("key_not_encrypted"));
            }
            // The sealed envelope is matched to job.key above. OpenSSH checks
            // that its decrypted private key matches this envelope before ADD;
            // loading need not run the same bcrypt derivation in ssh-keygen too.
            process::load_key_snapshot(
                &snap.memory,
                pass,
                &job.user.runtime().join("agent.sock"),
                job.rules.lifetime_seconds,
            )?;
        }
        _ => return Err(Error("invalid_operation")),
    }
    Ok(json!({"ok":true,"committed":job.operation=="encrypt"}))
}
pub fn unprivileged(job: &Job, pass: &[u8]) -> Result<Value> {
    let input = process::memfile(&serde_json::to_vec(job)?, true)?;
    let secret = process::memfile(pass, true)?;
    let mut output = process::memfile(&[], false)?;
    let mut c = process::clean_command(
        std::env::current_exe()?
            .to_str()
            .ok_or(Error("invalid_path"))?,
    );
    c.arg("--file-task")
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(output.try_clone()?));
    process::wait(
        process::protected_spawn_as(
            &mut c,
            &[(secret.as_raw_fd(), 4)],
            Some((job.user.uid, job.user.gid)),
        )?,
        45,
    )?;
    output.seek(SeekFrom::Start(0))?;
    let mut data = Vec::new();
    output.take(4 * 1024 * 1024).read_to_end(&mut data)?;
    let v: Value = serde_json::from_slice(&data)?;
    if let Some(code) = v.get("error_code").and_then(Value::as_str) {
        return Err(Error(stable_code(code)));
    }
    Ok(v)
}
pub fn stable_code(code: &str) -> &'static str {
    match code {
        "empty_passphrase" => "empty_passphrase",
        "confirmation_mismatch" => "confirmation_mismatch",
        "file_conflict" => "file_conflict",
        "partial_commit" => "partial_commit",
        "outside_ssh_directory" => "outside_ssh_directory",
        "multiple_hard_links" => "multiple_hard_links",
        "key_operation_failed" => "wrong_passphrase_or_invalid_key",
        "wrong_passphrase_or_invalid_key" => "wrong_passphrase_or_invalid_key",
        "unlock_failed" => "unlock_failed",
        "fingerprint_mismatch" => "fingerprint_mismatch",
        "biometric_denied" => "biometric_denied",
        "tpm_unavailable" => "tpm_unavailable",
        "credential_unavailable" => "credential_unavailable",
        "cancelled" => "cancelled",
        "invalid_passphrase" => "invalid_passphrase",
        "unsafe_key_file" => "unsafe_key_file",
        "unsafe_directory" => "unsafe_directory",
        "write_failed" => "write_failed",
        _ => "operation_failed",
    }
}
fn credential(job: &Job, pass: Option<&[u8]>) -> Result<Zeroizing<Vec<u8>>> {
    let key = job.key.as_ref().ok_or(Error("key_not_found"))?;
    let mut c = process::clean_command("/usr/bin/systemd-creds");
    let mut output = process::memfile(&[], false)?;
    let input;
    if let Some(secret) = pass {
        c.args([
            "encrypt",
            "--no-ask-password",
            "--with-key=host+tpm2",
            "--tpm2-pcrs=7",
            &format!("--name={}", credential_name(&job.user, &key.id)),
            "-",
            "-",
        ]);
        input = process::memfile(secret, true)?;
    } else {
        c.args([
            "decrypt",
            "--no-ask-password",
            "--refuse-null",
            &format!("--name={}", credential_name(&job.user, &key.id)),
            "-",
            "-",
        ]);
        input = File::open(credential_path(&job.user, &key.id))
            .map_err(|_| Error("credential_unavailable"))?;
    }
    process::wait(
        process::protected_spawn(&mut c, &[(input.as_raw_fd(), 0), (output.as_raw_fd(), 1)])?,
        30,
    )
    .map_err(|_| {
        Error(if pass.is_some() {
            "tpm_unavailable"
        } else {
            "credential_unavailable"
        })
    })?;
    output.seek(SeekFrom::Start(0))?;
    let mut bytes = Zeroizing::new(Vec::new());
    output.take(64 * 1024).read_to_end(&mut bytes)?;
    Ok(bytes)
}
#[repr(C)]
struct PamMessage {
    style: c_int,
    message: *const c_char,
}
#[repr(C)]
struct PamResponse {
    response: *mut c_char,
    code: c_int,
}
#[repr(C)]
struct PamConv {
    callback: unsafe extern "C" fn(
        c_int,
        *mut *const PamMessage,
        *mut *mut PamResponse,
        *mut c_void,
    ) -> c_int,
    data: *mut c_void,
}
#[link(name = "pam")]
unsafe extern "C" {
    fn pam_start(
        service: *const c_char,
        user: *const c_char,
        conv: *const PamConv,
        handle: *mut *mut c_void,
    ) -> c_int;
    fn pam_authenticate(handle: *mut c_void, flags: c_int) -> c_int;
    fn pam_end(handle: *mut c_void, status: c_int) -> c_int;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ProgressPhase {
    FingerprintStarting,
    FingerprintWaiting,
    FingerprintRetry,
    CredentialDecrypting,
    KeyLoading,
    PassphraseVerifying,
    CredentialSealing,
    CredentialVerifying,
    FileEncrypting,
}
fn progress(channel: &mut UnixStream, phase: ProgressPhase) -> Result<()> {
    // The only payload is a fixed enum. Raw PAM text, driver names and secrets
    // never leave the worker through this progress channel.
    serde_json::to_writer(&mut *channel, &json!({"state":"progress", "phase":phase}))
        .map_err(|_| Error("cancelled"))?;
    channel.write_all(b"\n").map_err(|_| Error("cancelled"))
}

// These C-locale phrases are emitted by upstream pam_fprintd 1.94.5.
// Waiting comes from VerifyFingerSelected after VerifyStart succeeded; a
// generic PAM_TEXT_INFO (e.g. a timeout) must not imply scanner readiness.
// Source: pam/pam_fprintd.c and pam/fingerprint-strings.h in fprintd 1.94.5.
fn fingerprint_message_phase(style: c_int, text: &str) -> Option<ProgressPhase> {
    if style == 4 {
        let request = text
            .strip_prefix("Place your ")
            .and_then(|value| value.split_once(" on "))
            .or_else(|| {
                text.strip_prefix("Swipe your ")
                    .and_then(|value| value.split_once(" across "))
            });
        if let Some((finger, reader)) = request
            && matches!(
                finger,
                "finger"
                    | "left thumb"
                    | "left index finger"
                    | "left middle finger"
                    | "left ring finger"
                    | "left little finger"
                    | "right thumb"
                    | "right index finger"
                    | "right middle finger"
                    | "right ring finger"
                    | "right little finger"
            )
            && !reader.is_empty()
            && !reader.chars().any(char::is_control)
        {
            return Some(ProgressPhase::FingerprintWaiting);
        }
    } else if style == 3
        && matches!(
            text,
            "Swipe your finger again"
                | "Place your finger on the reader again"
                | "Swipe was too short, try again"
                | "Your finger was not centered, try swiping your finger again"
                | "Your finger was not centered, try touching the sensor again"
                | "Remove your finger, and try swiping your finger again"
                | "Remove your finger, and try touching the sensor again"
                | "Swipe was too fast, try again"
                | "Finger scan was too fast, try again"
        )
    {
        return Some(ProgressPhase::FingerprintRetry);
    }
    // No-match is deliberately absent: max-tries=1 makes it terminal, not an
    // invitation to start our own authentication/retry loop.
    None
}
struct FingerprintConversation<'a> {
    channel: &'a mut UnixStream,
    failed: bool,
    channel_failed: bool,
}
unsafe extern "C" fn conversation(
    n: c_int,
    messages: *mut *const PamMessage,
    response: *mut *mut PamResponse,
    data: *mut c_void,
) -> c_int {
    const PAM_CONV_ERR: c_int = 19;
    const PAM_BUF_ERR: c_int = 5;
    if data.is_null() {
        return PAM_CONV_ERR;
    }
    let context = unsafe { &mut *data.cast::<FingerprintConversation<'_>>() };
    if response.is_null() {
        context.failed = true;
        return PAM_CONV_ERR;
    }
    unsafe {
        *response = std::ptr::null_mut();
    }
    if context.failed || n <= 0 || n > 32 || messages.is_null() {
        context.failed = true;
        return PAM_CONV_ERR;
    }
    // Validate the entire batch before emitting progress. A password prompt
    // means the installed PAM service is wrong: never answer or relay it.
    for i in 0..n {
        let message = unsafe { *messages.add(i as usize) };
        if message.is_null()
            || !matches!(unsafe { (*message).style }, 3 | 4)
            || unsafe { (*message).message.is_null() }
        {
            context.failed = true;
            return PAM_CONV_ERR;
        }
    }
    let r = unsafe {
        libc::calloc(n as usize, std::mem::size_of::<PamResponse>()).cast::<PamResponse>()
    };
    if r.is_null() {
        context.failed = true;
        return PAM_BUF_ERR;
    }
    for i in 0..n {
        let message = unsafe { &**messages.add(i as usize) };
        // PAM owns the valid C string; cap inspection without retaining a copy.
        const LIMIT: usize = 1024;
        let length = unsafe { libc::strnlen(message.message, LIMIT + 1) };
        if length > LIMIT {
            continue;
        }
        let bytes = unsafe { std::slice::from_raw_parts(message.message.cast::<u8>(), length) };
        if let Ok(text) = std::str::from_utf8(bytes)
            && let Some(phase) = fingerprint_message_phase(message.style, text)
            && progress(context.channel, phase).is_err()
        {
            context.failed = true;
            context.channel_failed = true;
            unsafe {
                libc::free(r.cast());
            }
            return PAM_CONV_ERR;
        }
    }
    unsafe {
        *response = r;
    }
    0
}
fn fingerprint_with(
    user: &User,
    channel: &mut UnixStream,
    authenticate: impl FnOnce(&CString, &PamConv) -> Result<c_int>,
) -> Result<()> {
    let name = CString::new(user.name.as_str()).map_err(|_| Error("wrong_user"))?;
    progress(channel, ProgressPhase::FingerprintStarting)?;
    let mut context = FingerprintConversation {
        channel,
        failed: false,
        channel_failed: false,
    };
    let conv = PamConv {
        callback: conversation,
        data: (&mut context as *mut FingerprintConversation<'_>).cast(),
    };
    let status = authenticate(&name, &conv);
    // Some pam_fprintd callbacks ignore conversation's return value. A broken
    // UI channel or rejected password prompt must still prevent credential use
    // even if a PAM module subsequently returns PAM_SUCCESS.
    if context.channel_failed {
        Err(Error("cancelled"))
    } else if context.failed || status? != 0 {
        Err(Error("biometric_denied"))
    } else {
        Ok(())
    }
}
fn fingerprint(user: &User, channel: &mut UnixStream) -> Result<()> {
    fingerprint_with(user, channel, |name, conv| {
        let mut handle = std::ptr::null_mut();
        let start = unsafe {
            pam_start(
                c"ssh-keys-fingerprint".as_ptr(),
                name.as_ptr(),
                conv,
                &mut handle,
            )
        };
        if start != 0 {
            return Err(Error("biometric_denied"));
        }
        let status = unsafe { pam_authenticate(handle, 0) };
        unsafe {
            pam_end(handle, status);
        }
        Ok(status)
    })
}
fn line(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>> {
    let mut result = Zeroizing::new(Vec::new());
    let mut b = [0u8; 1];
    while result.len() < 32 * 1024 {
        stream.read_exact(&mut b)?;
        if b[0] == b'\n' {
            return Ok(result);
        }
        result.push(b[0]);
    }
    Err(Error("invalid_message"))
}
pub fn run(job: Job) -> Result<Value> {
    // Reject retired/unknown jobs before display setup or any child process.
    if !matches!(
        job.operation.as_str(),
        "scan" | "sync" | "unlock" | "encrypt" | "rules.key" | "unbind"
    ) {
        return Err(Error("invalid_operation"));
    }
    if unsafe { libc::geteuid() } != 0 {
        return Err(Error("wrong_user"));
    }
    if job.operation == "scan" {
        return unprivileged(&job, b"");
    }
    let (mut channel, ui_channel) = UnixStream::pair()?;
    let display = crate::platform::connect_display(
        &job.user,
        job.display.as_ref().ok_or(Error("session_unavailable"))?,
    )?;
    channel.set_read_timeout(Some(Duration::from_secs(120)))?;
    channel.set_write_timeout(Some(Duration::from_secs(1)))?;
    let mut c = process::clean_command("/usr/lib/ssh-keys/prompt");
    c.env("HOME", &job.user.home)
        .env("USER", &job.user.name)
        .env("XDG_RUNTIME_DIR", format!("/run/user/{}", job.user.uid))
        .env("WAYLAND_SOCKET", "4")
        .env("QT_QPA_PLATFORM", "wayland")
        .env("SSH_KEYS_UI_LANGUAGE", crate::locale::system_ui_language());
    process::descriptors(
        &mut c,
        &[(ui_channel.as_raw_fd(), 3), (display.as_raw_fd(), 4)],
        Some((job.user.uid, job.user.gid)),
        false,
    )?;
    let mut ui = c.spawn()?;
    drop(ui_channel);
    drop(display);
    serde_json::to_writer(&mut channel, &job)?;
    channel.write_all(b"\n")?;
    let bytes = line(&mut channel)?;
    let answer: Answer = serde_json::from_slice(&bytes)?;
    if !answer.consent {
        let _ = ui.wait();
        return Err(Error("cancelled"));
    }
    let done = Arc::new(AtomicBool::new(false));
    let flag = done.clone();
    let mut cancel = channel.try_clone()?;
    std::thread::spawn(move || {
        let _ = line(&mut cancel);
        if !flag.load(Ordering::SeqCst) {
            unsafe {
                libc::kill(0, libc::SIGKILL);
            }
        }
    });
    let result = (|| -> Result<Value> {
        if matches!(job.operation.as_str(), "rules.key" | "unbind") {
            if answer.mode != "confirm"
                || !answer.passphrase.is_empty()
                || !answer.confirmation.is_empty()
            {
                return Err(Error("invalid_confirmation"));
            }
            return Ok(json!({"ok":true,"confirmed":true}));
        }
        let key = job.key.as_ref().ok_or(Error("key_not_found"))?;
        let mut task = job.clone();
        match job.operation.as_str() {
            "encrypt" => {
                if answer.passphrase.is_empty() {
                    return Err(Error("empty_passphrase"));
                }
                if answer.passphrase != answer.confirmation {
                    return Err(Error("confirmation_mismatch"));
                }
                progress(&mut channel, ProgressPhase::FileEncrypting)?;
                unprivileged(&task, answer.passphrase.as_bytes())
            }
            "sync" => {
                if answer.passphrase.is_empty() {
                    return Err(Error("empty_passphrase"));
                }
                task.operation = "verify".into();
                progress(&mut channel, ProgressPhase::PassphraseVerifying)?;
                unprivileged(&task, answer.passphrase.as_bytes())?;
                fingerprint(&job.user, &mut channel)?;
                progress(&mut channel, ProgressPhase::CredentialSealing)?;
                let encrypted = credential(&job, Some(answer.passphrase.as_bytes()))?;
                progress(&mut channel, ProgressPhase::CredentialVerifying)?;
                let mut check = process::clean_command("/usr/bin/systemd-creds");
                let mut roundtrip = process::memfile(&[], false)?;
                let input = process::memfile(&encrypted, true)?;
                check.args([
                    "decrypt",
                    "--no-ask-password",
                    "--refuse-null",
                    &format!("--name={}", credential_name(&job.user, &key.id)),
                    "-",
                    "-",
                ]);
                process::wait(
                    process::protected_spawn(
                        &mut check,
                        &[(input.as_raw_fd(), 0), (roundtrip.as_raw_fd(), 1)],
                    )?,
                    30,
                )
                .map_err(|_| Error("credential_unavailable"))?;
                roundtrip.seek(SeekFrom::Start(0))?;
                let verified = process::read_secret(roundtrip)?;
                if verified.as_slice() != answer.passphrase.as_bytes() {
                    return Err(Error("credential_unavailable"));
                }
                // Commit in the main service only after the uncancelled worker
                // completes. A lock/cancel cannot leave a late binding behind.
                Ok(json!({"ok":true,"sealed_credential":STANDARD.encode(encrypted.as_slice())}))
            }
            "unlock" => {
                task.operation = "load".into();
                if answer.mode == "fingerprint" {
                    if !job.bound {
                        return Err(Error("credential_unavailable"));
                    }
                    fingerprint(&job.user, &mut channel)?;
                    progress(&mut channel, ProgressPhase::CredentialDecrypting)?;
                    let secret = credential(&job, None)?;
                    progress(&mut channel, ProgressPhase::KeyLoading)?;
                    let mut value = unprivileged(&task, &secret)?;
                    value["auth_method"] = json!("fingerprint");
                    Ok(value)
                } else if answer.mode == "password" {
                    progress(&mut channel, ProgressPhase::KeyLoading)?;
                    let mut value = unprivileged(&task, answer.passphrase.as_bytes())?;
                    value["auth_method"] = json!("password");
                    Ok(value)
                } else {
                    Err(Error("invalid_mode"))
                }
            }
            _ => Err(Error("invalid_operation")),
        }
    })();
    done.store(true, Ordering::SeqCst);
    let notice = match &result {
        Ok(_) => json!({"state":"completed"}),
        Err(e) => json!({"state":"error","error_code":e.0}),
    };
    let _ = serde_json::to_writer(&mut channel, &notice);
    let _ = channel.write_all(b"\n");
    // The window owns no long-lived secrets and exits after this result.
    let _ = process::wait(ui, 3);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frames(peer: &mut UnixStream) -> Vec<Value> {
        peer.set_nonblocking(true).unwrap();
        let mut bytes = Vec::new();
        match peer.read_to_end(&mut bytes) {
            Ok(_) => (),
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock),
        }
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).unwrap())
            .collect()
    }
    fn inform(conv: &PamConv, messages: &[(c_int, &str)]) -> c_int {
        let text: Vec<_> = messages
            .iter()
            .map(|(_, text)| CString::new(*text).unwrap())
            .collect();
        let messages: Vec<_> = messages
            .iter()
            .zip(&text)
            .map(|((style, _), text)| PamMessage {
                style: *style,
                message: text.as_ptr(),
            })
            .collect();
        let mut pointers: Vec<_> = messages
            .iter()
            .map(|message| message as *const PamMessage)
            .collect();
        let mut response = std::ptr::null_mut();
        let status = unsafe {
            (conv.callback)(
                messages.len() as c_int,
                pointers.as_mut_ptr(),
                &mut response,
                conv.data,
            )
        };
        if status == 0 {
            assert!(!response.is_null());
            for i in 0..messages.len() {
                assert!(unsafe { (*response.add(i)).response.is_null() });
                assert_eq!(unsafe { (*response.add(i)).code }, 0);
            }
        } else {
            assert!(response.is_null());
        }
        unsafe {
            libc::free(response.cast());
        }
        status
    }
    fn user() -> User {
        User::get(unsafe { libc::getuid() }).unwrap()
    }

    #[test]
    fn retired_native_jobs_reject_before_display_or_secret_work() {
        let temporary = tempfile::tempdir().unwrap();
        for operation in ["rules.global", "mode", "revoke", "unknown-operation"] {
            let job = Job {
                user: User {
                    uid: 65534,
                    gid: 65534,
                    name: "retired-native-fixture".into(),
                    home: temporary.path().join("absent-home"),
                },
                operation: operation.into(),
                key: None,
                request_id: "retired-native-fixture".into(),
                reason: String::new(),
                caller: "test fixture".into(),
                rules: Rules::default(),
                fingerprint_mode: false,
                bound: false,
                wayland: String::new(),
                display: None,
                value: json!({"lifetime_seconds": 1800}),
            };
            // Runs as the ordinary test user; no display connection, key,
            // helper process, or real user state can be needed for rejection.
            assert_eq!(run(job).unwrap_err().0, "invalid_operation");
            assert_eq!(temporary.path().read_dir().unwrap().count(), 0);
        }
    }

    #[test]
    fn progress_wire_contains_only_fixed_phase_and_state_fields() {
        let (mut channel, mut peer) = UnixStream::pair().unwrap();
        for phase in [
            ProgressPhase::FingerprintStarting,
            ProgressPhase::FingerprintWaiting,
            ProgressPhase::FingerprintRetry,
            ProgressPhase::CredentialDecrypting,
            ProgressPhase::KeyLoading,
            ProgressPhase::PassphraseVerifying,
            ProgressPhase::CredentialSealing,
            ProgressPhase::CredentialVerifying,
            ProgressPhase::FileEncrypting,
        ] {
            progress(&mut channel, phase).unwrap();
            let frames = frames(&mut peer);
            assert_eq!(frames, vec![json!({"state":"progress", "phase":phase})]);
            assert_eq!(frames[0].as_object().unwrap().len(), 2);
        }
    }

    #[test]
    fn pam_progress_requires_known_text_and_correct_message_style() {
        for finger in [
            "finger",
            "left thumb",
            "left index finger",
            "left middle finger",
            "left ring finger",
            "left little finger",
            "right thumb",
            "right index finger",
            "right middle finger",
            "right ring finger",
            "right little finger",
        ] {
            for text in [
                format!("Place your {finger} on the fingerprint reader"),
                format!("Swipe your {finger} across disposable test reader"),
            ] {
                assert_eq!(
                    fingerprint_message_phase(4, &text),
                    Some(ProgressPhase::FingerprintWaiting)
                );
                assert_eq!(fingerprint_message_phase(3, &text), None);
            }
        }
        for text in [
            "Place your finger on the reader again",
            "Swipe your finger again",
            "Swipe was too short, try again",
            "Your finger was not centered, try swiping your finger again",
            "Your finger was not centered, try touching the sensor again",
            "Remove your finger, and try swiping your finger again",
            "Remove your finger, and try touching the sensor again",
            "Swipe was too fast, try again",
            "Finger scan was too fast, try again",
        ] {
            assert_eq!(
                fingerprint_message_phase(3, text),
                Some(ProgressPhase::FingerprintRetry)
            );
        }
        for text in [
            "Verification timed out",
            "Failed to match fingerprint",
            "An unknown error occurred",
            "disposable secret marker",
            "Place your password on a reader",
            "Place your finger on ",
            "Place your finger on reader\nnot a stage",
            "reader ready",
            "verify-match",
        ] {
            assert_eq!(fingerprint_message_phase(3, text), None);
            assert_eq!(fingerprint_message_phase(4, text), None);
        }
    }

    #[test]
    fn pam_conversation_drops_unknown_or_long_text_and_never_relays_reader_names() {
        let (mut channel, mut peer) = UnixStream::pair().unwrap();
        let mut context = FingerprintConversation {
            channel: &mut channel,
            failed: false,
            channel_failed: false,
        };
        let conv = PamConv {
            callback: conversation,
            data: (&mut context as *mut FingerprintConversation<'_>).cast(),
        };
        assert_eq!(
            inform(
                &conv,
                &[
                    (
                        4,
                        "Place your right index finger on disposable-private-driver-marker"
                    ),
                    (3, "Finger scan was too fast, try again"),
                    (3, "disposable-secret-marker"),
                    (4, "Verification timed out"),
                    (3, "Failed to match fingerprint")
                ]
            ),
            0
        );
        let oversized = format!("Place your finger on {}", "x".repeat(2048));
        assert_eq!(inform(&conv, &[(4, &oversized)]), 0);
        assert!(!context.failed);
        let actual = frames(&mut peer);
        assert_eq!(
            actual,
            vec![
                json!({"state":"progress", "phase":"fingerprint_waiting"}),
                json!({"state":"progress", "phase":"fingerprint_retry"})
            ]
        );
        let serialized = serde_json::to_string(&actual).unwrap();
        assert!(
            !serialized.contains("marker")
                && !serialized.contains("right index")
                && !serialized.contains("reader")
        );
    }

    #[test]
    fn pam_password_prompts_or_invalid_batches_fail_before_any_progress_and_stay_failed() {
        for invalid_style in [1, 2, 0, 5] {
            let (mut channel, mut peer) = UnixStream::pair().unwrap();
            let mut context = FingerprintConversation {
                channel: &mut channel,
                failed: false,
                channel_failed: false,
            };
            let conv = PamConv {
                callback: conversation,
                data: (&mut context as *mut FingerprintConversation<'_>).cast(),
            };
            assert_eq!(
                inform(
                    &conv,
                    &[
                        (4, "Place your finger on the fingerprint reader"),
                        (invalid_style, "disposable password prompt")
                    ]
                ),
                19
            );
            assert!(context.failed);
            assert_eq!(
                inform(&conv, &[(4, "Place your finger on the fingerprint reader")]),
                19
            );
            assert!(frames(&mut peer).is_empty());
        }
        for count in [0, 33] {
            let (mut channel, mut peer) = UnixStream::pair().unwrap();
            let mut context = FingerprintConversation {
                channel: &mut channel,
                failed: false,
                channel_failed: false,
            };
            let mut response = std::ptr::null_mut();
            assert_eq!(
                unsafe {
                    conversation(
                        count,
                        std::ptr::null_mut(),
                        &mut response,
                        (&mut context as *mut FingerprintConversation<'_>).cast(),
                    )
                },
                19
            );
            assert!(context.failed && response.is_null() && frames(&mut peer).is_empty());
        }
    }

    #[test]
    fn fingerprint_starting_never_claims_readiness_without_pam_information() {
        let (mut channel, mut peer) = UnixStream::pair().unwrap();
        let attempts = std::cell::Cell::new(0);
        for _ in 0..2 {
            fingerprint_with(&user(), &mut channel, |_, _| {
                attempts.set(attempts.get() + 1);
                assert_eq!(
                    frames(&mut peer),
                    vec![json!({"state":"progress", "phase":"fingerprint_starting"})]
                );
                Ok(0)
            })
            .unwrap();
            assert!(frames(&mut peer).is_empty());
        }
        assert_eq!(attempts.get(), 2);
        assert_eq!(
            fingerprint_with(&user(), &mut channel, |_, _| Ok(7))
                .unwrap_err()
                .0,
            "biometric_denied"
        );
        assert_eq!(
            frames(&mut peer),
            vec![json!({"state":"progress", "phase":"fingerprint_starting"})]
        );
    }

    #[test]
    fn ignored_pam_conversation_failure_cannot_authorize_credentials() {
        let (mut channel, mut peer) = UnixStream::pair().unwrap();
        let result = fingerprint_with(&user(), &mut channel, |_, conv| {
            assert_eq!(inform(conv, &[(1, "disposable password prompt")]), 19);
            Ok(0) // A module ignores conversation failure and claims success.
        });
        assert_eq!(result.unwrap_err().0, "biometric_denied");
        assert_eq!(
            frames(&mut peer),
            vec![json!({"state":"progress", "phase":"fingerprint_starting"})]
        );

        let (mut channel, peer) = UnixStream::pair().unwrap();
        // Other parallel fixtures fork. CLOEXEC closes inherited descriptors
        // only at exec, so drop(peer) alone need not disconnect this endpoint
        // immediately. Keep a duplicate deliberately: shutdown must inject the
        // same failure even while another descriptor references the socket.
        let inherited_peer = peer.try_clone().unwrap();
        let result = fingerprint_with(&user(), &mut channel, |_, conv| {
            peer.shutdown(std::net::Shutdown::Both).unwrap();
            drop(peer);
            assert_eq!(
                inform(conv, &[(4, "Place your finger on the fingerprint reader")]),
                19
            );
            Ok(0)
        });
        assert_eq!(result.unwrap_err().0, "cancelled");
        drop(inherited_peer);
    }

    #[test]
    fn disconnected_progress_channel_prevents_authentication_from_starting() {
        let (mut channel, peer) = UnixStream::pair().unwrap();
        let inherited_peer = peer.try_clone().unwrap();
        peer.shutdown(std::net::Shutdown::Both).unwrap();
        drop(peer);
        let result = fingerprint_with(&user(), &mut channel, |_, _| {
            panic!("authentication must not start after the protected window disconnected")
        });
        assert_eq!(result.unwrap_err().0, "cancelled");
        drop(inherited_peer);
    }
}
