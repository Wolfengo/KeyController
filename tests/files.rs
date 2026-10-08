use serde_json::{Value, json};
use ssh_keys::{
    keys::{self, Snapshot},
    platform::User,
    process,
    state::Rules,
    worker::Job,
};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    os::{
        fd::AsRawFd,
        unix::fs::{PermissionsExt, symlink},
    },
    path::Path,
    process::{Command, Stdio},
};

fn fixture(algorithm: &str) -> (tempfile::TempDir, User, keys::Key) {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join(".ssh")).unwrap();
    fs::set_permissions(dir.path().join(".ssh"), fs::Permissions::from_mode(0o700)).unwrap();
    let path = dir.path().join(".ssh/key");
    assert!(
        Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", algorithm, "-N", "", "-f"])
            .arg(&path)
            .status()
            .unwrap()
            .success()
    );
    let mut user = User::get(unsafe { libc::getuid() }).unwrap();
    user.home = dir.path().into();
    let key = keys::scan(&dir.path().join(".ssh"), user.uid)
        .unwrap()
        .remove(0);
    (dir, user, key)
}
fn task(user: &User, key: &keys::Key, action: &str, pass: &[u8]) -> Value {
    let job = Job {
        user: user.clone(),
        operation: action.into(),
        key: Some(key.clone()),
        request_id: "test".into(),
        reason: String::new(),
        caller: "test".into(),
        rules: Rules::default(),
        fingerprint_mode: false,
        bound: false,
        wayland: String::new(),
        display: None,
        value: Value::Null,
    };
    let input = process::memfile(&serde_json::to_vec(&job).unwrap(), true).unwrap();
    let secret = process::memfile(pass, true).unwrap();
    let mut out = process::memfile(&[], false).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_ssh-keysd"));
    command
        .arg("--file-task")
        .stdin(Stdio::from(input))
        .stdout(Stdio::from(out.try_clone().unwrap()))
        .stderr(Stdio::piped());
    let result = process::protected_spawn(&mut command, &[(secret.as_raw_fd(), 4)])
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(result.status.success());
    assert!(result.stderr.is_empty());
    out.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    out.read_to_end(&mut bytes).unwrap();
    if !pass.is_empty() {
        assert!(!bytes.windows(pass.len()).any(|b| b == pass));
    }
    serde_json::from_slice(&bytes).unwrap()
}
#[test]
fn encrypt_ed25519_rsa_ecdsa_preserves_identity_and_no_backup() {
    for algorithm in ["ed25519", "rsa", "ecdsa"] {
        let (dir, user, key) = fixture(algorithm);
        let public = fs::read(key.path.with_extension("pub")).unwrap();
        let fingerprint = key.fingerprint.clone();
        assert_eq!(
            task(&user, &key, "encrypt", b"test-only-passphrase")["committed"],
            true
        );
        let after = keys::scan(&dir.path().join(".ssh"), user.uid).unwrap();
        assert_eq!(after.len(), 1);
        assert!(after[0].encrypted);
        assert_eq!(after[0].fingerprint, fingerprint);
        assert_eq!(fs::read(key.path.with_extension("pub")).unwrap(), public);
        assert_eq!(fs::read_dir(dir.path().join(".ssh")).unwrap().count(), 2);
        assert_eq!(
            task(&user, &after[0], "verify", b"test-only-passphrase")["ok"],
            true
        );
        assert!(
            task(&user, &after[0], "verify", b"wrong-test-passphrase")["error_code"].is_string()
        );
    }
}
#[test]
fn empty_password_and_write_failure_leave_original() {
    let (dir, user, key) = fixture("ed25519");
    let before = fs::read(&key.path).unwrap();
    assert_eq!(
        task(&user, &key, "encrypt", b"")["error_code"],
        "empty_passphrase"
    );
    assert_eq!(fs::read(&key.path).unwrap(), before);
    assert_eq!(
        task(&user, &key, "encrypt", &vec![b'x'; 1024])["error_code"],
        "invalid_passphrase"
    );
    assert_eq!(fs::read(&key.path).unwrap(), before);
    fs::set_permissions(dir.path().join(".ssh"), fs::Permissions::from_mode(0o500)).unwrap();
    assert!(task(&user, &key, "encrypt", b"test-only-password")["error_code"].is_string());
    assert_eq!(fs::read(&key.path).unwrap(), before);
    fs::set_permissions(dir.path().join(".ssh"), fs::Permissions::from_mode(0o700)).unwrap();
}
#[test]
fn symlink_target_preserved_hardlinks_and_outside_refused() {
    let (dir, user, key) = fixture("ed25519");
    let root = dir.path().join(".ssh");
    let link = root.join("alias");
    symlink("key", &link).unwrap();
    let mut alias = key.clone();
    alias.path = link.clone();
    assert_eq!(
        task(&user, &alias, "encrypt", b"test-only-password")["ok"],
        true
    );
    assert!(
        fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
    let (other, user3, key3) = fixture("ed25519");
    fs::hard_link(&key3.path, other.path().join(".ssh/hard")).unwrap();
    assert_eq!(
        task(&user3, &key3, "encrypt", b"test-only-password")["error_code"],
        "multiple_hard_links"
    );
    fs::remove_file(&link).unwrap();
    symlink(&key3.path, &link).unwrap();
    assert_eq!(
        task(&user, &alias, "encrypt", b"test-only-password")["error_code"],
        "outside_ssh_directory"
    );
}
#[test]
fn file_conflict_cannot_replace_changed_source() {
    let (dir, user, key) = fixture("ed25519");
    let root = dir.path().join(".ssh");
    let mut snap = Snapshot::open(&root, &key.path, user.uid, true).unwrap();
    fs::write(&key.path, b"concurrent replacement").unwrap();
    assert_eq!(snap.unchanged().unwrap_err().0, "file_conflict");
    assert_eq!(fs::read(&key.path).unwrap(), b"concurrent replacement");
    let mut snapshot_bytes = Vec::new();
    snap.memory.read_to_end(&mut snapshot_bytes).unwrap();
    assert!(keys::parse(&snapshot_bytes).is_ok());
    use std::io::Write;
    assert!(snap.memory.write_all(b"x").is_err());
}
#[test]
fn discovery_ignores_nonkeys_marks_copies_and_formats() {
    let (dir, user, key) = fixture("ed25519");
    let root = dir.path().join(".ssh");
    fs::create_dir(root.join("nested")).unwrap();
    fs::copy(&key.path, root.join("nested/copy")).unwrap();
    fs::write(root.join("config"), "Host example\n").unwrap();
    fs::write(root.join("known_hosts"), "example ssh-ed25519 AAAA\n").unwrap();
    fs::write(
        root.join("legacy"),
        "-----BEGIN RSA PRIVATE KEY-----\nnot supported\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap();
    let keys = keys::scan(&root, user.uid).unwrap();
    assert_eq!(keys.len(), 3);
    let supported: Vec<_> = keys.iter().filter(|k| k.id == key.id).collect();
    assert_eq!(supported.len(), 2);
    assert!(supported.iter().all(|k| k.unencrypted_copies.len() == 2));
    assert!(
        keys.iter()
            .any(|k| k.unavailable.as_deref() == Some("unsupported_format"))
    );
    assert_eq!(keys::resolve(&keys, "key").unwrap().id, key.id);
}
#[test]
fn malformed_public_envelopes_are_bounded() {
    for bytes in [
        b"".as_slice(),
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n",
        b"ssh-ed25519 AAAA",
    ] {
        assert!(keys::parse(bytes).is_err());
    }
    let mut value: &[u8] = &[255, 255, 255, 255];
    assert!(keys::field(&mut value).is_err());
    let v = json!({"api_version":1,"action":"keys.unlock","passphrase":"not-accepted"});
    assert!(serde_json::from_value::<ssh_keys::protocol::Command>(v).is_err());
    assert!(Path::new(env!("CARGO_BIN_EXE_ssh-keysd")).is_file());
}

#[test]
fn cancelling_a_running_keygen_never_replaces_plaintext() {
    use std::time::{Duration, Instant};
    let (_dir, user, key) = fixture("ed25519");
    let before = fs::read(&key.path).unwrap();
    let job = Job {
        user: user.clone(),
        operation: "encrypt".into(),
        key: Some(key.clone()),
        request_id: "cancel-test".into(),
        reason: String::new(),
        caller: "test".into(),
        rules: Rules::default(),
        fingerprint_mode: false,
        bound: false,
        wayland: String::new(),
        display: None,
        value: Value::Null,
    };
    let input = process::memfile(&serde_json::to_vec(&job).unwrap(), true).unwrap();
    let secret = process::memfile(b"disposable-test-password", true).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_ssh-keysd"));
    command
        .arg("--file-task")
        .stdin(Stdio::from(input))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    process::descriptors(&mut command, &[], None, true).unwrap();
    let mut child = process::protected_spawn(&mut command, &[(secret.as_raw_fd(), 4)]).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        assert!(
            Instant::now() < until,
            "did not observe keygen encryption phase"
        );
        let children =
            fs::read_to_string(format!("/proc/{}/task/{}/children", child.id(), child.id()))
                .unwrap_or_default();
        let changing = children.split_whitespace().any(|pid| {
            fs::read(format!("/proc/{pid}/cmdline"))
                .is_ok_and(|args| args.split(|b| *b == 0).any(|arg| arg == b"-p"))
        });
        if changing {
            break;
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    assert!(!child.wait().unwrap().success());
    assert_eq!(fs::read(&key.path).unwrap(), before);
}

#[test]
fn encrypted_key_loads_through_internal_askpass_and_expires_in_disposable_agent() {
    use std::time::{Duration, Instant};
    struct TestAgent(std::process::Child);
    impl Drop for TestAgent {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let (dir, user, key) = fixture("ed25519");
    let pass = b"disposable-internal-askpass";
    assert_eq!(task(&user, &key, "encrypt", pass)["ok"], true);
    let socket = dir.path().join("agent.sock");
    let _agent = TestAgent(
        Command::new("/usr/bin/ssh-agent")
            .args(["-D", "-a"])
            .arg(&socket)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while !socket.exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    let snap = Snapshot::open(&dir.path().join(".ssh"), &key.path, user.uid, false).unwrap();
    process::load_key_snapshot(&snap.memory, pass, &socket, 2).unwrap();
    let loaded = ssh_keys::agent::list(&socket).unwrap();
    assert_eq!(loaded.len(), 1);
    assert!(loaded.contains_key(&key.id));
    std::thread::sleep(Duration::from_secs(3));
    assert!(ssh_keys::agent::list(&socket).unwrap().is_empty());
}

#[test]
fn single_decryption_load_checks_identity_and_rejects_wrong_secret_without_retries() {
    use base64::{Engine, engine::general_purpose::STANDARD};
    use std::time::{Duration, Instant};
    struct Agent(std::process::Child);
    impl Drop for Agent {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    for algorithm in ["ed25519", "rsa", "ecdsa"] {
        let (dir, user, key) = fixture(algorithm);
        let pass = b"disposable-single-load-fixture";
        assert_eq!(task(&user, &key, "encrypt", pass)["ok"], true);
        let snap = Snapshot::open(&dir.path().join(".ssh"), &key.path, user.uid, false).unwrap();
        let socket = dir.path().join("agent.sock");
        let _agent = Agent(
            Command::new("/usr/bin/ssh-agent")
                .args(["-D", "-a"])
                .arg(&socket)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let until = Instant::now() + Duration::from_secs(3);
        while !socket.exists() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(10));
        }

        let began = Instant::now();
        snap.verify(pass).unwrap();
        process::load_key_snapshot(&snap.memory, pass, &socket, 60).unwrap();
        let duplicate_ms = began.elapsed().as_millis();
        assert_eq!(
            ssh_keys::agent::list(&socket)
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            vec![&key.id]
        );
        ssh_keys::agent::remove_key(&socket, &key).unwrap();
        let began = Instant::now();
        process::load_key_snapshot(&snap.memory, pass, &socket, 60).unwrap();
        let single_ms = began.elapsed().as_millis();
        assert_eq!(
            ssh_keys::agent::list(&socket)
                .unwrap()
                .keys()
                .collect::<Vec<_>>(),
            vec![&key.id]
        );
        ssh_keys::agent::remove_key(&socket, &key).unwrap();
        eprintln!(
            "SYNTHETIC_LOAD_TIMING {algorithm}: duplicate_ms={duplicate_ms} single_ms={single_ms}"
        );

        let began = Instant::now();
        assert_eq!(
            process::load_key_snapshot(&snap.memory, b"wrong-disposable-secret", &socket, 60)
                .unwrap_err()
                .0,
            "unlock_failed"
        );
        // This used to repeat the same wrong answer until the 30s process timeout.
        assert!(
            began.elapsed() < Duration::from_secs(10),
            "askpass retried a rejected secret"
        );
        assert!(ssh_keys::agent::list(&socket).unwrap().is_empty());
        assert_eq!(
            process::load_key_snapshot(&snap.memory, b"", &socket, 60)
                .unwrap_err()
                .0,
            "empty_passphrase"
        );
        assert_eq!(
            process::load_key_snapshot(&snap.memory, b"invalid\nsecret", &socket, 60)
                .unwrap_err()
                .0,
            "invalid_passphrase"
        );

        // A valid but unrelated public envelope must not make ssh-add load the
        // original encrypted private identity, even with the correct password.
        let (_other_dir, _other_user, other) = fixture(algorithm);
        let text = fs::read_to_string(&key.path).unwrap();
        let body: String = text
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let mut raw = STANDARD.decode(body).unwrap();
        let mut rest = &raw[b"openssh-key-v1\0".len()..];
        for _ in 0..3 {
            keys::field(&mut rest).unwrap();
        }
        assert_eq!(&rest[..4], &[0, 0, 0, 1]);
        rest = &rest[4..];
        let offset = raw.len() - rest.len() + 4;
        let public_len = keys::field(&mut rest).unwrap().len();
        let replacement = STANDARD.decode(&other.public_blob).unwrap();
        assert_eq!(public_len, replacement.len());
        raw[offset..offset + public_len].copy_from_slice(&replacement);
        let armor = format!(
            "-----BEGIN OPENSSH PRIVATE KEY-----\n{}\n-----END OPENSSH PRIVATE KEY-----\n",
            STANDARD.encode(&raw)
        );
        assert_eq!(keys::parse(armor.as_bytes()).unwrap().fingerprint, other.id);
        let forged = process::memfile(armor.as_bytes(), true).unwrap();
        assert_eq!(
            process::load_key_snapshot(&forged, pass, &socket, 60)
                .unwrap_err()
                .0,
            "unlock_failed"
        );
        assert!(ssh_keys::agent::list(&socket).unwrap().is_empty());
    }
}
