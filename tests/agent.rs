use ssh_keys::agent::{self, Guard};
use std::{
    os::unix::net::{UnixListener, UnixStream},
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

struct Agent(Child);
impl Drop for Agent {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn managed_add_tracks_ambiguous_exchange_separately_from_definitive_replies() {
    for reply in [None, Some(5), Some(6)] {
        let dir = tempfile::tempdir().unwrap();
        let backend = dir.path().join("backend");
        let public = dir.path().join("public");
        let listener = UnixListener::bind(&backend).unwrap();
        let guard = Arc::new(Mutex::new(Guard {
            worker_group: Some(unsafe { libc::getpgrp() }),
            ..Default::default()
        }));
        agent::proxy_at(
            UnixListener::bind(&public).unwrap(),
            unsafe { libc::getuid() },
            backend,
            guard.clone(),
        );
        let responder = std::thread::spawn(move || {
            let (mut connection, _) = listener.accept().unwrap();
            assert_eq!(agent::packet(&mut connection).unwrap().as_slice(), [17]);
            if let Some(code) = reply {
                agent::write(&mut connection, &[code]).unwrap();
            }
        });
        let result = agent::exchange(&public, &[17]);
        responder.join().unwrap();
        let guard = guard.lock().unwrap();
        assert_eq!(guard.managed_add_uncertain, reply.is_none());
        assert_eq!(guard.managed_added_at.is_some(), reply == Some(6));
        assert_eq!(result.is_ok(), reply.is_some());
    }
}

#[test]
fn retired_worker_group_cannot_add_through_a_new_connection() {
    let dir = tempfile::tempdir().unwrap();
    let backend = dir.path().join("backend");
    let public = dir.path().join("public");
    let listener = UnixListener::bind(&backend).unwrap();
    let mut guard = Guard::default();
    guard
        .retired_worker_groups
        .insert(unsafe { libc::getpgrp() });
    agent::proxy_at(
        UnixListener::bind(&public).unwrap(),
        unsafe { libc::getuid() },
        backend,
        Arc::new(Mutex::new(guard)),
    );
    let responder = std::thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        connection
            .set_read_timeout(Some(Duration::from_millis(200)))
            .unwrap();
        assert!(agent::packet(&mut connection).is_err());
    });
    assert_eq!(agent::exchange(&public, &[17]).unwrap().as_slice(), [5]);
    responder.join().unwrap();
}

#[test]
fn old_connection_cannot_forward_after_backend_generation_changes() {
    let dir = tempfile::tempdir().unwrap();
    let backend = dir.path().join("backend");
    let public = dir.path().join("public");
    let backend_listener = UnixListener::bind(&backend).unwrap();
    let guard = Arc::new(Mutex::new(Guard::default()));
    agent::proxy_at(
        UnixListener::bind(&public).unwrap(),
        unsafe { libc::getuid() },
        backend,
        guard.clone(),
    );
    let backend_thread = std::thread::spawn(move || {
        let (mut connection, _) = backend_listener.accept().unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        assert_eq!(agent::packet(&mut connection).unwrap().as_slice(), [11]);
        agent::write(&mut connection, &[12, 0, 0, 0, 0]).unwrap();
        assert!(agent::packet(&mut connection).is_err());
    });
    let mut client = UnixStream::connect(&public).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    agent::write(&mut client, &[11]).unwrap();
    assert_eq!(
        agent::packet(&mut client).unwrap().as_slice(),
        [12, 0, 0, 0, 0]
    );
    guard.lock().unwrap().generation += 1;
    agent::write(&mut client, &[17]).unwrap();
    assert!(agent::packet(&mut client).is_err());
    backend_thread.join().unwrap();
}

#[test]
fn exited_peer_cannot_replay_add_waiting_in_accept_backlog() {
    let dir = tempfile::tempdir().unwrap();
    let backend = dir.path().join("backend");
    let public = dir.path().join("public");
    let backend_listener = UnixListener::bind(&backend).unwrap();
    backend_listener.set_nonblocking(true).unwrap();
    let frontend_listener = UnixListener::bind(&public).unwrap();
    // The packet reaches the listening socket before the proxy accepts it;
    // the process is already reaped when a new backend generation serves it.
    assert!(
        Command::new("/usr/bin/python3")
            .args([
                "-c",
                "import socket,sys; s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(bytes([0,0,0,1,17]))",
            ])
            .arg(&public)
            .status()
            .unwrap()
            .success()
    );
    agent::proxy_at(
        frontend_listener,
        unsafe { libc::getuid() },
        backend,
        Arc::new(Mutex::new(Guard {
            generation: 1,
            ..Default::default()
        })),
    );
    let deadline = Instant::now() + Duration::from_millis(500);
    loop {
        match backend_listener.accept() {
            Ok((mut connection, _)) => {
                connection
                    .set_read_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                assert!(agent::packet(&mut connection).is_err());
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => panic!("backend accept failed: {error}"),
        }
    }
}

#[test]
fn sleep_marker_blocks_add_on_existing_and_new_connections_before_server_refresh() {
    let directory = tempfile::tempdir().unwrap();
    let backend = directory.path().join("backend");
    let public = directory.path().join("public");
    let marker = directory.path().join("sleep-marker");
    let backend_listener = UnixListener::bind(&backend).unwrap();
    let guard = Arc::new(Mutex::new(Guard {
        sleep_marker: Some(marker.clone()),
        ..Default::default()
    }));
    agent::proxy_at(
        UnixListener::bind(&public).unwrap(),
        unsafe { libc::getuid() },
        backend,
        guard.clone(),
    );
    let responder = std::thread::spawn(move || {
        let (mut prior, _) = backend_listener.accept().unwrap();
        prior
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        assert_eq!(agent::packet(&mut prior).unwrap().as_slice(), [11]);
        agent::write(&mut prior, &[12, 0, 0, 0, 0]).unwrap();
        let (mut fresh, _) = backend_listener.accept().unwrap();
        fresh
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        // Neither ADD is forwarded even though the event loop has not yet
        // changed blocked/generation on either connection.
        assert!(agent::packet(&mut prior).is_err());
        assert!(agent::packet(&mut fresh).is_err());
    });
    let mut prior = UnixStream::connect(&public).unwrap();
    prior
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    agent::write(&mut prior, &[11]).unwrap();
    assert_eq!(
        agent::packet(&mut prior).unwrap().as_slice(),
        [12, 0, 0, 0, 0]
    );
    std::fs::write(&marker, b"disposable marker").unwrap();
    assert!(!guard.lock().unwrap().blocked);
    assert_eq!(guard.lock().unwrap().generation, 0);
    agent::write(&mut prior, &[17]).unwrap();
    assert_eq!(agent::packet(&mut prior).unwrap().as_slice(), [5]);
    assert_eq!(agent::exchange(&public, &[17]).unwrap().as_slice(), [5]);
    drop(prior);
    responder.join().unwrap();
}

#[test]
fn sleep_marker_blocks_live_peer_add_already_waiting_in_accept_backlog() {
    let directory = tempfile::tempdir().unwrap();
    let backend = directory.path().join("backend");
    let public = directory.path().join("public");
    let marker = directory.path().join("sleep-marker");
    let backend_listener = UnixListener::bind(&backend).unwrap();
    let frontend_listener = UnixListener::bind(&public).unwrap();
    // Unlike the exited-peer test, this caller stays alive. Its ADD was queued
    // before the proxy even started, while the persistent sleep fence exists.
    let mut queued = UnixStream::connect(&public).unwrap();
    queued
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    agent::write(&mut queued, &[17]).unwrap();
    std::fs::write(&marker, b"disposable marker").unwrap();
    let guard = Arc::new(Mutex::new(Guard {
        sleep_marker: Some(marker),
        ..Default::default()
    }));
    agent::proxy_at(frontend_listener, unsafe { libc::getuid() }, backend, guard);
    assert_eq!(agent::packet(&mut queued).unwrap().as_slice(), [5]);
    drop(queued);
    let (mut connection, _) = backend_listener.accept().unwrap();
    connection
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    assert!(agent::packet(&mut connection).is_err());
}

#[test]
fn proxy_session_eligibility_preserves_loaded_keys_manual_revoke_and_agent_ttl() {
    let dir = tempfile::tempdir().unwrap();
    let backend = dir.path().join("backend");
    let public = dir.path().join("public");
    let key = dir.path().join("key");
    let _agent = Agent(
        Command::new("/usr/bin/ssh-agent")
            .args(["-D", "-a"])
            .arg(&backend)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    while !backend.exists() {
        assert!(Instant::now() < deadline);
        std::thread::sleep(Duration::from_millis(10));
    }
    assert!(
        Command::new("/usr/bin/ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-f"])
            .arg(&key)
            .status()
            .unwrap()
            .success()
    );
    let listener = UnixListener::bind(&public).unwrap();
    let guard = Arc::new(Mutex::new(Guard::default()));
    agent::proxy_at(
        listener,
        unsafe { libc::getuid() },
        backend.clone(),
        guard.clone(),
    );
    let add = |ttl: bool| {
        let mut c = Command::new("/usr/bin/ssh-add");
        c.env("SSH_AUTH_SOCK", &public)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if ttl {
            c.args(["-t", "2"]);
        }
        c.arg(&key).status().unwrap().success()
    };
    assert!(add(false));
    assert_eq!(agent::list(&public).unwrap().len(), 1);
    assert!(guard.lock().unwrap().lifetimes.is_empty());
    let mut signer = Command::new("/usr/bin/ssh-keygen")
        .args(["-Y", "sign", "-n", "ssh-keys-test", "-f"])
        .arg(key.with_extension("pub"))
        .env("SSH_AUTH_SOCK", &public)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    use std::io::Write;
    signer
        .stdin
        .take()
        .unwrap()
        .write_all(b"disposable signing test")
        .unwrap();
    assert!(signer.wait().unwrap().success());
    guard.lock().unwrap().blocked = true;
    // An unavailable/locked session prevents additions, but the existing key
    // remains listed and usable until manual revocation or OpenSSH expiry.
    assert!(!add(false));
    assert_eq!(agent::list(&public).unwrap().len(), 1);
    assert!(
        Command::new("/usr/bin/ssh-add")
            .arg("-T")
            .arg(key.with_extension("pub"))
            .env("SSH_AUTH_SOCK", &public)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap()
            .success()
    );
    let keys = agent::list(&backend).unwrap();
    for blob in keys.values() {
        agent::remove(&backend, blob).unwrap();
    }
    assert!(!add(false));
    assert!(agent::list(&public).unwrap().is_empty());
    guard.lock().unwrap().blocked = false;
    assert!(add(true));
    assert_eq!(agent::list(&public).unwrap().len(), 1);
    std::thread::sleep(Duration::from_secs(3));
    assert!(agent::list(&public).unwrap().is_empty());
}

struct LifetimeFixture {
    _directory: tempfile::TempDir,
    _agent: Agent,
    backend: std::path::PathBuf,
    public: std::path::PathBuf,
    keys: Vec<(std::path::PathBuf, String, Vec<u8>)>,
    guard: Arc<Mutex<Guard>>,
}
impl LifetimeFixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let backend = directory.path().join("backend");
        let public = directory.path().join("public");
        let agent = Agent(
            Command::new("/usr/bin/ssh-agent")
                .args(["-D", "-a"])
                .arg(&backend)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap(),
        );
        let until = Instant::now() + Duration::from_secs(3);
        while !backend.exists() {
            assert!(Instant::now() < until);
            std::thread::sleep(Duration::from_millis(10));
        }
        let mut keys = Vec::new();
        for name in ["a", "b", "c"] {
            let path = directory.path().join(name);
            assert!(
                Command::new("/usr/bin/ssh-keygen")
                    .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                    .arg(&path)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status()
                    .unwrap()
                    .success()
            );
            let header = ssh_keys::keys::parse(&std::fs::read(&path).unwrap()).unwrap();
            use base64::Engine;
            let blob = base64::engine::general_purpose::STANDARD
                .decode(header.public_blob)
                .unwrap();
            keys.push((path, header.fingerprint, blob));
        }
        let guard = Arc::new(Mutex::new(Guard::default()));
        agent::proxy_at(
            UnixListener::bind(&public).unwrap(),
            unsafe { libc::getuid() },
            backend.clone(),
            guard.clone(),
        );
        Self {
            _directory: directory,
            _agent: agent,
            backend,
            public,
            keys,
            guard,
        }
    }
    fn add(&self, key: usize, managed: Option<u32>) {
        {
            let mut guard = self.guard.lock().unwrap();
            guard.worker_group = managed.map(|_| unsafe { libc::getpgrp() });
            guard.managed_key = managed.map(|seconds| (self.keys[key].1.clone(), seconds));
        }
        let mut command = Command::new("/usr/bin/ssh-add");
        if let Some(seconds) = managed.filter(|seconds| *seconds > 0) {
            command.args(["-t", &seconds.to_string()]);
        }
        assert!(
            command
                .arg(&self.keys[key].0)
                .env("SSH_AUTH_SOCK", &self.public)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
        self.guard.lock().unwrap().worker_group = None;
        self.guard.lock().unwrap().managed_key = None;
    }
    fn sign(&self, key: usize) -> ssh_keys::Result<zeroize::Zeroizing<Vec<u8>>> {
        let mut message = vec![13];
        field(&mut message, &self.keys[key].2);
        field(&mut message, b"disposable deadline signing fixture");
        message.extend_from_slice(&0u32.to_be_bytes());
        agent::exchange(&self.public, &message)
    }
    fn lock(&self, lock: bool) {
        let mut message = vec![if lock { 22 } else { 23 }];
        field(&mut message, b"disposable agent lock fixture");
        assert_eq!(
            agent::exchange(&self.public, &message).unwrap().as_slice(),
            [6]
        );
    }
}
fn field(message: &mut Vec<u8>, value: &[u8]) {
    message.extend_from_slice(&(value.len() as u32).to_be_bytes());
    message.extend_from_slice(value);
}

#[test]
fn managed_deadline_survives_external_add_and_is_enforced_before_sign_without_tick() {
    let fixture = LifetimeFixture::new();
    fixture.add(0, Some(60));
    fixture.add(1, Some(120));
    let original = fixture.guard.lock().unwrap().lifetimes.clone();
    fixture.add(2, None);
    fixture.add(0, None); // Original OpenSSH now has an unlimited replacement.
    assert_eq!(fixture.guard.lock().unwrap().lifetimes, original);
    assert_eq!(fixture.sign(0).unwrap()[0], 14);
    // Model the suspend-aware clock passing the deadline while the helper is
    // busy. Keep the displayed wall-clock timestamp untouched and in the future.
    fixture
        .guard
        .lock()
        .unwrap()
        .lifetimes
        .get_mut(&fixture.keys[0].1)
        .unwrap()
        .deadline = Some(
        agent::boot_now()
            .unwrap()
            .saturating_sub(Duration::from_secs(1)),
    );
    assert_eq!(fixture.sign(0).unwrap().as_slice(), [5]);
    let loaded = agent::list(&fixture.backend).unwrap();
    assert!(!loaded.contains_key(&fixture.keys[0].1));
    assert!(loaded.contains_key(&fixture.keys[1].1) && loaded.contains_key(&fixture.keys[2].1));
    let guard = fixture.guard.lock().unwrap();
    assert!(!guard.reset_required);
    assert_eq!(
        guard.lifetimes.get(&fixture.keys[1].1),
        original.get(&fixture.keys[1].1)
    );
    assert!(!guard.lifetimes.contains_key(&fixture.keys[0].1));
}

#[test]
fn removal_affects_only_its_key_and_external_reload_does_not_resurrect_window() {
    let fixture = LifetimeFixture::new();
    fixture.add(0, Some(60));
    fixture.add(1, Some(120));
    let original = fixture.guard.lock().unwrap().lifetimes[&fixture.keys[0].1].clone();
    agent::remove(&fixture.public, &fixture.keys[1].2).unwrap();
    fixture.add(1, None); // No metadata poll between REMOVE and ADD.
    let guard = fixture.guard.lock().unwrap();
    assert_eq!(guard.lifetimes[&fixture.keys[0].1], original);
    assert!(!guard.lifetimes.contains_key(&fixture.keys[1].1));
    drop(guard);
    assert!(
        agent::list(&fixture.backend)
            .unwrap()
            .contains_key(&fixture.keys[1].1)
    );
    assert_eq!(
        agent::exchange(&fixture.public, &[19]).unwrap().as_slice(),
        [6]
    );
    assert!(fixture.guard.lock().unwrap().lifetimes.is_empty());
}

#[test]
fn lock_unlock_preserves_window_and_expired_locked_agent_fences_all_packets() {
    let fixture = LifetimeFixture::new();
    fixture.add(0, Some(60));
    let original = fixture.guard.lock().unwrap().lifetimes[&fixture.keys[0].1].clone();
    fixture.lock(true);
    assert!(agent::list(&fixture.public).unwrap().is_empty());
    assert!(fixture.guard.lock().unwrap().agent_locked);
    fixture.lock(false);
    assert_eq!(
        fixture.guard.lock().unwrap().lifetimes[&fixture.keys[0].1],
        original
    );
    assert_eq!(fixture.sign(0).unwrap()[0], 14);
    fixture.lock(true);
    fixture
        .guard
        .lock()
        .unwrap()
        .lifetimes
        .get_mut(&fixture.keys[0].1)
        .unwrap()
        .deadline = Some(
        agent::boot_now()
            .unwrap()
            .saturating_sub(Duration::from_secs(1)),
    );
    assert!(fixture.sign(0).is_err());
    let guard = fixture.guard.lock().unwrap();
    assert!(guard.reset_required && guard.blocked && guard.agent_locked);
    assert!(guard.lifetimes.contains_key(&fixture.keys[0].1));
    drop(guard);
    // Even a new connection and a mistakenly cleared ordinary session flag
    // cannot bypass the fence while the event loop has not reset the backend.
    fixture.guard.lock().unwrap().blocked = false;
    assert!(agent::exchange(&fixture.public, &[11]).is_err());
}

#[test]
fn external_add_marks_unlimited_unknown_but_new_managed_add_starts_exact_window() {
    let fixture = LifetimeFixture::new();
    fixture.add(0, Some(0));
    fixture.add(1, Some(60));
    let finite = fixture.guard.lock().unwrap().lifetimes[&fixture.keys[1].1].clone();
    fixture.add(2, None);
    assert!(
        !fixture
            .guard
            .lock()
            .unwrap()
            .lifetimes
            .contains_key(&fixture.keys[0].1)
    );
    assert_eq!(
        fixture.guard.lock().unwrap().lifetimes[&fixture.keys[1].1],
        finite
    );
    agent::remove(&fixture.public, &fixture.keys[0].2).unwrap();
    let before = agent::boot_now().unwrap();
    fixture.add(0, Some(60));
    let after = agent::boot_now().unwrap();
    let guard = fixture.guard.lock().unwrap();
    let grant = &guard.lifetimes[&fixture.keys[0].1];
    assert!(grant.deadline.unwrap() >= before + Duration::from_secs(60));
    assert!(grant.deadline.unwrap() <= after + Duration::from_secs(60));
    assert!(grant.expires_at.is_some());
    assert_eq!(guard.lifetimes[&fixture.keys[1].1], finite);
}

#[test]
fn proxy_keeps_extension_and_sign_packets_opaque_on_one_backend_connection() {
    let directory = tempfile::tempdir().unwrap();
    let backend = directory.path().join("backend");
    let public = directory.path().join("public");
    let listener = UnixListener::bind(&backend).unwrap();
    agent::proxy_at(
        UnixListener::bind(&public).unwrap(),
        unsafe { libc::getuid() },
        backend,
        Arc::new(Mutex::new(Guard::default())),
    );
    let extension = [
        27, 0, 0, 0, 7, b'f', b'i', b'x', b't', b'u', b'r', b'e', 0, 1, 2,
    ];
    let signing = [13, 4, 3, 2, 1, 0];
    let responder = std::thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        for request in [&extension[..], &signing[..]] {
            assert_eq!(agent::packet(&mut connection).unwrap().as_slice(), request);
            agent::write(&mut connection, &[5]).unwrap();
        }
    });
    let mut connection = UnixStream::connect(&public).unwrap();
    for request in [&extension[..], &signing[..]] {
        agent::write(&mut connection, request).unwrap();
        assert_eq!(agent::packet(&mut connection).unwrap().as_slice(), [5]);
    }
    responder.join().unwrap();
}

#[test]
fn ambiguous_external_add_preserves_finite_window_without_claiming_unlimited_ttl() {
    let directory = tempfile::tempdir().unwrap();
    let backend = directory.path().join("backend");
    let public = directory.path().join("public");
    let listener = UnixListener::bind(&backend).unwrap();
    let finite = agent::Lifetime::new(60).unwrap();
    let mut initial = Guard::default();
    initial.lifetimes.insert("finite".into(), finite.clone());
    initial
        .lifetimes
        .insert("unlimited".into(), agent::Lifetime::new(0).unwrap());
    let guard = Arc::new(Mutex::new(initial));
    agent::proxy_at(
        UnixListener::bind(&public).unwrap(),
        unsafe { libc::getuid() },
        backend,
        guard.clone(),
    );
    let responder = std::thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        assert_eq!(agent::packet(&mut connection).unwrap().as_slice(), [17]);
        // No reply: the caller cannot prove whether OpenSSH committed ADD.
    });
    assert!(agent::exchange(&public, &[17]).is_err());
    responder.join().unwrap();
    let guard = guard.lock().unwrap();
    assert_eq!(guard.lifetimes.len(), 1);
    assert_eq!(guard.lifetimes["finite"], finite);
}

#[test]
fn failed_selective_deadline_removal_fences_pending_sign_and_retains_expired_record() {
    let directory = tempfile::tempdir().unwrap();
    let backend = directory.path().join("backend");
    let public = directory.path().join("public");
    let listener = UnixListener::bind(&backend).unwrap();
    let blob = b"disposable public identity fixture";
    let fingerprint = ssh_keys::keys::fingerprint(blob);
    let mut lifetime = agent::Lifetime::new(60).unwrap();
    lifetime.deadline = Some(Duration::ZERO);
    let mut initial = Guard::default();
    initial
        .lifetimes
        .insert(fingerprint.clone(), lifetime.clone());
    let guard = Arc::new(Mutex::new(initial));
    agent::proxy_at(
        UnixListener::bind(&public).unwrap(),
        unsafe { libc::getuid() },
        backend,
        guard.clone(),
    );
    let responder = std::thread::spawn(move || {
        let (mut transit, _) = listener.accept().unwrap();
        transit
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (mut query, _) = listener.accept().unwrap();
        assert_eq!(agent::packet(&mut query).unwrap().as_slice(), [11]);
        let mut identities = vec![12, 0, 0, 0, 1];
        field(&mut identities, blob);
        field(&mut identities, b"fixture");
        agent::write(&mut query, &identities).unwrap();
        let (mut removal, _) = listener.accept().unwrap();
        let mut expected = vec![18];
        field(&mut expected, blob);
        assert_eq!(agent::packet(&mut removal).unwrap().as_slice(), expected);
        agent::write(&mut removal, &[5]).unwrap();
        // The original SIGN must never reach its connection after revoke fails.
        assert!(agent::packet(&mut transit).is_err());
    });
    assert!(agent::exchange(&public, &[13]).is_err());
    responder.join().unwrap();
    let guard = guard.lock().unwrap();
    assert!(guard.reset_required && guard.blocked);
    assert_eq!(guard.lifetimes[&fingerprint], lifetime);
}

#[test]
fn managed_deadline_is_derived_from_suspend_aware_clock_boottime() {
    fn raw_boottime() -> Duration {
        let mut time = std::mem::MaybeUninit::<libc::timespec>::uninit();
        assert_eq!(
            unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, time.as_mut_ptr()) },
            0
        );
        let time = unsafe { time.assume_init() };
        Duration::new(time.tv_sec as u64, time.tv_nsec as u32)
    }
    let before = raw_boottime();
    let lifetime = agent::Lifetime::new(60).unwrap();
    let after = raw_boottime();
    assert!(lifetime.deadline.unwrap() >= before + Duration::from_secs(60));
    assert!(lifetime.deadline.unwrap() <= after + Duration::from_secs(60));
}

#[test]
fn cleanup_crossing_another_deadline_rechecks_before_forwarding_sign() {
    fn accept(listener: &UnixListener) -> UnixStream {
        let until = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(2)))
                        .unwrap();
                    return stream;
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    assert!(
                        Instant::now() < until,
                        "expected maintenance connection before SIGN"
                    );
                    std::thread::sleep(Duration::from_millis(2));
                }
                Err(error) => panic!("disposable accept failed: {error}"),
            }
        }
    }
    let directory = tempfile::tempdir().unwrap();
    let backend = directory.path().join("backend");
    let public = directory.path().join("public");
    let listener = UnixListener::bind(&backend).unwrap();
    listener.set_nonblocking(true).unwrap();
    let first = b"first disposable public identity";
    let second = b"second disposable public identity";
    let mut initial = Guard::default();
    let mut one = agent::Lifetime::new(60).unwrap();
    one.deadline = Some(Duration::ZERO);
    initial
        .lifetimes
        .insert(ssh_keys::keys::fingerprint(first), one);
    let mut two = agent::Lifetime::new(60).unwrap();
    let second_deadline = agent::boot_now().unwrap() + Duration::from_millis(200);
    two.deadline = Some(second_deadline);
    initial
        .lifetimes
        .insert(ssh_keys::keys::fingerprint(second), two);
    let guard = Arc::new(Mutex::new(initial));
    agent::proxy_at(
        UnixListener::bind(&public).unwrap(),
        unsafe { libc::getuid() },
        backend,
        guard.clone(),
    );
    let responder = std::thread::spawn(move || {
        let mut transit = accept(&listener);
        for (step, blob) in [first.as_slice(), second.as_slice()]
            .into_iter()
            .enumerate()
        {
            let mut query = accept(&listener);
            assert_eq!(agent::packet(&mut query).unwrap().as_slice(), [11]);
            let mut identities = vec![12];
            identities.extend_from_slice(&(if step == 0 { 2u32 } else { 1 }).to_be_bytes());
            if step == 0 {
                field(&mut identities, first);
                field(&mut identities, b"fixture one");
            }
            field(&mut identities, second);
            field(&mut identities, b"fixture two");
            agent::write(&mut query, &identities).unwrap();
            let mut removal = accept(&listener);
            let mut expected = vec![18];
            field(&mut expected, blob);
            assert_eq!(agent::packet(&mut removal).unwrap().as_slice(), expected);
            if step == 0 {
                let now = agent::boot_now().unwrap();
                assert!(
                    now < second_deadline,
                    "fixture must initially have staggered deadlines"
                );
                std::thread::sleep(second_deadline - now + Duration::from_millis(10));
            }
            agent::write(&mut removal, &[6]).unwrap();
        }
        // Only after both revocations may the original request reach OpenSSH.
        assert_eq!(agent::packet(&mut transit).unwrap().as_slice(), [13]);
        agent::write(&mut transit, &[5]).unwrap();
    });
    assert_eq!(agent::exchange(&public, &[13]).unwrap().as_slice(), [5]);
    responder.join().unwrap();
    assert!(guard.lock().unwrap().lifetimes.is_empty());
}
