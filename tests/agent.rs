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
    assert_eq!(guard.lock().unwrap().external_epoch, 1);
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
