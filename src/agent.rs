use crate::{Error, Result, keys, platform};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{Arc, Mutex},
    time::Duration,
};
use zeroize::Zeroizing;

pub const MAX_PACKET: usize = 2 * 1024 * 1024;
pub fn packet(stream: &mut UnixStream) -> Result<Zeroizing<Vec<u8>>> {
    let mut len = [0; 4];
    stream.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_PACKET {
        return Err(Error("invalid_agent_packet"));
    }
    let mut body = Zeroizing::new(vec![0; n]);
    stream.read_exact(&mut body)?;
    Ok(body)
}
pub fn write(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(bytes)?;
    Ok(())
}
pub fn exchange(path: &Path, bytes: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    stream.set_write_timeout(Some(Duration::from_millis(500)))?;
    write(&mut stream, bytes)?;
    packet(&mut stream)
}
pub fn list(path: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
    let bytes = exchange(path, &[11])?;
    if bytes.len() < 5 || bytes[0] != 12 {
        return Err(Error("agent_unavailable"));
    }
    let n = u32::from_be_bytes(bytes[1..5].try_into().unwrap());
    if n > 4096 {
        return Err(Error("agent_limit"));
    }
    let mut rest = &bytes[5..];
    let mut result = BTreeMap::new();
    for _ in 0..n {
        let pubkey = keys::field(&mut rest)?;
        let _comment = keys::field(&mut rest)?;
        result.insert(keys::fingerprint(pubkey), pubkey.to_vec());
    }
    if !rest.is_empty() {
        return Err(Error("invalid_agent_packet"));
    }
    Ok(result)
}
pub fn remove(path: &Path, public: &[u8]) -> Result<()> {
    let mut message = vec![18];
    message.extend_from_slice(&(public.len() as u32).to_be_bytes());
    message.extend_from_slice(public);
    if exchange(path, &message)?.as_slice() != [6] {
        return Err(Error("revoke_failed"));
    }
    Ok(())
}
pub fn remove_key(path: &Path, key: &keys::Key) -> Result<()> {
    remove(
        path,
        &STANDARD
            .decode(&key.public_blob)
            .map_err(|_| Error("invalid_key"))?,
    )
}
#[derive(Default)]
pub struct Guard {
    pub blocked: bool,
    // Checked for every ADD, including when the server event loop has not yet
    // observed the coordinator's marker. None is used by isolated fixtures.
    pub sleep_marker: Option<std::path::PathBuf>,
    pub generation: u64,
    pub worker_group: Option<i32>,
    pub external_epoch: u64,
    pub managed_added_at: Option<u64>,
    pub managed_add_uncertain: bool,
    pub retired_worker_groups: BTreeSet<i32>,
}
pub fn peer(stream: &UnixStream) -> Result<libc::ucred> {
    let mut u = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of_val(&u) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut u as *mut libc::ucred).cast(),
            &mut len,
        )
    } != 0
    {
        return Err(Error("wrong_peer"));
    }
    Ok(u)
}
fn peer_pidfd(stream: &UnixStream) -> Result<File> {
    let mut fd: libc::c_int = -1;
    let mut len = std::mem::size_of_val(&fd) as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&mut fd as *mut libc::c_int).cast(),
            &mut len,
        )
    } != 0
        || fd < 0
    {
        return Err(Error("wrong_peer"));
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}
fn peer_exited(fd: &File) -> bool {
    let mut poll = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    unsafe { libc::poll(&mut poll, 1, 0) != 0 }
}
// The proxy coordinates managed loading and cancellation with ordinary
// ssh-add. The private OpenSSH socket is root-only; its process runs as uid.
// We never interpret, persist or log private-key/signing packets.
pub fn proxy(listener: UnixListener, user: platform::User, guard: Arc<Mutex<Guard>>) {
    proxy_at(
        listener,
        user.uid,
        user.runtime().join("backend.sock"),
        guard,
    )
}
pub fn proxy_at(
    listener: UnixListener,
    uid: u32,
    backend_path: std::path::PathBuf,
    guard: Arc<Mutex<Guard>>,
) {
    std::thread::spawn(move || {
        let count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        for socket in listener.incoming().flatten() {
            let Ok(cred) = peer(&socket) else { continue };
            if cred.uid != uid || count.load(std::sync::atomic::Ordering::Relaxed) >= 64 {
                continue;
            }
            let Ok(peer_process) = peer_pidfd(&socket) else {
                continue;
            };
            // Capture before spawning: a delayed connection handler must not
            // replay buffered packets into a backend started after a reset.
            let generation = match guard.lock() {
                Ok(g) => g.generation,
                Err(_) => continue,
            };
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let count = count.clone();
            let guard = guard.clone();
            let path = backend_path.clone();
            std::thread::spawn(move || {
                let mut socket = socket;
                let _ = socket.set_read_timeout(Some(Duration::from_secs(30)));
                let _ = socket.set_write_timeout(Some(Duration::from_secs(1)));
                let run = || -> Result<()> {
                    // Keep one backend connection per frontend connection:
                    // OpenSSH session-bind and destination constraints depend on it.
                    let mut backend = UnixStream::connect(path)?;
                    backend.set_read_timeout(Some(Duration::from_millis(500)))?;
                    backend.set_write_timeout(Some(Duration::from_millis(500)))?;
                    loop {
                        let message = packet(&mut socket)?;
                        let mutation =
                            matches!(message[0], 17 | 18 | 19 | 20 | 21 | 22 | 23 | 25 | 26);
                        let mut g = guard.lock().map_err(|_| Error("guard_failed"))?;
                        if generation != g.generation {
                            return Err(Error("agent_reset"));
                        }
                        let adding = matches!(message[0], 17 | 20 | 22 | 23 | 25 | 26);
                        let group = unsafe { libc::getpgid(cred.pid) };
                        if adding
                            && (g.blocked
                                || g.sleep_marker
                                    .as_deref()
                                    .is_some_and(platform::sleep_marker_active)
                                || g.retired_worker_groups.contains(&group)
                                || peer_exited(&peer_process))
                        {
                            write(&mut socket, &[5])?;
                            continue;
                        }
                        let managed = g.worker_group == Some(group);
                        if adding && managed {
                            // A failed exchange may still have committed ADD.
                            // Cancellation must reset only in that ambiguous case.
                            g.managed_add_uncertain = true;
                        }
                        write(&mut backend, &message)?;
                        let result = packet(&mut backend)?;
                        if adding && managed && matches!(result.as_slice(), [5] | [6]) {
                            g.managed_add_uncertain = false;
                        }
                        if mutation && result.as_slice() == [6] && !managed {
                            g.external_epoch = g.external_epoch.wrapping_add(1);
                        } else if adding && result.as_slice() == [6] {
                            g.managed_added_at = Some(platform::now());
                        }
                        drop(g);
                        write(&mut socket, &result)?;
                    }
                };
                let _ = run();
                count.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            });
        }
    });
}
