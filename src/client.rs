use crate::{
    Error, Result,
    protocol::{self, Command},
};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{fs::MetadataExt, net::UnixStream},
    },
    time::{Duration, Instant},
};
pub fn call(cmd: &Command) -> Result<Value> {
    call_with_timeout(cmd, Duration::from_secs(10))
}

pub fn call_with_timeout(cmd: &Command, timeout: Duration) -> Result<Value> {
    call_socket(cmd, "control.sock", timeout)
}

// The desktop endpoint permits direct revocation, unlock-method preferences
// only. Access rules and other management changes require the protected native
// dialog; the public control endpoint never permits these mutations.
pub fn call_desktop(cmd: &Command) -> Result<Value> {
    call_socket(cmd, "desktop.sock", Duration::from_secs(10))
}

fn call_socket(cmd: &Command, socket: &str, timeout: Duration) -> Result<Value> {
    let deadline = Instant::now() + timeout;
    let uid = unsafe { libc::getuid() };
    let dir = format!("/run/ssh-keys/{uid}");
    for p in ["/run/ssh-keys", &dir] {
        let m = fs::symlink_metadata(p).map_err(|_| Error("helper_unavailable"))?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(Error("unsafe_socket_directory"));
        }
    }
    let mut stream = connect_socket(&format!("{dir}/{socket}"), deadline)?;
    if crate::agent::peer(&stream)?.uid != 0 {
        return Err(Error("wrong_server"));
    }
    exchange(&mut stream, cmd, deadline)
}
fn exchange(stream: &mut UnixStream, cmd: &Command, deadline: Instant) -> Result<Value> {
    let mut request = serde_json::to_vec(cmd)?;
    request.push(b'\n');
    if request.len() > protocol::MAX_MESSAGE {
        return Err(Error("invalid_message"));
    }
    let mut written = 0;
    while written < request.len() {
        stream.set_write_timeout(Some(remaining(deadline)?.min(Duration::from_secs(1))))?;
        match stream.write(&request[written..]) {
            Ok(0) => return Err(Error("io_error")),
            Ok(count) => written += count,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let mut bytes = Vec::new();
    let mut one = [0; 1];
    while bytes.len() < 4 * 1024 * 1024 {
        stream.set_read_timeout(Some(remaining(deadline)?))?;
        match stream.read(&mut one) {
            Ok(1) if one[0] != b'\n' => bytes.push(one[0]),
            Ok(_) => break,
            // CLI signal handling must still receive the id of an accepted
            // initial request so it can cancel that exact request afterwards.
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e.into()),
        }
    }
    let v: Value = serde_json::from_slice(&bytes)?;
    if v["api_version"] != protocol::API {
        return Err(Error("api_mismatch"));
    }
    Ok(v)
}
fn connect_socket(path: &str, deadline: Instant) -> Result<UnixStream> {
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path.len() >= address.sun_path.len() || path.as_bytes().contains(&0) {
        return Err(Error("helper_unavailable"));
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, source) in address.sun_path.iter_mut().zip(path.as_bytes()) {
        *target = *source as libc::c_char;
    }
    loop {
        remaining(deadline)?;
        // A full local listen backlog must not make an ostensibly bounded
        // request block forever inside UnixStream::connect. Failed attempts
        // own no request data and are closed before retrying.
        let fd = unsafe {
            libc::socket(
                libc::AF_UNIX,
                libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
                0,
            )
        };
        if fd < 0 {
            return Err(Error("helper_unavailable"));
        }
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        let connected = unsafe {
            libc::connect(
                stream.as_raw_fd(),
                (&address as *const libc::sockaddr_un).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        };
        if connected == 0 {
            stream.set_nonblocking(false)?;
            return Ok(stream);
        }
        let error = std::io::Error::last_os_error().raw_os_error();
        drop(stream);
        if !matches!(error, Some(libc::EAGAIN | libc::EINTR | libc::EINPROGRESS)) {
            return Err(Error("helper_unavailable"));
        }
        std::thread::sleep(remaining(deadline)?.min(Duration::from_millis(10)));
    }
}
fn remaining(deadline: Instant) -> Result<Duration> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(Error("operation_timeout"))
    } else {
        Ok(left)
    }
}
pub fn print(v: &Value, json: bool) -> i32 {
    if json {
        println!("{}", v);
    } else {
        println!(
            "{}{}",
            v["state"].as_str().unwrap_or("error"),
            v["error_code"]
                .as_str()
                .map(|s| format!(": {s}"))
                .unwrap_or_default()
        );
        if let Some(id) = v["request_id"].as_str() {
            println!("request: {id}");
        }
        if let Some(keys) = v["keys"].as_array() {
            for k in keys {
                println!(
                    "{}  {}  {}",
                    k["key_id"].as_str().unwrap_or(""),
                    k["state"].as_str().unwrap_or(""),
                    k["name"].as_str().unwrap_or("")
                );
            }
        }
    }
    match v["state"].as_str() {
        Some("pending") => 3,
        Some("error" | "denied" | "cancelled" | "expired" | "partial") => 1,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixListener;

    #[test]
    fn bounded_connection_preserves_blocking_cloexec_socket_and_peer_identity() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let stream = connect_socket(
            path.to_str().unwrap(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let (_accepted, _) = listener.accept().unwrap();
        assert_eq!(crate::agent::peer(&stream).unwrap().uid, unsafe {
            libc::getuid()
        });
        assert_ne!(
            unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        assert_eq!(
            unsafe { libc::fcntl(stream.as_raw_fd(), libc::F_GETFL) } & libc::O_NONBLOCK,
            0
        );
    }

    #[test]
    fn full_listen_queue_cannot_extend_connection_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        assert_eq!(unsafe { libc::listen(listener.as_raw_fd(), 0) }, 0);
        let _queued = connect_socket(
            path.to_str().unwrap(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let start = Instant::now();
        let result = connect_socket(path.to_str().unwrap(), start + Duration::from_millis(75));
        assert_eq!(result.unwrap_err().0, "operation_timeout");
        assert!(start.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn fragmented_response_cannot_restart_rpc_deadline_for_each_byte() {
        let (mut stream, mut peer) = UnixStream::pair().unwrap();
        let sender = std::thread::spawn(move || {
            let mut byte = [0];
            while peer.read_exact(&mut byte).is_ok() && byte[0] != b'\n' {}
            for byte in b"{\"api_version\":1,\"state\":\"pending\"}\n" {
                if peer.write_all(&[*byte]).is_err() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(25));
            }
        });
        let start = Instant::now();
        let result = exchange(
            &mut stream,
            &Command::new("capabilities"),
            start + Duration::from_millis(90),
        );
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_millis(500));
        drop(stream);
        sender.join().unwrap();
    }

    #[test]
    fn blocked_request_write_uses_the_total_rpc_budget() {
        let (mut stream, _peer) = UnixStream::pair().unwrap();
        let buffer: libc::c_int = 4096;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_SNDBUF,
                    (&buffer as *const libc::c_int).cast(),
                    std::mem::size_of_val(&buffer) as libc::socklen_t,
                )
            },
            0
        );
        let mut command = Command::new("keys.unlock");
        command.key = Some("x".repeat(60 * 1024)); // Public synthetic request data only.
        let start = Instant::now();
        assert!(exchange(&mut stream, &command, start + Duration::from_millis(90)).is_err());
        assert!(start.elapsed() < Duration::from_millis(500));
    }
}
