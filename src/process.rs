use crate::{Error, Result};
use std::{
    ffi::CString,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::{net::UnixStream, process::CommandExt},
    },
    process::{Command, Stdio},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

pub fn harden() -> Result<()> {
    unsafe {
        let limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0
            || libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0
            || libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        {
            return Err(Error("hardening_failed"));
        }
        libc::umask(0o077);
    }
    ptrace_protection()
}
// Constructors run after exec has reset dumpability. Yama prevents unrelated
// same-UID processes from attaching in that secret-free bootstrap interval and
// retaining access after the private descriptor handshake. Production secret
// processes descend from the root service, never from a client application.
fn ptrace_protection() -> Result<()> {
    match std::fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope")
        .ok()
        .as_deref()
        .map(str::trim)
    {
        Some("1" | "2" | "3") => Ok(()),
        _ => Err(Error("ptrace_protection_required")),
    }
}
pub fn memfile(data: &[u8], sealed: bool) -> Result<File> {
    let name = CString::new("ssh-keys-memory").unwrap();
    let fd =
        unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING) };
    if fd < 0 {
        return Err(Error("memory_file_failed"));
    }
    let mut f = unsafe { File::from_raw_fd(fd) };
    if unsafe { libc::fchmod(fd, 0o600) } != 0 {
        return Err(Error("memory_file_failed"));
    }
    f.write_all(data)?;
    f.seek(SeekFrom::Start(0))?;
    if sealed
        && unsafe {
            libc::fcntl(
                fd,
                libc::F_ADD_SEALS,
                libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL,
            )
        } < 0
    {
        return Err(Error("memory_seal_failed"));
    }
    Ok(f)
}
pub fn read_secret(mut f: impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut f).take(8193).read_to_end(&mut bytes)?;
    if bytes.len() > 8192 {
        return Err(Error("secret_too_long"));
    }
    Ok(bytes)
}
pub fn clean_command(program: &str) -> Command {
    let mut c = Command::new(program);
    c.env_clear()
        .env("PATH", "/usr/bin")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    c
}
// All mappings are first duplicated above the reserved range, so collisions
// between source descriptors and the destination numbers cannot alias secrets.
pub fn descriptors(
    c: &mut Command,
    mapping: &[(RawFd, RawFd)],
    identity: Option<(u32, u32)>,
    group: bool,
) -> Result<()> {
    let mut keep = Vec::new();
    let parent_pid = unsafe { libc::getpid() };
    for (fd, dest) in mapping {
        let dup = unsafe { libc::fcntl(*fd, libc::F_DUPFD_CLOEXEC, 32) };
        if dup < 0 {
            return Err(Error("fd_failed"));
        }
        keep.push((unsafe { File::from_raw_fd(dup) }, *dest));
    }
    unsafe {
        c.pre_exec(move || {
            if libc::syscall(
                libc::SYS_close_range,
                3u32,
                u32::MAX,
                libc::CLOSE_RANGE_CLOEXEC,
            ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            for (f, dest) in &keep {
                if libc::dup2(f.as_raw_fd(), *dest) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if group && libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if let Some((uid, gid)) = identity
                && libc::geteuid() == 0
                && (libc::setgroups(0, std::ptr::null()) != 0
                    || libc::setgid(gid) != 0
                    || libc::setuid(uid) != 0)
            {
                return Err(std::io::Error::last_os_error());
            }
            let limit = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            if libc::setrlimit(libc::RLIMIT_CORE, &limit) != 0
                || libc::prctl(libc::PR_SET_DUMPABLE, 0) != 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::getppid() != parent_pid {
                return Err(std::io::Error::from_raw_os_error(libc::ECANCELED));
            }
            Ok(())
        });
    }
    Ok(())
}
pub fn wait(mut child: std::process::Child, seconds: u64) -> Result<()> {
    let until = Instant::now() + Duration::from_secs(seconds);
    loop {
        if let Some(status) = child.try_wait()? {
            return if status.success() {
                Ok(())
            } else {
                Err(Error("operation_failed"))
            };
        }
        if Instant::now() >= until {
            let _ = child.kill();
            let _ = child.wait();
            return Err(Error("operation_timeout"));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
pub fn protected_spawn(c: &mut Command, mapping: &[(RawFd, RawFd)]) -> Result<std::process::Child> {
    protected_spawn_as(c, mapping, None)
}
pub fn protected_spawn_as(
    c: &mut Command,
    mapping: &[(RawFd, RawFd)],
    identity: Option<(u32, u32)>,
) -> Result<std::process::Child> {
    ptrace_protection()?;
    if mapping.is_empty() || mapping.len() > 8 {
        return Err(Error("fd_failed"));
    }
    let library =
        if std::env::current_exe()?.parent() == Some(std::path::Path::new("/usr/lib/ssh-keys")) {
            "/usr/lib/ssh-keys/harden.so"
        } else {
            env!("SSH_KEYS_BUILD_HARDEN")
        };
    let (mut parent, child_socket) = UnixStream::pair()?;
    parent.set_read_timeout(Some(Duration::from_secs(2)))?;
    parent.set_write_timeout(Some(Duration::from_secs(2)))?;
    c.env("LD_PRELOAD", library)
        .env("SSH_KEYS_HARDEN_STAGE", "1");
    descriptors(c, &[(child_socket.as_raw_fd(), 30)], identity, false)?;
    let mut child = c.spawn()?;
    drop(child_socket);
    let mut transfer = || -> Result<()> {
        let mut ready = [0];
        parent.read_exact(&mut ready)?;
        if ready != *b"R" {
            return Err(Error("hardening_failed"));
        }
        let destinations: Vec<i32> = mapping.iter().map(|m| m.1).collect();
        let sources: Vec<i32> = mapping.iter().map(|m| m.0).collect();
        let size = std::mem::size_of_val(sources.as_slice());
        unsafe {
            let capacity = libc::CMSG_SPACE(size as u32) as usize;
            let mut control = vec![0usize; capacity.div_ceil(std::mem::size_of::<usize>())];
            let mut io = libc::iovec {
                iov_base: destinations.as_ptr().cast_mut().cast(),
                iov_len: size,
            };
            let mut msg: libc::msghdr = std::mem::zeroed();
            msg.msg_iov = &mut io;
            msg.msg_iovlen = 1;
            msg.msg_control = control.as_mut_ptr().cast();
            msg.msg_controllen = capacity;
            let header = libc::CMSG_FIRSTHDR(&msg);
            (*header).cmsg_level = libc::SOL_SOCKET;
            (*header).cmsg_type = libc::SCM_RIGHTS;
            (*header).cmsg_len = libc::CMSG_LEN(size as u32) as usize;
            std::ptr::copy_nonoverlapping(
                sources.as_ptr().cast::<u8>(),
                libc::CMSG_DATA(header),
                size,
            );
            if libc::sendmsg(parent.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) != size as isize {
                return Err(Error("fd_failed"));
            }
        }
        Ok(())
    };
    if transfer().is_err() {
        let _ = child.kill();
        let _ = child.wait();
        return Err(Error("hardening_failed"));
    }
    Ok(child)
}
// The caller supplies a sealed snapshot whose OpenSSH envelope fingerprint
// has already been matched to the selected identity. Original ssh-add checks
// the decrypted private key against that envelope before sending agent ADD.
// Do not decrypt it once with ssh-keygen and again with ssh-add.
pub fn load_key_snapshot(
    key: &File,
    pass: &[u8],
    socket: &std::path::Path,
    lifetime_seconds: u32,
) -> Result<()> {
    if pass.len() > 1023 || pass.contains(&0) || pass.contains(&b'\n') || pass.contains(&b'\r') {
        return Err(Error("invalid_passphrase"));
    }
    if pass.is_empty() {
        return Err(Error("empty_passphrase"));
    }
    let secret = memfile(pass, true)?;
    let mut c = clean_command("/usr/bin/ssh-add");
    if lifetime_seconds > 0 {
        c.args(["-t", &lifetime_seconds.to_string()]);
    }
    c.args(["-q", "/proc/self/fd/3"])
        .env("SSH_AUTH_SOCK", socket)
        .env("SSH_ASKPASS", std::env::current_exe()?)
        .env("SSH_KEYS_INTERNAL_ASKPASS", "1")
        .env("SSH_KEYS_ASKPASS_ONCE", "1")
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", "ssh-keys");
    wait(
        protected_spawn(&mut c, &[(key.as_raw_fd(), 3), (secret.as_raw_fd(), 4)])?,
        30,
    )
    .map_err(|_| Error("unlock_failed"))
}

pub fn key_command(
    args: &[&str],
    key: &File,
    pass: &[u8],
    capture: bool,
) -> Result<Zeroizing<Vec<u8>>> {
    // OpenSSH read_passphrase/ssh_askpass has a 1024-byte buffer including NUL.
    // Never silently install a truncated UTF-8 passphrase.
    if pass.len() > 1023 || pass.contains(&0) || pass.contains(&b'\n') || pass.contains(&b'\r') {
        return Err(Error("invalid_passphrase"));
    }
    let secret = memfile(pass, true)?;
    let output = memfile(&[], false)?;
    let mut c = clean_command("/usr/bin/ssh-keygen");
    c.args(args)
        .args(["-f", "/proc/self/fd/3"])
        .env("SSH_ASKPASS", std::env::current_exe()?)
        .env("SSH_KEYS_INTERNAL_ASKPASS", "1")
        .env("SSH_ASKPASS_REQUIRE", "force")
        .env("DISPLAY", "ssh-keys");
    let mut mapping = vec![(key.as_raw_fd(), 3), (secret.as_raw_fd(), 4)];
    if capture {
        mapping.push((output.as_raw_fd(), 1));
    }
    wait(protected_spawn(&mut c, &mapping)?, 30).map_err(|_| Error("key_operation_failed"))?;
    let mut out = output;
    out.seek(SeekFrom::Start(0))?;
    read_secret(out)
}
pub fn askpass() -> Result<()> {
    // The packaged constructor answers inside OpenSSH's nondumpable fork child.
    // Reaching a real askpass exec means that integration is unavailable. Never
    // accept inherited secrets or emit a passphrase through this fallback.
    Err(Error("askpass_integration_unavailable"))
}
