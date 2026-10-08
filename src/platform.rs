use crate::{Error, Result, process};
use serde::{Deserialize, Serialize};
use std::{
    ffi::{CStr, CString},
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
            net::UnixStream,
        },
    },
    path::{Path, PathBuf},
    sync::mpsc::Sender,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use zbus::{
    blocking::{Connection, Proxy},
    zvariant::OwnedObjectPath,
};

#[derive(Clone, Serialize, Deserialize)]
pub struct User {
    pub uid: u32,
    pub gid: u32,
    pub name: String,
    pub home: PathBuf,
}
impl User {
    pub fn get(uid: u32) -> Result<Self> {
        let mut data = vec![0u8; 65536];
        let mut p = std::mem::MaybeUninit::<libc::passwd>::uninit();
        let mut result = std::ptr::null_mut();
        unsafe {
            if libc::getpwuid_r(
                uid,
                p.as_mut_ptr(),
                data.as_mut_ptr().cast(),
                data.len(),
                &mut result,
            ) != 0
                || result.is_null()
            {
                return Err(Error("unknown_user"));
            }
            let p = p.assume_init();
            Ok(Self {
                uid,
                gid: p.pw_gid,
                name: CStr::from_ptr(p.pw_name).to_string_lossy().into_owned(),
                home: PathBuf::from(CStr::from_ptr(p.pw_dir).to_string_lossy().into_owned()),
            })
        }
    }
    pub fn runtime(&self) -> PathBuf {
        PathBuf::from(format!("/run/ssh-keys/{}", self.uid))
    }
    pub fn state_dir(&self) -> PathBuf {
        PathBuf::from(format!("/var/lib/ssh-keys/{}", self.uid))
    }
}
// This directory belongs to the root sleep coordinator, independently of
// each helper's RuntimeDirectory, so helper restarts cannot clear the fence.
pub const SLEEP_MARKER: &str = "/run/ssh-keys-sleep/active";

pub fn sleep_marker_active(path: &Path) -> bool {
    match fs::symlink_metadata(path) {
        Ok(_) => true,
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
pub fn random_id() -> Result<String> {
    let mut bytes = [0; 16];
    File::open("/dev/urandom")?.read_exact(&mut bytes)?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
pub fn save_json(path: &Path, value: &impl Serialize) -> Result<()> {
    save_bytes(path, &serde_json::to_vec(value)?)
}
pub fn save_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    match save_bytes_outcome(path, bytes, sync_parent)? {
        SaveOutcome::Durable => Ok(()),
        SaveOutcome::ReplacedButUnsynced(error) => Err(error),
    }
}

#[derive(Debug)]
pub(crate) enum SaveOutcome {
    Durable,
    // The replacement is visible and must not be reported as rolled back.
    // Only its persistence across a crash remains uncertain.
    ReplacedButUnsynced(Error),
}

pub(crate) fn save_json_outcome(path: &Path, value: &impl Serialize) -> Result<SaveOutcome> {
    save_bytes_outcome(path, &serde_json::to_vec(value)?, sync_parent)
}

#[cfg(test)]
pub(crate) fn save_json_outcome_with_parent_sync(
    path: &Path,
    value: &impl Serialize,
    parent_sync: impl FnOnce(&Path) -> Result<()>,
) -> Result<SaveOutcome> {
    save_bytes_outcome(path, &serde_json::to_vec(value)?, parent_sync)
}

fn sync_parent(parent: &Path) -> Result<()> {
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn save_bytes_outcome(
    path: &Path,
    bytes: &[u8],
    parent_sync: impl FnOnce(&Path) -> Result<()>,
) -> Result<SaveOutcome> {
    let parent = path.parent().ok_or(Error("invalid_path"))?;
    let tmp = parent.join(format!(".{}.tmp", random_id()?));
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    let result = (|| -> Result<SaveOutcome> {
        f.write_all(bytes)?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        // Every error above means the old destination is still intact. After
        // rename succeeds the caller must distinguish a durability failure.
        Ok(match parent_sync(parent) {
            Ok(()) => SaveOutcome::Durable,
            Err(error) => SaveOutcome::ReplacedButUnsynced(error),
        })
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}
pub fn own_socket(path: &Path, uid: u32) -> Result<()> {
    let p = CString::new(path.as_os_str().as_encoded_bytes()).map_err(|_| Error("invalid_path"))?;
    if unsafe { libc::chown(p.as_ptr(), uid, u32::MAX) } != 0 {
        return Err(Error("socket_ownership"));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}
/// Root-logind identity of the compositor. This is an internal worker message,
/// never a caller-supplied choice of Wayland server.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisplayIdentity {
    pub session_id: String,
    pub controller: String,
    pub compositor_pid: u32,
    pub compositor_start_ticks: u64,
    pub wayland: String,
}
#[derive(Clone, Default)]
pub struct Session {
    pub available: bool,
    pub locked: bool,
    // Presentation compatibility only; never use this path to launch a prompt.
    pub wayland: String,
    pub display: Option<DisplayIdentity>,
}
#[derive(Clone, Debug)]
struct LoginSession {
    id: String,
    uid: u32,
    leader: u32,
    scope: String,
    locked: bool,
}
const SESSION_ERROR: Error = Error("session_unavailable");
const MAX_SESSION_BYTES: u64 = 64 * 1024;

fn bounded_text(path: &Path, trusted_root: bool) -> Result<String> {
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.len() > MAX_SESSION_BYTES
        || (trusted_root && (metadata.uid() != 0 || metadata.mode() & 0o022 != 0))
    {
        return Err(SESSION_ERROR);
    }
    let mut text = String::new();
    (&mut file)
        .take(MAX_SESSION_BYTES + 1)
        .read_to_string(&mut text)?;
    if text.len() as u64 > MAX_SESSION_BYTES || text.contains('\0') {
        return Err(SESSION_ERROR);
    }
    Ok(text)
}
fn trusted_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
        return Err(SESSION_ERROR);
    }
    Ok(())
}
fn valid_session_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 64 && id.bytes().all(|c| c.is_ascii_alphanumeric())
}
fn valid_controller(name: &str) -> bool {
    name.len() <= 64
        && name.strip_prefix(':').is_some_and(|rest| {
            let parts: Vec<_> = rest.split('.').collect();
            parts.len() == 2
                && parts
                    .iter()
                    .all(|s| !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()))
        })
}
fn controller_from_record(text: &str, session: &LoginSession) -> Result<String> {
    let mut fields = std::collections::HashMap::new();
    for line in text.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or(SESSION_ERROR)?;
        if matches!(
            key,
            "UID" | "ACTIVE" | "REMOTE" | "TYPE" | "LEADER" | "SCOPE" | "CONTROLLER"
        ) && fields.insert(key, value).is_some()
        {
            return Err(SESSION_ERROR);
        }
    }
    if fields.get("UID").and_then(|v| v.parse::<u32>().ok()) != Some(session.uid)
        || fields.get("LEADER").and_then(|v| v.parse::<u32>().ok()) != Some(session.leader)
        || fields.get("SCOPE").copied() != Some(session.scope.as_str())
        || fields.get("TYPE").copied() != Some("wayland")
        || fields.get("ACTIVE").copied() != Some("1")
        || fields.get("REMOTE").copied() != Some("0")
    {
        return Err(SESSION_ERROR);
    }
    let controller = fields.get("CONTROLLER").copied().ok_or(SESSION_ERROR)?;
    if !valid_controller(controller) {
        return Err(SESSION_ERROR);
    }
    Ok(controller.into())
}
fn session_controller(session: &LoginSession) -> Result<String> {
    if !valid_session_id(&session.id) {
        return Err(SESSION_ERROR);
    }
    for path in ["/run", "/run/systemd", "/run/systemd/sessions"] {
        trusted_directory(Path::new(path))?;
    }
    // logind has no public Controller property. Its root-owned state records
    // the unique SYSTEM-bus name holding TakeControl. This private format is a
    // compatibility dependency: missing/changed data fails closed, never falls
    // back to user-manager environment, a sorted socket, or process basename.
    let path = PathBuf::from("/run/systemd/sessions").join(&session.id);
    controller_from_record(&bounded_text(&path, true)?, session)
}
fn active_session(c: &Connection, uid: u32) -> Result<LoginSession> {
    let manager = Proxy::new(
        c,
        "org.freedesktop.login1",
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    )?;
    let sessions: Vec<(String, u32, String, String, OwnedObjectPath)> =
        manager.call("ListSessions", &())?;
    let mut selected = None;
    for (id, owner, _, _, path) in sessions {
        if owner != uid {
            continue;
        }
        let s = Proxy::new(
            c,
            "org.freedesktop.login1",
            path.as_str(),
            "org.freedesktop.login1.Session",
        )?;
        let active: bool = s.get_property("Active")?;
        let remote: bool = s.get_property("Remote")?;
        let kind: String = s.get_property("Type")?;
        if !active || remote || kind != "wayland" {
            continue;
        }
        let class: String = s.get_property("Class")?;
        let seat: (String, OwnedObjectPath) = s.get_property("Seat")?;
        if class != "user" || seat.0.is_empty() || selected.is_some() {
            return Err(SESSION_ERROR);
        }
        let leader = s.get_property("Leader")?;
        let scope: String = s.get_property("Scope")?;
        if !valid_session_id(&id) || scope != format!("session-{id}.scope") {
            return Err(SESSION_ERROR);
        }
        selected = Some(LoginSession {
            id,
            uid,
            leader,
            scope,
            locked: s.get_property("LockedHint")?,
        });
    }
    selected.ok_or(SESSION_ERROR)
}
fn controller_pid(c: &Connection, controller: &str, uid: u32) -> Result<u32> {
    let bus = Proxy::new(
        c,
        "org.freedesktop.DBus",
        "/org/freedesktop/DBus",
        "org.freedesktop.DBus",
    )?;
    let pid: u32 = bus.call("GetConnectionUnixProcessID", &(controller,))?;
    let owner: u32 = bus.call("GetConnectionUnixUser", &(controller,))?;
    if owner != uid || pid < 2 || pid > i32::MAX as u32 {
        return Err(SESSION_ERROR);
    }
    Ok(pid)
}
fn start_ticks(stat: &str, pid: u32) -> Result<u64> {
    if stat.split_once(' ').and_then(|v| v.0.parse::<u32>().ok()) != Some(pid) {
        return Err(SESSION_ERROR);
    }
    let (_, rest) = stat.rsplit_once(") ").ok_or(SESSION_ERROR)?;
    rest.split_whitespace()
        .nth(19)
        .and_then(|s| s.parse::<u64>().ok())
        .filter(|n| *n > 0)
        .ok_or(SESSION_ERROR)
}
fn valid_cgroup(text: &str, uid: u32, id: &str) -> bool {
    let direct = format!("0::/user.slice/user-{uid}.slice/session-{id}.scope");
    let uwsm = format!(
        "0::/user.slice/user-{uid}.slice/user@{uid}.service/session.slice/wayland-wm@hyprland.desktop.service"
    );
    let lines: Vec<_> = text.lines().collect();
    lines.len() == 1 && (lines[0] == direct || lines[0] == uwsm)
}
fn verified_process(pid: u32, uid: u32, id: &str) -> Result<u64> {
    let base = PathBuf::from(format!("/proc/{pid}"));
    let status = bounded_text(&base.join("status"), false)?;
    let uids: Vec<_> = status
        .lines()
        .find_map(|line| line.strip_prefix("Uid:"))
        .ok_or(SESSION_ERROR)?
        .split_whitespace()
        .map(str::parse::<u32>)
        .collect();
    if uids.len() != 4
        || uids.iter().any(|v| v.as_ref().ok() != Some(&uid))
        || !valid_cgroup(&bounded_text(&base.join("cgroup"), false)?, uid, id)
    {
        return Err(SESSION_ERROR);
    }
    let executable = fs::read_link(base.join("exe"))?;
    // Keep a legitimately running old package binary usable after an upgrade.
    if executable != Path::new("/usr/bin/Hyprland")
        && executable != Path::new("/usr/bin/Hyprland (deleted)")
    {
        return Err(SESSION_ERROR);
    }
    let binary = File::open(base.join("exe"))?;
    let metadata = binary.metadata()?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(SESSION_ERROR);
    }
    start_ticks(&bounded_text(&base.join("stat"), false)?, pid)
}
fn pin_process(pid: u32) -> Result<File> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0) };
    if fd < 0 {
        return Err(SESSION_ERROR);
    }
    Ok(unsafe { File::from_raw_fd(fd as i32) })
}
fn require_alive(pidfd: &File) -> Result<()> {
    let mut p = libc::pollfd {
        fd: pidfd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe { libc::poll(&mut p, 1, 0) } != 0 {
        return Err(SESSION_ERROR);
    }
    Ok(())
}
fn valid_display_name(name: &str) -> bool {
    name.len() <= 64
        && name
            .strip_prefix("wayland-")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|c| c.is_ascii_digit()))
}
fn display_socket(path: &Path, uid: u32, pid: u32) -> Result<UnixStream> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.uid() != uid {
        return Err(SESSION_ERROR);
    }
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut address: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.is_empty() || bytes.len() >= address.sun_path.len() || bytes.contains(&0) {
        return Err(SESSION_ERROR);
    }
    address.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (target, byte) in address.sun_path.iter_mut().zip(bytes) {
        *target = *byte as libc::c_char;
    }
    let fd = unsafe {
        libc::socket(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            0,
        )
    };
    if fd < 0 {
        return Err(SESSION_ERROR);
    }
    let socket = unsafe { UnixStream::from_raw_fd(fd) };
    // A full/unresponsive listen queue cannot block the privileged watcher.
    if unsafe {
        libc::connect(
            fd,
            (&address as *const libc::sockaddr_un).cast(),
            std::mem::size_of::<libc::sockaddr_un>() as libc::socklen_t,
        )
    } != 0
    {
        return Err(SESSION_ERROR);
    }
    let mut peer: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut peer as *mut libc::ucred).cast(),
            &mut length,
        )
    } != 0
        || length as usize != std::mem::size_of::<libc::ucred>()
        || peer.uid != uid
        || peer.pid < 1
        || peer.pid as u32 != pid
    {
        return Err(SESSION_ERROR);
    }
    socket.set_nonblocking(false)?;
    Ok(socket)
}
fn runtime_directory(uid: u32) -> Result<PathBuf> {
    for path in ["/run", "/run/user"] {
        trusted_directory(Path::new(path))?;
    }
    let path = PathBuf::from(format!("/run/user/{uid}"));
    let metadata = fs::symlink_metadata(&path)?;
    if !metadata.is_dir() || metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err(SESSION_ERROR);
    }
    Ok(path)
}
fn discover_display_in(runtime: &Path, uid: u32, pid: u32) -> Result<String> {
    let mut verified = None;
    let mut count = 0;
    for (index, entry) in fs::read_dir(runtime)?.enumerate() {
        if index >= 1024 {
            return Err(SESSION_ERROR);
        }
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str().filter(|name| valid_display_name(name)) else {
            continue;
        };
        count += 1;
        if count > 64 {
            return Err(SESSION_ERROR);
        }
        if display_socket(&entry.path(), uid, pid).is_ok()
            && verified.replace(name.to_owned()).is_some()
        {
            return Err(SESSION_ERROR);
        }
    }
    verified.ok_or(SESSION_ERROR)
}
pub fn session(uid: u32) -> Result<Session> {
    let c = Connection::system()?;
    let login = active_session(&c, uid)?;
    let controller = session_controller(&login)?;
    let pid = controller_pid(&c, &controller, uid)?;
    let pin = pin_process(pid)?;
    let ticks = verified_process(pid, uid, &login.id)?;
    let wayland = discover_display_in(&runtime_directory(uid)?, uid, pid)?;
    require_alive(&pin)?;
    if session_controller(&login)? != controller
        || controller_pid(&c, &controller, uid)? != pid
        || verified_process(pid, uid, &login.id)? != ticks
    {
        return Err(SESSION_ERROR);
    }
    Ok(Session {
        available: true,
        locked: login.locked,
        wayland: wayland.clone(),
        display: Some(DisplayIdentity {
            session_id: login.id,
            controller,
            compositor_pid: pid,
            compositor_start_ticks: ticks,
            wayland,
        }),
    })
}
/// Return a connected, authenticated socket. The caller must pass this SAME FD
/// as WAYLAND_SOCKET; reconnecting by pathname discards the TOCTOU protection.
pub fn connect_display(user: &User, expected: &DisplayIdentity) -> Result<UnixStream> {
    if !valid_display_name(&expected.wayland) || !valid_controller(&expected.controller) {
        return Err(SESSION_ERROR);
    }
    let c = Connection::system()?;
    let login = active_session(&c, user.uid)?;
    if login.locked
        || login.id != expected.session_id
        || session_controller(&login)? != expected.controller
        || controller_pid(&c, &expected.controller, user.uid)? != expected.compositor_pid
    {
        return Err(SESSION_ERROR);
    }
    let pin = pin_process(expected.compositor_pid)?;
    if verified_process(expected.compositor_pid, user.uid, &login.id)?
        != expected.compositor_start_ticks
    {
        return Err(SESSION_ERROR);
    }
    let socket = display_socket(
        &runtime_directory(user.uid)?.join(&expected.wayland),
        user.uid,
        expected.compositor_pid,
    )?;
    require_alive(&pin)?;
    let current = active_session(&c, user.uid)?;
    if current.locked
        || current.id != login.id
        || session_controller(&current)? != expected.controller
        || controller_pid(&c, &expected.controller, user.uid)? != expected.compositor_pid
        || verified_process(expected.compositor_pid, user.uid, &current.id)?
            != expected.compositor_start_ticks
    {
        return Err(SESSION_ERROR);
    }
    Ok(socket)
}
// Session state controls consent windows and new managed loads only. It does
// not revoke loaded identities. A separate root sleep coordinator owns suspend.
pub enum Event {
    Session(Session),
}
pub fn watch(uid: u32, tx: Sender<Event>) {
    std::thread::spawn(move || {
        loop {
            let s = session(uid).unwrap_or_default();
            if tx.send(Event::Session(s)).is_err() {
                break;
            }
            std::thread::sleep(Duration::from_secs(1));
        }
    });
}
pub fn agent_unit(user: &User, action: &str) -> Result<()> {
    let mut c = process::clean_command("/usr/bin/systemctl");
    c.args([
        action,
        &format!("ssh-keys-agent@{}.socket", user.uid),
        &format!("ssh-keys-agent@{}.service", user.uid),
    ]);
    process::wait(c.spawn()?, 3)
}
pub fn notify_watchdog() {
    unsafe extern "C" {
        fn sd_notify(unset_environment: libc::c_int, state: *const libc::c_char) -> libc::c_int;
    }
    unsafe {
        sd_notify(0, c"WATCHDOG=1".as_ptr());
    }
}
#[link(name = "systemd")]
unsafe extern "C" {}

#[cfg(test)]
mod sleep_tests {
    use super::*;

    #[test]
    fn marker_presence_and_inspection_errors_fail_closed_without_following_links() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let marker = directory.path().join("active");
        assert!(!sleep_marker_active(&marker));
        fs::write(&marker, b"disposable marker").unwrap();
        assert!(sleep_marker_active(&marker));
        fs::remove_file(&marker).unwrap();
        symlink(directory.path().join("absent-target"), &marker).unwrap();
        assert!(sleep_marker_active(&marker));
        fs::remove_file(&marker).unwrap();
        fs::create_dir(&marker).unwrap();
        assert!(sleep_marker_active(&marker));
        let not_directory = directory.path().join("regular-file");
        fs::write(&not_directory, b"disposable fixture").unwrap();
        assert!(sleep_marker_active(&not_directory.join("active")));
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use std::os::unix::{fs::symlink, net::UnixListener};

    fn login() -> LoginSession {
        LoginSession {
            id: "42".into(),
            uid: 1000,
            leader: 1200,
            scope: "session-42.scope".into(),
            locked: false,
        }
    }
    fn record() -> String {
        "# logind state\nUID=1000\nACTIVE=1\nREMOTE=0\nTYPE=wayland\nLEADER=1200\nSCOPE=session-42.scope\nCONTROLLER=:1.52\n".into()
    }
    #[test]
    fn controller_record_requires_exact_session_and_unique_required_fields() {
        assert_eq!(
            controller_from_record(&record(), &login()).unwrap(),
            ":1.52"
        );
        for (old, new) in [
            ("UID=1000", "UID=1001"),
            ("ACTIVE=1", "ACTIVE=0"),
            ("REMOTE=0", "REMOTE=1"),
            ("TYPE=wayland", "TYPE=x11"),
            ("LEADER=1200", "LEADER=1201"),
            ("SCOPE=session-42.scope", "SCOPE=session-43.scope"),
            ("CONTROLLER=:1.52", "CONTROLLER=org.example.fake"),
            ("CONTROLLER=:1.52", "CONTROLLER=\":1.52\""),
            ("CONTROLLER=:1.52", ""),
            ("UID=1000", "UID=1000\nUID=1000"),
        ] {
            assert!(
                controller_from_record(&record().replace(old, new), &login()).is_err(),
                "accepted {new}"
            );
        }
        assert!(controller_from_record("unknown format", &login()).is_err());
        assert!(controller_from_record(&(record() + "CONTROLLER=:1.99\n"), &login()).is_err());
    }
    #[test]
    fn names_reject_paths_and_untrusted_bus_aliases() {
        for id in ["", "../1", "1/2", ".", "42\n", "_42"] {
            assert!(!valid_session_id(id));
        }
        for name in [
            "",
            ":1",
            ":1.2.3",
            ":.2",
            "org.freedesktop.login1",
            ":1.2\n",
        ] {
            assert!(!valid_controller(name));
        }
        for name in [
            "wayland-",
            "wayland-0.lock",
            "../wayland-1",
            "/tmp/wayland-1",
            "wayland-1/2",
        ] {
            assert!(!valid_display_name(name));
        }
        assert!(valid_display_name("wayland-10"));
    }
    #[test]
    fn cgroups_exclude_other_users_sessions_nested_and_app_scopes() {
        let valid = "0::/user.slice/user-1000.slice/user@1000.service/session.slice/wayland-wm@hyprland.desktop.service";
        assert!(valid_cgroup(valid, 1000, "42"));
        assert!(valid_cgroup(
            "0::/user.slice/user-1000.slice/session-42.scope\n",
            1000,
            "42"
        ));
        for group in [
            valid.replace("1000", "1001"),
            valid.replace("session.slice", "app.slice"),
            format!("{valid}/nested"),
            format!("{valid}\n{valid}"),
            "0::/user.slice/user-1000.slice/session-43.scope".into(),
        ] {
            assert!(!valid_cgroup(&group, 1000, "42"));
        }
    }
    #[test]
    fn process_start_identity_parses_comm_parentheses_and_checks_pid() {
        let mut fields = vec!["S"; 20];
        fields[19] = "123456";
        let stat = format!("1373 (Hyprland (test) name) {}", fields.join(" "));
        assert_eq!(start_ticks(&stat, 1373).unwrap(), 123456);
        assert!(start_ticks(&stat, 1374).is_err());
        assert!(start_ticks("1373 (Hyprland) S", 1373).is_err());
        assert!(start_ticks(&stat.replace("123456", "0"), 1373).is_err());
    }
    #[test]
    fn record_files_are_bounded_regular_and_never_follow_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let data = directory.path().join("record");
        fs::write(&data, record()).unwrap();
        assert_eq!(bounded_text(&data, false).unwrap(), record());
        let link = directory.path().join("link");
        symlink(&data, &link).unwrap();
        assert!(bounded_text(&link, false).is_err());
        fs::set_permissions(&data, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(bounded_text(&data, true).is_err());
        fs::write(&data, vec![b'x'; MAX_SESSION_BYTES as usize + 1]).unwrap();
        assert!(bounded_text(&data, false).is_err());
        fs::write(&data, b"UID=1000\0").unwrap();
        assert!(bounded_text(&data, false).is_err());
        assert!(bounded_text(directory.path(), false).is_err());
    }
    #[test]
    fn connected_socket_authenticates_peer_pid_uid_and_rejects_symlinks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("wayland-0");
        let listener = UnixListener::bind(&path).unwrap();
        let uid = unsafe { libc::getuid() };
        let pid = unsafe { libc::getpid() } as u32;
        let mut verified = display_socket(&path, uid, pid).unwrap();
        let (mut accepted, _) = listener.accept().unwrap();
        assert!(display_socket(&path, uid, pid + 1).is_err());
        assert!(display_socket(&path, uid.wrapping_add(1), pid).is_err());
        let link = directory.path().join("wayland-1");
        symlink(&path, &link).unwrap();
        assert!(display_socket(&link, uid, pid).is_err());
        // Replacement of a pathname does not replace the already verified FD.
        fs::remove_file(&path).unwrap();
        let _replacement = UnixListener::bind(&path).unwrap();
        accepted
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        verified.write_all(b"x").unwrap();
        let mut byte = [0];
        accepted.read_exact(&mut byte).unwrap();
        assert_eq!(byte, *b"x");
    }
    #[test]
    fn discovery_rejects_ambiguous_authenticated_sockets() {
        let directory = tempfile::tempdir().unwrap();
        let uid = unsafe { libc::getuid() };
        let pid = unsafe { libc::getpid() } as u32;
        let first = UnixListener::bind(directory.path().join("wayland-0")).unwrap();
        assert_eq!(
            discover_display_in(directory.path(), uid, pid).unwrap(),
            "wayland-0"
        );
        let _ = first.accept().unwrap();
        let _second = UnixListener::bind(directory.path().join("wayland-1")).unwrap();
        assert!(discover_display_in(directory.path(), uid, pid).is_err());
        assert!(discover_display_in(directory.path(), uid, pid + 1).is_err());
    }
    #[test]
    fn pidfd_pins_a_live_process_and_unknown_pids_fail() {
        let pin = pin_process(unsafe { libc::getpid() } as u32).unwrap();
        require_alive(&pin).unwrap();
        assert!(pin_process(u32::MAX).is_err());
    }
    #[test]
    #[ignore = "read-only integration with an unlocked local Omarchy session"]
    fn real_session_controller_connection() {
        let user = User::get(unsafe { libc::getuid() }).unwrap();
        let found = session(user.uid).unwrap();
        assert!(found.available && !found.locked);
        let display = found.display.unwrap();
        let connected = connect_display(&user, &display).unwrap();
        assert!(connected.peer_addr().is_ok());
        println!(
            "verified logind session {}, controller {}, Hyprland PID {}, socket {}",
            display.session_id, display.controller, display.compositor_pid, display.wayland
        );
    }
}
