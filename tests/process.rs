use ssh_keys::process;
use std::{
    fs,
    io::Read,
    os::{
        fd::AsRawFd,
        unix::{net::UnixStream, process::ExitStatusExt},
    },
    path::Path,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

struct Running(Child);
impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// Both builds use the same executable body. In the normal dynamically linked
// build, reaching main and writing readiness proves the constructor received
// and installed the private descriptors. The static build cannot run a
// preload constructor and must never see the fixture at all.
const PROBE: &str = r#"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "exec-closed")) {
        if (fcntl(4, F_GETFD) != FD_CLOEXEC) return 95;
        unsetenv("LD_PRELOAD");
        execl(argv[0], argv[0], argv[2], (char *)NULL);
        return 96;
    }
    if (argc == 2 && !strcmp(argv[1], "internal-askpass")) {
        int p[2];
        if (prctl(PR_GET_DUMPABLE) != 0 || pipe(p)) return 97;
        pid_t child = fork();
        if (child < 0) return 98;
        if (!child) {
            close(p[0]);
            if (dup2(p[1], 1) < 0) _exit(99);
            execlp(getenv("SSH_ASKPASS"), "unused", "fixture prompt", (char *)NULL);
            _exit(100);
        }
        close(p[1]);
        char data[64] = {0};
        ssize_t bytes = read(p[0], data, sizeof data);
        close(p[0]);
        int status;
        if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 101;
        const char expected[] = "nonsecret fixture for FD4\n";
        if (bytes != sizeof expected - 1 || memcmp(data, expected, bytes)) return 102;
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "internal-askpass-once")) {
        for (int attempt = 0; attempt < 2; attempt++) {
            int p[2];
            if (prctl(PR_GET_DUMPABLE) != 0 || fcntl(4, F_GETFD) != FD_CLOEXEC || pipe(p)) return 105;
            pid_t child = fork();
            if (child < 0) return 106;
            if (!child) {
                close(p[0]);
                if (prctl(PR_GET_DUMPABLE) != 0 || fcntl(4, F_GETFD) != FD_CLOEXEC) _exit(107);
                if (dup2(p[1], 1) < 0) _exit(108);
                close(p[1]);
                // This deliberately nonexistent helper can only succeed if
                // the preload serves the answer in this fork without exec.
                execlp(getenv("SSH_ASKPASS"), "unused", "fixture prompt", (char *)NULL);
                _exit(109);
            }
            close(p[1]);
            char data[64] = {0};
            size_t length = 0;
            while (length < sizeof data) {
                ssize_t bytes = read(p[0], data + length, sizeof data - length);
                if (bytes < 0 && errno == EINTR) continue;
                if (bytes < 0) return 110;
                if (!bytes) break;
                length += bytes;
            }
            close(p[0]);
            int status;
            if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status)) return 111;
            const char *expected = attempt == 0 ? "nonsecret fixture for FD4\n" : "\n";
            if (length != strlen(expected) || memcmp(data, expected, length)) return 112;
            if (lseek(4, 0, SEEK_CUR) != (off_t)strlen("nonsecret fixture for FD4")) return 113;
        }
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "abort-after-secret")) {
        char data[32];
        if (read(4, data, sizeof data) <= 0) return 103;
        raise(SIGABRT);
        return 104;
    }
    if (argc == 2) {
        char byte;
        if (read(4, &byte, 1) != -1 || errno != EBADF) return 90;
        int marker = open(argv[1], O_WRONLY | O_CREAT | O_EXCL, 0600);
        if (marker < 0 || write(marker, "no descriptor", 13) != 13) return 91;
        close(marker);
        return 0;
    }
    struct rlimit core;
    if (prctl(PR_GET_DUMPABLE) != 0 || getrlimit(RLIMIT_CORE, &core) != 0 ||
        core.rlim_cur != 0 || core.rlim_max != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)
        return 92;
    char fixture[32] = {0};
    const char expected[] = "nonsecret fixture for FD4";
    if (read(4, fixture, sizeof fixture) != sizeof expected - 1 ||
        memcmp(fixture, expected, sizeof expected - 1) != 0)
        return 93;
    if (write(5, "ready", 5) != 5) return 94;
    for (;;) pause();
}
"#;

fn compile_probe(dir: &Path, static_link: bool) -> std::path::PathBuf {
    let source = dir.join("probe.c");
    let binary = dir.join("probe");
    fs::write(&source, PROBE).unwrap();
    let mut compiler = Command::new("/usr/bin/cc");
    compiler.args(["-O2", "-Wall", "-Wextra", "-Werror"]);
    if static_link {
        compiler.arg("-static");
    }
    let result = compiler
        .arg(&source)
        .arg("-o")
        .arg(&binary)
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "compiling the process probe failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    binary
}

#[test]
fn protected_descriptors_are_inaccessible_after_confirmed_startup_and_cancel_is_final() {
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "run this same-UID isolation test as an unprivileged user"
    );
    let dir = tempfile::tempdir().unwrap();
    let binary = compile_probe(dir.path(), false);
    let fixture = process::memfile(b"nonsecret fixture for FD4", true).unwrap();
    let (mut ready, child_ready) = UnixStream::pair().unwrap();
    ready
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    let mut command = process::clean_command(binary.to_str().unwrap());
    let mut child = Running(
        process::protected_spawn(
            &mut command,
            &[(fixture.as_raw_fd(), 4), (child_ready.as_raw_fd(), 5)],
        )
        .unwrap(),
    );
    drop(child_ready);
    let mut message = [0; 5];
    ready.read_exact(&mut message).unwrap();
    assert_eq!(&message, b"ready");
    let pid = child.0.id();
    let fd = format!("/proc/{pid}/fd/4");
    let error =
        fs::read(&fd).expect_err("same-UID parent must not read the child's private descriptor");
    assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    assert!(fs::read_link(&fd).is_err());
    let limits = fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
    let core = limits
        .lines()
        .find(|line| line.starts_with("Max core file size"))
        .unwrap();
    let fields: Vec<_> = core.split_whitespace().collect();
    assert_eq!(&fields[4..6], &["0", "0"]);
    assert!(child.0.try_wait().unwrap().is_none());
    child.0.kill().unwrap();
    assert_eq!(child.0.wait().unwrap().signal(), Some(libc::SIGKILL));
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
    assert_eq!(ready.read(&mut message).unwrap(), 0);
}

#[test]
fn missing_hardening_constructor_never_receives_the_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile_probe(dir.path(), true);
    let marker = dir.path().join("no-descriptor");
    let fixture = process::memfile(b"nonsecret fixture for FD4", true).unwrap();
    let mut command = process::clean_command(binary.to_str().unwrap());
    command.arg(&marker);
    let started = Instant::now();
    let result = process::protected_spawn(&mut command, &[(fixture.as_raw_fd(), 4)]);
    assert!(matches!(result, Err(ssh_keys::Error("hardening_failed"))));
    assert!(started.elapsed() < Duration::from_secs(4));
    assert_eq!(fs::read(&marker).unwrap(), b"no descriptor");
}

#[test]
fn a_protected_process_is_reaped_when_its_deadline_expires() {
    let fixture = process::memfile(b"nonsecret deadline fixture", true).unwrap();
    let mut command = process::clean_command("/usr/bin/sleep");
    command.arg("30").stderr(Stdio::null());
    let child = process::protected_spawn(&mut command, &[(fixture.as_raw_fd(), 4)]).unwrap();
    let pid = child.id();
    let result = process::wait(child, 1);
    assert!(matches!(result, Err(ssh_keys::Error("operation_timeout"))));
    assert!(!Path::new(&format!("/proc/{pid}")).exists());
}

#[test]
fn secondary_exec_loses_secret_descriptors_even_without_the_constructor() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile_probe(dir.path(), false);
    let marker = dir.path().join("exec-has-no-secret");
    let fixture = process::memfile(b"nonsecret fixture for FD4", true).unwrap();
    let mut command = process::clean_command(binary.to_str().unwrap());
    command.arg("exec-closed").arg(&marker);
    process::wait(
        process::protected_spawn(&mut command, &[(fixture.as_raw_fd(), 4)]).unwrap(),
        3,
    )
    .unwrap();
    assert_eq!(fs::read(marker).unwrap(), b"no descriptor");
}

#[test]
fn internal_askpass_answers_without_executing_any_helper() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile_probe(dir.path(), false);
    let fixture = process::memfile(b"nonsecret fixture for FD4", true).unwrap();
    let mut command = process::clean_command(binary.to_str().unwrap());
    // A real exec of this deliberately nonexistent helper cannot succeed.
    command
        .arg("internal-askpass")
        .env("SSH_KEYS_INTERNAL_ASKPASS", "1")
        .env("SSH_ASKPASS", dir.path().join("must-never-execute"));
    process::wait(
        process::protected_spawn(&mut command, &[(fixture.as_raw_fd(), 4)]).unwrap(),
        3,
    )
    .unwrap();
}

#[test]
fn one_shot_askpass_consumes_shared_offset_across_two_hardened_forks_without_exec() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile_probe(dir.path(), false);
    let fixture = process::memfile(b"nonsecret fixture for FD4", true).unwrap();
    let mut command = process::clean_command(binary.to_str().unwrap());
    command
        .arg("internal-askpass-once")
        .env("SSH_KEYS_INTERNAL_ASKPASS", "1")
        .env("SSH_KEYS_ASKPASS_ONCE", "1")
        .env("SSH_ASKPASS", dir.path().join("must-never-execute"));
    process::wait(
        process::protected_spawn(&mut command, &[(fixture.as_raw_fd(), 4)]).unwrap(),
        3,
    )
    .unwrap();
}

#[test]
fn crash_after_receiving_fixture_does_not_dump_core() {
    let dir = tempfile::tempdir().unwrap();
    let binary = compile_probe(dir.path(), false);
    let fixture = process::memfile(b"nonsecret fixture for FD4", true).unwrap();
    let mut command = process::clean_command(binary.to_str().unwrap());
    command.arg("abort-after-secret");
    let status = process::protected_spawn(&mut command, &[(fixture.as_raw_fd(), 4)])
        .unwrap()
        .wait()
        .unwrap();
    assert_eq!(status.signal(), Some(libc::SIGABRT));
    assert!(!status.core_dumped());
}

#[test]
fn real_askpass_exec_fails_closed_and_writes_no_secret() {
    let fixture = process::memfile(b"nonsecret fixture for FD4", true).unwrap();
    let mut command = process::clean_command(env!("CARGO_BIN_EXE_ssh-keysd"));
    command
        .env("SSH_KEYS_INTERNAL_ASKPASS", "1")
        .stdout(Stdio::piped());
    let result = process::protected_spawn(&mut command, &[(fixture.as_raw_fd(), 4)])
        .unwrap()
        .wait_with_output()
        .unwrap();
    assert!(!result.status.success());
    assert!(result.stdout.is_empty() && result.stderr.is_empty());
}
