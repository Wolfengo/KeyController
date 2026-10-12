use serde_json::Value;
use ssh_keys::{
    Error, Result, client,
    protocol::{self, Command},
};
use std::{
    io::IsTerminal,
    sync::atomic::{AtomicI32, Ordering},
    time::Duration,
};

const HELP: &str = "kctrl — request SSH key access in your local graphical session\n\n  capabilities [--json]\n  keys list [--json]\n  keys status --key ID [--json]\n  keys unlock --key ID --interactive [--reason TEXT] [--wait | --no-wait] [--json]\n  requests status REQUEST-ID [--json]\n  requests cancel REQUEST-ID [--json]\n\nUnlock waits for a terminal result by default. --no-wait returns pending immediately.\nExit status: 0 completed query/unlock, 3 pending (NOT unlocked), 1 error/denial/cancel,\n130 interrupted by Ctrl+C, 143 terminated by SIGTERM.\nRequests expire after 120 seconds. Waiting allows 5 extra seconds for server cleanup,\nthen attempts cancellation once. Ctrl+C/SIGTERM also attempt cancellation; a shared\nrequest may be cancelled for all its waiters. JSON output is one final response.\nFingerprint scanning starts when the protected window appears; access still requires\na successful fingerprint. Password unlock requires the key passphrase in that window.\nNo passphrase, policy, binding or file-encryption arguments are accepted.\nA loaded key is available to other processes of your user; revocation does not close\nexisting SSH connections. API v1. See /usr/share/doc/keycontroller/api.md.";
const WAIT_LIMIT: Duration = Duration::from_secs(protocol::REQUEST_SECONDS + 5);
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const RPC_LIMIT: Duration = Duration::from_secs(5);
const CANCEL_LIMIT: Duration = Duration::from_secs(2);
static INTERRUPTED: AtomicI32 = AtomicI32::new(0);

struct Invocation {
    command: Command,
    wait: bool,
}

fn parse(args: &[String]) -> Result<Invocation> {
    let first = args.first().ok_or(Error("usage"))?;
    let (mut c, mut i) = if first == "capabilities" {
        (Command::new("capabilities"), 1)
    } else {
        let second = args.get(1).ok_or(Error("usage"))?;
        let action = format!("{first}.{second}");
        if ![
            "keys.list",
            "keys.status",
            "keys.unlock",
            "requests.status",
            "requests.cancel",
        ]
        .contains(&action.as_str())
        {
            return Err(Error("usage"));
        }
        (Command::new(&action), 2)
    };
    if c.action.starts_with("requests.") {
        c.request_id = Some(
            args.get(i)
                .filter(|v| !v.starts_with('-'))
                .ok_or(Error("usage"))?
                .clone(),
        );
        i += 1;
    }
    let mut wait = None;
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {}
            "--interactive" if c.action == "keys.unlock" => c.interactive = true,
            "--wait" | "--no-wait" if c.action == "keys.unlock" => {
                if wait.is_some() {
                    return Err(Error("usage"));
                }
                wait = Some(args[i] == "--wait");
            }
            "--key" if c.action == "keys.status" || c.action == "keys.unlock" => {
                i += 1;
                if c.key.is_some() {
                    return Err(Error("usage"));
                }
                c.key = Some(args.get(i).ok_or(Error("usage"))?.clone());
            }
            "--reason" if c.action == "keys.unlock" => {
                i += 1;
                c.reason = args.get(i).ok_or(Error("usage"))?.clone();
            }
            _ => return Err(Error("usage")),
        }
        i += 1;
    }
    if (c.action == "keys.status" || c.action == "keys.unlock") && c.key.is_none() {
        return Err(Error("usage"));
    }
    if c.action == "keys.unlock" && !c.interactive {
        return Err(Error("interaction_required"));
    }
    c.validate()?;
    let wait = c.action == "keys.unlock" && wait.unwrap_or(true);
    Ok(Invocation { command: c, wait })
}

extern "C" fn interrupted(signal: libc::c_int) {
    // Only a lock-free flag is touched inside the signal handler. IPC and
    // output remain in normal control flow, never in signal context.
    let _ = INTERRUPTED.compare_exchange(0, signal, Ordering::Relaxed, Ordering::Relaxed);
}

struct Signals {
    int: libc::sigaction,
    term: libc::sigaction,
}
impl Signals {
    fn install() -> Result<Self> {
        unsafe {
            let mut action: libc::sigaction = std::mem::zeroed();
            action.sa_sigaction = interrupted as *const () as usize;
            libc::sigemptyset(&mut action.sa_mask);
            let mut previous = Self {
                int: std::mem::zeroed(),
                term: std::mem::zeroed(),
            };
            if libc::sigaction(libc::SIGINT, &action, &mut previous.int) != 0 {
                return Err(Error("signal_handler_failed"));
            }
            if libc::sigaction(libc::SIGTERM, &action, &mut previous.term) != 0 {
                libc::sigaction(libc::SIGINT, &previous.int, std::ptr::null_mut());
                return Err(Error("signal_handler_failed"));
            }
            Ok(previous)
        }
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        unsafe {
            libc::sigaction(libc::SIGINT, &self.int, std::ptr::null_mut());
            libc::sigaction(libc::SIGTERM, &self.term, std::ptr::null_mut());
        }
    }
}

fn boottime() -> Result<Duration> {
    let mut value: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_BOOTTIME, &mut value) } != 0 {
        return Err(Error("clock_unavailable"));
    }
    Ok(Duration::new(value.tv_sec as u64, value.tv_nsec as u32))
}

trait WaitIo {
    fn call(&mut self, command: &Command, timeout: Duration) -> Result<Value>;
    fn elapsed(&self) -> Duration;
    fn interrupted(&self) -> bool;
    fn pause(&mut self, duration: Duration);
    fn progress(&mut self);
}
struct LocalIo {
    started: Duration,
    progress: bool,
}
impl WaitIo for LocalIo {
    fn call(&mut self, command: &Command, timeout: Duration) -> Result<Value> {
        client::call_with_timeout(command, timeout)
    }
    fn elapsed(&self) -> Duration {
        // Suspended time counts toward the CLI's own bound. A clock failure
        // ends waiting rather than extending authorization or returning success.
        boottime()
            .map(|now| now.saturating_sub(self.started))
            .unwrap_or(Duration::MAX)
    }
    fn interrupted(&self) -> bool {
        INTERRUPTED.load(Ordering::Relaxed) != 0
    }
    fn pause(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
    fn progress(&mut self) {
        if self.progress {
            eprintln!(
                "Waiting for KeyController authentication… (Ctrl+C stops waiting and requests cancellation)"
            );
        }
    }
}

fn identifier(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|id| !id.is_empty() && id.len() <= 512 && !id.chars().any(char::is_control))
}
fn request_command(action: &str, id: &str) -> Command {
    let mut command = Command::new(action);
    command.request_id = Some(id.into());
    command
}
fn local_error(code: &str, key: Option<&str>, request: Option<&str>) -> Value {
    protocol::response("error", key, request, None, Some(code))
}
fn stop_wait(io: &mut impl WaitIo, key: &str, id: &str, code: &str) -> Value {
    // Best effort and exactly once. Cancellation can race completion or a
    // disconnected helper, so never claim the server confirmed cancellation.
    let _ = io.call(&request_command("requests.cancel", id), CANCEL_LIMIT);
    local_error(code, Some(key), Some(id))
}
fn wait_failure(io: &impl WaitIo) -> Option<&'static str> {
    if io.interrupted() {
        Some("interrupted")
    } else if io.elapsed() >= WAIT_LIMIT {
        Some("wait_timeout")
    } else {
        None
    }
}
fn terminal(value: &Value) -> bool {
    matches!(
        value["state"].as_str(),
        Some("unlocked" | "error" | "cancelled" | "denied" | "expired")
    )
}
fn run(invocation: Invocation, io: &mut impl WaitIo) -> Value {
    if invocation.wait && io.interrupted() {
        return protocol::error("interrupted");
    }
    let initial = match io.call(
        &invocation.command,
        if invocation.wait {
            RPC_LIMIT
        } else {
            Duration::from_secs(10)
        },
    ) {
        Ok(value) => value,
        Err(error) => {
            return protocol::error(if io.interrupted() {
                "interrupted"
            } else {
                error.0
            });
        }
    };
    if !invocation.wait {
        return initial;
    }
    if initial["state"] != "pending" {
        if io.interrupted() {
            return local_error("interrupted", identifier(&initial["key_id"]), None);
        }
        return if initial["api_version"] == protocol::API
            && terminal(&initial)
            && (initial["state"] != "unlocked"
                || (identifier(&initial["key_id"]).is_some() && initial["error_code"].is_null()))
        {
            initial
        } else {
            protocol::error("invalid_response")
        };
    }
    if initial["api_version"] != protocol::API || !initial["error_code"].is_null() {
        return protocol::error("invalid_response");
    }
    let (Some(key), Some(id)) = (
        identifier(&initial["key_id"]),
        identifier(&initial["request_id"]),
    ) else {
        return protocol::error("invalid_response");
    };
    io.progress();
    loop {
        if let Some(code) = wait_failure(io) {
            return stop_wait(io, key, id, code);
        }
        io.pause(POLL_INTERVAL.min(WAIT_LIMIT.saturating_sub(io.elapsed())));
        if let Some(code) = wait_failure(io) {
            return stop_wait(io, key, id, code);
        }
        let response = io.call(
            &request_command("requests.status", id),
            RPC_LIMIT.min(WAIT_LIMIT.saturating_sub(io.elapsed())),
        );
        if let Some(code) = wait_failure(io) {
            return stop_wait(io, key, id, code);
        }
        let mut response = match response {
            Ok(value) => value,
            Err(error) => return stop_wait(io, key, id, error.0),
        };
        let state = response["state"].as_str().unwrap_or("");
        let matching = response["key_id"] == key && response["request_id"] == id;
        if response["api_version"] != protocol::API
            || (!matching
                && !(state == "error"
                    && response["key_id"].is_null()
                    && response["request_id"].is_null()))
            || (state != "pending" && !terminal(&response))
            || (matches!(state, "pending" | "unlocked") && !response["error_code"].is_null())
        {
            return stop_wait(io, key, id, "invalid_response");
        }
        if state == "pending" {
            continue;
        }
        if state == "unlocked" {
            // Request history can outlive actual agent access (including sleep
            // or timer expiry). Verify current access without another unlock.
            let mut status = Command::new("keys.status");
            status.key = Some(key.into());
            let current = io.call(
                &status,
                RPC_LIMIT.min(WAIT_LIMIT.saturating_sub(io.elapsed())),
            );
            if let Some(code) = wait_failure(io) {
                return stop_wait(io, key, id, code);
            }
            let current = match current {
                Ok(value) => value,
                Err(error) => return stop_wait(io, key, id, error.0),
            };
            if current["api_version"] == protocol::API && current["state"] == "error" {
                return local_error(
                    current["error_code"].as_str().unwrap_or("invalid_response"),
                    Some(key),
                    Some(id),
                );
            }
            if current["api_version"] != protocol::API || current["key_id"] != key {
                return stop_wait(io, key, id, "invalid_response");
            }
            if current["state"] != "unlocked" || !current["error_code"].is_null() {
                return local_error("unlock_not_active", Some(key), Some(id));
            }
            response["expires_at"] = current["expires_at"].clone();
        } else if state == "error" && response["request_id"].is_null() {
            response["request_id"] = Value::String(id.into());
            response["key_id"] = Value::String(key.into());
        }
        return response;
    }
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return;
    }
    let json = args.iter().any(|a| a == "--json");
    let mut _signals = None;
    let mut result = (|| -> Result<Value> {
        let invocation = parse(&args)?;
        if invocation.wait {
            _signals = Some(Signals::install()?);
        }
        let mut io = LocalIo {
            started: boottime()?,
            progress: !json && std::io::stderr().is_terminal(),
        };
        Ok(run(invocation, &mut io))
    })()
    .unwrap_or_else(|e| protocol::error(e.0));
    let signal = INTERRUPTED.load(Ordering::Relaxed);
    if signal != 0 && result["state"] == "unlocked" {
        result = local_error(
            "interrupted",
            identifier(&result["key_id"]),
            identifier(&result["request_id"]),
        );
    }
    let exit = client::print(&result, json);
    std::process::exit(if signal == 0 { exit } else { 128 + signal });
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    const KEY: &str = "SHA256:disposable-public-test-fingerprint";
    const REQUEST: &str = "disposable-request";

    fn invocation(extra: &[&str]) -> Invocation {
        let mut args = vec!["keys", "unlock", "--key", "fixture", "--interactive"];
        args.extend_from_slice(extra);
        parse(&args.into_iter().map(String::from).collect::<Vec<_>>()).unwrap()
    }
    fn reply(state: &str) -> Value {
        protocol::response(state, Some(KEY), Some(REQUEST), None, None)
    }
    #[derive(Default)]
    struct FakeIo {
        replies: VecDeque<Result<Value>>,
        calls: Vec<Value>,
        timeouts: Vec<Duration>,
        elapsed: Duration,
        jump_on_pause: Option<Duration>,
        interrupted: bool,
        interrupt_after_call: Option<usize>,
        raise_after_call: Option<(usize, i32)>,
        real_signals: bool,
        progress: usize,
    }
    impl FakeIo {
        fn replies(replies: Vec<Value>) -> Self {
            Self {
                replies: replies.into_iter().map(Ok).collect(),
                ..Self::default()
            }
        }
        fn actions(&self) -> Vec<&str> {
            self.calls
                .iter()
                .map(|command| command["action"].as_str().unwrap())
                .collect()
        }
        fn assert_one_unlock(&self) {
            assert_eq!(
                self.actions()
                    .iter()
                    .filter(|action| **action == "keys.unlock")
                    .count(),
                1
            );
            for command in &self.calls {
                if matches!(
                    command["action"].as_str(),
                    Some("requests.status" | "requests.cancel")
                ) {
                    assert_eq!(command["request_id"], REQUEST);
                    assert!(command["key"].is_null());
                }
            }
        }
    }
    impl WaitIo for FakeIo {
        fn call(&mut self, command: &Command, timeout: Duration) -> Result<Value> {
            self.calls.push(serde_json::to_value(command).unwrap());
            self.timeouts.push(timeout);
            assert!(!timeout.is_zero());
            if self.interrupt_after_call == Some(self.calls.len()) {
                self.interrupted = true;
            }
            if let Some((call, signal)) = self.raise_after_call
                && call == self.calls.len()
            {
                assert_eq!(unsafe { libc::raise(signal) }, 0);
            }
            self.replies.pop_front().expect("unexpected extra IPC call")
        }
        fn elapsed(&self) -> Duration {
            self.elapsed
        }
        fn interrupted(&self) -> bool {
            self.interrupted || (self.real_signals && INTERRUPTED.load(Ordering::Relaxed) != 0)
        }
        fn pause(&mut self, duration: Duration) {
            self.elapsed += self.jump_on_pause.take().unwrap_or(duration);
        }
        fn progress(&mut self) {
            self.progress += 1;
        }
    }

    #[test]
    fn wait_is_default_only_for_interactive_unlock_and_flags_are_exclusive() {
        assert!(invocation(&[]).wait);
        assert!(invocation(&["--wait"]).wait);
        assert!(!invocation(&["--no-wait"]).wait);
        for args in [
            vec!["keys", "list", "--wait"],
            vec!["requests", "status", REQUEST, "--no-wait"],
            vec!["keys", "unlock", "--key", "fixture", "--wait"],
            vec![
                "keys",
                "unlock",
                "--key",
                "fixture",
                "--interactive",
                "--wait",
                "--no-wait",
            ],
            vec![
                "keys",
                "unlock",
                "--key",
                "fixture",
                "--interactive",
                "--wait",
                "--wait",
            ],
            vec![
                "keys",
                "unlock",
                "--key",
                "fixture",
                "--interactive",
                "--no-wait",
                "--no-wait",
            ],
        ] {
            assert!(parse(&args.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
        }
        assert!(!parse(&["capabilities".into()]).unwrap().wait);
    }

    #[test]
    fn default_wait_polls_only_one_request_then_checks_current_access() {
        let mut current = reply("unlocked");
        current["expires_at"] = serde_json::json!(123456);
        let mut io = FakeIo::replies(vec![
            reply("pending"),
            reply("pending"),
            reply("unlocked"),
            current,
        ]);
        let result = run(invocation(&["--json"]), &mut io);
        assert_eq!(result["state"], "unlocked");
        assert_eq!(result["expires_at"], 123456);
        assert_eq!(
            io.actions(),
            [
                "keys.unlock",
                "requests.status",
                "requests.status",
                "keys.status"
            ]
        );
        assert_eq!(io.calls.last().unwrap()["key"], KEY);
        assert_eq!(io.progress, 1);
        assert!(io.elapsed < WAIT_LIMIT);
        io.assert_one_unlock();
    }

    #[test]
    fn no_wait_preserves_pending_and_loaded_keys_return_immediately() {
        let mut io = FakeIo::replies(vec![reply("pending")]);
        let result = run(invocation(&["--no-wait"]), &mut io);
        assert_eq!(result["state"], "pending");
        assert_eq!(client::print(&result, true), 3);
        assert_eq!(io.actions(), ["keys.unlock"]);
        assert_eq!(io.progress, 0);
        let mut loaded = reply("unlocked");
        loaded["request_id"] = Value::Null;
        loaded["expires_at"] = serde_json::json!(123456);
        let mut io = FakeIo::replies(vec![loaded.clone()]);
        assert_eq!(run(invocation(&[]), &mut io), loaded);
        assert_eq!(io.actions(), ["keys.unlock"]);
        assert_eq!(io.elapsed, Duration::ZERO);
    }

    #[test]
    fn denial_cancel_lock_sleep_and_server_expiry_are_terminal_without_retry() {
        for (state, code) in [
            ("denied", "biometric_denied"),
            ("cancelled", "cancelled"),
            ("cancelled", "session_locked"),
            ("cancelled", "sleep_in_progress"),
            ("expired", "request_expired"),
            ("error", "prompt_unavailable"),
        ] {
            let mut terminal = reply(state);
            terminal["error_code"] = Value::String(code.into());
            let mut io = FakeIo::replies(vec![reply("pending"), terminal.clone()]);
            assert_eq!(run(invocation(&[]), &mut io), terminal);
            assert_eq!(io.actions(), ["keys.unlock", "requests.status"]);
            io.assert_one_unlock();
        }
    }

    #[test]
    fn completed_history_is_not_access_after_lifetime_expiry_or_sleep() {
        for (current, code) in [
            (reply("locked"), "unlock_not_active"),
            (
                protocol::error("session_locked_or_unavailable"),
                "session_locked_or_unavailable",
            ),
        ] {
            let mut io = FakeIo::replies(vec![reply("pending"), reply("unlocked"), current]);
            let result = run(invocation(&[]), &mut io);
            assert_eq!(result["state"], "error");
            assert_eq!(result["error_code"], code);
            assert_eq!(result["request_id"], REQUEST);
            io.assert_one_unlock();
        }
    }

    #[test]
    fn local_deadline_is_bounded_and_cancelled_once_without_claiming_server_expiry() {
        let mut io = FakeIo::replies(vec![reply("pending"), reply("cancelled")]);
        io.jump_on_pause = Some(WAIT_LIMIT + Duration::from_secs(20));
        let result = run(invocation(&[]), &mut io);
        assert_eq!(result["state"], "error");
        assert_eq!(result["error_code"], "wait_timeout");
        assert_eq!(io.actions(), ["keys.unlock", "requests.cancel"]);
        assert_eq!(io.timeouts.last(), Some(&CANCEL_LIMIT));
        io.assert_one_unlock();
    }

    #[test]
    fn pending_polls_never_reset_the_deadline_and_have_bounded_rpc_budgets() {
        let mut io = FakeIo::replies(vec![reply("pending"); 300]);
        let result = run(invocation(&[]), &mut io);
        assert_eq!(result["error_code"], "wait_timeout");
        assert_eq!(io.elapsed, WAIT_LIMIT);
        assert_eq!(io.actions().last(), Some(&"requests.cancel"));
        assert_eq!(
            io.actions()
                .iter()
                .filter(|action| **action == "requests.cancel")
                .count(),
            1
        );
        assert!(io.timeouts.iter().all(|timeout| *timeout <= RPC_LIMIT));
        io.assert_one_unlock();
    }

    #[test]
    fn interrupt_cancels_exact_request_even_when_server_completion_races_it() {
        for after in [1, 2, 3] {
            let mut responses = vec![reply("pending")];
            responses.extend((1..after).map(|_| reply("unlocked")));
            responses.push(reply("unlocked")); // Cancellation races an already completed request.
            let mut io = FakeIo::replies(responses);
            io.interrupt_after_call = Some(after);
            let result = run(invocation(&[]), &mut io);
            assert_eq!(result["state"], "error");
            assert_eq!(result["error_code"], "interrupted");
            assert_eq!(io.actions().last(), Some(&"requests.cancel"));
            assert_eq!(
                io.actions()
                    .iter()
                    .filter(|action| **action == "requests.cancel")
                    .count(),
                1
            );
            io.assert_one_unlock();
        }
        let mut io = FakeIo {
            interrupted: true,
            ..FakeIo::default()
        };
        assert_eq!(run(invocation(&[]), &mut io)["error_code"], "interrupted");
        assert!(io.calls.is_empty());
    }

    #[test]
    fn transport_failure_cancels_once_and_never_retries_unlock() {
        let mut io = FakeIo {
            replies: [
                Ok(reply("pending")),
                Err(Error("helper_unavailable")),
                Err(Error("helper_unavailable")),
            ]
            .into(),
            ..FakeIo::default()
        };
        let result = run(invocation(&[]), &mut io);
        assert_eq!(result["state"], "error");
        assert_eq!(result["error_code"], "helper_unavailable");
        assert_eq!(result["request_id"], REQUEST);
        assert_eq!(
            io.actions(),
            ["keys.unlock", "requests.status", "requests.cancel"]
        );
        io.assert_one_unlock();
    }

    #[test]
    fn mismatched_or_malformed_status_cannot_authorize_the_requested_key() {
        for replacement in [
            serde_json::json!({"state":"unlocked"}),
            protocol::response("unlocked", Some(KEY), Some("another-request"), None, None),
            protocol::response("unlocked", Some("another-key"), Some(REQUEST), None, None),
            reply("completed"),
        ] {
            let mut io = FakeIo::replies(vec![reply("pending"), replacement, reply("cancelled")]);
            assert_eq!(
                run(invocation(&[]), &mut io)["error_code"],
                "invalid_response"
            );
            assert_eq!(io.actions().last(), Some(&"requests.cancel"));
            io.assert_one_unlock();
        }
    }

    #[test]
    fn real_signal_handlers_only_record_and_normal_flow_cancels_one_request() {
        // Isolate actual signals from the parallel test runner. This environment
        // switch is confined to the test executable, never the production CLI.
        const FIXTURE: &str = "KEYCONTROLLER_CLI_TEST_SIGNAL";
        if let Ok(signal) = std::env::var(FIXTURE) {
            let signal: i32 = signal.parse().unwrap();
            assert!(matches!(signal, libc::SIGINT | libc::SIGTERM));
            let _signals = Signals::install().unwrap();
            let mut io = FakeIo::replies(vec![reply("pending"), reply("cancelled")]);
            io.real_signals = true;
            io.raise_after_call = Some((1, signal));
            let result = run(invocation(&["--json"]), &mut io);
            assert_eq!(result["error_code"], "interrupted");
            assert_eq!(INTERRUPTED.load(Ordering::Relaxed), signal);
            assert_eq!(io.actions(), ["keys.unlock", "requests.cancel"]);
            io.assert_one_unlock();
            client::print(&result, true);
            return;
        }
        for signal in [libc::SIGINT, libc::SIGTERM] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::real_signal_handlers_only_record_and_normal_flow_cancels_one_request",
                    "--nocapture",
                ])
                .env(FIXTURE, signal.to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let lines: Vec<Value> = String::from_utf8(output.stdout)
                .unwrap()
                .lines()
                .filter_map(|line| serde_json::from_str(line).ok())
                .collect();
            assert_eq!(lines.len(), 1);
            assert_eq!(lines[0]["state"], "error");
            assert_eq!(lines[0]["error_code"], "interrupted");
        }
    }

    #[test]
    fn secret_arguments_rejected() {
        for flags in [
            vec!["keys", "unlock", "--key", "a", "--passphrase", "secret"],
            vec!["keys", "encrypt", "--key", "a"],
            vec!["keys", "sync", "--key", "a"],
        ] {
            assert!(parse(&flags.into_iter().map(String::from).collect::<Vec<_>>()).is_err());
        }
    }
}
