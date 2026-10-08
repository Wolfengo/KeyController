use crate::{
    Error, Result,
    agent::{self, Guard},
    keys::{self, Key},
    platform::{self, Event, Session, User},
    process,
    protocol::{self, Command},
    state::{RequestGate, Rules, Settings},
    worker::{self, Job},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    os::unix::net::UnixListener,
    process::{Child, Stdio},
    sync::{Arc, Mutex, mpsc},
    time::{Duration, Instant},
};

struct Active {
    job: Job,
    child: Child,
    output: File,
    deadline: Instant,
    epoch: u64,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DialogRequest {
    action: String,
    #[serde(default)]
    value: Value,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ModeRequest {
    fingerprint_mode: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SleepCommand {
    api_version: u32,
    action: String,
}
impl SleepCommand {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let value: Value = serde_json::from_slice(bytes)?;
        if !value.is_object() {
            return Err(Error("invalid_json"));
        }
        Ok(serde_json::from_value(value)?)
    }
}

pub struct Server {
    user: User,
    backend_path: std::path::PathBuf,
    state_directory: std::path::PathBuf,
    sleep_marker: std::path::PathBuf,
    sleeping: bool,
    settings: Settings,
    inventory: Vec<Key>,
    guard: Arc<Mutex<Guard>>,
    session: Session,
    gate: RequestGate,
    active: Option<Active>,
    history: BTreeMap<String, Value>,
    history_order: VecDeque<String>,
    agent_reset_failed: bool,
    expiry: BTreeMap<String, Option<u64>>,
    external_epoch: u64,
    gate_clock: Instant,
    #[cfg(test)]
    reset_backend: fn(&Server) -> Result<()>,
    #[cfg(test)]
    save_global_settings: fn(&std::path::Path, &Settings) -> Result<platform::SaveOutcome>,
}
impl Server {
    fn save(&self) -> Result<()> {
        platform::save_json(&self.state_directory.join("settings.json"), &self.settings)
    }
    fn credential_path(&self, id: &str) -> std::path::PathBuf {
        self.state_directory.join(
            worker::credential_path(&self.user, id)
                .file_name()
                .expect("credential filename"),
        )
    }
    fn confirmation_operation(operation: &str) -> bool {
        matches!(operation, "rules.key" | "unbind")
    }
    fn operation_key(job: &Job) -> &str {
        job.key
            .as_ref()
            .map(|key| key.id.as_str())
            .unwrap_or("__scan")
    }
    fn commit_confirmation(&mut self, job: &Job, result: &Value) -> Result<()> {
        if result.get("ok") != Some(&Value::Bool(true))
            || result.get("confirmed") != Some(&Value::Bool(true))
        {
            return Err(Error("confirmation_required"));
        }
        self.require_available()?;
        match job.operation.as_str() {
            "rules.key" => {
                let key = job.key.as_ref().ok_or(Error("key_not_found"))?;
                let rules: Option<Rules> = serde_json::from_value(job.value.clone())?;
                if let Some(rules) = &rules {
                    rules.validate()?;
                }
                self.settings.keys.entry(key.id.clone()).or_default().rules = rules;
            }
            "unbind" => {
                let key = job.key.as_ref().ok_or(Error("key_not_found"))?;
                self.revoke(key)?;
                let path = self.credential_path(&key.id);
                if path.exists() {
                    fs::remove_file(path)?;
                    File::open(&self.state_directory)?.sync_all()?;
                }
                self.settings
                    .keys
                    .entry(key.id.clone())
                    .or_default()
                    .fingerprint_mode = false;
            }
            _ => return Err(Error("invalid_action")),
        }
        self.save()
    }
    fn backend(&self) -> std::path::PathBuf {
        self.backend_path.clone()
    }
    fn sleep_preparing(&self) -> bool {
        self.sleeping || platform::sleep_marker_active(&self.sleep_marker)
    }
    fn require_available(&self) -> Result<()> {
        if self.sleep_preparing() {
            return Err(Error("sleep_in_progress"));
        }
        if !self.session.available || self.session.locked || self.agent_reset_failed {
            return Err(Error("session_locked_or_unavailable"));
        }
        Ok(())
    }
    fn available(&self) -> bool {
        self.require_available().is_ok()
    }
    fn prepare_sleep(&mut self) -> Result<()> {
        self.sleeping = true;
        {
            // Serialize with every in-flight ADD and invalidate connections
            // accepted before preparation. The coordinator destroys the entire
            // helper/listener/backend after this ACK when revocation is on,
            // which also closes connections still in the kernel accept backlog.
            let mut guard = self.guard.lock().unwrap();
            guard.blocked = true;
            guard.generation = guard.generation.wrapping_add(1);
        }
        // Always cancel/reap pending work. Opting out preserves prior loaded
        // identities, never an unfinished load whose result was not delivered.
        self.cancel_active("cancelled", Some("sleep_in_progress"), true)?;
        self.refresh_guard();
        Ok(())
    }
    fn observe_sleep_marker(&mut self) -> Result<()> {
        if !self.sleeping && platform::sleep_marker_active(&self.sleep_marker) {
            self.prepare_sleep()?;
        }
        Ok(())
    }
    fn sleep_command(&mut self, cmd: SleepCommand, peer: libc::ucred) -> Result<Value> {
        if peer.uid != 0 {
            return Err(Error("wrong_user"));
        }
        if cmd.api_version != protocol::API {
            return Err(Error("api_mismatch"));
        }
        match cmd.action.as_str() {
            "sleep.prepare" => {
                if !platform::sleep_marker_active(&self.sleep_marker) {
                    return Err(Error("sleep_marker_missing"));
                }
                self.prepare_sleep()?;
            }
            "sleep.resume" => {
                if platform::sleep_marker_active(&self.sleep_marker) {
                    return Err(Error("sleep_in_progress"));
                }
                if self.sleeping {
                    // Fence clients accepted during preparation before allowing
                    // any new ADD. No key is loaded or lifetime renewed here.
                    {
                        let mut guard = self.guard.lock().unwrap();
                        guard.generation = guard.generation.wrapping_add(1);
                    }
                    self.sleeping = false;
                    self.refresh_guard();
                }
            }
            _ => return Err(Error("invalid_action")),
        }
        let mut value = protocol::response("ready", None, None, None, None);
        value["operation"] = json!(cmd.action);
        value["revoke_on_sleep"] = json!(self.settings.revoke_on_sleep);
        Ok(value)
    }
    fn refresh_guard(&self) {
        self.guard.lock().unwrap().blocked = !self.available();
    }
    fn update_session(&mut self, session: Session) -> Result<()> {
        self.session = session;
        self.refresh_guard();
        if !self.available() {
            // Closing consent windows is independent of loaded-key lifetime.
            // Preserve existing identities while cancelling an unfinished load.
            let reason = if self.sleep_preparing() {
                "sleep_in_progress"
            } else {
                "session_locked_or_unavailable"
            };
            self.cancel_active("cancelled", Some(reason), true)?;
        }
        Ok(())
    }
    fn remember(&mut self, id: String, value: Value) {
        if !self.history.contains_key(&id) {
            self.history_order.push_back(id.clone());
        }
        self.history.insert(id, value);
        while self.history_order.len() > 128 {
            if let Some(oldest) = self.history_order.pop_front() {
                self.history.remove(&oldest);
            }
        }
    }
    fn reset_agent(&mut self) -> Result<()> {
        let was_blocked = {
            let mut guard = self.guard.lock().unwrap();
            let was = guard.blocked;
            guard.blocked = true;
            guard.generation = guard.generation.wrapping_add(1);
            guard.external_epoch = guard.external_epoch.wrapping_add(1);
            guard.managed_added_at = None;
            was
        };
        self.expiry.clear();
        #[cfg(not(test))]
        let reset = platform::agent_unit(&self.user, "stop")
            .and_then(|()| platform::agent_unit(&self.user, "start"));
        // Unit tests must never control a real system service. Their backend
        // hook resets only the disposable agent allocated by each fixture.
        #[cfg(test)]
        let reset = (self.reset_backend)(self);
        if reset.is_err() {
            // Keep the proxy closed and make the service exit; systemd then
            // tears down every dependent socket and process before recovery.
            self.agent_reset_failed = true;
            return Err(Error("agent_reset_failed"));
        }
        self.guard.lock().unwrap().blocked = was_blocked;
        Ok(())
    }
    fn reconcile(&mut self) -> Result<BTreeMap<String, Vec<u8>>> {
        let epoch = self.guard.lock().unwrap().external_epoch;
        if epoch != self.external_epoch {
            self.expiry.clear();
            self.external_epoch = epoch;
        }
        let loaded = agent::list(&self.backend()).map_err(|_| Error("agent_unavailable"))?;
        self.expiry.retain(|id, _| loaded.contains_key(id));
        Ok(loaded)
    }
    fn status(&self, k: &Key, loaded: &BTreeMap<String, Vec<u8>>, desktop: bool) -> Value {
        let live = loaded.contains_key(&k.id);
        let known = self.expiry.get(&k.id);
        let mut v = protocol::response(
            if live { "unlocked" } else { "locked" },
            Some(&k.id),
            None,
            known.copied().flatten(),
            None,
        );
        let o = v.as_object_mut().unwrap();
        o.insert("name".into(), json!(k.name));
        o.insert("fingerprint".into(), json!(k.fingerprint));
        o.insert("path".into(), json!(k.path));
        o.insert("algorithm".into(), json!(k.algorithm));
        o.insert("encrypted".into(), json!(k.encrypted));
        o.insert("unavailable".into(), json!(k.unavailable));
        o.insert("unencrypted_copies".into(), json!(k.unencrypted_copies));
        o.insert("rules".into(), json!(self.settings.effective(&k.id)));
        o.insert(
            "inherits".into(),
            json!(
                self.settings
                    .keys
                    .get(&k.id)
                    .is_none_or(|s| s.rules.is_none())
            ),
        );
        o.insert("bound".into(), json!(self.credential_path(&k.id).is_file()));
        o.insert(
            "mode".into(),
            json!(if self
                .settings
                .keys
                .get(&k.id)
                .is_some_and(|s| s.fingerprint_mode)
            {
                "fingerprint"
            } else {
                "password"
            }),
        );
        o.insert("lifetime_known".into(), json!(live && known.is_some()));
        if let Some(active) = &self.active
            && active.job.key.as_ref().is_some_and(|x| x.id == k.id)
        {
            if desktop || active.job.operation == "unlock" {
                o.insert("request_id".into(), json!(active.job.request_id));
                o.insert("operation".into(), json!(active.job.operation));
            }
            o.insert("busy".into(), json!(true));
        }
        v
    }
    fn query(&mut self, candidates: bool) -> Result<Value> {
        let loaded = self.reconcile()?;
        let mut seen = BTreeSet::new();
        let keys: Vec<_> = self
            .inventory
            .iter()
            .filter(|k| candidates || (k.encrypted && seen.insert(k.id.clone())))
            .map(|k| self.status(k, &loaded, candidates))
            .collect();
        let mut v = protocol::response("ready", None, None, None, None);
        v["keys"] = json!(keys);
        v["global_rules"] = json!(self.settings.global_rules());
        if candidates {
            v["ui_language"] = json!(crate::locale::system_ui_language());
        }
        v["scanned"] = json!(self.settings.scanned);
        v["session_available"] = json!(self.available());
        v["sleep_preparing"] = json!(self.sleep_preparing());
        let active = self
            .active
            .as_ref()
            .filter(|a| candidates || a.job.operation == "unlock");
        v["active_request"] = json!(active.map(|a| &a.job.request_id));
        v["active_operation"] = json!(active.map(|a| &a.job.operation));
        Ok(v)
    }
    fn request(
        &mut self,
        key: Option<Key>,
        operation: &str,
        cmd: &Command,
        caller: &str,
    ) -> Result<Value> {
        if !matches!(
            operation,
            "scan" | "unlock" | "sync" | "encrypt" | "rules.key" | "unbind"
        ) {
            return Err(Error("invalid_operation"));
        }
        self.require_available()?;
        if operation != "scan" {
            let k = key.as_ref().ok_or(Error("key_not_found"))?;
            if k.unavailable.is_some() && !Self::confirmation_operation(operation) {
                return Err(Error("key_unavailable"));
            }
            if operation == "unlock" {
                let loaded = self.reconcile()?;
                if loaded.contains_key(&k.id) {
                    return Ok(self.status(k, &loaded, false));
                }
                if !k.encrypted {
                    return Err(Error("key_not_encrypted"));
                }
            }
        }
        if operation != "scan" && !cmd.interactive {
            return Err(Error("interaction_required"));
        }
        let key_id = key.as_ref().map(|k| k.id.as_str()).unwrap_or("__scan");
        if let Some(active) = &self.active
            && active.job.operation != operation
        {
            return Err(Error("busy"));
        }
        if Self::confirmation_operation(operation) && self.active.is_some() {
            return Err(Error("busy"));
        }
        let existing = if operation == "scan" {
            self.gate.check_active(key_id)?
        } else if operation == "unlock" {
            self.gate
                .check(key_id, self.gate_clock.elapsed().as_secs())?
        } else {
            self.gate
                .check_dialog(key_id, self.gate_clock.elapsed().as_secs())?
        };
        if let Some(id) = existing {
            return Ok(self
                .history
                .get(&id)
                .cloned()
                .unwrap_or_else(|| protocol::error("request_not_found")));
        }
        let request_id = platform::random_id()?;
        let rules = self.settings.effective(key_id);
        let job = Job {
            user: self.user.clone(),
            operation: operation.into(),
            key: key.clone(),
            request_id: request_id.clone(),
            reason: cmd.reason.clone(),
            caller: caller.into(),
            rules,
            value: cmd.value.clone(),
            fingerprint_mode: self
                .settings
                .keys
                .get(key_id)
                .is_some_and(|s| s.fingerprint_mode),
            bound: self.credential_path(key_id).is_file(),
            wayland: self.session.wayland.clone(),
            display: self.session.display.clone(),
        };
        let input = process::memfile(&serde_json::to_vec(&job)?, true)?;
        let output = process::memfile(&[], false)?;
        let mut c = process::clean_command("/usr/lib/ssh-keys/ssh-keysd");
        c.arg("--worker")
            // PAM progress uses a fixed, narrowly recognized message set.
            .env("LC_ALL", "C")
            .stdin(Stdio::from(input))
            .stdout(Stdio::from(output.try_clone()?));
        process::descriptors(&mut c, &[], None, true)?;
        // Hold the proxy guard across spawn so a fast loader is never mistaken
        // for an unrelated ssh-add before its process group is registered.
        let mut g = self.guard.lock().unwrap();
        let child = c.spawn()?;
        // A newly allocated leader cannot belong to a still-existing retired
        // group. Drop its old numeric tombstone if the kernel reused that PID.
        g.retired_worker_groups.remove(&(child.id() as i32));
        g.worker_group = Some(child.id() as i32);
        g.managed_added_at = None;
        g.managed_add_uncertain = false;
        let epoch = g.external_epoch;
        drop(g);
        self.gate.active = Some((key_id.into(), request_id.clone()));
        let mut v = protocol::response(
            "pending",
            key.as_ref().map(|k| k.id.as_str()),
            Some(&request_id),
            None,
            None,
        );
        v["operation"] = json!(operation);
        self.remember(request_id.clone(), v.clone());
        self.active = Some(Active {
            job,
            child,
            output,
            deadline: Instant::now() + Duration::from_secs(protocol::REQUEST_SECONDS),
            epoch,
        });
        Ok(v)
    }
    fn revoke(&mut self, key: &Key) -> Result<()> {
        let mut guard = self.guard.lock().unwrap();
        let was = guard.blocked;
        guard.blocked = true;
        let result = agent::list(&self.backend()).and_then(|list| {
            if list.contains_key(&key.id) {
                agent::remove_key(&self.backend(), key)
            } else {
                Ok(())
            }
        });
        if result.is_err() {
            drop(guard);
            if self
                .active
                .as_ref()
                .is_some_and(|active| active.job.operation == "unlock")
            {
                // Selective removal failed, so all identities must be reset.
                // Fence any unrelated loader first: otherwise it could open a
                // new proxy connection and repopulate the restarted backend.
                self.cancel_active("cancelled", Some("agent_unavailable"), false)?;
            } else {
                self.reset_agent()?;
            }
            guard = self.guard.lock().unwrap();
        }
        self.expiry.remove(&key.id);
        guard.blocked = was;
        Ok(())
    }
    fn cancel(&mut self, state: &str, code: Option<&str>) -> Result<()> {
        self.cancel_active(state, code, false)
    }
    fn cancel_active(
        &mut self,
        state: &str,
        code: Option<&str>,
        preserve_loaded: bool,
    ) -> Result<()> {
        if let Some(mut active) = self.active.take() {
            let (uncertain, added) = {
                // Serialize with any ADD already in progress and fence both
                // old connections and unaccepted sockets from this worker.
                let mut guard = self.guard.lock().unwrap();
                guard.blocked = true;
                guard.generation = guard.generation.wrapping_add(1);
                guard.retired_worker_groups.retain(|group| {
                    (unsafe { libc::kill(-*group, 0) == 0 })
                        || std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
                });
                guard.retired_worker_groups.insert(active.child.id() as i32);
                (
                    guard.managed_add_uncertain,
                    guard.managed_added_at.is_some(),
                )
            };
            unsafe {
                libc::kill(-(active.child.id() as i32), libc::SIGKILL);
            }
            let _ = active.child.wait();
            self.guard.lock().unwrap().worker_group = None;
            let key = active.job.key.as_ref();
            let key_id = Self::operation_key(&active.job);
            if active.job.operation == "unlock" {
                if !preserve_loaded || uncertain {
                    // A failed/unknown ADD may commit after its connection
                    // failed. The failure path remains fail-closed.
                    self.reset_agent()?;
                } else if added && let Some(k) = key {
                    // Session cancellation removes only this unfinished load.
                    self.revoke(k)?;
                }
            }
            let mut actual_state = state;
            let mut actual_code = code;
            if active.job.operation == "encrypt" {
                if let Some(k) = key {
                    self.revoke(k)?;
                }
                // Cancellation may race the atomic rename. Do not run a file
                // helper synchronously inside the session event loop.
                self.settings.scanned = false;
                self.save()?;
                actual_state = "partial";
                actual_code = Some("commit_state_unknown");
            }
            self.gate.finish(
                key_id,
                active.job.operation == "unlock",
                self.gate_clock.elapsed().as_secs(),
            );
            let mut value = protocol::response(
                actual_state,
                key.map(|k| k.id.as_str()),
                Some(&active.job.request_id),
                None,
                actual_code,
            );
            value["operation"] = json!(active.job.operation);
            self.remember(active.job.request_id.clone(), value);
        }
        self.refresh_guard();
        Ok(())
    }
    fn tick(&mut self) -> Result<()> {
        let Some(active) = self.active.as_mut() else {
            return Ok(());
        };
        if Instant::now() >= active.deadline {
            return self.cancel("expired", Some("request_expired"));
        }
        let Some(status) = active.child.try_wait()? else {
            return Ok(());
        };
        if !status.success() {
            return self.cancel("cancelled", Some("cancelled"));
        }
        let mut active = self.active.take().unwrap();
        active.output.seek(SeekFrom::Start(0))?;
        let mut out = Vec::new();
        active.output.take(4 * 1024 * 1024).read_to_end(&mut out)?;
        let result: Value =
            serde_json::from_slice(&out).unwrap_or(json!({"error_code":"worker_failed"}));
        let (epoch, added_at) = {
            let mut g = self.guard.lock().unwrap();
            g.worker_group = None;
            (g.external_epoch, g.managed_added_at)
        };
        let key = active.job.key.as_ref();
        let id = key.map(|k| k.id.as_str());
        let mut code = result
            .get("error_code")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut state = if code.as_deref() == Some("cancelled") {
            "cancelled"
        } else if code.as_deref() == Some("biometric_denied") {
            "denied"
        } else if code.is_some() {
            "error"
        } else {
            "completed"
        };
        if code.is_none() {
            match active.job.operation.as_str() {
                "scan" => {
                    self.inventory = serde_json::from_value(result["keys"].clone())?;
                    self.settings.scanned = true;
                    platform::save_json(
                        &self.state_directory.join("inventory.json"),
                        &self.inventory,
                    )?;
                    self.save()?;
                    state = "scanned";
                }
                "unlock" => {
                    if !self.available() {
                        if let Some(k) = key {
                            self.revoke(k)?;
                        }
                        state = "cancelled";
                        code = Some(
                            if self.sleep_preparing() {
                                "sleep_in_progress"
                            } else {
                                "session_locked"
                            }
                            .into(),
                        );
                    } else if let Some(k) = key {
                        if !agent::list(&self.backend())?.contains_key(&k.id) {
                            state = "error";
                            code = Some("agent_unavailable".into());
                        } else {
                            if epoch == active.epoch {
                                self.expiry.insert(
                                    k.id.clone(),
                                    if active.job.rules.lifetime_seconds == 0 {
                                        None
                                    } else {
                                        Some(
                                            added_at.unwrap_or(platform::now())
                                                + active.job.rules.lifetime_seconds as u64,
                                        )
                                    },
                                );
                            }
                            state = "unlocked";
                            self.settings
                                .keys
                                .entry(k.id.clone())
                                .or_default()
                                .fingerprint_mode = result["auth_method"] == "fingerprint";
                            self.save()?;
                        }
                    }
                }
                "sync" => {
                    if let Some(k) = key {
                        self.revoke(k)?;
                        let ciphertext = STANDARD
                            .decode(
                                result["sealed_credential"]
                                    .as_str()
                                    .ok_or(Error("worker_failed"))?,
                            )
                            .map_err(|_| Error("worker_failed"))?;
                        platform::save_bytes(&self.credential_path(&k.id), &ciphertext)?;
                        self.settings
                            .keys
                            .entry(k.id.clone())
                            .or_default()
                            .fingerprint_mode = true;
                        self.save()?;
                    }
                    state = "synced";
                }
                "encrypt" => {
                    if let Some(k) = key {
                        self.revoke(k)?;
                    }
                    state = "encrypted";
                }
                operation if Self::confirmation_operation(operation) => {
                    if let Err(error) = self.commit_confirmation(&active.job, &result) {
                        state = "error";
                        code = Some(error.0.into());
                    }
                }
                _ => {}
            }
        }
        if active.job.operation == "unlock" && (code.is_some() || state != "unlocked") {
            // A failed ssh-add can already have sent ADD before losing its
            // reply. Invalidate queued connections and destroy that backend
            // before exposing an error/cancelled result to the caller.
            unsafe {
                libc::kill(-(active.child.id() as i32), libc::SIGKILL);
            }
            self.reset_agent()?;
        }
        if active.job.operation == "encrypt" {
            if let Some(keys) = result.get("keys") {
                self.inventory = serde_json::from_value(keys.clone())?;
                self.settings.scanned = true;
                platform::save_json(
                    &self.state_directory.join("inventory.json"),
                    &self.inventory,
                )?;
                self.save()?;
            } else if code.is_none() || code.as_deref() == Some("partial_commit") {
                self.settings.scanned = false;
                self.save()?;
                state = "partial";
                code = Some("partial_commit".into());
            }
            if code.as_deref() == Some("partial_commit") {
                state = "partial";
                if let Some(k) = key {
                    self.revoke(k)?;
                }
            }
        }
        self.gate.finish(
            Self::operation_key(&active.job),
            active.job.operation == "unlock" && matches!(state, "cancelled" | "denied"),
            self.gate_clock.elapsed().as_secs(),
        );
        let expiry = id.and_then(|k| self.expiry.get(k).copied().flatten());
        let mut value = protocol::response(
            state,
            id,
            Some(&active.job.request_id),
            expiry,
            code.as_deref(),
        );
        value["operation"] = json!(active.job.operation);
        self.remember(active.job.request_id.clone(), value);
        Ok(())
    }
    fn validate_client(&self, cmd: &Command, peer: libc::ucred) -> Result<()> {
        cmd.validate()?;
        if peer.uid != self.user.uid {
            return Err(Error("wrong_user"));
        }
        Ok(())
    }
    fn caller(peer: libc::ucred) -> String {
        let exe = fs::read_link(format!("/proc/{}/exe", peer.pid)).unwrap_or_default();
        // Display only. Any process of this user can launch desktop dialogs;
        // the native window mediates authentication and management confirmation.
        format!("{} (PID {})", exe.display(), peer.pid)
    }
    fn request_result(&mut self, cmd: &Command, desktop: bool) -> Result<Value> {
        let id = cmd
            .request_id
            .as_deref()
            .ok_or(Error("request_not_found"))?;
        let known = self.history.get(id).ok_or(Error("request_not_found"))?;
        if !desktop && known["operation"] != "unlock" {
            return Err(Error("request_not_found"));
        }
        if cmd.action == "requests.cancel"
            && self.active.as_ref().is_some_and(|a| a.job.request_id == id)
        {
            self.cancel("cancelled", Some("cancelled"))?;
        }
        self.history
            .get(id)
            .cloned()
            .ok_or(Error("request_not_found"))
    }
    fn command(&mut self, cmd: Command, peer: libc::ucred) -> Result<Value> {
        self.validate_client(&cmd, peer)?;
        if matches!(
            cmd.action.as_str(),
            "capabilities"
                | "keys.list"
                | "keys.status"
                | "keys.unlock"
                | "requests.status"
                | "requests.cancel"
        ) && !cmd.value.is_null()
        {
            return Err(Error("invalid_json"));
        }
        match cmd.action.as_str() {
            "capabilities" => {
                let mut v = protocol::response("ready", None, None, None, None);
                v["capabilities"] = json!([
                    "keys.list",
                    "keys.status",
                    "keys.unlock",
                    "requests.status",
                    "requests.cancel"
                ]);
                v["interactive_required"] = json!(true);
                v["fingerprint_autostart"] = json!(true);
                v["request_limits"] = json!({
                    "windows_per_minute":3, "cancel_cooldown_seconds":30, "scope":"unlock_requests"
                });
                v["request_timeout_seconds"] = json!(120);
                v["managed_socket"] = json!(self.user.runtime().join("agent.sock"));
                v["revocation"] = json!({
                    "automatic": "openssh_lifetime", "manual": true,
                    "on_lock": false, "on_sleep": self.settings.revoke_on_sleep,
                    "sleep_supported": true
                });
                Ok(v)
            }
            "requests.status" | "requests.cancel" => self.request_result(&cmd, false),
            "keys.list" => self.query(false),
            "keys.status" | "keys.unlock" => {
                let name = cmd.key.as_deref().ok_or(Error("key_not_found"))?;
                let key = keys::resolve(&self.inventory, name)?.clone();
                if cmd.action == "keys.status" {
                    let loaded = self.reconcile()?;
                    Ok(self.status(&key, &loaded, false))
                } else {
                    self.request(Some(key), "unlock", &cmd, &Self::caller(peer))
                }
            }
            _ => Err(Error("forbidden")),
        }
    }
    fn desktop_command(&mut self, mut cmd: Command, peer: libc::ucred) -> Result<Value> {
        self.validate_client(&cmd, peer)?;
        match cmd.action.as_str() {
            "capabilities" => {
                let mut v = protocol::response("ready", None, None, None, None);
                v["capabilities"] = json!([
                    "panel.list",
                    "scan",
                    "dialog.open",
                    "mode",
                    "revoke",
                    "rules.global",
                    "requests.status",
                    "requests.cancel"
                ]);
                v["dialog_actions"] = json!(["sync", "encrypt", "rules.key", "unbind"]);
                v["interactive_required"] = json!(true);
                v["native_confirmation_required"] = json!(true);
                v["native_confirmation_scope"] = json!("dialog.open");
                v["direct_actions"] = json!(["mode", "revoke", "rules.global"]);
                v["request_limits"] = json!({
                    "windows_per_minute":3, "cancel_cooldown_seconds":0, "scope":"desktop_dialogs"
                });
                v["request_timeout_seconds"] = json!(120);
                Ok(v)
            }
            "requests.status" | "requests.cancel" => self.request_result(&cmd, true),
            "panel.list" => self.query(true),
            "mode" | "revoke" | "rules.global" => self.direct_action(cmd),
            "scan" => self.request(None, "scan", &cmd, &Self::caller(peer)),
            "dialog.open" => {
                if !cmd.interactive {
                    return Err(Error("interaction_required"));
                }
                let dialog: DialogRequest = serde_json::from_value(cmd.value.clone())?;
                if !matches!(
                    dialog.action.as_str(),
                    "sync" | "encrypt" | "rules.key" | "unbind"
                ) {
                    return Err(Error("invalid_action"));
                }
                cmd.action = dialog.action;
                cmd.value = dialog.value;
                self.management_dialog(cmd, &Self::caller(peer))
            }
            _ => Err(Error("forbidden")),
        }
    }
    // These desktop operations intentionally require no second prompt.
    // The socket identifies the owner, not a privileged or human-operated
    // client; same-UID programs can perform these limited actions as well.
    fn direct_action(&mut self, cmd: Command) -> Result<Value> {
        self.require_available()?;
        if cmd.action == "rules.global" {
            if cmd.key.is_some() || cmd.request_id.is_some() || !cmd.value.is_object() {
                return Err(Error("invalid_json"));
            }
            let mut proposed = cmd.value;
            let revoke_on_sleep = match proposed.as_object_mut().unwrap().remove("revoke_on_sleep")
            {
                None => self.settings.revoke_on_sleep,
                Some(Value::Bool(enabled)) => enabled,
                Some(_) => return Err(Error("invalid_json")),
            };
            let rules: Rules = serde_json::from_value(proposed)?;
            rules.validate()?;
            if self.active.is_some() {
                return Err(Error("busy"));
            }
            // This changes inherited policy for subsequent loads only. Do not
            // reconcile or mutate the agent, recorded expiries or key overrides.
            let mut settings = self.settings.clone();
            settings.global = rules;
            settings.revoke_on_sleep = revoke_on_sleep;
            let path = self.state_directory.join("settings.json");
            #[cfg(not(test))]
            let outcome = platform::save_json_outcome(&path, &settings)?;
            #[cfg(test)]
            let outcome = (self.save_global_settings)(&path, &settings)?;
            // Both successful outcomes have replaced the on-disk policy. A
            // failed directory fsync cannot roll the rename back, so publish
            // the new policy and report its uncertain durability explicitly.
            self.settings = settings;
            let (state, error) = match outcome {
                platform::SaveOutcome::Durable => ("ready", None),
                platform::SaveOutcome::ReplacedButUnsynced(_) => {
                    ("partial", Some("settings_durability_unknown"))
                }
            };
            let mut result = protocol::response(state, None, None, None, error);
            result["operation"] = json!("rules.global");
            result["global_rules"] = json!(self.settings.global_rules());
            return Ok(result);
        }
        let name = cmd.key.as_deref().ok_or(Error("key_not_found"))?;
        let key = keys::resolve(&self.inventory, name)?.clone();
        let loaded = match cmd.action.as_str() {
            "mode" => {
                let mode: ModeRequest = serde_json::from_value(cmd.value)?;
                if self.active.is_some() {
                    return Err(Error("busy"));
                }
                if !self.credential_path(&key.id).is_file() {
                    return Err(Error("not_bound"));
                }
                let loaded = self.reconcile()?;
                // Save before publishing the new in-memory choice. A failed
                // write must not apply an unsaved mode or mutate agent access.
                let mut settings = self.settings.clone();
                settings
                    .keys
                    .entry(key.id.clone())
                    .or_default()
                    .fingerprint_mode = mode.fingerprint_mode;
                platform::save_json(&self.state_directory.join("settings.json"), &settings)?;
                self.settings = settings;
                loaded
            }
            "revoke" => {
                if !cmd.value.is_null() {
                    return Err(Error("invalid_json"));
                }
                if self.active.as_ref().is_some_and(|active| {
                    active.job.operation == "unlock"
                        && active
                            .job
                            .key
                            .as_ref()
                            .is_some_and(|pending| pending.id == key.id)
                }) {
                    // Fence queued ADDs and kill/reap the matching loader
                    // before removal. Unrelated requests keep their deadline.
                    self.cancel_active("cancelled", Some("cancelled"), true)?;
                }
                // Binding/encryption never ADD an identity; their later commit
                // only revokes access again. Leave those operations running.
                self.revoke(&key)?;
                self.reconcile()?
            }
            _ => return Err(Error("invalid_action")),
        };
        let mut result = self.status(&key, &loaded, true);
        result["operation"] = json!(cmd.action);
        result["request_id"] = Value::Null;
        result["busy"] = json!(self.active.as_ref().is_some_and(|active| {
            active
                .job
                .key
                .as_ref()
                .is_some_and(|pending| pending.id == key.id)
        }));
        Ok(result)
    }
    // This dispatcher is reachable only via the desktop dialog launcher. It
    // captures proposed values; no operation commits until its native worker
    // has received consent through the inherited private channel.
    fn management_dialog(&mut self, cmd: Command, caller: &str) -> Result<Value> {
        self.require_available()?;
        let name = cmd.key.as_deref().ok_or(Error("key_not_found"))?;
        let key = if cmd.action == "encrypt" {
            self.inventory
                .iter()
                .find(|k| k.path.to_string_lossy() == name)
                .ok_or(Error("key_not_found"))?
        } else {
            keys::resolve(&self.inventory, name)?
        }
        .clone();
        match cmd.action.as_str() {
            "sync" => {
                if !key.encrypted {
                    return Err(Error("key_not_encrypted"));
                }
                self.request(Some(key), "sync", &cmd, caller)
            }
            "encrypt" => {
                if key.encrypted {
                    return self.query(true);
                }
                self.request(Some(key), "encrypt", &cmd, caller)
            }
            "unbind" => {
                if self.active.is_some() {
                    return Err(Error("busy"));
                }
                let operation = cmd.action.clone();
                let mut approved = cmd;
                approved.value = Value::Null;
                self.request(Some(key), &operation, &approved, caller)
            }
            "rules.key" => {
                if self.active.is_some() {
                    return Err(Error("busy"));
                }
                let rules: Option<Rules> = serde_json::from_value(cmd.value.clone())?;
                if let Some(r) = &rules {
                    r.validate()?;
                }
                let mut approved = cmd;
                approved.value = json!(rules);
                self.request(Some(key), "rules.key", &approved, caller)
            }
            _ => Err(Error("invalid_action")),
        }
    }
}
fn listen_sleep_commands(
    listener: UnixListener,
    commands: mpsc::SyncSender<(SleepCommand, libc::ucred, mpsc::Sender<Value>)>,
) {
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let Ok(peer) = agent::peer(&stream) else {
                continue;
            };
            if peer.uid != 0 {
                continue;
            }
            let mut stream = stream;
            let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
            let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
            let mut bytes = Vec::new();
            let mut one = [0; 1];
            let mut framed = false;
            let deadline = Instant::now() + Duration::from_secs(1);
            while bytes.len() < 256 && Instant::now() < deadline {
                match stream.read(&mut one) {
                    Ok(1) if one[0] == b'\n' => {
                        framed = true;
                        break;
                    }
                    Ok(1) => bytes.push(one[0]),
                    _ => break,
                }
            }
            let parsed = if framed {
                SleepCommand::parse(&bytes)
            } else {
                Err(Error("invalid_json"))
            };
            let result = match parsed {
                Ok(cmd) => {
                    let (reply, answer) = mpsc::channel();
                    if commands.try_send((cmd, peer, reply)).is_err() {
                        protocol::error("busy")
                    } else {
                        answer
                            .recv_timeout(Duration::from_secs(8))
                            .unwrap_or_else(|_| protocol::error("service_timeout"))
                    }
                }
                Err(error) => protocol::error(error.0),
            };
            let _ = serde_json::to_writer(&mut stream, &result);
            let _ = stream.write_all(b"\n");
        }
    });
}

pub fn serve(uid: u32) -> Result<()> {
    if unsafe { libc::geteuid() } != 0 || uid == 0 {
        return Err(Error("wrong_user"));
    }
    process::harden()?;
    let user = User::get(uid)?;
    fs::create_dir_all(user.state_dir())?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(user.state_dir(), fs::Permissions::from_mode(0o700))?;
    let settings_path = user.state_dir().join("settings.json");
    let inventory_path = user.state_dir().join("inventory.json");
    let settings = if settings_path.exists() {
        let (settings, migrated) =
            Settings::from_persisted(serde_json::from_reader(File::open(&settings_path)?)?)?;
        if migrated {
            platform::save_json(&settings_path, &settings)?;
        }
        settings
    } else {
        Settings::default()
    };
    let inventory = if inventory_path.exists() {
        serde_json::from_reader(File::open(inventory_path)?)?
    } else {
        Vec::new()
    };
    let control_path = user.runtime().join("control.sock");
    let desktop_path = user.runtime().join("desktop.sock");
    let agent_path = user.runtime().join("agent.sock");
    let sleep_path = user.runtime().join("sleep.sock");
    for p in [&control_path, &desktop_path, &agent_path, &sleep_path] {
        if p.exists() {
            fs::remove_file(p)?;
        }
    }
    let listener = UnixListener::bind(&control_path)?;
    platform::own_socket(&control_path, uid)?;
    let desktop = UnixListener::bind(&desktop_path)?;
    platform::own_socket(&desktop_path, uid)?;
    let public = UnixListener::bind(&agent_path)?;
    platform::own_socket(&agent_path, uid)?;
    let sleep = UnixListener::bind(&sleep_path)?;
    platform::own_socket(&sleep_path, 0)?;
    let sleep_marker = std::path::PathBuf::from(platform::SLEEP_MARKER);
    let sleeping = platform::sleep_marker_active(&sleep_marker);
    let guard = Arc::new(Mutex::new(Guard {
        blocked: true,
        sleep_marker: Some(sleep_marker.clone()),
        ..Default::default()
    }));
    agent::proxy(public, user.clone(), guard.clone());
    let mut server = Server {
        backend_path: user.runtime().join("backend.sock"),
        state_directory: user.state_dir(),
        sleep_marker,
        sleeping,
        user,
        settings,
        inventory,
        guard,
        session: Session::default(),
        gate: RequestGate::default(),
        active: None,
        history: BTreeMap::new(),
        history_order: VecDeque::new(),
        agent_reset_failed: false,
        expiry: BTreeMap::new(),
        external_epoch: 0,
        gate_clock: Instant::now(),
        #[cfg(test)]
        reset_backend: |_| Err(Error("test_backend_not_configured")),
        #[cfg(test)]
        save_global_settings: platform::save_json_outcome,
    };
    // The root-only preparation channel has its own reader and bounded queue.
    // User API traffic cannot queue ahead of the mandatory sleep barrier.
    let (sleep_tx, sleep_commands) = mpsc::sync_channel(4);
    listen_sleep_commands(sleep, sleep_tx);
    let (events, rx) = mpsc::channel();
    platform::watch(uid, events);
    let (tx, commands) =
        mpsc::sync_channel::<(Command, libc::ucred, bool, mpsc::Sender<Value>)>(32);
    for (listener, is_desktop) in [(listener, false), (desktop, true)] {
        let tx = tx.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let tx = tx.clone();
                // Read bounded frames before enqueueing. Idle/malicious API clients
                // cannot hold the session event loop or allocate unbounded memory.
                let Ok(peer) = agent::peer(&stream) else {
                    continue;
                };
                if peer.uid != uid {
                    continue;
                }
                let mut stream = stream;
                let _ = stream.set_read_timeout(Some(Duration::from_millis(200)));
                let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
                let mut bytes = Vec::new();
                let mut one = [0; 1];
                let deadline = Instant::now() + Duration::from_secs(1);
                while bytes.len() < protocol::MAX_MESSAGE && Instant::now() < deadline {
                    match stream.read(&mut one) {
                        Ok(1) if one[0] != b'\n' => bytes.push(one[0]),
                        _ => break,
                    }
                }
                let Ok(cmd) = serde_json::from_slice(&bytes) else {
                    let _ = serde_json::to_writer(&mut stream, &protocol::error("invalid_json"));
                    let _ = stream.write_all(b"\n");
                    continue;
                };
                let (reply, answer) = mpsc::channel();
                if tx.try_send((cmd, peer, is_desktop, reply)).is_err() {
                    continue;
                }
                // One reader per socket; bounded service handling. The event
                // loop continues to service session updates independently.
                let result = answer
                    .recv_timeout(Duration::from_secs(8))
                    .unwrap_or(protocol::error("service_timeout"));
                let _ = serde_json::to_writer(&mut stream, &result);
                let _ = stream.write_all(b"\n");
            }
        });
    }
    loop {
        server.observe_sleep_marker()?;
        for (cmd, peer, reply) in sleep_commands.try_iter() {
            let result = server
                .sleep_command(cmd, peer)
                .unwrap_or_else(|error| protocol::error(error.0));
            let _ = reply.send(result);
        }
        for event in rx.try_iter() {
            match event {
                Event::Session(session) => server.update_session(session)?,
            }
        }
        if let Ok((cmd, peer, desktop, reply)) = commands.try_recv() {
            let result = if desktop {
                server.desktop_command(cmd, peer)
            } else {
                server.command(cmd, peer)
            }
            .unwrap_or_else(|e| protocol::error(e.0));
            let _ = reply.send(result);
        }
        if server.agent_reset_failed {
            return Err(Error("agent_reset_failed"));
        }
        server.tick()?;
        platform::notify_watchdog();
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::CommandExt;

    struct TestAgent(Child);
    impl Drop for TestAgent {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    fn fixture() -> (tempfile::TempDir, TestAgent, Server, Key, Key) {
        let directory = tempfile::tempdir().unwrap();
        let backend = directory.path().join("backend");
        let agent = TestAgent(
            std::process::Command::new("/usr/bin/ssh-agent")
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
        let make_key = |name: &str| {
            let path = directory.path().join(name);
            assert!(
                std::process::Command::new("/usr/bin/ssh-keygen")
                    .args(["-q", "-t", "ed25519", "-N", "", "-f"])
                    .arg(&path)
                    .status()
                    .unwrap()
                    .success()
            );
            let header = keys::parse(&fs::read(&path).unwrap()).unwrap();
            Key {
                id: header.fingerprint.clone(),
                path,
                name: name.into(),
                fingerprint: header.fingerprint,
                algorithm: header.algorithm,
                encrypted: false,
                public_blob: header.public_blob,
                unavailable: None,
                unencrypted_copies: Vec::new(),
            }
        };
        let prior = make_key("prior");
        let pending = make_key("pending");
        let mut server = Server {
            user: User::get(unsafe { libc::getuid() }).unwrap(),
            backend_path: backend,
            state_directory: directory.path().to_path_buf(),
            sleep_marker: directory.path().join("sleep-marker"),
            sleeping: false,
            settings: Settings::default(),
            inventory: vec![prior.clone(), pending.clone()],
            guard: Arc::new(Mutex::new(Guard {
                sleep_marker: Some(directory.path().join("sleep-marker")),
                ..Default::default()
            })),
            session: Session {
                available: true,
                ..Default::default()
            },
            gate: RequestGate::default(),
            active: None,
            history: BTreeMap::new(),
            history_order: VecDeque::new(),
            agent_reset_failed: false,
            expiry: BTreeMap::new(),
            external_epoch: 0,
            gate_clock: Instant::now(),
            save_global_settings: platform::save_json_outcome,
            reset_backend: |server| {
                assert!(server.guard.lock().unwrap().blocked);
                assert!(
                    server
                        .active
                        .as_ref()
                        .is_none_or(|active| active.job.operation != "unlock")
                );
                if agent::exchange(&server.backend(), &[19])?.as_slice() == [6] {
                    Ok(())
                } else {
                    Err(Error("test_backend_reset_failed"))
                }
            },
        };
        add(&server, &prior);
        server
            .expiry
            .insert(prior.id.clone(), Some(platform::now() + 60));
        (directory, agent, server, prior, pending)
    }

    fn add(server: &Server, key: &Key) {
        assert!(
            std::process::Command::new("/usr/bin/ssh-add")
                .args(["-t", "60"])
                .arg(&key.path)
                .env("SSH_AUTH_SOCK", server.backend())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .unwrap()
                .success()
        );
    }

    fn pending_request(server: &mut Server, key: Key, already_added: bool) -> u32 {
        let child = std::process::Command::new("/usr/bin/sleep")
            .arg("30")
            .process_group(0)
            .spawn()
            .unwrap();
        let pid = child.id();
        let job = Job {
            user: server.user.clone(),
            operation: "unlock".into(),
            key: Some(key.clone()),
            request_id: "pending-request".into(),
            reason: String::new(),
            caller: "test fixture".into(),
            rules: Rules {
                lifetime_seconds: 60,
            },
            value: Value::Null,
            fingerprint_mode: false,
            bound: false,
            wayland: String::new(),
            display: None,
        };
        server.gate.active = Some((key.id, job.request_id.clone()));
        {
            let mut guard = server.guard.lock().unwrap();
            guard.worker_group = Some(pid as i32);
            guard.managed_added_at = already_added.then(platform::now);
        }
        server.active = Some(Active {
            job,
            child,
            output: process::memfile(b"{}", false).unwrap(),
            deadline: Instant::now() + Duration::from_secs(30),
            epoch: 0,
        });
        let mut value = protocol::response(
            "pending",
            Some(&key.fingerprint),
            Some("pending-request"),
            None,
            None,
        );
        value["operation"] = json!("unlock");
        server.remember("pending-request".into(), value);
        pid
    }

    fn pending_confirmation(server: &mut Server, key: &Key, operation: &str, value: Value) {
        pending_request(server, key.clone(), false);
        let active = server.active.as_mut().unwrap();
        active.job.operation = operation.into();
        active.job.value = value;
        server.gate.active = Some((
            Server::operation_key(&active.job).into(),
            active.job.request_id.clone(),
        ));
        server.history.get_mut("pending-request").unwrap()["operation"] = json!(operation);
    }

    fn finish_confirmation(server: &mut Server, result: Value) {
        let active = server.active.as_mut().unwrap();
        let _ = active.child.kill();
        let _ = active.child.wait();
        active.child = std::process::Command::new("/usr/bin/true").spawn().unwrap();
        active.child.wait().unwrap();
        active.output = process::memfile(&serde_json::to_vec(&result).unwrap(), false).unwrap();
        server.tick().unwrap();
    }

    fn peer(server: &Server) -> libc::ucred {
        libc::ucred {
            pid: unsafe { libc::getpid() },
            uid: server.user.uid,
            gid: server.user.gid,
        }
    }
    fn dialog(action: &str, key: &Key, value: Value) -> Command {
        let mut cmd = Command::new("dialog.open");
        cmd.interactive = true;
        cmd.key = Some(key.id.clone());
        cmd.value = json!({"action":action,"value":value});
        cmd
    }

    #[test]
    fn public_protocol_rejects_management_and_desktop_limits_direct_actions() {
        let (_directory, _agent, mut server, key, _) = fixture();
        let peer = peer(&server);
        let before = serde_json::to_value(&server.settings).unwrap();
        for action in [
            "sync",
            "encrypt",
            "rules.global",
            "rules.key",
            "mode",
            "unbind",
            "revoke",
            "panel.list",
            "scan",
            "dialog.open",
        ] {
            let mut cmd = Command::new(action);
            cmd.interactive = true;
            cmd.key = Some(key.id.clone());
            cmd.value = json!({"action":"rules.global","value":{"lifetime_seconds":900}});
            assert_eq!(
                server.command(cmd, peer).unwrap_err().0,
                "forbidden",
                "{action}"
            );
        }
        for action in ["sync", "encrypt", "rules.key", "unbind", "keys.unlock"] {
            let mut cmd = Command::new(action);
            cmd.interactive = true;
            cmd.key = Some(key.id.clone());
            cmd.value = json!({"confirmed":true,"ok":true});
            assert_eq!(
                server.desktop_command(cmd, peer).unwrap_err().0,
                "forbidden",
                "{action}"
            );
        }
        assert!(server.active.is_none());
        assert_eq!(serde_json::to_value(&server.settings).unwrap(), before);
        assert_eq!(agent::list(&server.backend()).unwrap().len(), 1);
        let mut invalid = Command::new("keys.unlock");
        invalid.interactive = true;
        invalid.key = Some(key.id.clone());
        invalid.value = json!({"action":"sync","confirmed":true});
        assert_eq!(server.command(invalid, peer).unwrap_err().0, "invalid_json");
        let public = server.command(Command::new("capabilities"), peer).unwrap();
        assert_eq!(
            public["capabilities"],
            json!([
                "keys.list",
                "keys.status",
                "keys.unlock",
                "requests.status",
                "requests.cancel"
            ])
        );
        assert_eq!(public["request_limits"]["scope"], "unlock_requests");
        assert_eq!(public["fingerprint_autostart"], true);
        assert_eq!(public["interactive_required"], true);
        let desktop = server
            .desktop_command(Command::new("capabilities"), peer)
            .unwrap();
        assert_eq!(desktop["request_limits"]["cancel_cooldown_seconds"], 0);
        assert_eq!(desktop["request_limits"]["scope"], "desktop_dialogs");
        assert_eq!(
            desktop["direct_actions"],
            json!(["mode", "revoke", "rules.global"])
        );
        assert_eq!(desktop["native_confirmation_scope"], "dialog.open");
        assert_eq!(
            desktop["dialog_actions"],
            json!(["sync", "encrypt", "rules.key", "unbind"])
        );
        assert_eq!(
            desktop["capabilities"],
            json!([
                "panel.list",
                "scan",
                "dialog.open",
                "mode",
                "revoke",
                "rules.global",
                "requests.status",
                "requests.cancel"
            ])
        );
        assert_eq!(
            server
                .desktop_command(Command::new("panel.list"), peer)
                .unwrap()["state"],
            "ready"
        );
        let wrong_peer = libc::ucred {
            uid: peer.uid.wrapping_add(1),
            ..peer
        };
        assert_eq!(
            server
                .command(Command::new("capabilities"), wrong_peer)
                .unwrap_err()
                .0,
            "wrong_user"
        );
        assert_eq!(
            server
                .desktop_command(Command::new("capabilities"), wrong_peer)
                .unwrap_err()
                .0,
            "wrong_user"
        );
    }

    #[test]
    fn desktop_dialog_requires_interaction_and_json_cannot_grant_consent() {
        let (_directory, _agent, mut server, key, _) = fixture();
        let peer = peer(&server);
        let before = serde_json::to_value(&server.settings).unwrap();
        for action in ["sync", "encrypt", "rules.key", "unbind"] {
            let mut cmd = dialog(action, &key, json!({"lifetime_seconds":900}));
            cmd.interactive = false;
            assert_eq!(
                server.desktop_command(cmd, peer).unwrap_err().0,
                "interaction_required"
            );
        }
        for extra in ["confirmed", "ok", "consent", "operation"] {
            let mut cmd = dialog("rules.key", &key, json!({"lifetime_seconds":900}));
            cmd.value[extra] = json!(true);
            assert_eq!(
                server.desktop_command(cmd, peer).unwrap_err().0,
                "invalid_json"
            );
        }
        let invalid = dialog(
            "rules.key",
            &key,
            json!({"lifetime_seconds":900,"confirmed":true}),
        );
        assert_eq!(
            server.desktop_command(invalid, peer).unwrap_err().0,
            "invalid_json"
        );
        assert_eq!(
            server
                .desktop_command(dialog("keys.unlock", &key, Value::Null), peer)
                .unwrap_err()
                .0,
            "invalid_action"
        );
        for action in ["mode", "revoke", "rules.global"] {
            assert_eq!(
                server
                    .desktop_command(dialog(action, &key, Value::Null), peer)
                    .unwrap_err()
                    .0,
                "invalid_action"
            );
        }
        assert!(server.active.is_none());
        assert_eq!(serde_json::to_value(&server.settings).unwrap(), before);
    }

    #[test]
    fn caller_names_never_bypass_either_window_quota() {
        let (_directory, _agent, mut server, _, mut key) = fixture();
        key.encrypted = true; // Metadata only; quotas prevent spawning workers.
        for time in 0..3 {
            server.gate.check("prior-unlock", time).unwrap();
            server.gate.check_dialog("prior-dialog", time).unwrap();
        }
        let mut cmd = Command::new("unused");
        cmd.interactive = true;
        for caller in ["/usr/lib/ssh-keys/panel-client", "untrusted qs process"] {
            for operation in ["unlock", "sync", "encrypt", "rules.key", "unbind"] {
                let target = Some(key.clone());
                assert_eq!(
                    server
                        .request(target, operation, &cmd, caller)
                        .unwrap_err()
                        .0,
                    "rate_limited"
                );
                assert!(server.active.is_none());
            }
        }
    }

    #[test]
    fn binding_cancellation_does_not_delay_or_spend_unlock_quota() {
        let (_directory, _agent, mut server, key, _) = fixture();
        for worker_closes in [false, true] {
            server.gate.check_dialog(&key.id, 0).unwrap();
            pending_confirmation(&mut server, &key, "sync", Value::Null);
            if worker_closes {
                finish_confirmation(&mut server, json!({"error_code":"cancelled"}));
            } else {
                server.cancel("cancelled", Some("cancelled")).unwrap();
            }
            assert!(server.active.is_none());
            assert!(server.gate.active.is_none());
            assert_eq!(server.history["pending-request"]["state"], "cancelled");
            assert_eq!(server.history["pending-request"]["operation"], "sync");
        }
        for now in 0..3 {
            assert_eq!(server.gate.check(&key.id, now).unwrap(), None);
        }
        assert_eq!(server.gate.check(&key.id, 3).unwrap_err().0, "rate_limited");
    }

    #[test]
    fn public_requests_cannot_discover_or_cancel_management_jobs() {
        let (_directory, _agent, mut server, key, _) = fixture();
        let peer = peer(&server);
        pending_confirmation(
            &mut server,
            &key,
            "rules.key",
            json!({"lifetime_seconds":45}),
        );
        server.inventory[0].encrypted = true;
        let public = server.command(Command::new("keys.list"), peer).unwrap();
        assert!(public["active_request"].is_null());
        assert!(public["active_operation"].is_null());
        assert!(public.get("ui_language").is_none());
        assert_eq!(public["keys"].as_array().unwrap().len(), 1);
        assert!(public["keys"][0]["request_id"].is_null());
        let mut status = Command::new("keys.status");
        status.key = Some(key.id.clone());
        let status = server.command(status, peer).unwrap();
        assert!(status["request_id"].is_null());
        assert_eq!(status["busy"], true);
        for action in ["requests.status", "requests.cancel"] {
            let mut cmd = Command::new(action);
            cmd.request_id = Some("pending-request".into());
            assert_eq!(
                server.command(cmd, peer).unwrap_err().0,
                "request_not_found"
            );
            assert_eq!(server.active.as_ref().unwrap().job.operation, "rules.key");
        }
        let desktop = server
            .desktop_command(Command::new("panel.list"), peer)
            .unwrap();
        assert_eq!(desktop["active_request"], "pending-request");
        assert_eq!(desktop["active_operation"], "rules.key");
        assert!(matches!(desktop["ui_language"].as_str(), Some("ru" | "en")));
        let mut cancel = Command::new("requests.cancel");
        cancel.request_id = Some("pending-request".into());
        assert_eq!(
            server.desktop_command(cancel, peer).unwrap()["state"],
            "cancelled"
        );
        let mut status = Command::new("requests.status");
        status.request_id = Some("pending-request".into());
        assert_eq!(
            server.command(status, peer).unwrap_err().0,
            "request_not_found"
        );
    }

    #[test]
    fn loaded_access_does_not_create_a_window_or_extend_lifetime() {
        let (_directory, _agent, mut server, key, _) = fixture();
        let peer = peer(&server);
        let expiry = server.expiry[&key.id];
        for now in 0..3 {
            server.gate.check("previous", now).unwrap();
        }
        server.gate.finish(&key.id, true, 0);
        let mut cmd = Command::new("keys.unlock");
        cmd.key = Some(key.id.clone());
        cmd.interactive = true;
        let response = server.command(cmd, peer).unwrap();
        assert_eq!(response["state"], "unlocked");
        assert_eq!(response["expires_at"], json!(expiry));
        assert!(response["request_id"].is_null());
        assert_eq!(server.expiry[&key.id], expiry);
        assert!(server.active.is_none());
    }

    #[test]
    fn unlock_coalesces_and_management_cannot_replace_an_active_request() {
        let (_directory, _agent, mut server, _, mut key) = fixture();
        let peer = peer(&server);
        key.encrypted = true;
        server.inventory[1].encrypted = true;
        pending_request(&mut server, key.clone(), false);
        let deadline = server.active.as_ref().unwrap().deadline;
        let mut cmd = Command::new("keys.unlock");
        cmd.key = Some(key.id.clone());
        cmd.interactive = true;
        assert_eq!(
            server.command(cmd, peer).unwrap()["request_id"],
            "pending-request"
        );
        assert_eq!(server.active.as_ref().unwrap().deadline, deadline);
        assert_eq!(
            server
                .desktop_command(dialog("sync", &key, Value::Null), peer)
                .unwrap_err()
                .0,
            "busy"
        );
        assert_eq!(server.active.as_ref().unwrap().job.operation, "unlock");
        let mut status = Command::new("requests.status");
        status.request_id = Some("pending-request".into());
        assert_eq!(server.command(status, peer).unwrap()["operation"], "unlock");
        // Cancel via session loss so the disposable fixture never controls a
        // real system agent unit; this path preserves pre-existing identities.
        server.update_session(Session::default()).unwrap();
        let mut status = Command::new("requests.status");
        status.request_id = Some("pending-request".into());
        assert_eq!(server.command(status, peer).unwrap()["state"], "cancelled");
        assert_eq!(server.gate.check(&key.id, 0).unwrap_err().0, "cooldown");
    }

    #[test]
    fn only_strict_worker_confirmation_commits_captured_policy() {
        let (_directory, _agent, mut server, key, _) = fixture();
        let expiry = server.expiry[&key.id];
        server.settings.global.lifetime_seconds = 900;
        for response in [
            json!({}),
            json!({"ok":true}),
            json!({"confirmed":true}),
            json!({"ok":true,"confirmed":"true"}),
            json!({"ok":true,"confirmed":false}),
        ] {
            pending_confirmation(
                &mut server,
                &key,
                "rules.key",
                json!({"lifetime_seconds":900}),
            );
            finish_confirmation(&mut server, response);
            assert_eq!(server.settings.effective(&key.id).lifetime_seconds, 900);
            assert!(
                server
                    .settings
                    .keys
                    .get(&key.id)
                    .is_none_or(|settings| settings.rules.is_none())
            );
            assert_eq!(
                server.history["pending-request"]["error_code"],
                "confirmation_required"
            );
        }
        pending_confirmation(
            &mut server,
            &key,
            "rules.key",
            json!({"lifetime_seconds":900}),
        );
        finish_confirmation(
            &mut server,
            json!({"ok":true,"confirmed":true,"value":{"lifetime_seconds":0}}),
        );
        assert_eq!(server.settings.effective(&key.id).lifetime_seconds, 900);
        assert!(server.settings.keys[&key.id].rules.is_some());
        assert_eq!(server.expiry[&key.id], expiry);
        assert_eq!(agent::list(&server.backend()).unwrap().len(), 1);
        let persisted: Settings = serde_json::from_slice(
            &fs::read(server.state_directory.join("settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(
            persisted.keys[&key.id]
                .rules
                .as_ref()
                .unwrap()
                .lifetime_seconds,
            900
        );

        pending_confirmation(
            &mut server,
            &key,
            "rules.key",
            json!({"lifetime_seconds":45}),
        );
        finish_confirmation(&mut server, json!({"ok":true,"confirmed":true}));
        assert_eq!(server.settings.effective(&key.id).lifetime_seconds, 45);
        pending_confirmation(&mut server, &key, "rules.key", Value::Null);
        finish_confirmation(&mut server, json!({"ok":true,"confirmed":true}));
        assert!(server.settings.keys[&key.id].rules.is_none());
        assert_eq!(server.settings.effective(&key.id).lifetime_seconds, 900);
        assert_eq!(server.expiry[&key.id], expiry);
    }

    #[test]
    fn cancelled_or_expired_confirmations_leave_settings_binding_and_access_unchanged() {
        let (_directory, _agent, mut server, key, _) = fixture();
        let credential = server.credential_path(&key.id);
        fs::write(&credential, b"disposable ciphertext fixture").unwrap();
        server
            .settings
            .keys
            .entry(key.id.clone())
            .or_default()
            .fingerprint_mode = true;
        server.save().unwrap();
        let settings_file = server.state_directory.join("settings.json");
        let before = fs::read(&settings_file).unwrap();
        let expiry = server.expiry[&key.id];
        for expire in [false, true] {
            for (operation, value) in [
                ("rules.key", json!({"lifetime_seconds":45})),
                ("unbind", Value::Null),
            ] {
                pending_confirmation(&mut server, &key, operation, value);
                server.active.as_mut().unwrap().output =
                    process::memfile(b"{\"ok\":true,\"confirmed\":true}", false).unwrap();
                if expire {
                    server.active.as_mut().unwrap().deadline = Instant::now();
                    server.tick().unwrap();
                } else {
                    server.cancel("cancelled", Some("cancelled")).unwrap();
                }
                assert!(server.active.is_none());
                assert_eq!(fs::read(&settings_file).unwrap(), before);
                assert_eq!(serde_json::to_vec(&server.settings).unwrap(), before);
                assert!(credential.is_file());
                assert_eq!(server.expiry[&key.id], expiry);
                assert_eq!(agent::list(&server.backend()).unwrap().len(), 1);
            }
        }
        assert_eq!(server.gate.check(&key.id, 0).unwrap(), None);
    }

    #[test]
    fn confirmed_unbind_revokes_only_after_approval_and_mutations_cannot_replace_pending_job() {
        let (_directory, _agent, mut server, key, _) = fixture();
        let credential = server.credential_path(&key.id);
        fs::write(&credential, b"disposable ciphertext fixture").unwrap();
        pending_confirmation(&mut server, &key, "unbind", Value::Null);
        let peer = libc::ucred {
            pid: unsafe { libc::getpid() },
            uid: server.user.uid,
            gid: server.user.gid,
        };
        for action in ["rules.key", "unbind"] {
            let mut cmd = Command::new(action);
            cmd.interactive = true;
            cmd.key = Some(key.id.clone());
            cmd.value = json!({"lifetime_seconds":0});
            assert_eq!(
                server
                    .management_dialog(cmd, &Server::caller(peer))
                    .unwrap_err()
                    .0,
                "busy"
            );
            assert_eq!(server.active.as_ref().unwrap().job.operation, "unbind");
        }
        assert!(credential.is_file());
        assert_eq!(agent::list(&server.backend()).unwrap().len(), 1);
        finish_confirmation(&mut server, json!({"ok":true,"confirmed":true}));
        assert!(!credential.exists());
        assert!(agent::list(&server.backend()).unwrap().is_empty());
        assert!(!server.settings.keys[&key.id].fingerprint_mode);
        assert_eq!(server.history["pending-request"]["state"], "completed");
    }

    fn direct(action: &str, key: &Key, value: Value) -> Command {
        let mut cmd = Command::new(action);
        cmd.key = Some(key.id.clone());
        cmd.value = value;
        cmd
    }

    fn global_rules(value: Value) -> Command {
        let mut cmd = Command::new("rules.global");
        cmd.value = value;
        cmd
    }

    #[test]
    fn direct_global_rules_save_inheritance_without_access_binding_or_quota_effects() {
        let (_directory, _agent, mut server, key, custom) = fixture();
        let owner = peer(&server);
        server.settings.scanned = true;
        server.settings.global.lifetime_seconds = 60;
        server
            .settings
            .keys
            .entry(key.id.clone())
            .or_default()
            .fingerprint_mode = true;
        server
            .settings
            .keys
            .entry(custom.id.clone())
            .or_default()
            .rules = Some(Rules {
            lifetime_seconds: 45,
        });
        let credential = server.credential_path(&key.id);
        fs::write(&credential, b"disposable ciphertext fixture").unwrap();
        server.save().unwrap();
        let per_key = serde_json::to_value(&server.settings.keys).unwrap();
        let expiry = server.expiry.clone();
        let generation = server.guard.lock().unwrap().generation;
        let external_epoch = server.external_epoch;
        for now in 0..3 {
            server.gate.check("old-window", now).unwrap();
            server.gate.check_dialog("old-dialog", now).unwrap();
        }
        // Repeating the same setting, unlimited access and both lifetime
        // boundaries affect only the inherited policy for subsequent loads.
        for desired in [900, 900, 0, 31_536_000] {
            let response = server
                .desktop_command(global_rules(json!({"lifetime_seconds":desired})), owner)
                .unwrap();
            assert_eq!(
                response,
                json!({
                    "api_version":protocol::API, "state":"ready", "operation":"rules.global",
                    "key_id":null, "request_id":null, "expires_at":null, "error_code":null,
                    "global_rules":{"lifetime_seconds":desired,"revoke_on_sleep":false}
                })
            );
            let saved: Settings = serde_json::from_slice(
                &fs::read(server.state_directory.join("settings.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(saved.global.lifetime_seconds, desired);
            assert!(saved.scanned && server.settings.scanned);
            assert_eq!(serde_json::to_value(&saved.keys).unwrap(), per_key);
            assert_eq!(
                serde_json::to_value(&server.settings.keys).unwrap(),
                per_key
            );
            assert_eq!(server.settings.effective(&key.id).lifetime_seconds, desired);
            assert_eq!(server.settings.effective(&custom.id).lifetime_seconds, 45);
            assert_eq!(server.expiry, expiry);
            let loaded = agent::list(&server.backend()).unwrap();
            assert_eq!(loaded.len(), 1);
            assert!(loaded.contains_key(&key.id));
            assert_eq!(
                fs::read(&credential).unwrap(),
                b"disposable ciphertext fixture"
            );
            assert_eq!(server.guard.lock().unwrap().generation, generation);
            assert_eq!(server.external_epoch, external_epoch);
            assert!(server.active.is_none() && server.gate.active.is_none());
            assert!(server.history.is_empty());
        }
        assert_eq!(
            server.gate.check("old-window", 3).unwrap_err().0,
            "rate_limited"
        );
        assert_eq!(
            server.gate.check_dialog("old-dialog", 3).unwrap_err().0,
            "rate_limited"
        );
    }

    #[test]
    fn direct_global_rules_validate_owner_session_strict_object_and_no_target() {
        let (_directory, _agent, mut server, key, _) = fixture();
        let owner = peer(&server);
        server.save().unwrap();
        let settings = serde_json::to_value(&server.settings).unwrap();
        let disk = fs::read(server.state_directory.join("settings.json")).unwrap();
        let expiry = server.expiry.clone();
        let stranger = libc::ucred {
            uid: owner.uid.wrapping_add(1),
            ..owner
        };
        let value = json!({"lifetime_seconds":900});
        assert_eq!(
            server
                .desktop_command(global_rules(value.clone()), stranger)
                .unwrap_err()
                .0,
            "wrong_user"
        );
        assert_eq!(
            server
                .command(global_rules(value.clone()), owner)
                .unwrap_err()
                .0,
            "forbidden"
        );
        for (available, locked) in [(false, false), (true, true)] {
            server.session.available = available;
            server.session.locked = locked;
            assert_eq!(
                server
                    .desktop_command(global_rules(value.clone()), owner)
                    .unwrap_err()
                    .0,
                "session_locked_or_unavailable"
            );
        }
        server.session.available = true;
        server.session.locked = false;
        for invalid in [
            Value::Null,
            json!({}),
            json!(true),
            json!([]),
            json!([900]),
            json!({"lifetime_seconds":-1}),
            json!({"lifetime_seconds":1.5}),
            json!({"lifetime_seconds":"900"}),
            json!({"lifetime_seconds":null}),
            json!({"lifetime_seconds":900,"confirmed":true}),
            json!({"lifetime_seconds":900,"revoke_on_lock":false}),
        ] {
            assert_eq!(
                server
                    .desktop_command(global_rules(invalid), owner)
                    .unwrap_err()
                    .0,
                "invalid_json"
            );
        }
        assert_eq!(
            server
                .desktop_command(global_rules(json!({"lifetime_seconds":31_536_001})), owner)
                .unwrap_err()
                .0,
            "invalid_lifetime"
        );
        for (target, request) in [
            (Some(key.id.clone()), None),
            (None, Some("pending-request".into())),
        ] {
            let mut cmd = global_rules(value.clone());
            cmd.key = target;
            cmd.request_id = request;
            assert_eq!(
                server.desktop_command(cmd, owner).unwrap_err().0,
                "invalid_json"
            );
        }
        assert_eq!(
            server
                .desktop_command(dialog("rules.global", &key, value.clone()), owner)
                .unwrap_err()
                .0,
            "invalid_action"
        );
        assert_eq!(
            server
                .request(
                    None,
                    "rules.global",
                    &global_rules(value),
                    "untrusted caller"
                )
                .unwrap_err()
                .0,
            "invalid_operation"
        );
        assert_eq!(serde_json::to_value(&server.settings).unwrap(), settings);
        assert_eq!(
            fs::read(server.state_directory.join("settings.json")).unwrap(),
            disk
        );
        assert_eq!(server.expiry, expiry);
        assert_eq!(agent::list(&server.backend()).unwrap().len(), 1);
        assert!(server.active.is_none() && server.history.is_empty());
    }

    #[test]
    fn direct_global_rules_busy_keeps_pending_job_and_its_captured_lifetime() {
        let (_directory, _agent, mut server, key, pending) = fixture();
        let owner = peer(&server);
        server.save().unwrap();
        let disk = fs::read(server.state_directory.join("settings.json")).unwrap();
        let settings = serde_json::to_value(&server.settings).unwrap();
        let expiry = server.expiry.clone();
        let pid = pending_request(&mut server, pending, false);
        let deadline = server.active.as_ref().unwrap().deadline;
        let rules = server.active.as_ref().unwrap().job.rules.clone();
        for operation in ["unlock", "sync", "rules.key", "scan"] {
            server.active.as_mut().unwrap().job.operation = operation.into();
            assert_eq!(
                server
                    .desktop_command(global_rules(json!({"lifetime_seconds":900})), owner)
                    .unwrap_err()
                    .0,
                "busy"
            );
            let active = server.active.as_ref().unwrap();
            assert_eq!(active.child.id(), pid);
            assert_eq!(active.deadline, deadline);
            assert_eq!(active.job.rules, rules);
            assert_eq!(active.job.operation, operation);
            assert_eq!(server.guard.lock().unwrap().generation, 0);
            assert_eq!(unsafe { libc::kill(pid as i32, 0) }, 0);
            assert_eq!(server.history["pending-request"]["state"], "pending");
            assert_eq!(serde_json::to_value(&server.settings).unwrap(), settings);
            assert_eq!(
                fs::read(server.state_directory.join("settings.json")).unwrap(),
                disk
            );
            assert_eq!(server.expiry, expiry);
        }
        server.active.as_mut().unwrap().job.operation = "unlock".into();
        server
            .cancel_active("cancelled", Some("cancelled"), true)
            .unwrap();
        let loaded = agent::list(&server.backend()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key(&key.id));
    }

    #[test]
    fn failed_global_rules_write_does_not_publish_policy_or_mutate_access() {
        let (directory, _agent, mut server, key, _) = fixture();
        let owner = peer(&server);
        server.settings.global.lifetime_seconds = 60;
        server
            .settings
            .keys
            .entry(key.id.clone())
            .or_default()
            .fingerprint_mode = true;
        let credential = server.credential_path(&key.id);
        fs::write(&credential, b"disposable ciphertext fixture").unwrap();
        server.save().unwrap();
        let settings = serde_json::to_value(&server.settings).unwrap();
        let disk = fs::read(server.state_directory.join("settings.json")).unwrap();
        let expiry = server.expiry.clone();
        let blocker = directory.path().join("not-a-directory");
        fs::write(&blocker, b"disposable write failure fixture").unwrap();
        let original_directory = server.state_directory.clone();
        // Fail before the atomic replacement, leaving the saved settings
        // available for a byte-for-byte comparison after the rejected save.
        server.state_directory = blocker;
        let result = server.desktop_command(
            global_rules(json!({"lifetime_seconds":900,"revoke_on_sleep":true})),
            owner,
        );
        server.state_directory = original_directory;
        assert!(result.is_err());
        assert_eq!(serde_json::to_value(&server.settings).unwrap(), settings);
        assert_eq!(
            fs::read(server.state_directory.join("settings.json")).unwrap(),
            disk
        );
        assert_eq!(server.expiry, expiry);
        let loaded = agent::list(&server.backend()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key(&key.id));
        assert_eq!(
            fs::read(&credential).unwrap(),
            b"disposable ciphertext fixture"
        );
        assert!(server.active.is_none() && server.history.is_empty());
    }

    #[test]
    fn global_rules_parent_sync_failure_reports_committed_policy_without_extending_access() {
        let (_directory, _agent, mut server, key, custom) = fixture();
        let owner = peer(&server);
        server.settings.global.lifetime_seconds = 60;
        server
            .settings
            .keys
            .entry(key.id.clone())
            .or_default()
            .fingerprint_mode = true;
        server
            .settings
            .keys
            .entry(custom.id.clone())
            .or_default()
            .rules = Some(Rules {
            lifetime_seconds: 45,
        });
        let credential = server.credential_path(&key.id);
        fs::write(&credential, b"disposable ciphertext fixture").unwrap();
        server.save().unwrap();
        let per_key = serde_json::to_value(&server.settings.keys).unwrap();
        let expiry = server.expiry.clone();
        let generation = server.guard.lock().unwrap().generation;
        server.save_global_settings = |path, settings| {
            platform::save_json_outcome_with_parent_sync(path, settings, |parent| {
                // Inject only the final directory-sync failure: the same
                // atomic writer must already have replaced the real file.
                let replaced: Settings =
                    serde_json::from_slice(&fs::read(parent.join("settings.json")).unwrap())
                        .unwrap();
                assert_eq!(
                    serde_json::to_value(&replaced).unwrap(),
                    serde_json::to_value(settings).unwrap()
                );
                assert_eq!(replaced.global.lifetime_seconds, 900);
                Err(Error("disposable_parent_sync_failure"))
            })
        };
        let response = server
            .desktop_command(
                global_rules(json!({"lifetime_seconds":900,"revoke_on_sleep":true})),
                owner,
            )
            .unwrap();
        assert_eq!(
            response,
            json!({
                "api_version":protocol::API, "state":"partial", "operation":"rules.global",
                "key_id":null, "request_id":null, "expires_at":null,
                "error_code":"settings_durability_unknown",
                "global_rules":{"lifetime_seconds":900,"revoke_on_sleep":true}
            })
        );
        let saved: Settings = serde_json::from_slice(
            &fs::read(server.state_directory.join("settings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(saved.global, server.settings.global);
        assert!(saved.revoke_on_sleep && server.settings.revoke_on_sleep);
        assert_eq!(server.settings.effective(&key.id).lifetime_seconds, 900);
        assert_eq!(server.settings.effective(&custom.id).lifetime_seconds, 45);
        assert_eq!(serde_json::to_value(&saved.keys).unwrap(), per_key);
        assert_eq!(
            serde_json::to_value(&server.settings.keys).unwrap(),
            per_key
        );
        assert_eq!(server.expiry, expiry);
        let loaded = agent::list(&server.backend()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key(&key.id));
        assert_eq!(
            fs::read(&credential).unwrap(),
            b"disposable ciphertext fixture"
        );
        assert_eq!(server.guard.lock().unwrap().generation, generation);
        assert!(server.active.is_none() && server.history.is_empty());
    }

    #[test]
    fn global_sleep_preference_is_atomic_independent_and_legacy_timer_updates_preserve_it() {
        let (_directory, _agent, mut server, key, custom) = fixture();
        let owner = peer(&server);
        let expiry = server.expiry.clone();
        server
            .settings
            .keys
            .entry(custom.id.clone())
            .or_default()
            .rules = Some(Rules {
            lifetime_seconds: 45,
        });
        for enabled in [true, false, true] {
            let response = server
                .desktop_command(
                    global_rules(json!({
                        "lifetime_seconds":900,"revoke_on_sleep":enabled,
                    })),
                    owner,
                )
                .unwrap();
            assert_eq!(
                response["global_rules"],
                json!({"lifetime_seconds":900,"revoke_on_sleep":enabled})
            );
            // Older panels can still change a duration without resetting sleep
            // policy. Missing and explicit null are deliberately different.
            let response = server
                .desktop_command(global_rules(json!({"lifetime_seconds":120})), owner)
                .unwrap();
            assert_eq!(
                response["global_rules"],
                json!({"lifetime_seconds":120,"revoke_on_sleep":enabled})
            );
            let saved: Settings = serde_json::from_slice(
                &fs::read(server.state_directory.join("settings.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(saved.revoke_on_sleep, enabled);
            assert_eq!(saved.global.lifetime_seconds, 120);
            assert_eq!(server.settings.effective(&custom.id).lifetime_seconds, 45);
            let capabilities = server.command(Command::new("capabilities"), owner).unwrap();
            assert_eq!(capabilities["revocation"]["on_sleep"], enabled);
            assert_eq!(capabilities["revocation"]["sleep_supported"], true);
            assert_eq!(capabilities["revocation"]["on_lock"], false);
            assert_eq!(server.expiry, expiry);
            let loaded = agent::list(&server.backend()).unwrap();
            assert_eq!(loaded.len(), 1);
            assert!(loaded.contains_key(&key.id));
        }
        let before = serde_json::to_value(&server.settings).unwrap();
        for invalid in [Value::Null, json!(1), json!("true"), json!([]), json!({})] {
            assert_eq!(
                server
                    .desktop_command(
                        global_rules(json!({"lifetime_seconds":120,"revoke_on_sleep":invalid})),
                        owner
                    )
                    .unwrap_err()
                    .0,
                "invalid_json"
            );
        }
        assert_eq!(serde_json::to_value(&server.settings).unwrap(), before);
        assert!(server.active.is_none() && server.history.is_empty());
    }

    fn sleep_command(action: &str) -> SleepCommand {
        SleepCommand {
            api_version: protocol::API,
            action: action.into(),
        }
    }

    fn root_peer() -> libc::ucred {
        libc::ucred {
            pid: unsafe { libc::getpid() },
            uid: 0,
            gid: 0,
        }
    }

    #[test]
    fn sleep_admin_protocol_is_strict_root_only_and_absent_from_user_endpoints() {
        let (_directory, _agent, mut server, _, _) = fixture();
        let owner = peer(&server);
        for action in ["sleep.prepare", "sleep.resume"] {
            assert_eq!(
                server.command(Command::new(action), owner).unwrap_err().0,
                "forbidden"
            );
            assert_eq!(
                server
                    .desktop_command(Command::new(action), owner)
                    .unwrap_err()
                    .0,
                "forbidden"
            );
            let stranger = libc::ucred {
                uid: owner.uid.max(1),
                ..owner
            };
            assert_eq!(
                server
                    .sleep_command(sleep_command(action), stranger)
                    .unwrap_err()
                    .0,
                "wrong_user"
            );
        }
        for invalid in [
            json!([1, "sleep.prepare"]),
            json!(null),
            json!({}),
            json!({"api_version":1,"action":"sleep.prepare","key":"x"}),
            json!({"api_version":1,"action":"sleep.prepare","value":null}),
            json!({"api_version":1,"action":"sleep.prepare","request_id":null}),
            json!({"api_version":1,"action":"sleep.prepare","reason":"x"}),
            json!({"api_version":1,"action":"sleep.prepare","interactive":true}),
        ] {
            assert!(SleepCommand::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
        }
        let parsed = SleepCommand::parse(br#"{"api_version":1,"action":"sleep.prepare"}"#).unwrap();
        assert_eq!(
            server.sleep_command(parsed, root_peer()).unwrap_err().0,
            "sleep_marker_missing"
        );
        assert_eq!(
            server
                .sleep_command(sleep_command("keys.unlock"), root_peer())
                .unwrap_err()
                .0,
            "invalid_action"
        );
        let invalid_version = SleepCommand {
            api_version: protocol::API + 1,
            action: "sleep.prepare".into(),
        };
        assert_eq!(
            server
                .sleep_command(invalid_version, root_peer())
                .unwrap_err()
                .0,
            "api_mismatch"
        );
        assert!(!server.sleeping && server.available());
        assert!(server.active.is_none());
        assert_eq!(agent::list(&server.backend()).unwrap().len(), 1);
    }

    #[test]
    fn prepare_sleep_reaps_loader_and_fences_connections_while_opt_out_preserves_prior_access() {
        use std::os::unix::net::UnixStream;
        for already_added in [false, true] {
            let (directory, _agent, mut server, prior, pending) = fixture();
            let expiry = server.expiry.clone();
            if already_added {
                add(&server, &pending);
            }
            let pid = pending_request(&mut server, pending, already_added);
            let public = directory.path().join("proxy");
            agent::proxy_at(
                UnixListener::bind(&public).unwrap(),
                server.user.uid,
                server.backend(),
                server.guard.clone(),
            );
            let mut before_sleep = UnixStream::connect(&public).unwrap();
            before_sleep
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            agent::write(&mut before_sleep, &[11]).unwrap();
            assert_eq!(agent::packet(&mut before_sleep).unwrap()[0], 12);
            fs::write(&server.sleep_marker, b"disposable sleep marker").unwrap();
            let response = server
                .sleep_command(sleep_command("sleep.prepare"), root_peer())
                .unwrap();
            assert_eq!(response["state"], "ready");
            assert_eq!(response["operation"], "sleep.prepare");
            assert_eq!(response["revoke_on_sleep"], false);
            assert!(response["request_id"].is_null());
            assert!(server.sleeping && !server.available());
            assert!(server.active.is_none() && server.gate.active.is_none());
            assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
            assert_eq!(server.history["pending-request"]["state"], "cancelled");
            assert_eq!(
                server.history["pending-request"]["error_code"],
                "sleep_in_progress"
            );
            {
                let guard = server.guard.lock().unwrap();
                assert!(guard.blocked && guard.worker_group.is_none());
                assert!(guard.retired_worker_groups.contains(&(pid as i32)));
            }
            agent::write(&mut before_sleep, &[17]).unwrap();
            assert!(agent::packet(&mut before_sleep).is_err());
            let mut during_sleep = UnixStream::connect(&public).unwrap();
            during_sleep
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            agent::write(&mut during_sleep, &[17]).unwrap();
            assert_eq!(agent::packet(&mut during_sleep).unwrap().as_slice(), [5]);
            assert_eq!(
                server
                    .sleep_command(sleep_command("sleep.resume"), root_peer())
                    .unwrap_err()
                    .0,
                "sleep_in_progress"
            );
            server
                .update_session(Session {
                    available: true,
                    ..Default::default()
                })
                .unwrap();
            assert!(server.guard.lock().unwrap().blocked);
            fs::remove_file(&server.sleep_marker).unwrap();
            // Removing the persistent marker alone is not a resume command.
            server
                .update_session(Session {
                    available: true,
                    ..Default::default()
                })
                .unwrap();
            assert!(server.sleeping && !server.available());
            let response = server
                .sleep_command(sleep_command("sleep.resume"), root_peer())
                .unwrap();
            assert_eq!(response["state"], "ready");
            assert_eq!(response["operation"], "sleep.resume");
            assert!(!server.sleeping && server.available());
            assert!(!server.guard.lock().unwrap().blocked);
            agent::write(&mut during_sleep, &[17]).unwrap();
            assert!(agent::packet(&mut during_sleep).is_err());
            server.tick().unwrap();
            let loaded = agent::list(&server.backend()).unwrap();
            assert_eq!(loaded.len(), 1);
            assert!(loaded.contains_key(&prior.id));
            assert_eq!(server.expiry, expiry);
        }
    }

    #[test]
    fn sleep_marker_rejects_user_actions_before_loaded_key_shortcut_or_native_launch() {
        let (_directory, _agent, mut server, loaded, _) = fixture();
        let owner = peer(&server);
        let expiry = server.expiry.clone();
        fs::write(&server.sleep_marker, b"disposable marker").unwrap();
        assert!(!server.sleeping); // The event loop has not latched it yet.
        let mut unlock = Command::new("keys.unlock");
        unlock.key = Some(loaded.id.clone());
        unlock.interactive = true;
        assert_eq!(
            server.command(unlock, owner).unwrap_err().0,
            "sleep_in_progress"
        );
        for cmd in [
            Command::new("scan"),
            direct("revoke", &loaded, Value::Null),
            direct("mode", &loaded, json!({"fingerprint_mode":true})),
            global_rules(json!({"lifetime_seconds":900,"revoke_on_sleep":false})),
            dialog("sync", &loaded, Value::Null),
            dialog("encrypt", &loaded, Value::Null),
            dialog("unbind", &loaded, Value::Null),
            dialog("rules.key", &loaded, Value::Null),
        ] {
            assert_eq!(
                server.desktop_command(cmd, owner).unwrap_err().0,
                "sleep_in_progress"
            );
        }
        let panel = server
            .desktop_command(Command::new("panel.list"), owner)
            .unwrap();
        assert_eq!(panel["sleep_preparing"], true);
        assert_eq!(panel["session_available"], false);
        assert!(server.active.is_none() && server.history.is_empty());
        assert_eq!(server.expiry, expiry);
        assert_eq!(agent::list(&server.backend()).unwrap().len(), 1);
        fs::remove_file(&server.sleep_marker).unwrap();
        assert_eq!(
            server
                .desktop_command(Command::new("panel.list"), owner)
                .unwrap()["sleep_preparing"],
            false
        );
    }

    #[test]
    fn sleep_marker_observation_cancels_every_pending_operation_before_user_commands() {
        for operation in ["unlock", "sync", "encrypt", "rules.key", "unbind", "scan"] {
            let (_directory, _agent, mut server, prior, pending) = fixture();
            server.settings.revoke_on_sleep = true;
            let expiry = server.expiry.clone();
            pending_confirmation(&mut server, &pending, operation, Value::Null);
            let pid = server.active.as_ref().unwrap().child.id();
            fs::write(&server.sleep_marker, b"disposable sleep marker").unwrap();
            assert!(!server.available()); // No session event or admin ACK yet.
            server.observe_sleep_marker().unwrap();
            assert!(server.sleeping && server.guard.lock().unwrap().blocked);
            assert!(server.active.is_none());
            assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
            let result = &server.history["pending-request"];
            assert_eq!(
                result["state"],
                if operation == "encrypt" {
                    "partial"
                } else {
                    "cancelled"
                }
            );
            assert_eq!(
                result["error_code"],
                if operation == "encrypt" {
                    "commit_state_unknown"
                } else {
                    "sleep_in_progress"
                }
            );
            let owner = peer(&server);
            assert_eq!(
                server
                    .desktop_command(
                        global_rules(json!({"lifetime_seconds":0,"revoke_on_sleep":false})),
                        owner
                    )
                    .unwrap_err()
                    .0,
                "sleep_in_progress"
            );
            let response = server
                .sleep_command(sleep_command("sleep.prepare"), root_peer())
                .unwrap();
            assert_eq!(response["revoke_on_sleep"], true);
            // prepare is the fence ACK. The coordinator is responsible for
            // stopping all three units when this flag is true.
            let loaded = agent::list(&server.backend()).unwrap();
            assert_eq!(loaded.len(), 1);
            assert!(loaded.contains_key(&prior.id));
            assert_eq!(server.expiry, expiry);
            assert_eq!(
                agent::exchange(&server.backend(), &[19])
                    .unwrap()
                    .as_slice(),
                [6]
            );
            fs::remove_file(&server.sleep_marker).unwrap();
            server
                .sleep_command(sleep_command("sleep.resume"), root_peer())
                .unwrap();
            assert!(server.reconcile().unwrap().is_empty());
            server.tick().unwrap();
            assert!(agent::list(&server.backend()).unwrap().is_empty());
            assert!(server.expiry.is_empty() && server.active.is_none());
        }
    }

    #[test]
    fn direct_desktop_actions_validate_owner_session_payload_and_binding() {
        let (_directory, _agent, mut server, key, _) = fixture();
        let owner = peer(&server);
        let before = serde_json::to_value(&server.settings).unwrap();
        for (action, value) in [
            ("mode", json!({"fingerprint_mode":true})),
            ("revoke", Value::Null),
        ] {
            let stranger = libc::ucred {
                uid: owner.uid.wrapping_add(1),
                ..owner
            };
            assert_eq!(
                server
                    .desktop_command(direct(action, &key, value.clone()), stranger)
                    .unwrap_err()
                    .0,
                "wrong_user"
            );
            assert_eq!(
                server
                    .command(direct(action, &key, value.clone()), owner)
                    .unwrap_err()
                    .0,
                "forbidden"
            );
            for (available, locked) in [(false, false), (true, true)] {
                server.session.available = available;
                server.session.locked = locked;
                assert_eq!(
                    server
                        .desktop_command(direct(action, &key, value.clone()), owner)
                        .unwrap_err()
                        .0,
                    "session_locked_or_unavailable"
                );
            }
            server.session.available = true;
            server.session.locked = false;
        }
        for value in [
            Value::Null,
            json!({}),
            json!(true),
            json!({"fingerprint_mode":"true"}),
            json!({"fingerprint_mode":true,"confirmed":true}),
        ] {
            assert_eq!(
                server
                    .desktop_command(direct("mode", &key, value), owner)
                    .unwrap_err()
                    .0,
                "invalid_json"
            );
        }
        for value in [json!({}), json!(false), json!({"confirmed":true})] {
            assert_eq!(
                server
                    .desktop_command(direct("revoke", &key, value), owner)
                    .unwrap_err()
                    .0,
                "invalid_json"
            );
        }
        assert_eq!(
            server
                .desktop_command(
                    direct("mode", &key, json!({"fingerprint_mode":false})),
                    owner
                )
                .unwrap_err()
                .0,
            "not_bound"
        );
        assert_eq!(serde_json::to_value(&server.settings).unwrap(), before);
        assert_eq!(agent::list(&server.backend()).unwrap().len(), 1);
        assert!(server.active.is_none() && server.history.is_empty());
    }

    #[test]
    fn direct_mode_is_an_idempotent_saved_choice_without_access_or_quota_effects() {
        let (_directory, _agent, mut server, key, _) = fixture();
        let owner = peer(&server);
        let credential = server.credential_path(&key.id);
        fs::write(&credential, b"disposable ciphertext fixture").unwrap();
        server
            .settings
            .keys
            .entry(key.id.clone())
            .or_default()
            .rules = Some(Rules {
            lifetime_seconds: 45,
        });
        let expiry = server.expiry[&key.id];
        let generation = server.guard.lock().unwrap().generation;
        for now in 0..3 {
            server.gate.check("old-window", now).unwrap();
            server.gate.check_dialog("old-dialog", now).unwrap();
        }
        for desired in [true, true, false, false] {
            let response = server
                .desktop_command(
                    direct("mode", &key, json!({"fingerprint_mode":desired})),
                    owner,
                )
                .unwrap();
            assert_eq!(
                response["mode"],
                if desired { "fingerprint" } else { "password" }
            );
            assert_eq!(response["operation"], "mode");
            assert_eq!(response["state"], "unlocked");
            assert_eq!(response["busy"], false);
            assert!(response["request_id"].is_null());
            assert_eq!(response["expires_at"], json!(expiry));
            assert_eq!(response["rules"]["lifetime_seconds"], 45);
            assert_eq!(response["inherits"], false);
            assert_eq!(response["bound"], true);
            let saved: Settings = serde_json::from_slice(
                &fs::read(server.state_directory.join("settings.json")).unwrap(),
            )
            .unwrap();
            assert_eq!(saved.keys[&key.id].fingerprint_mode, desired);
            assert_eq!(server.expiry[&key.id], expiry);
            assert_eq!(agent::list(&server.backend()).unwrap().len(), 1);
            assert_eq!(
                fs::read(&credential).unwrap(),
                b"disposable ciphertext fixture"
            );
            assert_eq!(server.guard.lock().unwrap().generation, generation);
            assert!(server.active.is_none() && server.history.is_empty());
        }
        // A filesystem error before replacement must not publish a new mode.
        fs::remove_file(server.state_directory.join("settings.json")).unwrap();
        fs::create_dir(server.state_directory.join("settings.json")).unwrap();
        let before = serde_json::to_value(&server.settings).unwrap();
        assert!(
            server
                .desktop_command(
                    direct("mode", &key, json!({"fingerprint_mode":true})),
                    owner
                )
                .is_err()
        );
        assert_eq!(serde_json::to_value(&server.settings).unwrap(), before);
        assert_eq!(server.expiry[&key.id], expiry);
        assert_eq!(agent::list(&server.backend()).unwrap().len(), 1);
    }

    #[test]
    fn direct_revoke_is_immediate_idempotent_and_preserves_other_access_and_binding() {
        let (_directory, _agent, mut server, key, other) = fixture();
        let owner = peer(&server);
        add(&server, &other);
        server
            .expiry
            .insert(other.id.clone(), Some(platform::now() + 45));
        let other_expiry = server.expiry[&other.id];
        let credential = server.credential_path(&key.id);
        fs::write(&credential, b"disposable ciphertext fixture").unwrap();
        server
            .settings
            .keys
            .entry(key.id.clone())
            .or_default()
            .fingerprint_mode = true;
        server.save().unwrap();
        let settings = fs::read(server.state_directory.join("settings.json")).unwrap();
        for now in 0..3 {
            server.gate.check("old-window", now).unwrap();
            server.gate.check_dialog("old-dialog", now).unwrap();
        }
        for _ in 0..2 {
            let response = server
                .desktop_command(direct("revoke", &key, Value::Null), owner)
                .unwrap();
            assert_eq!(response["operation"], "revoke");
            assert_eq!(response["state"], "locked");
            assert_eq!(response["mode"], "fingerprint");
            assert_eq!(response["bound"], true);
            assert_eq!(response["busy"], false);
            assert!(response["request_id"].is_null() && response["expires_at"].is_null());
            let loaded = agent::list(&server.backend()).unwrap();
            assert_eq!(loaded.len(), 1);
            assert!(loaded.contains_key(&other.id));
            assert!(!server.expiry.contains_key(&key.id));
            assert_eq!(server.expiry[&other.id], other_expiry);
            assert_eq!(
                fs::read(server.state_directory.join("settings.json")).unwrap(),
                settings
            );
            assert_eq!(
                fs::read(&credential).unwrap(),
                b"disposable ciphertext fixture"
            );
            assert!(server.active.is_none() && server.history.is_empty());
        }
    }

    #[test]
    fn direct_revoke_cancels_matching_loader_and_fences_queued_agent_connections() {
        use std::os::unix::net::UnixStream;
        for already_added in [false, true] {
            let (directory, _agent, mut server, prior, pending) = fixture();
            let owner = peer(&server);
            let prior_expiry = server.expiry[&prior.id];
            if already_added {
                add(&server, &pending);
            }
            let pid = pending_request(&mut server, pending.clone(), already_added);
            let public = directory.path().join("proxy");
            agent::proxy_at(
                UnixListener::bind(&public).unwrap(),
                server.user.uid,
                server.backend(),
                server.guard.clone(),
            );
            let mut old_connection = UnixStream::connect(&public).unwrap();
            old_connection
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            agent::write(&mut old_connection, &[11]).unwrap();
            assert_eq!(agent::packet(&mut old_connection).unwrap()[0], 12);
            // Invalid payload cannot even cancel a pending loader.
            assert_eq!(
                server
                    .desktop_command(direct("revoke", &pending, json!({"ok":true})), owner)
                    .unwrap_err()
                    .0,
                "invalid_json"
            );
            assert!(server.active.is_some());
            let response = server
                .desktop_command(direct("revoke", &pending, Value::Null), owner)
                .unwrap();
            assert_eq!(response["state"], "locked");
            assert_eq!(response["operation"], "revoke");
            assert_eq!(response["busy"], false);
            assert!(response["request_id"].is_null());
            assert!(server.active.is_none() && server.gate.active.is_none());
            assert_eq!(server.history["pending-request"]["state"], "cancelled");
            assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
            let guard = server.guard.lock().unwrap();
            assert!(guard.retired_worker_groups.contains(&(pid as i32)));
            assert_eq!(guard.generation, 1);
            assert!(guard.worker_group.is_none() && !guard.blocked);
            drop(guard);
            // A malformed ADD would receive agent failure if forwarded; EOF
            // proves this pre-cancellation connection was fenced instead.
            agent::write(&mut old_connection, &[17]).unwrap();
            assert!(agent::packet(&mut old_connection).is_err());
            server.tick().unwrap();
            let loaded = agent::list(&server.backend()).unwrap();
            assert_eq!(loaded.len(), 1);
            assert!(loaded.contains_key(&prior.id));
            assert_eq!(server.expiry[&prior.id], prior_expiry);
        }
    }

    #[test]
    fn direct_revoke_other_key_preserves_pending_loader_and_mode_is_busy() {
        let (_directory, _agent, mut server, prior, pending) = fixture();
        let owner = peer(&server);
        fs::write(
            server.credential_path(&prior.id),
            b"disposable ciphertext fixture",
        )
        .unwrap();
        let pid = pending_request(&mut server, pending.clone(), false);
        let deadline = server.active.as_ref().unwrap().deadline;
        assert_eq!(
            server
                .desktop_command(
                    direct("mode", &prior, json!({"fingerprint_mode":true})),
                    owner
                )
                .unwrap_err()
                .0,
            "busy"
        );
        let response = server
            .desktop_command(direct("revoke", &prior, Value::Null), owner)
            .unwrap();
        assert_eq!(response["state"], "locked");
        assert_eq!(response["busy"], false);
        assert!(response["request_id"].is_null());
        assert_eq!(server.active.as_ref().unwrap().child.id(), pid);
        assert_eq!(server.active.as_ref().unwrap().deadline, deadline);
        assert_eq!(server.guard.lock().unwrap().generation, 0);
        assert_eq!(server.history["pending-request"]["state"], "pending");
        add(&server, &pending);
        server.guard.lock().unwrap().managed_added_at = Some(platform::now());
        finish_confirmation(&mut server, json!({"auth_method":"password"}));
        assert_eq!(server.history["pending-request"]["state"], "unlocked");
        let loaded = agent::list(&server.backend()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key(&pending.id) && !loaded.contains_key(&prior.id));
    }

    #[test]
    fn revoke_during_binding_or_encryption_keeps_job_but_late_commit_cannot_load_key() {
        for operation in ["sync", "encrypt"] {
            let (_directory, _agent, mut server, key, _) = fixture();
            let owner = peer(&server);
            pending_confirmation(&mut server, &key, operation, Value::Null);
            let deadline = server.active.as_ref().unwrap().deadline;
            let response = server
                .desktop_command(direct("revoke", &key, Value::Null), owner)
                .unwrap();
            assert_eq!(response["state"], "locked");
            assert_eq!(response["busy"], true);
            assert_eq!(response["operation"], "revoke");
            assert!(response["request_id"].is_null());
            assert_eq!(server.active.as_ref().unwrap().deadline, deadline);
            assert_eq!(server.active.as_ref().unwrap().job.operation, operation);
            let result = if operation == "sync" {
                json!({"sealed_credential":STANDARD.encode(b"disposable ciphertext fixture")})
            } else {
                json!({"keys":server.inventory})
            };
            finish_confirmation(&mut server, result);
            assert_eq!(
                server.history["pending-request"]["state"],
                if operation == "sync" {
                    "synced"
                } else {
                    "encrypted"
                }
            );
            assert!(agent::list(&server.backend()).unwrap().is_empty());
            assert!(!server.expiry.contains_key(&key.id));
        }
    }

    #[test]
    fn selective_revoke_failure_fences_unrelated_loader_before_whole_agent_reset() {
        let (_directory, _agent, mut server, key, pending) = fixture();
        let owner = peer(&server);
        let pid = pending_request(&mut server, pending, false);
        // The loaded fingerprint still resolves; invalid public data causes
        // selective REMOVE to fail without contacting any system service.
        server.inventory[0].public_blob = "invalid base64".into();
        server.reset_backend = |server| {
            assert!(server.active.is_none());
            let guard = server.guard.lock().unwrap();
            assert!(guard.blocked && guard.generation >= 2);
            assert!(guard.worker_group.is_none());
            let retired = *guard.retired_worker_groups.iter().next().unwrap();
            assert_eq!(unsafe { libc::kill(retired, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
            drop(guard);
            assert_eq!(agent::exchange(&server.backend(), &[19])?.as_slice(), [6]);
            Ok(())
        };
        let response = server
            .desktop_command(direct("revoke", &key, Value::Null), owner)
            .unwrap();
        assert_eq!(response["state"], "locked");
        assert_eq!(response["busy"], false);
        assert!(response["request_id"].is_null());
        assert!(server.active.is_none() && server.gate.active.is_none());
        assert!(
            server
                .guard
                .lock()
                .unwrap()
                .retired_worker_groups
                .contains(&(pid as i32))
        );
        assert_eq!(server.history["pending-request"]["state"], "cancelled");
        assert_eq!(
            server.history["pending-request"]["error_code"],
            "agent_unavailable"
        );
        assert!(server.expiry.is_empty());
        assert!(agent::list(&server.backend()).unwrap().is_empty());
        server.tick().unwrap();
        assert!(agent::list(&server.backend()).unwrap().is_empty());
    }

    #[test]
    fn failed_whole_agent_reset_after_direct_revoke_keeps_proxy_closed_and_loader_dead() {
        let (_directory, _agent, mut server, key, pending) = fixture();
        let owner = peer(&server);
        let pid = pending_request(&mut server, pending, false);
        server.inventory[0].public_blob = "invalid base64".into();
        server.reset_backend = |_| Err(Error("disposable_reset_failure"));
        assert_eq!(
            server
                .desktop_command(direct("revoke", &key, Value::Null), owner)
                .unwrap_err()
                .0,
            "agent_reset_failed"
        );
        assert!(server.agent_reset_failed && server.active.is_none());
        let guard = server.guard.lock().unwrap();
        assert!(guard.blocked && guard.worker_group.is_none());
        assert!(guard.retired_worker_groups.contains(&(pid as i32)));
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
        assert!(server.expiry.is_empty());
    }

    #[test]
    fn session_changes_preserve_loaded_identity_generation_and_lifetime() {
        let (_directory, _agent, mut server, prior, _) = fixture();
        let expiry = server.expiry[&prior.id];
        for session in [
            Session {
                available: true,
                locked: true,
                ..Default::default()
            },
            Session::default(),
            Session {
                available: true,
                ..Default::default()
            },
        ] {
            server.update_session(session).unwrap();
            assert!(
                agent::list(&server.backend())
                    .unwrap()
                    .contains_key(&prior.id)
            );
            assert_eq!(server.expiry[&prior.id], expiry);
            assert_eq!(server.guard.lock().unwrap().generation, 0);
        }
    }

    #[test]
    fn locked_session_cancels_prompt_without_revoking_preloaded_identity() {
        let (_directory, _agent, mut server, prior, pending) = fixture();
        let expiry = server.expiry[&prior.id];
        let pid = pending_request(&mut server, pending, false);
        server
            .update_session(Session {
                available: true,
                locked: true,
                ..Default::default()
            })
            .unwrap();
        assert!(server.active.is_none());
        assert!(server.gate.active.is_none());
        assert_eq!(server.history["pending-request"]["state"], "cancelled");
        assert_eq!(
            server.history["pending-request"]["error_code"],
            "session_locked_or_unavailable"
        );
        assert!(
            server
                .guard
                .lock()
                .unwrap()
                .retired_worker_groups
                .contains(&(pid as i32))
        );
        assert_eq!(agent::list(&server.backend()).unwrap().len(), 1);
        assert_eq!(server.expiry[&prior.id], expiry);
        let rejected = server.request(None, "scan", &Command::new("scan"), "fixture");
        assert_eq!(rejected.unwrap_err().0, "session_locked_or_unavailable");
    }

    #[test]
    fn unavailable_session_removes_only_unfinished_load() {
        let (_directory, _agent, mut server, prior, pending) = fixture();
        let expiry = server.expiry[&prior.id];
        add(&server, &pending);
        pending_request(&mut server, pending.clone(), true);
        server.update_session(Session::default()).unwrap();
        let loaded = agent::list(&server.backend()).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(loaded.contains_key(&prior.id));
        assert!(!loaded.contains_key(&pending.id));
        assert_eq!(server.expiry[&prior.id], expiry);
        assert!(!server.agent_reset_failed);
    }
}
