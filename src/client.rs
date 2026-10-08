use crate::{
    Error, Result,
    protocol::{self, Command},
};
use serde_json::Value;
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::MetadataExt, net::UnixStream},
    time::Duration,
};
pub fn call(cmd: &Command) -> Result<Value> {
    call_socket(cmd, "control.sock")
}

// The desktop endpoint permits direct revocation, unlock-method preferences
// and global lifetime/sleep settings. Other management changes require the protected
// native dialog; the public control endpoint never permits these mutations.
pub fn call_desktop(cmd: &Command) -> Result<Value> {
    call_socket(cmd, "desktop.sock")
}

fn call_socket(cmd: &Command, socket: &str) -> Result<Value> {
    let uid = unsafe { libc::getuid() };
    let dir = format!("/run/ssh-keys/{uid}");
    for p in ["/run/ssh-keys", &dir] {
        let m = fs::symlink_metadata(p).map_err(|_| Error("helper_unavailable"))?;
        if !m.is_dir() || m.uid() != 0 || m.mode() & 0o022 != 0 {
            return Err(Error("unsafe_socket_directory"));
        }
    }
    let mut stream =
        UnixStream::connect(format!("{dir}/{socket}")).map_err(|_| Error("helper_unavailable"))?;
    if crate::agent::peer(&stream)?.uid != 0 {
        return Err(Error("wrong_server"));
    }
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(1)))?;
    serde_json::to_writer(&mut stream, cmd)?;
    stream.write_all(b"\n")?;
    let mut bytes = Vec::new();
    let mut one = [0; 1];
    while bytes.len() < 4 * 1024 * 1024 {
        match stream.read(&mut one) {
            Ok(1) if one[0] != b'\n' => bytes.push(one[0]),
            Ok(_) => break,
            Err(e) => return Err(e.into()),
        }
    }
    let v: Value = serde_json::from_slice(&bytes)?;
    if v["api_version"] != protocol::API {
        return Err(Error("api_mismatch"));
    }
    Ok(v)
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
