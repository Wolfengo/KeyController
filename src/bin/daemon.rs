use ssh_keys::{
    Error, Result, process, protocol,
    worker::{self, Job},
};
use std::{
    fs::File,
    io::{Read, Write},
    os::fd::FromRawFd,
};
fn run() -> Result<()> {
    process::harden()?;
    if std::env::var("SSH_KEYS_INTERNAL_ASKPASS").as_deref() == Ok("1") {
        return process::askpass();
    }
    let args: Vec<_> = std::env::args().collect();
    if args.len() == 2 && (args[1] == "--worker" || args[1] == "--file-task") {
        let mut input = Vec::new();
        std::io::stdin().take(128 * 1024).read_to_end(&mut input)?;
        let job: Job = serde_json::from_slice(&input)?;
        let result = if args[1] == "--worker" {
            worker::run(job)
        } else {
            // Read the granted descriptor directly: reopening a root-owned
            // memfd after dropping UID would correctly fail its mode check.
            let secret = process::read_secret(unsafe { File::from_raw_fd(4) })?;
            worker::file_task(&job, &secret)
        };
        let value = result.unwrap_or_else(|e| protocol::error(e.0));
        serde_json::to_writer(std::io::stdout(), &value)?;
        std::io::stdout().write_all(b"\n")?;
        return Ok(());
    }
    if args.len() != 2 {
        return Err(Error("usage_ssh_keysd_uid"));
    }
    let uid = args[1].parse::<u32>().map_err(|_| Error("invalid_uid"))?;
    ssh_keys::server::serve(uid)
}
fn main() {
    if let Err(e) = run() {
        eprintln!("ssh-keysd: {}", e.0);
        std::process::exit(1);
    }
}
