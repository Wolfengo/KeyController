use ssh_keys::{
    client,
    protocol::{self, Command},
};

fn call(mut cmd: Command) -> ssh_keys::Result<serde_json::Value> {
    match cmd.action.as_str() {
        "keys.list" | "keys.status" | "keys.unlock" => client::call(&cmd),
        "capabilities" | "panel.list" | "scan" | "requests.status" | "requests.cancel" | "mode"
        | "revoke" => client::call_desktop(&cmd),
        "sync" | "encrypt" | "rules.key" | "unbind" | "settings.global" | "settings.key" => {
            // These are shortcuts for opening a specific native dialog. Its
            // private consent channel, never this launch command, grants the
            // requested change. Unknown fields cannot carry self-approval.
            cmd.value = serde_json::json!({"action":cmd.action,"value":cmd.value});
            cmd.action = "dialog.open".into();
            client::call_desktop(&cmd)
        }
        _ => Err(ssh_keys::Error("forbidden")),
    }
}

fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let result = (|| -> ssh_keys::Result<serde_json::Value> {
        if args.len() == 1 && args[0].starts_with('{') {
            let cmd: Command = serde_json::from_str(&args[0])?;
            return call(cmd);
        }
        Err(ssh_keys::Error("invalid_action"))
    })();
    let v = result.unwrap_or_else(|e| protocol::error(e.0));
    std::process::exit(client::print(&v, true));
}
