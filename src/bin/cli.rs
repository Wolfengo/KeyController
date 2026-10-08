use ssh_keys::{
    Error, Result, client,
    protocol::{self, Command},
};
const HELP: &str = "kctrl — request SSH key access in your local graphical session\n\n  capabilities [--json]\n  keys list [--json]\n  keys status --key ID [--json]\n  keys unlock --key ID --interactive [--reason TEXT] [--json]\n  requests status REQUEST-ID [--json]\n  requests cancel REQUEST-ID [--json]\n\nExit status: 0 completed query/unlock, 3 pending (NOT unlocked), 1 error/denial/cancel.\nRequests expire after 120 seconds. Fingerprint scanning starts when the protected\nwindow appears; access still requires a successful fingerprint. Password unlock\nrequires entering the key passphrase and submitting it. The window can be cancelled.\nNo passphrase, policy, binding or file-encryption arguments are accepted.\nA loaded key is available to other processes of your user; revocation does not close\nexisting SSH connections. API v1. See /usr/share/doc/keycontroller/api.md.";
fn parse(args: &[String]) -> Result<Command> {
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
    while i < args.len() {
        match args[i].as_str() {
            "--json" => {}
            "--interactive" if c.action == "keys.unlock" => c.interactive = true,
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
    Ok(c)
}
fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.is_empty() || args.iter().any(|a| a == "--help" || a == "-h") {
        println!("{HELP}");
        return;
    }
    let json = args.iter().any(|a| a == "--json");
    let result = parse(&args)
        .and_then(|c| client::call(&c))
        .unwrap_or_else(|e| protocol::error(e.0));
    std::process::exit(client::print(&result, json));
}
#[cfg(test)]
mod tests {
    use super::*;
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
