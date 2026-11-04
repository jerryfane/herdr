use crate::api::schema::{
    GuestAuditParams, GuestInviteCreateParams, GuestListParams, GuestRevokeParams,
    GuestUpdateParams, Method, Request,
};

const HELP: &str = "Usage:
  herdr guest invite <agent> --name <name> [--owner-name NAME] [--machine-label LABEL] [--ttl SECS] [--share-gram] [--machine ALIAS]
  herdr guest list [--machine ALIAS]
  herdr guest share-gram <guest-id> on|off [--machine ALIAS]
  herdr guest revoke <guest-or-invite-id> [--machine ALIAS]
  herdr guest log [<guest-id>] [--limit N] [--machine ALIAS]

Share one named, running agent with one outside person through the HerdrUp
guest relay. The guest can prompt it (labeled \"<name> (via HerdrUp): \") and
watch its terminal, but cannot type into the terminal or reach any other pane.
With --share-gram (or share-gram on later) the guest also sees every Gram the
agent sends from the moment the guest accepted, with its files. Invites work
once and expire after 24 hours by default. --machine runs the command on that
saved SSH machine.";

/// Options that take no value.
const FLAGS: &[&str] = &["share-gram"];

pub(super) fn run_guest_command(args: &[String]) -> std::io::Result<i32> {
    let result = match args.first().map(String::as_str) {
        Some("invite") => invite(&args[1..]),
        Some("list") => list(&args[1..]),
        Some("share-gram") => share_gram(&args[1..]),
        Some("revoke") => revoke(&args[1..]),
        Some("log") => log(&args[1..]),
        Some("help" | "--help" | "-h") => {
            println!("{HELP}");
            return Ok(0);
        }
        _ => Err(String::new()),
    };
    match result {
        Ok(code) => Ok(code),
        Err(message) => {
            if !message.is_empty() {
                eprintln!("{message}");
            }
            eprintln!("{HELP}");
            Ok(2)
        }
    }
}

/// Positional arguments plus `--flag value` options and value-less [`FLAGS`].
struct Parsed {
    positional: Vec<String>,
    options: Vec<(String, String)>,
}

impl Parsed {
    fn option(&self, name: &str) -> Option<String> {
        self.options
            .iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.clone())
    }

    fn flag(&self, name: &str) -> bool {
        self.options.iter().any(|(key, _)| key == name)
    }
}

fn parse(args: &[String], known: &[&str]) -> Result<Parsed, String> {
    let mut parsed = Parsed {
        positional: Vec::new(),
        options: Vec::new(),
    };
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        if let Some(name) = arg.strip_prefix("--") {
            if !known.contains(&name) {
                return Err(format!("unknown option: {arg}"));
            }
            if FLAGS.contains(&name) {
                parsed.options.push((name.to_string(), String::new()));
                continue;
            }
            let value = iter
                .next()
                .ok_or_else(|| format!("{arg} requires a value"))?;
            parsed.options.push((name.to_string(), value.clone()));
        } else {
            parsed.positional.push(arg.clone());
        }
    }
    Ok(parsed)
}

fn send(id: &str, method: Method) -> std::io::Result<i32> {
    super::print_response(&super::send_request(&Request {
        id: id.into(),
        method,
    })?)
}

fn invite(args: &[String]) -> Result<i32, String> {
    let parsed = parse(
        args,
        &[
            "name",
            "owner-name",
            "machine-label",
            "ttl",
            "share-gram",
            "machine",
        ],
    )?;
    let [target] = parsed.positional.as_slice() else {
        return Err("invite takes exactly one agent".into());
    };
    let name = parsed.option("name").ok_or("--name is required")?;
    let ttl_secs = parsed
        .option("ttl")
        .map(|ttl| ttl.parse::<u64>().map_err(|_| "--ttl must be seconds"))
        .transpose()?;
    let owner_name = parsed
        .option("owner-name")
        .or_else(|| super::login_user_from_env(|name| std::env::var_os(name)))
        .unwrap_or_else(|| "owner".into());
    let machine_label = parsed
        .option("machine-label")
        .unwrap_or_else(default_machine_label);
    send(
        "cli:guest:invite",
        Method::GuestInviteCreate(GuestInviteCreateParams {
            target: target.clone(),
            name,
            owner_name,
            machine_label,
            ttl_secs,
            share_gram: parsed.flag("share-gram"),
            machine: parsed.option("machine"),
        }),
    )
    .map_err(|err| err.to_string())
}

/// Turn Gram sharing on or off for an accepted guest.
fn share_gram(args: &[String]) -> Result<i32, String> {
    let parsed = parse(args, &["machine"])?;
    let [guest_id, setting] = parsed.positional.as_slice() else {
        return Err("share-gram takes a guest id and on or off".into());
    };
    let share_gram = match setting.as_str() {
        "on" => true,
        "off" => false,
        _ => return Err("share-gram takes on or off".into()),
    };
    send(
        "cli:guest:update",
        Method::GuestUpdate(GuestUpdateParams {
            guest_id: guest_id.clone(),
            share_gram,
            machine: parsed.option("machine"),
        }),
    )
    .map_err(|err| err.to_string())
}

fn list(args: &[String]) -> Result<i32, String> {
    let parsed = parse(args, &["machine"])?;
    if !parsed.positional.is_empty() {
        return Err("list takes no arguments".into());
    }
    send(
        "cli:guest:list",
        Method::GuestList(GuestListParams {
            machine: parsed.option("machine"),
        }),
    )
    .map_err(|err| err.to_string())
}

/// Revoke by guest id, falling back to an invite id.
fn revoke(args: &[String]) -> Result<i32, String> {
    let parsed = parse(args, &["machine"])?;
    let [id] = parsed.positional.as_slice() else {
        return Err("revoke takes exactly one id".into());
    };
    let request = |guest: bool| Request {
        id: "cli:guest:revoke".into(),
        method: Method::GuestRevoke(GuestRevokeParams {
            guest_id: guest.then(|| id.clone()),
            invite_id: (!guest).then(|| id.clone()),
            machine: parsed.option("machine"),
        }),
    };
    let response = super::send_request(&request(true)).map_err(|err| err.to_string())?;
    let response = if response["error"]["code"] == "guest_not_found" {
        super::send_request(&request(false)).map_err(|err| err.to_string())?
    } else {
        response
    };
    super::print_response(&response).map_err(|err| err.to_string())
}

fn log(args: &[String]) -> Result<i32, String> {
    let parsed = parse(args, &["limit", "machine"])?;
    let guest_id = match parsed.positional.as_slice() {
        [] => None,
        [id] => Some(id.clone()),
        _ => return Err("log takes at most one guest id".into()),
    };
    let limit = parsed
        .option("limit")
        .map(|limit| {
            limit
                .parse::<usize>()
                .map_err(|_| "--limit must be a number")
        })
        .transpose()?;
    send(
        "cli:guest:log",
        Method::GuestAudit(GuestAuditParams {
            guest_id,
            limit,
            before_ms: None,
            machine: parsed.option("machine"),
        }),
    )
    .map_err(|err| err.to_string())
}

fn default_machine_label() -> String {
    #[cfg(unix)]
    {
        let mut buffer = [0u8; 256];
        // SAFETY: the buffer is valid for its length; gethostname NUL-terminates
        // on success within it.
        let status = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
        if status == 0 {
            let end = buffer
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(buffer.len());
            if let Ok(name) = std::str::from_utf8(&buffer[..end]) {
                if !name.is_empty() {
                    return name.to_string();
                }
            }
        }
    }
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "Herdr".into())
}
