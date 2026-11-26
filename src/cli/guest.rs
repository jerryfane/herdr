use crate::api::schema::{
    GuestAuditParams, GuestInviteCreateParams, GuestListParams, GuestRemoveDeviceParams,
    GuestRevokeParams, GuestUpdateParams, Method, Request,
};

const HELP: &str = "Usage:
  herdr guest invite <agent> --name <name> [--owner-name NAME] [--machine-label LABEL] [--ttl SECS] [--share-gram] [--machine ALIAS]
  herdr guest list [--machine ALIAS]
  herdr guest share-gram <guest-id> on|off [--machine ALIAS]
  herdr guest relabel <label> [--guest ID | --invite ID] [--machine ALIAS]
  herdr guest revoke <guest-or-invite-id> [--machine ALIAS]
  herdr guest revoke --person <person> [--machine ALIAS]
  herdr guest remove-device <guest-id> <fingerprint> [--machine ALIAS]
  herdr guest log [<guest-id>] [--limit N] [--machine ALIAS]

Share one named, running agent with one outside person through the HerdrUp
guest relay. The guest can prompt it (labeled \"<name> (via HerdrUp): \") and
watch its terminal, but cannot type into the terminal or reach any other pane.
With --share-gram (or share-gram on later) the guest also sees every Gram the
agent sends from the moment the guest accepted, with its files. Invites work
once and expire after 24 hours by default. A guest may bind the share to their
HerdrUp account to use it from each of their devices ([guest] accounts):
revoke --person (the person from guest list) revokes all of a person's shares
at once, and remove-device drops one of their devices. relabel renames this
machine for every existing guest and pending invite (or the one given); guests
see the new label when they next connect, and a pending invite keeps showing
the old name until it is accepted. --machine runs the
command on that saved SSH machine.";

/// Options that take no value.
const FLAGS: &[&str] = &["share-gram"];

pub(super) fn run_guest_command(args: &[String]) -> std::io::Result<i32> {
    let result = match args.first().map(String::as_str) {
        Some("invite") => invite(&args[1..]),
        Some("list") => list(&args[1..]),
        Some("share-gram") => share_gram(&args[1..]),
        Some("relabel") => relabel(&args[1..]),
        Some("revoke") => revoke(&args[1..]),
        Some("remove-device") => remove_device(&args[1..]),
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
pub(super) struct Parsed {
    pub(super) positional: Vec<String>,
    options: Vec<(String, String)>,
}

impl Parsed {
    pub(super) fn option(&self, name: &str) -> Option<String> {
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

pub(super) fn parse(args: &[String], known: &[&str]) -> Result<Parsed, String> {
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

pub(super) fn send(id: &str, method: Method) -> std::io::Result<i32> {
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
            machine_label_rev: None,
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
            guest_id: Some(guest_id.clone()),
            share_gram: Some(share_gram),
            machine: parsed.option("machine"),
            ..Default::default()
        }),
    )
    .map_err(|err| err.to_string())
}

/// Set the machine label existing guests and pending invites show.
fn relabel(args: &[String]) -> Result<i32, String> {
    send(
        "cli:guest:relabel",
        Method::GuestUpdate(relabel_params(args)?),
    )
    .map_err(|err| err.to_string())
}

fn relabel_params(args: &[String]) -> Result<GuestUpdateParams, String> {
    let parsed = parse(args, &["guest", "invite", "machine"])?;
    let [label] = parsed.positional.as_slice() else {
        return Err("relabel takes exactly one label".into());
    };
    let guest_id = parsed.option("guest");
    let invite_id = parsed.option("invite");
    if guest_id.is_some() && invite_id.is_some() {
        return Err("relabel takes --guest or --invite, not both".into());
    }
    Ok(GuestUpdateParams {
        guest_id,
        invite_id,
        machine_label: Some(label.clone()),
        machine_label_rev: Some(crate::guest::store::now_ms()),
        machine: parsed.option("machine"),
        ..Default::default()
    })
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

/// Revoke by guest id, falling back to an invite id; or every share of one
/// person with `--person`.
fn revoke(args: &[String]) -> Result<i32, String> {
    let parsed = parse(args, &["machine", "person"])?;
    if let Some(person) = parsed.option("person") {
        if !parsed.positional.is_empty() {
            return Err("revoke takes an id or --person, not both".into());
        }
        return send(
            "cli:guest:revoke",
            Method::GuestRevoke(GuestRevokeParams {
                person: Some(person),
                machine: parsed.option("machine"),
                ..Default::default()
            }),
        )
        .map_err(|err| err.to_string());
    }
    let [id] = parsed.positional.as_slice() else {
        return Err("revoke takes exactly one id".into());
    };
    let request = |guest: bool| Request {
        id: "cli:guest:revoke".into(),
        method: Method::GuestRevoke(GuestRevokeParams {
            guest_id: guest.then(|| id.clone()),
            invite_id: (!guest).then(|| id.clone()),
            person: None,
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

/// Drop one device from an account-bound share.
fn remove_device(args: &[String]) -> Result<i32, String> {
    let parsed = parse(args, &["machine"])?;
    let [guest_id, fingerprint] = parsed.positional.as_slice() else {
        return Err("remove-device takes a guest id and a device fingerprint".into());
    };
    send(
        "cli:guest:remove-device",
        Method::GuestRemoveDevice(GuestRemoveDeviceParams {
            guest_id: guest_id.clone(),
            fingerprint: fingerprint.clone(),
            machine: parsed.option("machine"),
        }),
    )
    .map_err(|err| err.to_string())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<String> {
        list.iter().map(|arg| (*arg).to_string()).collect()
    }

    #[test]
    fn relabel_builds_a_scoped_or_host_wide_update() {
        let all = relabel_params(&args(&["Jerry's Mac"])).unwrap();
        assert_eq!(all.machine_label.as_deref(), Some("Jerry's Mac"));
        assert!(all.machine_label_rev.is_some_and(|rev| rev > 0));
        assert_eq!(
            (all.guest_id, all.invite_id, all.share_gram),
            (None, None, None)
        );
        let one = relabel_params(&args(&["Mac", "--guest", "g1"])).unwrap();
        assert_eq!(one.guest_id.as_deref(), Some("g1"));
        let invite =
            relabel_params(&args(&["Mac", "--invite", "i1", "--machine", "studio"])).unwrap();
        assert_eq!(invite.invite_id.as_deref(), Some("i1"));
        assert_eq!(invite.machine.as_deref(), Some("studio"));
        assert!(relabel_params(&args(&["Mac", "--guest", "g", "--invite", "i"])).is_err());
        assert!(relabel_params(&args(&[])).is_err());
        assert!(relabel_params(&args(&["a", "b"])).is_err());
    }
}
