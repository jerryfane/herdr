use crate::api::schema::{
    GramGrabParams, GramListParams, GramMarkReadParams, GramPostParams, GramSendParams, Method,
    Request,
};

/// `herdr gram` — the owner<->agent message channel used by the Herdr app.
///
/// Agents mainly use `send` (message the owner, push-notified), `list --queue`
/// (see unclaimed work the owner posted), and `grab <id>` (claim one). `post` and
/// `mark-read` are owner/testing conveniences. The caller's identity comes from
/// `HERDR_PANE_ID`, which every Herdr pane sets; it is sent as `caller_pane_id`
/// and resolved to the agent's label server-side.
pub(super) fn run_gram_command(args: &[String]) -> std::io::Result<i32> {
    let Some(subcommand) = args.first().map(|arg| arg.as_str()) else {
        print_gram_help();
        return Ok(2);
    };

    match subcommand {
        "send" => gram_send(&args[1..]),
        "post" => gram_post(&args[1..]),
        "list" => gram_list(&args[1..]),
        "grab" => gram_grab(&args[1..]),
        "mark-read" => gram_mark_read(&args[1..]),
        "help" | "--help" | "-h" => {
            print_gram_help();
            Ok(0)
        }
        _ => {
            print_gram_help();
            Ok(2)
        }
    }
}

fn env_pane_id() -> Option<String> {
    std::env::var("HERDR_PANE_ID")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| super::normalize_pane_id(&value))
}

fn gram_send(args: &[String]) -> std::io::Result<i32> {
    let (text, from) = match parse_send_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };

    super::print_response(&super::send_request(&Request {
        id: "cli:gram:send".into(),
        method: Method::GramSend(GramSendParams {
            text,
            caller_pane_id: env_pane_id(),
            from,
        }),
    })?)
}

fn gram_post(args: &[String]) -> std::io::Result<i32> {
    let (text, to) = match parse_post_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };

    super::print_response(&super::send_request(&Request {
        id: "cli:gram:post".into(),
        method: Method::GramPost(GramPostParams { text, to }),
    })?)
}

fn gram_list(args: &[String]) -> std::io::Result<i32> {
    let (only_queue, unread_only, owner) = match parse_list_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };

    // Default: attach this pane's id for the agent/pane view. `--owner` (and
    // `--unread`, which is an owner-only view) omit it so the server returns the
    // owner view — otherwise the owner view would be unreachable from any pane,
    // since HERDR_PANE_ID is set on every managed pane.
    let owner_view = owner || unread_only;
    let caller_pane_id = if owner_view { None } else { env_pane_id() };

    super::print_response(&super::send_request(&Request {
        id: "cli:gram:list".into(),
        method: Method::GramList(GramListParams {
            caller_pane_id,
            only_queue,
            unread_only,
        }),
    })?)
}

fn gram_grab(args: &[String]) -> std::io::Result<i32> {
    let (id, grabbed_by) = match parse_grab_args(args) {
        Ok(parsed) => parsed,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };

    super::print_response(&super::send_request(&Request {
        id: "cli:gram:grab".into(),
        method: Method::GramGrab(GramGrabParams {
            id,
            caller_pane_id: env_pane_id(),
            grabbed_by,
        }),
    })?)
}

fn gram_mark_read(args: &[String]) -> std::io::Result<i32> {
    let id = match parse_single_id(args, "mark-read") {
        Ok(id) => id,
        Err(message) => {
            eprintln!("{message}");
            return Ok(2);
        }
    };

    super::print_response(&super::send_request(&Request {
        id: "cli:gram:mark_read".into(),
        method: Method::GramMarkRead(GramMarkReadParams { id }),
    })?)
}

// MARK: - arg parsing (pure, unit-tested)

/// `send <text> [--from LABEL]` -> (text, from).
fn parse_send_args(args: &[String]) -> Result<(String, Option<String>), String> {
    let mut text: Option<String> = None;
    let mut from: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--from" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --from".into());
                };
                from = Some(value.clone());
                index += 2;
            }
            other if is_flag(other) => return Err(format!("unknown option: {other}")),
            other => {
                if text.is_some() {
                    return Err("unexpected extra argument; quote the message text".into());
                }
                text = Some(other.to_string());
                index += 1;
            }
        }
    }
    let text = text.ok_or("usage: herdr gram send <text> [--from LABEL]")?;
    Ok((text, from))
}

/// `post <text> [--to AGENT]` -> (text, to). `--to` addresses one agent; omit it
/// to post to the shared grab-queue.
fn parse_post_args(args: &[String]) -> Result<(String, Option<String>), String> {
    let mut text: Option<String> = None;
    let mut to: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--to" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --to".into());
                };
                to = Some(value.clone());
                index += 2;
            }
            other if is_flag(other) => return Err(format!("unknown option: {other}")),
            other => {
                if text.is_some() {
                    return Err("unexpected extra argument; quote the message text".into());
                }
                text = Some(other.to_string());
                index += 1;
            }
        }
    }
    let text = text.ok_or("usage: herdr gram post <text> [--to AGENT]")?;
    Ok((text, to))
}

/// `list [--queue] [--unread] [--owner]` -> (only_queue, unread_only, owner).
/// `--queue` (shared unclaimed work) and `--unread` (owner's unread inbox) are
/// mutually exclusive. `--owner` reads as the owner (omits the caller pane);
/// `--unread` implies it.
fn parse_list_args(args: &[String]) -> Result<(bool, bool, bool), String> {
    let mut only_queue = false;
    let mut unread_only = false;
    let mut owner = false;
    for arg in args {
        match arg.as_str() {
            "--queue" => only_queue = true,
            "--unread" => unread_only = true,
            "--owner" => owner = true,
            other => return Err(format!("unknown option: {other}")),
        }
    }
    if only_queue && unread_only {
        return Err("--queue and --unread cannot be combined".into());
    }
    Ok((only_queue, unread_only, owner))
}

/// `grab <id> [--as LABEL]` -> (id, grabbed_by).
fn parse_grab_args(args: &[String]) -> Result<(String, Option<String>), String> {
    let mut id: Option<String> = None;
    let mut grabbed_by: Option<String> = None;
    let mut index = 0;
    while index < args.len() {
        match args[index].as_str() {
            "--as" => {
                let Some(value) = args.get(index + 1) else {
                    return Err("missing value for --as".into());
                };
                grabbed_by = Some(value.clone());
                index += 2;
            }
            other if is_flag(other) => return Err(format!("unknown option: {other}")),
            other => {
                if id.is_some() {
                    return Err("unexpected extra argument".into());
                }
                id = Some(other.to_string());
                index += 1;
            }
        }
    }
    let id = id.ok_or("usage: herdr gram grab <id> [--as LABEL]")?;
    Ok((id, grabbed_by))
}

fn parse_single_id(args: &[String], subcommand: &str) -> Result<String, String> {
    match args {
        [id] if !is_flag(id) => Ok(id.clone()),
        _ => Err(format!("usage: herdr gram {subcommand} <id>")),
    }
}

fn is_flag(value: &str) -> bool {
    value.starts_with("--")
}

fn print_gram_help() {
    eprintln!("herdr gram commands:");
    eprintln!("  herdr gram send <text> [--from LABEL]   message the owner (push-notified)");
    eprintln!("  herdr gram list [--queue] [--unread] [--owner]   list messages (--owner: read as the owner)");
    eprintln!("  herdr gram grab <id> [--as LABEL]        claim a shared queue item");
    eprintln!("  herdr gram post <text> [--to AGENT]      owner: post to the queue or one agent");
    eprintln!("  herdr gram mark-read <id>                owner: mark an agent message read");
    eprintln!();
    eprintln!("--from/--as override the attribution label (default: your agent name).");
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn send_parses_text_and_from() {
        assert_eq!(
            parse_send_args(&args(&["digest ready", "--from", "trend-scout"])).unwrap(),
            ("digest ready".to_string(), Some("trend-scout".to_string()))
        );
        assert_eq!(
            parse_send_args(&args(&["hello"])).unwrap(),
            ("hello".to_string(), None)
        );
    }

    #[test]
    fn send_requires_text_and_rejects_extra() {
        assert!(parse_send_args(&args(&[])).is_err());
        assert!(parse_send_args(&args(&["a", "b"])).is_err());
        assert!(parse_send_args(&args(&["--from", "x"])).is_err());
    }

    #[test]
    fn post_parses_to() {
        assert_eq!(
            parse_post_args(&args(&["do this", "--to", "alpha"])).unwrap(),
            ("do this".to_string(), Some("alpha".to_string()))
        );
        assert_eq!(
            parse_post_args(&args(&["shared work"])).unwrap(),
            ("shared work".to_string(), None)
        );
    }

    #[test]
    fn list_flags_are_exclusive() {
        assert_eq!(
            parse_list_args(&args(&["--queue"])).unwrap(),
            (true, false, false)
        );
        assert_eq!(
            parse_list_args(&args(&["--unread"])).unwrap(),
            (false, true, false)
        );
        assert_eq!(
            parse_list_args(&args(&["--owner"])).unwrap(),
            (false, false, true)
        );
        assert_eq!(parse_list_args(&args(&[])).unwrap(), (false, false, false));
        assert!(parse_list_args(&args(&["--queue", "--unread"])).is_err());
        assert!(parse_list_args(&args(&["--nope"])).is_err());
    }

    #[test]
    fn grab_parses_id_and_as() {
        assert_eq!(
            parse_grab_args(&args(&["gram-1", "--as", "alpha"])).unwrap(),
            ("gram-1".to_string(), Some("alpha".to_string()))
        );
        assert!(parse_grab_args(&args(&[])).is_err());
    }

    #[test]
    fn mark_read_needs_one_id() {
        assert_eq!(
            parse_single_id(&args(&["gram-1"]), "mark-read").unwrap(),
            "gram-1".to_string()
        );
        assert!(parse_single_id(&args(&[]), "mark-read").is_err());
        assert!(parse_single_id(&args(&["--x"]), "mark-read").is_err());
    }
}
