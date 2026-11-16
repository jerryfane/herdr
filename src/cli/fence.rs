//! `herdr fence explain`: how the pane fence treats a pane and one path in it
//! (docs/next/design/pane-fence.md, section 9).

use clap::{Arg, ArgAction, ArgMatches, Command};

use crate::api::schema::{FenceExplainParams, Method, Request};

use super::projection::{self, ParseError};

pub(crate) fn command() -> Command {
    Command::new("fence")
        .about("Inspect the pane fence")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommand(
            Command::new("explain")
                .about("Show whether a pane is fenced and why a path is read-only in it")
                .arg(
                    Arg::new("target")
                        .value_name("PANE_OR_AGENT")
                        .required(true)
                        .help("A pane id, or an agent name or label"),
                )
                .arg(
                    Arg::new("path")
                        .value_name("PATH")
                        .help("An absolute path, or one starting with ~/"),
                )
                .arg(
                    Arg::new("json")
                        .long("json")
                        .action(ArgAction::SetTrue)
                        .help("Print the API response as JSON"),
                ),
        )
}

fn request(matches: &ArgMatches) -> Result<Request, ParseError> {
    match matches.subcommand() {
        Some(("explain", matches)) => Ok(Request {
            id: "cli:fence:explain".into(),
            method: Method::FenceExplain(FenceExplainParams {
                target: matches
                    .get_one::<String>("target")
                    .cloned()
                    .unwrap_or_default(),
                path: matches.get_one::<String>("path").cloned(),
            }),
        }),
        _ => Err(ParseError::Usage("expected fence explain".into())),
    }
}

pub(super) fn run_fence_command(args: &[String]) -> std::io::Result<i32> {
    let json = args.iter().any(|arg| arg == "--json");
    let request = match projection::parse(command(), args, request) {
        Ok(request) => request,
        Err(ParseError::Clap(error)) => return super::print_clap_error(&error),
        Err(ParseError::Usage(message)) => {
            eprintln!("{message}");
            return Ok(2);
        }
        Err(ParseError::Io(error)) => return Err(error),
    };
    let response = super::send_request(&request)?;
    if json || response.get("error").is_some() {
        return super::print_response(&response);
    }
    print!("{}", explain_text(&response["result"]["explain"]));
    Ok(0)
}

fn explain_text(explain: &serde_json::Value) -> String {
    let yes_no = |value: &serde_json::Value| match value.as_bool() {
        Some(true) => "yes",
        Some(false) => "no",
        None => "unknown",
    };
    let mut out = String::new();
    let pane = explain["pane_id"].as_str().unwrap_or("?");
    match explain["agent"].as_str() {
        Some(agent) => out.push_str(&format!("pane {pane} (agent {agent})\n")),
        None => out.push_str(&format!("pane {pane}\n")),
    }
    out.push_str(&format!(
        "  fenced now:           {}\n",
        yes_no(&explain["running_fenced"])
    ));
    out.push_str(&format!(
        "  fenced after restart: {}",
        yes_no(&explain["config_fences"])
    ));
    if let Some(count) = explain["deny_count"].as_u64() {
        out.push_str(&format!(" ({count} read-only paths)"));
    }
    out.push('\n');
    if let Some(missing) = explain["missing"].as_array().filter(|m| !m.is_empty()) {
        out.push_str(&format!(
            "  not on this host:     {} entries\n",
            missing.len()
        ));
    }
    let path = &explain["path"];
    if path.is_object() {
        let shown = path["path"].as_str().unwrap_or("?");
        let resolved = path["resolved"].as_str().unwrap_or(shown);
        out.push_str(shown);
        if resolved != shown {
            out.push_str(&format!(" -> {resolved}"));
        }
        out.push('\n');
        let access = path["access"].as_str().unwrap_or("?").replace('_', "-");
        out.push_str(&format!(
            "  after restart:        {access} ({})\n",
            path["rule"].as_str().unwrap_or("?")
        ));
        if path["pinned"].as_bool() == Some(true) {
            out.push_str("  pinned:               cannot be deleted or renamed from the pane\n");
        }
        if let Some(read_only) = path["enforced_read_only"].as_bool() {
            out.push_str(&format!(
                "  now:                  {}\n",
                if read_only { "read-only" } else { "writable" }
            ));
        }
    }
    out
}
