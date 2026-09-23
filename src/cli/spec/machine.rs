use clap::{Arg, ArgAction, Command};

use super::{json_flag, option};

pub(super) fn command() -> Command {
    Command::new("machine")
        .about("Manage saved SSH machines")
        .subcommand(
            Command::new("list")
                .about("List saved SSH machines")
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("status")
                .about("Show saved, endpoint, and federation health separately")
                .arg(json_flag()),
        )
        .subcommand(
            Command::new("add")
                .about("Prepare the remote Herdr server and save an SSH machine")
                .arg(
                    Arg::new("ssh-target")
                        .value_name("SSH_TARGET")
                        .required(true),
                )
                .arg(
                    option("label", "LABEL")
                        .required(true)
                        .help("Set the machine label shown in the sidebar"),
                )
                .arg(
                    option("remote-session", "NAME")
                        .help("Set the explicit Herdr session on the remote machine"),
                ),
        )
        .subcommand(
            profile_command("rename", "Rename a saved SSH machine").arg(
                option("label", "LABEL")
                    .required(true)
                    .help("Set the machine label shown in the sidebar"),
            ),
        )
        .subcommand(
            profile_command("grant", "Grant a selected live remote agent reverse observe/interact on a trusted machine")
                .arg(Arg::new("agent-terminal-id").value_name("MACHINE/TERMINAL_ID").required(true))
                .arg(Arg::new("observe").long("observe").action(ArgAction::SetTrue))
                .arg(Arg::new("interact").long("interact").action(ArgAction::SetTrue))
                .arg(option("observe-peer", "ALIAS").action(ArgAction::Append))
                .arg(option("interact-peer", "ALIAS").action(ArgAction::Append))
                .after_help("Requires a pinned saved federation machine and explicit reverse_coordinator_machine_id on the remote. Same-user processes can spoof the granted pane identity; this is not per-process isolation."),
        )
        .subcommand(
            profile_command("revoke", "Revoke a selected remote agent's reverse access")
                .arg(Arg::new("agent-terminal-id").value_name("MACHINE/TERMINAL_ID").required(true)),
        )
        .subcommand(profile_command("remove", "Remove a saved SSH machine"))
        .subcommand(profile_command("enable", "Enable a saved SSH machine"))
        .subcommand(profile_command("disable", "Disable a saved SSH machine"))
}

fn profile_command(name: &'static str, about: &'static str) -> Command {
    Command::new(name).about(about).arg(
        Arg::new("profile-id")
            .value_name("PROFILE_ID")
            .required(true),
    )
}
