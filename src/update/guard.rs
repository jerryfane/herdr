//! `herdr server update-guard --attempt <id> --lock-fd <fd>`: carries out one
//! in-app update after `server.update_apply` has answered. It holds the
//! attempt lock it inherited as `<fd>` until the outcome is recorded.
//!
//! It runs from `updates/previous/herdr`, a copy of the build that was serving,
//! as an API client of the local socket, in its own session. In order it
//! downloads and verifies the build, runs its `--version`, records what the
//! server serves now, asks the server for one live handoff to the new build,
//! and watches the result for up to 180 s. Only a build that passes every
//! check is installed on disk. A build that fails gets exactly one live
//! handoff back to the previous build, which must then pass the same checks.
//! The guard never kills or restarts a server: whatever it can't confirm ends
//! as `needs_attention`, with what to inspect.
//!
//! `restart_later` stops after the smoke test and installs the build on disk
//! right away. The running server keeps its own inode, so it is untouched and
//! the next restart runs the new build.

use std::collections::BTreeSet;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::api::client::{ApiClient, ConnectionTarget};
use crate::api::schema::{
    EmptyParams, GuestListParams, Method, PingParams, Request, ServerLiveHandoffParams,
    UpdateOutcome, UpdatePhase,
};

use super::apply::{MANIFEST_FILE, SIGNATURE_FILE};
use super::state::{
    process_alive, AttemptLock, AttemptRecord, UpdateDirs, BINARY_NAME, PREVIOUS_DIR,
};
use super::verify;

const SMOKE_TEST_TIMEOUT: Duration = Duration::from_secs(10);
const OBSERVE_TOTAL: Duration = Duration::from_secs(180);
const OBSERVE_IDENTIFY: Duration = Duration::from_secs(30);
const OBSERVE_RELAY: Duration = Duration::from_secs(60);
const OBSERVE_ROUTES: Duration = Duration::from_secs(90);
const CALL_TIMEOUT: Duration = Duration::from_secs(20);
const BRIDGE_TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(500);
const ROLLBACK_MARKER: &str = "rollback-started";
const BEFORE_FILE: &str = "before.json";

/// Debug builds only: make the guard's checks fail on purpose, so tests can
/// drive the rollback paths with real servers. `forward_checks` fails the
/// checks of the new build; `rollback_handoff` also makes the handoff back
/// ask for a protocol no server speaks, so it is refused.
#[cfg(debug_assertions)]
const TEST_FAULT_ENV: &str = "HERDR_UPDATE_TEST_GUARD_FAULT";

pub(crate) fn run(args: &[String]) -> io::Result<i32> {
    let (attempt_id, lock_fd) = match args {
        [attempt_flag, id, fd_flag, fd]
            if attempt_flag == "--attempt" && !id.is_empty() && fd_flag == "--lock-fd" =>
        {
            match fd.parse::<std::os::fd::RawFd>() {
                Ok(fd) if fd >= 0 => (id.clone(), fd),
                _ => return Ok(usage()),
            }
        }
        _ => return Ok(usage()),
    };
    let dirs = UpdateDirs::current();
    // Held until this process exits, so the lock outlives the outcome write.
    let _lock = match AttemptLock::inherited(&dirs, lock_fd) {
        Ok(lock) => lock,
        Err(err) => {
            eprintln!("update attempt {attempt_id}: no update lock: {err}");
            return Ok(2);
        }
    };
    let Some(record) = dirs
        .load()
        .attempt
        .filter(|record| record.public.attempt_id == attempt_id)
    else {
        eprintln!("update attempt {attempt_id} is not the current attempt");
        return Ok(2);
    };
    let mut guard = Guard { dirs, record };
    let (outcome, message) = guard.carry_out();
    guard.finish(outcome, message);
    Ok(0)
}

fn usage() -> i32 {
    eprintln!("usage: herdr server update-guard --attempt <id> --lock-fd <fd>");
    2
}

struct Guard {
    dirs: UpdateDirs,
    record: AttemptRecord,
}

impl Guard {
    fn build_dir(&self) -> PathBuf {
        self.dirs.build_dir(&self.record.public.build_id)
    }

    fn new_exe(&self) -> PathBuf {
        self.build_dir().join(BINARY_NAME)
    }

    fn say(&mut self, line: impl Into<String>) {
        let line: String = line.into();
        let stamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        if let Ok(mut file) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dirs.guard_log())
        {
            let _ = writeln!(file, "{stamp} {} {line}", self.record.public.attempt_id);
        }
    }

    /// Record progress. A failed write is logged, never fatal: the switch
    /// must not stop because the status file could not be written.
    fn save(&mut self, change: impl FnOnce(&mut AttemptRecord)) {
        change(&mut self.record);
        let record = self.record.clone();
        if let Err(err) = self.dirs.update(|state| state.attempt = Some(record)) {
            self.say(format!("can't write the state file: {err}"));
        }
    }

    fn phase(&mut self, phase: UpdatePhase) {
        self.say(format!("phase {phase:?}"));
        self.save(|record| record.public.phase = phase);
    }

    fn carry_out(&mut self) -> (UpdateOutcome, String) {
        match self.prepare() {
            Ok(prepared) => {
                if self.record.public.restart_later {
                    return self.install_for_restart();
                }
                self.switch(prepared)
            }
            Err(err) => {
                self.say(format!("stopped before the switch: {err}"));
                (UpdateOutcome::FailedNoChange, err)
            }
        }
    }

    /// Download, verify and smoke-test the build. Nothing has changed yet.
    fn prepare(&mut self) -> Result<Prepared, String> {
        let build_dir = self.build_dir();
        let bytes = std::fs::read(build_dir.join(MANIFEST_FILE))
            .map_err(|err| format!("can't read the saved manifest: {err}"))?;
        let minisig = std::fs::read_to_string(build_dir.join(SIGNATURE_FILE))
            .map_err(|err| format!("can't read the saved signature: {err}"))?;
        let manifest = verify::verify_trusted(&bytes, &minisig).map_err(|err| err.to_string())?;
        if manifest.build_id != self.record.public.build_id {
            return Err("the saved manifest names a different build".into());
        }
        let asset = verify::platform_asset(&manifest)
            .map_err(|err| err.to_string())?
            .ok_or("the manifest publishes no binary for this platform")?;

        let part = build_dir.join(format!("{BINARY_NAME}.part"));
        let _ = std::fs::remove_file(&part);
        let mut reported = 0;
        super::fetch_asset(&asset.url, asset.size, &part, |done| {
            if done != reported {
                reported = done;
                self.save(|record| record.public.bytes_done = done);
            }
        })?;
        self.phase(UpdatePhase::Verifying);
        super::check_asset(&part, asset.size, &asset.sha256)?;
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&part, std::fs::Permissions::from_mode(0o755))
                .map_err(|err| format!("can't mark the download executable: {err}"))?;
        }
        let new_exe = self.new_exe();
        std::fs::rename(&part, &new_exe)
            .map_err(|err| format!("can't move the download into place: {err}"))?;

        self.phase(UpdatePhase::Testing);
        let version = smoke_test(&new_exe, &manifest.commit)?;
        self.say(format!("smoke test passed: {version}"));
        Ok(Prepared {
            version,
            protocol: manifest.protocol,
            sha256: asset.sha256,
        })
    }

    fn install_for_restart(&mut self) -> (UpdateOutcome, String) {
        self.phase(UpdatePhase::Installing);
        let new_exe = self.new_exe();
        let install = self.record.install_path.clone();
        match install_verified(&new_exe, &install) {
            Ok(()) => (
                UpdateOutcome::DownloadedRestartRequired,
                format!(
                    "{} is installed at {}; it takes over when herdr restarts",
                    self.record.public.to,
                    install.display()
                ),
            ),
            Err(err) => (
                UpdateOutcome::FailedNoChange,
                format!("can't install {}: {err}", install.display()),
            ),
        }
    }

    fn switch(&mut self, prepared: Prepared) -> (UpdateOutcome, String) {
        let client =
            ApiClient::for_target(ConnectionTarget::SocketPath(self.record.socket.clone()));
        let before = match snapshot(&client, &self.record.socket) {
            Ok(before) => before,
            Err(err) => {
                return (
                    UpdateOutcome::FailedNoChange,
                    format!("can't record the server's state before the switch: {err}"),
                )
            }
        };
        if let Ok(json) = serde_json::to_vec_pretty(&before) {
            let _ = std::fs::write(self.build_dir().join(BEFORE_FILE), json);
        }
        let panes = before.panes.len();
        self.save(|record| record.public.panes = Some(panes));
        self.say(format!(
            "before: pid {}, {panes} panes, relay {}, {} healthy routes",
            before.old_pid,
            if before.relay_up { "up" } else { "not up" },
            before.healthy_routes.len()
        ));

        let mut live = LiveSwitch {
            guard: self,
            client,
            before,
            prepared,
            new_pid: None,
        };
        let decision = decide(&mut live);
        // Leave everything in place for whoever inspects an unconfirmed state.
        if decision.0 != UpdateOutcome::NeedsAttention {
            let new_serves = live.new_pid.is_some()
                && matches!(
                    decision.0,
                    UpdateOutcome::Updated | UpdateOutcome::UpdatedDiskStale
                );
            let old_exe_dir = live
                .guard
                .record
                .running_exe
                .parent()
                .map(Path::to_path_buf);
            live.guard.cleanup(new_serves, old_exe_dir.as_deref());
        }
        decision
    }

    /// Keep the build that serves and the rollback copy; remove the rest.
    fn cleanup(&mut self, new_serves: bool, old_exe_dir: Option<&Path>) {
        let Ok(entries) = std::fs::read_dir(self.dirs.root()) else {
            return;
        };
        let this_build = self.build_dir();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.is_dir() || path.file_name().is_some_and(|name| name == PREVIOUS_DIR) {
                continue;
            }
            let keep = if path == this_build {
                new_serves
            } else {
                !new_serves && old_exe_dir.is_some_and(|dir| dir == path)
            };
            if !keep {
                if let Err(err) = std::fs::remove_dir_all(&path) {
                    self.say(format!("can't remove {}: {err}", path.display()));
                }
            }
        }
    }

    fn finish(&mut self, outcome: UpdateOutcome, message: String) {
        self.say(format!("outcome {outcome:?}: {message}"));
        if outcome == UpdateOutcome::RolledBack {
            let build_id = self.record.public.build_id.clone();
            if let Err(err) = self.dirs.update(|state| {
                if !state.has_rolled_back(&build_id) {
                    state.rolled_back.push(build_id.clone());
                }
            }) {
                self.say(format!("can't record the rollback: {err}"));
            }
        }
        self.save(|record| {
            record.public.outcome = Some(outcome);
            record.public.message = Some(message);
        });
    }
}

struct Prepared {
    /// The `<v>` the new build printed; the handoff's `expected_version`.
    version: String,
    protocol: u32,
    sha256: String,
}

/// Copy `source` over `install` (copy beside it, then rename) and check the
/// installed file's hash.
fn install_verified(source: &Path, install: &Path) -> io::Result<()> {
    crate::persist::staged_build::activate_on_disk(source, install)?;
    let want = crate::checksum::file_sha256(source)?;
    let got = crate::checksum::file_sha256(install)?;
    if want != got {
        return Err(io::Error::other(format!(
            "the installed file's sha256 is {got}, not {want}"
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Smoke test
// ---------------------------------------------------------------------------

/// Run `<exe> --version` and return the version it reports.
fn smoke_test(exe: &Path, manifest_commit: &str) -> Result<String, String> {
    let mut child = std::process::Command::new(exe)
        .arg("--version")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|err| format!("the new build does not start: {err}"))?;
    let deadline = Instant::now() + SMOKE_TEST_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "the new build's --version did not finish within {}s",
                    SMOKE_TEST_TIMEOUT.as_secs()
                ));
            }
            Err(err) => return Err(format!("can't wait for the new build: {err}")),
        }
    };
    let mut output = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut output);
    }
    if !status.success() {
        return Err(format!("the new build's --version exited with {status}"));
    }
    parse_version_line(&output, manifest_commit)
}

/// `herdr <v> (<c>)`, where `c` is a prefix of the manifest's commit.
fn parse_version_line(output: &str, manifest_commit: &str) -> Result<String, String> {
    let line = output.trim();
    let refuse = || format!("the new build reports `{line}`, not `herdr <version> (<commit>)`");
    let rest = line.strip_prefix("herdr ").ok_or_else(refuse)?;
    let (version, commit) = rest.split_once(" (").ok_or_else(refuse)?;
    let commit = commit.strip_suffix(')').ok_or_else(refuse)?;
    if version.is_empty() || version.contains(char::is_whitespace) || commit.len() < 7 {
        return Err(refuse());
    }
    if !commit.bytes().all(|byte| byte.is_ascii_hexdigit()) || !manifest_commit.starts_with(commit)
    {
        return Err(format!(
            "the new build is commit {commit}, but the manifest is {manifest_commit}"
        ));
    }
    Ok(version.to_string())
}

// ---------------------------------------------------------------------------
// The switch and its decision table
// ---------------------------------------------------------------------------

/// How a `server.live_handoff` request ended.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Handoff {
    Committed,
    /// The server answered with an error: it refused or rolled back before
    /// commit and still serves.
    Refused(String),
    /// No answer: the result is only known by looking.
    Unknown(String),
}

/// What observing the server after a switch found.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Observed {
    /// The expected build serves and passed every check.
    Passed,
    /// The build that served before the switch still serves.
    OldStillServing,
    /// A check failed. `switched` says whether the new build was identified
    /// as the server, so a handoff back can reach it.
    Failed { reason: String, switched: bool },
}

/// The side effects the decision table drives. The real implementation talks
/// to the server; tests substitute recorded answers.
trait Switch {
    fn phase(&mut self, phase: UpdatePhase);
    fn handoff_forward(&mut self) -> Handoff;
    fn observe_forward(&mut self) -> Observed;
    /// After a forward handoff the server refused: confirm it is unchanged.
    fn confirm_unchanged(&mut self) -> Result<(), String>;
    /// Take the one-time rollback marker; false if it already exists.
    fn mark_rollback(&mut self) -> bool;
    fn handoff_back(&mut self) -> Handoff;
    fn observe_back(&mut self) -> Result<(), String>;
    fn install(&mut self) -> Result<(), String>;
}

fn decide(switch: &mut impl Switch) -> (UpdateOutcome, String) {
    switch.phase(UpdatePhase::Switching);
    let forward = switch.handoff_forward();
    if let Handoff::Refused(reason) = &forward {
        return match switch.confirm_unchanged() {
            Ok(()) => (
                UpdateOutcome::FailedNoChange,
                format!("the server refused the switch: {reason}"),
            ),
            Err(check) => (
                UpdateOutcome::NeedsAttention,
                format!("the server refused the switch ({reason}), then failed a check: {check}"),
            ),
        };
    }

    switch.phase(UpdatePhase::Confirming);
    let reason = match switch.observe_forward() {
        Observed::Passed => {
            switch.phase(UpdatePhase::Installing);
            return match switch.install() {
                Ok(()) => (UpdateOutcome::Updated, "updated and installed".into()),
                Err(err) => (
                    UpdateOutcome::UpdatedDiskStale,
                    format!("the new build serves, but installing it on disk failed: {err}"),
                ),
            };
        }
        Observed::OldStillServing => {
            let cause = match &forward {
                Handoff::Unknown(err) => format!("the switch did not take effect ({err})"),
                _ => "the switch did not take effect".to_string(),
            };
            return match switch.confirm_unchanged() {
                Ok(()) => (UpdateOutcome::FailedNoChange, cause),
                Err(check) => (
                    UpdateOutcome::NeedsAttention,
                    format!("{cause}, and the previous build then failed a check: {check}"),
                ),
            };
        }
        Observed::Failed {
            reason,
            switched: false,
        } => {
            return (
                UpdateOutcome::NeedsAttention,
                format!("no server could be confirmed after the switch: {reason}"),
            )
        }
        Observed::Failed { reason, .. } => reason,
    };

    if !switch.mark_rollback() {
        return (
            UpdateOutcome::NeedsAttention,
            format!("the new build failed a check ({reason}), and a rollback was already tried"),
        );
    }
    let back = switch.handoff_back();
    match switch.observe_back() {
        Ok(()) => (
            UpdateOutcome::RolledBack,
            format!("the new build failed a check ({reason}); the previous build serves again"),
        ),
        Err(check) => (
            UpdateOutcome::NeedsAttention,
            format!(
                "the new build failed a check ({reason}); the handoff back ({}) could not be \
                 confirmed: {check}",
                match back {
                    Handoff::Committed => "committed".to_string(),
                    Handoff::Refused(err) => format!("refused: {err}"),
                    Handoff::Unknown(err) => format!("no answer: {err}"),
                }
            ),
        ),
    }
}

/// What the server served before the switch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct Before {
    old_pid: u32,
    panes: BTreeSet<String>,
    guests: serde_json::Value,
    relay_up: bool,
    healthy_routes: BTreeSet<String>,
}

fn snapshot(client: &ApiClient, socket: &Path) -> Result<Before, String> {
    Ok(Before {
        old_pid: serving_pid(socket).ok_or("can't identify the serving process")?,
        panes: panes(client)?,
        guests: guests(client)?,
        relay_up: relay_up(client)?,
        healthy_routes: healthy_routes(client)?,
    })
}

/// The build a set of checks expects to find serving.
struct Expect<'a> {
    sha256: &'a str,
    version: &'a str,
    protocol: u32,
    /// The pid that served before this handoff; it must be gone.
    replaced_pid: u32,
    /// The binary whose `api-bridge --multi` makes the round trip.
    bridge_exe: &'a Path,
}

struct LiveSwitch<'g> {
    guard: &'g mut Guard,
    client: ApiClient,
    before: Before,
    prepared: Prepared,
    new_pid: Option<u32>,
}

impl LiveSwitch<'_> {
    fn handoff(&mut self, import_exe: &Path, version: &str, protocol: u32) -> Handoff {
        let request = Request {
            id: "update-guard:live-handoff".into(),
            method: Method::ServerLiveHandoff(ServerLiveHandoffParams {
                import_exe: Some(import_exe.display().to_string()),
                expected_protocol: Some(protocol),
                expected_version: Some(version.to_string()),
            }),
        };
        let result = match self
            .client
            .request_value_with_timeout(&request, super::SERVER_HANDOFF_REQUEST_TIMEOUT)
        {
            Ok(value) if value.get("result").is_some() => Handoff::Committed,
            Ok(value) => Handoff::Refused(
                value["error"]["message"]
                    .as_str()
                    .or_else(|| value["error"]["code"].as_str())
                    .unwrap_or("unknown error")
                    .to_string(),
            ),
            Err(err) => Handoff::Unknown(err.to_string()),
        };
        self.guard.say(format!(
            "live handoff to {} ({version}, protocol {protocol}): {result:?}",
            import_exe.display()
        ));
        result
    }

    fn previous_version(&self) -> String {
        self.guard.record.public.from.clone()
    }
}

impl Switch for LiveSwitch<'_> {
    fn phase(&mut self, phase: UpdatePhase) {
        self.guard.phase(phase);
    }

    fn handoff_forward(&mut self) -> Handoff {
        let new_exe = self.guard.new_exe();
        let version = self.prepared.version.clone();
        let protocol = self.prepared.protocol;
        self.handoff(&new_exe, &version, protocol)
    }

    fn observe_forward(&mut self) -> Observed {
        let socket = self.guard.record.socket.clone();
        let new_exe = self.guard.new_exe();
        let expect = Expect {
            sha256: &self.prepared.sha256,
            version: &self.prepared.version,
            protocol: self.prepared.protocol,
            replaced_pid: self.before.old_pid,
            bridge_exe: &new_exe,
        };
        let started = Instant::now();
        let pid = match identify(&socket, &expect, started + OBSERVE_IDENTIFY) {
            Ok(pid) => pid,
            Err(reason) => {
                let old = self.before.old_pid;
                if serving_pid(&socket) == Some(old) && process_alive(old) {
                    return Observed::OldStillServing;
                }
                return Observed::Failed {
                    reason,
                    switched: false,
                };
            }
        };
        self.new_pid = Some(pid);
        self.guard
            .say(format!("new server pid {pid} serves the new build"));
        let result = check_serving(&self.client, &socket, &expect, pid, &self.before, started)
            .and_then(|()| test_fault(Fault::ForwardChecks));
        match result {
            Ok(()) => Observed::Passed,
            Err(reason) => {
                self.guard.say(format!("check failed: {reason}"));
                Observed::Failed {
                    reason,
                    switched: true,
                }
            }
        }
    }

    fn confirm_unchanged(&mut self) -> Result<(), String> {
        let socket = self.guard.record.socket.clone();
        let old = self.before.old_pid;
        let previous = self.guard.dirs.previous_exe();
        let version = self.previous_version();
        let sha256 = self.guard.record.previous_sha256.clone();
        let expect = Expect {
            sha256: &sha256,
            version: &version,
            protocol: crate::protocol::PROTOCOL_VERSION,
            replaced_pid: 0,
            bridge_exe: &previous,
        };
        if serving_pid(&socket) != Some(old) || !process_alive(old) {
            return Err(format!("pid {old} no longer serves"));
        }
        check_serving(
            &self.client,
            &socket,
            &expect,
            old,
            &self.before,
            Instant::now(),
        )
    }

    fn mark_rollback(&mut self) -> bool {
        let marker = self.guard.build_dir().join(ROLLBACK_MARKER);
        let taken = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&marker)
            .and_then(|mut file| writeln!(file, "{}", self.guard.record.public.attempt_id))
            .is_ok();
        self.guard.say(if taken {
            "rollback-started marker written; one handoff back".to_string()
        } else {
            "rollback-started marker exists; no second handoff".to_string()
        });
        taken
    }

    fn handoff_back(&mut self) -> Handoff {
        let previous = self.guard.dirs.previous_exe();
        let version = self.previous_version();
        let protocol = match test_fault(Fault::RollbackHandoff) {
            Ok(()) => crate::protocol::PROTOCOL_VERSION,
            Err(_) => u32::MAX,
        };
        self.handoff(&previous, &version, protocol)
    }

    fn observe_back(&mut self) -> Result<(), String> {
        let socket = self.guard.record.socket.clone();
        let previous = self.guard.dirs.previous_exe();
        let version = self.previous_version();
        let sha256 = self.guard.record.previous_sha256.clone();
        let replaced = self.new_pid.unwrap_or(self.before.old_pid);
        let expect = Expect {
            sha256: &sha256,
            version: &version,
            protocol: crate::protocol::PROTOCOL_VERSION,
            replaced_pid: replaced,
            bridge_exe: &previous,
        };
        let started = Instant::now();
        let pid = identify(&socket, &expect, started + OBSERVE_IDENTIFY)?;
        self.guard
            .say(format!("pid {pid} serves the previous build again"));
        check_serving(&self.client, &socket, &expect, pid, &self.before, started)
    }

    fn install(&mut self) -> Result<(), String> {
        let new_exe = self.guard.new_exe();
        let install = self.guard.record.install_path.clone();
        install_verified(&new_exe, &install)
            .map_err(|err| format!("{}: {err}", install.display()))?;
        self.guard.say(format!(
            "installed {} at {}",
            new_exe.display(),
            install.display()
        ));
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Checks
// ---------------------------------------------------------------------------

/// Wait until the socket's server is a new process running the expected
/// binary and the process it replaced is gone.
fn identify(socket: &Path, expect: &Expect<'_>, deadline: Instant) -> Result<u32, String> {
    let mut last = String::from("no server answered");
    loop {
        match serving_pid(socket) {
            Some(pid) if pid == expect.replaced_pid => {
                last = format!("pid {pid}, the server before the handoff, still serves");
            }
            Some(pid) => match process_image_sha256(pid) {
                Ok(sha) if sha != expect.sha256 => {
                    last = format!(
                        "pid {pid} runs a binary with sha256 {sha}, not {}",
                        expect.sha256
                    );
                }
                Ok(_) if expect.replaced_pid != 0 && process_alive(expect.replaced_pid) => {
                    last = format!("pid {} has not exited", expect.replaced_pid);
                }
                Ok(_) => return Ok(pid),
                Err(err) => last = format!("can't hash pid {pid}'s binary: {err}"),
            },
            None => {}
        }
        if Instant::now() >= deadline {
            return Err(last);
        }
        std::thread::sleep(POLL);
    }
}

/// Every check after identification, against the `before` snapshot.
fn check_serving(
    client: &ApiClient,
    socket: &Path,
    expect: &Expect<'_>,
    pid: u32,
    before: &Before,
    started: Instant,
) -> Result<(), String> {
    let total = started + OBSERVE_TOTAL;
    let pong = call(client, Method::Ping(PingParams::default()))?;
    if pong["version"].as_str() != Some(expect.version)
        || pong["protocol"].as_u64() != Some(u64::from(expect.protocol))
    {
        return Err(format!(
            "ping reports {} protocol {}, not {} protocol {}",
            pong["version"], pong["protocol"], expect.version, expect.protocol
        ));
    }
    if before.relay_up {
        wait_until(started + OBSERVE_RELAY, || match relay_up(client) {
            Ok(true) => Ok(()),
            Ok(false) => Err("the gram relay is not up again".into()),
            Err(err) => Err(err),
        })?;
    }
    wait_until(started + OBSERVE_ROUTES, || {
        let now = healthy_routes(client)?;
        let lost: Vec<_> = before.healthy_routes.difference(&now).collect();
        if lost.is_empty() {
            Ok(())
        } else {
            Err(format!("routes no longer healthy: {lost:?}"))
        }
    })?;
    let now = panes(client)?;
    let missing: Vec<_> = before.panes.difference(&now).collect();
    if !missing.is_empty() {
        return Err(format!("panes missing after the switch: {missing:?}"));
    }
    if guests(client)? != before.guests {
        return Err("guest grants changed".into());
    }
    bridge_round_trip(expect.bridge_exe, socket)?;
    if serving_pid(socket) != Some(pid) {
        return Err(format!("pid {pid} stopped serving during the checks"));
    }
    if Instant::now() > total {
        return Err(format!(
            "the checks took longer than {}s",
            OBSERVE_TOTAL.as_secs()
        ));
    }
    Ok(())
}

fn wait_until(
    deadline: Instant,
    mut check: impl FnMut() -> Result<(), String>,
) -> Result<(), String> {
    loop {
        let result = check();
        if result.is_ok() || Instant::now() >= deadline {
            return result;
        }
        std::thread::sleep(POLL);
    }
}

fn call(client: &ApiClient, method: Method) -> Result<serde_json::Value, String> {
    let request = Request {
        id: "update-guard".into(),
        method,
    };
    let value = client
        .request_value_with_timeout(&request, CALL_TIMEOUT)
        .map_err(|err| err.to_string())?;
    if let Some(error) = value.get("error") {
        return Err(error.to_string());
    }
    Ok(value["result"].clone())
}

fn panes(client: &ApiClient) -> Result<BTreeSet<String>, String> {
    let result = call(client, Method::SessionSnapshot(EmptyParams::default()))?;
    Ok(result["snapshot"]["panes"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|pane| pane["pane_id"].as_str().map(str::to_string))
        .collect())
}

/// The grants, invites and revocations, without timestamps that move on
/// their own (`last_seen_ms`).
fn guests(client: &ApiClient) -> Result<serde_json::Value, String> {
    let result = call(client, Method::GuestList(GuestListParams::default()))?;
    let guests: Vec<_> = result["guests"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|guest| {
            serde_json::json!({
                "guest_id": guest["guest_id"],
                "grant": guest["grant"]["terminal_id"],
                "revoked": guest["revoked"],
                "share_gram": guest["share_gram"],
            })
        })
        .collect();
    let invites: Vec<_> = result["invites"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|invite| {
            serde_json::json!({
                "invite_id": invite["invite_id"],
                "grant": invite["grant"]["terminal_id"],
                "used_by": invite["used_by"],
            })
        })
        .collect();
    Ok(serde_json::json!({"guests": guests, "invites": invites}))
}

/// The relay is up when it has peers and every gateway is up.
fn relay_up(client: &ApiClient) -> Result<bool, String> {
    let result = call(client, Method::GramRelayStatus(EmptyParams::default()))?;
    let peers = result["coordinator"]["peers"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    Ok(!peers.is_empty()
        && peers
            .iter()
            .all(|peer| peer["gateway"]["state"].as_str() == Some("up")))
}

fn healthy_routes(client: &ApiClient) -> Result<BTreeSet<String>, String> {
    let result = call(client, Method::MachineStatus(EmptyParams::default()))?;
    Ok(result["machines"]
        .as_object()
        .into_iter()
        .flatten()
        .filter(|(_, machine)| {
            machine["saved_state"].as_str() == Some("coordinated")
                && machine["federation_reachability"].as_str() == Some("reachable")
                && !machine["stale"].as_bool().unwrap_or(false)
        })
        .map(|(id, _)| id.clone())
        .collect())
}

/// One `api-bridge --multi` session with two requests, as the app's SSH
/// route uses it, pointed at `socket` whatever session the server was
/// started with.
fn bridge_round_trip(exe: &Path, socket: &Path) -> Result<(), String> {
    let mut child = std::process::Command::new(exe)
        .args(["api-bridge", "--multi"])
        .env(crate::api::SOCKET_PATH_ENV_VAR, socket)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|err| format!("api-bridge --multi does not start: {err}"))?;
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(
            b"{\"id\":\"m1\",\"method\":\"ping\",\"params\":{}}\n\
              {\"id\":\"m2\",\"method\":\"workspace.list\",\"params\":{}}\n",
        );
    }
    let deadline = Instant::now() + BRIDGE_TIMEOUT;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            // A client process that hangs is stopped; it holds no panes.
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("api-bridge --multi did not finish".into());
            }
        }
    }
    let mut output = String::new();
    if let Some(mut stdout) = child.stdout.take() {
        let _ = stdout.read_to_string(&mut output);
    }
    let answered = output
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .filter(|value| value.get("result").is_some())
        .count();
    if answered == 2 {
        Ok(())
    } else {
        Err(format!(
            "api-bridge --multi answered {answered} of 2 requests"
        ))
    }
}

/// The pid serving `socket`, from the kernel's view of a fresh connection.
fn serving_pid(socket: &Path) -> Option<u32> {
    let stream = std::os::unix::net::UnixStream::connect(socket).ok()?;
    crate::platform::unix_stream_peer_pid(&stream)
}

/// sha256 of the image `pid` runs.
#[cfg(target_os = "linux")]
fn process_image_sha256(pid: u32) -> io::Result<String> {
    crate::checksum::file_sha256(Path::new(&format!("/proc/{pid}/exe")))
}

/// sha256 of the file `pid` was started from. macOS has no handle to the
/// running image, so this hashes its path; the guard never replaces the
/// files it starts servers from while they run.
#[cfg(target_os = "macos")]
fn process_image_sha256(pid: u32) -> io::Result<String> {
    let mut buffer = vec![0u8; 4096];
    let pid = libc::c_int::try_from(pid).map_err(io::Error::other)?;
    // SAFETY: the buffer is valid for its length.
    let len = unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) };
    if len <= 0 {
        return Err(io::Error::last_os_error());
    }
    buffer.truncate(len as usize);
    use std::os::unix::ffi::OsStrExt as _;
    crate::checksum::file_sha256(Path::new(std::ffi::OsStr::from_bytes(&buffer)))
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn process_image_sha256(_pid: u32) -> io::Result<String> {
    Err(io::Error::other(
        "this platform can't identify the serving binary",
    ))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fault {
    ForwardChecks,
    RollbackHandoff,
}

/// `Err` when a debug build's test fault asks this check to fail.
#[cfg(debug_assertions)]
fn test_fault(fault: Fault) -> Result<(), String> {
    let active = match std::env::var(TEST_FAULT_ENV).as_deref() {
        Ok("forward_checks") => fault == Fault::ForwardChecks,
        Ok("rollback_handoff") => true,
        _ => false,
    };
    if active {
        Err(format!("test fault {fault:?}"))
    } else {
        Ok(())
    }
}

#[cfg(not(debug_assertions))]
fn test_fault(_fault: Fault) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_line_yields_the_version_when_the_commit_matches() {
        let commit = "8a02b834abcdef0123456789abcdef0123456789";
        assert_eq!(
            parse_version_line(
                "herdr 0.9.6-preview.2026-10-28-8a02b834abcd (8a02b83)\n",
                commit
            ),
            Ok("0.9.6-preview.2026-10-28-8a02b834abcd".to_string())
        );
    }

    #[test]
    fn version_line_refuses_other_commits_and_shapes() {
        let commit = "8a02b834abcdef0123456789abcdef0123456789";
        for output in [
            "herdr 0.9.6 (1234567)",
            "herdr 0.9.6",
            "herdr 0.9.6 (8a02b8)",
            "herdr  (8a02b83)",
            "hrdr 0.9.6 (8a02b83)",
            "herdr 0.9.6 (8a02b83",
            "herdr 0.9.6 (zzzzzzz)",
            "",
        ] {
            assert!(parse_version_line(output, commit).is_err(), "{output:?}");
        }
    }

    #[test]
    fn smoke_test_refuses_a_binary_that_does_not_report_a_herdr_version() {
        // A shell answers `--version` with an error or its own banner.
        let err = smoke_test(
            Path::new("/bin/sh"),
            "8a02b834abcdef0123456789abcdef0123456789",
        )
        .unwrap_err();
        assert!(
            err.contains("not `herdr") || err.contains("exited"),
            "{err}"
        );
        assert!(smoke_test(Path::new("/nonexistent/herdr"), "8a02b83").is_err());
    }

    /// Recorded answers for the decision table, and the calls it made.
    struct Script {
        forward: Handoff,
        observed: Observed,
        unchanged: Result<(), String>,
        marker_free: bool,
        back_observed: Result<(), String>,
        install: Result<(), String>,
        calls: Vec<&'static str>,
    }

    impl Script {
        fn passing() -> Self {
            Self {
                forward: Handoff::Committed,
                observed: Observed::Passed,
                unchanged: Ok(()),
                marker_free: true,
                back_observed: Ok(()),
                install: Ok(()),
                calls: Vec::new(),
            }
        }

        fn failing_checks() -> Self {
            Self {
                observed: Observed::Failed {
                    reason: "panes missing".into(),
                    switched: true,
                },
                ..Self::passing()
            }
        }

        fn count(&self, call: &str) -> usize {
            self.calls.iter().filter(|made| **made == call).count()
        }
    }

    impl Switch for Script {
        fn phase(&mut self, _phase: UpdatePhase) {}
        fn handoff_forward(&mut self) -> Handoff {
            self.calls.push("handoff_forward");
            self.forward.clone()
        }
        fn observe_forward(&mut self) -> Observed {
            self.calls.push("observe_forward");
            self.observed.clone()
        }
        fn confirm_unchanged(&mut self) -> Result<(), String> {
            self.calls.push("confirm_unchanged");
            self.unchanged.clone()
        }
        fn mark_rollback(&mut self) -> bool {
            self.calls.push("mark_rollback");
            self.marker_free
        }
        fn handoff_back(&mut self) -> Handoff {
            self.calls.push("handoff_back");
            Handoff::Committed
        }
        fn observe_back(&mut self) -> Result<(), String> {
            self.calls.push("observe_back");
            self.back_observed.clone()
        }
        fn install(&mut self) -> Result<(), String> {
            self.calls.push("install");
            self.install.clone()
        }
    }

    #[test]
    fn passing_checks_install_and_never_hand_back() {
        let mut script = Script::passing();
        assert_eq!(decide(&mut script).0, UpdateOutcome::Updated);
        assert_eq!(script.count("install"), 1);
        assert_eq!(script.count("handoff_back"), 0);
    }

    #[test]
    fn a_failed_install_after_passing_checks_is_disk_stale() {
        let mut script = Script {
            install: Err("read-only".into()),
            ..Script::passing()
        };
        assert_eq!(decide(&mut script).0, UpdateOutcome::UpdatedDiskStale);
        assert_eq!(script.count("handoff_back"), 0);
    }

    #[test]
    fn failing_checks_hand_back_exactly_once_and_never_install() {
        let mut script = Script::failing_checks();
        assert_eq!(decide(&mut script).0, UpdateOutcome::RolledBack);
        assert_eq!(script.count("handoff_back"), 1);
        assert_eq!(script.count("install"), 0);

        let mut script = Script {
            back_observed: Err("old build not back".into()),
            ..Script::failing_checks()
        };
        assert_eq!(decide(&mut script).0, UpdateOutcome::NeedsAttention);
        assert_eq!(script.count("handoff_back"), 1, "{:?}", script.calls);
        assert_eq!(script.count("install"), 0);
    }

    #[test]
    fn an_existing_rollback_marker_stops_a_second_handoff_back() {
        let mut script = Script {
            marker_free: false,
            ..Script::failing_checks()
        };
        assert_eq!(decide(&mut script).0, UpdateOutcome::NeedsAttention);
        assert_eq!(script.count("handoff_back"), 0);
    }

    #[test]
    fn a_refused_switch_changes_nothing() {
        let mut script = Script {
            forward: Handoff::Refused("expected protocol 99".into()),
            ..Script::passing()
        };
        assert_eq!(decide(&mut script).0, UpdateOutcome::FailedNoChange);
        assert_eq!(script.count("observe_forward"), 0);
        assert_eq!(script.count("handoff_back") + script.count("install"), 0);

        let mut script = Script {
            forward: Handoff::Refused("expected protocol 99".into()),
            unchanged: Err("panes missing".into()),
            ..Script::passing()
        };
        assert_eq!(decide(&mut script).0, UpdateOutcome::NeedsAttention);
        assert_eq!(script.count("handoff_back") + script.count("install"), 0);
    }

    #[test]
    fn a_switch_that_did_not_take_effect_is_no_change() {
        let mut script = Script {
            forward: Handoff::Unknown("connection reset".into()),
            observed: Observed::OldStillServing,
            ..Script::passing()
        };
        assert_eq!(decide(&mut script).0, UpdateOutcome::FailedNoChange);
        assert_eq!(script.count("handoff_back") + script.count("install"), 0);
    }

    #[test]
    fn no_identifiable_server_holds_without_a_handoff_back() {
        let mut script = Script {
            observed: Observed::Failed {
                reason: "nobody serves".into(),
                switched: false,
            },
            ..Script::passing()
        };
        assert_eq!(decide(&mut script).0, UpdateOutcome::NeedsAttention);
        assert_eq!(script.count("handoff_back") + script.count("install"), 0);
    }
}
