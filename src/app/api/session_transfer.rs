use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use crate::agent_resume::{AgentSessionRef, PersistedAgentSession};
use crate::api::schema::{
    AgentSessionTransferPhase, AgentTransferSessionParams, ErrorBody, ResponseResult,
};
use crate::app::App;
use crate::detect::AgentState;
use crate::events::AppEvent;
use crate::session_transfer::{
    HarnessKind, OmissionSummary, PrepareRequest, PreparedTransfer, RuntimeSessionTransfer,
    RuntimeVerificationKind, TransferError, VerifiedTargetProcess,
};

use super::responses::{encode_error, encode_error_body, encode_success};

const TRANSFER_PREPARE_TIMEOUT: Duration = Duration::from_secs(45);
const TRANSFER_LAUNCH_TIMEOUT: Duration = Duration::from_secs(30);
const TRANSFER_VERIFICATION_TIMEOUT: Duration = Duration::from_secs(45);
// Disposable E2E measured the real detector publishing `Blocked` immediately
// after a ~3.05s first JSONL verification. One additional second caught that
// observed lag. This narrows rather than closes the race: a blocker published
// after the window can still follow an otherwise verified cutover.
const TRANSFER_BLOCKER_OBSERVATION_DELAY: Duration = Duration::from_secs(1);

struct TransferAccountRoute {
    config_home: PathBuf,
    sessions_root: PathBuf,
    launch_env: crate::config::AccountLaunchEnv,
}

fn omp_named_profile_is_active() -> bool {
    omp_profile_value_is_named(
        std::env::var_os("OMP_PROFILE").as_deref(),
        std::env::var_os("PI_PROFILE").as_deref(),
    )
}

fn omp_profile_value_is_named(omp_profile: Option<&OsStr>, pi_profile: Option<&OsStr>) -> bool {
    // Native OMP gives OMP_PROFILE precedence whenever it is defined, including
    // the empty and `default` values. PI_PROFILE is only its legacy fallback.
    let Some(value) = omp_profile.or(pi_profile) else {
        return false;
    };
    let value = value.to_string_lossy();
    let value = value.trim();
    !value.is_empty() && value != "default"
}

impl App {
    pub(super) fn handle_agent_transfer_session(
        &mut self,
        id: String,
        params: AgentTransferSessionParams,
    ) -> String {
        let resolved = match self.resolve_agent_target(&params.target) {
            Ok(resolved) => resolved,
            Err(err) => return encode_error_body(id, self.agent_target_error_body(err)),
        };
        let Some(terminal_id) = self
            .state
            .workspaces
            .get(resolved.ws_idx)
            .and_then(|workspace| workspace.terminal_id(resolved.pane_id))
            .cloned()
        else {
            return encode_error(id, "agent_not_found", "agent was not found");
        };
        if params.confirm {
            return self.confirm_agent_session_transfer(id, params, terminal_id);
        }
        if params.transfer_id.is_some() {
            return encode_error(
                id,
                "invalid_transfer_confirmation",
                "transfer_id is only accepted together with confirm=true",
            );
        }

        let live_cwd = self
            .terminal_runtimes
            .get(&terminal_id)
            .and_then(|runtime| runtime.cwd());
        let (
            source,
            source_agent,
            source_session_ref,
            source_account,
            source_state,
            launch_pending,
            transfer_active,
            cwd,
            source_transcript_path,
            source_cursor,
            source_process_pid,
        ) = {
            let Some(terminal) = self.state.terminals.get(&terminal_id) else {
                return encode_error(id, "agent_not_found", "agent was not found");
            };
            let Some((source, agent, session_ref)) = Self::terminal_resume_source(terminal) else {
                return encode_error(
                    id,
                    "no_resumable_session",
                    "agent has no resumable native session to transfer",
                );
            };
            let source_transcript_path = terminal
                .reported_agent_session_path_for(&source, &agent, &session_ref)
                .map(PathBuf::from)
                .or_else(|| {
                    (session_ref.kind == crate::agent_resume::AgentSessionRefKind::Path)
                        .then(|| PathBuf::from(&session_ref.value))
                });
            let source_runtime =
                terminal.reported_agent_session_runtime_for(&source, &agent, &session_ref);
            (
                source,
                agent,
                session_ref,
                terminal.agent_account.clone(),
                terminal.state,
                terminal.managed_agent_launch_pending(),
                terminal.session_transfer.as_ref().is_some_and(|transfer| {
                    matches!(
                        transfer.phase,
                        AgentSessionTransferPhase::Preparing
                            | AgentSessionTransferPhase::Ready
                            | AgentSessionTransferPhase::VerifyingCutover
                            | AgentSessionTransferPhase::LaunchingTarget
                            | AgentSessionTransferPhase::AwaitingTarget
                            | AgentSessionTransferPhase::RollingBack
                    ) || (transfer.phase == AgentSessionTransferPhase::Completed
                        && transfer.awaiting_deferred_target_report)
                }),
                live_cwd.unwrap_or_else(|| terminal.cwd.clone()),
                source_transcript_path,
                source_runtime.and_then(|runtime| runtime.cursor.clone()),
                source_runtime.and_then(|runtime| runtime.process_pid),
            )
        };
        if source_state != AgentState::Idle || launch_pending {
            return encode_error(
                id,
                "agent_not_idle",
                "agent session transfer requires an idle, fully launched source agent",
            );
        }
        if transfer_active {
            return encode_error(
                id,
                "session_transfer_in_progress",
                "this agent already has a session transfer in progress",
            );
        }
        let Some(source_kind) = HarnessKind::from_agent_label(&source_agent) else {
            return encode_error(
                id,
                "unsupported_source_harness",
                "agent session transfer supports Claude Code, Codex, and OMP",
            );
        };
        let expected_ref_kind = if source_kind == HarnessKind::Omp {
            crate::agent_resume::AgentSessionRefKind::Path
        } else {
            crate::agent_resume::AgentSessionRefKind::Id
        };
        if source_session_ref.kind != expected_ref_kind {
            return encode_error(
                id,
                "unsupported_session_reference",
                format!(
                    "{} session transfer requires a native {:?} reference",
                    source_kind.label(),
                    expected_ref_kind
                ),
            );
        }
        if source != source_kind.source() {
            return encode_error(
                id,
                "untrusted_session_source",
                "the current session was not reported by the official harness integration",
            );
        }
        let target_kind = HarnessKind::from(params.to);
        if target_kind == source_kind {
            return encode_error(
                id,
                "same_session_harness",
                "source and target harness are the same",
            );
        }

        let source_route =
            match self.resolve_transfer_account(source_kind, source_account.as_deref()) {
                Ok(resolved) => resolved,
                Err(error) => return encode_error_body(id, error),
            };
        let target_route =
            match self.resolve_transfer_account(target_kind, params.account.as_deref()) {
                Ok(resolved) => resolved,
                Err(error) => return encode_error_body(id, error),
            };
        if source_kind == HarnessKind::Omp {
            let (Some(cursor), Some(process_pid)) = (source_cursor.as_deref(), source_process_pid)
            else {
                return encode_error(
                    id,
                    "omp_session_proof_missing",
                    "the official OMP integration has not reported its active leaf and process PID; update the integration and retry",
                );
            };
            let foreground_job = self
                .terminal_runtimes
                .get(&terminal_id)
                .and_then(|runtime| runtime.child_pid())
                .and_then(crate::detect::foreground_job);
            if foreground_job
                .as_ref()
                .and_then(|job| crate::session_transfer::omp_reported_process(job, process_pid))
                != Some(process_pid)
            {
                return encode_error(
                    id,
                    "omp_session_process_mismatch",
                    format!(
                        "OMP reported process {process_pid} for leaf {cursor}, but that PID is not the current foreground OMP process"
                    ),
                );
            }
        }
        if target_kind == HarnessKind::Claude {
            if let Some(blocker) = super::agents::claude_account_launch_blocker(
                target_route.config_home.to_string_lossy().as_ref(),
                Some(cwd.to_string_lossy().as_ref()),
            ) {
                return encode_error(
                    id,
                    blocker.code(),
                    blocker.message(params.account.as_deref().unwrap_or("default")),
                );
            }
        }

        let transfer_id = match crate::session_transfer::new_transfer_id() {
            Ok(transfer_id) => transfer_id,
            Err(err) => return encode_error(id, "session_transfer_failed", err.to_string()),
        };
        let source_session = PersistedAgentSession {
            source,
            agent: source_agent,
            session_ref: source_session_ref.clone(),
        };
        let transfer = RuntimeSessionTransfer {
            id: transfer_id.clone(),
            source_kind,
            source_session: source_session.clone(),
            source_account: source_account.clone(),
            source_config_home: source_route.config_home.clone(),
            source_sessions_root: source_route.sessions_root.clone(),
            source_cursor: source_cursor.clone(),
            source_process_pid,
            target_kind,
            target_account: params.account.clone(),
            target_config_home: target_route.config_home.clone(),
            target_sessions_root: target_route.sessions_root.clone(),
            phase: AgentSessionTransferPhase::Preparing,
            message_count: 0,
            omissions: OmissionSummary::default(),
            error: None,
            source_path: None,
            source_fingerprint: None,
            target_session_ref: None,
            target_cursor: None,
            target_transcript_path: None,
            target_fingerprint: None,
            target_deadline: None,
            target_process: None,
            source_rollback_process: None,
            verification_in_flight: None,
            verification_observation_deadline: None,
            awaiting_deferred_target_report: false,
            target_report_accepted: false,
        };
        if let Some(terminal) = self.state.terminals.get_mut(&terminal_id) {
            terminal.session_transfer = Some(transfer);
            // This remains the durable owner until a verified target reports.
            terminal.set_persisted_agent_session(source_session);
        }
        self.schedule_session_save();

        let request = PrepareRequest {
            source_kind,
            source_sessions_root: source_route.sessions_root,
            source_session_ref,
            source_cursor,
            source_transcript_path,
            target_kind,
            target_config_home: target_route.config_home,
            target_sessions_root: target_route.sessions_root,
            target_launch_env: target_route.launch_env,
            cwd,
            timeout: TRANSFER_PREPARE_TIMEOUT,
        };
        let event_tx = self.event_tx.clone();
        let worker_terminal_id = terminal_id.clone();
        let worker_transfer_id = transfer_id.clone();
        let worker = std::thread::Builder::new()
            .name(format!("herdr-session-transfer-{transfer_id}"))
            .spawn(move || {
                let result = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|err| {
                        TransferError::CodexImport(format!(
                            "could not start transfer worker runtime: {err}"
                        ))
                    })
                    .and_then(|runtime| {
                        runtime.block_on(crate::session_transfer::prepare(request))
                    });
                let _ = event_tx.blocking_send(AppEvent::AgentSessionTransferPrepared {
                    terminal_id: worker_terminal_id,
                    transfer_id: worker_transfer_id,
                    result: Box::new(result),
                });
            });
        if let Err(err) = worker {
            if let Some(transfer) = self
                .state
                .terminals
                .get_mut(&terminal_id)
                .and_then(|terminal| terminal.session_transfer.as_mut())
            {
                transfer.phase = AgentSessionTransferPhase::Failed;
                transfer.error = Some(format!("could not start transfer worker: {err}"));
            }
            return encode_error(
                id,
                "session_transfer_failed",
                format!("could not start transfer worker: {err}"),
            );
        }

        let agent = match self.agent_info_for_target(&params.target) {
            Ok(agent) => agent,
            Err(err) => return encode_error_body(id, self.agent_target_error_body(err)),
        };
        encode_success(id, ResponseResult::AgentInfo { agent })
    }

    fn confirm_agent_session_transfer(
        &mut self,
        id: String,
        params: AgentTransferSessionParams,
        terminal_id: crate::terminal::TerminalId,
    ) -> String {
        let Some(requested_transfer_id) = params.transfer_id.as_deref() else {
            return encode_error(
                id,
                "missing_transfer_id",
                "confirming a session transfer requires its transfer_id",
            );
        };
        let Some(transfer) = self
            .state
            .terminals
            .get(&terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_ref())
            .cloned()
        else {
            return encode_error(
                id,
                "session_transfer_not_found",
                "this agent has no prepared session transfer",
            );
        };
        if transfer.id != requested_transfer_id {
            return encode_error(
                id,
                "session_transfer_mismatch",
                "the transfer_id does not match this agent's prepared transfer",
            );
        }
        if transfer.phase != AgentSessionTransferPhase::Ready {
            return encode_error(
                id,
                "session_transfer_not_ready",
                "the session transfer is not ready for confirmation",
            );
        }
        if HarnessKind::from(params.to) != transfer.target_kind
            || params.account != transfer.target_account
        {
            return encode_error(
                id,
                "session_transfer_mismatch",
                "the target harness or account differs from the prepared transfer",
            );
        }
        let Some(source_path) = transfer.source_path.clone() else {
            return encode_error(
                id,
                "session_transfer_failed",
                "the prepared transfer is missing its verified source transcript",
            );
        };
        let Some(source_fingerprint) = transfer.source_fingerprint.clone() else {
            return encode_error(
                id,
                "session_transfer_failed",
                "the prepared transfer is missing its source fingerprint",
            );
        };
        let Some(target_path) = transfer.target_transcript_path.clone() else {
            return encode_error(
                id,
                "session_transfer_failed",
                "the prepared transfer is missing its staged target transcript",
            );
        };
        let Some(target_fingerprint) = transfer.target_fingerprint.clone() else {
            return encode_error(
                id,
                "session_transfer_failed",
                "the prepared transfer is missing its target fingerprint",
            );
        };
        if let Err(reason) = self.verify_transfer_account_routes(&transfer) {
            self.fail_session_transfer_before_cutover(&terminal_id, &reason);
            return encode_error(id, "session_transfer_account_changed", reason);
        }
        let terminal_still_idle = self
            .state
            .terminals
            .get(&terminal_id)
            .is_some_and(|terminal| {
                terminal.state == AgentState::Idle
                    && !terminal.managed_agent_launch_pending()
                    && terminal.agent_account == transfer.source_account
                    && Self::terminal_resume_source(terminal).is_some_and(
                        |(source, agent, session_ref)| {
                            source == transfer.source_session.source
                                && agent == transfer.source_session.agent
                                && session_ref == transfer.source_session.session_ref
                        },
                    )
            });
        if !terminal_still_idle {
            let reason = "source session changed or stopped being idle before confirmation; source stayed running and cutover was refused";
            self.fail_session_transfer_before_cutover(&terminal_id, reason);
            return encode_error(id, "session_transfer_changed", reason);
        }

        let Some(target_ref) = transfer.target_session_ref.as_ref() else {
            return encode_error(
                id,
                "session_transfer_failed",
                "the prepared transfer is missing its typed target session reference",
            );
        };
        let Some(plan) = crate::agent_resume::plan(
            transfer.target_kind.source(),
            transfer.target_kind.label(),
            target_ref,
        ) else {
            return encode_error(
                id,
                "session_transfer_failed",
                "the target harness has no native resume plan",
            );
        };
        let _ = plan;
        if let Some(runtime_transfer) = self
            .state
            .terminals
            .get_mut(&terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_mut())
        {
            runtime_transfer.phase = AgentSessionTransferPhase::VerifyingCutover;
            runtime_transfer.error = None;
            runtime_transfer.target_deadline = Some(Instant::now() + TRANSFER_VERIFICATION_TIMEOUT);
        }
        self.schedule_session_save();

        let event_tx = self.event_tx.clone();
        let worker_terminal_id = terminal_id.clone();
        let worker_transfer_id = transfer.id.clone();
        let source_sessions_root = transfer.source_sessions_root.clone();
        let target_sessions_root = transfer.target_sessions_root.clone();
        let worker = std::thread::Builder::new()
            .name(format!("herdr-session-cutover-{}", transfer.id))
            .spawn(move || {
                let result = crate::session_transfer::verify_unchanged_transcripts(
                    &source_sessions_root,
                    &source_path,
                    &source_fingerprint,
                    &target_sessions_root,
                    &target_path,
                    &target_fingerprint,
                );
                let _ = event_tx.blocking_send(AppEvent::AgentSessionTransferCutoverVerified {
                    terminal_id: worker_terminal_id,
                    transfer_id: worker_transfer_id,
                    result,
                });
            });
        if let Err(err) = worker {
            let reason = format!("could not start cutover verification worker: {err}");
            self.fail_session_transfer_before_cutover(&terminal_id, &reason);
            return encode_error(id, "session_transfer_failed", reason);
        }

        let agent = match self.agent_info_for_target(&params.target) {
            Ok(agent) => agent,
            Err(err) => return encode_error_body(id, self.agent_target_error_body(err)),
        };
        encode_success(id, ResponseResult::AgentInfo { agent })
    }

    fn fail_session_transfer_before_cutover(
        &mut self,
        terminal_id: &crate::terminal::TerminalId,
        reason: &str,
    ) {
        if let Some(transfer) = self
            .state
            .terminals
            .get_mut(terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_mut())
        {
            transfer.phase = AgentSessionTransferPhase::Failed;
            transfer.error = Some(reason.to_string());
            transfer.target_deadline = None;
            transfer.verification_in_flight = None;
            transfer.verification_observation_deadline = None;
        }
        self.schedule_session_save();
    }

    fn resolve_unchanged_transfer_account(
        &self,
        kind: HarnessKind,
        account: Option<&str>,
        expected_home: &std::path::Path,
        expected_sessions_root: &std::path::Path,
        role: &str,
    ) -> Result<crate::config::AccountLaunchEnv, String> {
        let route = self
            .resolve_transfer_account(kind, account)
            .map_err(|error| {
                format!(
                    "{role} account routing is no longer available: {}",
                    error.message
                )
            })?;
        if route.config_home != expected_home || route.sessions_root != expected_sessions_root {
            return Err(format!(
                "{role} account routing changed from config {} / sessions {} to config {} / sessions {}; cutover was refused",
                expected_home.display(),
                expected_sessions_root.display(),
                route.config_home.display(),
                route.sessions_root.display(),
            ));
        }
        Ok(route.launch_env)
    }

    fn verify_transfer_account_routes(
        &self,
        transfer: &RuntimeSessionTransfer,
    ) -> Result<(), String> {
        self.resolve_unchanged_transfer_account(
            transfer.source_kind,
            transfer.source_account.as_deref(),
            &transfer.source_config_home,
            &transfer.source_sessions_root,
            "source",
        )?;
        self.resolve_unchanged_transfer_account(
            transfer.target_kind,
            transfer.target_account.as_deref(),
            &transfer.target_config_home,
            &transfer.target_sessions_root,
            "target",
        )?;
        Ok(())
    }

    fn resolve_transfer_account(
        &self,
        kind: HarnessKind,
        account_id: Option<&str>,
    ) -> Result<TransferAccountRoute, ErrorBody> {
        let Some(account_id) = account_id else {
            if kind == HarnessKind::Omp && omp_named_profile_is_active() {
                return Err(ErrorBody {
                    code: "omp_profile_unsupported".into(),
                    message: "OMP named profiles are not supported by agent session transfer yet; use the default profile or a Herdr OMP account".into(),
                });
            }
            let config_home =
                crate::config::default_config_dir(kind.label()).ok_or_else(|| ErrorBody {
                    code: "config_home_unavailable".into(),
                    message: format!("could not resolve the default {} config home", kind.label()),
                })?;
            let sessions_root = if kind == HarnessKind::Omp {
                crate::config::omp_sessions_dir(&config_home)
            } else {
                config_home.clone()
            };
            return Ok(TransferAccountRoute {
                config_home,
                sessions_root,
                launch_env: crate::config::AccountLaunchEnv::unselected(),
            });
        };
        let account = self
            .loaded_accounts
            .iter()
            .find(|account| account.id == account_id)
            .ok_or_else(|| ErrorBody {
                code: "unknown_account".into(),
                message: format!("no configured account with id {account_id}"),
            })?;
        if account.kind != kind.label() {
            return Err(ErrorBody {
                code: "account_kind_mismatch".into(),
                message: format!(
                    "account {account_id} is for kind {}, not {}",
                    account.kind,
                    kind.label()
                ),
            });
        }
        let env = account.launch_env().ok_or_else(|| ErrorBody {
            code: "unknown_account".into(),
            message: format!("account {account_id} has no supported config-home routing"),
        })?;
        let config_home = PathBuf::from(&account.config_dir);
        let sessions_root = if kind == HarnessKind::Omp {
            crate::config::omp_sessions_dir(&config_home)
        } else {
            config_home.clone()
        };
        Ok(TransferAccountRoute {
            config_home,
            sessions_root,
            launch_env: env,
        })
    }

    pub(crate) fn handle_agent_session_transfer_prepared(
        &mut self,
        terminal_id: crate::terminal::TerminalId,
        transfer_id: String,
        result: Result<PreparedTransfer, TransferError>,
    ) -> bool {
        let Some(transfer_snapshot) = self
            .state
            .terminals
            .get(&terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_ref())
            .cloned()
        else {
            return false;
        };
        if transfer_snapshot.id != transfer_id
            || transfer_snapshot.phase != AgentSessionTransferPhase::Preparing
        {
            return false;
        }
        let prepared = match result {
            Ok(prepared) => prepared,
            Err(err) => {
                let transfer = self
                    .state
                    .terminals
                    .get_mut(&terminal_id)
                    .and_then(|terminal| terminal.session_transfer.as_mut())
                    .expect("transfer exists");
                transfer.phase = AgentSessionTransferPhase::Failed;
                transfer.error = Some(err.to_string());
                self.schedule_session_save();
                return false;
            }
        };

        let terminal_still_idle = self
            .state
            .terminals
            .get(&terminal_id)
            .is_some_and(|terminal| {
                terminal.state == AgentState::Idle
                    && terminal.agent_account == transfer_snapshot.source_account
                    && Self::terminal_resume_source(terminal).is_some_and(
                        |(source, agent, session_ref)| {
                            source == transfer_snapshot.source_session.source
                                && agent == transfer_snapshot.source_session.agent
                                && session_ref == transfer_snapshot.source_session.session_ref
                        },
                    )
            });
        if !terminal_still_idle {
            let terminal = self
                .state
                .terminals
                .get_mut(&terminal_id)
                .expect("terminal exists");
            let transfer = terminal.session_transfer.as_mut().expect("transfer exists");
            transfer.phase = AgentSessionTransferPhase::Failed;
            transfer.error = Some(
                "source changed while the destination was being staged; source stayed running and confirmation was refused"
                    .to_string(),
            );
            self.schedule_session_save();
            return false;
        }

        {
            let terminal = self
                .state
                .terminals
                .get_mut(&terminal_id)
                .expect("terminal exists");
            let transfer = terminal.session_transfer.as_mut().expect("transfer exists");
            transfer.phase = AgentSessionTransferPhase::Ready;
            transfer.message_count = prepared.staged.transcript.messages.len() as u64;
            transfer.omissions = prepared.staged.transcript.omissions;
            transfer.source_path = Some(prepared.source_path);
            transfer.source_fingerprint = Some(prepared.source_fingerprint);
            transfer.target_session_ref = Some(prepared.staged.session_ref);
            transfer.target_cursor = prepared.staged.cursor;
            transfer.target_transcript_path = Some(prepared.staged.transcript_path);
            transfer.target_fingerprint = Some(prepared.staged.transcript.fingerprint);
            transfer.error = None;
        }
        self.schedule_session_save();
        false
    }

    pub(crate) fn handle_agent_session_transfer_cutover_verified(
        &mut self,
        terminal_id: crate::terminal::TerminalId,
        transfer_id: String,
        result: Result<(), TransferError>,
    ) -> bool {
        let Some(snapshot) = self
            .state
            .terminals
            .get(&terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_ref())
            .cloned()
        else {
            return false;
        };
        if snapshot.id != transfer_id
            || snapshot.phase != AgentSessionTransferPhase::VerifyingCutover
        {
            return false;
        }
        if let Err(error) = result {
            self.fail_session_transfer_before_cutover(
                &terminal_id,
                &format!(
                    "source or staged destination changed before cutover; source stayed running: {error}"
                ),
            );
            return false;
        }
        if let Err(reason) = self.verify_transfer_account_routes(&snapshot) {
            self.fail_session_transfer_before_cutover(&terminal_id, &reason);
            return false;
        }
        let terminal_still_idle = self
            .state
            .terminals
            .get(&terminal_id)
            .is_some_and(|terminal| {
                terminal.state == AgentState::Idle
                    && !terminal.managed_agent_launch_pending()
                    && terminal.agent_account == snapshot.source_account
                    && Self::terminal_resume_source(terminal).is_some_and(
                        |(source, agent, session_ref)| {
                            source == snapshot.source_session.source
                                && agent == snapshot.source_session.agent
                                && session_ref == snapshot.source_session.session_ref
                        },
                    )
            });
        if !terminal_still_idle {
            self.fail_session_transfer_before_cutover(
                &terminal_id,
                "source session changed or stopped being idle during cutover verification; source stayed running",
            );
            return false;
        }

        let Some(target_ref) = snapshot.target_session_ref.clone() else {
            self.fail_session_transfer_before_cutover(
                &terminal_id,
                "the verified transfer is missing its typed target session reference",
            );
            return false;
        };
        if snapshot.source_kind == HarnessKind::Omp {
            let source_proof_still_current = self
                .state
                .terminals
                .get(&terminal_id)
                .and_then(|terminal| {
                    terminal.reported_agent_session_runtime_for(
                        &snapshot.source_session.source,
                        &snapshot.source_session.agent,
                        &snapshot.source_session.session_ref,
                    )
                })
                .is_some_and(|proof| {
                    proof.cursor == snapshot.source_cursor
                        && proof.process_pid == snapshot.source_process_pid
                });
            let process_still_current = snapshot.source_process_pid.is_some_and(|pid| {
                self.terminal_runtimes
                    .get(&terminal_id)
                    .and_then(|runtime| runtime.child_pid())
                    .and_then(crate::detect::foreground_job)
                    .as_ref()
                    .and_then(|job| crate::session_transfer::omp_reported_process(job, pid))
                    == Some(pid)
            });
            if !source_proof_still_current || !process_still_current {
                self.fail_session_transfer_before_cutover(
                    &terminal_id,
                    "OMP active leaf or foreground process changed during confirmation; source stayed running",
                );
                return false;
            }
        }
        let Some(plan) = crate::agent_resume::plan(
            snapshot.target_kind.source(),
            snapshot.target_kind.label(),
            &target_ref,
        ) else {
            self.fail_session_transfer_before_cutover(
                &terminal_id,
                "the target harness has no native resume plan",
            );
            return false;
        };
        let target_env = match self.resolve_unchanged_transfer_account(
            snapshot.target_kind,
            snapshot.target_account.as_deref(),
            &snapshot.target_config_home,
            &snapshot.target_sessions_root,
            "target",
        ) {
            Ok(env) => env.vars,
            Err(reason) => {
                self.fail_session_transfer_before_cutover(&terminal_id, &reason);
                return false;
            }
        };
        // `TerminalState::cwd` can lag a shell `cd` until its OSC/process report
        // reaches the app loop. Snapshot the live shell cwd before killing the
        // source so both the target and any rollback reopen in the directory the
        // user was actually working in.
        let live_cwd = self
            .terminal_runtimes
            .get(&terminal_id)
            .and_then(|runtime| runtime.cwd());
        let terminal = self
            .state
            .terminals
            .get_mut(&terminal_id)
            .expect("terminal exists");
        let runtime_transfer = terminal.session_transfer.as_mut().expect("transfer exists");
        runtime_transfer.phase = AgentSessionTransferPhase::LaunchingTarget;
        runtime_transfer.error = None;
        runtime_transfer.target_deadline = None;
        runtime_transfer.target_process = None;
        runtime_transfer.source_rollback_process = None;
        runtime_transfer.verification_in_flight = None;
        runtime_transfer.verification_observation_deadline = None;
        runtime_transfer.awaiting_deferred_target_report = false;
        if let Some(name) = terminal.agent_name.clone() {
            terminal.begin_managed_agent(
                name,
                snapshot.target_kind.agent(),
                Instant::now(),
                crate::app::agents::AGENT_START_SETTLE_DELAY,
                TRANSFER_LAUNCH_TIMEOUT,
            );
        }
        terminal.set_persisted_agent_session(snapshot.source_session);
        terminal.pending_agent_resume_plan = Some(plan);
        terminal.pending_launch_env = target_env;
        terminal.agent_account = snapshot.target_account;
        if let Some(cwd) = live_cwd {
            terminal.cwd = cwd;
        }
        terminal.respawn_shell_on_exit = true;
        self.schedule_session_save();
        self.shutdown_terminal_runtime(terminal_id);
        true
    }

    pub(crate) fn mark_session_transfer_runtime_launched(
        &mut self,
        terminal_id: &crate::terminal::TerminalId,
        launched_agent: &str,
    ) {
        let Some(transfer) = self
            .state
            .terminals
            .get_mut(terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_mut())
        else {
            return;
        };
        let expected = match transfer.phase {
            AgentSessionTransferPhase::LaunchingTarget => transfer.target_kind.label(),
            AgentSessionTransferPhase::RollingBack => transfer.source_kind.label(),
            _ => return,
        };
        if launched_agent == expected {
            if transfer.phase == AgentSessionTransferPhase::LaunchingTarget {
                transfer.phase = AgentSessionTransferPhase::AwaitingTarget;
                transfer.target_process = None;
                transfer.source_rollback_process = None;
                transfer.verification_in_flight = None;
                transfer.verification_observation_deadline = None;
                transfer.awaiting_deferred_target_report = false;
                transfer.target_report_accepted = false;
            }
            transfer.target_deadline = Some(Instant::now() + TRANSFER_LAUNCH_TIMEOUT);
        }
    }

    pub(crate) fn begin_agent_session_transfer_rollback(
        &mut self,
        terminal_id: &crate::terminal::TerminalId,
        reason: impl Into<String>,
    ) -> bool {
        let reason = reason.into();
        let Some(transfer) = self
            .state
            .terminals
            .get(terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_ref())
        else {
            return false;
        };
        let rollback_allowed = matches!(
            transfer.phase,
            AgentSessionTransferPhase::LaunchingTarget | AgentSessionTransferPhase::AwaitingTarget
        ) || (transfer.phase == AgentSessionTransferPhase::Completed
            && transfer.awaiting_deferred_target_report);
        if !rollback_allowed {
            return false;
        }
        let source_session = transfer.source_session.clone();
        let source_kind = transfer.source_kind;
        let source_account = transfer.source_account.clone();
        let source_config_home = transfer.source_config_home.clone();
        let source_sessions_root = transfer.source_sessions_root.clone();
        let source_env = match self.resolve_unchanged_transfer_account(
            source_kind,
            source_account.as_deref(),
            &source_config_home,
            &source_sessions_root,
            "source rollback",
        ) {
            Ok(env) => env.vars,
            Err(account_error) => {
                let transfer = self
                    .state
                    .terminals
                    .get_mut(terminal_id)
                    .and_then(|terminal| terminal.session_transfer.as_mut())
                    .expect("transfer exists");
                transfer.phase = AgentSessionTransferPhase::Failed;
                transfer.error = Some(format!(
                    "{reason}; source rollback was refused because {account_error}"
                ));
                transfer.target_deadline = None;
                transfer.verification_in_flight = None;
                transfer.verification_observation_deadline = None;
                self.schedule_session_save();
                return true;
            }
        };
        let Some(plan) = crate::agent_resume::plan(
            &source_session.source,
            &source_session.agent,
            &source_session.session_ref,
        ) else {
            let transfer = self
                .state
                .terminals
                .get_mut(terminal_id)
                .and_then(|terminal| terminal.session_transfer.as_mut())
                .expect("transfer exists");
            transfer.phase = AgentSessionTransferPhase::Failed;
            transfer.error = Some(format!(
                "{reason}; source rollback plan could not be reconstructed"
            ));
            return true;
        };
        let terminal = self
            .state
            .terminals
            .get_mut(terminal_id)
            .expect("terminal exists");
        let transfer = terminal.session_transfer.as_mut().expect("transfer exists");
        transfer.phase = AgentSessionTransferPhase::RollingBack;
        transfer.error = Some(format!("{reason}; restoring the source session"));
        transfer.target_deadline = None;
        transfer.target_process = None;
        transfer.source_rollback_process = None;
        transfer.verification_in_flight = None;
        transfer.verification_observation_deadline = None;
        transfer.awaiting_deferred_target_report = false;
        if let Some(name) = terminal.agent_name.clone() {
            terminal.begin_managed_agent(
                name,
                source_kind.agent(),
                Instant::now(),
                crate::app::agents::AGENT_START_SETTLE_DELAY,
                TRANSFER_LAUNCH_TIMEOUT,
            );
        }
        terminal.hook_authority = None;
        terminal.set_persisted_agent_session(source_session);
        terminal.pending_agent_resume_plan = Some(plan);
        terminal.pending_launch_env = source_env;
        terminal.agent_account = source_account;
        terminal.respawn_shell_on_exit = true;
        self.schedule_session_save();
        if self.terminal_runtimes.get(terminal_id).is_some() {
            self.shutdown_terminal_runtime(terminal_id.clone());
        }
        true
    }

    pub(crate) fn fail_agent_session_transfer_rollback_launch(
        &mut self,
        terminal_id: &crate::terminal::TerminalId,
        reason: impl Into<String>,
    ) -> bool {
        let Some(terminal) = self.state.terminals.get_mut(terminal_id) else {
            return false;
        };
        let Some(transfer) = terminal.session_transfer.as_mut() else {
            return false;
        };
        if transfer.phase != AgentSessionTransferPhase::RollingBack {
            return false;
        }
        transfer.phase = AgentSessionTransferPhase::Failed;
        transfer.error = Some(format!(
            "target failed and the source rollback could not launch: {}",
            reason.into()
        ));
        transfer.target_deadline = None;
        transfer.verification_in_flight = None;
        transfer.verification_observation_deadline = None;
        terminal.pending_agent_resume_plan = None;
        terminal.pending_launch_env.clear();
        terminal.respawn_shell_on_exit = true;
        self.schedule_session_save();
        true
    }

    pub(crate) fn reconcile_agent_session_transfer_report(
        &mut self,
        pane_id: crate::layout::PaneId,
        source: &str,
        agent_label: &str,
        session_ref: Option<&AgentSessionRef>,
        session_cursor: Option<&str>,
        process_pid: Option<u32>,
        accepted: bool,
    ) {
        if !accepted {
            return;
        }
        let Some((_, pane)) = self.find_pane(pane_id) else {
            return;
        };
        let terminal_id = pane.attached_terminal_id.clone();
        let Some(transfer) = self
            .state
            .terminals
            .get(&terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_ref())
        else {
            return;
        };
        let phase = transfer.phase;
        let (expected_source, expected_agent, expected_ref, expected_kind, trust_root) = match phase
        {
            AgentSessionTransferPhase::AwaitingTarget => (
                transfer.target_kind.source(),
                transfer.target_kind.label(),
                transfer.target_session_ref.as_ref(),
                transfer.target_kind,
                transfer.target_sessions_root.clone(),
            ),
            AgentSessionTransferPhase::Completed if transfer.awaiting_deferred_target_report => (
                transfer.target_kind.source(),
                transfer.target_kind.label(),
                transfer.target_session_ref.as_ref(),
                transfer.target_kind,
                transfer.target_sessions_root.clone(),
            ),
            AgentSessionTransferPhase::RollingBack => (
                transfer.source_session.source.as_str(),
                transfer.source_session.agent.as_str(),
                Some(&transfer.source_session.session_ref),
                transfer.source_kind,
                transfer.source_sessions_root.clone(),
            ),
            _ => return,
        };
        let normalized_report_ref = session_ref.and_then(|reported| {
            if expected_kind != HarnessKind::Omp {
                return Some(reported.clone());
            }
            if reported.kind != crate::agent_resume::AgentSessionRefKind::Path {
                return None;
            }
            crate::session_transfer::validate_transcript_path(
                &trust_root,
                std::path::Path::new(&reported.value),
            )
            .ok()
            .and_then(|path| AgentSessionRef::path(path.to_string_lossy().into_owned()))
        });
        let report_matches = source == expected_source
            && agent_label == expected_agent
            && normalized_report_ref.as_ref() == expected_ref;
        if !report_matches {
            if phase == AgentSessionTransferPhase::AwaitingTarget
                || phase == AgentSessionTransferPhase::Completed
            {
                self.begin_agent_session_transfer_rollback(
                    &terminal_id,
                    "target launched but reported a different native session",
                );
            } else if phase == AgentSessionTransferPhase::RollingBack {
                let terminal = self
                    .state
                    .terminals
                    .get_mut(&terminal_id)
                    .expect("terminal exists");
                let transfer = terminal.session_transfer.as_mut().expect("transfer exists");
                let source_session = transfer.source_session.clone();
                transfer.phase = AgentSessionTransferPhase::Failed;
                transfer.error = Some(
                    "target failed and the source rollback reported a different native session"
                        .to_string(),
                );
                transfer.target_deadline = None;
                transfer.verification_in_flight = None;
                transfer.verification_observation_deadline = None;
                terminal.hook_authority = None;
                terminal.set_persisted_agent_session(source_session);
                self.schedule_session_save();
            }
            return;
        }

        if expected_kind == HarnessKind::Omp {
            let (Some(cursor), Some(process_pid)) = (session_cursor, process_pid) else {
                if phase == AgentSessionTransferPhase::RollingBack {
                    self.fail_agent_session_transfer_rollback_launch(
                        &terminal_id,
                        "the official OMP source report omitted its active leaf or process PID",
                    );
                } else {
                    self.begin_agent_session_transfer_rollback(
                        &terminal_id,
                        "the official OMP target report omitted its active leaf or process PID",
                    );
                }
                return;
            };
            let foreground_job = self
                .terminal_runtimes
                .get(&terminal_id)
                .and_then(|runtime| runtime.child_pid())
                .and_then(crate::detect::foreground_job);
            if foreground_job
                .as_ref()
                .and_then(|job| crate::session_transfer::omp_reported_process(job, process_pid))
                != Some(process_pid)
            {
                if phase == AgentSessionTransferPhase::RollingBack {
                    self.fail_agent_session_transfer_rollback_launch(
                        &terminal_id,
                        format!("OMP source report named PID {process_pid}, which is not the current foreground OMP process"),
                    );
                } else {
                    self.begin_agent_session_transfer_rollback(
                        &terminal_id,
                        format!("OMP target report named PID {process_pid}, which is not the current foreground OMP process"),
                    );
                }
                return;
            }
            let now = Instant::now();
            if let Some(transfer) = self
                .state
                .terminals
                .get_mut(&terminal_id)
                .and_then(|terminal| terminal.session_transfer.as_mut())
            {
                let proof = VerifiedTargetProcess {
                    pid: process_pid,
                    observed_at: now,
                };
                match phase {
                    AgentSessionTransferPhase::AwaitingTarget => {
                        transfer.target_cursor = Some(cursor.to_string());
                        transfer.target_process = Some(proof);
                        transfer.target_report_accepted = true;
                    }
                    AgentSessionTransferPhase::RollingBack => {
                        transfer.source_cursor = Some(cursor.to_string());
                        transfer.source_rollback_process = Some(proof);
                    }
                    _ => {}
                }
            }
            self.schedule_session_save();
            self.reconcile_codex_session_transfer_readiness_with_job(
                &terminal_id,
                now,
                foreground_job.as_ref(),
            );
            self.reconcile_codex_session_transfer_rollback_with_job(
                &terminal_id,
                now,
                foreground_job.as_ref(),
            );
            return;
        }

        let terminal = self
            .state
            .terminals
            .get_mut(&terminal_id)
            .expect("terminal exists");
        let transfer = terminal.session_transfer.as_mut().expect("transfer exists");
        transfer.target_deadline = None;
        transfer.verification_in_flight = None;
        transfer.verification_observation_deadline = None;
        match phase {
            AgentSessionTransferPhase::AwaitingTarget => {
                transfer.phase = AgentSessionTransferPhase::Completed;
                transfer.error = None;
                transfer.awaiting_deferred_target_report = false;
                transfer.target_report_accepted = true;
            }
            AgentSessionTransferPhase::Completed => {
                transfer.awaiting_deferred_target_report = false;
            }
            AgentSessionTransferPhase::RollingBack => {
                transfer.phase = AgentSessionTransferPhase::RolledBack;
                // Keep the target failure as useful, truthful status.
            }
            _ => {}
        }
        self.schedule_session_save();
    }

    pub(crate) fn reconcile_codex_session_transfer_process(
        &mut self,
        pane_id: crate::layout::PaneId,
        agent: crate::detect::Agent,
    ) -> bool {
        if !matches!(
            agent,
            crate::detect::Agent::Codex | crate::detect::Agent::Omp
        ) {
            return false;
        }
        let Some((_, pane)) = self.find_pane(pane_id) else {
            return false;
        };
        let terminal_id = pane.attached_terminal_id.clone();
        let foreground_job = self
            .terminal_runtimes
            .get(&terminal_id)
            .and_then(|runtime| runtime.child_pid())
            .and_then(crate::detect::foreground_job);
        let now = Instant::now();
        let target_changed = self.reconcile_codex_session_transfer_readiness_with_job(
            &terminal_id,
            // The detector event can have been queued behind a previous runtime.
            // Anchor the proof to this fresh process-tree read, never to the
            // event's older observation timestamp.
            now,
            foreground_job.as_ref(),
        );
        let rollback_changed = self.reconcile_codex_session_transfer_rollback_with_job(
            &terminal_id,
            now,
            foreground_job.as_ref(),
        );
        target_changed || rollback_changed
    }

    pub(crate) fn reconcile_codex_session_transfer_readiness_with_job(
        &mut self,
        terminal_id: &crate::terminal::TerminalId,
        now: Instant,
        foreground_job: Option<&crate::platform::ForegroundJob>,
    ) -> bool {
        let Some(snapshot) = self
            .state
            .terminals
            .get(terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_ref())
            .cloned()
        else {
            return false;
        };
        if snapshot.phase != AgentSessionTransferPhase::AwaitingTarget
            || !matches!(snapshot.target_kind, HarnessKind::Codex | HarnessKind::Omp)
        {
            return false;
        }
        let Some(target_ref) = snapshot.target_session_ref.as_ref() else {
            return self.begin_agent_session_transfer_rollback(
                terminal_id,
                "target launch is missing its staged native session reference",
            );
        };
        let target_session = target_ref.value.as_str();
        let current_pid = foreground_job.and_then(|job| match snapshot.target_kind {
            HarnessKind::Codex => {
                crate::session_transfer::codex_resume_process(job, target_session)
            }
            HarnessKind::Omp => snapshot
                .target_process
                .and_then(|proof| crate::session_transfer::omp_reported_process(job, proof.pid)),
            HarnessKind::Claude => None,
        });
        let mut changed = false;
        if let Some(pid) = current_pid {
            let proof = match snapshot.target_process {
                Some(proof) if proof.pid == pid => proof,
                _ => VerifiedTargetProcess {
                    pid,
                    observed_at: now,
                },
            };
            if snapshot.target_process != Some(proof) {
                if let Some(transfer) = self
                    .state
                    .terminals
                    .get_mut(terminal_id)
                    .and_then(|terminal| terminal.session_transfer.as_mut())
                {
                    transfer.target_process = Some(proof);
                    changed = true;
                }
                tracing::info!(
                    transfer = %snapshot.id,
                    terminal = %terminal_id,
                    target_session = %target_session,
                    target_pid = pid,
                    target_harness = %snapshot.target_kind.label(),
                    "bound session transfer to the exact target process"
                );
            }
        }

        let blocked = self
            .state
            .terminals
            .get(terminal_id)
            .is_some_and(|terminal| terminal.state == AgentState::Blocked);
        if blocked {
            return self.begin_agent_session_transfer_rollback(
                terminal_id,
                format!(
                    "{} resume for session {target_session} stopped at an interactive blocker",
                    snapshot.target_kind.label()
                ),
            ) || changed;
        }

        if snapshot
            .verification_observation_deadline
            .is_some_and(|deadline| now < deadline)
        {
            return changed;
        }

        let proof = self
            .state
            .terminals
            .get(terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_ref())
            .and_then(|transfer| transfer.target_process);
        let deadline_expired = snapshot
            .target_deadline
            .is_some_and(|deadline| now >= deadline);
        let settle_elapsed = snapshot.verification_observation_deadline.is_some()
            || proof.is_some_and(|proof| {
                now >= proof
                    .observed_at
                    .checked_add(crate::app::agents::AGENT_START_SETTLE_DELAY)
                    .unwrap_or(proof.observed_at)
            });
        if !deadline_expired && !settle_elapsed {
            return changed;
        }
        let Some(pid) = current_pid else {
            let reason = match proof {
                Some(proof) => format!(
                    "exact {} resume process {} for session {target_session} exited before cutover verification",
                    snapshot.target_kind.label(), proof.pid
                ),
                None if snapshot.target_kind == HarnessKind::Codex => format!(
                    "target did not expose the exact Codex resume process for session {target_session} before the launch deadline"
                ),
                None => format!(
                    "target did not expose the exact verified {} process for session {target_session} before the launch deadline",
                    snapshot.target_kind.label()
                ),
            };
            return self.begin_agent_session_transfer_rollback(terminal_id, reason) || changed;
        };

        self.start_session_transfer_runtime_verification(
            terminal_id,
            snapshot,
            RuntimeVerificationKind::Target,
            pid,
            now,
        ) || changed
    }

    pub(crate) fn session_transfer_process_exited(
        &mut self,
        pane_id: crate::layout::PaneId,
    ) -> bool {
        let Some((_, pane)) = self.find_pane(pane_id) else {
            return false;
        };
        let terminal_id = pane.attached_terminal_id.clone();
        let transfer_state = self
            .state
            .terminals
            .get(&terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_ref())
            .map(|transfer| {
                (
                    transfer.phase,
                    transfer.target_deadline.is_some(),
                    transfer.target_kind,
                )
            });
        match transfer_state {
            Some((AgentSessionTransferPhase::AwaitingTarget, _, target_kind)) => {
                let reason = match target_kind {
                    HarnessKind::Codex => {
                        "the Codex resume command exited before destination cutover was verified"
                    }
                    HarnessKind::Omp => {
                        "the OMP resume command exited before its session, leaf, and transcript were verified"
                    }
                    HarnessKind::Claude => {
                        "the Claude resume command exited before reporting the verified session"
                    }
                };
                self.begin_agent_session_transfer_rollback(&terminal_id, reason)
            }
            // Beginning rollback first kills the still-live target shell. That
            // PaneDied arrives while the source plan is armed but before the
            // source runtime has launched. Only a RollingBack transfer WITH a
            // launch deadline has actually started the source and can therefore
            // treat this exit as a failed source rollback.
            Some((AgentSessionTransferPhase::RollingBack, true, _)) => self
                .fail_agent_session_transfer_rollback_launch(
                    &terminal_id,
                    "the source resume command exited before reporting its native session",
                ),
            _ => false,
        }
    }

    pub(crate) fn reconcile_codex_session_transfer_rollback_with_job(
        &mut self,
        terminal_id: &crate::terminal::TerminalId,
        now: Instant,
        foreground_job: Option<&crate::platform::ForegroundJob>,
    ) -> bool {
        let Some(snapshot) = self
            .state
            .terminals
            .get(terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_ref())
            .cloned()
        else {
            return false;
        };
        if snapshot.phase != AgentSessionTransferPhase::RollingBack
            || !matches!(snapshot.source_kind, HarnessKind::Codex | HarnessKind::Omp)
        {
            return false;
        }
        let source_session_id = snapshot.source_session.session_ref.value.as_str();
        let current_pid = foreground_job.and_then(|job| match snapshot.source_kind {
            HarnessKind::Codex => {
                crate::session_transfer::codex_resume_process(job, source_session_id)
            }
            HarnessKind::Omp => snapshot
                .source_rollback_process
                .and_then(|proof| crate::session_transfer::omp_reported_process(job, proof.pid)),
            HarnessKind::Claude => None,
        });
        let mut changed = false;
        if let Some(pid) = current_pid {
            let proof = match snapshot.source_rollback_process {
                Some(proof) if proof.pid == pid => proof,
                _ => VerifiedTargetProcess {
                    pid,
                    observed_at: now,
                },
            };
            if snapshot.source_rollback_process != Some(proof) {
                if let Some(transfer) = self
                    .state
                    .terminals
                    .get_mut(terminal_id)
                    .and_then(|terminal| terminal.session_transfer.as_mut())
                {
                    transfer.source_rollback_process = Some(proof);
                    changed = true;
                }
                tracing::info!(
                    transfer = %snapshot.id,
                    terminal = %terminal_id,
                    source_session = %source_session_id,
                    source_pid = pid,
                    source_harness = %snapshot.source_kind.label(),
                    "bound session-transfer rollback to the exact source process"
                );
            }
        }

        let blocked = self
            .state
            .terminals
            .get(terminal_id)
            .is_some_and(|terminal| terminal.state == AgentState::Blocked);
        if blocked {
            return self.fail_agent_session_transfer_rollback_launch(
                terminal_id,
                format!(
                    "the {} source resume for session {source_session_id} stopped at an interactive blocker",
                    snapshot.source_kind.label()
                ),
            ) || changed;
        }

        if snapshot
            .verification_observation_deadline
            .is_some_and(|deadline| now < deadline)
        {
            return changed;
        }

        let proof = self
            .state
            .terminals
            .get(terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_ref())
            .and_then(|transfer| transfer.source_rollback_process);
        let deadline_expired = snapshot
            .target_deadline
            .is_some_and(|deadline| now >= deadline);
        let settle_elapsed = snapshot.verification_observation_deadline.is_some()
            || proof.is_some_and(|proof| {
                now >= proof
                    .observed_at
                    .checked_add(crate::app::agents::AGENT_START_SETTLE_DELAY)
                    .unwrap_or(proof.observed_at)
            });
        if !deadline_expired && !settle_elapsed {
            return changed;
        }
        let Some(pid) = current_pid else {
            let reason = match proof {
                Some(proof) => format!(
                    "exact {} source resume process {} for session {source_session_id} exited before rollback verification",
                    snapshot.source_kind.label(), proof.pid
                ),
                None if snapshot.source_kind == HarnessKind::Codex => format!(
                    "source rollback did not expose the exact Codex resume process for session {source_session_id} before the launch deadline"
                ),
                None => format!(
                    "source rollback did not expose the exact verified {} process for session {source_session_id} before the launch deadline",
                    snapshot.source_kind.label()
                ),
            };
            return self.fail_agent_session_transfer_rollback_launch(terminal_id, reason)
                || changed;
        };

        self.start_session_transfer_runtime_verification(
            terminal_id,
            snapshot,
            RuntimeVerificationKind::SourceRollback,
            pid,
            now,
        ) || changed
    }

    fn start_session_transfer_runtime_verification(
        &mut self,
        terminal_id: &crate::terminal::TerminalId,
        snapshot: RuntimeSessionTransfer,
        kind: RuntimeVerificationKind,
        process_pid: u32,
        now: Instant,
    ) -> bool {
        if snapshot.verification_in_flight.is_some() {
            return false;
        }
        let expected_phase = match kind {
            RuntimeVerificationKind::Target => AgentSessionTransferPhase::AwaitingTarget,
            RuntimeVerificationKind::SourceRollback => AgentSessionTransferPhase::RollingBack,
        };
        let Some(transfer) = self
            .state
            .terminals
            .get_mut(terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_mut())
        else {
            return false;
        };
        if transfer.id != snapshot.id || transfer.phase != expected_phase {
            return false;
        }
        transfer.verification_in_flight = Some(kind);
        // The three-second settle only decides when to start the first
        // background read. A successful first read opens a bounded blocker
        // observation window; the destination is reread at its end so content,
        // not elapsed time, remains the cutover gate. A worker deadline merely
        // prevents a stuck filesystem read from hanging the transaction forever.
        transfer.target_deadline = Some(now + TRANSFER_VERIFICATION_TIMEOUT);
        self.schedule_session_save();

        let event_tx = self.event_tx.clone();
        let worker_terminal_id = terminal_id.clone();
        let worker_transfer_id = snapshot.id.clone();
        let worker = std::thread::Builder::new()
            .name(format!("herdr-session-verify-{}", snapshot.id))
            .spawn(move || {
                let result = snapshot.verified_visible_destination();
                let _ = event_tx.blocking_send(AppEvent::AgentSessionTransferRuntimeVerified {
                    terminal_id: worker_terminal_id,
                    transfer_id: worker_transfer_id,
                    kind,
                    process_pid,
                    result,
                });
            });
        if let Err(error) = worker {
            if let Some(transfer) = self
                .state
                .terminals
                .get_mut(terminal_id)
                .and_then(|terminal| terminal.session_transfer.as_mut())
            {
                transfer.verification_in_flight = None;
            }
            let reason = format!("could not start destination verification worker: {error}");
            return match kind {
                RuntimeVerificationKind::Target => {
                    self.begin_agent_session_transfer_rollback(terminal_id, reason)
                }
                RuntimeVerificationKind::SourceRollback => {
                    self.fail_agent_session_transfer_rollback_launch(terminal_id, reason)
                }
            };
        }
        true
    }

    pub(crate) fn handle_agent_session_transfer_runtime_verified(
        &mut self,
        terminal_id: crate::terminal::TerminalId,
        transfer_id: String,
        kind: RuntimeVerificationKind,
        process_pid: u32,
        result: Result<(), TransferError>,
    ) -> bool {
        let foreground_job = self
            .terminal_runtimes
            .get(&terminal_id)
            .and_then(|runtime| runtime.child_pid())
            .and_then(crate::detect::foreground_job);
        self.handle_agent_session_transfer_runtime_verified_with_job(
            terminal_id,
            transfer_id,
            kind,
            process_pid,
            result,
            foreground_job.as_ref(),
        )
    }

    pub(crate) fn handle_agent_session_transfer_runtime_verified_with_job(
        &mut self,
        terminal_id: crate::terminal::TerminalId,
        transfer_id: String,
        kind: RuntimeVerificationKind,
        process_pid: u32,
        result: Result<(), TransferError>,
        foreground_job: Option<&crate::platform::ForegroundJob>,
    ) -> bool {
        let Some(snapshot) = self
            .state
            .terminals
            .get(&terminal_id)
            .and_then(|terminal| terminal.session_transfer.as_ref())
            .cloned()
        else {
            return false;
        };
        let expected_phase = match kind {
            RuntimeVerificationKind::Target => AgentSessionTransferPhase::AwaitingTarget,
            RuntimeVerificationKind::SourceRollback => AgentSessionTransferPhase::RollingBack,
        };
        if snapshot.id != transfer_id
            || snapshot.phase != expected_phase
            || snapshot.verification_in_flight != Some(kind)
        {
            return false;
        }
        let expected_session_ref = match kind {
            RuntimeVerificationKind::Target => snapshot.target_session_ref.as_ref(),
            RuntimeVerificationKind::SourceRollback => Some(&snapshot.source_session.session_ref),
        };
        let Some(expected_session_ref) = expected_session_ref else {
            let reason = "runtime verification is missing the expected native session reference";
            return match kind {
                RuntimeVerificationKind::Target => {
                    self.begin_agent_session_transfer_rollback(&terminal_id, reason)
                }
                RuntimeVerificationKind::SourceRollback => {
                    self.fail_agent_session_transfer_rollback_launch(&terminal_id, reason)
                }
            };
        };
        let expected_session_id = expected_session_ref.value.as_str();
        let runtime_kind = match kind {
            RuntimeVerificationKind::Target => snapshot.target_kind,
            RuntimeVerificationKind::SourceRollback => snapshot.source_kind,
        };
        let current_pid = foreground_job.and_then(|job| match runtime_kind {
            HarnessKind::Codex => {
                crate::session_transfer::codex_resume_process(job, expected_session_id)
            }
            HarnessKind::Omp => crate::session_transfer::omp_reported_process(job, process_pid),
            HarnessKind::Claude => None,
        });
        if current_pid != Some(process_pid) {
            let reason = format!(
                "exact {} resume process {process_pid} for session {expected_session_id} was no longer current when transcript verification finished",
                runtime_kind.label()
            );
            return match kind {
                RuntimeVerificationKind::Target => {
                    self.begin_agent_session_transfer_rollback(&terminal_id, reason)
                }
                RuntimeVerificationKind::SourceRollback => {
                    self.fail_agent_session_transfer_rollback_launch(&terminal_id, reason)
                }
            };
        }
        let blocked = self
            .state
            .terminals
            .get(&terminal_id)
            .is_some_and(|terminal| terminal.state == AgentState::Blocked);
        if blocked {
            let reason = format!(
                "{} resume for session {expected_session_id} reached an interactive blocker while transcript verification finished",
                runtime_kind.label()
            );
            return match kind {
                RuntimeVerificationKind::Target => {
                    self.begin_agent_session_transfer_rollback(&terminal_id, reason)
                }
                RuntimeVerificationKind::SourceRollback => {
                    self.fail_agent_session_transfer_rollback_launch(&terminal_id, reason)
                }
            };
        }
        if let Err(error) = result {
            let reason = match kind {
                RuntimeVerificationKind::Target => format!(
                    "{} resume process {process_pid} for session {expected_session_id} was alive, but the destination transcript did not verify: {error}",
                    runtime_kind.label()
                ),
                RuntimeVerificationKind::SourceRollback => format!(
                    "{} source resume process {process_pid} for session {expected_session_id} was alive, but the native transcript did not verify: {error}",
                    runtime_kind.label()
                ),
            };
            return match kind {
                RuntimeVerificationKind::Target => {
                    self.begin_agent_session_transfer_rollback(&terminal_id, reason)
                }
                RuntimeVerificationKind::SourceRollback => {
                    self.fail_agent_session_transfer_rollback_launch(&terminal_id, reason)
                }
            };
        }

        if snapshot.verification_observation_deadline.is_none() {
            let Some(transfer) = self
                .state
                .terminals
                .get_mut(&terminal_id)
                .and_then(|terminal| terminal.session_transfer.as_mut())
            else {
                return false;
            };
            transfer.target_deadline = None;
            transfer.verification_in_flight = None;
            transfer.verification_observation_deadline =
                Some(Instant::now() + TRANSFER_BLOCKER_OBSERVATION_DELAY);
            tracing::info!(
                transfer = %snapshot.id,
                terminal = %terminal_id,
                session = %expected_session_id,
                process_pid,
                verification = ?kind,
                "verified native transcript and exact process; observing for a late interactive blocker"
            );
            self.schedule_session_save();
            return true;
        }

        let Some(terminal) = self.state.terminals.get_mut(&terminal_id) else {
            return false;
        };
        let name = terminal.agent_name.clone();
        let Some(transfer) = terminal.session_transfer.as_mut() else {
            return false;
        };
        transfer.target_deadline = None;
        transfer.verification_in_flight = None;
        transfer.verification_observation_deadline = None;
        terminal.hook_authority = None;
        match kind {
            RuntimeVerificationKind::Target => {
                let target_ref = expected_session_ref.clone();
                transfer.phase = AgentSessionTransferPhase::Completed;
                transfer.error = None;
                transfer.target_process = Some(VerifiedTargetProcess {
                    pid: process_pid,
                    observed_at: snapshot
                        .target_process
                        .map_or_else(Instant::now, |proof| proof.observed_at),
                });
                transfer.awaiting_deferred_target_report =
                    runtime_kind == HarnessKind::Codex && !snapshot.target_report_accepted;
                terminal.set_persisted_agent_session(PersistedAgentSession {
                    source: snapshot.target_kind.source().to_string(),
                    agent: snapshot.target_kind.label().to_string(),
                    session_ref: target_ref,
                });
                if let Some(name) = name {
                    terminal.restore_managed_agent(name, snapshot.target_kind.agent());
                }
                tracing::info!(
                    transfer = %snapshot.id,
                    terminal = %terminal_id,
                    target_session = %expected_session_id,
                    target_pid = process_pid,
                    target_harness = %runtime_kind.label(),
                    "completed session transfer from destination transcript and exact process proof"
                );
            }
            RuntimeVerificationKind::SourceRollback => {
                transfer.phase = AgentSessionTransferPhase::RolledBack;
                transfer.source_rollback_process = Some(VerifiedTargetProcess {
                    pid: process_pid,
                    observed_at: snapshot
                        .source_rollback_process
                        .map_or_else(Instant::now, |proof| proof.observed_at),
                });
                terminal.set_persisted_agent_session(snapshot.source_session.clone());
                if let Some(name) = name {
                    terminal.restore_managed_agent(name, snapshot.source_kind.agent());
                }
                tracing::info!(
                    transfer = %snapshot.id,
                    terminal = %terminal_id,
                    source_session = %expected_session_id,
                    source_pid = process_pid,
                    source_harness = %runtime_kind.label(),
                    "completed session-transfer rollback from native transcript and exact source process proof"
                );
            }
        }
        self.schedule_session_save();
        true
    }

    pub(crate) fn expire_session_transfer_deadlines(&mut self, now: Instant) -> bool {
        // Active transfers are rare, but this runs on the app tick. Only inspect
        // a process tree when a Codex/OMP proof has reached its settle point or the
        // launch deadline itself has arrived; normal pane-scaled ticks stay I/O-free.
        let native_due: Vec<_> = self
            .state
            .terminals
            .iter()
            .filter_map(|(terminal_id, terminal)| {
                let transfer = terminal.session_transfer.as_ref()?;
                let proof = match transfer.phase {
                    AgentSessionTransferPhase::AwaitingTarget
                        if matches!(
                            transfer.target_kind,
                            HarnessKind::Codex | HarnessKind::Omp
                        ) =>
                    {
                        transfer.target_process
                    }
                    AgentSessionTransferPhase::RollingBack
                        if matches!(
                            transfer.source_kind,
                            HarnessKind::Codex | HarnessKind::Omp
                        ) =>
                    {
                        transfer.source_rollback_process
                    }
                    _ => return None,
                };
                let deadline_due = transfer
                    .target_deadline
                    .is_some_and(|deadline| deadline <= now);
                if transfer.verification_in_flight.is_some() {
                    return deadline_due.then(|| terminal_id.clone());
                }
                let settle_due = match transfer.verification_observation_deadline {
                    Some(observation_deadline) => observation_deadline <= now,
                    None => proof.is_some_and(|proof| {
                        proof
                            .observed_at
                            .checked_add(crate::app::agents::AGENT_START_SETTLE_DELAY)
                            .is_none_or(|settle| settle <= now)
                    }),
                };
                (deadline_due || settle_due).then(|| terminal_id.clone())
            })
            .collect();
        let mut changed = false;
        for terminal_id in native_due {
            let foreground_job = self
                .terminal_runtimes
                .get(&terminal_id)
                .and_then(|runtime| runtime.child_pid())
                .and_then(crate::detect::foreground_job);
            changed |= self.reconcile_codex_session_transfer_readiness_with_job(
                &terminal_id,
                now,
                foreground_job.as_ref(),
            );
            changed |= self.reconcile_codex_session_transfer_rollback_with_job(
                &terminal_id,
                now,
                foreground_job.as_ref(),
            );
        }

        let expired: Vec<_> = self
            .state
            .terminals
            .iter()
            .filter_map(|(terminal_id, terminal)| {
                terminal
                    .session_transfer
                    .as_ref()
                    .filter(|transfer| {
                        transfer
                            .target_deadline
                            .is_some_and(|deadline| deadline <= now)
                    })
                    .map(|transfer| (terminal_id.clone(), transfer.phase, transfer.target_kind))
            })
            .collect();
        for (terminal_id, phase, target_kind) in expired {
            match phase {
                AgentSessionTransferPhase::VerifyingCutover => {
                    self.fail_session_transfer_before_cutover(
                        &terminal_id,
                        "source and destination fingerprint verification did not finish before its worker deadline; source stayed running",
                    );
                    changed = true;
                }
                AgentSessionTransferPhase::AwaitingTarget => {
                    let verification_in_flight = self
                        .state
                        .terminals
                        .get(&terminal_id)
                        .and_then(|terminal| terminal.session_transfer.as_ref())
                        .is_some_and(|transfer| transfer.verification_in_flight.is_some());
                    let reason = if verification_in_flight {
                        "destination JSONL verification did not finish before its worker deadline"
                    } else if target_kind == HarnessKind::Codex {
                        "target did not expose the exact verified Codex session before the launch deadline"
                    } else {
                        "target did not report the verified session before the launch deadline"
                    };
                    changed |= self.begin_agent_session_transfer_rollback(&terminal_id, reason);
                }
                AgentSessionTransferPhase::RollingBack => {
                    if let Some(transfer) = self
                        .state
                        .terminals
                        .get_mut(&terminal_id)
                        .and_then(|terminal| terminal.session_transfer.as_mut())
                    {
                        transfer.phase = AgentSessionTransferPhase::Failed;
                        transfer.error = Some(if transfer.verification_in_flight.is_some() {
                            "target failed and source rollback JSONL verification did not finish before its worker deadline"
                                .to_string()
                        } else {
                            "target failed and the source rollback did not report its native session before the deadline"
                                .to_string()
                        });
                        transfer.target_deadline = None;
                        transfer.verification_in_flight = None;
                        transfer.verification_observation_deadline = None;
                        changed = true;
                    }
                }
                _ => {}
            }
        }
        if changed {
            self.schedule_session_save();
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::{omp_profile_value_is_named, App, HarnessKind};
    use std::ffi::OsStr;

    #[test]
    fn omp_profile_precedence_matches_native_resolution() {
        assert!(omp_profile_value_is_named(
            Some(OsStr::new("work")),
            Some(OsStr::new("legacy")),
        ));
        assert!(!omp_profile_value_is_named(
            Some(OsStr::new("default")),
            Some(OsStr::new("work")),
        ));
        assert!(!omp_profile_value_is_named(
            Some(OsStr::new("")),
            Some(OsStr::new("work")),
        ));
        assert!(omp_profile_value_is_named(None, Some(OsStr::new("work")),));
        assert!(!omp_profile_value_is_named(None, None));
    }

    #[test]
    fn default_omp_transfer_route_uses_native_profile_precedence() {
        let _guard = crate::config::test_config_env_lock().lock().unwrap();
        let keys = ["HOME", "PI_CODING_AGENT_DIR", "OMP_PROFILE", "PI_PROFILE"];
        let previous = keys.map(|key| (key, std::env::var_os(key)));
        std::env::set_var("HOME", "/tmp/herdr-omp-profile-home");
        std::env::set_var("PI_CODING_AGENT_DIR", "/tmp/herdr-omp-selected");
        std::env::set_var("PI_PROFILE", "work");

        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let app = App::new(
            &crate::config::Config::default(),
            true,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );

        std::env::set_var("OMP_PROFILE", "default");
        assert!(app.resolve_transfer_account(HarnessKind::Omp, None).is_ok());
        std::env::set_var("OMP_PROFILE", "");
        assert!(app.resolve_transfer_account(HarnessKind::Omp, None).is_ok());
        std::env::remove_var("OMP_PROFILE");
        let error = match app.resolve_transfer_account(HarnessKind::Omp, None) {
            Ok(_) => panic!("legacy PI_PROFILE is active only when OMP_PROFILE is absent"),
            Err(error) => error,
        };
        assert_eq!(error.code, "omp_profile_unsupported");

        for (key, value) in previous {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
    }
}
