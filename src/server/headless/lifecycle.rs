use super::*;

const LIVE_HANDOFF_RESPONSE_WRITE_TIMEOUT: Duration = Duration::from_secs(6);

pub(super) fn wait_for_live_handoff_response_write(
    response_write_complete: Option<std::sync::mpsc::Receiver<()>>,
) {
    let Some(response_write_complete) = response_write_complete else {
        return;
    };

    match response_write_complete.recv_timeout(LIVE_HANDOFF_RESPONSE_WRITE_TIMEOUT) {
        Ok(()) => {}
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            warn!("timed out waiting for live handoff response write; old server exiting");
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            warn!("live handoff response writer disconnected; old server exiting");
        }
    }
}

impl HeadlessServer {
    /// Starts the guest relay link once this process owns the panes.
    #[cfg(unix)]
    pub(super) fn start_guest_link(&mut self) {
        if self.guest_link.is_none() {
            self.guest_link = crate::guest::link::GuestLink::start_for_daemon();
        }
    }

    /// Hands the panes to a replacement server. The replacement starts its
    /// guest link only after the handoff commits, so this one stops first:
    /// dropping it returns once its relay socket is closed, so the two never
    /// hold the relay's host slot at once. A failed handoff has already reaped
    /// the replacement, so the link restarts here.
    #[cfg(unix)]
    pub(super) fn perform_live_handoff(
        &mut self,
        params: crate::api::schema::ServerLiveHandoffParams,
    ) -> io::Result<()> {
        self.perform_supervised_live_handoff(params, crate::server::supervision::detect())
    }

    /// [`Self::perform_live_handoff`] for a caller that already asked how this
    /// process is supervised. The single choke point for every handoff, however
    /// it was requested: refuses before a socket is opened or a child spawned
    /// when this process' exit would take the replacement down with it.
    #[cfg(unix)]
    pub(super) fn perform_supervised_live_handoff(
        &mut self,
        params: crate::api::schema::ServerLiveHandoffParams,
        supervision: crate::server::supervision::Supervision,
    ) -> io::Result<()> {
        if supervision.forbids_process_handoff() {
            warn!(
                ?supervision,
                pid = std::process::id(),
                "refusing live handoff: exiting would deactivate the supervising unit and kill the panes"
            );
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                crate::server::supervision::HANDOFF_REFUSAL,
            ));
        }
        info!(?supervision, "live handoff allowed");
        drop(self.guest_link.take());
        let result = self.export_live_handoff(params, supervision.hands_over_main_pid());
        if result.is_err() {
            self.start_guest_link();
        }
        result
    }

    /// `hand_over_main_pid`: this is the main process of a `Type=notify` unit, so
    /// the replacement gets the notification socket, and once it owns the panes
    /// systemd is told it is the unit's main process before this one exits.
    #[cfg(unix)]
    fn export_live_handoff(
        &mut self,
        params: crate::api::schema::ServerLiveHandoffParams,
        hand_over_main_pid: bool,
    ) -> io::Result<()> {
        info!("starting live handoff");
        let import_exe = params.import_exe.as_deref().map(std::path::PathBuf::from);
        let socket_path = crate::server::handoff::handoff_socket_path();
        let token = format!(
            "{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        );
        let listener = match crate::server::handoff::bind_listener(&socket_path) {
            Ok(listener) => listener,
            Err(err) => {
                self.handoff_in_progress = false;
                return Err(err);
            }
        };

        let mut pane_by_terminal = HashMap::new();
        for ws in &self.app.state.workspaces {
            for tab in &ws.tabs {
                for (pane_id, pane) in &tab.panes {
                    pane_by_terminal.insert(pane.attached_terminal_id.clone(), pane_id.raw());
                }
            }
        }

        self.handoff_in_progress = true;
        self.disconnect_all_clients_for_handoff();
        let _ = reject_pending_client_connections(&self.client_listener);

        let mut paused_terminal_ids = Vec::new();
        for terminal_id in pane_by_terminal.keys() {
            if let Some(runtime) = self.app.terminal_runtimes.get(terminal_id) {
                if let Err(err) = runtime.pause_handoff_reader(Duration::from_secs(2)) {
                    self.rollback_handoff_before_commit(&socket_path, &paused_terminal_ids);
                    return Err(err);
                }
                paused_terminal_ids.push(terminal_id.clone());
            }
        }

        let snapshot = crate::persist::capture(
            &self.app.state.workspaces,
            &self.app.state.terminals,
            &self.app.terminal_runtimes,
            self.app.state.active,
            self.app.state.selected,
            &self.app.state.archived_agents,
        );

        let mut handoff_entries = Vec::new();
        for (terminal_id, runtime) in self.app.terminal_runtimes.iter() {
            let Some(pane_id) = pane_by_terminal.get(terminal_id).copied() else {
                continue;
            };
            let mut handoff_runtime = runtime.handoff_runtime_state(pane_id);
            handoff_runtime.agent_state = self
                .app
                .state
                .terminals
                .get(terminal_id)
                .and_then(|terminal| terminal.handoff_agent_state());
            let has_agent_session = self
                .app
                .state
                .terminals
                .get(terminal_id)
                .is_some_and(|terminal| terminal.persisted_agent_session.is_some());
            if !has_agent_session {
                handoff_runtime.initial_history_ansi = runtime.handoff_history_ansi();
            }
            handoff_entries.push((terminal_id.clone(), handoff_runtime));
        }

        let panes = handoff_entries
            .iter()
            .map(|(_, runtime)| runtime.clone())
            .collect();
        let manifest = crate::server::handoff::manifest_for(
            snapshot,
            panes,
            params.expected_protocol,
            params.expected_version,
            self.api_window_title.clone(),
            self.host_shutdown_intent.get(),
        );
        let mut import_child = match crate::server::handoff::spawn_handoff_import(
            import_exe.as_deref(),
            &socket_path,
            &token,
            hand_over_main_pid,
        ) {
            Ok(child) => child,
            Err(err) => {
                self.rollback_handoff_before_commit(&socket_path, &paused_terminal_ids);
                return Err(err);
            }
        };
        let child_pid = import_child.id();
        info!(pid = child_pid, socket = %socket_path.display(), "spawned handoff import server");

        let mut fds = Vec::new();
        let duplicate_result = (|| {
            for (terminal_id, _) in &handoff_entries {
                let Some(runtime) = self.app.terminal_runtimes.get(terminal_id) else {
                    continue;
                };
                fds.push(runtime.duplicate_handoff_fd()?);
            }
            Ok::<(), io::Error>(())
        })();
        if let Err(err) = duplicate_result {
            for fd in fds {
                let _ = unsafe { libc::close(fd) };
            }
            crate::server::handoff::cleanup_failed_import_child(&mut import_child);
            self.rollback_handoff_before_commit(&socket_path, &paused_terminal_ids);
            return Err(err);
        }

        let mut stream = match crate::server::handoff::accept_and_validate_on(
            listener,
            &socket_path,
            &token,
            child_pid,
            &manifest,
        ) {
            Ok(stream) => stream,
            Err(err) => {
                for fd in fds {
                    let _ = unsafe { libc::close(fd) };
                }
                crate::server::handoff::cleanup_failed_import_child(&mut import_child);
                self.rollback_handoff_before_commit(&socket_path, &paused_terminal_ids);
                return Err(err);
            }
        };

        let send_result = crate::server::handoff::send_fds_and_wait_restored(&mut stream, &fds);
        for fd in fds {
            let _ = unsafe { libc::close(fd) };
        }
        if let Err(err) = send_result {
            crate::server::handoff::cleanup_failed_import_child(&mut import_child);
            self.rollback_handoff_before_commit(&socket_path, &paused_terminal_ids);
            return Err(err);
        }

        if let Some(api_server) = &self.api_server {
            let _ = api_server.remove_socket_file_if_owned();
        } else {
            let _ = std::fs::remove_file(crate::api::socket_path());
        }
        let _ = remove_socket_file_if_owned(&self.client_socket_path, &self.client_socket_identity);
        if let Err(err) = crate::server::handoff::wait_ready(&mut stream) {
            crate::server::handoff::cleanup_failed_import_child(&mut import_child);
            match self.wait_then_restore_public_sockets_after_failed_handoff() {
                Ok(()) => {
                    self.rollback_handoff_before_commit(&socket_path, &paused_terminal_ids);
                }
                Err(restore_err) => {
                    self.rollback_handoff_before_commit(&socket_path, &paused_terminal_ids);
                    return Err(io::Error::other(format!(
                        "handoff replacement server did not become ready: {err}; old server could not restore public sockets: {restore_err}"
                    )));
                }
            }
            return Err(io::Error::other(format!(
                "handoff replacement server did not become ready: {err}"
            )));
        }
        // The manager must name the replacement as the unit's main process BEFORE the
        // commit: up to here the handoff is still reversible, after it the old pane
        // runtimes are gone. Only a manager that follows another process aborts it;
        // see `supervision::hand_over_main_pid` for why an unknown owner commits.
        if hand_over_main_pid {
            use crate::server::supervision::MainPidOwner;
            let owner = with_handoff_manager(|manager| {
                crate::server::supervision::hand_over_main_pid(child_pid, manager)
            });
            match owner {
                MainPidOwner::Replacement => info!(
                    pid = child_pid,
                    "systemd follows the replacement as the unit's main process"
                ),
                MainPidOwner::Unknown(err) => tracing::error!(
                    pid = child_pid,
                    err = %err,
                    "systemd may already follow the replacement as main process and won't say; committing, since stopping it could end the unit and every pane"
                ),
                MainPidOwner::Ours(err) => {
                    warn!(
                        pid = child_pid,
                        err = %err,
                        "systemd does not follow the replacement; aborting the handoff"
                    );
                    crate::server::handoff::cleanup_failed_import_child(&mut import_child);
                    let restored = self.wait_then_restore_public_sockets_after_failed_handoff();
                    self.rollback_handoff_before_commit(&socket_path, &paused_terminal_ids);
                    return Err(match restored {
                        Ok(()) => err,
                        Err(restore_err) => io::Error::other(format!(
                            "{err}; old server could not restore public sockets: {restore_err}"
                        )),
                    });
                }
            }
        }
        if let Err(err) = crate::server::handoff::report_committed(&mut stream) {
            // The same rule as before the commit: the replacement is stopped only when
            // the manager follows another process, or stopping it could be the unit's
            // main process dying.
            let owner = hand_over_main_pid.then(|| {
                with_handoff_manager(|manager| {
                    crate::server::supervision::take_main_pid_back(
                        child_pid,
                        std::process::id(),
                        manager,
                        io::Error::new(err.kind(), format!("commit failed: {err}")),
                    )
                })
            });
            match owner {
                Some(owner) if !owner.allows_stopping_the_replacement() => {
                    tracing::error!(
                        pid = child_pid,
                        ?owner,
                        "commit failed while systemd may follow the replacement as main process; not stopping it"
                    );
                    // It never gets the commit, so it gives up and exits on its own
                    // (no signal from here); reap it when it does.
                    std::thread::spawn(move || {
                        let _ = import_child.wait();
                    });
                }
                _ => crate::server::handoff::cleanup_failed_import_child(&mut import_child),
            }
            match self.wait_then_restore_public_sockets_after_failed_handoff() {
                Ok(()) => {
                    self.rollback_handoff_before_commit(&socket_path, &paused_terminal_ids);
                }
                Err(restore_err) => {
                    self.rollback_handoff_before_commit(&socket_path, &paused_terminal_ids);
                    return Err(io::Error::other(format!(
                        "handoff replacement server was ready, but commit failed: {err}; old server could not restore public sockets: {restore_err}"
                    )));
                }
            }
            return Err(err);
        }

        for (terminal_id, runtime) in self.app.terminal_runtimes.drain_for_handoff() {
            if !pane_by_terminal.contains_key(&terminal_id) {
                continue;
            }
            debug!(terminal = %terminal_id, "preserving pane runtime for handoff");
            runtime.preserve_for_handoff();
        }
        crate::server::handoff::wait_owned_ack(&mut stream);
        Ok(())
    }

    pub(super) fn finish_live_handoff_shutdown(&mut self) {
        self.shutting_down = true;
        self.app.state.should_quit = true;
        self.app.policy.persist_session = false;
        info!("live handoff completed; old server exiting");
    }

    #[cfg(not(unix))]
    pub(super) fn perform_live_handoff(
        &mut self,
        _params: crate::api::schema::ServerLiveHandoffParams,
    ) -> io::Result<()> {
        Err(io::Error::other("live handoff is only supported on Unix"))
    }

    #[cfg(unix)]
    fn restore_public_sockets_after_failed_handoff(&mut self) -> io::Result<()> {
        let api_tx = self
            .api_tx
            .clone()
            .ok_or_else(|| io::Error::other("cannot restore api socket without api sender"))?;
        let loaded_config = crate::config::Config::load();
        let api_server = api::start_server_with_stop_control(
            api_tx,
            self.app.event_hub.clone(),
            self.server_stop.clone(),
            &loaded_config.config,
            self.app.federation.clone(),
        )?;

        let client_path = client_socket_path();
        prepare_socket_path(&client_path)?;
        let listener = bind_local_listener(&client_path)?;
        restrict_socket_permissions(&client_path)?;
        let client_socket_identity = socket_file_identity(&client_path)?;
        listener.set_nonblocking(ListenerNonblockingMode::Accept)?;

        self.app
            .set_federation_manager(api_server.federation_manager());
        self.api_server = Some(api_server);
        self.client_listener = listener;
        self.client_socket_path = client_path;
        self.client_socket_identity = client_socket_identity;
        Ok(())
    }

    #[cfg(unix)]
    fn wait_then_restore_public_sockets_after_failed_handoff(&mut self) -> io::Result<()> {
        let timeout = crate::server::handoff::COMMIT_TIMEOUT + Duration::from_secs(2);
        wait_for_old_public_sockets_to_close(timeout)?;
        self.restore_public_sockets_after_failed_handoff()
    }

    #[cfg(unix)]
    fn rollback_handoff_before_commit(
        &mut self,
        socket_path: &Path,
        paused_terminal_ids: &[crate::terminal::TerminalId],
    ) {
        for terminal_id in paused_terminal_ids {
            if let Some(runtime) = self.app.terminal_runtimes.get(terminal_id) {
                runtime.set_handoff_reader_paused(false);
            }
        }
        self.handoff_in_progress = false;
        let _ = std::fs::remove_file(socket_path);
    }

    #[cfg(unix)]
    pub(super) fn nudge_handoff_panes_on_first_client_attach(&mut self) {
        if !self.pending_handoff_repaint_nudge {
            return;
        }
        self.pending_handoff_repaint_nudge = false;
        self.app
            .terminal_runtimes
            .nudge_child_redraw_after_handoff();
    }

    #[cfg(not(unix))]
    pub(super) fn nudge_handoff_panes_on_first_client_attach(&mut self) {}
    /// Initiates graceful shutdown.
    pub(super) fn initiate_shutdown(&mut self) {
        if self.shutting_down {
            return;
        }
        let reason = if self.host_shutdown_requested.load(Ordering::Acquire) {
            ShutdownReason::HostShutdown
        } else {
            self.server_stop
                .take_reason()
                .unwrap_or(ShutdownReason::Unknown)
        };
        info!(%reason, "server shutdown initiated");
        self.shutting_down = true;

        // Clear client-local host graphics, then send ServerShutdown to all connected clients.
        let shutdown_msg = ServerMessage::ServerShutdown {
            reason: Some("server is shutting down".to_owned()),
        };
        self.send_to_all_clients(shutdown_msg);

        // Give client writer threads a moment to flush the shutdown message.
        // A short sleep ensures the message is written to the socket before
        // we close the connections.
        std::thread::sleep(Duration::from_millis(50));

        // Signal the main loop to exit.
        self.should_quit.store(true, Ordering::Release);
        self.app.state.should_quit = true;
    }

    /// Completes the shutdown sequence: send ServerShutdown to clients,
    /// close client connections, remove socket files, and clean up.
    pub(super) async fn complete_shutdown(&mut self) -> io::Result<()> {
        info!("completing server shutdown");
        self.reject_late_client_connections().await;

        // Send ServerShutdown to all remaining clients.
        if !self.clients.is_empty() {
            let shutdown_msg = ServerMessage::ServerShutdown {
                reason: Some("server is shutting down".to_owned()),
            };
            self.send_to_all_clients(shutdown_msg);

            // Give writer threads a moment to flush before closing.
            std::thread::sleep(Duration::from_millis(50));
        }

        // Reject only the requests already queued when shutdown reached cleanup.
        self.reject_queued_api_requests_for_shutdown();

        // Close all client connections.
        let staged_files = self
            .clients
            .drain()
            .flat_map(|(_, client)| client.staged_clipboard_files)
            .collect::<Vec<_>>();
        crate::server::clipboard_image::remove_files(staged_files);

        // Remove socket files.
        self.cleanup_sockets()?;

        Ok(())
    }

    /// Removes socket files created by the server.
    pub(super) fn cleanup_sockets(&self) -> io::Result<()> {
        if let Err(err) =
            remove_socket_file_if_owned(&self.client_socket_path, &self.client_socket_identity)
        {
            if err.kind() != io::ErrorKind::NotFound {
                warn!(
                    path = %self.client_socket_path.display(),
                    err = %err,
                    "failed to remove client socket on shutdown"
                );
            }
        }
        Ok(())
    }
}

#[cfg(unix)]
pub(super) fn wait_for_old_public_sockets_to_close(timeout: Duration) -> io::Result<()> {
    let deadline = Instant::now() + timeout;
    let api_socket = api::socket_path();
    let client_socket = client_socket_path();
    while Instant::now() < deadline {
        let api_open = api_socket.exists() && crate::ipc::connect_local_stream(&api_socket).is_ok();
        let client_open =
            client_socket.exists() && crate::ipc::connect_local_stream(&client_socket).is_ok();
        if !api_open && !client_open {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "old server sockets did not close before handoff import bind",
    ))
}

/// The systemd manager a live handoff talks to, with the test faults applied.
/// `HERDR_TEST_SYSTEMD_HANDOVER_FAIL`: `refused` drops `MAINPID=` for any other
/// process, so the manager processes the barrier but keeps this process as main,
/// as one that refuses the replacement does; `unknown` loses every read-back, as a
/// manager that takes notifications but stops answering queries.
#[cfg(unix)]
fn with_handoff_manager<R>(
    handover: impl FnOnce(crate::server::supervision::Manager<'_>) -> R,
) -> R {
    let fault = std::env::var("HERDR_TEST_SYSTEMD_HANDOVER_FAIL").ok();
    let systemd = crate::server::supervision::Manager::systemd();
    let ours = format!("MAINPID={}", std::process::id());
    let send = |message: &str, deadline: std::time::Instant| {
        if fault.as_deref() == Some("refused") && message != ours {
            return Ok(());
        }
        (systemd.send)(message, deadline)
    };
    let main_pid = |deadline: std::time::Instant| match fault.as_deref() {
        Some("unknown") => None,
        _ => (systemd.main_pid)(deadline),
    };
    handover(crate::server::supervision::Manager {
        send: &send,
        main_pid: &main_pid,
        ..systemd
    })
}
