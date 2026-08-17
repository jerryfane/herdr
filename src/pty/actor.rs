#[cfg(unix)]
mod unix;

#[cfg(unix)]
pub(crate) use unix::*;

#[cfg(windows)]
mod windows {
    use std::io::{Read, Write};
    use std::sync::{mpsc as std_mpsc, Arc, Mutex};
    use std::time::Duration;

    use bytes::Bytes;
    use portable_pty::{MasterPty, PtySize};
    use tokio::sync::mpsc;
    use tracing::{debug, warn};

    pub(crate) struct PtyReadResult {
        pub terminal_responses: Vec<Bytes>,
    }

    type ReadCallback = Box<dyn FnMut(&[u8]) -> PtyReadResult + Send + 'static>;
    type ReaderExitCallback = Box<dyn FnOnce() + Send + 'static>;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    struct PtyResize {
        rows: u16,
        cols: u16,
        cell_width_px: u32,
        cell_height_px: u32,
    }

    struct PtyResizeRequest {
        resize: PtyResize,
        terminal_responses: Vec<Bytes>,
    }

    pub(crate) struct PtyIoActorConfig {
        pub pane_id: u32,
        pub master: Box<dyn MasterPty + Send>,
        pub initially_quiesced: bool,
        pub on_read: ReadCallback,
        pub on_reader_exit: Option<ReaderExitCallback>,
    }

    enum PtyIoControlCommand {
        Resize(PtyResizeRequest),
        Shutdown,
    }

    enum PtyIoDataCommand {
        WriteUserInput(Bytes),
        WriteUserInputAcknowledged {
            bytes: Bytes,
            reply: std_mpsc::Sender<std::io::Result<()>>,
        },
    }

    // Commands multiplexed onto the single dedicated writer thread. Terminal
    // responses and plain user input carry no reply; acknowledged user input
    // carries a reply so the writer can confirm the bytes reached the PTY.
    enum PtyWrite {
        Bytes(Bytes),
        Acknowledged {
            bytes: Bytes,
            reply: std_mpsc::Sender<std::io::Result<()>>,
        },
    }

    #[derive(Clone)]
    pub(crate) struct PtyIoActorHandle {
        data_tx: mpsc::Sender<PtyIoDataCommand>,
        control_tx: std_mpsc::Sender<PtyIoControlCommand>,
        write_tx: std_mpsc::Sender<PtyWrite>,
        response_order: Arc<Mutex<()>>,
        accepting: Arc<Mutex<bool>>,
    }

    impl PtyIoActorHandle {
        pub(crate) async fn write_user_input(
            &self,
            bytes: Bytes,
        ) -> Result<(), mpsc::error::SendError<Bytes>> {
            if !*self
                .accepting
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
            {
                return Err(mpsc::error::SendError(bytes));
            }
            self.data_tx
                .send(PtyIoDataCommand::WriteUserInput(bytes))
                .await
                .map_err(|err| match err.0 {
                    PtyIoDataCommand::WriteUserInput(bytes)
                    | PtyIoDataCommand::WriteUserInputAcknowledged { bytes, .. } => {
                        mpsc::error::SendError(bytes)
                    }
                })
        }

        pub(crate) fn try_write_user_input(
            &self,
            bytes: Bytes,
        ) -> Result<(), mpsc::error::TrySendError<Bytes>> {
            if !*self
                .accepting
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
            {
                return Err(mpsc::error::TrySendError::Closed(bytes));
            }
            self.data_tx
                .try_send(PtyIoDataCommand::WriteUserInput(bytes))
                .map_err(|err| match err {
                    mpsc::error::TrySendError::Full(PtyIoDataCommand::WriteUserInput(bytes))
                    | mpsc::error::TrySendError::Full(
                        PtyIoDataCommand::WriteUserInputAcknowledged { bytes, .. },
                    ) => mpsc::error::TrySendError::Full(bytes),
                    mpsc::error::TrySendError::Closed(PtyIoDataCommand::WriteUserInput(bytes))
                    | mpsc::error::TrySendError::Closed(
                        PtyIoDataCommand::WriteUserInputAcknowledged { bytes, .. },
                    ) => mpsc::error::TrySendError::Closed(bytes),
                })
        }

        pub(crate) fn write_user_input_acknowledged(
            &self,
            bytes: Bytes,
            timeout: Duration,
        ) -> std::io::Result<()> {
            if !*self
                .accepting
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
            {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "PTY actor is not accepting input",
                ));
            }
            let (reply, response) = std_mpsc::channel();
            self.data_tx
                .try_send(PtyIoDataCommand::WriteUserInputAcknowledged { bytes, reply })
                .map_err(|err| match err {
                    mpsc::error::TrySendError::Full(_) => std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "PTY input queue is full",
                    ),
                    mpsc::error::TrySendError::Closed(_) => {
                        std::io::Error::new(std::io::ErrorKind::BrokenPipe, "PTY actor closed")
                    }
                })?;
            response.recv_timeout(timeout).map_err(|err| match err {
                std_mpsc::RecvTimeoutError::Timeout => std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "PTY write acknowledgement timed out",
                ),
                std_mpsc::RecvTimeoutError::Disconnected => std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "PTY actor closed before acknowledging input",
                ),
            })?
        }

        pub(crate) fn write_terminal_response(&self, response: impl FnOnce() -> Option<Bytes>) {
            let _order = self
                .response_order
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if let Some(bytes) = response().filter(|bytes| !bytes.is_empty()) {
                let _ = self.write_tx.send(PtyWrite::Bytes(bytes));
            }
        }

        pub(crate) fn resize(
            &self,
            rows: u16,
            cols: u16,
            cell_width_px: u32,
            cell_height_px: u32,
            terminal_responses: Vec<Bytes>,
        ) {
            let _ = self
                .control_tx
                .send(PtyIoControlCommand::Resize(PtyResizeRequest {
                    resize: PtyResize {
                        rows,
                        cols,
                        cell_width_px,
                        cell_height_px,
                    },
                    terminal_responses,
                }));
        }

        pub(crate) fn shutdown(&self) {
            if let Ok(mut accepting) = self.accepting.lock() {
                *accepting = false;
            }
            let _ = self.control_tx.send(PtyIoControlCommand::Shutdown);
        }
    }

    pub(crate) struct PtyIoActor;

    impl PtyIoActor {
        pub(crate) fn spawn(config: PtyIoActorConfig) -> std::io::Result<PtyIoActorHandle> {
            let PtyIoActorConfig {
                pane_id,
                master,
                initially_quiesced,
                mut on_read,
                on_reader_exit,
            } = config;

            let mut reader = master
                .try_clone_reader()
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            let writer = master
                .take_writer()
                .map_err(|err| std::io::Error::other(err.to_string()))?;
            let (data_tx, data_rx) = mpsc::channel::<PtyIoDataCommand>(1024);
            let (control_tx, control_rx) = std_mpsc::channel::<PtyIoControlCommand>();
            let (write_tx, write_rx) = std_mpsc::channel::<PtyWrite>();
            let response_order = Arc::new(Mutex::new(()));
            let accepting = Arc::new(Mutex::new(!initially_quiesced));

            {
                let accepting = Arc::clone(&accepting);
                std::thread::spawn(move || run_writer_loop(pane_id, write_rx, writer, accepting));
            }

            {
                let write_tx = write_tx.clone();
                std::thread::spawn(move || run_input_bridge(pane_id, data_rx, write_tx));
            }

            {
                let write_tx = write_tx.clone();
                let response_order = Arc::clone(&response_order);
                let accepting = Arc::clone(&accepting);
                std::thread::spawn(move || {
                    let mut buf = [0u8; 8192];
                    loop {
                        match reader.read(&mut buf) {
                            Ok(0) => break,
                            Ok(n) => {
                                let _order = response_order
                                    .lock()
                                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                                let result = on_read(&buf[..n]);
                                if result.terminal_responses.into_iter().any(|response| {
                                    write_tx.send(PtyWrite::Bytes(response)).is_err()
                                }) {
                                    break;
                                }
                            }
                            Err(err) => {
                                debug!(pane_id, err = %err, "windows pty reader failed");
                                break;
                            }
                        }
                    }
                    if let Ok(mut accepting) = accepting.lock() {
                        *accepting = false;
                    }
                    if let Some(on_reader_exit) = on_reader_exit {
                        on_reader_exit();
                    }
                    debug!(pane_id, "windows pty reader thread exiting");
                });
            }

            {
                let write_tx = write_tx.clone();
                std::thread::spawn(move || {
                    for command in control_rx {
                        match command {
                            PtyIoControlCommand::Resize(request) => {
                                let size = request.resize;
                                if let Err(err) = master.resize(PtySize {
                                    rows: size.rows,
                                    cols: size.cols,
                                    pixel_width: size.cell_width_px.min(u16::MAX as u32) as u16,
                                    pixel_height: size.cell_height_px.min(u16::MAX as u32) as u16,
                                }) {
                                    warn!(pane_id, err = %err, "windows pty resize failed");
                                }
                                if request.terminal_responses.into_iter().any(|response| {
                                    write_tx.send(PtyWrite::Bytes(response)).is_err()
                                }) {
                                    break;
                                }
                            }
                            PtyIoControlCommand::Shutdown => break,
                        }
                    }
                    debug!(pane_id, "windows pty control thread exiting");
                });
            }

            Ok(PtyIoActorHandle {
                data_tx,
                control_tx,
                write_tx,
                response_order,
                accepting,
            })
        }
    }

    // Bridges the async input channel onto the single dedicated writer thread,
    // preserving the acknowledged-write reply so the writer can confirm delivery.
    fn run_input_bridge(
        pane_id: u32,
        mut data_rx: mpsc::Receiver<PtyIoDataCommand>,
        write_tx: std_mpsc::Sender<PtyWrite>,
    ) {
        while let Some(command) = data_rx.blocking_recv() {
            let forwarded = match command {
                PtyIoDataCommand::WriteUserInput(bytes) => write_tx.send(PtyWrite::Bytes(bytes)),
                PtyIoDataCommand::WriteUserInputAcknowledged { bytes, reply } => {
                    write_tx.send(PtyWrite::Acknowledged { bytes, reply })
                }
            };
            if forwarded.is_err() {
                break;
            }
        }
        debug!(pane_id, "windows pty input thread exiting");
    }

    // Owns the PTY writer. All writes (terminal responses and user input) are
    // serialized here so there is a single writer with no shared lock. An
    // acknowledged write replies with the write result once it reaches the PTY.
    fn run_writer_loop(
        pane_id: u32,
        write_rx: std_mpsc::Receiver<PtyWrite>,
        mut writer: Box<dyn Write + Send>,
        accepting: Arc<Mutex<bool>>,
    ) {
        for command in write_rx {
            match command {
                PtyWrite::Bytes(bytes) => {
                    if writer.write_all(&bytes).is_err() || writer.flush().is_err() {
                        break;
                    }
                }
                PtyWrite::Acknowledged { bytes, reply } => {
                    let running = *accepting
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let result = if running {
                        match writer.write_all(&bytes) {
                            Ok(()) => writer.flush(),
                            Err(err) => Err(err),
                        }
                    } else {
                        Err(std::io::Error::new(
                            std::io::ErrorKind::BrokenPipe,
                            "PTY actor is not accepting input",
                        ))
                    };
                    let failed = result.is_err();
                    let _ = reply.send(result);
                    if failed {
                        break;
                    }
                }
            }
        }
        debug!(pane_id, "windows pty writer thread exiting");
    }

    #[allow(dead_code)]
    fn _assert_duration_send(_: Duration) {}

    #[cfg(test)]
    mod tests {
        use super::*;

        #[derive(Default)]
        struct WriterState {
            bytes: Vec<u8>,
            flushes: usize,
        }

        struct ChunkedWriter {
            state: Arc<Mutex<WriterState>>,
            max_chunk: usize,
        }

        impl Write for ChunkedWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                let written = bytes.len().min(self.max_chunk);
                self.state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .bytes
                    .extend_from_slice(&bytes[..written]);
                Ok(written)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                self.state
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .flushes += 1;
                Ok(())
            }
        }

        struct ClosedWriter;

        impl Write for ClosedWriter {
            fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "writer closed",
                ))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        fn handle(
            data_tx: mpsc::Sender<PtyIoDataCommand>,
            write_tx: std_mpsc::Sender<PtyWrite>,
            accepting: Arc<Mutex<bool>>,
        ) -> PtyIoActorHandle {
            let (control_tx, _control_rx) = std_mpsc::channel();
            PtyIoActorHandle {
                data_tx,
                control_tx,
                write_tx,
                response_order: Arc::new(Mutex::new(())),
                accepting,
            }
        }

        #[test]
        fn windows_acknowledged_write_completes_partial_writes_and_flushes() {
            let state = Arc::new(Mutex::new(WriterState::default()));
            let writer: Box<dyn Write + Send> = Box::new(ChunkedWriter {
                state: Arc::clone(&state),
                max_chunk: 3,
            });
            let accepting = Arc::new(Mutex::new(true));
            let (write_tx, write_rx) = std_mpsc::channel();
            let writer_thread = {
                let accepting = Arc::clone(&accepting);
                std::thread::spawn(move || run_writer_loop(1, write_rx, writer, accepting))
            };
            let (data_tx, data_rx) = mpsc::channel(4);
            let bridge_thread = {
                let write_tx = write_tx.clone();
                std::thread::spawn(move || run_input_bridge(1, data_rx, write_tx))
            };
            let handle = handle(data_tx, write_tx, accepting);

            handle
                .write_user_input_acknowledged(
                    Bytes::from_static(b"complete partial batch"),
                    Duration::from_secs(1),
                )
                .expect("partial writes must complete before acknowledgement");

            let state = state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            assert_eq!(state.bytes, b"complete partial batch");
            assert_eq!(state.flushes, 1);
            drop(state);
            drop(handle);
            bridge_thread.join().expect("input bridge thread joins");
            writer_thread.join().expect("writer thread joins");
        }

        #[test]
        fn windows_acknowledged_write_reports_closed_writer() {
            let writer: Box<dyn Write + Send> = Box::new(ClosedWriter);
            let accepting = Arc::new(Mutex::new(true));
            let (write_tx, write_rx) = std_mpsc::channel();
            let writer_thread = {
                let accepting = Arc::clone(&accepting);
                std::thread::spawn(move || run_writer_loop(1, write_rx, writer, accepting))
            };
            let (data_tx, data_rx) = mpsc::channel(4);
            let bridge_thread = {
                let write_tx = write_tx.clone();
                std::thread::spawn(move || run_input_bridge(1, data_rx, write_tx))
            };
            let handle = handle(data_tx, write_tx, accepting);

            let err = handle
                .write_user_input_acknowledged(
                    Bytes::from_static(b"prompt"),
                    Duration::from_secs(1),
                )
                .expect_err("closed writer must fail acknowledgement");

            assert_eq!(err.kind(), std::io::ErrorKind::BrokenPipe);
            drop(handle);
            bridge_thread.join().expect("input bridge thread joins");
            writer_thread.join().expect("writer thread joins");
        }

        #[test]
        fn windows_acknowledged_write_reports_queue_backpressure_and_actor_exit() {
            let accepting = Arc::new(Mutex::new(true));
            let (full_tx, _full_rx) = mpsc::channel(1);
            full_tx
                .try_send(PtyIoDataCommand::WriteUserInput(Bytes::from_static(
                    b"fill",
                )))
                .expect("fill data queue");
            let (full_write_tx, _full_write_rx) = std_mpsc::channel();
            let full_handle = handle(full_tx, full_write_tx, Arc::clone(&accepting));
            let full = full_handle
                .write_user_input_acknowledged(
                    Bytes::from_static(b"prompt"),
                    Duration::from_secs(1),
                )
                .expect_err("full queue must reject acknowledged write");
            assert_eq!(full.kind(), std::io::ErrorKind::WouldBlock);

            let (closed_tx, closed_rx) = mpsc::channel(1);
            drop(closed_rx);
            let (closed_write_tx, _closed_write_rx) = std_mpsc::channel();
            let closed_handle = handle(closed_tx, closed_write_tx, accepting);
            let closed = closed_handle
                .write_user_input_acknowledged(
                    Bytes::from_static(b"prompt"),
                    Duration::from_secs(1),
                )
                .expect_err("actor exit must reject acknowledged write");
            assert_eq!(closed.kind(), std::io::ErrorKind::BrokenPipe);
        }
    }
}

#[cfg(windows)]
pub(crate) use windows::*;
