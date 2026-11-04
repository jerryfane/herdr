//! Windows transport for `herdr api-bridge` (see `api_bridge`): a named-pipe
//! connection to the local API endpoint, read by polling `PeekNamedPipe` so
//! another thread can end it, writes that a shutdown cancels with
//! `CancelSynchronousIo`, and a zero-byte write probe on stdout to notice the
//! SSH channel going away.

use std::io::{self, Read, Write};
use std::mem::ManuallyDrop;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use crate::ipc::{LocalStream, LocalStreamReadCount};

/// First wait between polls of a connection with nothing to read. It doubles
/// up to [`READ_POLL_MAX_INTERVAL`] and starts over once data arrives, so a
/// quick reply is seen within a millisecond and an idle subscription costs a
/// few dozen `PeekNamedPipe` calls a second.
const READ_POLL_MIN_INTERVAL: Duration = Duration::from_millis(1);
const READ_POLL_MAX_INTERVAL: Duration = Duration::from_millis(16);
/// The Unix bridge's back-off between stdout polls.
const HANGUP_PROBE_INTERVAL: Duration = Duration::from_millis(50);
/// A shutdown can catch a write after it registered but before it entered the
/// kernel, when there is nothing to cancel yet. It retries this often, for at
/// most [`WRITE_CANCEL_ATTEMPTS`] tries (one second).
const WRITE_CANCEL_RETRY_INTERVAL: Duration = Duration::from_millis(1);
const WRITE_CANCEL_ATTEMPTS: u32 = 1000;

/// A connection to the API pipe. Synchronous named-pipe I/O cannot be woken
/// from another thread by closing the handle. Reads therefore poll
/// `PeekNamedPipe` (as herdr's other Windows pipe readers do) and end at end of
/// file once [`ConnectionShutdown::shut_down`] runs. A write or flush blocked
/// on a peer that stopped reading is cancelled instead. Both behave like a
/// Unix socket after `shutdown(2)`.
pub(super) struct Connection {
    stream: LocalStream,
    shared: Arc<Shared>,
    poll_interval: Duration,
}

#[derive(Default)]
struct Shared {
    shut_down: AtomicBool,
    /// The thread inside a write or flush of the pipe, for `CancelSynchronousIo`.
    writer: Mutex<Option<OwnedHandle>>,
}

impl Shared {
    fn is_shut_down(&self) -> bool {
        self.shut_down.load(Ordering::Acquire)
    }

    fn writer(&self) -> MutexGuard<'_, Option<OwnedHandle>> {
        self.writer.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

pub(super) fn connect(socket_path: &Path) -> io::Result<Connection> {
    Ok(Connection {
        stream: crate::ipc::connect_local_stream(socket_path)?,
        shared: Arc::default(),
        poll_interval: READ_POLL_MIN_INTERVAL,
    })
}

impl Connection {
    /// Runs one blocking pipe write or flush where a shutdown can cancel it.
    fn cancellable<T>(
        &mut self,
        io: impl FnOnce(&mut LocalStream) -> io::Result<T>,
    ) -> io::Result<T> {
        {
            let mut writer = self.shared.writer();
            if self.shared.is_shut_down() {
                return Err(io::ErrorKind::BrokenPipe.into());
            }
            *writer = Some(current_thread()?);
        }
        let result = io(&mut self.stream);
        *self.shared.writer() = None;
        match result {
            Err(_) if self.shared.is_shut_down() => Err(io::ErrorKind::BrokenPipe.into()),
            result => result,
        }
    }
}

/// A real handle to the calling thread (`GetCurrentThread` is only a pseudo
/// handle, meaningless to another thread).
fn current_thread() -> io::Result<OwnedHandle> {
    use windows_sys::Win32::Foundation::{DuplicateHandle, DUPLICATE_SAME_ACCESS};
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, GetCurrentThread};

    let mut handle = std::ptr::null_mut();
    if unsafe {
        DuplicateHandle(
            GetCurrentProcess(),
            GetCurrentThread(),
            GetCurrentProcess(),
            &mut handle,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: DuplicateHandle succeeded, so `handle` is a new handle we own.
    Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
}

impl Read for Connection {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.shared.is_shut_down() {
                return Ok(0);
            }
            match crate::ipc::poll_local_stream_read_count(&mut self.stream, buf)? {
                LocalStreamReadCount::Data(read) => {
                    self.poll_interval = READ_POLL_MIN_INTERVAL;
                    return Ok(read);
                }
                LocalStreamReadCount::Closed => return Ok(0),
                LocalStreamReadCount::Pending => {
                    std::thread::sleep(self.poll_interval);
                    self.poll_interval = (self.poll_interval * 2).min(READ_POLL_MAX_INTERVAL);
                }
            }
        }
    }
}

impl Write for Connection {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.cancellable(|stream| stream.write(buf))
    }

    fn flush(&mut self) -> io::Result<()> {
        self.cancellable(|stream| stream.flush())
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        // interprocess hands a pipe with unflushed writes to a background
        // thread that flushes it before closing. After a shutdown the peer
        // may never read again, so close the handle now instead.
        if self.shared.is_shut_down() {
            let LocalStream::NamedPipe(stream) = &self.stream;
            stream.inner().assume_flushed();
        }
    }
}

/// Ends a [`Connection`] from any thread. Its pending or later reads return
/// end of file, a write or flush blocked in the pipe is cancelled, and later
/// writes fail.
pub(super) struct ConnectionShutdown(Arc<Shared>);

impl ConnectionShutdown {
    pub(super) fn new(conn: &Connection) -> io::Result<Self> {
        Ok(Self(Arc::clone(&conn.shared)))
    }

    pub(super) fn shut_down(&self) {
        use windows_sys::Win32::System::IO::CancelSynchronousIo;

        let mut writer = self.0.writer();
        self.0.shut_down.store(true, Ordering::Release);
        for _ in 0..WRITE_CANCEL_ATTEMPTS {
            let Some(thread) = writer.as_ref() else {
                return;
            };
            // Fails with ERROR_NOT_FOUND while the registered write has not
            // entered the kernel yet. The writer clears its slot when the
            // call returns, so a retry never cancels unrelated I/O.
            if unsafe { CancelSynchronousIo(thread.as_raw_handle()) } != 0 {
                return;
            }
            drop(writer);
            std::thread::sleep(WRITE_CANCEL_RETRY_INTERVAL);
            writer = self.0.writer();
        }
    }
}

/// Returns once stdout loses its peer (or probing it fails).
///
/// Win32-OpenSSH gives the command a pipe per stdio stream, so there is
/// nothing like a Unix socketpair hangup to wait for: stdout's handle is
/// write-only (no `PeekNamedPipe`), and stdin ends when the client merely
/// half-closes it. A zero-byte write to stdout completes at once while sshd
/// still reads it and fails (`ERROR_NO_DATA`) once sshd has closed its end.
/// A console or a file has no reader to lose, so this never returns for one.
pub(super) fn wait_for_output_hangup() {
    use windows_sys::Win32::Storage::FileSystem::{GetFileType, FILE_TYPE_PIPE};

    let stdout = io::stdout();
    let handle = stdout.as_raw_handle();
    if unsafe { GetFileType(handle) } != FILE_TYPE_PIPE {
        loop {
            std::thread::park();
        }
    }
    // SAFETY: the process's stdout handle stays open for the process's whole
    // life, and `ManuallyDrop` keeps this borrowed `File` from closing it.
    let output = ManuallyDrop::new(unsafe { std::fs::File::from_raw_handle(handle) });
    loop {
        std::thread::sleep(HANGUP_PROBE_INTERVAL);
        // Probe under the stdout lock: sshd's pipe is overlapped, and any
        // I/O completing beside a pending std write on it aborts the process
        // (rust-lang/rust#81357).
        let _lock = stdout.lock();
        if probe_output_reader(&output).is_err() {
            return;
        }
    }
}

/// A zero-byte write: succeeds while the pipe's reader is open.
fn probe_output_reader(mut output: &std::fs::File) -> io::Result<()> {
    output.write(&[]).map(drop)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_probe_fails_once_the_reader_closes() {
        let (reader, writer) = io::pipe().unwrap();
        let writer = std::fs::File::from(std::os::windows::io::OwnedHandle::from(writer));

        probe_output_reader(&writer).unwrap();
        drop(reader);

        assert!(probe_output_reader(&writer).is_err());
    }

    #[test]
    fn output_probe_writes_nothing() {
        let (mut reader, writer) = io::pipe().unwrap();
        let mut writer = std::fs::File::from(std::os::windows::io::OwnedHandle::from(writer));

        probe_output_reader(&writer).unwrap();
        writer.write_all(b"line\n").unwrap();
        drop(writer);

        let mut read = Vec::new();
        reader.read_to_end(&mut read).unwrap();
        assert_eq!(read, b"line\n");
    }
}
