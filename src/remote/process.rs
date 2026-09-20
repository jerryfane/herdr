use std::io::{self, Read as _};
use std::process::Output;
use std::thread;
use std::time::{Duration, Instant};

const POLL_INTERVAL: Duration = Duration::from_millis(50);

pub(super) fn wait_with_output_timeout(
    child: std::process::Child,
    timeout: Duration,
) -> io::Result<Output> {
    wait_with_output_timeout_or_cancel(child, timeout, || false)
}

pub(super) fn wait_with_output_timeout_or_cancel(
    mut child: std::process::Child,
    timeout: Duration,
    cancelled: impl Fn() -> bool,
) -> io::Result<Output> {
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| io::Error::other("SSH command stdout was not captured"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| io::Error::other("SSH command stderr was not captured"))?;
    let stdout = thread::spawn(move || {
        let mut stdout = stdout;
        let mut bytes = Vec::new();
        stdout.read_to_end(&mut bytes).map(|_| bytes)
    });
    let stderr = thread::spawn(move || {
        let mut stderr = stderr;
        let mut bytes = Vec::new();
        stderr.read_to_end(&mut bytes).map(|_| bytes)
    });
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) => {}
            Err(error) => {
                terminate_child_tree(&mut child);
                let _ = stdout.join();
                let _ = stderr.join();
                return Err(error);
            }
        }
        if cancelled() {
            terminate_child_tree(&mut child);
            let _ = stdout.join();
            let _ = stderr.join();
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "noninteractive SSH command cancelled",
            ));
        }
        if started.elapsed() >= timeout {
            terminate_child_tree(&mut child);
            let _ = stdout.join();
            let _ = stderr.join();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "noninteractive SSH command timed out",
            ));
        }
        thread::sleep(POLL_INTERVAL);
    };
    let stdout = stdout
        .join()
        .map_err(|_| io::Error::other("SSH stdout reader panicked"))??;
    let stderr = stderr
        .join()
        .map_err(|_| io::Error::other("SSH stderr reader panicked"))??;
    Ok(Output {
        status,
        stdout,
        stderr,
    })
}

fn terminate_child_tree(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        if let Ok(process_group_id) = i32::try_from(child.id()) {
            // The caller starts the command as its process-group leader. Killing
            // the group closes descendant-held stdout/stderr pipes as well.
            unsafe {
                libc::kill(-process_group_id, libc::SIGKILL);
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};

    #[test]
    fn timeout_kills_the_child() {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("exec sleep 10")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        crate::platform::configure_status_command(&mut command);
        let started = Instant::now();
        let error = wait_with_output_timeout(command.spawn().unwrap(), Duration::from_millis(25))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(1));
    }

    #[test]
    fn cancellation_kills_the_child() {
        let mut command = Command::new("sh");
        command
            .arg("-c")
            .arg("sleep 10 & wait")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        crate::platform::configure_status_command(&mut command);
        let started = Instant::now();
        let error = wait_with_output_timeout_or_cancel(
            command.spawn().unwrap(),
            Duration::from_secs(10),
            || true,
        )
        .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Interrupted);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
