//! Keeps a CLI stop from taking down the server that hosts the calling pane.
//!
//! A pane inherits `HERDR_SOCKET_PATH` from its server, so `herdr server stop`
//! run inside one targets that server unless something overrides the socket.
//! Path strings cannot tell whether the target is the caller's host: the same
//! server answers on several paths, and pane ids repeat across servers. The
//! guard asks the target for the root process of the pane named by
//! `HERDR_PANE_ID` and treats the target as the caller's host only when this
//! process runs under that root process.

use std::path::Path;
use std::time::Duration;

use crate::api::client::{ApiClient, ApiClientError, ConnectionTarget};
use crate::api::schema::{Method, PaneProcessInfoParams, Request, ResponseResult};
use crate::integration::HERDR_PANE_ID_ENV_VAR;

const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, PartialEq, Eq)]
enum Host {
    /// The target does not run the caller's pane, or nothing answers there.
    Other,
    /// The target runs the pane this process lives in.
    Caller,
    /// The target has a pane with the caller's id, but whether this process
    /// runs in it could not be confirmed.
    Unconfirmed(String),
}

/// Refuses to stop the server at `socket_path` when it hosts the calling pane.
/// `socket_source` says how the socket was chosen. Pass `force` to skip.
pub(super) fn check(socket_path: &Path, socket_source: &str, force: bool) -> Result<(), String> {
    if force {
        return Ok(());
    }
    let Some(pane_id) = super::target::caller_pane_id() else {
        return Ok(());
    };
    let host = classify(probe(socket_path, &pane_id), |pid| {
        crate::platform::current_process_descends_from(pid)
    });
    refusal(&host, socket_path, socket_source, &pane_id).map_or(Ok(()), Err)
}

fn probe(socket_path: &Path, pane_id: &str) -> Result<serde_json::Value, ApiClientError> {
    ApiClient::for_target(ConnectionTarget::SocketPath(socket_path.to_owned()))
        .request_value_with_timeout(
            &Request {
                id: "cli:server:stop-guard".into(),
                method: Method::PaneProcessInfo(PaneProcessInfoParams {
                    pane_id: Some(pane_id.to_owned()),
                }),
            },
            PROBE_TIMEOUT,
        )
}

fn classify(
    response: Result<serde_json::Value, ApiClientError>,
    descends_from: impl FnOnce(u32) -> Option<bool>,
) -> Host {
    let response = match response.and_then(crate::api::client::parse_response_value) {
        Ok(response) => response,
        // Nothing runs there; the stop itself reports that.
        Err(ApiClientError::Io(error)) if super::server_not_running_error(&error) => {
            return Host::Other
        }
        // The pane id is free there, or names a pane with no process, which
        // cannot be where this process runs.
        Err(ApiClientError::ErrorResponse(response))
            if matches!(
                response.error.code.as_str(),
                "pane_not_found" | "pane_unavailable"
            ) =>
        {
            return Host::Other
        }
        Err(error) => return Host::Unconfirmed(format!("pane lookup failed: {error}")),
    };
    let ResponseResult::PaneProcessInfo { process_info } = response.result else {
        return Host::Unconfirmed("pane lookup returned an unexpected result".into());
    };
    let Some(root_pid) = process_info.shell_pid else {
        return Host::Unconfirmed("the server reported no process for the pane".into());
    };
    match descends_from(root_pid) {
        Some(true) => Host::Caller,
        Some(false) => Host::Other,
        None => Host::Unconfirmed("this process's ancestry could not be read".into()),
    }
}

fn refusal(host: &Host, socket_path: &Path, socket_source: &str, pane_id: &str) -> Option<String> {
    let reason = match host {
        Host::Other => return None,
        Host::Caller => format!(
            "that server hosts this pane ({HERDR_PANE_ID_ENV_VAR}={pane_id}), so stopping it ends this shell and every other pane on it"
        ),
        Host::Unconfirmed(why) => format!(
            "it may host this pane ({HERDR_PANE_ID_ENV_VAR}={pane_id}) and {why}"
        ),
    };
    Some(format!(
        "refusing to stop the herdr server at {} ({socket_source}): {reason}. Run this outside herdr or point it at another server; pass --force to stop this server anyway.",
        socket_path.display()
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::schema::{ErrorBody, ErrorResponse, PaneProcessInfo, SuccessResponse};

    fn process_info(shell_pid: Option<u32>) -> Result<serde_json::Value, ApiClientError> {
        Ok(serde_json::to_value(SuccessResponse {
            id: "probe".into(),
            result: ResponseResult::PaneProcessInfo {
                process_info: PaneProcessInfo {
                    pane_id: "w1:p1".into(),
                    shell_pid,
                    foreground_process_group_id: None,
                    tty: None,
                    foreground_processes: Vec::new(),
                },
            },
        })
        .unwrap())
    }

    fn error(code: &str) -> Result<serde_json::Value, ApiClientError> {
        Ok(serde_json::to_value(ErrorResponse {
            id: "probe".into(),
            error: ErrorBody {
                code: code.into(),
                message: format!("{code} message"),
            },
        })
        .unwrap())
    }

    fn never_asked(_: u32) -> Option<bool> {
        panic!("ancestry must not be checked")
    }

    #[test]
    fn the_target_hosts_the_caller_only_when_this_process_runs_under_the_pane_root() {
        let mut asked = None;
        let host = classify(process_info(Some(42)), |pid| {
            asked = Some(pid);
            Some(true)
        });
        assert_eq!(host, Host::Caller);
        assert_eq!(asked, Some(42));
        // Same pane id on another server: its pane root is not our ancestor.
        assert_eq!(
            classify(process_info(Some(42)), |_| Some(false)),
            Host::Other
        );
    }

    #[test]
    fn a_target_without_that_live_pane_or_without_a_server_is_another_server() {
        assert_eq!(classify(error("pane_not_found"), never_asked), Host::Other);
        assert_eq!(
            classify(error("pane_unavailable"), never_asked),
            Host::Other
        );
        for kind in [
            std::io::ErrorKind::NotFound,
            std::io::ErrorKind::ConnectionRefused,
        ] {
            assert_eq!(
                classify(Err(ApiClientError::Io(kind.into())), never_asked),
                Host::Other
            );
        }
    }

    #[test]
    fn an_unanswerable_probe_refuses_rather_than_risking_the_hosting_server() {
        for host in [
            classify(error("unknown_method"), never_asked),
            classify(
                Err(ApiClientError::Io(std::io::ErrorKind::TimedOut.into())),
                never_asked,
            ),
            classify(process_info(None), never_asked),
            classify(process_info(Some(42)), |_| None),
        ] {
            assert!(matches!(host, Host::Unconfirmed(_)), "{host:?}");
        }
    }

    #[test]
    fn the_refusal_names_the_socket_its_source_and_force() {
        let message = refusal(
            &Host::Caller,
            Path::new("/run/herdr/herdr.sock"),
            "from inherited HERDR_SOCKET_PATH",
            "w1:p1",
        )
        .unwrap();
        assert!(message.contains("/run/herdr/herdr.sock"), "{message}");
        assert!(
            message.contains("from inherited HERDR_SOCKET_PATH"),
            "{message}"
        );
        assert!(message.contains("HERDR_PANE_ID=w1:p1"), "{message}");
        assert!(message.contains("--force"), "{message}");
        assert_eq!(
            refusal(
                &Host::Other,
                Path::new("/x.sock"),
                "default socket",
                "w1:p1"
            ),
            None
        );
    }
}
