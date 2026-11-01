//! Owner-only `guest.*` RPCs. Federation peers never reach this (the method
//! table denies every `guest.*`) and guests never reach it (their gate is an
//! allowlist). A `machine` alias routes the call to that saved SSH machine.

use std::collections::HashMap;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use super::{
    api_method_name, error_response_json, federation_identity_unverified_error,
    proxy_federated_response, stale_peer_generation_response, write_text_line_allow_disconnect,
};
use super::{api_response_outcome, ApiRequestSender};
use crate::api::client::ConnectionTarget;
use crate::api::federation_manager::PeerRoute;
use crate::api::schema::{Method, Request};
use crate::api::transport::ApiStream;

pub(super) fn maybe_handle(
    stream: &mut ApiStream,
    request: &mut Request,
    peers: &HashMap<String, PeerRoute>,
    api_tx: &ApiRequestSender,
    running: &Arc<AtomicBool>,
    changes_ui: bool,
) -> Option<std::io::Result<()>> {
    let machine = match &mut request.method {
        Method::GuestInviteCreate(params) => params.machine.take(),
        Method::GuestList(params) => params.machine.take(),
        Method::GuestRevoke(params) => params.machine.take(),
        Method::GuestUpdate(params) => params.machine.take(),
        Method::GuestAudit(params) => params.machine.take(),
        _ => return None,
    };
    let method = api_method_name(&request.method);
    let response = match machine {
        Some(alias) => route_to_saved_machine(&alias, request, peers, running),
        None => handle_local(request, api_tx),
    };
    let result = write_text_line_allow_disconnect(stream, &response);
    match &result {
        Ok(()) => crate::logging::api_request_completed(
            &request.id,
            method,
            api_response_outcome(&response),
            changes_ui,
        ),
        Err(err) => crate::logging::api_request_failed(&request.id, method, &err.to_string()),
    }
    Some(result)
}

/// Forward to a saved SSH machine through its bridge. Explicit TCP peers are
/// not owner channels, so they are refused.
fn route_to_saved_machine(
    alias: &str,
    request: &Request,
    peers: &HashMap<String, PeerRoute>,
    running: &Arc<AtomicBool>,
) -> String {
    let Some(route) = peers
        .get(alias)
        .filter(|route| matches!(route.target(), ConnectionTarget::SocketPath(_)))
    else {
        return error_response_json(
            request.id.clone(),
            "machine_not_found",
            format!("no saved SSH machine named {alias:?} is connected"),
        );
    };
    if !route.identity_validated() {
        return serde_json::to_string(&federation_identity_unverified_error(
            request.id.clone(),
            alias,
        ))
        .unwrap_or_default();
    }
    let stamp = route.stamp();
    let response = proxy_federated_response(route, &stamp, request, running);
    if route.is_current(&stamp) {
        response
    } else {
        stale_peer_generation_response(request.id.clone(), &stamp)
    }
}

#[cfg(not(unix))]
fn handle_local(request: &Request, _api_tx: &ApiRequestSender) -> String {
    error_response_json(
        request.id.clone(),
        "unsupported",
        "guest access is available on macOS and Linux only".into(),
    )
}

#[cfg(unix)]
fn handle_local(request: &Request, api_tx: &ApiRequestSender) -> String {
    use crate::api::schema::{ResponseResult, SuccessResponse};

    let id = request.id.clone();
    let result = match &request.method {
        Method::GuestInviteCreate(params) => {
            match super::guest_gate::probe_target(api_tx, None, Some(&params.target)) {
                Err(response) => return response,
                Ok(super::guest_gate::Probe { agent: None, .. }) => Err((
                    "agent_not_found",
                    format!("{} is not an agent pane", params.target),
                )),
                Ok(super::guest_gate::Probe {
                    agent: Some(agent),
                    running,
                    ..
                }) => crate::guest::create_invite(
                    &agent,
                    running,
                    &params.name,
                    &params.owner_name,
                    &params.machine_label,
                    params.ttl_secs,
                    params.share_gram,
                    &crate::guest::InviteRelay::configured(),
                )
                .map(
                    |(invite, url, web_url)| ResponseResult::GuestInviteCreated {
                        invite,
                        url,
                        web_url,
                    },
                ),
            }
        }
        Method::GuestList(_) => {
            crate::guest::list().map(|(guests, invites, link)| ResponseResult::GuestList {
                guests,
                invites,
                link,
            })
        }
        Method::GuestRevoke(params) => {
            match crate::guest::revoke(params.guest_id.as_deref(), params.invite_id.as_deref()) {
                Ok(Some(closed_streams)) => Ok(ResponseResult::GuestRevoked {
                    guest_id: params.guest_id.clone(),
                    invite_id: params.invite_id.clone(),
                    closed_streams,
                }),
                Ok(None) => Err((
                    "guest_not_found",
                    "no guest or invite with that id".to_string(),
                )),
                Err(err) => Err(err),
            }
        }
        Method::GuestUpdate(params) => {
            match crate::guest::update(&params.guest_id, params.share_gram) {
                Ok(Some(guest)) => Ok(ResponseResult::GuestUpdated { guest }),
                Ok(None) => Err((
                    "guest_not_found",
                    "no active guest with that id".to_string(),
                )),
                Err(err) => Err(err),
            }
        }
        Method::GuestAudit(params) => {
            crate::guest::read_audit(params.guest_id.as_deref(), params.before_ms, params.limit)
                .map(|entries| ResponseResult::GuestAudit { entries })
        }
        _ => unreachable!("maybe_handle only passes guest.* methods"),
    };
    match result {
        Ok(result) => serde_json::to_string(&SuccessResponse { id, result }).unwrap_or_default(),
        Err((code, message)) => error_response_json(id, code, message),
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::api::schema::GuestListParams;
    use std::io::{BufRead as _, BufReader, Write as _};

    fn list_request() -> Request {
        Request {
            id: "gl".into(),
            method: Method::GuestList(GuestListParams::default()),
        }
    }

    #[test]
    fn machine_routing_reaches_only_saved_ssh_machines() {
        let running = Arc::new(AtomicBool::new(true));
        let tcp = PeerRoute::for_test(ConnectionTarget::Tcp {
            addr: "127.0.0.1:9".parse().unwrap(),
            token: None,
        });
        let peers = HashMap::from([("tcp-peer".to_string(), tcp)]);
        for alias in ["tcp-peer", "missing"] {
            let response = route_to_saved_machine(alias, &list_request(), &peers, &running);
            let value: serde_json::Value = serde_json::from_str(&response).unwrap();
            assert_eq!(value["error"]["code"], "machine_not_found", "{alias}");
        }

        let path = std::env::temp_dir().join(format!(
            "herdr-guest-route-{}-{}",
            std::process::id(),
            crate::guest::store::now_ms()
        ));
        let listener = crate::ipc::bind_local_listener(&path).unwrap();
        let remote = std::thread::spawn(move || {
            use interprocess::local_socket::traits::Listener as _;
            let mut stream = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&mut stream).read_line(&mut line).unwrap();
            writeln!(
                stream,
                r#"{{"id":"gl","result":{{"type":"guest_list","guests":[],"invites":[],"link":{{"state":"up","last_error":null}}}}}}"#
            )
            .unwrap();
            line
        });
        let saved = PeerRoute::for_test(ConnectionTarget::SocketPath(path.clone()));
        let unverified =
            PeerRoute::for_test_unvalidated(ConnectionTarget::SocketPath(path.clone()));
        let peers = HashMap::from([
            ("studio".to_string(), saved),
            ("pending".to_string(), unverified),
        ]);
        let refused = route_to_saved_machine("pending", &list_request(), &peers, &running);
        assert!(
            refused.contains("federation_identity_unverified"),
            "{refused}"
        );
        let response = route_to_saved_machine("studio", &list_request(), &peers, &running);
        assert!(response.contains(r#""state":"up""#), "{response}");
        let forwarded: serde_json::Value = serde_json::from_str(&remote.join().unwrap()).unwrap();
        assert_eq!(forwarded["method"], "guest.list");
        assert!(forwarded["params"].get("machine").is_none(), "{forwarded}");
        let _ = std::fs::remove_file(path);
    }
}
