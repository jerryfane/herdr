//! Owner-only `owner_access.*` RPCs: the owner's browsers allowed on this
//! machine. The apps call them on each machine over SSH, so there is no
//! `machine` routing. Federation peers never reach this (the method table
//! denies every `owner_access.*`), fenced callers are refused by the fence
//! gate (no `owner_access.*` is on its allow list), and guests never reach it
//! (their gate is an allowlist).

use super::write_text_line_allow_disconnect;
use super::{api_method_name, api_response_outcome, error_response_json};
use crate::api::schema::{Method, Request};
use crate::api::transport::ApiStream;

pub(super) fn maybe_handle(
    stream: &mut ApiStream,
    request: &Request,
    changes_ui: bool,
) -> Option<std::io::Result<()>> {
    if !matches!(
        request.method,
        Method::OwnerAccessInfo(_)
            | Method::OwnerAccessList(_)
            | Method::OwnerAccessAdd(_)
            | Method::OwnerAccessRenew(_)
            | Method::OwnerAccessRemove(_)
    ) {
        return None;
    }
    let method = api_method_name(&request.method);
    let response = handle(request);
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

#[cfg(not(unix))]
fn handle(request: &Request) -> String {
    error_response_json(
        request.id.clone(),
        "owner_access_unsupported",
        "owner access is available on macOS and Linux only".into(),
    )
}

#[cfg(unix)]
fn handle(request: &Request) -> String {
    use crate::api::schema::{OwnerScope, ResponseResult, SuccessResponse};
    use crate::guest::owner::{self, RemoveTarget};
    use crate::guest::store::{guest_dir, now_ms};

    let id = request.id.clone();
    let dir = guest_dir();
    let now = now_ms();
    let result = match &request.method {
        Method::OwnerAccessInfo(_) => {
            let relay_url = crate::config::Config::load().config.guest.relay_url;
            owner::info_in(&dir, relay_url).map(|info| ResponseResult::OwnerAccessInfo {
                protocol: owner::PROTOCOL,
                host_id: info.host_id,
                node_pub: info.node_pub,
                relay_url: info.relay_url,
                link: info.link,
                max_ttl_secs: owner::MAX_TTL_SECS,
                scopes: vec![OwnerScope::Chat, OwnerScope::Terminal],
                version: crate::build_info::version(),
            })
        }
        Method::OwnerAccessList(_) => {
            owner::list_in(&dir, now).map(|grants| ResponseResult::OwnerAccessList { grants })
        }
        Method::OwnerAccessAdd(params) => {
            owner::add_in(&dir, &crate::guest::account::Env::PRODUCTION, params, now)
                .map(|(grant, replaced)| ResponseResult::OwnerAccessAdded { grant, replaced })
        }
        Method::OwnerAccessRenew(params) => {
            owner::renew_in(&dir, &params.grant_id, params.ttl_secs, params.scope, now)
                .map(|grant| ResponseResult::OwnerAccessRenewed { grant })
        }
        Method::OwnerAccessRemove(params) => {
            let target = match (
                params.grant_id.as_deref(),
                params.device_pub.as_deref(),
                params.fingerprint.as_deref(),
            ) {
                (Some(grant_id), None, None) => Ok(RemoveTarget::Grant(grant_id)),
                (None, Some(device_pub), None) => Ok(RemoveTarget::Device(device_pub)),
                (None, None, Some(fingerprint)) => Ok(RemoveTarget::Fingerprint(fingerprint)),
                _ => Err((
                    "invalid_params",
                    "pass exactly one of grant_id, device_pub or fingerprint".to_string(),
                )),
            };
            target
                .and_then(|target| owner::remove_in(&dir, target, now))
                .map(|removed| ResponseResult::OwnerAccessRemoved { removed })
        }
        _ => unreachable!("maybe_handle only passes owner_access.* methods"),
    };
    match result {
        Ok(result) => serde_json::to_string(&SuccessResponse { id, result }).unwrap_or_default(),
        Err((code, message)) => error_response_json(id, code, message),
    }
}
