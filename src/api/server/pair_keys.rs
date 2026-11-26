//! Owner-only `pair.*` RPCs: device keys in this machine's
//! `~/.ssh/authorized_keys`, marked `herdr-pair`. The apps call them on each
//! machine over SSH, so there is no `machine` routing. Federation peers never
//! reach this (the method table denies every `pair.*`), fenced callers are
//! refused by the fence gate (no `pair.*` is on its allow list), owner
//! browsers by the owner gate and guests by theirs (both are allowlists).

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
        Method::PairAddKey(_) | Method::PairKeysList(_) | Method::PairKeysRemove(_)
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
        "pair_unsupported",
        "device keys are available on macOS and Linux only".into(),
    )
}

#[cfg(unix)]
fn handle(request: &Request) -> String {
    use crate::api::schema::{PairKeyInfo, ResponseResult, SuccessResponse};
    use crate::pairing;

    let id = request.id.clone();
    let info = |key: pairing::PairedKey| PairKeyInfo {
        fingerprint: key.fingerprint,
        label: key.label,
        comment: key.comment,
    };
    let path = pairing::authorized_keys_path(&pairing::home_dir());
    let io_error = |err: std::io::Error| ("pair_io_failed", err.to_string());
    let result = match &request.method {
        Method::PairAddKey(params) => {
            pairing::add_paired_key(&path, &params.public_key, &params.label)
                .map(|added| ResponseResult::PairKeyAdded {
                    added: added.added,
                    already: !added.added,
                    fingerprint: added.fingerprint,
                    label: added.label,
                })
                .map_err(|err| (err.code, err.message))
        }
        Method::PairKeysList(_) => pairing::list_paired_keys(&path)
            .map(|keys| ResponseResult::PairKeysList {
                keys: keys.into_iter().map(info).collect(),
            })
            .map_err(io_error),
        Method::PairKeysRemove(params) => pairing::remove_paired_keys(&path, &params.fingerprint)
            .map(|removed| ResponseResult::PairKeysRemoved {
                removed: removed.into_iter().map(info).collect(),
            })
            .map_err(io_error),
        _ => unreachable!("maybe_handle only passes pair.* methods"),
    };
    match result {
        Ok(result) => serde_json::to_string(&SuccessResponse { id, result }).unwrap_or_default(),
        Err((code, message)) => error_response_json(id, code, message),
    }
}
