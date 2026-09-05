//! Gram message handlers: the owner<->agent channel surfaced in the app.
//!
//! `gram.send` (agent->owner, push-notified), `gram.post` (owner->agent, shared
//! queue or direct), `gram.list` (audience inferred from the caller pane),
//! `gram.grab` (first-wins claim of a shared item), and `gram.mark_read`.
//!
//! Identity and its guarantees. There is no per-connection identity, so the
//! caller passes its `HERDR_PANE_ID` as `caller_pane_id` and the server resolves
//! it (see [`App::caller_identity`]) to a single label: the agent's **name** when
//! one is set, else the pane's public id. The agent name is the durable choice —
//! it is persisted in the session snapshot and restored across a restart or a
//! live-handoff (the deploy path), which the terminal id is not. It is, however,
//! a NAME: renaming or clearing an agent, moving an unnamed pane between
//! workspaces, or reusing a freed name changes or transfers the identity, and a
//! message or claim is attributed to the identity at the moment it was written.
//! That is deliberate name-semantics, not a safety property: **the grab is
//! first-wins atomic at the storage layer regardless of identity, so no two
//! agents can ever claim the same item.** Identity affects only which items a
//! caller sees as "mine" in the agent view. A durable, immutable, non-reusable
//! identity is tracked as a follow-up.
//!
//! The owner's app sends no `caller_pane_id` (owner view = everything); a
//! `caller_pane_id` that names no live pane is an error, not a silent
//! fall-through to the owner view. Sender/owner attribution is advisory, not
//! authenticated — the trust domain is already flat.
//!
//! The `gram.delete` and `gram.get_file` audience checks carry the same caveat:
//! an agent that supplies its caller pane may only delete or download a message
//! it can see, but "owner" is simply the ABSENCE of a caller pane, so a local
//! caller that omits it acts with owner authority. This is COOPERATIVE FILTERING
//! within a flat trust domain — every local process can already read `gram.json`
//! and the blob files directly — not authenticated isolation, and it must not be
//! relied on to hide a secret from a determined co-resident agent. A
//! capability-bound identity that would make it a real boundary is the
//! durable-identity follow-up (issue #49).

use base64::Engine as _;

use super::responses::{encode_error, encode_success};
use crate::api::schema::{
    GramDeleteParams, GramDirection, GramFileInfo, GramFileUpload, GramGetFileParams,
    GramGrabParams, GramListParams, GramMarkReadParams, GramMessageInfo, GramPostParams,
    GramSendParams, GramUploadChunkParams, GramUploadStreamParams, ResponseResult,
};
use crate::app::App;
use crate::persist::gram::{
    new_id, GramDirection as StoredDirection, GramFile, GramItem, MAX_LABEL_BYTES, MAX_MIME_BYTES,
    MAX_TEXT_BYTES,
};

/// Why a claim could not be completed.
enum GrabError {
    NotFound,
    /// The item is not a shared, still-open queue item (direct message, wrong
    /// direction, or already claimed by name below).
    NotGrabbable,
    /// Already claimed; carries the current grabber's identity.
    AlreadyGrabbed(String),
}

/// The result of a delete attempt, decided under the store lock.
enum DeleteOutcome {
    /// The message was removed. Carries its id so the handler can also delete any
    /// attached file bytes on disk once file attachments exist.
    Deleted(String),
    /// No message with that id.
    NotFound,
    /// The message exists but the calling agent is not involved in it.
    Forbidden,
}

impl App {
    pub(super) fn handle_gram_send(&mut self, id: String, params: GramSendParams) -> String {
        let text = params.text.trim();
        // A file-only message (no caption) is fine; an empty text-only message is
        // not.
        if let Some(err) = validate_text(&id, text, params.file.is_some()) {
            return err;
        }
        if let Some(err) = validate_label(&id, "from", params.from.as_deref()) {
            return err;
        }
        if self.no_session {
            return gram_unavailable(id);
        }

        let from = self.resolve_sender(params.from.as_deref(), params.caller_pane_id.as_deref());
        let message_id = new_id();
        let store_id = crate::persist::machine::get_or_create();
        let file = match attach_file(&id, &message_id, params.file) {
            Ok(file) => file,
            Err(err) => return err,
        };
        let item = GramItem {
            id: message_id,
            direction: StoredDirection::AgentToOwner,
            from: from.clone(),
            to: None,
            text: text.to_string(),
            grabbed_by: None,
            grabbed_unix_ms: None,
            created_unix_ms: super::unix_millis_now(),
            read_by_owner: false,
            file,
            origin_id: store_id.clone(),
        };

        match crate::persist::gram::append(item.clone()) {
            Ok(_) => {
                self.emit_apns_gram_message(&from, text, item.file.as_ref());
                encode_success(
                    id,
                    ResponseResult::GramSent {
                        message: gram_item_to_info(item),
                        store_id,
                    },
                )
            }
            Err(err) => {
                // The record didn't persist; don't leave orphaned attachment bytes.
                crate::persist::gram_files::remove_message_files(&item.id);
                encode_error(id, "gram_store_save_failed", err.to_string())
            }
        }
    }

    pub(super) fn handle_gram_post(&mut self, id: String, params: GramPostParams) -> String {
        let text = params.text.trim();
        if let Some(err) = validate_text(&id, text, params.file.is_some()) {
            return err;
        }
        if let Some(err) = validate_label(&id, "to", params.to.as_deref()) {
            return err;
        }
        if self.no_session {
            return gram_unavailable(id);
        }

        let to = params
            .to
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        // A direct message must name a live agent, else it would be visible to no
        // one and never expire — a silent black hole. Omit `to` for the shared
        // queue instead.
        if let Some(target) = &to {
            if !self.is_live_agent_name(target) {
                return encode_error(
                    id,
                    "invalid_params",
                    format!(
                        "no live agent named '{target}'; omit --to to post to the shared queue"
                    ),
                );
            }
        }

        let message_id = new_id();
        let store_id = crate::persist::machine::get_or_create();
        let file = match attach_file(&id, &message_id, params.file) {
            Ok(file) => file,
            Err(err) => return err,
        };
        let item = GramItem {
            id: message_id,
            direction: StoredDirection::OwnerToAgent,
            from: "owner".to_string(),
            to,
            text: text.to_string(),
            grabbed_by: None,
            grabbed_unix_ms: None,
            created_unix_ms: super::unix_millis_now(),
            // The owner's own message is not an unread inbox item for the owner.
            read_by_owner: true,
            file,
            origin_id: store_id.clone(),
        };

        match crate::persist::gram::append(item.clone()) {
            Ok(_) => encode_success(
                id,
                ResponseResult::GramSent {
                    message: gram_item_to_info(item),
                    store_id,
                },
            ),
            Err(err) => {
                crate::persist::gram_files::remove_message_files(&item.id);
                encode_error(id, "gram_store_save_failed", err.to_string())
            }
        }
    }

    pub(super) fn handle_gram_list(&mut self, id: String, params: GramListParams) -> String {
        if self.no_session {
            return gram_unavailable(id);
        }

        let items = crate::persist::gram::load();
        let filtered = match params.caller_pane_id.as_deref() {
            // A supplied caller pane selects the agent view. Failing open to the
            // owner view (as an earlier version did) would silently drop
            // `only_queue` and return a state-dependent answer; mirror
            // `pane.current`'s pane_not_found instead. (Not a confidentiality
            // boundary — the owner view is reachable by omitting the pane.)
            Some(pane) => {
                // `unread_only` is an owner-view filter with no meaning here; reject
                // the combination rather than silently ignore it.
                if params.unread_only {
                    return encode_error(
                        id,
                        "invalid_params",
                        "unread_only is only valid in the owner view; omit caller_pane_id",
                    );
                }
                let Some(identity) = self.caller_identity(pane) else {
                    return encode_error(
                        id,
                        "unknown_caller",
                        "caller_pane_id is not a known pane; omit it to read as the owner",
                    );
                };
                filter_agent_view(&items, &identity, params.only_queue)
            }
            // No caller pane: the owner (app) view.
            None => filter_owner_view(&items, params.only_queue, params.unread_only),
        };
        // Store order is oldest-first; clients want newest-first.
        let messages: Vec<GramMessageInfo> =
            filtered.into_iter().rev().map(gram_item_to_info).collect();
        encode_success(
            id,
            ResponseResult::GramList {
                messages,
                store_id: crate::persist::machine::get_or_create(),
            },
        )
    }

    pub(super) fn handle_gram_grab(&mut self, id: String, params: GramGrabParams) -> String {
        if let Some(err) = validate_label(&id, "grabbed_by", params.grabbed_by.as_deref()) {
            return err;
        }
        if self.no_session {
            return gram_unavailable(id);
        }

        // Claimant = explicit --as override, else the caller pane's identity.
        let who = params
            .grabbed_by
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| {
                params
                    .caller_pane_id
                    .as_deref()
                    .and_then(|pane| self.caller_identity(pane))
            });
        let Some(who) = who else {
            return encode_error(
                id,
                "unknown_caller",
                "could not resolve the grabbing agent; pass a valid caller_pane_id or grabbed_by",
            );
        };

        let target_id = params.id.clone();
        let now = super::unix_millis_now();
        // The claim runs under the store's advisory lock, and the app loop
        // serializes API requests, so this check-then-set is atomic across both
        // threads and processes — first grab wins, independent of identity. A lost
        // race changes nothing, so it does not rewrite the store.
        let outcome = crate::persist::gram::update_if_changed(move |items| {
            let result = (|| {
                let Some(item) = items.iter_mut().find(|item| item.id == target_id) else {
                    return Err(GrabError::NotFound);
                };
                if item.direction != StoredDirection::OwnerToAgent || item.to.is_some() {
                    return Err(GrabError::NotGrabbable);
                }
                if let Some(existing) = &item.grabbed_by {
                    return Err(GrabError::AlreadyGrabbed(existing.clone()));
                }
                item.grabbed_by = Some(who.clone());
                item.grabbed_unix_ms = Some(now);
                Ok(item.clone())
            })();
            let changed = result.is_ok();
            (result, changed)
        });

        match outcome {
            Ok((Ok(item), _)) => encode_success(
                id,
                ResponseResult::GramGrabbed {
                    message: gram_item_to_info(item),
                },
            ),
            Ok((Err(GrabError::NotFound), _)) => {
                encode_error(id, "not_found", "no gram message with that id")
            }
            Ok((Err(GrabError::NotGrabbable), _)) => encode_error(
                id,
                "not_grabbable",
                "that message is not a shared-queue item",
            ),
            Ok((Err(GrabError::AlreadyGrabbed(owner)), _)) => {
                encode_error(id, "already_grabbed", format!("already grabbed by {owner}"))
            }
            Err(err) => encode_error(id, "gram_store_save_failed", err.to_string()),
        }
    }

    pub(super) fn handle_gram_mark_read(
        &mut self,
        id: String,
        params: GramMarkReadParams,
    ) -> String {
        if self.no_session {
            return gram_unavailable(id);
        }

        let target_id = params.id.clone();
        // Returns (found, changed); a re-mark of an already-read message is found
        // but changes nothing, so it does not rewrite the store.
        let outcome = crate::persist::gram::update_if_changed(move |items| {
            match items.iter_mut().find(|item| item.id == target_id) {
                Some(item) => {
                    let changed = !item.read_by_owner;
                    item.read_by_owner = true;
                    (true, changed)
                }
                None => (false, false),
            }
        });
        match outcome {
            Ok((true, _)) => encode_success(id, ResponseResult::Ok {}),
            Ok((false, _)) => encode_error(id, "not_found", "no gram message with that id"),
            Err(err) => encode_error(id, "gram_store_save_failed", err.to_string()),
        }
    }

    pub(super) fn handle_gram_delete(&mut self, id: String, params: GramDeleteParams) -> String {
        if self.no_session {
            return gram_unavailable(id);
        }

        // Resolve the caller's authority. The owner's app sends no caller pane and
        // may delete anything; an agent supplies its pane and may delete only a
        // message it is involved in. A caller pane that names no live pane is an
        // error, mirroring `gram.list` — not a silent fall-through to owner power.
        let identity = match params.caller_pane_id.as_deref() {
            Some(pane) => match self.caller_identity(pane) {
                Some(identity) => Some(identity),
                None => {
                    return encode_error(
                        id,
                        "unknown_caller",
                        "caller_pane_id is not a known pane; omit it to delete as the owner",
                    );
                }
            },
            None => None,
        };

        let target_id = params.id.clone();
        // The decision (find, authorize, remove) is pure over the list so it is
        // unit-tested without an App; the store is rewritten only when a message
        // was actually removed, so a not-found / forbidden delete does not churn
        // the file.
        let outcome = crate::persist::gram::update_if_changed(move |items| {
            apply_delete(items, &target_id, identity.as_deref())
        });

        match outcome {
            Ok((DeleteOutcome::Deleted(removed_id), _)) => {
                // Remove the attachment bytes too, so a secret (a temporary API key
                // sent as a file) does not outlive the record it was deleted with.
                crate::persist::gram_files::remove_message_files(&removed_id);
                encode_success(id, ResponseResult::Ok {})
            }
            Ok((DeleteOutcome::NotFound, _)) => {
                encode_error(id, "not_found", "no gram message with that id")
            }
            Ok((DeleteOutcome::Forbidden, _)) => encode_error(
                id,
                "forbidden",
                "you can only delete a gram message you sent, grabbed, or that is addressed to you",
            ),
            Err(err) => encode_error(id, "gram_store_save_failed", err.to_string()),
        }
    }

    pub(super) fn handle_gram_upload_chunk(
        &mut self,
        id: String,
        params: GramUploadChunkParams,
    ) -> String {
        if self.no_session {
            return gram_unavailable(id);
        }
        // Single writer per upload_id. A live `gram.upload.stream` channel appends
        // on the server thread with no lock, and an `offset: 0` chunk here would
        // TRUNCATE the staging file, discarding bytes that channel already acked.
        // The offset rule would make the result loud rather than silent, but a
        // second writer on one upload is always a client bug: refuse it.
        if crate::api::upload_id_is_streaming(&params.upload_id) {
            return encode_error(
                id,
                "upload_in_progress",
                "another stream is already uploading this upload_id",
            );
        }
        let bytes = match base64::engine::general_purpose::STANDARD
            .decode(params.data_base64.as_bytes())
        {
            Ok(bytes) => bytes,
            Err(_) => return encode_error(id, "invalid_params", "data_base64 is not valid base64"),
        };
        match crate::persist::gram_files::append_chunk(&params.upload_id, params.offset, &bytes) {
            Ok(()) => encode_success(id, ResponseResult::Ok {}),
            Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => {
                encode_error(id, "invalid_params", err.to_string())
            }
            Err(err) => encode_error(id, "gram_file_error", err.to_string()),
        }
    }

    /// Validates a streaming upload before the server thread starts reading frames.
    /// `no_session` is the ONLY app-owned state the per-chunk handler consults; every
    /// other step (base64 decode, `append_chunk`) is pure filesystem and runs on the
    /// server thread, so this is the whole app-side cost of a streamed upload.
    pub(super) fn handle_gram_upload_stream_open(
        &mut self,
        id: String,
        _params: GramUploadStreamParams,
    ) -> String {
        if self.no_session {
            return gram_unavailable(id);
        }
        encode_success(id, ResponseResult::Ok {})
    }

    pub(super) fn handle_gram_get_file(&mut self, id: String, params: GramGetFileParams) -> String {
        if self.no_session {
            return gram_unavailable(id);
        }
        // Resolve the caller's authority: the owner (no caller pane) may download
        // any file; an agent may download only a file on a message it can see.
        let identity = match params.caller_pane_id.as_deref() {
            Some(pane) => match self.caller_identity(pane) {
                Some(identity) => Some(identity),
                None => {
                    return encode_error(
                        id,
                        "unknown_caller",
                        "caller_pane_id is not a known pane; omit it to read as the owner",
                    );
                }
            },
            None => None,
        };
        let Some(item) = crate::persist::gram::load()
            .into_iter()
            .find(|item| item.id == params.id)
        else {
            return encode_error(id, "not_found", "no gram message with that id");
        };
        if let Some(identity) = &identity {
            if !agent_can_see(&item, identity) {
                return encode_error(
                    id,
                    "forbidden",
                    "you can only download a file on a message you can see",
                );
            }
        }
        let Some(file) = item.file else {
            return encode_error(id, "no_file", "that message has no attached file");
        };
        match crate::persist::gram_files::read_message_file(&item.id, &file.name) {
            Ok(bytes) => {
                let data_base64 = base64::engine::general_purpose::STANDARD.encode(&bytes);
                encode_success(
                    id,
                    ResponseResult::GramFileContent {
                        name: file.name,
                        mime: file.mime,
                        size: file.size,
                        data_base64,
                    },
                )
            }
            Err(err) => encode_error(id, "gram_file_error", format!("failed to read file: {err}")),
        }
    }

    /// Resolve the label to record as `from` for an agent->owner message: an
    /// explicit override, else the caller pane's identity, else "agent". An
    /// explicit `from` overrides attribution entirely (the message is then
    /// attributed to that label, not the caller), which the CLI help notes.
    fn resolve_sender(&self, from: Option<&str>, caller_pane_id: Option<&str>) -> String {
        from.map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| caller_pane_id.and_then(|pane| self.caller_identity(pane)))
            .unwrap_or_else(|| "agent".to_string())
    }

    /// Resolve a public pane id (an agent's `HERDR_PANE_ID`) to its identity: the
    /// per-agent name if set (durable across restart / live-handoff, since it is
    /// snapshotted and restored), else the pane's public id. `None` only when the
    /// pane id names no known pane. See the module header for the name-semantics
    /// this identity carries.
    fn caller_identity(&self, caller_pane_id: &str) -> Option<String> {
        let (ws_idx, pane_id) = self.parse_pane_id(caller_pane_id)?;
        let terminal_id = self.state.workspaces.get(ws_idx)?.terminal_id(pane_id)?;
        self.state
            .terminals
            .get(terminal_id)
            .and_then(|terminal| terminal.agent_name.clone())
            .filter(|name| !name.trim().is_empty())
            .or_else(|| self.public_pane_id(ws_idx, pane_id))
    }

    /// Whether some live terminal has this exact unique agent name. Used to reject
    /// a direct `gram.post` to a nonexistent agent instead of black-holing it.
    fn is_live_agent_name(&self, name: &str) -> bool {
        self.state
            .terminals
            .values()
            .any(|terminal| terminal.agent_name.as_deref() == Some(name))
    }

    /// Deliver one gram alert to registered devices that opted into gram push.
    /// A sibling of `emit_apns_agent_notifications`: detached, best-effort, guarded
    /// by `crate::push::enabled`. The alert deep-links to the app's Gram page, so
    /// it carries no pane/workspace id (the payload's `gram` marker signals this).
    fn emit_apns_gram_message(&self, from: &str, text: &str, file: Option<&GramFile>) {
        if self.no_session || !crate::push::enabled(&self.state.push_config) {
            return;
        }
        let title =
            super::sanitized_notification_text(from, 80).unwrap_or_else(|| "New gram".to_string());
        let mut body = super::sanitized_notification_text(text, 240).unwrap_or_default();
        // Note an attachment so a file-only (or captioned) gram reads sensibly on
        // the lock screen. The name is already a sanitized basename.
        if let Some(file) = file {
            let hint = format!("📎 {}", file.name);
            body = if body.is_empty() {
                hint
            } else {
                format!("{body}\n{hint}")
            };
        }
        let notification = crate::push::PushNotification {
            title,
            body,
            pane_id: String::new(),
            workspace_id: String::new(),
            kind: crate::push::PushKind::Gram,
        };
        let cfg = self.state.push_config.clone();
        if let Err(err) = std::thread::Builder::new()
            .name("herdr-push-gram".to_string())
            .spawn(move || crate::push::deliver(cfg, vec![notification]))
        {
            tracing::warn!(error = %err, "failed to spawn gram push sender thread; dropping message");
        }
    }
}

/// Reject an over-long message, and an empty one unless a file is attached (a
/// file with no caption is fine). Returns the encoded error response, or `None`
/// when the text is acceptable.
fn validate_text(id: &str, text: &str, allow_empty: bool) -> Option<String> {
    if text.is_empty() && !allow_empty {
        return Some(encode_error(
            id.to_string(),
            "invalid_params",
            "text is empty",
        ));
    }
    if text.len() > MAX_TEXT_BYTES {
        return Some(encode_error(
            id.to_string(),
            "invalid_params",
            format!("text exceeds {MAX_TEXT_BYTES} bytes; send large content as a file"),
        ));
    }
    None
}

/// Assemble a staged upload onto `message_id`, returning its metadata for the
/// record. No file → `Ok(None)`. A bad upload (missing/oversized/invalid id or
/// name) returns an encoded error response so the caller can return it directly.
fn attach_file(
    request_id: &str,
    message_id: &str,
    upload: Option<GramFileUpload>,
) -> Result<Option<GramFile>, String> {
    let Some(upload) = upload else {
        return Ok(None);
    };
    if upload.name.trim().is_empty() {
        return Err(encode_error(
            request_id.to_string(),
            "invalid_params",
            "file.name is empty",
        ));
    }
    // The mime is caller-supplied and persisted in gram.json, which the store's
    // byte budget does NOT count (it budgets text). Cap it so a caller cannot
    // smuggle large data through this field and bloat the store past its budget.
    if let Some(err) = validate_mime(request_id, &upload.mime) {
        return Err(err);
    }
    // Finalize is the OTHER writer on a staging file, and it is no longer serialized
    // against appends: before streaming, every chunk ran on this single-threaded app
    // loop, so a finalize could not overlap one. Now appends run on the API server
    // thread, and `finalize` reads the size, hashes the file, then renames it — so a
    // frame landing mid-sequence would record a sha256 taken over more bytes than the
    // recorded size, and an append after the rename would land INSIDE the finalized
    // message file. That is silent corruption of the integrity fields a client
    // verifies a download against, so refuse while a stream owns the upload.
    if crate::api::upload_id_is_streaming(&upload.upload_id) {
        return Err(encode_error(
            request_id.to_string(),
            "upload_in_progress",
            "a stream is still uploading this upload_id; close it before attaching",
        ));
    }
    match crate::persist::gram_files::finalize(message_id, &upload.upload_id, &upload.name) {
        Ok(finalized) => Ok(Some(GramFile {
            name: finalized.name,
            size: finalized.size,
            mime: upload.mime,
            sha256: finalized.sha256,
        })),
        // A malformed upload (unknown id, empty or oversized staging, bad name) is
        // the caller's mistake; anything else is a real I/O failure.
        Err(err) if err.kind() == std::io::ErrorKind::InvalidInput => Err(encode_error(
            request_id.to_string(),
            "invalid_params",
            err.to_string(),
        )),
        Err(err) => Err(encode_error(
            request_id.to_string(),
            "gram_file_error",
            err.to_string(),
        )),
    }
}

/// Reject a persisted `mime` longer than [`MAX_MIME_BYTES`], so a caller cannot
/// smuggle large data through the one attachment field the store's text budget
/// does not count. Separate from [`validate_label`] because mime has its own,
/// larger bound.
fn validate_mime(id: &str, mime: &str) -> Option<String> {
    if mime.len() > MAX_MIME_BYTES {
        return Some(encode_error(
            id.to_string(),
            "invalid_params",
            format!("file.mime exceeds {MAX_MIME_BYTES} bytes"),
        ));
    }
    None
}

/// Reject a persisted label override (`from`, `to`, `grabbed_by`) longer than
/// [`MAX_LABEL_BYTES`], so a caller cannot bypass the text budget through them.
/// Measured after trimming, matching what the handlers persist.
fn validate_label(id: &str, field: &str, value: Option<&str>) -> Option<String> {
    match value.map(str::trim) {
        Some(value) if value.len() > MAX_LABEL_BYTES => Some(encode_error(
            id.to_string(),
            "invalid_params",
            format!("{field} exceeds {MAX_LABEL_BYTES} bytes"),
        )),
        _ => None,
    }
}

fn gram_unavailable(id: String) -> String {
    encode_error(
        id,
        "gram_unavailable",
        "gram requires the shared herdr server",
    )
}

fn gram_item_to_info(item: GramItem) -> GramMessageInfo {
    GramMessageInfo {
        id: item.id,
        direction: match item.direction {
            StoredDirection::AgentToOwner => GramDirection::AgentToOwner,
            StoredDirection::OwnerToAgent => GramDirection::OwnerToAgent,
        },
        from: item.from,
        to: item.to,
        text: item.text,
        grabbed_by: item.grabbed_by,
        grabbed_unix_ms: item.grabbed_unix_ms,
        created_unix_ms: item.created_unix_ms,
        read_by_owner: item.read_by_owner,
        file: item.file.map(|file| GramFileInfo {
            name: file.name,
            size: file.size,
            mime: file.mime,
            sha256: file.sha256,
        }),
        origin_id: item.origin_id,
    }
}

/// True for a shared, still-open queue item any agent may claim.
fn is_open_shared_queue(item: &GramItem) -> bool {
    item.direction == StoredDirection::OwnerToAgent
        && item.to.is_none()
        && item.grabbed_by.is_none()
}

/// Whether an agent identity may delete a message: it sent it, it is addressed to
/// it, or it grabbed it. The owner (no caller pane) bypasses this check entirely.
/// This is the same "involved in it" relation the agent view uses for membership,
/// minus the shared open queue — an agent should not be able to delete unclaimed
/// work it never touched out from under the owner.
fn agent_may_delete(item: &GramItem, identity: &str) -> bool {
    let sent_by_me = item.direction == StoredDirection::AgentToOwner && item.from == identity;
    let addressed_to_me =
        item.direction == StoredDirection::OwnerToAgent && item.to.as_deref() == Some(identity);
    let grabbed_by_me = item.grabbed_by.as_deref() == Some(identity);
    sent_by_me || addressed_to_me || grabbed_by_me
}

/// Decide and apply a delete against the in-memory list. `identity` is `None` for
/// the owner (may delete any message) or `Some(agent)` (may delete only a message
/// it is involved in). Returns the outcome plus whether the list changed, matching
/// [`crate::persist::gram::update_if_changed`]'s mutation contract — the store is
/// rewritten only on an actual removal. Pure over the list so the find/authorize/
/// remove logic is unit-tested without an App or the store.
fn apply_delete(
    items: &mut Vec<GramItem>,
    id: &str,
    identity: Option<&str>,
) -> (DeleteOutcome, bool) {
    let Some(pos) = items.iter().position(|item| item.id == id) else {
        return (DeleteOutcome::NotFound, false);
    };
    if let Some(identity) = identity {
        if !agent_may_delete(&items[pos], identity) {
            return (DeleteOutcome::Forbidden, false);
        }
    }
    let removed = items.remove(pos);
    (DeleteOutcome::Deleted(removed.id), true)
}

/// Whether a message belongs in an agent's view: the shared ungrabbed queue, an
/// item addressed to it, one it grabbed, or one it sent. This is the audience
/// boundary — an agent may list and download the files of what it can see, but not
/// another agent's direct message (which is how a secret is sent). The owner (no
/// caller pane) can see everything.
fn agent_can_see(item: &GramItem, identity: &str) -> bool {
    let addressed_to_me =
        item.direction == StoredDirection::OwnerToAgent && item.to.as_deref() == Some(identity);
    let grabbed_by_me = item.grabbed_by.as_deref() == Some(identity);
    let sent_by_me = item.direction == StoredDirection::AgentToOwner && item.from == identity;
    is_open_shared_queue(item) || addressed_to_me || grabbed_by_me || sent_by_me
}

/// The agent's view: the shared ungrabbed queue, items addressed to it, items it
/// grabbed, and its own sent messages. `only_queue` narrows to just the shared,
/// still-open queue so an agent can quickly scan available work. Membership is by
/// the caller's current identity (see the module header for the name-semantics).
fn filter_agent_view(items: &[GramItem], identity: &str, only_queue: bool) -> Vec<GramItem> {
    items
        .iter()
        .filter(|item| {
            if only_queue {
                return is_open_shared_queue(item);
            }
            agent_can_see(item, identity)
        })
        .cloned()
        .collect()
}

/// The owner's view: the shared open queue (`only_queue`), just unread
/// agent->owner messages (`unread_only`), or everything.
fn filter_owner_view(items: &[GramItem], only_queue: bool, unread_only: bool) -> Vec<GramItem> {
    items
        .iter()
        .filter(|item| {
            if only_queue {
                return is_open_shared_queue(item);
            }
            if unread_only {
                return item.direction == StoredDirection::AgentToOwner && !item.read_by_owner;
            }
            true
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner_shared(id: &str) -> GramItem {
        GramItem {
            id: id.to_string(),
            direction: StoredDirection::OwnerToAgent,
            from: "owner".to_string(),
            to: None,
            text: "shared task".to_string(),
            grabbed_by: None,
            grabbed_unix_ms: None,
            created_unix_ms: 1,
            read_by_owner: true,
            file: None,
            origin_id: "machine_test".to_string(),
        }
    }

    #[test]
    fn agent_view_shows_queue_direct_grabs_and_own_sends() {
        let mut direct = owner_shared("direct");
        direct.to = Some("alpha".to_string());
        let mut grabbed_by_me = owner_shared("mine");
        grabbed_by_me.grabbed_by = Some("alpha".to_string());
        let mut grabbed_by_other = owner_shared("theirs");
        grabbed_by_other.grabbed_by = Some("beta".to_string());
        let mut my_send = owner_shared("sent");
        my_send.direction = StoredDirection::AgentToOwner;
        my_send.from = "alpha".to_string();
        my_send.to = None;

        let items = vec![
            owner_shared("open"),
            direct,
            grabbed_by_me,
            grabbed_by_other,
            my_send,
        ];
        let ids: Vec<String> = filter_agent_view(&items, "alpha", false)
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert!(ids.contains(&"open".to_string()));
        assert!(ids.contains(&"direct".to_string()));
        assert!(ids.contains(&"mine".to_string()));
        assert!(ids.contains(&"sent".to_string()));
        // A shared item grabbed by another agent is hidden.
        assert!(!ids.contains(&"theirs".to_string()));
    }

    #[test]
    fn agent_view_only_queue_is_shared_and_open() {
        let mut grabbed = owner_shared("grabbed");
        grabbed.grabbed_by = Some("beta".to_string());
        let items = vec![owner_shared("open"), grabbed];
        let ids: Vec<String> = filter_agent_view(&items, "alpha", true)
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert_eq!(ids, vec!["open".to_string()]);
    }

    #[test]
    fn owner_view_default_unread_and_queue() {
        let mut unread = owner_shared("unread");
        unread.direction = StoredDirection::AgentToOwner;
        unread.read_by_owner = false;
        let mut read = owner_shared("read");
        read.direction = StoredDirection::AgentToOwner;
        read.read_by_owner = true;
        let mut grabbed = owner_shared("grabbed");
        grabbed.grabbed_by = Some("beta".to_string());

        let items = vec![owner_shared("open"), unread, read, grabbed];

        // Default: everything.
        assert_eq!(filter_owner_view(&items, false, false).len(), 4);
        // unread_only: just the unread agent->owner message.
        let unread_ids: Vec<String> = filter_owner_view(&items, false, true)
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert_eq!(unread_ids, vec!["unread".to_string()]);
        // only_queue: just the shared, still-open item (not the grabbed one).
        let queue_ids: Vec<String> = filter_owner_view(&items, true, false)
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert_eq!(queue_ids, vec!["open".to_string()]);
    }

    #[test]
    fn agent_may_delete_only_own_involvement() {
        // A shared, still-open queue item the agent never touched: not deletable
        // by an agent (only the owner may remove unclaimed work).
        assert!(!agent_may_delete(&owner_shared("open"), "alpha"));

        let mut direct = owner_shared("direct");
        direct.to = Some("alpha".to_string());
        assert!(agent_may_delete(&direct, "alpha"));
        assert!(!agent_may_delete(&direct, "beta"));

        let mut grabbed = owner_shared("grabbed");
        grabbed.grabbed_by = Some("alpha".to_string());
        assert!(agent_may_delete(&grabbed, "alpha"));
        assert!(!agent_may_delete(&grabbed, "beta"));

        let mut sent = owner_shared("sent");
        sent.direction = StoredDirection::AgentToOwner;
        sent.from = "alpha".to_string();
        assert!(agent_may_delete(&sent, "alpha"));
        assert!(!agent_may_delete(&sent, "beta"));
    }

    /// Deleted-id label used by `apply_delete` on success.
    fn deleted_id(outcome: &DeleteOutcome) -> Option<&str> {
        match outcome {
            DeleteOutcome::Deleted(id) => Some(id.as_str()),
            _ => None,
        }
    }

    #[test]
    fn apply_delete_owner_removes_any_message() {
        let mut items = vec![owner_shared("a"), owner_shared("b")];
        let (outcome, changed) = apply_delete(&mut items, "a", None);
        assert_eq!(deleted_id(&outcome), Some("a"));
        assert!(changed);
        assert_eq!(
            items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["b"]
        );
    }

    #[test]
    fn apply_delete_agent_only_its_own() {
        let mut direct = owner_shared("direct");
        direct.to = Some("alpha".to_string());
        let mut items = vec![owner_shared("open"), direct];

        // A shared item the agent never touched: forbidden, list unchanged.
        let (outcome, changed) = apply_delete(&mut items, "open", Some("alpha"));
        assert!(matches!(outcome, DeleteOutcome::Forbidden));
        assert!(!changed);
        assert_eq!(items.len(), 2);

        // A message addressed to the agent: removed.
        let (outcome, changed) = apply_delete(&mut items, "direct", Some("alpha"));
        assert_eq!(deleted_id(&outcome), Some("direct"));
        assert!(changed);
        assert_eq!(
            items.iter().map(|i| i.id.as_str()).collect::<Vec<_>>(),
            vec!["open"]
        );
    }

    #[test]
    fn agent_can_see_matches_view_membership() {
        // Shared open queue: visible to any agent.
        assert!(agent_can_see(&owner_shared("open"), "alpha"));

        // A direct message is visible only to its addressee — the audience wall
        // that keeps a secret sent to one agent from another.
        let mut direct = owner_shared("direct");
        direct.to = Some("alpha".to_string());
        assert!(agent_can_see(&direct, "alpha"));
        assert!(!agent_can_see(&direct, "beta"));

        let mut grabbed = owner_shared("grabbed");
        grabbed.grabbed_by = Some("alpha".to_string());
        assert!(agent_can_see(&grabbed, "alpha"));
        assert!(!agent_can_see(&grabbed, "beta"));

        let mut sent = owner_shared("sent");
        sent.direction = StoredDirection::AgentToOwner;
        sent.from = "alpha".to_string();
        assert!(agent_can_see(&sent, "alpha"));
        assert!(!agent_can_see(&sent, "beta"));
    }

    #[test]
    fn apply_delete_missing_id_is_not_found_and_no_change() {
        let mut items = vec![owner_shared("a")];
        let (outcome, changed) = apply_delete(&mut items, "nope", None);
        assert!(matches!(outcome, DeleteOutcome::NotFound));
        assert!(!changed);
        assert_eq!(items.len(), 1);
    }

    #[test]
    fn validate_text_rejects_empty_and_oversized() {
        assert!(validate_text("id", "", false).is_some());
        // Empty is allowed when a file is attached (a caption-less file).
        assert!(validate_text("id", "", true).is_none());
        assert!(validate_text("id", "hello", false).is_none());
        let big = "x".repeat(MAX_TEXT_BYTES + 1);
        assert!(validate_text("id", &big, false).is_some());
        // Even with a file, an over-long caption is rejected.
        assert!(validate_text("id", &big, true).is_some());
        let ok = "x".repeat(MAX_TEXT_BYTES);
        assert!(validate_text("id", &ok, false).is_none());
    }

    #[test]
    fn validate_label_caps_length() {
        assert!(validate_label("id", "from", None).is_none());
        assert!(validate_label("id", "from", Some("alpha")).is_none());
        let big = "x".repeat(MAX_LABEL_BYTES + 1);
        assert!(validate_label("id", "grabbed_by", Some(&big)).is_some());
    }

    #[test]
    fn validate_mime_caps_length() {
        assert!(validate_mime("id", "image/png").is_none());
        assert!(validate_mime("id", &"x".repeat(MAX_MIME_BYTES)).is_none());
        assert!(validate_mime("id", &"x".repeat(MAX_MIME_BYTES + 1)).is_some());
    }

    #[test]
    fn gram_item_to_info_carries_origin_id_to_the_wire() {
        let mut item = owner_shared("m1");
        item.origin_id = "machine_abc123".to_string();
        assert_eq!(gram_item_to_info(item).origin_id, "machine_abc123");
    }

    #[test]
    fn wire_message_without_origin_id_decodes_to_empty() {
        // A message serialized by an older daemon has no origin_id; it must still
        // decode (empty), so the app keeps rendering old grams. See issue #98.
        let legacy = serde_json::json!({
            "id": "gram-1-2-3",
            "direction": "agent_to_owner",
            "from": "alpha",
            "text": "hi",
            "created_unix_ms": 1u64,
        });
        let info: GramMessageInfo = serde_json::from_value(legacy).unwrap();
        assert_eq!(info.origin_id, "");
    }

    #[test]
    fn gram_send_stamps_and_returns_the_stable_store_origin_id() {
        // Redirect config-home to a throwaway dir so the send writes to a temp
        // store (never the real ~/.config/herdr/gram.json) and machine::get_or_create
        // mints a temp id. nextest runs each test in its own process, so the
        // machine-id OnceLock and this env var stay isolated to this test.
        let _guard = crate::config::test_config_env_lock().lock().unwrap();
        let prev_xdg = std::env::var_os("XDG_CONFIG_HOME");
        let tmp = std::env::temp_dir().join(format!(
            "herdr-gram-origin-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::create_dir_all(&tmp).unwrap();
        std::env::set_var("XDG_CONFIG_HOME", &tmp);

        let (_api_tx, api_rx) = tokio::sync::mpsc::unbounded_channel();
        let mut app = App::new(
            &crate::config::Config::default(),
            false,
            None,
            api_rx,
            crate::api::EventHub::default(),
        );

        let send = |app: &mut App, req: &str| -> serde_json::Value {
            let raw = app.handle_gram_send(
                req.to_string(),
                GramSendParams {
                    text: "ping".to_string(),
                    caller_pane_id: None,
                    from: Some("tester".to_string()),
                    file: None,
                },
            );
            serde_json::from_str(&raw).unwrap()
        };

        let first = send(&mut app, "req-1");
        let store_id = first["result"]["store_id"]
            .as_str()
            .unwrap_or("")
            .to_string();
        let origin_id = first["result"]["message"]["origin_id"]
            .as_str()
            .unwrap_or("");
        // The mint site actually stamped the stable install id (not an empty string
        // or the volatile pid), and it is echoed on the send response envelope.
        assert!(store_id.starts_with("machine_"), "store_id: {store_id:?}");
        assert_eq!(
            origin_id, store_id,
            "message.origin_id must equal the store it landed in"
        );

        // A second send carries the SAME origin_id — the stability the pid lacked
        // (a restart would have changed the pid segment; the store id does not).
        let second = send(&mut app, "req-2");
        assert_eq!(
            second["result"]["message"]["origin_id"]
                .as_str()
                .unwrap_or(""),
            store_id
        );

        match prev_xdg {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
