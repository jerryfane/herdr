//! Gram message handlers: the owner<->agent channel surfaced in the app.
//!
//! `gram.send` (agent->owner, push-notified), `gram.post` (owner->agent, shared
//! queue or direct), `gram.list` (audience inferred from the caller pane),
//! `gram.grab` (first-wins claim of a shared item), and `gram.mark_read`.
//!
//! Identity: there is no per-connection identity, so the caller passes its
//! `HERDR_PANE_ID` as `caller_pane_id` and the server resolves it (see
//! [`App::caller_identity`]) to a `(display, key)` pair: `display` is the agent
//! name or the pane's public id (human-readable attribution), and `key` is the
//! terminal id — stable across rename / clear / pane-move and never reused, so it
//! is the durable identity used to match a message or claim back to its owner
//! (see `identity_matches`). The owner's app sends no `caller_pane_id` (owner view
//! = everything); a `caller_pane_id` that names no live pane is an error, not a
//! silent fall-through to the owner view. Sender/owner attribution is advisory,
//! not authenticated — the trust domain is already flat.

use super::responses::{encode_error, encode_success};
use crate::api::schema::{
    GramDirection, GramGrabParams, GramListParams, GramMarkReadParams, GramMessageInfo,
    GramPostParams, GramSendParams, ResponseResult,
};
use crate::app::App;
use crate::persist::gram::{
    new_id, GramDirection as StoredDirection, GramItem, MAX_LABEL_BYTES, MAX_TEXT_BYTES,
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

impl App {
    pub(super) fn handle_gram_send(&mut self, id: String, params: GramSendParams) -> String {
        let text = params.text.trim();
        if let Some(err) = validate_text(&id, text) {
            return err;
        }
        if let Some(err) = validate_label(&id, "from", params.from.as_deref()) {
            return err;
        }
        if self.no_session {
            return gram_unavailable(id);
        }

        let (from, from_key) =
            self.resolve_sender(params.from.as_deref(), params.caller_pane_id.as_deref());
        let item = GramItem {
            id: new_id(),
            direction: StoredDirection::AgentToOwner,
            from: from.clone(),
            from_key,
            to: None,
            text: text.to_string(),
            grabbed_by: None,
            grabbed_by_key: None,
            grabbed_unix_ms: None,
            created_unix_ms: super::unix_millis_now(),
            read_by_owner: false,
        };

        match crate::persist::gram::append(item.clone()) {
            Ok(_) => {
                self.emit_apns_gram_message(&from, text);
                encode_success(
                    id,
                    ResponseResult::GramSent {
                        message: gram_item_to_info(item),
                    },
                )
            }
            Err(err) => encode_error(id, "gram_store_save_failed", err.to_string()),
        }
    }

    pub(super) fn handle_gram_post(&mut self, id: String, params: GramPostParams) -> String {
        let text = params.text.trim();
        if let Some(err) = validate_text(&id, text) {
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

        let item = GramItem {
            id: new_id(),
            direction: StoredDirection::OwnerToAgent,
            from: "owner".to_string(),
            from_key: None,
            to,
            text: text.to_string(),
            grabbed_by: None,
            grabbed_by_key: None,
            grabbed_unix_ms: None,
            created_unix_ms: super::unix_millis_now(),
            // The owner's own message is not an unread inbox item for the owner.
            read_by_owner: true,
        };

        match crate::persist::gram::append(item.clone()) {
            Ok(_) => encode_success(
                id,
                ResponseResult::GramSent {
                    message: gram_item_to_info(item),
                },
            ),
            Err(err) => encode_error(id, "gram_store_save_failed", err.to_string()),
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
                let Some((display, key)) = self.caller_identity(pane) else {
                    return encode_error(
                        id,
                        "unknown_caller",
                        "caller_pane_id is not a known pane; omit it to read as the owner",
                    );
                };
                filter_agent_view(&items, &display, Some(&key), params.only_queue)
            }
            // No caller pane: the owner (app) view.
            None => filter_owner_view(&items, params.only_queue, params.unread_only),
        };
        // Store order is oldest-first; clients want newest-first.
        let messages: Vec<GramMessageInfo> =
            filtered.into_iter().rev().map(gram_item_to_info).collect();
        encode_success(id, ResponseResult::GramList { messages })
    }

    pub(super) fn handle_gram_grab(&mut self, id: String, params: GramGrabParams) -> String {
        if let Some(err) = validate_label(&id, "grabbed_by", params.grabbed_by.as_deref()) {
            return err;
        }
        if self.no_session {
            return gram_unavailable(id);
        }

        // Display label = explicit --as override, else the caller's display
        // identity. The stable key comes only from the caller pane (an explicit
        // override has no pane), and matching in the view prefers the key.
        let explicit = params
            .grabbed_by
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string);
        let caller = params
            .caller_pane_id
            .as_deref()
            .and_then(|pane| self.caller_identity(pane));
        let who_display = explicit.or_else(|| caller.as_ref().map(|(display, _)| display.clone()));
        let who_key = caller.map(|(_, key)| key);
        let Some(who_display) = who_display else {
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
        // threads and processes — first grab wins. A lost race changes nothing, so
        // it does not rewrite the store (update_if_changed).
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
                item.grabbed_by = Some(who_display.clone());
                item.grabbed_by_key = who_key.clone();
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

    /// Resolve `(display, key)` for an agent->owner message's sender. `display` is
    /// an explicit `from` override, else the caller's display identity, else
    /// "agent". `key` is the caller's stable terminal-id key (`None` when there is
    /// no caller pane), used for "is this mine" matching regardless of the display
    /// label — so a `--from` override never hides the sender's own message.
    fn resolve_sender(
        &self,
        from: Option<&str>,
        caller_pane_id: Option<&str>,
    ) -> (String, Option<String>) {
        let caller = caller_pane_id.and_then(|pane| self.caller_identity(pane));
        let display = from
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| caller.as_ref().map(|(display, _)| display.clone()))
            .unwrap_or_else(|| "agent".to_string());
        (display, caller.map(|(_, key)| key))
    }

    /// Resolve a public pane id (an agent's `HERDR_PANE_ID`) to `(display, key)`.
    /// `display` is the per-agent name if set, else the pane's public id (both
    /// unique per pane, for human-readable attribution). `key` is the terminal id,
    /// which is stable across rename / clear / pane-move and never reused (it is
    /// minted from wall-clock micros + a counter), so it is the durable identity
    /// used to match a message or claim back to its owner. `None` only when the
    /// pane id names no known pane.
    fn caller_identity(&self, caller_pane_id: &str) -> Option<(String, String)> {
        let (ws_idx, pane_id) = self.parse_pane_id(caller_pane_id)?;
        let terminal_id = self.state.workspaces.get(ws_idx)?.terminal_id(pane_id)?;
        let key = terminal_id.to_string();
        let display = self
            .state
            .terminals
            .get(terminal_id)
            .and_then(|terminal| terminal.agent_name.clone())
            .filter(|name| !name.trim().is_empty())
            .or_else(|| self.public_pane_id(ws_idx, pane_id))
            .unwrap_or_else(|| key.clone());
        Some((display, key))
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
    fn emit_apns_gram_message(&self, from: &str, text: &str) {
        if self.no_session || !crate::push::enabled(&self.state.push_config) {
            return;
        }
        let title =
            super::sanitized_notification_text(from, 80).unwrap_or_else(|| "New gram".to_string());
        let body = super::sanitized_notification_text(text, 240).unwrap_or_default();
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

/// Reject an empty or over-long message before it reaches the store. Returns the
/// encoded error response, or `None` when the text is acceptable.
fn validate_text(id: &str, text: &str) -> Option<String> {
    if text.is_empty() {
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
    }
}

/// True for a shared, still-open queue item any agent may claim.
fn is_open_shared_queue(item: &GramItem) -> bool {
    item.direction == StoredDirection::OwnerToAgent
        && item.to.is_none()
        && item.grabbed_by.is_none()
}

/// Does a stored item belong to the caller? Prefer the stable key (present on
/// items written by this build); fall back to the display label for legacy items
/// or a caller with no pane. Matching on the key means a rename, an agent-name
/// clear, a pane move, or a `--from`/`--as` display override never hides an item
/// from its true owner, nor reveals it to a later agent that reused the label.
fn identity_matches(
    stored_key: Option<&str>,
    stored_display: &str,
    my_display: &str,
    my_key: Option<&str>,
) -> bool {
    match (stored_key, my_key) {
        (Some(stored_key), Some(my_key)) => stored_key == my_key,
        _ => stored_display == my_display,
    }
}

/// The agent's view: the shared ungrabbed queue, items addressed to it, items it
/// grabbed, and its own sent messages. `only_queue` narrows to just the shared,
/// still-open queue so an agent can quickly scan available work. `key` is the
/// caller's stable identity; "grabbed by me" / "sent by me" match on it.
fn filter_agent_view(
    items: &[GramItem],
    display: &str,
    key: Option<&str>,
    only_queue: bool,
) -> Vec<GramItem> {
    items
        .iter()
        .filter(|item| {
            if only_queue {
                return is_open_shared_queue(item);
            }
            let addressed_to_me = item.direction == StoredDirection::OwnerToAgent
                && item.to.as_deref() == Some(display);
            let grabbed_by_me = item.grabbed_by.as_deref().is_some_and(|grabbed_by| {
                identity_matches(item.grabbed_by_key.as_deref(), grabbed_by, display, key)
            });
            let sent_by_me = item.direction == StoredDirection::AgentToOwner
                && identity_matches(item.from_key.as_deref(), &item.from, display, key);
            is_open_shared_queue(item) || addressed_to_me || grabbed_by_me || sent_by_me
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
            from_key: None,
            to: None,
            text: "shared task".to_string(),
            grabbed_by: None,
            grabbed_by_key: None,
            grabbed_unix_ms: None,
            created_unix_ms: 1,
            read_by_owner: true,
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
        let ids: Vec<String> = filter_agent_view(&items, "alpha", None, false)
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
    fn agent_view_matches_on_stable_key_across_rename_and_reuse() {
        // Item grabbed by key "k-alpha" while the agent displayed as "alpha".
        let mut grabbed = owner_shared("mine");
        grabbed.grabbed_by = Some("alpha".to_string());
        grabbed.grabbed_by_key = Some("k-alpha".to_string());
        let items = vec![grabbed];

        // The same agent, now renamed to "alpha-2" but still key "k-alpha", still
        // sees its claim (key match, display changed).
        let seen: Vec<String> = filter_agent_view(&items, "alpha-2", Some("k-alpha"), false)
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert_eq!(seen, vec!["mine".to_string()]);

        // A different agent that reused the old display name "alpha" but has a
        // different key does NOT see the claim.
        let other: Vec<String> = filter_agent_view(&items, "alpha", Some("k-beta"), false)
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert!(other.is_empty());
    }

    #[test]
    fn agent_view_only_queue_is_shared_and_open() {
        let mut grabbed = owner_shared("grabbed");
        grabbed.grabbed_by = Some("beta".to_string());
        let items = vec![owner_shared("open"), grabbed];
        let ids: Vec<String> = filter_agent_view(&items, "alpha", None, true)
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
    fn validate_text_rejects_empty_and_oversized() {
        assert!(validate_text("id", "").is_some());
        assert!(validate_text("id", "hello").is_none());
        let big = "x".repeat(MAX_TEXT_BYTES + 1);
        assert!(validate_text("id", &big).is_some());
        let ok = "x".repeat(MAX_TEXT_BYTES);
        assert!(validate_text("id", &ok).is_none());
    }

    #[test]
    fn validate_label_caps_length() {
        assert!(validate_label("id", "from", None).is_none());
        assert!(validate_label("id", "from", Some("alpha")).is_none());
        let big = "x".repeat(MAX_LABEL_BYTES + 1);
        assert!(validate_label("id", "grabbed_by", Some(&big)).is_some());
    }
}
