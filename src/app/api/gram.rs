//! Gram message handlers: the owner<->agent channel surfaced in the app.
//!
//! `gram.send` (agent->owner, push-notified), `gram.post` (owner->agent, shared
//! queue or direct), `gram.list` (audience inferred from the caller pane),
//! `gram.grab` (first-wins claim of a shared item), and `gram.mark_read`.
//!
//! Identity: there is no per-connection identity, so the caller passes its
//! `HERDR_PANE_ID` as `caller_pane_id` and the server resolves it to the agent's
//! effective label (see [`App::caller_agent_label`]). The owner's app has no
//! pane, so a caller that does not resolve to an agent is treated as the owner.

use super::responses::{encode_error, encode_success};
use crate::api::schema::{
    GramDirection, GramGrabParams, GramListParams, GramMarkReadParams, GramMessageInfo,
    GramPostParams, GramSendParams, ResponseResult,
};
use crate::app::App;
use crate::persist::gram::{new_id, GramDirection as StoredDirection, GramItem};

/// Why a claim could not be completed.
enum GrabError {
    NotFound,
    /// The item is not a shared, still-open queue item (direct message, wrong
    /// direction, or already claimed by name below).
    NotGrabbable,
    /// Already claimed; carries the current owner's label.
    AlreadyGrabbed(String),
}

impl App {
    pub(super) fn handle_gram_send(&mut self, id: String, params: GramSendParams) -> String {
        let text = params.text.trim();
        if text.is_empty() {
            return encode_error(id, "invalid_params", "text is empty");
        }
        if self.no_session {
            return gram_unavailable(id);
        }

        let from =
            self.resolve_sender_label(params.from.as_deref(), params.caller_pane_id.as_deref());
        let item = GramItem {
            id: new_id(),
            direction: StoredDirection::AgentToOwner,
            from: from.clone(),
            to: None,
            text: text.to_string(),
            grabbed_by: None,
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
        if text.is_empty() {
            return encode_error(id, "invalid_params", "text is empty");
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
        let item = GramItem {
            id: new_id(),
            direction: StoredDirection::OwnerToAgent,
            from: "owner".to_string(),
            to,
            text: text.to_string(),
            grabbed_by: None,
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
            return encode_success(id, ResponseResult::GramList { messages: vec![] });
        }

        let items = crate::persist::gram::load();
        let caller = params
            .caller_pane_id
            .as_deref()
            .and_then(|pane| self.caller_agent_label(pane));

        let filtered = match caller {
            Some(agent) => filter_agent_view(&items, &agent, params.only_queue),
            None => filter_owner_view(&items, params.unread_only),
        };
        // Store order is oldest-first; clients want newest-first.
        let messages: Vec<GramMessageInfo> =
            filtered.into_iter().rev().map(gram_item_to_info).collect();
        encode_success(id, ResponseResult::GramList { messages })
    }

    pub(super) fn handle_gram_grab(&mut self, id: String, params: GramGrabParams) -> String {
        if self.no_session {
            return gram_unavailable(id);
        }

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
                    .and_then(|pane| self.caller_agent_label(pane))
            });
        let Some(who) = who else {
            return encode_error(
                id,
                "unknown_caller",
                "could not resolve the grabbing agent; pass caller_pane_id or grabbed_by",
            );
        };

        let target_id = params.id.clone();
        let now = super::unix_millis_now();
        // The claim runs under the store's advisory lock, and the app loop
        // serializes API requests, so this check-then-set is atomic across both
        // threads and processes — first grab wins.
        let outcome = crate::persist::gram::update(move |items| {
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
        let outcome = crate::persist::gram::update(move |items| {
            match items.iter_mut().find(|item| item.id == target_id) {
                Some(item) => {
                    item.read_by_owner = true;
                    true
                }
                None => false,
            }
        });
        match outcome {
            Ok((true, _)) => encode_success(id, ResponseResult::Ok {}),
            Ok((false, _)) => encode_error(id, "not_found", "no gram message with that id"),
            Err(err) => encode_error(id, "gram_store_save_failed", err.to_string()),
        }
    }

    /// Resolve the label to record as `from` for an agent->owner message:
    /// an explicit override, else the caller pane's agent label, else "agent".
    fn resolve_sender_label(&self, from: Option<&str>, caller_pane_id: Option<&str>) -> String {
        from.map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
            .or_else(|| caller_pane_id.and_then(|pane| self.caller_agent_label(pane)))
            .unwrap_or_else(|| "agent".to_string())
    }

    /// Resolve a public pane id (an agent's `HERDR_PANE_ID`) to that agent's
    /// effective label, mirroring the pane -> terminal -> agent path the push
    /// notifier uses. Returns `None` when the pane is unknown or has no agent.
    fn caller_agent_label(&self, caller_pane_id: &str) -> Option<String> {
        let (ws_idx, pane_id) = self.parse_pane_id(caller_pane_id)?;
        let terminal_id = self.state.workspaces.get(ws_idx)?.terminal_id(pane_id)?;
        let terminal = self.state.terminals.get(terminal_id)?;
        terminal.effective_agent_label().map(str::to_string)
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

/// The agent's view: the shared ungrabbed queue, items addressed to it, items it
/// grabbed, and its own sent messages. `only_queue` narrows to just the shared,
/// still-open queue so an agent can quickly scan available work.
fn filter_agent_view(items: &[GramItem], agent: &str, only_queue: bool) -> Vec<GramItem> {
    items
        .iter()
        .filter(|item| {
            let is_shared_open = item.direction == StoredDirection::OwnerToAgent
                && item.to.is_none()
                && item.grabbed_by.is_none();
            if only_queue {
                return is_shared_open;
            }
            let addressed_to_me = item.direction == StoredDirection::OwnerToAgent
                && item.to.as_deref() == Some(agent);
            let grabbed_by_me = item.grabbed_by.as_deref() == Some(agent);
            let sent_by_me = item.direction == StoredDirection::AgentToOwner && item.from == agent;
            is_shared_open || addressed_to_me || grabbed_by_me || sent_by_me
        })
        .cloned()
        .collect()
}

/// The owner's view: everything, or just unread agent->owner messages.
fn filter_owner_view(items: &[GramItem], unread_only: bool) -> Vec<GramItem> {
    items
        .iter()
        .filter(|item| {
            if unread_only {
                item.direction == StoredDirection::AgentToOwner && !item.read_by_owner
            } else {
                true
            }
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
    fn owner_view_unread_only_is_unread_agent_messages() {
        let mut unread = owner_shared("unread");
        unread.direction = StoredDirection::AgentToOwner;
        unread.read_by_owner = false;
        let mut read = owner_shared("read");
        read.direction = StoredDirection::AgentToOwner;
        read.read_by_owner = true;

        let items = vec![owner_shared("owner-post"), unread, read];
        let all = filter_owner_view(&items, false);
        assert_eq!(all.len(), 3);
        let ids: Vec<String> = filter_owner_view(&items, true)
            .into_iter()
            .map(|item| item.id)
            .collect();
        assert_eq!(ids, vec!["unread".to_string()]);
    }
}
