//! The Gram a guest with `share_gram` sees: the granted agent's Grams to the
//! owner from the moment the guest accepted, and the guest's own posts to the
//! agent. The guest keeps its own read marks in `gram-read.json`; the owner's
//! `read_by_owner` is never touched.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io;
use std::path::Path;

use crate::persist::gram::{GramDirection, GramItem};

use super::{store, GuestPrincipal};

pub(crate) const DEFAULT_LIST_LIMIT: usize = 100;
pub(crate) const MAX_LIST_LIMIT: usize = 500;
const READ_FILE: &str = "gram-read.json";

/// Read marks per guest id.
type ReadMarks = BTreeMap<String, BTreeSet<String>>;

/// Whether `item` is in the guest's shared Gram: a Gram the granted agent
/// itself sent (see [`super::grant_sent`]), or the guest's own post to it,
/// created since the guest accepted. It does not depend on the agent running
/// now: what qualifies is fixed by who sent it, so history stays readable
/// while the grant is paused and nothing new can qualify meanwhile.
pub(crate) fn visible(guest: &GuestPrincipal, item: &GramItem) -> bool {
    visible_in(&guest.grant, guest.created_ms, &guest.name, item)
}

/// [`visible`] for a stored guest record.
pub(crate) fn visible_to(guest: &store::GuestRecord, item: &GramItem) -> bool {
    visible_in(&guest.grant, guest.created_ms, &guest.name, item)
}

fn visible_in(
    grant: &crate::api::schema::GuestGrantInfo,
    created_ms: u64,
    name: &str,
    item: &GramItem,
) -> bool {
    let Some(agent) = grant.agent_name.as_deref() else {
        return false;
    };
    if item.created_unix_ms < created_ms {
        return false;
    }
    match item.direction {
        GramDirection::AgentToOwner => super::grant_sent(grant, &item.from, item.sender.as_ref()),
        GramDirection::OwnerToAgent => {
            item.to.as_deref() == Some(agent) && item.from == super::post_from(name)
        }
    }
}

/// Whether an active guest, sharing the Gram or not, could see `item`.
pub(crate) fn any_guest_may_see(guests: &[store::GuestRecord], item: &GramItem) -> bool {
    guests
        .iter()
        .any(|guest| !guest.revoked && visible_to(guest, item))
}

/// Whether an active guest sharing the Gram can see `item`.
pub(crate) fn any_guest_sees(guests: &[store::GuestRecord], item: &GramItem) -> bool {
    guests
        .iter()
        .any(|guest| !guest.revoked && guest.share_gram && visible_to(guest, item))
}

/// The guest's Gram: this machine's store and, on a Gram-relay remote, the
/// copies kept for guests, oldest first.
pub(crate) fn items(guest: &GuestPrincipal) -> Vec<GramItem> {
    let mut items = crate::persist::gram::load();
    match super::mirror::load(&guest.dir) {
        Ok(copies) => items.extend(copies),
        Err(err) => tracing::warn!(err = %err, "guest gram copies unavailable"),
    }
    items.sort_by_key(|item| item.created_unix_ms);
    items
}

/// `gram.list` for a guest: newest first, `limit` (default 100, at most 500)
/// messages strictly older than `before_id`, and whether older ones remain.
/// Errors name the invalid parameter.
pub(crate) fn list(
    guest: &GuestPrincipal,
    items: &[GramItem],
    limit: Option<usize>,
    before_id: Option<&str>,
) -> Result<(Vec<serde_json::Value>, bool), &'static str> {
    let limit = limit.unwrap_or(DEFAULT_LIST_LIMIT);
    if !(1..=MAX_LIST_LIMIT).contains(&limit) {
        return Err("limit must be 1 to 500");
    }
    // The store keeps messages oldest first.
    let mut newest_first = items.iter().rev().filter(|item| visible(guest, item));
    if let Some(before_id) = before_id {
        if !newest_first.any(|item| item.id == before_id) {
            return Err("before_id is not a message in this list");
        }
    }
    let read = read_ids(&guest.dir, &guest.guest_id).map_err(|_| "guest read marks unavailable")?;
    let mut page = Vec::new();
    for item in newest_first.by_ref() {
        if page.len() == limit {
            return Ok((page, true));
        }
        page.push(view(item, &read));
    }
    Ok((page, false))
}

/// The fields a guest sees: no claim, owner read state or store identity.
fn view(item: &GramItem, read: &BTreeSet<String>) -> serde_json::Value {
    let own_post = item.direction == GramDirection::OwnerToAgent;
    let mut view = serde_json::json!({
        "id": item.id,
        "direction": item.direction,
        "from": item.from,
        "text": item.text,
        "created_unix_ms": item.created_unix_ms,
        "read": own_post || read.contains(&item.id),
    });
    if let Some(file) = &item.file {
        view["file"] = serde_json::json!({
            "name": file.name,
            "size": file.size,
            "mime": file.mime,
            "sha256": file.sha256,
        });
    }
    view
}

fn read_ids(dir: &Path, guest_id: &str) -> io::Result<BTreeSet<String>> {
    let mut marks: ReadMarks = store::load_side(dir, READ_FILE)?;
    Ok(marks.remove(guest_id).unwrap_or_default())
}

/// Mark `ids` read for this guest. Marks of messages no longer in
/// `visible_ids` (deleted since) are dropped, so the file stays bounded.
pub(crate) fn mark_read(
    dir: &Path,
    guest_id: &str,
    ids: &[String],
    visible_ids: &HashSet<&str>,
) -> io::Result<()> {
    store::update_side(dir, READ_FILE, |marks: &mut ReadMarks| {
        let entry = marks.entry(guest_id.to_string()).or_default();
        let before = entry.clone();
        entry.extend(ids.iter().cloned());
        entry.retain(|id| visible_ids.contains(id.as_str()));
        ((), *entry != before)
    })
}

/// Drop a revoked guest's read marks.
pub(crate) fn forget(dir: &Path, guest_id: &str) -> io::Result<()> {
    store::update_side(dir, READ_FILE, |marks: &mut ReadMarks| {
        ((), marks.remove(guest_id).is_some())
    })
}
