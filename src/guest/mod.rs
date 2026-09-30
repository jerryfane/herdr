//! Guest access: one outside person uses one shared agent through the HerdrUp
//! guest relay. This module owns the guest store, invites, admission, the
//! audit log and the live-session registry. The relay client lives in `link`;
//! the per-request gate lives in `crate::api::server::guest_gate`.
//!
//! The interface functions below are the contract with `link`, which is the
//! only production caller of `host_info`, `link_wanted`, `admit`, `serve` and
//! `subscribe_changes`.

pub(crate) mod audit;
pub(crate) mod gram;
pub(crate) mod link;
pub(crate) mod mirror;
pub(crate) mod push;
pub(crate) mod store;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex, Weak};

use serde::Serialize;

use crate::api::schema::{
    AgentInfo, GuestAuditEntry, GuestAuditEvent, GuestAuditFile, GuestGrantInfo, GuestInfo,
    GuestInviteInfo, GuestLinkInfo, GuestLinkState,
};
use store::{AdmitOutcome, RevokeTarget};

pub struct GuestHostInfo {
    pub host_id: String,
    pub relay_secret: String,
    pub node_secret: [u8; 32],
    // Contract field; the link's Noise responder derives it from the secret.
    #[allow(dead_code)]
    pub node_public: [u8; 32],
    pub relay_url: String,
}

/// Creates the node key and `host.json` on first use.
pub(crate) fn host_info() -> std::io::Result<GuestHostInfo> {
    let (host, node_secret) = store::load_host(&store::guest_dir())?;
    Ok(GuestHostInfo {
        host_id: host.host_id,
        relay_secret: host.relay_secret,
        node_public: store::x25519_public(&node_secret),
        node_secret,
        relay_url: crate::config::Config::load().config.guest.relay_url,
    })
}

/// At least one non-revoked guest or one unexpired, unused invite. Invite
/// expiry does not fire [`subscribe_changes`]; poll this on a timer too.
pub(crate) fn link_wanted() -> bool {
    store::link_wanted_in(&store::guest_dir(), store::now_ms())
}

/// An admitted guest, bound to one agent grant for one API connection.
#[derive(Debug, Clone)]
pub struct GuestPrincipal {
    pub(crate) guest_id: String,
    pub(crate) name: String,
    pub(crate) fingerprint: String,
    pub(crate) grant: GuestGrantInfo,
    pub(crate) dir: PathBuf,
    /// When the guest accepted: it sees the agent's Grams from here on.
    pub(crate) created_ms: u64,
}

impl GuestPrincipal {
    fn from_record(record: &store::GuestRecord, dir: PathBuf) -> Self {
        Self {
            guest_id: record.guest_id.clone(),
            name: record.name.clone(),
            fingerprint: record.fingerprint.clone(),
            grant: record.grant.clone(),
            dir,
            created_ms: record.created_ms,
        }
    }

    /// Whether the guest shares the agent's Gram now. Read from the store on
    /// every call, so `guest.update` applies to sessions already admitted.
    pub(crate) fn shares_gram(&self) -> bool {
        store::shares_gram(&self.dir, &self.guest_id)
    }

    /// `<name> (via HerdrUp): `, prefixed to every prompt.
    pub(crate) fn label(&self) -> String {
        store::guest_label(&self.name)
    }

    /// `<name> (via HerdrUp)`, the sender of the guest's Gram posts.
    pub(crate) fn post_from(&self) -> String {
        post_from(&self.name)
    }

    /// Record one audit event. Audit failures are logged, never fatal.
    pub(crate) fn audit(
        &self,
        event: GuestAuditEvent,
        method: Option<&str>,
        text: Option<String>,
        file: Option<GuestAuditFile>,
    ) {
        let entry = GuestAuditEntry {
            ts_ms: store::now_ms(),
            guest_id: self.guest_id.clone(),
            name: self.name.clone(),
            fingerprint: self.fingerprint.clone(),
            event,
            pane: self.grant.terminal_id.clone(),
            method: method.map(str::to_string),
            text,
            file,
        };
        if let Err(err) = audit::append(&self.dir, &entry) {
            tracing::warn!(err = %err, "guest audit log write failed");
        }
    }
}

fn same_kind(a: &str, b: &str) -> bool {
    match (
        crate::detect::parse_agent_label(a),
        crate::detect::parse_agent_label(b),
    ) {
        (Some(a), Some(b)) => a == b,
        _ => a == b,
    }
}

/// `<name> (via HerdrUp)`, the sender of a guest's Gram posts.
pub(crate) fn post_from(name: &str) -> String {
    store::guest_label(name).trim_end_matches(": ").to_string()
}

/// The grant names the agent with this name and kind in this terminal. The
/// harness session may change: a restarted agent keeps its guest.
pub(crate) fn grant_names(
    grant: &GuestGrantInfo,
    terminal_id: &str,
    name: Option<&str>,
    kind: &str,
) -> bool {
    grant.terminal_id == terminal_id
        && grant.agent_name.is_some()
        && grant.agent_name.as_deref() == name
        && same_kind(kind, grant.kind())
}

/// A Gram to the owner came from the granted agent: sent from its terminal,
/// by an agent of its kind, under its name. A Gram with no recorded local
/// sender (relayed, remote, sent without a pane, or older) never qualifies,
/// whatever its `from` says.
pub(crate) fn grant_sent(
    grant: &GuestGrantInfo,
    from: &str,
    sender: Option<&crate::persist::gram::GramSender>,
) -> bool {
    sender.is_some_and(|sender| {
        sender
            .agent
            .as_deref()
            .is_some_and(|kind| grant_names(grant, &sender.terminal_id, Some(from), kind))
    })
}

// Short-lived per-connection value; the contract shape stays unboxed.
#[allow(clippy::large_enum_variant)]
pub enum Admission {
    Admitted {
        principal: GuestPrincipal,
        reply: serde_json::Value,
    },
    Refused(&'static str),
}

/// Message-1 payload in, message-2 payload out.
pub(crate) fn admit(device_pub: [u8; 32], hello: &serde_json::Value) -> Admission {
    admit_in(store::guest_dir(), device_pub, hello)
}

pub(crate) fn admit_in(dir: PathBuf, device_pub: [u8; 32], hello: &serde_json::Value) -> Admission {
    let outcome = match store::admit_in(&dir, &device_pub, hello, store::now_ms()) {
        Ok(outcome) => outcome,
        Err(err) => {
            tracing::warn!(err = %err, "guest store unavailable; refusing guest");
            return Admission::Refused("unknown");
        }
    };
    let (record, event) = match outcome {
        AdmitOutcome::Refused(error) => return Admission::Refused(error),
        AdmitOutcome::Accepted { guest, replaced } => {
            // Close the replaced grants' live sessions now, not at their next
            // request, and stop pushing to them.
            for guest_id in &replaced {
                revoke_live(guest_id);
                forget_guest(&dir, guest_id);
            }
            notify_changes();
            (guest, Some(GuestAuditEvent::Accepted))
        }
        AdmitOutcome::Returning { guest, connected } => {
            (guest, connected.then_some(GuestAuditEvent::Connected))
        }
    };
    let principal = GuestPrincipal::from_record(&record, dir);
    if let Some(event) = event {
        principal.audit(event, None, None, None);
    }
    let reply = serde_json::json!({
        "ok": true,
        "guest_id": record.guest_id,
        "name": record.name,
        "machine_label": record.machine_label,
        "owner_name": record.owner_name,
        "agent": {"name": record.grant.agent_name, "target": record.grant.terminal_id},
        "features": {"gram": record.share_gram, "push": true},
    });
    Admission::Admitted { principal, reply }
}

/// Run one API connection as `principal`. Blocks until the request is
/// answered or the stream ends, then closes the stream.
pub(crate) fn serve(principal: GuestPrincipal, stream: std::os::unix::net::UnixStream) {
    crate::api::serve_guest_stream(principal, stream);
}

#[derive(Clone, Serialize)]
pub struct LinkStatus {
    pub state: &'static str,
    pub last_error: Option<String>,
}

static LINK_STATUS: Mutex<Option<LinkStatus>> = Mutex::new(None);

pub(crate) fn set_link_status(status: LinkStatus) {
    *LINK_STATUS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(status);
}

fn link_info() -> GuestLinkInfo {
    let status = LINK_STATUS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .clone();
    let Some(status) = status else {
        return GuestLinkInfo {
            state: GuestLinkState::Off,
            last_error: None,
        };
    };
    let state = match status.state {
        "connecting" => GuestLinkState::Connecting,
        "up" => GuestLinkState::Up,
        "retrying" => GuestLinkState::Retrying,
        _ => GuestLinkState::Off,
    };
    GuestLinkInfo {
        state,
        last_error: status.last_error,
    }
}

static SUBSCRIBERS: Mutex<Vec<mpsc::Sender<()>>> = Mutex::new(Vec::new());

/// Fires when guests or invites change (created, accepted, revoked).
pub(crate) fn subscribe_changes() -> mpsc::Receiver<()> {
    let (tx, rx) = mpsc::channel();
    SUBSCRIBERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .push(tx);
    rx
}

fn notify_changes() {
    SUBSCRIBERS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .retain(|subscriber| subscriber.send(()).is_ok());
}

/// Live guest connections per guest id. Revoke trips every flag; gates and
/// stream watchers check theirs and close with `guest_revoked`.
static LIVE: Mutex<Option<HashMap<String, Vec<Weak<AtomicBool>>>>> = Mutex::new(None);

pub(crate) struct LiveSession {
    revoked: Arc<AtomicBool>,
}

impl LiveSession {
    pub(crate) fn revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
}

pub(crate) fn register_live(guest_id: &str) -> LiveSession {
    let revoked = Arc::new(AtomicBool::new(false));
    let mut live = LIVE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let sessions = live
        .get_or_insert_with(HashMap::new)
        .entry(guest_id.to_string())
        .or_default();
    sessions.retain(|session| session.strong_count() > 0);
    sessions.push(Arc::downgrade(&revoked));
    LiveSession { revoked }
}

fn revoke_live(guest_id: &str) -> usize {
    let mut live = LIVE.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(sessions) = live.as_mut().and_then(|live| live.remove(guest_id)) else {
        return 0;
    };
    sessions
        .iter()
        .filter_map(Weak::upgrade)
        .inspect(|flag| flag.store(true, Ordering::Release))
        .count()
}

/// Owner RPC failure: an API error code and message.
pub(crate) type OwnerError = (&'static str, String);

fn io_error(err: std::io::Error) -> OwnerError {
    ("guest_store_failed", err.to_string())
}

/// `guest.invite.create` after the app resolved `agent` and its live check.
pub(crate) fn create_invite(
    agent: &AgentInfo,
    running: bool,
    name: &str,
    owner_name: &str,
    machine_label: &str,
    ttl_secs: Option<u64>,
    share_gram: bool,
) -> Result<(GuestInviteInfo, String, String), OwnerError> {
    if !store::valid_guest_name(name) {
        return Err((
            "guest_invalid_name",
            "guest name must match ^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$".into(),
        ));
    }
    for (field, value) in [("owner_name", owner_name), ("machine_label", machine_label)] {
        if value.trim().is_empty()
            || value.chars().count() > 64
            || value.chars().any(char::is_control)
        {
            return Err((
                "invalid_params",
                format!("{field} must be 1 to 64 printable characters"),
            ));
        }
    }
    let ttl_secs = ttl_secs.unwrap_or(store::DEFAULT_INVITE_TTL_SECS);
    if !(store::MIN_INVITE_TTL_SECS..=store::MAX_INVITE_TTL_SECS).contains(&ttl_secs) {
        return Err((
            "invalid_params",
            format!(
                "ttl_secs must be {} to {}",
                store::MIN_INVITE_TTL_SECS,
                store::MAX_INVITE_TTL_SECS
            ),
        ));
    }
    let grant = invite_grant(agent, running)?;
    let dir = store::guest_dir();
    let (host, node_secret) = store::load_host(&dir).map_err(io_error)?;
    let invite = store::create_invite(
        &dir,
        name,
        grant,
        owner_name,
        machine_label,
        ttl_secs,
        share_gram,
        store::now_ms(),
    )
    .map_err(io_error)?;
    notify_changes();
    let relay_url = crate::config::Config::load().config.guest.relay_url;
    let (url, web_url) = store::invite_links(
        &relay_url,
        &host,
        &store::x25519_public(&node_secret),
        &invite,
    );
    Ok((invite.record.info(), url, web_url))
}

/// The grant for a live, named, local agent with a stable harness session,
/// checked like `herdr machine grant`.
fn invite_grant(agent: &AgentInfo, running: bool) -> Result<GuestGrantInfo, OwnerError> {
    if agent.machine_id.is_some() {
        return Err((
            "agent_not_found",
            "target is a federated agent; pass `machine` to invite on its machine".into(),
        ));
    }
    let not_ready = |why: &str| ("agent_not_ready", format!("agent {}: {why}", agent.pane_id));
    if agent.archived.is_some() || agent.session_transfer.is_some() {
        return Err(not_ready("archived or transferring"));
    }
    if !running {
        return Err(not_ready("not running in its pane"));
    }
    let Some(agent_name) = agent.name.clone() else {
        return Err(not_ready("name the agent before sharing it"));
    };
    let Some(agent_session) = agent.agent_session.clone() else {
        return Err(not_ready("no stable harness session yet"));
    };
    Ok(GuestGrantInfo {
        terminal_id: agent.terminal_id.clone(),
        agent_name: Some(agent_name),
        agent_kind: agent.agent.clone(),
        agent_session,
    })
}

pub(crate) fn list() -> Result<(Vec<GuestInfo>, Vec<GuestInviteInfo>, GuestLinkInfo), OwnerError> {
    let store = store::load_store(&store::guest_dir()).map_err(io_error)?;
    Ok((
        store.guests.iter().map(store::GuestRecord::info).collect(),
        store
            .invites
            .iter()
            .map(store::InviteRecord::info)
            .collect(),
        link_info(),
    ))
}

/// Revoke a guest or delete an invite. Returns the live connections closed,
/// or `None` for an unknown id.
pub(crate) fn revoke(
    guest_id: Option<&str>,
    invite_id: Option<&str>,
) -> Result<Option<usize>, OwnerError> {
    let target = match (guest_id, invite_id) {
        (Some(guest_id), None) => RevokeTarget::Guest(guest_id),
        (None, Some(invite_id)) => RevokeTarget::Invite(invite_id),
        _ => {
            return Err((
                "invalid_params",
                "pass exactly one of guest_id or invite_id".into(),
            ))
        }
    };
    revoke_at(store::guest_dir(), target)
}

pub(crate) fn revoke_at(
    dir: PathBuf,
    target: RevokeTarget<'_>,
) -> Result<Option<usize>, OwnerError> {
    let Some(revoked) = store::revoke_in(&dir, target, store::now_ms()).map_err(io_error)? else {
        return Ok(None);
    };
    notify_changes();
    let Some(record) = revoked else {
        return Ok(Some(0));
    };
    let closed = revoke_live(&record.guest_id);
    forget_guest(&dir, &record.guest_id);
    GuestPrincipal::from_record(&record, dir).audit(GuestAuditEvent::Revoked, None, None, None);
    Ok(Some(closed))
}

/// Drop a revoked guest's push devices and Gram read marks.
fn forget_guest(dir: &std::path::Path, guest_id: &str) {
    if let Err(err) = push::remove_guest(dir, guest_id) {
        tracing::warn!(err = %err, "guest push devices removal failed");
    }
    if let Err(err) = gram::forget(dir, guest_id) {
        tracing::warn!(err = %err, "guest gram read marks removal failed");
    }
    prune_mirror(dir);
}

/// Drop the Gram copies no active sharing guest can see any more, and the
/// witnessed records no active guest could.
fn prune_mirror(dir: &std::path::Path) {
    let pruned = store::load_store(dir).and_then(|store| {
        mirror::prune(dir, |item| gram::any_guest_sees(&store.guests, item))?;
        mirror::forget_witnessed(dir, |item| gram::any_guest_may_see(&store.guests, item))
    });
    if let Err(err) = pruned {
        tracing::warn!(err = %err, "guest gram copies prune failed");
    }
}

/// `guest.update`: turn Gram sharing on or off for an active guest. `None`
/// when no active guest has this id.
pub(crate) fn update(guest_id: &str, share_gram: bool) -> Result<Option<GuestInfo>, OwnerError> {
    update_at(&store::guest_dir(), guest_id, share_gram)
}

pub(crate) fn update_at(
    dir: &std::path::Path,
    guest_id: &str,
    share_gram: bool,
) -> Result<Option<GuestInfo>, OwnerError> {
    let updated = store::update_share_gram(dir, guest_id, share_gram).map_err(io_error)?;
    if updated.is_some() {
        notify_changes();
    }
    if !share_gram {
        prune_mirror(dir);
    }
    Ok(updated.as_ref().map(store::GuestRecord::info))
}

pub(crate) fn read_audit(
    guest_id: Option<&str>,
    before_ms: Option<u64>,
    limit: Option<usize>,
) -> Result<Vec<GuestAuditEntry>, OwnerError> {
    let limit = limit.unwrap_or(audit::DEFAULT_READ_LIMIT);
    if !(1..=audit::MAX_READ_LIMIT).contains(&limit) {
        return Err((
            "invalid_params",
            format!("limit must be 1 to {}", audit::MAX_READ_LIMIT),
        ));
    }
    audit::read(&store::guest_dir(), guest_id, before_ms, limit).map_err(io_error)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn agent() -> AgentInfo {
        serde_json::from_value(json!({
            "terminal_id": "term_1", "name": "llm-opt", "agent_status": "idle",
            "agent_session": {"source": "herdr", "agent": "pi", "kind": "id", "value": "s-1"},
            "workspace_id": "w", "tab_id": "t", "pane_id": "w1:p1",
            "focused": false, "revision": 1
        }))
        .unwrap()
    }

    #[test]
    fn invites_need_a_live_named_local_agent_with_a_session() {
        assert!(invite_grant(&agent(), true).is_ok());
        assert_eq!(
            invite_grant(&agent(), false).unwrap_err().0,
            "agent_not_ready"
        );
        let mut unnamed = agent();
        unnamed.name = None;
        assert_eq!(
            invite_grant(&unnamed, true).unwrap_err().0,
            "agent_not_ready"
        );
        let mut sessionless = agent();
        sessionless.agent_session = None;
        assert_eq!(
            invite_grant(&sessionless, true).unwrap_err().0,
            "agent_not_ready"
        );
        let mut remote = agent();
        remote.machine_id = Some("studio".into());
        assert_eq!(
            invite_grant(&remote, true).unwrap_err().0,
            "agent_not_found"
        );
        let mut archived = agent();
        archived.archived = Some(crate::api::schema::AgentArchivedInfo {
            at: "2026-09-28T00:00:00Z".into(),
            by: "owner".into(),
            reason: None,
        });
        assert_eq!(
            invite_grant(&archived, true).unwrap_err().0,
            "agent_not_ready"
        );
    }

    #[test]
    fn guest_list_never_exposes_secrets_or_keys() {
        let _lock = crate::config::test_config_env_lock()
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let root = store::tests::TempDir::new("list-secrets");
        let config_home = root.0.parent().unwrap().to_path_buf();
        let previous = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("XDG_CONFIG_HOME", &config_home);
        let (invite, url, _) =
            create_invite(&agent(), true, "plotarmordev", "Jerry", "Mac", None, false).unwrap();
        let secret = url.rsplit('#').next().unwrap().to_string();
        let payload: serde_json::Value =
            serde_json::from_slice(&store::b64url_decode(&secret).unwrap()).unwrap();
        let hello = json!({"v": 1, "invite_id": invite.invite_id, "secret": payload["secret"], "device": "iPhone"});
        assert!(matches!(admit([6; 32], &hello), Admission::Admitted { .. }));
        let pending = create_invite(&agent(), true, "second", "Jerry", "Mac", None, false).unwrap();
        let (guests, invites, link) = list().unwrap();
        let rendered = serde_json::to_string(&(guests, invites, link)).unwrap();
        let dir = store::guest_dir();
        let host: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("host.json")).unwrap()).unwrap();
        let stored = std::fs::read_to_string(dir.join("guests.json")).unwrap();
        match previous {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        assert!(rendered.contains(&pending.0.invite_id));
        assert!(rendered.contains(&store::fingerprint(&[6; 32])));
        for secret in [
            payload["secret"].as_str().unwrap(),
            host["relay_secret"].as_str().unwrap(),
            &store::b64url(&[6; 32]),
            "secret_sha256",
            "device_pub",
        ] {
            assert!(!rendered.contains(secret), "guest.list leaked {secret}");
        }
        assert!(
            stored.contains("secret_sha256"),
            "the store keeps only the hash"
        );
    }

    #[test]
    fn admission_reply_and_revocation_of_live_sessions() {
        let dir = store::tests::TempDir::new("admit-reply");
        let invite = store::create_invite(
            &dir.0,
            "plotarmordev",
            store::tests::grant(),
            "Jerry",
            "Jerry's Mac Studio",
            3600,
            false,
            store::now_ms(),
        )
        .unwrap();
        let hello = json!({"v": 1, "invite_id": invite.record.invite_id, "secret": invite.secret, "device": "iPhone"});
        let Admission::Admitted { principal, reply } = admit_in(dir.0.clone(), [3; 32], &hello)
        else {
            panic!("accepted");
        };
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["name"], "plotarmordev");
        assert_eq!(reply["owner_name"], "Jerry");
        assert_eq!(reply["machine_label"], "Jerry's Mac Studio");
        assert_eq!(reply["agent"]["name"], "llm-opt");
        assert_eq!(reply["agent"]["target"], "term_1");
        assert!(matches!(
            admit_in(dir.0.clone(), [3; 32], &hello),
            Admission::Refused("invite_used")
        ));
        let live = register_live(&principal.guest_id);
        let other = register_live("someone-else");
        assert_eq!(revoke_live(&principal.guest_id), 1);
        assert!(live.revoked());
        assert!(!other.revoked());
        let entries = audit::read(&dir.0, Some(&principal.guest_id), None, 10).unwrap();
        assert_eq!(entries[0].event, GuestAuditEvent::Accepted);
    }

    fn invite_in(dir: &std::path::Path, share_gram: bool) -> store::NewInvite {
        store::create_invite(
            dir,
            "plotarmordev",
            store::tests::grant(),
            "Jerry",
            "Mac",
            3600,
            share_gram,
            store::now_ms(),
        )
        .unwrap()
    }

    fn accept_in(
        dir: &std::path::Path,
        invite: &store::NewInvite,
        device: u8,
    ) -> serde_json::Value {
        let hello = json!({"v": 1, "invite_id": invite.record.invite_id, "secret": invite.secret, "device": "iPhone"});
        match admit_in(dir.to_path_buf(), [device; 32], &hello) {
            Admission::Admitted { reply, .. } => reply,
            Admission::Refused(error) => panic!("refused: {error}"),
        }
    }

    #[test]
    fn hello_features_follow_share_gram_from_the_invite_and_updates() {
        let dir = store::tests::TempDir::new("features");
        let shared = accept_in(&dir.0, &invite_in(&dir.0, true), 1);
        assert_eq!(shared["features"], json!({"gram": true, "push": true}));

        let reply = accept_in(&dir.0, &invite_in(&dir.0, false), 2);
        assert_eq!(reply["features"], json!({"gram": false, "push": true}));
        let guest_id = reply["guest_id"].as_str().unwrap();
        let returning = || match admit_in(dir.0.clone(), [2; 32], &json!({"v": 1})) {
            Admission::Admitted { reply, .. } => reply,
            Admission::Refused(error) => panic!("refused: {error}"),
        };

        let updated = update_at(&dir.0, guest_id, true).unwrap().unwrap();
        assert!(updated.share_gram);
        assert_eq!(returning()["features"], json!({"gram": true, "push": true}));

        update_at(&dir.0, guest_id, false).unwrap().unwrap();
        assert_eq!(returning()["features"]["gram"], false);

        revoke_at(dir.0.clone(), RevokeTarget::Guest(guest_id)).unwrap();
        assert!(update_at(&dir.0, guest_id, true).unwrap().is_none());
        assert!(update_at(&dir.0, "unknown", true).unwrap().is_none());
    }

    fn device(token: &str) -> crate::persist::devices::RegisteredDevice {
        crate::persist::devices::RegisteredDevice {
            device_token: token.to_string(),
            platform: "ios".to_string(),
            notify_needs_input: true,
            notify_dies: true,
            notify_finishes: true,
            notify_gram: true,
            muted_panes: Vec::new(),
            registered_unix_ms: 0,
            relay_capability: None,
        }
    }

    fn device_owners(dir: &std::path::Path) -> Vec<(String, String)> {
        push::devices(dir)
            .unwrap()
            .into_iter()
            .map(|registered| (registered.guest_id, registered.device.device_token))
            .collect()
    }

    #[test]
    fn revoking_or_replacing_a_guest_deletes_its_push_devices() {
        let dir = store::tests::TempDir::new("push-revoke");
        let first = accept_in(&dir.0, &invite_in(&dir.0, true), 1);
        let second = accept_in(&dir.0, &invite_in(&dir.0, true), 2);
        let (first, second) = (
            first["guest_id"].as_str().unwrap().to_string(),
            second["guest_id"].as_str().unwrap().to_string(),
        );
        push::register(&dir.0, &first, device("aa")).unwrap();
        push::register(&dir.0, &second, device("bb")).unwrap();
        assert_eq!(device_owners(&dir.0).len(), 2);

        revoke_at(dir.0.clone(), RevokeTarget::Guest(&first)).unwrap();
        assert_eq!(device_owners(&dir.0), vec![(second.clone(), "bb".into())]);

        // A new invite accepted on the same device replaces the old grant.
        let replacement = accept_in(&dir.0, &invite_in(&dir.0, true), 2);
        assert_ne!(replacement["guest_id"], second.as_str());
        assert!(device_owners(&dir.0).is_empty());
    }
}
