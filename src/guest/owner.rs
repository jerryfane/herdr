//! Owner grants (`owner_access.*`): the owner's own browsers allowed on this
//! machine through the HerdrUp guest relay. A grant names one browser key,
//! is bound to the account of the device that approved it (from that
//! device's account statement), and lasts 1 hour to 30 days. Grants live in
//! `guests.json` under `owners`, beside guests and invites.
//!
//! A browser connects with an owner hello (`"mode": "owner"`): its Noise key
//! must hold a live grant, and its own account statement must name the
//! grant's account. Both must hold, so removing the browser from the
//! account (its statements stop) ends its access too. The per-request gate
//! is `crate::api::server::owner_gate`.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::api::schema::{
    GuestAuditEntry, GuestAuditEvent, GuestLinkInfo, OwnerAccessAddParams, OwnerGrantInfo,
    OwnerScope,
};

use super::account::{self, codes};
use super::{audit, io_error, notify_changes, store, AccountHolder, AccountSession, OwnerError};

/// `owner_access.info`'s `protocol`: 1 stores grants (`owner_access.*`);
/// 2 also admits owner browsers (owner hello, owner gate).
pub(crate) const PROTOCOL: u32 = 2;
/// Live connections one grant may hold at once, so one browser cannot take
/// every relay session of this machine and lock guests out.
pub(crate) const SESSION_CAP: usize = 8;
/// Refusal codes an owner browser acts on, besides the statement codes in
/// [`codes`].
pub(crate) mod refusals {
    /// No grant for this key, or it was removed or replaced.
    pub(crate) const NOT_GRANTED: &str = "owner_not_granted";
    /// The grant expired; renewing it brings it back.
    pub(crate) const EXPIRED: &str = "owner_expired";
    /// The grant already holds [`super::SESSION_CAP`] live connections.
    pub(crate) const BUSY: &str = "owner_busy";
}
/// The shortest grant: 1 hour.
pub(crate) const MIN_TTL_SECS: u64 = 60 * 60;
/// The longest grant: 30 days.
pub(crate) const MAX_TTL_SECS: u64 = 30 * 24 * 60 * 60;
/// Live (not revoked, not expired) grants per machine.
pub(crate) const MAX_LIVE_GRANTS: usize = 10;
/// Revoked and expired grants are deleted this long after they ended. Until
/// then an expired one can be renewed.
pub(crate) const ENDED_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
/// Grants kept in the store, live and ended together. Past it the grants
/// that ended first are deleted early, so repeated adds and removals cannot
/// grow `guests.json` without limit.
pub(crate) const MAX_STORED_GRANTS: usize = 50;
const MAX_LABEL_CHARS: usize = 64;

/// One browser allowed on this machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct OwnerGrant {
    /// b64url of 16 random bytes.
    pub grant_id: String,
    /// b64url of the browser's X25519 key: its Noise key.
    pub device_pub: String,
    pub fingerprint: String,
    /// The browser's name, for example `Chrome on macOS`.
    pub device: String,
    /// The approving device's account: its pairwise id on this host.
    pub account: String,
    pub scope: OwnerScope,
    /// The approving device's name, for display only.
    pub approved_by: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    #[serde(default)]
    pub renewed_ms: Option<u64>,
    #[serde(default)]
    pub last_seen_ms: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default)]
    pub revoked_ms: Option<u64>,
    /// The latest admission that was audited as `owner_connected` (at most
    /// one per [`store::CONNECTED_AUDIT_WINDOW_MS`]).
    #[serde(default)]
    pub last_connected_ms: Option<u64>,
}

impl OwnerGrant {
    /// Not revoked and not expired at `now`.
    pub(crate) fn live(&self, now: u64) -> bool {
        !self.revoked && now < self.expires_ms
    }

    /// When the grant stopped being usable, once it has.
    fn ended_ms(&self, now: u64) -> Option<u64> {
        if self.revoked {
            Some(self.revoked_ms.unwrap_or(self.expires_ms))
        } else {
            (now >= self.expires_ms).then_some(self.expires_ms)
        }
    }

    /// Live, or ended within [`store::REVOKED_LINK_GRACE_MS`]: the relay link
    /// stays up for it, as it does for a revoked guest.
    pub(crate) fn wants_link(&self, now: u64) -> bool {
        self.ended_ms(now)
            .is_none_or(|at| now < at.saturating_add(store::REVOKED_LINK_GRACE_MS))
    }

    /// Kept in the store: live, or ended within [`ENDED_RETENTION_MS`].
    fn retained(&self, now: u64) -> bool {
        self.ended_ms(now)
            .is_none_or(|at| now < at.saturating_add(ENDED_RETENTION_MS))
    }

    pub(crate) fn info(&self) -> OwnerGrantInfo {
        OwnerGrantInfo {
            grant_id: self.grant_id.clone(),
            device_pub: self.device_pub.clone(),
            fingerprint: self.fingerprint.clone(),
            device: self.device.clone(),
            scope: self.scope,
            approved_by: self.approved_by.clone(),
            created_ms: self.created_ms,
            expires_ms: self.expires_ms,
            renewed_ms: self.renewed_ms,
            last_seen_ms: self.last_seen_ms,
            revoked: self.revoked,
        }
    }

    fn audit(&self, dir: &Path, event: GuestAuditEvent, text: Option<String>, now: u64) {
        audit_grant(
            dir,
            [&self.grant_id, &self.device, &self.fingerprint],
            event,
            None,
            text,
            now,
        );
    }
}

/// One audit line for a grant (`[grant_id, device, fingerprint]`): the grant
/// id in `guest_id`, the browser's name in `name`, and an empty `pane`.
/// Audit failures are logged, never fatal.
fn audit_grant(
    dir: &Path,
    [grant_id, device, fingerprint]: [&str; 3],
    event: GuestAuditEvent,
    method: Option<&str>,
    text: Option<String>,
    now: u64,
) {
    let entry = GuestAuditEntry {
        ts_ms: now,
        guest_id: grant_id.to_owned(),
        name: device.to_owned(),
        fingerprint: fingerprint.to_owned(),
        event,
        pane: String::new(),
        method: method.map(str::to_owned),
        text,
        file: None,
    };
    if let Err(err) = audit::append(dir, &entry) {
        tracing::warn!(err = %err, "owner access audit log write failed");
    }
}

/// Drop grants that ended more than [`ENDED_RETENTION_MS`] ago, then the
/// grants that ended first while more than [`MAX_STORED_GRANTS`] remain.
/// Live grants are never dropped. Returns whether any was dropped.
pub(crate) fn prune(owners: &mut Vec<OwnerGrant>, now: u64) -> bool {
    let before = owners.len();
    owners.retain(|grant| grant.retained(now));
    let excess = owners.len().saturating_sub(MAX_STORED_GRANTS);
    if excess > 0 {
        let mut ended: Vec<(u64, usize)> = owners
            .iter()
            .enumerate()
            .filter_map(|(index, grant)| grant.ended_ms(now).map(|at| (at, index)))
            .collect();
        ended.sort_unstable();
        let dropped: std::collections::HashSet<usize> = ended
            .into_iter()
            .take(excess)
            .map(|(_, index)| index)
            .collect();
        let mut index = 0;
        owners.retain(|_| {
            let keep = !dropped.contains(&index);
            index += 1;
            keep
        });
    }
    owners.len() != before
}

fn limit_error() -> OwnerError {
    (
        "owner_grant_limit",
        format!("this machine already allows {MAX_LIVE_GRANTS} browsers; remove one first"),
    )
}

/// `ttl_secs` within 1 hour to 30 days; anything else is refused, never
/// clamped.
fn ttl_ms(ttl_secs: u64) -> Result<u64, OwnerError> {
    if (MIN_TTL_SECS..=MAX_TTL_SECS).contains(&ttl_secs) {
        Ok(ttl_secs * 1000)
    } else {
        Err((
            "owner_ttl_invalid",
            format!("ttl_secs must be {MIN_TTL_SECS} to {MAX_TTL_SECS} (1 hour to 30 days)"),
        ))
    }
}

/// A 32-byte key as unpadded base64url; padding is refused.
fn decode_key(field: &str, text: &str) -> Result<[u8; 32], OwnerError> {
    store::b64url_decode(text)
        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
        .ok_or_else(|| {
            (
                "invalid_params",
                format!("{field} must be 32 bytes as unpadded base64url"),
            )
        })
}

fn check_label(field: &str, value: &str) -> Result<(), OwnerError> {
    if value.trim().is_empty()
        || value.chars().count() > MAX_LABEL_CHARS
        || value.chars().any(char::is_control)
    {
        return Err((
            "invalid_params",
            format!("{field} must be 1 to {MAX_LABEL_CHARS} printable characters"),
        ));
    }
    Ok(())
}

/// `owner_access.info`: this machine's relay identity (created on first
/// use), the configured relay and the link state.
pub(crate) struct HostAccessInfo {
    pub host_id: String,
    pub node_pub: String,
    pub relay_url: String,
    pub link: GuestLinkInfo,
}

pub(crate) fn info_in(dir: &Path, relay_url: String) -> Result<HostAccessInfo, OwnerError> {
    let (host, node_secret) = store::load_host(dir).map_err(io_error)?;
    Ok(HostAccessInfo {
        host_id: host.host_id,
        node_pub: store::b64url(&store::x25519_public(&node_secret)),
        relay_url,
        link: super::link_info(),
    })
}

/// `owner_access.list`, deleting grants past their retention first.
pub(crate) fn list_in(dir: &Path, now: u64) -> Result<Vec<OwnerGrantInfo>, OwnerError> {
    store::update_store(dir, |store| {
        let pruned = prune(&mut store.owners, now);
        (store.owners.iter().map(OwnerGrant::info).collect(), pruned)
    })
    .map_err(io_error)
}

/// `owner_access.add`: checks the approving device's statement for this
/// host (signature, issuer, audience and time; not `dev`, which is the
/// approving device's key) and stores a grant bound to its account. A
/// grant for the same key that was not removed is replaced (revoked).
/// Returns the new grant and the ids it replaced.
pub(crate) fn add_in(
    dir: &Path,
    env: &account::Env<'_>,
    params: &OwnerAccessAddParams,
    now: u64,
) -> Result<(OwnerGrantInfo, Vec<String>), OwnerError> {
    let ttl_ms = ttl_ms(params.ttl_secs)?;
    let device_pub = decode_key("device_pub", &params.device_pub)?;
    check_label("device_name", &params.device_name)?;
    check_label("approved_by", &params.approved_by)?;
    let (host, _) = store::load_host(dir).map_err(io_error)?;
    let verified = account::check_unbound(
        dir,
        &(env.settings)(),
        env.fetch_keys,
        &host.host_id,
        &params.account_statement,
        now,
    )
    .map_err(|code| {
        (
            code,
            "the approving device's account statement for this machine was refused".to_string(),
        )
    })?;
    let grant = OwnerGrant {
        grant_id: store::b64url(&store::random_bytes::<16>().map_err(io_error)?),
        device_pub: store::b64url(&device_pub),
        fingerprint: store::fingerprint(&device_pub),
        device: params.device_name.clone(),
        account: verified.sub,
        scope: params.scope,
        approved_by: params.approved_by.clone(),
        created_ms: now,
        expires_ms: now.saturating_add(ttl_ms),
        renewed_ms: None,
        last_seen_ms: None,
        revoked: false,
        revoked_ms: None,
        last_connected_ms: None,
    };
    let stored = grant.clone();
    let replaced = store::update_store(dir, |store| {
        let pruned = prune(&mut store.owners, now);
        let same_key = |old: &OwnerGrant| !old.revoked && old.device_pub == stored.device_pub;
        let live_others = store
            .owners
            .iter()
            .filter(|old| old.live(now) && !same_key(old))
            .count();
        if live_others >= MAX_LIVE_GRANTS {
            return (None, pruned);
        }
        let mut replaced = Vec::new();
        for old in store.owners.iter_mut().filter(|old| same_key(old)) {
            old.revoked = true;
            old.revoked_ms = Some(now);
            replaced.push(old.clone());
        }
        store.owners.push(stored);
        (Some(replaced), true)
    })
    .map_err(io_error)?
    .ok_or_else(limit_error)?;
    notify_changes();
    for old in &replaced {
        super::revoke_live(&live_key(&old.grant_id));
        old.audit(
            dir,
            GuestAuditEvent::OwnerRemoved,
            Some("replaced".into()),
            now,
        );
    }
    grant.audit(
        dir,
        GuestAuditEvent::OwnerAdded,
        Some(grant.approved_by.clone()),
        now,
    );
    Ok((
        grant.info(),
        replaced.into_iter().map(|old| old.grant_id).collect(),
    ))
}

/// `owner_access.renew`: `expires = now + ttl_secs`, and the scope when
/// given. Revives an expired grant within its retention; a revoked one stays
/// revoked.
pub(crate) fn renew_in(
    dir: &Path,
    grant_id: &str,
    ttl_secs: u64,
    scope: Option<OwnerScope>,
    now: u64,
) -> Result<OwnerGrantInfo, OwnerError> {
    let ttl_ms = ttl_ms(ttl_secs)?;
    let renewed = store::update_store(dir, |store| {
        let pruned = prune(&mut store.owners, now);
        let Some(index) = store
            .owners
            .iter()
            .position(|grant| grant.grant_id == grant_id)
        else {
            return (
                Err((
                    "owner_grant_not_found",
                    "no owner grant with that id".to_string(),
                )),
                pruned,
            );
        };
        if store.owners[index].revoked {
            return (
                Err((
                    "owner_grant_revoked",
                    "this grant was removed; approve the browser again".to_string(),
                )),
                pruned,
            );
        }
        // Reviving an expired grant makes one more live grant.
        if !store.owners[index].live(now) {
            let live_others = store.owners.iter().filter(|other| other.live(now)).count();
            if live_others >= MAX_LIVE_GRANTS {
                return (Err(limit_error()), pruned);
            }
        }
        let grant = &mut store.owners[index];
        grant.expires_ms = now.saturating_add(ttl_ms);
        grant.renewed_ms = Some(now);
        if let Some(scope) = scope {
            grant.scope = scope;
        }
        (Ok(grant.clone()), true)
    })
    .map_err(io_error)??;
    // A grant renewed after it expired wants the link again.
    notify_changes();
    renewed.audit(
        dir,
        GuestAuditEvent::OwnerRenewed,
        Some(
            match renewed.scope {
                OwnerScope::Chat => "chat",
                OwnerScope::Terminal => "terminal",
            }
            .into(),
        ),
        now,
    );
    Ok(renewed.info())
}

/// Which grants `owner_access.remove` revokes.
pub(crate) enum RemoveTarget<'a> {
    Grant(&'a str),
    Device(&'a str),
    Fingerprint(&'a str),
}

impl RemoveTarget<'_> {
    fn matches(&self, grant: &OwnerGrant) -> bool {
        match self {
            Self::Grant(id) => grant.grant_id == *id,
            Self::Device(key) => grant.device_pub == *key,
            Self::Fingerprint(fingerprint) => grant.fingerprint == *fingerprint,
        }
    }
}

/// `owner_access.remove`: revoke every grant `target` names that was not
/// removed before. Returns their ids; none is not an error, so a sweep can
/// run again.
pub(crate) fn remove_in(
    dir: &Path,
    target: RemoveTarget<'_>,
    now: u64,
) -> Result<Vec<String>, OwnerError> {
    if let RemoveTarget::Device(key) = target {
        decode_key("device_pub", key)?;
    }
    let removed = store::update_store(dir, |store| {
        let pruned = prune(&mut store.owners, now);
        let mut removed = Vec::new();
        for grant in store
            .owners
            .iter_mut()
            .filter(|grant| !grant.revoked && target.matches(grant))
        {
            grant.revoked = true;
            grant.revoked_ms = Some(now);
            removed.push(grant.clone());
        }
        let changed = pruned || !removed.is_empty();
        (removed, changed)
    })
    .map_err(io_error)?;
    if !removed.is_empty() {
        notify_changes();
    }
    for grant in &removed {
        // Its live connections close now, not at their next request.
        super::revoke_live(&live_key(&grant.grant_id));
        grant.audit(dir, GuestAuditEvent::OwnerRemoved, None, now);
    }
    Ok(removed.into_iter().map(|grant| grant.grant_id).collect())
}

/// The live-registry key of a grant's connections.
fn live_key(grant_id: &str) -> String {
    format!("owner\n{grant_id}")
}

/// An admitted owner browser, for one relay connection. The grant is read
/// again on every request ([`OwnerPrincipal::current`]): its scope may
/// change with a renewal, and a removal or expiry ends the connection.
pub struct OwnerPrincipal {
    pub(crate) grant_id: String,
    pub(crate) fingerprint: String,
    pub(crate) device: String,
    pub(crate) dir: PathBuf,
    /// Registered at admission, so it counts against [`SESSION_CAP`] and a
    /// removal closes the connection at once.
    live: super::LiveSession,
}

impl OwnerPrincipal {
    /// The grant's scope now, or the code that ends the connection: removed,
    /// replaced or unknown (`owner_not_granted`) or expired
    /// (`owner_expired`).
    pub(crate) fn current(&self, now: u64) -> Result<OwnerScope, &'static str> {
        if self.live.revoked() {
            return Err(refusals::NOT_GRANTED);
        }
        let store = store::load_store(&self.dir).map_err(|_| refusals::NOT_GRANTED)?;
        let grant = store
            .owners
            .iter()
            .find(|grant| grant.grant_id == self.grant_id && !grant.revoked)
            .ok_or(refusals::NOT_GRANTED)?;
        if !grant.live(now) {
            return Err(refusals::EXPIRED);
        }
        Ok(grant.scope)
    }

    /// This connection's entry in the live registry: set once a removal or
    /// replacement closes it.
    pub(crate) fn live(&self) -> &super::LiveSession {
        &self.live
    }

    /// The viewer this browser's streams and width leases are tied to,
    /// whatever viewer id it sent.
    pub(crate) fn viewer_id(&self) -> String {
        format!("owner-web:{}", self.grant_id)
    }

    /// Record one audit event for this grant.
    pub(crate) fn audit(&self, event: GuestAuditEvent, method: Option<&str>, text: Option<String>) {
        audit_grant(
            &self.dir,
            [&self.grant_id, &self.device, &self.fingerprint],
            event,
            method,
            text,
            store::now_ms(),
        );
    }
}

/// An admitted owner hello: the principal, the message-2 payload, and the
/// statement-bound session (it ends at `account.deadline_ms` unless the
/// browser sends a newer statement).
pub(crate) struct OwnerAdmission {
    pub principal: OwnerPrincipal,
    pub reply: serde_json::Value,
    pub account: AccountSession,
}

/// The live grant for `device_pub`, or why there is none.
fn live_grant(
    dir: &Path,
    find: impl Fn(&OwnerGrant) -> bool,
    now: u64,
) -> Result<OwnerGrant, &'static str> {
    let store = store::load_store(dir).map_err(|err| {
        tracing::warn!(err = %err, "guest store unavailable; refusing owner browser");
        refusals::NOT_GRANTED
    })?;
    let grant = store
        .owners
        .into_iter()
        .find(|grant| !grant.revoked && find(grant))
        .ok_or(refusals::NOT_GRANTED)?;
    if !grant.live(now) {
        return Err(refusals::EXPIRED);
    }
    Ok(grant)
}

/// Checks `jws` as `device_pub`'s own statement for this host (`dev` is the
/// Noise-proved key) naming `grant`'s account. Statements are checked even
/// with `[guest] accounts` off: that switch governs guest shares, and an
/// owner grant always needs one. The deadline never passes the grant's
/// expiry, so the connection ends when the grant does.
fn check_statement(
    dir: &Path,
    env: &account::Env<'_>,
    grant: &OwnerGrant,
    device_pub: &[u8; 32],
    jws: &str,
    now: u64,
) -> Result<u64, &'static str> {
    let (host, _) = store::load_host(dir).map_err(|err| {
        tracing::warn!(err = %err, "guest host identity unavailable; refusing statement");
        codes::INVALID
    })?;
    let verified = account::check(
        dir,
        &(env.settings)(),
        env.fetch_keys,
        &host.host_id,
        device_pub,
        jws,
        now,
    )?;
    if verified.sub != grant.account {
        return Err(codes::MISMATCH);
    }
    Ok(verified.deadline_ms.min(grant.expires_ms))
}

/// Admits an owner hello (`{"v":1, "mode":"owner", "account":"<jws>",
/// "device":"…"}`) from the Noise-proved `device_pub`. Refusals are
/// `owner_not_granted`, `owner_expired`, `owner_busy` and the statement codes
/// (`account_required`, `statement_invalid`, `statement_expired`,
/// `account_keys_stale`, `account_mismatch`).
pub(crate) fn admit_in(
    dir: &Path,
    env: &account::Env<'_>,
    device_pub: [u8; 32],
    hello: &serde_json::Value,
    now: u64,
) -> Result<OwnerAdmission, &'static str> {
    let key = store::b64url(&device_pub);
    let grant = live_grant(dir, |grant| grant.device_pub == key, now)?;
    let jws = match hello.get("account") {
        None | Some(serde_json::Value::Null) => return Err(codes::REQUIRED),
        Some(serde_json::Value::String(jws)) => jws,
        Some(_) => return Err(codes::INVALID),
    };
    let deadline_ms = check_statement(dir, env, &grant, &device_pub, jws, now)?;
    let live = super::register_live_capped(&live_key(&grant.grant_id), SESSION_CAP)
        .ok_or(refusals::BUSY)?;
    let principal = OwnerPrincipal {
        grant_id: grant.grant_id.clone(),
        fingerprint: grant.fingerprint.clone(),
        device: grant.device.clone(),
        dir: dir.to_path_buf(),
        live,
    };
    if note_connected(dir, &grant.grant_id, now) {
        principal.audit(GuestAuditEvent::OwnerConnected, None, None);
    }
    let reply = serde_json::json!({
        "ok": true,
        "mode": "owner",
        "grant_id": grant.grant_id,
        "scope": grant.scope,
        "expires_unix": grant.expires_ms / 1000,
        "machine_label": crate::platform::hostname().unwrap_or_default(),
        "account": {"deadline_unix": deadline_ms / 1000},
        // `multi_request`: the connection serves further requests after a
        // reply (see `serve_session` in the API's owner gate).
        "features": {"owner": PROTOCOL, "multi_request": true},
    });
    Ok(OwnerAdmission {
        principal,
        reply,
        account: AccountSession {
            holder: AccountHolder::Owner(grant.grant_id),
            device_pub,
            deadline_ms,
        },
    })
}

/// Records an admission on the grant: `last_seen_ms` at most once per
/// [`store::LAST_SEEN_RESOLUTION_MS`], and whether this one should be
/// audited as `owner_connected` (at most once per
/// [`store::CONNECTED_AUDIT_WINDOW_MS`]).
fn note_connected(dir: &Path, grant_id: &str, now: u64) -> bool {
    let noted = store::update_store(dir, |store| {
        let Some(grant) = store
            .owners
            .iter_mut()
            .find(|grant| grant.grant_id == grant_id && !grant.revoked)
        else {
            return (false, false);
        };
        let due = |at: Option<u64>, every: u64| at.is_none_or(|at| now.saturating_sub(at) >= every);
        let seen = due(grant.last_seen_ms, store::LAST_SEEN_RESOLUTION_MS);
        let connected = due(grant.last_connected_ms, store::CONNECTED_AUDIT_WINDOW_MS);
        if seen {
            grant.last_seen_ms = Some(now);
        }
        if connected {
            grant.last_connected_ms = Some(now);
        }
        (connected, seen || connected)
    });
    noted.unwrap_or_else(|err| {
        tracing::warn!(err = %err, "owner grant last seen not recorded");
        false
    })
}

/// `account.refresh` on a live owner connection: the new deadline when the
/// statement is the browser's own, names the grant's account, and the grant
/// is still live; else the code that ends the connection.
pub(crate) fn refresh_in(
    dir: &Path,
    env: &account::Env<'_>,
    grant_id: &str,
    device_pub: &[u8; 32],
    jws: &str,
    now: u64,
) -> Result<u64, &'static str> {
    let key = store::b64url(device_pub);
    let grant = live_grant(
        dir,
        |grant| grant.grant_id == grant_id && grant.device_pub == key,
        now,
    )?;
    check_statement(dir, env, &grant, device_pub, jws, now)
}

/// A grant written straight into the store and an admitted principal for
/// it, for the API gate's tests (no statement, no relay).
#[cfg(test)]
pub(crate) fn test_principal(
    dir: &Path,
    device_pub: [u8; 32],
    scope: OwnerScope,
) -> OwnerPrincipal {
    let now = store::now_ms();
    let grant = OwnerGrant {
        grant_id: store::b64url(&store::random_bytes::<16>().unwrap()),
        device_pub: store::b64url(&device_pub),
        fingerprint: store::fingerprint(&device_pub),
        device: "Chrome on macOS".into(),
        account: "sub-Example-012345678".into(),
        scope,
        approved_by: "Jerry's iPhone".into(),
        created_ms: now,
        expires_ms: now + 60 * 60 * 1000,
        renewed_ms: None,
        last_seen_ms: None,
        revoked: false,
        revoked_ms: None,
        last_connected_ms: None,
    };
    let stored = grant.clone();
    store::update_store(dir, |store| {
        store.owners.push(stored);
        ((), true)
    })
    .unwrap();
    OwnerPrincipal {
        live: super::register_live_capped(&live_key(&grant.grant_id), SESSION_CAP).unwrap(),
        grant_id: grant.grant_id,
        fingerprint: grant.fingerprint,
        device: grant.device,
        dir: dir.to_path_buf(),
    }
}
