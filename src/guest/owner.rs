//! Owner grants (`owner_access.*`): the owner's own browsers allowed on this
//! machine through the HerdrUp guest relay. A grant names one browser key,
//! is bound to the account of the device that approved it (from that
//! device's account statement), and lasts 1 hour to 30 days. Grants live in
//! `guests.json` under `owners`, beside guests and invites.
//!
//! This module writes and lists grants; browsers cannot use them yet.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::api::schema::{
    GuestAuditEntry, GuestAuditEvent, GuestLinkInfo, OwnerAccessAddParams, OwnerGrantInfo,
    OwnerScope,
};

use super::{account, audit, io_error, notify_changes, store, OwnerError};

/// `owner_access.info`'s `protocol`.
pub(crate) const PROTOCOL: u32 = 1;
/// The shortest grant: 1 hour.
pub(crate) const MIN_TTL_SECS: u64 = 60 * 60;
/// The longest grant: 30 days.
pub(crate) const MAX_TTL_SECS: u64 = 30 * 24 * 60 * 60;
/// Live (not revoked, not expired) grants per machine.
pub(crate) const MAX_LIVE_GRANTS: usize = 10;
/// Revoked and expired grants are deleted this long after they ended. Until
/// then an expired one can be renewed.
pub(crate) const ENDED_RETENTION_MS: u64 = 30 * 24 * 60 * 60 * 1000;
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
        let entry = GuestAuditEntry {
            ts_ms: now,
            guest_id: self.grant_id.clone(),
            name: self.device.clone(),
            fingerprint: self.fingerprint.clone(),
            event,
            pane: String::new(),
            method: None,
            text,
            file: None,
        };
        if let Err(err) = audit::append(dir, &entry) {
            tracing::warn!(err = %err, "owner access audit log write failed");
        }
    }
}

/// Drop grants that ended more than [`ENDED_RETENTION_MS`] ago. Returns
/// whether any was dropped.
pub(crate) fn prune(owners: &mut Vec<OwnerGrant>, now: u64) -> bool {
    let before = owners.len();
    owners.retain(|grant| grant.retained(now));
    owners.len() != before
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
    let verified = account::check(
        dir,
        &(env.settings)(),
        env.fetch_keys,
        &host.host_id,
        None,
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
    .ok_or_else(|| {
        (
            "owner_grant_limit",
            format!("this machine already allows {MAX_LIVE_GRANTS} browsers; remove one first"),
        )
    })?;
    notify_changes();
    for old in &replaced {
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
        let Some(grant) = store
            .owners
            .iter_mut()
            .find(|grant| grant.grant_id == grant_id)
        else {
            return (
                Err((
                    "owner_grant_not_found",
                    "no owner grant with that id".to_string(),
                )),
                pruned,
            );
        };
        if grant.revoked {
            return (
                Err((
                    "owner_grant_revoked",
                    "this grant was removed; approve the browser again".to_string(),
                )),
                pruned,
            );
        }
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
        grant.audit(dir, GuestAuditEvent::OwnerRemoved, None, now);
    }
    Ok(removed.into_iter().map(|grant| grant.grant_id).collect())
}
