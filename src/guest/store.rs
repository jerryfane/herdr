//! Guest store (`guests.json`), host identity (`node_key`, `host.json`),
//! invites and admission. Everything lives in `<config>/guest/`: the directory
//! is 0700 and every file 0600, repaired on each load.

use std::fs::{self, OpenOptions};
use std::io::{self, Write as _};
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::api::schema::{
    AgentSessionInfo, GuestDeviceInfo, GuestGrantInfo, GuestInfo, GuestInviteInfo,
};

const DIR_MODE: u32 = 0o700;
const FILE_MODE: u32 = 0o600;
pub(crate) const DEFAULT_INVITE_TTL_SECS: u64 = 24 * 60 * 60;
pub(crate) const MIN_INVITE_TTL_SECS: u64 = 60;
pub(crate) const MAX_INVITE_TTL_SECS: u64 = 7 * 24 * 60 * 60;
/// Unused invites are dropped from the store this long after they expire.
const EXPIRED_INVITE_RETENTION_MS: u64 = 7 * 24 * 60 * 60 * 1000;
/// `last_seen_ms` is rewritten at most this often, so each request does not
/// rewrite the store.
const LAST_SEEN_RESOLUTION_MS: u64 = 60 * 1000;
/// One `connected` audit entry per guest per this window: every guest request
/// is its own Noise session.
pub(crate) const CONNECTED_AUDIT_WINDOW_MS: u64 = 10 * 60 * 1000;
/// The link stays up this long after the latest revoke, so a revoked guest
/// hears `revoked` rather than `host_offline`.
pub(crate) const REVOKED_LINK_GRACE_MS: u64 = 24 * 60 * 60 * 1000;

pub(crate) fn guest_dir() -> PathBuf {
    crate::config::config_dir().join("guest")
}

pub(crate) fn b64url(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn b64url_decode(text: &str) -> Option<Vec<u8>> {
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(text)
        .ok()
}

pub(crate) fn random_bytes<const N: usize>() -> io::Result<[u8; N]> {
    let mut bytes = [0u8; N];
    getrandom::getrandom(&mut bytes).map_err(io::Error::other)?;
    Ok(bytes)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// `SHA256:` plus lowercase hex of the first 8 bytes of SHA-256(device key),
/// grouped in 4s with `·`.
pub(crate) fn fingerprint(device_pub: &[u8; 32]) -> String {
    let hex = sha256_hex(device_pub);
    let groups: Vec<&str> = (0..4).map(|index| &hex[index * 4..index * 4 + 4]).collect();
    format!("SHA256:{}", groups.join("·"))
}

/// `^[A-Za-z0-9][A-Za-z0-9._-]{0,31}$`.
pub(crate) fn valid_guest_name(name: &str) -> bool {
    let mut chars = name.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    name.len() <= 32
        && first.is_ascii_alphanumeric()
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

pub(crate) fn guest_label(name: &str) -> String {
    format!("{name} (via HerdrUp): ")
}

pub(crate) fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|since| since.as_millis() as u64)
        .unwrap_or_default()
}

/// Create the directory 0700, or tighten an existing one.
pub(crate) fn ensure_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    repair_mode(dir, DIR_MODE)
}

fn repair_mode(path: &Path, mode: u32) -> io::Result<()> {
    match fs::metadata(path) {
        Ok(metadata) if metadata.permissions().mode() & 0o777 != mode => {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
        }
        Ok(_) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// Read a private file, first tightening its mode to 0600.
fn read_private(path: &Path) -> io::Result<Option<Vec<u8>>> {
    repair_mode(path, FILE_MODE)?;
    match fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// Atomically replace `path` with `bytes` through a 0600 temp file.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let written = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(FILE_MODE)
        .open(&tmp)
        .and_then(|mut file| {
            file.set_permissions(fs::Permissions::from_mode(FILE_MODE))?;
            file.write_all(bytes)?;
            file.sync_all()
        });
    if let Err(err) = written {
        let _ = fs::remove_file(&tmp);
        return Err(err);
    }
    fs::rename(&tmp, path).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

/// Hold the store lock for one read-modify-write.
fn with_lock<T>(dir: &Path, operation: impl FnOnce() -> io::Result<T>) -> io::Result<T> {
    ensure_dir(dir)?;
    let lock = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(FILE_MODE)
        .open(dir.join(".guests.lock"))?;
    lock.lock()?;
    operation()
}

fn load_side_unlocked<T: Default + serde::de::DeserializeOwned>(
    dir: &Path,
    file: &str,
) -> io::Result<T> {
    match read_private(&dir.join(file))? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err)),
        None => Ok(T::default()),
    }
}

/// Load a private JSON file kept beside `guests.json` (default when absent).
pub(crate) fn load_side<T: Default + serde::de::DeserializeOwned>(
    dir: &Path,
    file: &str,
) -> io::Result<T> {
    with_lock(dir, || load_side_unlocked(dir, file))
}

/// Read-modify-write a file kept beside `guests.json` under the store lock.
/// It is written only when `mutate` reports a change.
pub(crate) fn update_side<T, R>(
    dir: &Path,
    file: &str,
    mutate: impl FnOnce(&mut T) -> (R, bool),
) -> io::Result<R>
where
    T: Default + Serialize + serde::de::DeserializeOwned,
{
    with_lock(dir, || {
        let mut value = load_side_unlocked(dir, file)?;
        let (result, changed) = mutate(&mut value);
        if changed {
            write_private(&dir.join(file), &serde_json::to_vec_pretty(&value)?)?;
        }
        Ok(result)
    })
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct HostIdentity {
    pub host_id: String,
    pub relay_secret: String,
}

/// Load or create the X25519 node key and `host.json`.
pub(crate) fn load_host(dir: &Path) -> io::Result<(HostIdentity, [u8; 32])> {
    with_lock(dir, || {
        let key_path = dir.join("node_key");
        let node_secret: [u8; 32] = match read_private(&key_path)? {
            Some(bytes) => bytes.try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "guest node_key is not 32 bytes; refusing to replace it",
                )
            })?,
            None => {
                let secret = random_bytes::<32>()?;
                write_private(&key_path, &secret)?;
                secret
            }
        };
        let host_path = dir.join("host.json");
        let host = match read_private(&host_path)? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?,
            None => {
                let host = HostIdentity {
                    host_id: b64url(&random_bytes::<16>()?),
                    relay_secret: b64url(&random_bytes::<32>()?),
                };
                write_private(&host_path, &serde_json::to_vec_pretty(&host)?)?;
                host
            }
        };
        Ok((host, node_secret))
    })
}

/// X25519 public key for `secret`.
pub(crate) fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    use snow::resolvers::{CryptoResolver as _, DefaultResolver};
    let mut dh = DefaultResolver
        .resolve_dh(&snow::params::DHChoice::Curve25519)
        .expect("snow always resolves Curve25519");
    dh.set(secret);
    let mut public = [0u8; 32];
    public.copy_from_slice(dh.pubkey());
    public
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GuestRecord {
    pub guest_id: String,
    pub name: String,
    /// b64url X25519 device public key. Never leaves this file.
    pub device_pub: String,
    pub fingerprint: String,
    #[serde(default)]
    pub device: String,
    pub grant: GuestGrantInfo,
    #[serde(default)]
    pub owner_name: String,
    #[serde(default)]
    pub machine_label: String,
    pub created_ms: u64,
    #[serde(default)]
    pub last_seen_ms: Option<u64>,
    /// Last `connected` audit entry. Tracked apart from `last_seen_ms`, which
    /// a polling client refreshes every minute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_connected_ms: Option<u64>,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_ms: Option<u64>,
    /// The guest sees the agent's Gram from `created_ms` on.
    #[serde(default)]
    pub share_gram: bool,
    /// Names the granted agent had before the owner renamed it, so the
    /// guest's Gram from before a rename stays visible.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub former_names: Vec<FormerName>,
    /// Terminals the granted agent ran in before it was recreated in another
    /// one, so the guest's Gram from before that stays visible.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub former_terminals: Vec<FormerTerminal>,
    /// The harness sessions the granted agent ran in the grant's terminal
    /// since the grant followed it there (see [`rebind_grants`]): that
    /// terminal's Grams count only when this machine saw one of them send it,
    /// whatever its clock or a coordinator's said. Empty: the terminal the
    /// guest accepted, whose Grams all count.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terminal_sessions: Vec<AgentSessionInfo>,
    /// The guest's pairwise HerdrUp account id on this host when the share is
    /// bound to their account; `None` for a plain share bound to `device_pub`
    /// alone. Every connection to an account-bound share proves the account
    /// with a statement (see [`super::account`]).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account: Option<String>,
    /// Devices the account added after `device_pub`, which stays the
    /// redeeming device. A removed entry keeps its key out for good, even
    /// with a valid statement; it may name `device_pub` itself.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub devices: Vec<AccountDevice>,
}

/// One more device of an account-bound share's person.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AccountDevice {
    /// b64url X25519 device public key. Never leaves this file.
    pub device_pub: String,
    pub fingerprint: String,
    #[serde(default)]
    pub device: String,
    pub added_ms: u64,
    #[serde(default)]
    pub last_seen_ms: Option<u64>,
    #[serde(default)]
    pub removed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub removed_ms: Option<u64>,
}

/// A name the granted agent gave up in a rename. It names the agent only in
/// Grams created before `until_ms`: another agent may take it afterwards.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FormerName {
    pub name: String,
    pub until_ms: u64,
}

/// A terminal the granted agent left when it was recreated in another one.
/// Its Grams count as the agent's when sent from one of `sessions`, or any
/// of them when empty (the terminal the guest accepted). Terminal ids are
/// never reused, so it sends nothing after the agent left.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FormerTerminal {
    pub terminal_id: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sessions: Vec<AgentSessionInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InviteRecord {
    pub invite_id: String,
    /// Hex SHA-256 of the decoded 32-byte secret. The secret itself is never stored.
    pub secret_sha256: String,
    pub name: String,
    pub grant: GuestGrantInfo,
    pub owner_name: String,
    pub machine_label: String,
    pub created_ms: u64,
    pub expires_ms: u64,
    #[serde(default)]
    pub used_by: Option<String>,
    #[serde(default)]
    pub share_gram: bool,
    /// The sealed copy published on the relay for the short link, deleted on
    /// revoke and once the invite is redeemed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short: Option<ShortInvite>,
    /// [`GuestRecord::terminal_sessions`] for the guest who accepts it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terminal_sessions: Vec<AgentSessionInfo>,
}

/// Where a short invite's sealed blob lives. Its key is never stored: it
/// exists only in the link handed to the owner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ShortInvite {
    /// The blob id on the relay, 12 base64url characters.
    pub id: String,
    /// The relay holding the blob: the owner may change `relay_url` before
    /// the invite is redeemed or revoked.
    pub relay: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct GuestStore {
    #[serde(default)]
    pub guests: Vec<GuestRecord>,
    #[serde(default)]
    pub invites: Vec<InviteRecord>,
}

impl GuestRecord {
    pub(crate) fn info(&self) -> GuestInfo {
        GuestInfo {
            guest_id: self.guest_id.clone(),
            name: self.name.clone(),
            fingerprint: self.fingerprint.clone(),
            device: self.device.clone(),
            grant: self.grant.clone(),
            created_ms: self.created_ms,
            last_seen_ms: self.last_seen_ms,
            revoked: self.revoked,
            share_gram: self.share_gram,
            account_bound: self.account.is_some(),
            person: self.person().to_owned(),
            devices: self
                .devices
                .iter()
                .map(|device| GuestDeviceInfo {
                    fingerprint: device.fingerprint.clone(),
                    device: device.device.clone(),
                    added_ms: device.added_ms,
                    last_seen_ms: device.last_seen_ms,
                    removed: device.removed,
                })
                .collect(),
        }
    }

    /// Who the share belongs to: the account id when account-bound, else the
    /// device's fingerprint. `guest.revoke {person}` revokes by it.
    pub(crate) fn person(&self) -> &str {
        self.account.as_deref().unwrap_or(&self.fingerprint)
    }

    /// The device with this fingerprint may use the share now: the redeeming
    /// device or an added one, and not removed.
    pub(crate) fn admits_fingerprint(&self, fingerprint: &str) -> bool {
        let removed = self
            .devices
            .iter()
            .any(|device| device.fingerprint == fingerprint && device.removed);
        !removed
            && (self.fingerprint == fingerprint
                || self
                    .devices
                    .iter()
                    .any(|device| device.fingerprint == fingerprint))
    }

    /// The share holds this device key: the redeeming device or an added
    /// one, removed or not.
    fn holds_device(&self, device: &str) -> bool {
        self.device_pub == device || self.devices.iter().any(|added| added.device_pub == device)
    }
}

impl InviteRecord {
    pub(crate) fn info(&self) -> GuestInviteInfo {
        GuestInviteInfo {
            invite_id: self.invite_id.clone(),
            name: self.name.clone(),
            grant: self.grant.clone(),
            owner_name: self.owner_name.clone(),
            machine_label: self.machine_label.clone(),
            created_ms: self.created_ms,
            expires_ms: self.expires_ms,
            used_by: self.used_by.clone(),
            share_gram: self.share_gram,
        }
    }

    fn pending(&self, now: u64) -> bool {
        self.used_by.is_none() && now < self.expires_ms
    }
}

fn load_store_unlocked(dir: &Path) -> io::Result<GuestStore> {
    match read_private(&dir.join("guests.json"))? {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err)),
        None => Ok(GuestStore::default()),
    }
}

pub(crate) fn load_store(dir: &Path) -> io::Result<GuestStore> {
    with_lock(dir, || load_store_unlocked(dir))
}

/// Read-modify-write the store under the lock. The store is written only
/// when `mutate` reports a change.
pub(crate) fn update_store<T>(
    dir: &Path,
    mutate: impl FnOnce(&mut GuestStore) -> (T, bool),
) -> io::Result<T> {
    with_lock(dir, || {
        let mut store = load_store_unlocked(dir)?;
        let (value, changed) = mutate(&mut store);
        if changed {
            let now = now_ms();
            store.invites.retain(|invite| {
                invite.used_by.is_some()
                    || invite
                        .expires_ms
                        .saturating_add(EXPIRED_INVITE_RETENTION_MS)
                        > now
            });
            write_private(
                &dir.join("guests.json"),
                &serde_json::to_vec_pretty(&store)?,
            )?;
        }
        Ok(value)
    })
}

/// At least one non-revoked guest, one unexpired unused invite, or a revoke
/// within [`REVOKED_LINK_GRACE_MS`].
pub(crate) fn link_wanted_in(dir: &Path, now: u64) -> bool {
    load_store(dir).is_ok_and(|store| {
        store.guests.iter().any(|guest| {
            !guest.revoked
                || guest
                    .revoked_ms
                    .is_some_and(|at| now < at.saturating_add(REVOKED_LINK_GRACE_MS))
        }) || store.invites.iter().any(|invite| invite.pending(now))
    })
}

/// Record a resumed agent's new harness session on an active guest's grant.
/// Returns whether the stored grant changed.
pub(crate) fn update_grant_session(
    dir: &Path,
    guest_id: &str,
    session: &crate::api::schema::AgentSessionInfo,
) -> io::Result<bool> {
    update_store(dir, |store| {
        let Some(guest) = store
            .guests
            .iter_mut()
            .find(|guest| guest.guest_id == guest_id && !guest.revoked)
        else {
            return (false, false);
        };
        let changed = guest.grant.agent_session != *session;
        if changed {
            guest.grant.agent_session = session.clone();
            // In a terminal the grant followed the agent to, its new
            // session's Grams are the agent's too.
            if !guest.terminal_sessions.is_empty() && !guest.terminal_sessions.contains(session) {
                guest.terminal_sessions.push(session.clone());
            }
        }
        (changed, changed)
    })
}

/// The granted agent (this terminal, name and kind) runs `session` in a
/// terminal its grant followed it to: that session's Grams are the agent's
/// for every active guest and pending invite holding it there. Grants in the
/// terminal the guest accepted keep every session already. Returns whether
/// anything changed.
pub(crate) fn note_terminal_session(
    dir: &Path,
    terminal_id: &str,
    name: &str,
    kind: &str,
    session: &AgentSessionInfo,
) -> io::Result<bool> {
    let holds = |grant: &GuestGrantInfo, sessions: &[AgentSessionInfo]| {
        !sessions.is_empty()
            && !sessions.contains(session)
            && super::grant_names(grant, terminal_id, Some(name), kind)
    };
    update_store(dir, |store| {
        let mut changed = false;
        for guest in store
            .guests
            .iter_mut()
            .filter(|guest| !guest.revoked && holds(&guest.grant, &guest.terminal_sessions))
        {
            guest.terminal_sessions.push(session.clone());
            changed = true;
        }
        let now = now_ms();
        for invite in store
            .invites
            .iter_mut()
            .filter(|invite| invite.pending(now) && holds(&invite.grant, &invite.terminal_sessions))
        {
            invite.terminal_sessions.push(session.clone());
            changed = true;
        }
        (changed, changed)
    })
}

/// The active grant of this guest as stored now.
pub(crate) fn active_grant(dir: &Path, guest_id: &str) -> Option<GuestGrantInfo> {
    active_record(dir, guest_id).map(|guest| guest.grant)
}

/// This guest's record as stored now, unless it was revoked or removed (or
/// the store cannot be read).
pub(crate) fn active_record(dir: &Path, guest_id: &str) -> Option<GuestRecord> {
    load_store(dir)
        .ok()?
        .guests
        .into_iter()
        .find(|guest| guest.guest_id == guest_id && !guest.revoked)
}

/// The owner renamed the agent in `terminal_id` from `old` to `new`: every
/// active guest and pending invite granted that agent (this terminal, the
/// old name, this kind) now names it `new`, and each guest remembers the
/// name it had for its Gram from before `now`. With no `old` the agent had
/// no name, and the grants of this terminal and kind follow from whatever
/// name they last knew it by. Returns whether anything changed.
pub(crate) fn rename_grants(
    dir: &Path,
    terminal_id: &str,
    old: Option<&str>,
    new: &str,
    kind: &str,
    now: u64,
) -> io::Result<bool> {
    let follows = |grant: &GuestGrantInfo| match old {
        Some(old) => super::grant_names(grant, terminal_id, Some(old), kind),
        None => {
            grant.agent_name.as_deref().is_some_and(|name| name != new)
                && super::grant_holds(grant, terminal_id, kind)
        }
    };
    update_store(dir, |store| {
        let mut changed = false;
        for guest in store
            .guests
            .iter_mut()
            .filter(|guest| !guest.revoked && follows(&guest.grant))
        {
            if let Some(name) = guest.grant.agent_name.replace(new.to_string()) {
                guest.former_names.push(FormerName {
                    name,
                    until_ms: now,
                });
            }
            changed = true;
        }
        for invite in store
            .invites
            .iter_mut()
            .filter(|invite| invite.pending(now) && follows(&invite.grant))
        {
            invite.grant.agent_name = Some(new.to_string());
            changed = true;
        }
        (changed, changed)
    })
}

/// A grant or pending invite moved to the terminal its agent was recreated in.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Rebound {
    /// The guest id, or the invite id when `invite`.
    pub id: String,
    pub invite: bool,
    pub from: String,
    pub to: String,
}

/// Move every active guest and pending invite whose agent was recreated in
/// another terminal to that terminal: `recreated` names the one terminal now
/// holding the grant's agent session, or `None` to leave the grant alone. The
/// grant takes the agent's name there, remembering the old one, and each guest
/// remembers the terminal it left for its Gram from before `now`. A device
/// already granted the new terminal keeps that grant alone, as accepting
/// an invite there would have replaced this one. Revoked guests and used or
/// expired invites never move. Returns what moved.
pub(crate) fn rebind_grants<'a>(
    dir: &Path,
    now: u64,
    recreated: impl Fn(&GuestGrantInfo) -> Option<&'a super::SessionHolder>,
) -> io::Result<Vec<Rebound>> {
    update_store(dir, |store| {
        let mut rebound = Vec::new();
        for index in 0..store.guests.len() {
            let guest = &store.guests[index];
            if guest.revoked {
                continue;
            }
            let Some(holder) = recreated(&guest.grant) else {
                continue;
            };
            let device = &guest.device_pub;
            if store.guests.iter().any(|other| {
                !other.revoked
                    && other.device_pub == *device
                    && other.grant.terminal_id == holder.terminal_id
            }) {
                continue;
            }
            let guest = &mut store.guests[index];
            let from = std::mem::replace(&mut guest.grant.terminal_id, holder.terminal_id.clone());
            guest.former_terminals.push(FormerTerminal {
                terminal_id: from.clone(),
                sessions: std::mem::replace(
                    &mut guest.terminal_sessions,
                    vec![guest.grant.agent_session.clone()],
                ),
            });
            if let Some(name) = holder.name.as_deref() {
                if guest.grant.agent_name.as_deref() != Some(name) {
                    if let Some(old) = guest.grant.agent_name.replace(name.to_string()) {
                        guest.former_names.push(FormerName {
                            name: old,
                            until_ms: now,
                        });
                    }
                }
            }
            rebound.push(Rebound {
                id: guest.guest_id.clone(),
                invite: false,
                from,
                to: holder.terminal_id.clone(),
            });
        }
        for invite in store
            .invites
            .iter_mut()
            .filter(|invite| invite.pending(now))
        {
            let Some(holder) = recreated(&invite.grant) else {
                continue;
            };
            let from = std::mem::replace(&mut invite.grant.terminal_id, holder.terminal_id.clone());
            if holder.name.is_some() {
                invite.grant.agent_name.clone_from(&holder.name);
            }
            invite.terminal_sessions = vec![invite.grant.agent_session.clone()];
            rebound.push(Rebound {
                id: invite.invite_id.clone(),
                invite: true,
                from,
                to: holder.terminal_id.clone(),
            });
        }
        let changed = !rebound.is_empty();
        (rebound, changed)
    })
}

/// Whether an active guest shares the agent's Gram. False for a revoked or
/// unknown guest, or when the store cannot be read.
pub(crate) fn shares_gram(dir: &Path, guest_id: &str) -> bool {
    load_store(dir).is_ok_and(|store| {
        store
            .guests
            .iter()
            .any(|guest| guest.guest_id == guest_id && !guest.revoked && guest.share_gram)
    })
}

/// The guest was revoked or removed, or the owner removed the device with
/// `fingerprint` from its account-bound share (or the store cannot be read).
pub(crate) fn is_revoked(dir: &Path, guest_id: &str, fingerprint: &str) -> bool {
    load_store(dir).map_or(true, |store| {
        store
            .guests
            .iter()
            .find(|guest| guest.guest_id == guest_id)
            .is_none_or(|guest| guest.revoked || !guest.admits_fingerprint(fingerprint))
    })
}

pub(crate) struct NewInvite {
    pub record: InviteRecord,
    /// b64url secret; returned once, inside the links.
    pub secret: String,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn create_invite(
    dir: &Path,
    name: &str,
    grant: GuestGrantInfo,
    owner_name: &str,
    machine_label: &str,
    ttl_secs: u64,
    share_gram: bool,
    now: u64,
) -> io::Result<NewInvite> {
    let secret_bytes = random_bytes::<32>()?;
    let record = InviteRecord {
        invite_id: b64url(&random_bytes::<16>()?),
        secret_sha256: sha256_hex(&secret_bytes),
        name: name.to_string(),
        grant,
        owner_name: owner_name.to_string(),
        machine_label: machine_label.to_string(),
        created_ms: now,
        expires_ms: now.saturating_add(ttl_secs.saturating_mul(1000)),
        used_by: None,
        share_gram,
        short: None,
        terminal_sessions: Vec::new(),
    };
    let stored = record.clone();
    update_store(dir, move |store| {
        store.invites.push(stored);
        ((), true)
    })?;
    Ok(NewInvite {
        record,
        secret: b64url(&secret_bytes),
    })
}

/// Turn Gram sharing on or off for an active guest. Returns the updated
/// record, or `None` when no active guest has this id.
pub(crate) fn update_share_gram(
    dir: &Path,
    guest_id: &str,
    share_gram: bool,
) -> io::Result<Option<GuestRecord>> {
    update_store(dir, |store| {
        let Some(guest) = store
            .guests
            .iter_mut()
            .find(|guest| guest.guest_id == guest_id && !guest.revoked)
        else {
            return (None, false);
        };
        let changed = guest.share_gram != share_gram;
        guest.share_gram = share_gram;
        (Some(guest.clone()), changed)
    })
}

/// The v1 invite JSON: the long links carry it b64url-encoded and the short
/// link's relay blob carries these exact bytes sealed. With `accounts`
/// (`[guest] accounts`) it carries `"acct": 1`: the guest may bind the share
/// to their HerdrUp account.
pub(crate) fn invite_payload(
    relay_url: &str,
    host: &HostIdentity,
    host_pub: &[u8; 32],
    invite: &NewInvite,
    accounts: bool,
) -> String {
    let mut payload = serde_json::json!({
        "v": 1,
        "relay": relay_url.trim_end_matches('/'),
        "host_id": host.host_id,
        "host_pub": b64url(host_pub),
        "invite_id": invite.record.invite_id,
        "secret": invite.secret,
        "machine_label": invite.record.machine_label,
        "owner_name": invite.record.owner_name,
        "agent_name": invite.record.grant.agent_name,
        "guest_name": invite.record.name,
        "expires_unix": invite.record.expires_ms / 1000,
    });
    if accounts {
        payload["acct"] = serde_json::json!(1);
    }
    payload.to_string()
}

/// The app link and the long web link, each carrying `payload` b64url-encoded.
pub(crate) fn invite_links(relay_url: &str, payload: &str) -> (String, String) {
    let relay = relay_url.trim_end_matches('/');
    let encoded = b64url(payload.as_bytes());
    (
        format!("herdrup://guest-invite#{encoded}"),
        format!("{relay}/i/{encoded}"),
    )
}

/// Record where an invite's short-link blob was published. `false` when the
/// invite is gone or already redeemed, so the caller deletes the blob.
pub(crate) fn set_invite_short(
    dir: &Path,
    invite_id: &str,
    short: ShortInvite,
) -> io::Result<bool> {
    update_store(dir, |store| {
        let Some(invite) = store
            .invites
            .iter_mut()
            .find(|invite| invite.invite_id == invite_id && invite.used_by.is_none())
        else {
            return (false, false);
        };
        invite.short = Some(short);
        (true, true)
    })
}

/// What a hello's `account` statement amounted to. It is checked before the
/// store is locked, since checking may fetch the issuer's keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AccountHello {
    /// No statement: a plain hello.
    Absent,
    Verified(super::account::Verified),
    /// Refused with this code. A plain share ignores it.
    Refused(&'static str),
}

/// Outcome of a Noise message-1 payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AdmitOutcome {
    /// `connected` is true when this admission should be audited as a new
    /// connection (first contact in [`CONNECTED_AUDIT_WINDOW_MS`]). `added`
    /// is a device the person just added to an account-bound share.
    Returning {
        guest: GuestRecord,
        connected: bool,
        added: Option<AccountDevice>,
    },
    /// `replaced` lists this device's (or this account's) earlier guest ids
    /// for the same terminal, now revoked. `short` is the redeemed invite's
    /// relay blob, now to be deleted.
    Accepted {
        guest: GuestRecord,
        replaced: Vec<String>,
        short: Option<ShortInvite>,
    },
    Refused(&'static str),
}

/// The authenticated device a hello came from.
struct Arriving<'a> {
    /// b64url key.
    device: &'a str,
    fingerprint: &'a str,
    /// The `device` name it gave, printable and at most 64 characters.
    name: &'a str,
}

/// Admit a device. A returning guest sends `{"v":1,"guest_id":"..."}` to select
/// a grant belonging to its authenticated device key. Omitting `guest_id` works
/// only for a single active grant; ambiguous hellos get `guest_selection_required`.
/// A new guest instead sends `invite_id`, `secret` and `device`. The secret is
/// checked in constant time before the invite's state is revealed.
///
/// A hello may also carry `account`, a statement already checked into
/// `account`. Redeeming with one binds the share to the account; every hello
/// for an account-bound share needs one for that account, and it may come from
/// any of the account's devices: one the share has not seen is added to it
/// (`added`), and a device the owner removed stays out. Plain shares work
/// exactly as before and ignore `account`.
pub(crate) fn admit_in(
    dir: &Path,
    device_pub: &[u8; 32],
    hello: &serde_json::Value,
    account: &AccountHello,
    now: u64,
) -> io::Result<AdmitOutcome> {
    if hello.get("v").and_then(serde_json::Value::as_u64) != Some(1) {
        return Ok(AdmitOutcome::Refused("invite_invalid"));
    }
    let device = b64url(device_pub);
    let device_name: String = hello
        .get("device")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    let fingerprint = fingerprint(device_pub);
    let Some(invite_id) = hello.get("invite_id") else {
        let guest_id = match hello.get("guest_id") {
            None => None,
            Some(serde_json::Value::String(id)) if !id.is_empty() => Some(id.as_str()),
            Some(_) => return Ok(AdmitOutcome::Refused("unknown")),
        };
        let arriving = Arriving {
            device: &device,
            fingerprint: &fingerprint,
            name: &device_name,
        };
        return admit_returning(dir, &arriving, guest_id, account, now);
    };
    let (Some(invite_id), Some(secret)) = (
        invite_id.as_str(),
        hello.get("secret").and_then(serde_json::Value::as_str),
    ) else {
        return Ok(AdmitOutcome::Refused("invite_invalid"));
    };
    let secret_hash = b64url_decode(secret)
        .filter(|bytes| bytes.len() == 32)
        .map(|bytes| sha256_hex(&bytes));
    update_store(dir, |store| {
        let Some(index) = store
            .invites
            .iter()
            .position(|invite| invite.invite_id == invite_id)
        else {
            return (AdmitOutcome::Refused("invite_invalid"), false);
        };
        let invite = &store.invites[index];
        let secret_ok = secret_hash.as_deref().is_some_and(|hash| {
            crate::api::federation::constant_time_eq(
                hash.as_bytes(),
                invite.secret_sha256.as_bytes(),
            )
        });
        if !secret_ok {
            return (AdmitOutcome::Refused("invite_invalid"), false);
        }
        if invite.used_by.is_some() {
            return (AdmitOutcome::Refused("invite_used"), false);
        }
        if now >= invite.expires_ms {
            return (AdmitOutcome::Refused("invite_expired"), false);
        }
        // "Add to my account": the invite stays unused when the statement
        // fails, so the guest can retry or accept for this device only. The
        // redeeming device is new to the account's share, so it needs keys
        // fetched within the hour.
        let bound = match account {
            AccountHello::Absent => None,
            AccountHello::Refused(code) => return (AdmitOutcome::Refused(code), false),
            AccountHello::Verified(verified) if !verified.keys_fresh => {
                return (
                    AdmitOutcome::Refused(super::account::codes::KEYS_STALE),
                    false,
                )
            }
            AccountHello::Verified(verified) => Some(verified.sub.clone()),
        };
        let guest_id = match random_bytes::<16>() {
            Ok(bytes) => b64url(&bytes),
            Err(_) => return (AdmitOutcome::Refused("invite_invalid"), false),
        };
        // Re-inviting the same terminal replaces that grant, not the device's
        // (or the account's) independently authorized access to other agents
        // on this host.
        let mut replaced = Vec::new();
        for existing in store.guests.iter_mut().filter(|guest| {
            (guest.device_pub == device
                || bound
                    .as_ref()
                    .is_some_and(|sub| guest.account.as_ref() == Some(sub)))
                && !guest.revoked
                && guest.grant.terminal_id == invite.grant.terminal_id
        }) {
            existing.revoked = true;
            existing.revoked_ms = Some(now);
            replaced.push(existing.guest_id.clone());
        }
        let guest = GuestRecord {
            guest_id: guest_id.clone(),
            name: invite.name.clone(),
            device_pub: device.clone(),
            fingerprint: fingerprint.clone(),
            device: device_name.clone(),
            grant: invite.grant.clone(),
            owner_name: invite.owner_name.clone(),
            machine_label: invite.machine_label.clone(),
            created_ms: now,
            last_seen_ms: Some(now),
            last_connected_ms: None,
            revoked: false,
            revoked_ms: None,
            share_gram: invite.share_gram,
            former_names: Vec::new(),
            former_terminals: Vec::new(),
            terminal_sessions: invite.terminal_sessions.clone(),
            account: bound,
            devices: Vec::new(),
        };
        store.invites[index].used_by = Some(guest_id);
        let short = store.invites[index].short.take();
        store.guests.push(guest.clone());
        (
            AdmitOutcome::Accepted {
                guest,
                replaced,
                short,
            },
            true,
        )
    })
}

fn admit_returning(
    dir: &Path,
    arriving: &Arriving<'_>,
    guest_id: Option<&str>,
    account: &AccountHello,
    now: u64,
) -> io::Result<AdmitOutcome> {
    use super::account::codes;

    update_store(dir, |store| {
        let sub = match account {
            AccountHello::Verified(verified) => Some(verified.sub.as_str()),
            AccountHello::Absent | AccountHello::Refused(_) => None,
        };
        // The authenticated Noise device key, or a verified statement for the
        // share's account from that key, is always part of the lookup. A
        // guest id is a selector, never a credential or authority on its own.
        let matches = |guest: &&GuestRecord| {
            (guest.holds_device(arriving.device)
                || sub.is_some_and(|sub| guest.account.as_deref() == Some(sub)))
                && guest_id.is_none_or(|id| guest.guest_id == id)
        };
        let mut live = store
            .guests
            .iter()
            .enumerate()
            .filter(|(_, guest)| matches(guest) && !guest.revoked);
        let Some((selected, _)) = live.next() else {
            let known = store.guests.iter().any(|guest| matches(&guest));
            return (
                AdmitOutcome::Refused(if known { "revoked" } else { "unknown" }),
                false,
            );
        };
        // Old clients that omit the selector can reconnect only when unambiguous.
        // Never silently route one agent's request through another agent's grant.
        if live.next().is_some() {
            return (AdmitOutcome::Refused("guest_selection_required"), false);
        }
        let guest = &mut store.guests[selected];
        let mut added = None;
        let mut changed = false;
        // A plain share was matched by its device key alone, as always.
        if let Some(bound) = &guest.account {
            let verified = match account {
                AccountHello::Absent => return (AdmitOutcome::Refused(codes::REQUIRED), false),
                AccountHello::Refused(code) => return (AdmitOutcome::Refused(code), false),
                AccountHello::Verified(verified) => verified,
            };
            if verified.sub != *bound {
                return (AdmitOutcome::Refused(codes::MISMATCH), false);
            }
            let known = guest
                .devices
                .iter()
                .position(|device| device.device_pub == arriving.device);
            match known {
                Some(index) if guest.devices[index].removed => {
                    return (AdmitOutcome::Refused(codes::DEVICE_REMOVED), false)
                }
                Some(index) => {
                    let device = &mut guest.devices[index];
                    if device
                        .last_seen_ms
                        .is_none_or(|at| now.saturating_sub(at) >= LAST_SEEN_RESOLUTION_MS)
                    {
                        device.last_seen_ms = Some(now);
                        changed = true;
                    }
                }
                None if guest.device_pub == arriving.device => {}
                // Adding a device needs keys fetched within the hour.
                None if !verified.keys_fresh => {
                    return (AdmitOutcome::Refused(codes::KEYS_STALE), false)
                }
                None => {
                    let device = AccountDevice {
                        device_pub: arriving.device.to_owned(),
                        fingerprint: arriving.fingerprint.to_owned(),
                        device: arriving.name.to_owned(),
                        added_ms: now,
                        last_seen_ms: Some(now),
                        removed: false,
                        removed_ms: None,
                    };
                    guest.devices.push(device.clone());
                    added = Some(device);
                    changed = true;
                }
            }
        }
        // The first returning request after acceptance is a connection, and
        // then one per window however often the client polls.
        let connected = guest
            .last_connected_ms
            .is_none_or(|at| now.saturating_sub(at) >= CONNECTED_AUDIT_WINDOW_MS);
        if connected {
            guest.last_connected_ms = Some(now);
        }
        let previous = guest.last_seen_ms.unwrap_or_default();
        let seen = now.saturating_sub(previous) >= LAST_SEEN_RESOLUTION_MS;
        if seen {
            guest.last_seen_ms = Some(now);
        }
        changed |= connected || seen;
        (
            AdmitOutcome::Returning {
                guest: guest.clone(),
                connected,
                added,
            },
            changed,
        )
    })
}

/// Whether an admitted account-bound session may go on with a newer statement
/// for the account (already checked into `verified`): its share is still
/// active and bound to that account, and `device_pub` was not removed.
/// `Err` is the code the session closes with.
pub(crate) fn account_session_holds(
    dir: &Path,
    guest_id: &str,
    device_pub: &[u8; 32],
    verified: &super::account::Verified,
) -> Result<(), &'static str> {
    use super::account::codes;

    let store = load_store(dir).map_err(|_| "revoked")?;
    let Some(guest) = store
        .guests
        .iter()
        .find(|guest| guest.guest_id == guest_id && !guest.revoked)
    else {
        return Err("revoked");
    };
    if guest.account.as_deref() != Some(verified.sub.as_str()) {
        return Err(codes::MISMATCH);
    }
    if !guest.holds_device(&b64url(device_pub))
        || !guest.admits_fingerprint(&fingerprint(device_pub))
    {
        return Err(codes::DEVICE_REMOVED);
    }
    Ok(())
}

pub(crate) enum RevokeTarget<'a> {
    Guest(&'a str),
    Invite(&'a str),
    /// Every share of one person: an account id, or a plain share's device
    /// fingerprint (see [`GuestRecord::person`]).
    Person(&'a str),
}

/// What a revoke removed: the revoked guest record (kept, marked revoked),
/// the deleted invite, or the person's records it revoked now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Revoked {
    Guest(GuestRecord),
    Invite(InviteRecord),
    Person(Vec<GuestRecord>),
}

/// Revoke a guest, a person's guests, or delete an invite. `None` when the
/// id (or person) is unknown.
pub(crate) fn revoke_in(
    dir: &Path,
    target: RevokeTarget<'_>,
    now: u64,
) -> io::Result<Option<Revoked>> {
    update_store(dir, |store| match target {
        RevokeTarget::Guest(guest_id) => {
            match store
                .guests
                .iter_mut()
                .find(|guest| guest.guest_id == guest_id)
            {
                Some(guest) => {
                    if !guest.revoked {
                        guest.revoked = true;
                        guest.revoked_ms = Some(now);
                    }
                    (Some(Revoked::Guest(guest.clone())), true)
                }
                None => (None, false),
            }
        }
        RevokeTarget::Invite(invite_id) => {
            match store
                .invites
                .iter()
                .position(|invite| invite.invite_id == invite_id)
            {
                Some(index) => (Some(Revoked::Invite(store.invites.remove(index))), true),
                None => (None, false),
            }
        }
        RevokeTarget::Person(person) => {
            let mut known = false;
            let mut revoked = Vec::new();
            for guest in store
                .guests
                .iter_mut()
                .filter(|guest| guest.person() == person)
            {
                known = true;
                if !guest.revoked {
                    guest.revoked = true;
                    guest.revoked_ms = Some(now);
                    revoked.push(guest.clone());
                }
            }
            let changed = !revoked.is_empty();
            (known.then_some(Revoked::Person(revoked)), changed)
        }
    })
}

/// What `guest.remove_device` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeviceRemoval {
    /// The share after the removal.
    Removed(Box<GuestRecord>),
    /// The device was removed before; nothing changed.
    AlreadyRemoved(Box<GuestRecord>),
    UnknownGuest,
    UnknownDevice,
    /// A plain share has one device: revoke it instead.
    PlainShare,
}

/// Drop one device from an active account-bound share for good: it is marked
/// removed, so no statement brings it back. The redeeming device can be
/// removed too.
pub(crate) fn remove_device_in(
    dir: &Path,
    guest_id: &str,
    fingerprint: &str,
    now: u64,
) -> io::Result<DeviceRemoval> {
    update_store(dir, |store| {
        let Some(guest) = store
            .guests
            .iter_mut()
            .find(|guest| guest.guest_id == guest_id && !guest.revoked)
        else {
            return (DeviceRemoval::UnknownGuest, false);
        };
        if guest.account.is_none() {
            return (DeviceRemoval::PlainShare, false);
        }
        if let Some(device) = guest
            .devices
            .iter_mut()
            .find(|device| device.fingerprint == fingerprint)
        {
            if device.removed {
                return (
                    DeviceRemoval::AlreadyRemoved(Box::new(guest.clone())),
                    false,
                );
            }
            device.removed = true;
            device.removed_ms = Some(now);
            return (DeviceRemoval::Removed(Box::new(guest.clone())), true);
        }
        if guest.fingerprint != fingerprint {
            return (DeviceRemoval::UnknownDevice, false);
        }
        let redeeming = AccountDevice {
            device_pub: guest.device_pub.clone(),
            fingerprint: guest.fingerprint.clone(),
            device: guest.device.clone(),
            added_ms: guest.created_ms,
            last_seen_ms: guest.last_seen_ms,
            removed: true,
            removed_ms: Some(now),
        };
        guest.devices.push(redeeming);
        (DeviceRemoval::Removed(Box::new(guest.clone())), true)
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) struct TempDir(pub PathBuf);

    impl TempDir {
        pub(crate) fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let path = std::env::temp_dir()
                .join(format!("herdr-guest-{tag}-{}-{nanos}", std::process::id()));
            Self(path.join("guest"))
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            if let Some(parent) = self.0.parent() {
                let _ = fs::remove_dir_all(parent);
            }
        }
    }

    /// Test clock anchored at the real time, since the store prunes stale
    /// invites against the wall clock.
    fn at(offset_ms: u64) -> u64 {
        static START: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
        *START.get_or_init(now_ms) + offset_ms
    }

    pub(crate) fn grant() -> GuestGrantInfo {
        serde_json::from_value(json!({
            "terminal_id": "term_1",
            "agent_name": "llm-opt",
            "agent_session": {"source": "herdr", "agent": "pi", "kind": "id", "value": "s-1"}
        }))
        .unwrap()
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn invite(dir: &Path, now: u64) -> NewInvite {
        create_invite(
            dir,
            "plotarmordev",
            grant(),
            "Jerry",
            "Mac",
            3600,
            false,
            now,
        )
        .unwrap()
    }

    fn accept(invite: &NewInvite, device: &[u8; 32], now: u64, dir: &Path) -> AdmitOutcome {
        admit_in(
            dir,
            device,
            &json!({"v": 1, "invite_id": invite.record.invite_id, "secret": invite.secret, "device": "iPhone"}),
            &AccountHello::Absent,
            now,
        )
        .unwrap()
    }

    #[test]
    fn files_are_private_and_modes_are_repaired_on_load() {
        let dir = TempDir::new("modes");
        let (host, secret) = load_host(&dir.0).unwrap();
        invite(&dir.0, at(1_000));
        assert_eq!(mode(&dir.0), 0o700);
        for file in ["node_key", "host.json", "guests.json"] {
            assert_eq!(mode(&dir.0.join(file)), 0o600, "{file}");
        }
        fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o755)).unwrap();
        for file in ["node_key", "host.json", "guests.json"] {
            fs::set_permissions(dir.0.join(file), fs::Permissions::from_mode(0o644)).unwrap();
        }
        let (again, again_secret) = load_host(&dir.0).unwrap();
        load_store(&dir.0).unwrap();
        assert_eq!(mode(&dir.0), 0o700);
        for file in ["node_key", "host.json", "guests.json"] {
            assert_eq!(mode(&dir.0.join(file)), 0o600, "{file} repaired");
        }
        assert_eq!(host.host_id, again.host_id, "host identity is stable");
        assert_eq!(secret, again_secret);
        assert_eq!(b64url_decode(&host.host_id).unwrap().len(), 16);
        assert_eq!(b64url_decode(&host.relay_secret).unwrap().len(), 32);
    }

    #[test]
    fn a_corrupt_node_key_is_never_silently_replaced() {
        let dir = TempDir::new("badkey");
        ensure_dir(&dir.0).unwrap();
        write_private(&dir.0.join("node_key"), b"short").unwrap();
        assert!(load_host(&dir.0).is_err());
        assert_eq!(fs::read(dir.0.join("node_key")).unwrap(), b"short");
    }

    #[test]
    fn x25519_public_matches_rfc7748_vector() {
        let secret: [u8; 32] =
            hex_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        assert_eq!(
            x25519_public(&secret),
            hex_bytes::<32>("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        );
    }

    fn hex_bytes<const N: usize>(hex: &str) -> [u8; N] {
        let mut out = [0u8; N];
        for (index, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
        }
        out
    }

    /// Messaging apps (iMessage) split a link at `#` and send the fragment as a second
    /// message, so the shareable web link must carry the invite in its path. The app link
    /// keeps the fragment: it never leaves the device.
    #[test]
    fn the_web_link_carries_the_invite_in_its_path() {
        let dir = TempDir::new("links");
        let invite = invite(&dir.0, at(1_000));
        let host = HostIdentity {
            host_id: "h".repeat(22),
            relay_secret: String::new(),
        };
        let json = invite_payload("https://relay.test/", &host, &[9; 32], &invite, false);
        let (app, web) = invite_links("https://relay.test/", &json);
        assert!(
            !web.contains('#'),
            "web link must not use a fragment: {web}"
        );
        let payload = web
            .strip_prefix("https://relay.test/i/")
            .expect("path form");
        assert_eq!(app, format!("herdrup://guest-invite#{payload}"));
        let decoded: serde_json::Value =
            serde_json::from_slice(&b64url_decode(payload).expect("b64url")).unwrap();
        assert_eq!(decoded["secret"], json!(invite.secret));
        assert_eq!(decoded["relay"], json!("https://relay.test"));
        assert_eq!(b64url_decode(payload).unwrap(), json.as_bytes());
        assert!(
            decoded.get("acct").is_none(),
            "plain invites stay as they were"
        );
        let accounts = invite_payload("https://relay.test/", &host, &[9; 32], &invite, true);
        let accounts: serde_json::Value = serde_json::from_str(&accounts).unwrap();
        assert_eq!(accounts["acct"], json!(1));
        assert_eq!(accounts["secret"], decoded["secret"]);
    }

    /// The short-link blob is recorded only on a pending invite, and handed
    /// back once for deletion when the invite is redeemed or revoked.
    #[test]
    fn the_short_blob_is_handed_back_on_redeem_and_revoke() {
        let dir = TempDir::new("short");
        let short = ShortInvite {
            id: "AAAAAAAAAAAA".into(),
            relay: "https://relay.test".into(),
        };
        let redeemed = invite(&dir.0, at(1_000));
        assert!(set_invite_short(&dir.0, &redeemed.record.invite_id, short.clone()).unwrap());
        let AdmitOutcome::Accepted { short: handed, .. } =
            accept(&redeemed, &[3; 32], at(2_000), &dir.0)
        else {
            panic!("accepts");
        };
        assert_eq!(handed, Some(short.clone()));
        assert!(
            !set_invite_short(&dir.0, &redeemed.record.invite_id, short.clone()).unwrap(),
            "a redeemed invite takes no new blob"
        );
        assert!(!set_invite_short(&dir.0, "nope", short.clone()).unwrap());

        let revoked = invite(&dir.0, at(1_000));
        assert!(set_invite_short(&dir.0, &revoked.record.invite_id, short.clone()).unwrap());
        let Some(Revoked::Invite(record)) = revoke_in(
            &dir.0,
            RevokeTarget::Invite(&revoked.record.invite_id),
            at(3_000),
        )
        .unwrap() else {
            panic!("the invite is deleted");
        };
        assert_eq!(record.short, Some(short));
    }

    #[test]
    fn invite_is_single_use_and_binds_name_and_grant() {
        let dir = TempDir::new("single");
        let invite = invite(&dir.0, at(1_000));
        let AdmitOutcome::Accepted { guest, .. } = accept(&invite, &[7; 32], at(2_000), &dir.0)
        else {
            panic!("first use accepts");
        };
        assert_eq!(guest.name, "plotarmordev");
        assert_eq!(guest.grant, grant());
        assert_eq!(guest.device, "iPhone");
        assert_eq!(
            accept(&invite, &[8; 32], at(3_000), &dir.0),
            AdmitOutcome::Refused("invite_used")
        );
        assert_eq!(
            accept(&invite, &[7; 32], at(3_000), &dir.0),
            AdmitOutcome::Refused("invite_used"),
            "even the accepting device cannot reuse it"
        );
    }

    #[test]
    fn one_device_keeps_independent_agent_grants() {
        let dir = TempDir::new("multiple-grants");
        let first_invite = invite(&dir.0, at(1_000));
        let AdmitOutcome::Accepted { guest: first, .. } =
            accept(&first_invite, &[7; 32], at(2_000), &dir.0)
        else {
            panic!("first share accepts")
        };

        let mut second_grant = grant();
        second_grant.terminal_id = "term_2".into();
        second_grant.agent_name = Some("second-agent".into());
        let second_invite = create_invite(
            &dir.0,
            "plotarmordev",
            second_grant.clone(),
            "Jerry",
            "Mac",
            3600,
            true,
            at(3_000),
        )
        .unwrap();
        let AdmitOutcome::Accepted {
            guest: second,
            replaced,
            ..
        } = accept(&second_invite, &[7; 32], at(4_000), &dir.0)
        else {
            panic!("second share accepts")
        };
        assert!(
            replaced.is_empty(),
            "another agent must not revoke the first share"
        );

        for expected in [&first, &second] {
            let hello = json!({"v": 1, "guest_id": expected.guest_id});
            let AdmitOutcome::Returning { guest, .. } =
                admit_in(&dir.0, &[7; 32], &hello, &AccountHello::Absent, at(5_000)).unwrap()
            else {
                panic!("both agent shares must remain usable")
            };
            assert_eq!(guest.guest_id, expected.guest_id);
            assert_eq!(guest.grant, expected.grant);
            assert_eq!(guest.share_gram, expected.share_gram);
            assert_eq!(
                admit_in(&dir.0, &[8; 32], &hello, &AccountHello::Absent, at(5_000)).unwrap(),
                AdmitOutcome::Refused("unknown"),
                "a grant id does not authorize another device"
            );
        }
        assert_eq!(
            admit_in(
                &dir.0,
                &[7; 32],
                &json!({"v": 1}),
                &AccountHello::Absent,
                at(5_000)
            )
            .unwrap(),
            AdmitOutcome::Refused("guest_selection_required")
        );

        revoke_in(&dir.0, RevokeTarget::Guest(&first.guest_id), at(6_000)).unwrap();
        assert_eq!(
            admit_in(
                &dir.0,
                &[7; 32],
                &json!({"v": 1, "guest_id": first.guest_id}),
                &AccountHello::Absent,
                at(7_000)
            )
            .unwrap(),
            AdmitOutcome::Refused("revoked")
        );
        let AdmitOutcome::Returning { guest, .. } = admit_in(
            &dir.0,
            &[7; 32],
            &json!({"v": 1, "guest_id": second.guest_id}),
            &AccountHello::Absent,
            at(7_000),
        )
        .unwrap() else {
            panic!("revoking one share must leave the other usable")
        };
        assert_eq!(guest.grant, second_grant);
        assert!(guest.share_gram);
    }

    #[test]
    fn invite_expires() {
        let dir = TempDir::new("expiry");
        let invite = invite(&dir.0, at(1_000));
        assert_eq!(
            accept(&invite, &[7; 32], invite.record.expires_ms, &dir.0),
            AdmitOutcome::Refused("invite_expired")
        );
        assert!(!link_wanted_in(&dir.0, invite.record.expires_ms));
        assert!(link_wanted_in(&dir.0, invite.record.expires_ms - 1));
    }

    #[test]
    fn wrong_or_malformed_secret_is_invalid_and_reveals_nothing() {
        let dir = TempDir::new("secret");
        let invite = invite(&dir.0, at(1_000));
        // Flip one character of a valid secret.
        let mut forged = invite.secret.clone().into_bytes();
        forged[0] = if forged[0] == b'A' { b'B' } else { b'A' };
        let forged = String::from_utf8(forged).unwrap();
        for secret in [forged.as_str(), "", "not-base64!", &b64url(&[1; 31])] {
            let outcome = admit_in(
                &dir.0,
                &[7; 32],
                &json!({"v": 1, "invite_id": invite.record.invite_id, "secret": secret}),
                &AccountHello::Absent,
                at(2_000),
            )
            .unwrap();
            assert_eq!(
                outcome,
                AdmitOutcome::Refused("invite_invalid"),
                "{secret:?}"
            );
        }
        // A wrong secret for an expired or used invite still answers
        // invite_invalid, so state is never revealed without the secret.
        let expired = admit_in(
            &dir.0,
            &[7; 32],
            &json!({"v": 1, "invite_id": invite.record.invite_id, "secret": forged}),
            &AccountHello::Absent,
            invite.record.expires_ms + 1,
        )
        .unwrap();
        assert_eq!(expired, AdmitOutcome::Refused("invite_invalid"));
        let stored = fs::read_to_string(dir.0.join("guests.json")).unwrap();
        assert!(!stored.contains(&invite.secret), "secret is never stored");
        assert!(stored.contains(&sha256_hex(&b64url_decode(&invite.secret).unwrap())));
    }

    #[test]
    fn returning_devices_unknown_and_revoked() {
        let dir = TempDir::new("returning");
        let hello = json!({"v": 1});
        assert_eq!(
            admit_in(&dir.0, &[9; 32], &hello, &AccountHello::Absent, at(1_000)).unwrap(),
            AdmitOutcome::Refused("unknown")
        );
        let invite = invite(&dir.0, at(1_000));
        let AdmitOutcome::Accepted { guest, .. } = accept(&invite, &[9; 32], at(2_000), &dir.0)
        else {
            panic!("accepts");
        };
        let AdmitOutcome::Returning { guest: back, .. } =
            admit_in(&dir.0, &[9; 32], &hello, &AccountHello::Absent, at(3_000)).unwrap()
        else {
            panic!("returning guest admitted");
        };
        assert_eq!(back.guest_id, guest.guest_id);
        assert!(
            revoke_in(&dir.0, RevokeTarget::Guest(&guest.guest_id), at(3_500))
                .unwrap()
                .is_some()
        );
        assert_eq!(
            admit_in(&dir.0, &[9; 32], &hello, &AccountHello::Absent, at(4_000)).unwrap(),
            AdmitOutcome::Refused("revoked")
        );
        assert!(is_revoked(&dir.0, &guest.guest_id, &guest.fingerprint));
    }

    #[test]
    fn a_polling_guest_is_audited_connected_once_per_window() {
        let dir = TempDir::new("connected");
        let invite = invite(&dir.0, at(0));
        assert!(matches!(
            accept(&invite, &[2; 32], at(0), &dir.0),
            AdmitOutcome::Accepted { .. }
        ));
        let hello = json!({"v": 1});
        // A client polling every 20 s for 25 minutes.
        let connected: Vec<u64> = (1..=75)
            .map(|tick| tick * 20_000)
            .filter(|offset| {
                matches!(
                    admit_in(&dir.0, &[2; 32], &hello, &AccountHello::Absent, at(*offset)).unwrap(),
                    AdmitOutcome::Returning {
                        connected: true,
                        ..
                    }
                )
            })
            .collect();
        let window = CONNECTED_AUDIT_WINDOW_MS;
        assert_eq!(
            connected,
            vec![20_000, 20_000 + window, 20_000 + 2 * window]
        );
    }

    #[test]
    fn the_link_stays_wanted_for_a_day_after_the_latest_revoke() {
        let dir = TempDir::new("grace");
        let invite = invite(&dir.0, at(0));
        let AdmitOutcome::Accepted { guest, .. } = accept(&invite, &[1; 32], at(0), &dir.0) else {
            panic!("accepts");
        };
        let revoked_at = at(10_000);
        revoke_in(&dir.0, RevokeTarget::Guest(&guest.guest_id), revoked_at).unwrap();
        // A repeated revoke does not extend the grace period.
        revoke_in(
            &dir.0,
            RevokeTarget::Guest(&guest.guest_id),
            revoked_at + 5_000,
        )
        .unwrap();
        assert!(link_wanted_in(
            &dir.0,
            revoked_at + REVOKED_LINK_GRACE_MS - 1
        ));
        assert!(!link_wanted_in(&dir.0, revoked_at + REVOKED_LINK_GRACE_MS));
        assert_eq!(
            admit_in(
                &dir.0,
                &[1; 32],
                &json!({"v": 1}),
                &AccountHello::Absent,
                revoked_at + 1
            )
            .unwrap(),
            AdmitOutcome::Refused("revoked")
        );
    }

    #[test]
    fn a_resumed_session_updates_only_an_active_grant() {
        let dir = TempDir::new("resume");
        let invite = invite(&dir.0, at(0));
        let AdmitOutcome::Accepted { guest, .. } = accept(&invite, &[1; 32], at(0), &dir.0) else {
            panic!("accepts");
        };
        let mut session = grant().agent_session;
        assert!(!update_grant_session(&dir.0, &guest.guest_id, &session).unwrap());
        session.value = "s-2".into();
        assert!(update_grant_session(&dir.0, &guest.guest_id, &session).unwrap());
        assert!(!update_grant_session(&dir.0, &guest.guest_id, &session).unwrap());
        let stored = load_store(&dir.0).unwrap();
        assert_eq!(stored.guests[0].grant.agent_session.value, "s-2");
        revoke_in(&dir.0, RevokeTarget::Guest(&guest.guest_id), at(1_000)).unwrap();
        session.value = "s-3".into();
        assert!(!update_grant_session(&dir.0, &guest.guest_id, &session).unwrap());
    }

    #[test]
    fn a_new_invite_replaces_the_same_devices_old_grant() {
        let dir = TempDir::new("replace");
        let first = invite(&dir.0, at(1_000));
        let AdmitOutcome::Accepted { guest: old, .. } = accept(&first, &[5; 32], at(2_000), &dir.0)
        else {
            panic!("accepts");
        };
        let second = invite(&dir.0, at(3_000));
        let AdmitOutcome::Accepted {
            guest: new,
            replaced,
            ..
        } = accept(&second, &[5; 32], at(4_000), &dir.0)
        else {
            panic!("accepts");
        };
        assert!(is_revoked(&dir.0, &old.guest_id, &old.fingerprint));
        assert!(!is_revoked(&dir.0, &new.guest_id, &new.fingerprint));
        assert_eq!(replaced, vec![old.guest_id]);
    }

    #[test]
    fn revoking_an_invite_deletes_it_and_unknown_ids_are_reported() {
        let dir = TempDir::new("revoke-invite");
        let invite = invite(&dir.0, at(1_000));
        assert!(matches!(
            revoke_in(
                &dir.0,
                RevokeTarget::Invite(&invite.record.invite_id),
                at(3_500)
            )
            .unwrap(),
            Some(Revoked::Invite(record)) if record.invite_id == invite.record.invite_id
        ));
        assert_eq!(
            accept(&invite, &[7; 32], at(2_000), &dir.0),
            AdmitOutcome::Refused("invite_invalid")
        );
        assert_eq!(
            revoke_in(&dir.0, RevokeTarget::Guest("nope"), at(3_500)).unwrap(),
            None
        );
        assert_eq!(
            revoke_in(&dir.0, RevokeTarget::Invite("nope"), at(3_500)).unwrap(),
            None
        );
    }

    #[test]
    fn guest_name_rule() {
        for name in ["plotarmordev", "a", "A.b_c-9", &"x".repeat(32)] {
            assert!(valid_guest_name(name), "{name}");
        }
        for name in ["", ".a", "-a", "a b", "a/b", "Jerry:", &"x".repeat(33), "é"] {
            assert!(!valid_guest_name(name), "{name}");
        }
    }

    #[test]
    fn fingerprint_shape() {
        let print = fingerprint(&[0; 32]);
        assert!(print.starts_with("SHA256:"));
        let groups: Vec<&str> = print["SHA256:".len()..].split('·').collect();
        assert_eq!(groups.len(), 4);
        assert!(groups
            .iter()
            .all(|group| group.len() == 4 && group.chars().all(|c| c.is_ascii_hexdigit())));
        assert_eq!(groups.concat(), sha256_hex(&[0; 32])[..16]);
    }

    #[test]
    fn a_rename_moves_the_terminals_grants_and_pending_invites_and_survives_a_reload() {
        let dir = TempDir::new("rename");
        let accepted = invite(&dir.0, at(1_000));
        let AdmitOutcome::Accepted { guest, .. } = accept(&accepted, &[7; 32], at(2_000), &dir.0)
        else {
            panic!("accepts");
        };
        let pending = invite(&dir.0, at(3_000));
        let mut other_terminal = grant();
        other_terminal.terminal_id = "term_2".into();
        let elsewhere = create_invite(
            &dir.0,
            "friend",
            other_terminal,
            "Jerry",
            "Mac",
            3600,
            false,
            at(3_000),
        )
        .unwrap();

        // Another kind or another name in the terminal is not the grant.
        assert!(
            !rename_grants(&dir.0, "term_1", Some("llm-opt"), "x", "claude", at(4_000)).unwrap()
        );
        assert!(!rename_grants(&dir.0, "term_1", Some("other"), "x", "pi", at(4_000)).unwrap());
        assert!(rename_grants(
            &dir.0,
            "term_1",
            Some("llm-opt"),
            "llm-renamed",
            "pi",
            at(5_000)
        )
        .unwrap());

        // A fresh load: what the next admission reads.
        let store = load_store(&dir.0).unwrap();
        let record = store
            .guests
            .iter()
            .find(|record| record.guest_id == guest.guest_id)
            .unwrap();
        assert_eq!(record.grant.terminal_id, "term_1");
        assert_eq!(record.grant.agent_name.as_deref(), Some("llm-renamed"));
        assert_eq!(record.grant.agent_session, guest.grant.agent_session);
        assert_eq!(
            record.former_names,
            [FormerName {
                name: "llm-opt".into(),
                until_ms: at(5_000),
            }]
        );
        let name_of = |id: &str| {
            store
                .invites
                .iter()
                .find(|invite| invite.invite_id == id)
                .and_then(|invite| invite.grant.agent_name.clone())
        };
        assert_eq!(
            name_of(&pending.record.invite_id).as_deref(),
            Some("llm-renamed")
        );
        assert_eq!(
            name_of(&accepted.record.invite_id).as_deref(),
            Some("llm-opt"),
            "a used invite is history"
        );
        assert_eq!(
            name_of(&elsewhere.record.invite_id).as_deref(),
            Some("llm-opt"),
            "another terminal's agent keeps its own name"
        );
        assert_eq!(
            active_grant(&dir.0, &guest.guest_id)
                .unwrap()
                .agent_name
                .as_deref(),
            Some("llm-renamed")
        );

        // The pending invite binds the same terminal under the new name.
        let AdmitOutcome::Accepted { guest: late, .. } =
            accept(&pending, &[8; 32], at(6_000), &dir.0)
        else {
            panic!("accepts");
        };
        assert_eq!(late.grant.terminal_id, "term_1");
        assert_eq!(late.grant.agent_name.as_deref(), Some("llm-renamed"));
        assert!(late.former_names.is_empty());

        // Renaming back keeps both former names, oldest first.
        assert!(rename_grants(
            &dir.0,
            "term_1",
            Some("llm-renamed"),
            "llm-opt",
            "pi",
            at(7_000)
        )
        .unwrap());
        let names = || -> Vec<String> {
            load_store(&dir.0)
                .unwrap()
                .guests
                .iter()
                .find(|record| record.guest_id == guest.guest_id)
                .unwrap()
                .former_names
                .iter()
                .map(|former| former.name.clone())
                .collect()
        };
        assert_eq!(names(), ["llm-opt", "llm-renamed"]);

        // Named again after its name was cleared, the agent in the
        // terminal keeps its grants: they follow from their last name. Only
        // that terminal's agent of that kind.
        assert!(!rename_grants(&dir.0, "term_1", None, "x", "claude", at(8_000)).unwrap());
        assert!(!rename_grants(&dir.0, "term_9", None, "x", "pi", at(8_000)).unwrap());
        assert!(!rename_grants(&dir.0, "term_1", None, "llm-opt", "pi", at(8_000)).unwrap());
        assert!(rename_grants(&dir.0, "term_1", None, "llm-named", "pi", at(9_000)).unwrap());
        assert_eq!(
            active_grant(&dir.0, &guest.guest_id)
                .unwrap()
                .agent_name
                .as_deref(),
            Some("llm-named")
        );
        assert_eq!(names(), ["llm-opt", "llm-renamed", "llm-opt"]);
        let store = load_store(&dir.0).unwrap();
        assert_eq!(
            store
                .invites
                .iter()
                .find(|invite| invite.invite_id == elsewhere.record.invite_id)
                .and_then(|invite| invite.grant.agent_name.as_deref()),
            Some("llm-opt"),
            "another terminal's grant stays where it was"
        );
    }

    #[test]
    fn a_store_from_before_renames_loads_without_former_names() {
        let dir = TempDir::new("former-default");
        let accepted = invite(&dir.0, at(1_000));
        accept(&accepted, &[7; 32], at(2_000), &dir.0);
        let text = fs::read_to_string(dir.0.join("guests.json")).unwrap();
        assert!(!text.contains("former_names"), "{text}");
        let store = load_store(&dir.0).unwrap();
        assert!(store.guests[0].former_names.is_empty());
    }
}
