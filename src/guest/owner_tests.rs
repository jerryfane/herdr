//! Owner grants (`owner_access.*`) against a real store directory and a
//! throwaway account service: expiry bounds, add/renew/remove, the grant
//! limit, retention, the relay link, statement checks and persistence.

use serde_json::json;

use super::account::tests::{settings, Issuer, KeyServer};
use super::account::{codes, Env, Settings};
use super::owner::{self, RemoveTarget};
use super::store;
use super::NOTIFIED;
use crate::api::schema::{GuestAuditEvent, OwnerAccessAddParams, OwnerScope};

const SUB: &str = "sub-Example-012345678";
/// The approving device (a phone): its statement says `dev` = this key.
const PHONE: [u8; 32] = [0x41; 32];
/// The browser being allowed.
const BROWSER: [u8; 32] = [0x42; 32];
const HOUR_MS: u64 = 60 * 60 * 1000;
const DAY_MS: u64 = 24 * HOUR_MS;

struct Host {
    dir: store::tests::TempDir,
    host_id: String,
    issuer: Issuer,
    keys: KeyServer,
    accounts: std::sync::atomic::AtomicBool,
}

impl Host {
    fn new(tag: &str) -> Self {
        let dir = store::tests::TempDir::new(tag);
        let (host, _) = store::load_host(&dir.0).unwrap();
        let issuer = Issuer::new("k1");
        let keys = KeyServer::serving(issuer.jwks());
        Self {
            dir,
            host_id: host.host_id,
            issuer,
            keys,
            accounts: std::sync::atomic::AtomicBool::new(true),
        }
    }

    /// The phone's own statement for this host, issued now.
    fn statement(&self) -> String {
        self.issuer.statement(&self.host_id, &PHONE, SUB)
    }

    fn params(&self, device: &[u8; 32], ttl_secs: u64) -> OwnerAccessAddParams {
        OwnerAccessAddParams {
            device_pub: store::b64url(device),
            device_name: "Chrome on macOS".into(),
            scope: OwnerScope::Terminal,
            ttl_secs,
            account_statement: self.statement(),
            approved_by: "Jerry's iPhone".into(),
        }
    }

    fn add_with(
        &self,
        params: &OwnerAccessAddParams,
        now: u64,
    ) -> Result<(crate::api::schema::OwnerGrantInfo, Vec<String>), super::OwnerError> {
        let settings = || Settings {
            enabled: self.accounts.load(std::sync::atomic::Ordering::Relaxed),
            ..settings()
        };
        let fetch = |issuer: &str| self.keys.fetch(issuer);
        let notify = |_: crate::push::PushNotification| {};
        let env = Env {
            settings: &settings,
            fetch_keys: &fetch,
            notify_owner: &notify,
        };
        owner::add_in(&self.dir.0, &env, params, now)
    }

    fn add(&self, device: &[u8; 32], ttl_secs: u64) -> crate::api::schema::OwnerGrantInfo {
        self.add_with(&self.params(device, ttl_secs), store::now_ms())
            .unwrap()
            .0
    }

    fn grants(&self) -> Vec<owner::OwnerGrant> {
        store::load_store(&self.dir.0).unwrap().owners
    }

    fn link_wanted(&self, now: u64) -> bool {
        store::link_wanted_in(&self.dir.0, now)
    }
}

fn code<T: std::fmt::Debug>(result: Result<T, super::OwnerError>) -> &'static str {
    result.unwrap_err().0
}

#[test]
fn ttl_outside_one_hour_to_thirty_days_is_refused_never_clamped() {
    let host = Host::new("owner-ttl");
    let now = store::now_ms();
    for ttl in [0, 3599, 2_592_001, u64::MAX] {
        assert_eq!(
            code(host.add_with(&host.params(&BROWSER, ttl), now)),
            "owner_ttl_invalid",
            "{ttl}"
        );
    }
    assert!(host.grants().is_empty(), "nothing stored");
    let shortest = host.add(&BROWSER, 3600);
    assert_eq!(shortest.expires_ms - shortest.created_ms, HOUR_MS);
    let longest = host.add(&[0x43; 32], 2_592_000);
    assert_eq!(longest.expires_ms - longest.created_ms, 30 * DAY_MS);

    for ttl in [0, 3599, 2_592_001] {
        assert_eq!(
            code(owner::renew_in(
                &host.dir.0,
                &longest.grant_id,
                ttl,
                None,
                now
            )),
            "owner_ttl_invalid",
            "{ttl}"
        );
    }
    let stored = host.grants();
    assert_eq!(stored[1].expires_ms, longest.expires_ms, "renew refused");
}

#[test]
fn add_renew_and_remove_round_trip_through_the_store_and_audit() {
    let host = Host::new("owner-round-trip");
    let start = NOTIFIED.with(std::cell::Cell::get);
    let grant = host.add(&BROWSER, 7 * 24 * 3600);
    assert_eq!(grant.device_pub, store::b64url(&BROWSER));
    assert_eq!(grant.fingerprint, store::fingerprint(&BROWSER));
    assert_eq!(grant.device, "Chrome on macOS");
    assert_eq!(grant.approved_by, "Jerry's iPhone");
    assert_eq!(grant.scope, OwnerScope::Terminal);
    assert_eq!(grant.expires_ms, grant.created_ms + 7 * DAY_MS);
    assert_eq!(store::b64url_decode(&grant.grant_id).unwrap().len(), 16);
    let stored = &host.grants()[0];
    assert_eq!(stored.account, SUB, "bound to the approver's account");
    assert_eq!(stored.info(), grant);
    assert_eq!(
        owner::list_in(&host.dir.0, store::now_ms()).unwrap(),
        vec![grant.clone()]
    );

    let later = grant.created_ms + DAY_MS;
    let renewed = owner::renew_in(
        &host.dir.0,
        &grant.grant_id,
        3600,
        Some(OwnerScope::Chat),
        later,
    )
    .unwrap();
    assert_eq!(renewed.expires_ms, later + HOUR_MS, "now + ttl, not added");
    assert_eq!(renewed.renewed_ms, Some(later));
    assert_eq!(renewed.scope, OwnerScope::Chat);
    let kept = owner::renew_in(&host.dir.0, &grant.grant_id, 7200, None, later).unwrap();
    assert_eq!(kept.scope, OwnerScope::Chat, "no scope keeps it");
    assert_eq!(
        code(owner::renew_in(&host.dir.0, "nope", 3600, None, later)),
        "owner_grant_not_found"
    );

    assert_eq!(
        owner::remove_in(&host.dir.0, RemoveTarget::Grant(&grant.grant_id), later).unwrap(),
        vec![grant.grant_id.clone()]
    );
    assert!(host.grants()[0].revoked);
    assert_eq!(host.grants()[0].revoked_ms, Some(later));
    // Idempotent: removing again, or an unknown grant, removes nothing.
    assert!(
        owner::remove_in(&host.dir.0, RemoveTarget::Grant(&grant.grant_id), later)
            .unwrap()
            .is_empty()
    );
    assert!(
        owner::remove_in(&host.dir.0, RemoveTarget::Grant("nope"), later)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        code(owner::renew_in(
            &host.dir.0,
            &grant.grant_id,
            3600,
            None,
            later
        )),
        "owner_grant_revoked"
    );

    // By key and by fingerprint.
    let by_key = host.add(&[0x44; 32], 3600);
    let by_fingerprint = host.add(&[0x45; 32], 3600);
    assert_eq!(
        owner::remove_in(&host.dir.0, RemoveTarget::Device(&by_key.device_pub), later).unwrap(),
        vec![by_key.grant_id.clone()]
    );
    assert_eq!(
        owner::remove_in(
            &host.dir.0,
            RemoveTarget::Fingerprint(&by_fingerprint.fingerprint),
            later
        )
        .unwrap(),
        vec![by_fingerprint.grant_id.clone()]
    );

    let events: Vec<_> = super::audit::read(&host.dir.0, Some(&grant.grant_id), None, 10)
        .unwrap()
        .into_iter()
        .map(|entry| (entry.event, entry.name, entry.fingerprint))
        .collect();
    let named = |event| (event, grant.device.clone(), grant.fingerprint.clone());
    assert_eq!(
        events,
        vec![
            named(GuestAuditEvent::OwnerRemoved),
            named(GuestAuditEvent::OwnerRenewed),
            named(GuestAuditEvent::OwnerRenewed),
            named(GuestAuditEvent::OwnerAdded),
        ]
    );
    // add, two renews, three removes; the refusals and no-ops notify nothing.
    assert_eq!(NOTIFIED.with(std::cell::Cell::get) - start, 8);
}

#[test]
fn a_second_add_for_the_same_key_replaces_the_first() {
    let host = Host::new("owner-replace");
    let first = host.add(&BROWSER, 3600);
    let (second, replaced) = host
        .add_with(&host.params(&BROWSER, 7200), store::now_ms())
        .unwrap();
    assert_eq!(replaced, vec![first.grant_id.clone()]);
    let grants = host.grants();
    assert_eq!(grants.len(), 2);
    assert!(grants[0].revoked, "the first grant is revoked");
    assert!(!grants[1].revoked);
    assert_eq!(grants[1].grant_id, second.grant_id);
    let removed = super::audit::read(&host.dir.0, Some(&first.grant_id), None, 10).unwrap();
    assert_eq!(removed[0].event, GuestAuditEvent::OwnerRemoved);
    assert_eq!(removed[0].text.as_deref(), Some("replaced"));
}

#[test]
fn the_eleventh_live_grant_is_refused() {
    let host = Host::new("owner-limit");
    let grants: Vec<_> = (0..owner::MAX_LIVE_GRANTS as u8)
        .map(|index| host.add(&[0x50 + index; 32], 3600))
        .collect();
    let eleventh = host.params(&[0x60; 32], 3600);
    assert_eq!(
        code(host.add_with(&eleventh, store::now_ms())),
        "owner_grant_limit"
    );
    assert_eq!(host.grants().len(), owner::MAX_LIVE_GRANTS);
    // Replacing one of the ten is not an eleventh.
    host.add(&[0x50; 32], 7200);
    owner::remove_in(
        &host.dir.0,
        RemoveTarget::Grant(&grants[1].grant_id),
        store::now_ms(),
    )
    .unwrap();
    host.add_with(&eleventh, store::now_ms()).unwrap();
    // Expired grants do not count either.
    let past_expiry = store::now_ms() + 2 * HOUR_MS + 1;
    let mut late = host.params(&[0x61; 32], 3600);
    late.account_statement = host.issuer.sign(&host.issuer.claims(
        &host.host_id,
        &PHONE,
        SUB,
        past_expiry / 1000,
    ));
    host.add_with(&late, past_expiry).unwrap();
}

/// The approving device's statement issued at `now_ms`, for adds at a
/// later test clock.
fn add_at(
    host: &Host,
    device: &[u8; 32],
    ttl_secs: u64,
    now_ms: u64,
) -> Result<crate::api::schema::OwnerGrantInfo, super::OwnerError> {
    let mut params = host.params(device, ttl_secs);
    params.account_statement = host.issuer.sign(&host.issuer.claims(
        &host.host_id,
        &PHONE,
        SUB,
        now_ms / 1000,
    ));
    host.add_with(&params, now_ms).map(|(grant, _)| grant)
}

#[test]
fn renew_cannot_revive_an_expired_grant_past_the_live_limit() {
    let host = Host::new("owner-revive-limit");
    let now = store::now_ms();
    let short = host.add(&[0x50; 32], 3600);
    let long: Vec<_> = (1..owner::MAX_LIVE_GRANTS as u8)
        .map(|index| host.add(&[0x50 + index; 32], 2 * 24 * 3600))
        .collect();
    let later = now + 2 * HOUR_MS;
    // `short` expired, so a new key fits under the cap again.
    add_at(&host, &[0x60; 32], 3600, later).unwrap();
    assert_eq!(
        code(owner::renew_in(
            &host.dir.0,
            &short.grant_id,
            3600,
            None,
            later
        )),
        "owner_grant_limit",
        "reviving it would make 11 live grants"
    );
    assert!(
        !host.grants()[0].live(later),
        "the refused grant stays expired"
    );
    // Renewing a grant that is still live adds none, so it works at the cap.
    owner::renew_in(&host.dir.0, &long[0].grant_id, 3600, None, later).unwrap();
    // With one removed, the expired grant may come back.
    owner::remove_in(&host.dir.0, RemoveTarget::Grant(&long[1].grant_id), later).unwrap();
    owner::renew_in(&host.dir.0, &short.grant_id, 3600, None, later).unwrap();
    let live = host
        .grants()
        .iter()
        .filter(|grant| grant.live(later))
        .count();
    assert_eq!(live, owner::MAX_LIVE_GRANTS);
}

#[test]
fn stored_grants_are_capped_dropping_the_ones_that_ended_first() {
    let host = Host::new("owner-stored-cap");
    let now = store::now_ms();
    let total = owner::MAX_STORED_GRANTS + 10;
    // Every add for the same key revokes the one before it.
    let ids: Vec<String> = (0..total as u64)
        .map(|step| add_at(&host, &BROWSER, 3600, now + step).unwrap().grant_id)
        .collect();
    let stored: Vec<String> = host
        .grants()
        .into_iter()
        .map(|grant| grant.grant_id)
        .collect();
    assert_eq!(stored.len(), owner::MAX_STORED_GRANTS);
    assert_eq!(
        stored,
        ids[total - owner::MAX_STORED_GRANTS..],
        "oldest dropped first"
    );
    let last = host.grants().pop().unwrap();
    assert!(last.live(now + total as u64), "the live grant is kept");

    // Removals leave ended grants too; the cap still holds and live grants
    // are never dropped for it.
    let mut live = Vec::new();
    // Nine live in all with the BROWSER grant, so each add below fits.
    for index in 0..owner::MAX_LIVE_GRANTS as u8 - 2 {
        live.push(host.add(&[0x70 + index; 32], 3600).grant_id);
    }
    for index in 0..20u8 {
        let key = [0x90 + index; 32];
        host.add(&key, 3600);
        owner::remove_in(&host.dir.0, RemoveTarget::Device(&store::b64url(&key)), now).unwrap();
    }
    let grants = host.grants();
    assert!(grants.len() <= owner::MAX_STORED_GRANTS, "{}", grants.len());
    for id in live.iter().chain([&last.grant_id]) {
        assert!(grants.iter().any(|grant| &grant.grant_id == id), "{id}");
    }
}

#[test]
fn renew_revives_an_expired_grant_within_its_retention_only() {
    let host = Host::new("owner-revive");
    let grant = host.add(&BROWSER, 3600);
    let expired = grant.expires_ms + DAY_MS;
    let revived = owner::renew_in(&host.dir.0, &grant.grant_id, 3600, None, expired).unwrap();
    assert_eq!(revived.expires_ms, expired + HOUR_MS);
    assert!(host.link_wanted(expired + 1));

    let gone = revived.expires_ms + owner::ENDED_RETENTION_MS;
    assert_eq!(
        code(owner::renew_in(
            &host.dir.0,
            &grant.grant_id,
            3600,
            None,
            gone
        )),
        "owner_grant_not_found",
        "deleted 30 days after it expired"
    );
    assert!(host.grants().is_empty());
}

#[test]
fn ended_grants_are_deleted_thirty_days_after_they_end() {
    let host = Host::new("owner-prune");
    let expiring = host.add(&BROWSER, 3600);
    let removed = host.add(&[0x43; 32], 2_592_000);
    let removed_at = removed.created_ms + 2 * HOUR_MS;
    owner::remove_in(
        &host.dir.0,
        RemoveTarget::Grant(&removed.grant_id),
        removed_at,
    )
    .unwrap();

    let ids = |now| -> Vec<String> {
        owner::list_in(&host.dir.0, now)
            .unwrap()
            .into_iter()
            .map(|grant| grant.grant_id)
            .collect()
    };
    let expired_keep = expiring.expires_ms + owner::ENDED_RETENTION_MS - 1;
    assert_eq!(
        ids(expired_keep),
        vec![expiring.grant_id.clone(), removed.grant_id.clone()]
    );
    assert_eq!(
        ids(expiring.expires_ms + owner::ENDED_RETENTION_MS),
        vec![removed.grant_id.clone()],
        "the expired grant is deleted, the revoked one is a little younger"
    );
    assert!(ids(removed_at + owner::ENDED_RETENTION_MS).is_empty());
    assert!(host.grants().is_empty(), "deleted from guests.json too");
}

#[test]
fn the_relay_link_follows_owner_grants() {
    let host = Host::new("owner-link");
    let now = store::now_ms();
    assert!(!host.link_wanted(now), "nothing to share");
    let grant = host.add(&BROWSER, 3600);
    assert!(host.link_wanted(now), "a live grant brings the link up");
    assert!(host.link_wanted(grant.expires_ms), "grace after expiry");
    let after_grace = grant.expires_ms + store::REVOKED_LINK_GRACE_MS;
    assert!(!host.link_wanted(after_grace), "expired plus the grace");

    owner::renew_in(&host.dir.0, &grant.grant_id, 3600, None, after_grace).unwrap();
    assert!(
        host.link_wanted(after_grace),
        "a revived grant brings it back"
    );
    owner::remove_in(
        &host.dir.0,
        RemoveTarget::Grant(&grant.grant_id),
        after_grace,
    )
    .unwrap();
    assert!(host.link_wanted(after_grace + 1), "grace after removal");
    assert!(
        !host.link_wanted(after_grace + store::REVOKED_LINK_GRACE_MS),
        "removed plus the grace"
    );
}

#[test]
fn add_checks_the_approving_devices_own_statement() {
    let host = Host::new("owner-statement");
    let now = store::now_ms();
    // The phone's statement is for the phone's key, not the browser's: the
    // grant is bound to its account all the same.
    let (grant, _) = host.add_with(&host.params(&BROWSER, 3600), now).unwrap();
    assert_eq!(host.grants()[0].account, SUB);

    let mut refused = Vec::new();
    let with = |statement: String| OwnerAccessAddParams {
        account_statement: statement,
        ..host.params(&[0x43; 32], 3600)
    };
    let issued = |host_id: &str, iat_ms: u64| {
        host.issuer
            .sign(&host.issuer.claims(host_id, &PHONE, SUB, iat_ms / 1000))
    };
    for (statement, expected) in [
        (String::new(), codes::INVALID),
        ("a.b.c".to_string(), codes::INVALID),
        (issued("AnotherHost-0123456789", now), codes::INVALID),
        (issued(&host.host_id, now - HOUR_MS), codes::EXPIRED),
        (issued(&host.host_id, now + HOUR_MS), codes::EXPIRED),
        (
            Issuer::new("k1").statement(&host.host_id, &PHONE, SUB),
            codes::INVALID,
        ),
        (
            Issuer::new("k-other").statement(&host.host_id, &PHONE, SUB),
            codes::INVALID,
        ),
        (
            host.issuer.sign(&json!({"v": 1, "iss": "https://elsewhere.test", "aud": host.host_id, "sub": SUB, "dev": store::b64url(&PHONE), "iat": now / 1000, "exp": now / 1000 + 600})),
            codes::INVALID,
        ),
    ] {
        let result = host.add_with(&with(statement.clone()), now);
        refused.push((code(result), expected, statement));
    }
    for (got, expected, statement) in &refused {
        assert_eq!(got, expected, "{statement}");
    }
    assert_eq!(host.grants().len(), 1, "no refused add stored a grant");
    assert_eq!(host.grants()[0].grant_id, grant.grant_id);

    // `[guest] accounts = false` governs guest shares only: owner grants
    // still need, and still check, a statement.
    host.accounts
        .store(false, std::sync::atomic::Ordering::Relaxed);
    host.add_with(&host.params(&[0x44; 32], 3600), now).unwrap();
    assert_eq!(
        code(host.add_with(&with(issued("AnotherHost-0123456789", now)), now)),
        codes::INVALID
    );
}

#[test]
fn keys_and_labels_are_checked() {
    let host = Host::new("owner-keys");
    let now = store::now_ms();
    let key = store::b64url(&BROWSER);
    for device_pub in [
        format!("{key}="),
        store::b64url(&[0x42; 31]),
        store::b64url(&[0x42; 33]),
        base64::Engine::encode(&base64::engine::general_purpose::STANDARD, [0xfb; 32]),
        String::new(),
    ] {
        let params = OwnerAccessAddParams {
            device_pub: device_pub.clone(),
            ..host.params(&BROWSER, 3600)
        };
        assert_eq!(
            code(host.add_with(&params, now)),
            "invalid_params",
            "{device_pub}"
        );
        assert_eq!(
            code(owner::remove_in(
                &host.dir.0,
                RemoveTarget::Device(&device_pub),
                now
            )),
            "invalid_params",
            "{device_pub}"
        );
    }
    for name in [
        String::new(),
        "  ".into(),
        "x".repeat(65),
        "Chrome\nmacOS".into(),
    ] {
        let device = OwnerAccessAddParams {
            device_name: name.clone(),
            ..host.params(&BROWSER, 3600)
        };
        assert_eq!(
            code(host.add_with(&device, now)),
            "invalid_params",
            "{name:?}"
        );
        let approver = OwnerAccessAddParams {
            approved_by: name.clone(),
            ..host.params(&BROWSER, 3600)
        };
        assert_eq!(
            code(host.add_with(&approver, now)),
            "invalid_params",
            "{name:?}"
        );
    }
    assert!(host.grants().is_empty());
    let longest = OwnerAccessAddParams {
        device_name: "é".repeat(64),
        ..host.params(&BROWSER, 3600)
    };
    host.add_with(&longest, now).unwrap();
}

#[test]
fn owner_grants_persist_beside_guests_and_older_stores_still_load() {
    let host = Host::new("owner-persist");
    // A store from before owner grants.
    store::write_private(
        &host.dir.0.join("guests.json"),
        br#"{"guests": [], "invites": []}"#,
    )
    .unwrap();
    assert!(host.grants().is_empty());
    // Writing a store without grants leaves the field out.
    store::update_store(&host.dir.0, |_| ((), true)).unwrap();
    let raw = std::fs::read_to_string(host.dir.0.join("guests.json")).unwrap();
    assert!(!raw.contains("owners"), "{raw}");

    let grant = host.add(&BROWSER, 3600);
    let raw: serde_json::Value =
        serde_json::from_slice(&std::fs::read(host.dir.0.join("guests.json")).unwrap()).unwrap();
    assert_eq!(raw["owners"][0]["grant_id"], grant.grant_id);
    assert_eq!(raw["owners"][0]["account"], SUB);
    assert_eq!(raw["owners"][0]["scope"], "terminal");

    // A grant written without the optional fields loads with defaults.
    let minimal = json!({"owners": [{
        "grant_id": grant.grant_id,
        "device_pub": grant.device_pub,
        "fingerprint": grant.fingerprint,
        "device": "Chrome on macOS",
        "account": SUB,
        "scope": "chat",
        "approved_by": "Jerry's iPhone",
        "created_ms": grant.created_ms,
        "expires_ms": grant.expires_ms,
    }]});
    store::write_private(
        &host.dir.0.join("guests.json"),
        minimal.to_string().as_bytes(),
    )
    .unwrap();
    let loaded = &host.grants()[0];
    assert_eq!(loaded.scope, OwnerScope::Chat);
    assert!(!loaded.revoked);
    assert_eq!(
        (loaded.renewed_ms, loaded.last_seen_ms, loaded.revoked_ms),
        (None, None, None)
    );
    let reloaded = owner::list_in(&host.dir.0, store::now_ms()).unwrap();
    assert_eq!(reloaded[0].grant_id, grant.grant_id);
}

#[test]
fn info_reports_this_hosts_relay_identity() {
    let host = Host::new("owner-info");
    let info = owner::info_in(&host.dir.0, "https://relay.test".into()).unwrap();
    let (identity, node_secret) = store::load_host(&host.dir.0).unwrap();
    assert_eq!(info.host_id, identity.host_id);
    assert_eq!(info.host_id, host.host_id);
    assert_eq!(
        info.node_pub,
        store::b64url(&store::x25519_public(&node_secret))
    );
    assert_eq!(info.relay_url, "https://relay.test");

    // The identity is created when missing.
    let fresh = store::tests::TempDir::new("owner-info-fresh");
    let created = owner::info_in(&fresh.0, String::new()).unwrap();
    assert_eq!(store::b64url_decode(&created.host_id).unwrap().len(), 16);
    assert_eq!(store::b64url_decode(&created.node_pub).unwrap().len(), 32);
    assert_eq!(
        store::load_host(&fresh.0).unwrap().0.host_id,
        created.host_id
    );
}

/// Owner hellos through admission, with this host's throwaway account
/// service.
mod admission {
    use serde_json::Value;

    use super::*;
    use crate::guest::link::host::Admission as LinkAdmission;
    use crate::guest::owner::{refusals, OwnerAdmission};
    use crate::guest::Principal;

    impl Host {
        fn env_run<R>(&self, run: impl FnOnce(&Env<'_>) -> R) -> R {
            let settings = || Settings {
                enabled: self.accounts.load(std::sync::atomic::Ordering::Relaxed),
                ..settings()
            };
            let fetch = |issuer: &str| self.keys.fetch(issuer);
            let notify = |_: crate::push::PushNotification| {};
            run(&Env {
                settings: &settings,
                fetch_keys: &fetch,
                notify_owner: &notify,
            })
        }

        /// The browser's own statement, issued at `now_ms`.
        fn browser_statement(&self, device: &[u8; 32], sub: &str, now_ms: u64) -> String {
            self.issuer.sign(
                &self
                    .issuer
                    .claims(&self.host_id, device, sub, now_ms / 1000),
            )
        }

        fn owner_hello(&self, statement: Option<String>) -> Value {
            let mut hello = json!({"v": 1, "mode": "owner", "device": "Chrome on macOS"});
            if let Some(statement) = statement {
                hello["account"] = json!(statement);
            }
            hello
        }

        fn admit_at(
            &self,
            device: &[u8; 32],
            hello: &Value,
            now: u64,
        ) -> Result<OwnerAdmission, &'static str> {
            self.env_run(|env| owner::admit_in(&self.dir.0, env, *device, hello, now))
        }

        /// The browser's statement for `SUB`, now.
        fn admit(&self, device: &[u8; 32]) -> Result<OwnerAdmission, &'static str> {
            let now = store::now_ms();
            let hello = self.owner_hello(Some(self.browser_statement(device, SUB, now)));
            self.admit_at(device, &hello, now)
        }

        fn admit_any(&self, device: &[u8; 32], hello: &Value) -> LinkAdmission<Principal> {
            self.env_run(|env| {
                crate::guest::admit_principal_in(self.dir.0.clone(), env, *device, hello)
            })
        }
    }

    fn refused<T>(result: Result<T, &'static str>) -> &'static str {
        match result {
            Ok(_) => "<admitted>",
            Err(code) => code,
        }
    }

    #[test]
    fn a_live_grant_and_the_browsers_own_statement_admit_it() {
        let host = Host::new("owner-admit");
        assert_eq!(refused(host.admit(&BROWSER)), refusals::NOT_GRANTED);
        let grant = host.add(&BROWSER, 3600);
        let now = store::now_ms();
        let admitted = host.admit(&BROWSER).unwrap();
        let reply = &admitted.reply;
        assert_eq!(reply["ok"], true);
        assert_eq!(reply["mode"], "owner");
        assert_eq!(reply["grant_id"], grant.grant_id);
        assert_eq!(reply["scope"], "terminal");
        assert_eq!(reply["expires_unix"], grant.expires_ms / 1000);
        assert_eq!(reply["features"]["owner"], 2);
        assert_eq!(reply["features"]["multi_request"], true);
        // The statement's ten minutes plus the skew.
        let deadline = reply["account"]["deadline_unix"].as_u64().unwrap();
        assert!(
            (now / 1000 + 600..=now / 1000 + 661).contains(&deadline),
            "{reply}"
        );
        assert_eq!(admitted.account.deadline_ms / 1000, deadline);
        assert_eq!(
            admitted.account.holder,
            crate::guest::AccountHolder::Owner(grant.grant_id.clone())
        );
        assert_eq!(admitted.principal.current(now), Ok(OwnerScope::Terminal));
        let seen = host.grants()[0].clone();
        assert!(seen.last_seen_ms.is_some() && seen.last_connected_ms.is_some());
        let connected = |host: &Host| {
            super::super::audit::read(&host.dir.0, Some(&grant.grant_id), None, 50)
                .unwrap()
                .iter()
                .filter(|entry| entry.event == GuestAuditEvent::OwnerConnected)
                .count()
        };
        drop(admitted);
        host.admit(&BROWSER).unwrap();
        assert_eq!(connected(&host), 1, "one entry per 10 minutes");

        // `[guest] accounts` governs guest shares only.
        host.accounts
            .store(false, std::sync::atomic::Ordering::Relaxed);
        host.admit(&BROWSER).unwrap();
    }

    #[test]
    fn expired_removed_and_replaced_grants_are_refused() {
        let host = Host::new("owner-admit-ended");
        let grant = host.add(&BROWSER, 3600);
        let later = grant.expires_ms + 1;
        let hello = host.owner_hello(Some(host.browser_statement(&BROWSER, SUB, later)));
        assert_eq!(
            refused(host.admit_at(&BROWSER, &hello, later)),
            refusals::EXPIRED
        );
        let (replacement, _) = host
            .add_with(&host.params(&BROWSER, 3600), store::now_ms())
            .unwrap();
        host.admit(&BROWSER).unwrap();
        owner::remove_in(
            &host.dir.0,
            RemoveTarget::Grant(&replacement.grant_id),
            store::now_ms(),
        )
        .unwrap();
        assert_eq!(refused(host.admit(&BROWSER)), refusals::NOT_GRANTED);
    }

    #[test]
    fn the_statement_must_be_the_browsers_own_and_name_the_grants_account() {
        let host = Host::new("owner-admit-statement");
        host.add(&BROWSER, 3600);
        let now = store::now_ms();
        let other_sub = "sub-Another-012345678";
        for (statement, expected) in [
            (None, codes::REQUIRED),
            (
                Some(host.browser_statement(&BROWSER, other_sub, now)),
                codes::MISMATCH,
            ),
            // The approving phone's statement is not the browser's.
            (
                Some(host.browser_statement(&PHONE, SUB, now)),
                codes::INVALID,
            ),
            (
                Some(host.browser_statement(&BROWSER, SUB, now - 2 * HOUR_MS)),
                codes::EXPIRED,
            ),
            (
                Some(Issuer::new("k1").statement(&host.host_id, &BROWSER, SUB)),
                codes::INVALID,
            ),
        ] {
            let hello = host.owner_hello(statement.clone());
            assert_eq!(
                refused(host.admit_at(&BROWSER, &hello, now)),
                expected,
                "{statement:?}"
            );
        }
        let mut hello = host.owner_hello(None);
        hello["account"] = json!(7);
        assert_eq!(
            refused(host.admit_at(&BROWSER, &hello, now)),
            codes::INVALID
        );
    }

    #[test]
    fn cached_keys_within_their_grace_still_admit_a_granted_browser() {
        let host = Host::new("owner-admit-stale-keys");
        let t0 = store::now_ms();
        host.add(&BROWSER, 30 * 24 * 3600);
        // The account service is unreachable from here on.
        *host.keys.jwks.lock().unwrap() = None;
        let later = t0 + 3 * DAY_MS;
        let hello = host.owner_hello(Some(host.browser_statement(&BROWSER, SUB, later)));
        host.admit_at(&BROWSER, &hello, later).unwrap();
        let past_grace = t0 + 8 * DAY_MS;
        let hello = host.owner_hello(Some(host.browser_statement(&BROWSER, SUB, past_grace)));
        assert_eq!(
            refused(host.admit_at(&BROWSER, &hello, past_grace)),
            codes::KEYS_STALE
        );
    }

    #[test]
    fn a_refresh_extends_the_session_while_the_grant_and_account_hold() {
        let host = Host::new("owner-refresh");
        let grant = host.add(&BROWSER, 3600);
        let admitted = host.admit(&BROWSER).unwrap();
        let refresh = |jws: &str, now: u64| {
            host.env_run(|env| {
                owner::refresh_in(&host.dir.0, env, &grant.grant_id, &BROWSER, jws, now)
            })
        };
        let later = store::now_ms() + 9 * 60 * 1000;
        let extended = refresh(&host.browser_statement(&BROWSER, SUB, later), later).unwrap();
        assert!(extended > admitted.account.deadline_ms);
        // Never past the grant's expiry.
        let near_end = grant.expires_ms - 60 * 1000;
        let capped = refresh(&host.browser_statement(&BROWSER, SUB, near_end), near_end).unwrap();
        assert_eq!(capped, grant.expires_ms);
        assert_eq!(
            refresh(
                &host.browser_statement(&BROWSER, "sub-Another-012345678", later),
                later
            ),
            Err(codes::MISMATCH)
        );
        owner::remove_in(&host.dir.0, RemoveTarget::Grant(&grant.grant_id), later).unwrap();
        assert_eq!(
            refresh(&host.browser_statement(&BROWSER, SUB, later), later),
            Err(refusals::NOT_GRANTED)
        );
        assert!(admitted.principal.live().revoked(), "the removal closed it");
    }

    #[test]
    fn the_ninth_live_connection_of_one_grant_is_busy() {
        let host = Host::new("owner-busy");
        host.add(&BROWSER, 3600);
        let live: Vec<_> = (0..owner::SESSION_CAP)
            .map(|_| host.admit(&BROWSER).unwrap())
            .collect();
        assert_eq!(refused(host.admit(&BROWSER)), refusals::BUSY);
        drop(live);
        host.admit(&BROWSER).unwrap();
    }

    #[test]
    fn each_hello_mode_selects_only_its_own_kind_for_one_key() {
        let host = Host::new("owner-mode");
        let invite = store::create_invite(
            &host.dir.0,
            "alice",
            store::tests::grant(),
            "Jerry",
            "Mac",
            3600,
            false,
            store::now_ms(),
        )
        .unwrap();
        let guest_hello = json!({"v": 1, "invite_id": invite.record.invite_id, "secret": invite.secret, "device": "Chrome"});
        let guest_id = match host.admit_any(&BROWSER, &guest_hello) {
            LinkAdmission::Admitted {
                principal: Principal::Guest(guest),
                ..
            } => guest.guest_id,
            _ => panic!("a guest hello is a guest"),
        };
        // The key holds a guest share but no owner grant.
        let now = store::now_ms();
        let owner_hello = host.owner_hello(Some(host.browser_statement(&BROWSER, SUB, now)));
        assert!(matches!(
            host.admit_any(&BROWSER, &owner_hello),
            LinkAdmission::Refused(refusals::NOT_GRANTED)
        ));
        host.add(&BROWSER, 3600);
        assert!(matches!(
            host.admit_any(&BROWSER, &owner_hello),
            LinkAdmission::Admitted {
                principal: Principal::Owner(_),
                ..
            }
        ));
        match host.admit_any(&BROWSER, &json!({"v": 1, "device": "Chrome"})) {
            LinkAdmission::Admitted {
                principal: Principal::Guest(guest),
                ..
            } => assert_eq!(guest.guest_id, guest_id),
            _ => panic!("a returning guest hello still selects the share"),
        }
    }
}
