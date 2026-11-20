//! Account-bound shares end to end through admission (herdr#440): binding a
//! share to an account, adding and removing devices, revoking a person, the
//! `[guest] accounts` switch, and plain shares staying as they were.

use std::sync::Mutex;

use serde_json::{json, Value};

use super::account::tests::{settings, Issuer, KeyServer};
use super::account::{codes, Env, Settings};
use super::store::{self, AccountHello, AdmitOutcome};
use super::*;
use crate::api::schema::GuestAuditEvent;

const SUB: &str = "sub-Example-012345678";
const OTHER_SUB: &str = "sub-Another-012345678";
const PHONE: [u8; 32] = [0x31; 32];
const LAPTOP: [u8; 32] = [0x32; 32];
const TABLET: [u8; 32] = [0x33; 32];

/// A host directory with a throwaway account service.
struct Host {
    dir: store::tests::TempDir,
    host_id: String,
    issuer: Issuer,
    keys: KeyServer,
    accounts: bool,
    alerts: Mutex<Vec<crate::push::PushNotification>>,
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
            accounts: true,
            alerts: Mutex::new(Vec::new()),
        }
    }

    fn statement(&self, device: &[u8; 32], sub: &str) -> String {
        self.issuer.statement(&self.host_id, device, sub)
    }

    fn admit(&self, device: &[u8; 32], hello: &Value) -> Admission {
        let settings = || Settings {
            enabled: self.accounts,
            ..settings()
        };
        let fetch = |issuer: &str| self.keys.fetch(issuer);
        let notify = |alert: crate::push::PushNotification| self.alerts.lock().unwrap().push(alert);
        let env = Env {
            settings: &settings,
            fetch_keys: &fetch,
            notify_owner: &notify,
        };
        admit_with(self.dir.0.clone(), &env, *device, hello)
    }

    fn refresh(&self, session: &AccountSession, jws: &str) -> Result<u64, &'static str> {
        let settings = || Settings {
            enabled: self.accounts,
            ..settings()
        };
        let fetch = |issuer: &str| self.keys.fetch(issuer);
        let notify = |_: crate::push::PushNotification| {};
        let env = Env {
            settings: &settings,
            fetch_keys: &fetch,
            notify_owner: &notify,
        };
        refresh_account_in(&self.dir.0, &env, session, jws)
    }

    fn invite(&self) -> store::NewInvite {
        store::create_invite(
            &self.dir.0,
            "alice",
            store::tests::grant(),
            "Jerry",
            "Mac",
            3600,
            false,
            store::now_ms(),
        )
        .unwrap()
    }

    /// Accepts a new invite from `device`, bound to `sub` when given.
    fn accept(
        &self,
        device: &[u8; 32],
        sub: Option<&str>,
    ) -> (GuestPrincipal, Option<AccountSession>) {
        let invite = self.invite();
        let mut hello = json!({"v": 1, "invite_id": invite.record.invite_id, "secret": invite.secret, "device": "iPhone"});
        if let Some(sub) = sub {
            hello["account"] = json!(self.statement(device, sub));
        }
        match self.admit(device, &hello) {
            Admission::Admitted {
                principal, account, ..
            } => (principal, account),
            Admission::Refused(code) => panic!("refused: {code}"),
        }
    }

    fn returning(&self, device: &[u8; 32], statement: Option<String>, name: &str) -> Admission {
        let mut hello = json!({"v": 1, "device": name});
        if let Some(statement) = statement {
            hello["account"] = json!(statement);
        }
        self.admit(device, &hello)
    }

    fn record(&self, guest_id: &str) -> store::GuestRecord {
        store::load_store(&self.dir.0)
            .unwrap()
            .guests
            .into_iter()
            .find(|guest| guest.guest_id == guest_id)
            .unwrap()
    }

    fn audit(&self) -> Vec<crate::api::schema::GuestAuditEntry> {
        audit::read(&self.dir.0, None, None, 100).unwrap()
    }
}

fn refused(admission: Admission) -> &'static str {
    match admission {
        Admission::Refused(code) => code,
        Admission::Admitted { reply, .. } => panic!("admitted: {reply}"),
    }
}

fn admitted(admission: Admission) -> (GuestPrincipal, Value, Option<AccountSession>) {
    match admission {
        Admission::Admitted {
            principal,
            reply,
            account,
        } => (principal, reply, account),
        Admission::Refused(code) => panic!("refused: {code}"),
    }
}

#[test]
fn add_to_my_account_binds_the_share_and_sets_a_deadline() {
    let host = Host::new("acct-bind");
    let (principal, account) = host.accept(&PHONE, Some(SUB));
    let record = host.record(&principal.guest_id);
    assert_eq!(record.account.as_deref(), Some(SUB));
    assert!(
        record.devices.is_empty(),
        "the redeeming device is device_pub"
    );
    let session = account.expect("an account-bound session has a deadline");
    let now = store::now_ms();
    assert!(session.deadline_ms > now && session.deadline_ms <= now + 11 * 60 * 1000);
    let info = record.info();
    assert!(info.account_bound);
    assert_eq!(info.person, SUB);
    assert_eq!(host.keys.fetches(), 1);
}

#[test]
fn a_failed_statement_leaves_the_invite_for_another_try() {
    let host = Host::new("acct-retry");
    let invite = host.invite();
    let hello = |statement: String| json!({"v": 1, "invite_id": invite.record.invite_id, "secret": invite.secret, "device": "iPhone", "account": statement});
    // A statement for another device than the one in the handshake.
    assert_eq!(
        refused(host.admit(&PHONE, &hello(host.statement(&LAPTOP, SUB)))),
        codes::INVALID
    );
    let stored = store::load_store(&host.dir.0).unwrap();
    assert!(
        stored.invites[0].used_by.is_none(),
        "the invite is still unused"
    );
    admitted(host.admit(&PHONE, &hello(host.statement(&PHONE, SUB))));
}

#[test]
fn an_account_bound_device_without_a_statement_is_refused() {
    let host = Host::new("acct-required");
    let (principal, _) = host.accept(&PHONE, Some(SUB));
    assert_eq!(
        refused(host.returning(&PHONE, None, "iPhone")),
        codes::REQUIRED
    );
    assert_eq!(
        refused(host.returning(&PHONE, Some(host.statement(&PHONE, OTHER_SUB)), "iPhone")),
        codes::MISMATCH
    );
    let (again, reply, account) =
        admitted(host.returning(&PHONE, Some(host.statement(&PHONE, SUB)), "iPhone"));
    assert_eq!(again.guest_id, principal.guest_id);
    assert!(account.is_some());
    assert!(reply["account"]["deadline_unix"].is_u64(), "{reply}");
}

#[test]
fn a_new_device_is_added_with_an_audit_record_and_an_owner_push() {
    let host = Host::new("acct-add");
    let (principal, _) = host.accept(&PHONE, Some(SUB));
    let (laptop, _, account) =
        admitted(host.returning(&LAPTOP, Some(host.statement(&LAPTOP, SUB)), "MacBook"));
    assert_eq!(laptop.guest_id, principal.guest_id);
    assert_eq!(laptop.fingerprint, store::fingerprint(&LAPTOP));
    assert!(account.is_some());

    let record = host.record(&principal.guest_id);
    assert_eq!(record.devices.len(), 1);
    assert_eq!(record.devices[0].fingerprint, store::fingerprint(&LAPTOP));
    assert_eq!(record.devices[0].device, "MacBook");
    assert_eq!(
        record.info().devices[0].fingerprint,
        store::fingerprint(&LAPTOP)
    );

    let added: Vec<_> = host
        .audit()
        .into_iter()
        .filter(|entry| entry.event == GuestAuditEvent::DeviceAdded)
        .collect();
    assert_eq!(added.len(), 1);
    assert_eq!(added[0].fingerprint, store::fingerprint(&LAPTOP));
    assert_eq!(added[0].text.as_deref(), Some("MacBook"));
    let alerts = host.alerts.lock().unwrap();
    assert_eq!(alerts.len(), 1);
    assert_eq!(alerts[0].title, "alice added a device");
    assert_eq!(alerts[0].kind, crate::push::PushKind::GuestDevice);
    assert!(alerts[0].guest_scope.is_none(), "only the owner hears it");
    drop(alerts);

    // Coming back is not another addition.
    admitted(host.returning(&LAPTOP, Some(host.statement(&LAPTOP, SUB)), "MacBook"));
    assert_eq!(host.record(&principal.guest_id).devices.len(), 1);
    assert_eq!(host.alerts.lock().unwrap().len(), 1);
}

#[test]
fn a_removed_device_is_refused_even_with_a_valid_statement() {
    let host = Host::new("acct-remove");
    let (principal, _) = host.accept(&PHONE, Some(SUB));
    let (laptop, _, _) =
        admitted(host.returning(&LAPTOP, Some(host.statement(&LAPTOP, SUB)), "MacBook"));
    let live = laptop.register_live();
    let phone_live = principal.register_live();

    let (info, closed) = remove_device_at(&host.dir.0, &principal.guest_id, &laptop.fingerprint)
        .unwrap()
        .unwrap();
    assert_eq!(closed, 1);
    assert!(live.revoked(), "the removed device's session closes now");
    assert!(!phone_live.revoked(), "the person's other devices go on");
    assert!(info.devices[0].removed);
    assert!(laptop.current().is_none());
    assert!(principal.current().is_some());

    assert_eq!(
        refused(host.returning(&LAPTOP, Some(host.statement(&LAPTOP, SUB)), "MacBook")),
        codes::DEVICE_REMOVED
    );
    admitted(host.returning(&PHONE, Some(host.statement(&PHONE, SUB)), "iPhone"));
    assert!(host
        .audit()
        .iter()
        .any(|entry| entry.event == GuestAuditEvent::DeviceRemoved));

    // The redeeming device can be removed too.
    remove_device_at(&host.dir.0, &principal.guest_id, &principal.fingerprint)
        .unwrap()
        .unwrap();
    assert_eq!(
        refused(host.returning(&PHONE, Some(host.statement(&PHONE, SUB)), "iPhone")),
        codes::DEVICE_REMOVED
    );
    // Unknown devices and plain shares are told apart.
    assert_eq!(
        remove_device_at(
            &host.dir.0,
            &principal.guest_id,
            "SHA256:0000·0000·0000·0000"
        )
        .unwrap_err()
        .0,
        "guest_device_not_found"
    );
    let (plain, _) = host.accept(&TABLET, None);
    assert_eq!(
        remove_device_at(&host.dir.0, &plain.guest_id, &plain.fingerprint)
            .unwrap_err()
            .0,
        "guest_not_account_bound"
    );
}

#[test]
fn revoke_by_person_closes_every_live_session_of_that_person() {
    let host = Host::new("acct-person");
    let (first, _) = host.accept(&PHONE, Some(SUB));
    // A second share of the same person, for another terminal.
    let invite = store::create_invite(
        &host.dir.0,
        "alice",
        serde_json::from_value(json!({
            "terminal_id": "term_2",
            "agent_name": "other",
            "agent_session": {"source": "herdr", "agent": "pi", "kind": "id", "value": "s-2"}
        }))
        .unwrap(),
        "Jerry",
        "Mac",
        3600,
        false,
        store::now_ms(),
    )
    .unwrap();
    let hello = json!({"v": 1, "invite_id": invite.record.invite_id, "secret": invite.secret, "account": host.statement(&LAPTOP, SUB)});
    let (second, _, _) = admitted(host.admit(&LAPTOP, &hello));
    let (bystander, _) = host.accept(&TABLET, Some(OTHER_SUB));
    let lives = [first.register_live(), second.register_live()];
    let other = bystander.register_live();

    let closed = revoke_at(host.dir.0.clone(), RevokeTarget::Person(SUB))
        .unwrap()
        .unwrap();
    assert_eq!(closed, 2);
    assert!(lives.iter().all(LiveSession::revoked));
    assert!(!other.revoked());
    assert!(host.record(&first.guest_id).revoked);
    assert!(host.record(&second.guest_id).revoked);
    assert!(!host.record(&bystander.guest_id).revoked);
    assert_eq!(
        refused(host.returning(&PHONE, Some(host.statement(&PHONE, SUB)), "iPhone")),
        "revoked"
    );
    assert_eq!(
        revoke_at(
            host.dir.0.clone(),
            RevokeTarget::Person("nobody-0123456789")
        )
        .unwrap(),
        None
    );
    // A plain share's person is its fingerprint.
    let (plain, _) = host.accept(&[0x34; 32], None);
    let live = plain.register_live();
    assert_eq!(
        revoke_at(host.dir.0.clone(), RevokeTarget::Person(&plain.fingerprint)).unwrap(),
        Some(1)
    );
    assert!(live.revoked());
}

#[test]
fn an_in_band_refresh_needs_the_same_account_and_a_device_still_on_the_share() {
    let host = Host::new("acct-refresh");
    let (principal, account) = host.accept(&PHONE, Some(SUB));
    let session = account.unwrap();
    assert!(host.refresh(&session, &host.statement(&PHONE, SUB)).is_ok());
    assert_eq!(
        host.refresh(&session, &host.statement(&LAPTOP, SUB)),
        Err(codes::INVALID)
    );
    assert_eq!(
        host.refresh(&session, &host.statement(&PHONE, OTHER_SUB)),
        Err(codes::MISMATCH)
    );
    remove_device_at(&host.dir.0, &principal.guest_id, &principal.fingerprint)
        .unwrap()
        .unwrap();
    assert_eq!(
        host.refresh(&session, &host.statement(&PHONE, SUB)),
        Err(codes::DEVICE_REMOVED)
    );
    revoke_at(host.dir.0.clone(), RevokeTarget::Guest(&principal.guest_id)).unwrap();
    assert_eq!(
        host.refresh(&session, &host.statement(&PHONE, SUB)),
        Err("revoked")
    );
}

#[test]
fn stale_keys_keep_known_devices_but_refuse_new_ones() {
    let host = Host::new("acct-stale");
    let (principal, _) = host.accept(&PHONE, Some(SUB));
    // The service went away more than an hour ago.
    *host.keys.jwks.lock().unwrap() = None;
    store::update_side(
        &host.dir.0,
        account::KEYS_FILE,
        |cache: &mut account::KeyCache| {
            let past = store::now_ms() - 2 * account::KEYS_FRESH_MS;
            cache.fetched_ms = Some(past);
            cache.attempt_ms = Some(past);
            ((), true)
        },
    )
    .unwrap();
    let (again, _, _) =
        admitted(host.returning(&PHONE, Some(host.statement(&PHONE, SUB)), "iPhone"));
    assert_eq!(again.guest_id, principal.guest_id);
    assert_eq!(
        refused(host.returning(&LAPTOP, Some(host.statement(&LAPTOP, SUB)), "MacBook")),
        codes::KEYS_STALE
    );
    assert!(host.record(&principal.guest_id).devices.is_empty());
    // New shares need fresh keys too.
    let invite = host.invite();
    let hello = json!({"v": 1, "invite_id": invite.record.invite_id, "secret": invite.secret, "account": host.statement(&TABLET, SUB)});
    assert_eq!(refused(host.admit(&TABLET, &hello)), codes::KEYS_STALE);
}

#[test]
fn the_switch_off_suspends_account_shares_and_leaves_plain_ones_alone() {
    let mut host = Host::new("acct-off");
    let (plain, _) = host.accept(&TABLET, None);
    let (_bound, _) = host.accept(&PHONE, Some(SUB));
    host.accounts = false;
    let invite = host.invite();
    let hello = json!({"v": 1, "invite_id": invite.record.invite_id, "secret": invite.secret, "account": host.statement(&LAPTOP, SUB)});
    assert_eq!(refused(host.admit(&LAPTOP, &hello)), codes::DISABLED);
    assert_eq!(
        refused(host.returning(&PHONE, Some(host.statement(&PHONE, SUB)), "iPhone")),
        codes::DISABLED
    );
    let (again, _, account) = admitted(host.returning(&TABLET, None, "iPad"));
    assert_eq!(again.guest_id, plain.guest_id);
    assert!(account.is_none());
}

/// With accounts on, a host that never sees a statement never reads the
/// account settings or fetches keys, and plain shares get no deadline.
#[test]
fn plain_shares_never_touch_the_account_service() {
    let host = Host::new("acct-plain");
    let (plain, account) = host.accept(&TABLET, None);
    assert!(account.is_none());
    let record = host.record(&plain.guest_id);
    assert_eq!(record.account, None);
    assert!(!record.info().account_bound);
    assert_eq!(record.info().person, record.fingerprint);
    let (_, reply, account) = admitted(host.returning(&TABLET, None, "iPad"));
    assert!(account.is_none());
    assert!(reply.get("account").is_none(), "{reply}");
    assert_eq!(host.keys.fetches(), 0);
    assert!(!host.dir.0.join(account::KEYS_FILE).exists());
    // Another device cannot reach a plain share, statement or not.
    assert_eq!(
        refused(host.returning(&LAPTOP, Some(host.statement(&LAPTOP, SUB)), "x")),
        "unknown"
    );
    let stored = std::fs::read_to_string(host.dir.0.join("guests.json")).unwrap();
    assert!(!stored.contains("\"account\""), "{stored}");
    assert!(!stored.contains("\"devices\""), "{stored}");
}

/// A guests.json written before account-bound shares loads, admits its
/// guest, and is written back without new fields.
#[test]
fn an_old_guests_json_loads_and_admits_as_before() {
    let host = Host::new("acct-old");
    let device = store::b64url(&TABLET);
    let old = json!({
        "guests": [{
            "guest_id": "g-old",
            "name": "bob",
            "device_pub": device,
            "fingerprint": store::fingerprint(&TABLET),
            "device": "iPad",
            "grant": store::tests::grant(),
            "owner_name": "Jerry",
            "machine_label": "Mac",
            "created_ms": 1,
            "last_seen_ms": 1,
            "revoked": false,
            "share_gram": true
        }],
        "invites": []
    });
    std::fs::write(
        host.dir.0.join("guests.json"),
        serde_json::to_vec_pretty(&old).unwrap(),
    )
    .unwrap();
    let outcome = store::admit_in(
        &host.dir.0,
        &TABLET,
        &json!({"v": 1}),
        &AccountHello::Absent,
        store::now_ms(),
    )
    .unwrap();
    let AdmitOutcome::Returning { guest, added, .. } = outcome else {
        panic!("{outcome:?}");
    };
    assert_eq!(guest.guest_id, "g-old");
    assert_eq!(guest.account, None);
    assert!(added.is_none());
    let (principal, _, account) = admitted(host.returning(&TABLET, None, "iPad"));
    assert_eq!(principal.guest_id, "g-old");
    assert!(account.is_none());
    let stored: Value =
        serde_json::from_slice(&std::fs::read(host.dir.0.join("guests.json")).unwrap()).unwrap();
    let keys: Vec<&String> = stored["guests"][0].as_object().unwrap().keys().collect();
    assert!(
        !keys
            .iter()
            .any(|key| *key == "account" || *key == "devices"),
        "{keys:?}"
    );
}
