//! Every branch of `auth`, `code` and `account`, with a fake server, home,
//! NSS and sealer.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::*;
use crate::fake::{FakeCreds, TempDir};
use crate::login::door::{Params, Person as ServerPerson, Session};
use crate::login::testing::paths;

const NOW: u64 = 1_800_000_000;
const DAY: u64 = 86_400;
pub(crate) const PASSWORD: &str = "correct horse battery staple 1";
/// kdf.json's first vector: `PASSWORD` against this salt.
const SALT: &str = "AAAAAAAAAAAAAAAAAAAAAA==";
const SECRET: &str = "0d0R8jeMwo4LuShcvdP7aW4F1sSlks3OkaoTN5E60AE=";
pub(crate) const UID: u32 = 21001;

#[derive(Debug, Clone, PartialEq, Eq)]
enum Call {
    Params(String),
    Login(String, u8, String),
    Code(String, String),
}

/// Answers from a script, and records what it was asked. Asked with nothing
/// left in the script, it panics: the server was not to be asked.
#[derive(Default)]
struct FakeDoor {
    params: Mutex<VecDeque<Online<Params>>>,
    login: Mutex<VecDeque<Online<Step>>>,
    code: Mutex<VecDeque<Online<Step>>>,
    calls: Mutex<Vec<Call>>,
    upgrades: Mutex<Vec<(String, String, String, String)>>,
}

impl FakeDoor {
    fn calls(&self) -> Vec<Call> {
        self.calls.lock().unwrap().clone()
    }
}

impl Door for FakeDoor {
    fn params(&self, username: &str) -> Online<Params> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Params(username.into()));
        self.params
            .lock()
            .unwrap()
            .pop_front()
            .expect("params was not to be asked")
    }
    fn login(&self, username: &str, kdf_version: u8, secret: &str) -> Online<Step> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Login(username.into(), kdf_version, secret.into()));
        self.login
            .lock()
            .unwrap()
            .pop_front()
            .expect("login was not to be asked")
    }
    fn code(&self, challenge: &str, code: &str) -> Online<Step> {
        self.calls
            .lock()
            .unwrap()
            .push(Call::Code(challenge.into(), code.into()));
        self.code
            .lock()
            .unwrap()
            .pop_front()
            .expect("code was not to be asked")
    }
    fn accounts(&self) -> Option<&str> {
        Some("https://mauvely.com")
    }
    fn upgrade(&self, token: &str, password: &str, salt: &str, secret: &str) -> Result<(), String> {
        self.upgrades.lock().unwrap().push((
            token.into(),
            password.into(),
            salt.into(),
            secret.into(),
        ));
        Ok(())
    }
}

#[derive(Default)]
struct FakeHome {
    made: Mutex<Vec<String>>,
    fails: AtomicBool,
}

impl Home for Arc<FakeHome> {
    fn make(&self, username: &str) -> Result<(), String> {
        self.made.lock().unwrap().push(username.into());
        if self.fails.load(Ordering::SeqCst) {
            return Err("mauvely-home@ failed".into());
        }
        Ok(())
    }
}

/// What was handed over: the uid, then the session's token, expiry, origin
/// and handle.
type Handed = (u32, String, u64, String, String);

#[derive(Default)]
struct FakeHandOver(Mutex<Vec<Handed>>);

impl HandOver for Arc<FakeHandOver> {
    fn hand_over(&self, uid: u32, s: &HandOff) -> Result<(), crate::Error> {
        self.0.lock().unwrap().push((
            uid,
            s.token.into(),
            s.expires_at,
            s.origin.into(),
            s.handle.into(),
        ));
        Ok(())
    }
}

pub(crate) struct Fx {
    _dir: TempDir,
    pub svc: Service,
    door: Arc<FakeDoor>,
    home: Arc<FakeHome>,
    handed: Arc<FakeHandOver>,
    clock: Arc<AtomicU64>,
    names: Arc<Mutex<Vec<(String, u32)>>>,
}

/// NSS answers from a list the test can add to, and finds our own records
/// as nss-systemd would.
struct ListNames {
    local: Arc<Mutex<Vec<(String, u32)>>>,
    userdb: std::path::PathBuf,
}

impl Names for ListNames {
    fn user(&self, name: &str) -> Option<u32> {
        let local = self.local.lock().unwrap();
        local
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, u)| *u)
            .or_else(|| userdb::uid_of(&self.userdb, name))
    }
    fn uid(&self, uid: u32) -> Option<String> {
        let local = self.local.lock().unwrap();
        local
            .iter()
            .find(|(_, u)| *u == uid)
            .map(|(n, _)| n.clone())
            .or_else(|| userdb::name_of(&self.userdb, uid))
    }
    fn group(&self, name: &str) -> Option<u32> {
        self.user(name)
    }
    fn gid(&self, gid: u32) -> Option<String> {
        self.uid(gid)
    }
}

pub(crate) fn shared() -> Value {
    json!({
        "mode": "shared", "assigned": null, "admins": ["ada"],
        "org": { "name": "Suez", "slug": "suez" }, "offline_days": 14
    })
}

fn assigned_to(name: &str) -> Value {
    json!({
        "mode": "assigned", "assigned": { "username": name, "name": "Someone" },
        "admins": ["ada"], "org": { "name": "Suez", "slug": "suez" }, "offline_days": 14
    })
}

pub(crate) fn fx(people: Option<Value>) -> Fx {
    let dir = TempDir::new();
    let p = paths(&dir);
    if let Some(v) = people {
        crate::login::people::apply(&p, &v).unwrap();
    }
    let door = Arc::new(FakeDoor::default());
    let home = Arc::new(FakeHome::default());
    let handed = Arc::new(FakeHandOver::default());
    let clock = Arc::new(AtomicU64::new(NOW));
    let names = Arc::new(Mutex::new(vec![
        ("root".to_owned(), 0),
        ("polkitd".to_owned(), 998),
    ]));
    let slot: Arc<dyn Door> = door.clone();
    let c = Arc::clone(&clock);
    let svc = Service {
        names: Box::new(ListNames {
            local: Arc::clone(&names),
            userdb: p.userdb.clone(),
        }),
        paths: p,
        sealer: Box::new(FakeCreds),
        home: Box::new(Arc::clone(&home)),
        hand_over: Box::new(Arc::clone(&handed)),
        door: Box::new(move || Some(Arc::clone(&slot))),
        clock: Box::new(move || c.load(Ordering::SeqCst)),
        delay: Box::new(|_| {}),
    };
    Fx {
        _dir: dir,
        svc,
        door,
        home,
        handed,
        clock,
        names,
    }
}

impl Fx {
    fn auth(&self, peer: u32, service: &str, username: &str, password: &str) -> Auth {
        self.svc
            .auth(peer, service, username, Zeroizing::new(password.into()))
    }

    /// The answer of an `auth` that did not ask for a code.
    fn answer(&self, peer: u32, service: &str, username: &str, password: &str) -> Answer {
        match self.auth(peer, service, username, password) {
            Auth::Done(a, _) => a,
            Auth::Code(_) => panic!("a code was asked"),
        }
    }

    pub(crate) fn params(&self, p: Online<Params>) -> &Self {
        self.door.params.lock().unwrap().push_back(p);
        self
    }
    pub(crate) fn login(&self, s: Online<Step>) -> &Self {
        self.door.login.lock().unwrap().push_back(s);
        self
    }
    pub(crate) fn code(&self, s: Online<Step>) -> &Self {
        self.door.code.lock().unwrap().push_back(s);
        self
    }

    pub(crate) fn entry(&self, username: &str) -> Option<Entry> {
        cache::read(&self.svc.paths.cache, &FakeCreds, username)
    }

    /// A cache entry and records for `username`, as an online sign-in
    /// `days_ago` would have left them.
    pub(crate) fn signed_in_before(&self, username: &str, uid: u32, password: &str, days_ago: u64) {
        let entry = Entry {
            username: username.into(),
            handle: format!("{username}.suez"),
            uid,
            name: "Timur Inal".into(),
            device_admin: false,
            offline_days: 14,
            signed_in_at: NOW - days_ago * DAY,
            verifier: Verifier::new(password.as_bytes()).unwrap(),
        };
        cache::write(&self.svc.paths.cache, &FakeCreds, &entry).unwrap();
        userdb::write(
            &self.svc.paths.userdb,
            &Person {
                username: username.into(),
                uid,
                real_name: "Timur Inal".into(),
                device_admin: false,
            },
        )
        .unwrap();
    }
}

pub(crate) fn v1() -> Online<Params> {
    Online::Answer(Params {
        kdf_version: 1,
        auth_salt: Some(SALT.into()),
    })
}

fn v0() -> Online<Params> {
    Online::Answer(Params {
        kdf_version: 0,
        auth_salt: None,
    })
}

pub(crate) fn signed_in(username: &str, uid: u32, admin: bool, kdf_version: u8) -> Online<Step> {
    Online::Answer(Step::SignedIn(SignedIn {
        session: Session {
            token: "tok_os".into(),
            expires_at: NOW + 90 * DAY,
        },
        person: ServerPerson {
            username: username.into(),
            handle: format!("{username}.suez"),
            name: "Timur Inal".into(),
            uid,
            gid: uid,
            device_admin: admin,
            kdf_version,
        },
        offline_days: 14,
    }))
}

pub(crate) fn challenge(factor: &str) -> Online<Step> {
    Online::Answer(Step::Code {
        challenge: Zeroizing::new("ch_1".into()),
        factor: factor.into(),
        expires_at: NOW + 600,
    })
}

fn refused(r: Reason) -> Answer {
    Answer::Refused(r)
}

fn unreachable<T>() -> Online<T> {
    Online::Unreachable("connection refused".into())
}

// ── the login screen, online ────────────────────────────────────────────────

#[test]
fn a_version_1_account_signs_in_with_the_derived_secret() {
    let f = fx(Some(shared()));
    f.params(v1()).login(signed_in("timur", UID, false, 1));
    let Auth::Done(answer, upgrade) = f.auth(0, "plasmalogin", "timur", PASSWORD) else {
        panic!("a code was asked")
    };
    assert_eq!(answer, Answer::Ok);
    assert!(upgrade.is_none());
    // The vector's authSecret went to the server, never the password.
    assert_eq!(
        f.door.calls(),
        [
            Call::Params("timur".into()),
            Call::Login("timur".into(), 1, SECRET.into())
        ]
    );
    // Records, home, cache, hand-off.
    let d = &f.svc.paths.userdb;
    assert_eq!(userdb::uid_of(d, "timur"), Some(UID));
    assert!(userdb::admins(d).is_empty());
    assert_eq!(*f.home.made.lock().unwrap(), ["timur"]);
    let entry = f.entry("timur").unwrap();
    assert_eq!(
        (
            entry.uid,
            entry.handle.as_str(),
            entry.offline_days,
            entry.signed_in_at
        ),
        (UID, "timur.suez", 14, NOW)
    );
    assert_eq!(entry.verifier.check(PASSWORD.as_bytes()), Some(true));
    assert_eq!(
        *f.handed.0.lock().unwrap(),
        [(
            UID,
            "tok_os".to_owned(),
            NOW + 90 * DAY,
            "https://mauvely.com".to_owned(),
            "timur.suez".to_owned()
        )]
    );
}

#[test]
fn a_device_admin_joins_the_admin_group() {
    let f = fx(Some(shared()));
    f.params(v1()).login(signed_in("ada", UID, true, 1));
    assert_eq!(f.answer(0, "plasmalogin", "ada", PASSWORD), Answer::Ok);
    assert_eq!(userdb::admins(&f.svc.paths.userdb), ["ada"]);
    assert!(f.entry("ada").unwrap().device_admin);
}

#[test]
fn a_version_0_account_sends_its_password_and_is_upgraded_after() {
    let f = fx(Some(shared()));
    f.params(v0()).login(signed_in("timur", UID, false, 0));
    let Auth::Done(answer, Some(upgrade)) = f.auth(0, "plasmalogin", "timur", PASSWORD) else {
        panic!("no upgrade")
    };
    assert_eq!(answer, Answer::Ok);
    assert_eq!(
        f.door.calls()[1],
        Call::Login("timur".into(), 0, PASSWORD.into())
    );
    f.svc.upgrade(upgrade);
    let ups = f.door.upgrades.lock().unwrap().clone();
    assert_eq!(ups.len(), 1);
    let (token, password, salt, secret) = &ups[0];
    assert_eq!((token.as_str(), password.as_str()), ("tok_os", PASSWORD));
    // A fresh salt, and the secret derived against it.
    assert_ne!(salt, SALT);
    assert_eq!(
        kdf::auth_secret(PASSWORD.as_bytes(), salt, kdf::SERVER)
            .unwrap()
            .as_str(),
        secret
    );
}

#[test]
fn the_login_screen_asks_for_the_code_when_the_server_does() {
    let f = fx(Some(shared()));
    f.params(v1()).login(challenge("email"));
    let Auth::Code(pending) = f.auth(0, "plasmalogin", "timur", PASSWORD) else {
        panic!("no code was asked")
    };
    assert_eq!(pending.info, "Enter the code we emailed you.");
    // Nothing is made before the code.
    assert!(f.home.made.lock().unwrap().is_empty());
    assert!(f.entry("timur").is_none());

    f.code(signed_in("timur", UID, false, 1));
    let (answer, upgrade) = f.svc.code(pending, "123456");
    assert_eq!(answer, Answer::Ok);
    assert!(upgrade.is_none());
    assert_eq!(
        f.door.calls()[2],
        Call::Code("ch_1".into(), "123456".into())
    );
    assert!(f.entry("timur").is_some());
    assert_eq!(f.handed.0.lock().unwrap().len(), 1);
}

#[test]
fn a_wrong_code_is_refused_and_nothing_is_made() {
    let f = fx(Some(shared()));
    f.params(v1()).login(challenge("totp"));
    let Auth::Code(pending) = f.auth(0, "plasmalogin", "timur", PASSWORD) else {
        panic!()
    };
    assert_eq!(pending.info, "Enter the code from your authenticator app.");
    f.code(Online::Refused(Reason::Code));
    assert_eq!(f.svc.code(pending, "000000").0, refused(Reason::Code));
    assert!(f.entry("timur").is_none());
    assert!(f.handed.0.lock().unwrap().is_empty());
}

#[test]
fn a_code_after_its_challenge_expired_is_not_sent() {
    let f = fx(Some(shared()));
    f.params(v1()).login(challenge("totp"));
    let Auth::Code(pending) = f.auth(0, "plasmalogin", "timur", PASSWORD) else {
        panic!()
    };
    f.clock.store(NOW + 601, Ordering::SeqCst);
    assert_eq!(f.svc.code(pending, "123456").0, refused(Reason::Expired));
    assert_eq!(f.door.calls().len(), 2);
}

#[test]
fn the_code_has_no_offline_fallback() {
    let f = fx(Some(shared()));
    f.signed_in_before("timur", UID, PASSWORD, 1);
    f.params(v1()).login(challenge("totp"));
    let Auth::Code(pending) = f.auth(0, "plasmalogin", "timur", PASSWORD) else {
        panic!()
    };
    f.code(unreachable());
    assert_eq!(
        f.svc.code(pending, "123456").0,
        refused(Reason::Unreachable)
    );
    assert!(f.home.made.lock().unwrap().is_empty());
}

#[test]
fn the_server_must_sign_in_the_person_who_typed() {
    for wrong in [
        signed_in("ada", UID, false, 1),
        signed_in("timur", 0, false, 1),
        signed_in("timur", 1000, false, 1),
        signed_in("timur", 65_534, false, 1),
    ] {
        let f = fx(Some(shared()));
        f.params(v1()).login(wrong);
        assert_eq!(
            f.answer(0, "plasmalogin", "timur", PASSWORD),
            refused(Reason::Unavailable)
        );
        assert!(userdb::uid_of(&f.svc.paths.userdb, "timur").is_none());
        assert!(f.entry("timur").is_none());
    }
    // Another organisation's handle.
    let f = fx(Some(shared()));
    let Online::Answer(Step::SignedIn(mut s)) = signed_in("timur", UID, false, 1) else {
        panic!()
    };
    s.person.handle = "timur.other".into();
    f.params(v1()).login(Online::Answer(Step::SignedIn(s)));
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", PASSWORD),
        refused(Reason::Unavailable)
    );
}

#[test]
fn a_home_that_cannot_be_made_refuses_the_login() {
    let f = fx(Some(shared()));
    f.home.fails.store(true, Ordering::SeqCst);
    f.params(v1()).login(signed_in("timur", UID, false, 1));
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", PASSWORD),
        refused(Reason::Internal)
    );
    assert!(f.handed.0.lock().unwrap().is_empty());
}

#[test]
fn a_uid_or_name_another_account_has_is_never_taken_over() {
    // A local account already on the server's uid.
    let f = fx(Some(shared()));
    f.names.lock().unwrap().push(("localadmin".into(), UID));
    f.params(v1()).login(signed_in("timur", UID, false, 1));
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", PASSWORD),
        refused(Reason::Internal)
    );
    assert!(userdb::uid_of(&f.svc.paths.userdb, "timur").is_none());

    // The name was another person's here, on another uid.
    let f = fx(Some(shared()));
    f.signed_in_before("timur", 21_005, "an old password 1", 3);
    f.params(v1()).login(signed_in("timur", UID, false, 1));
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", PASSWORD),
        refused(Reason::Internal)
    );
    assert_eq!(userdb::uid_of(&f.svc.paths.userdb, "timur"), Some(21_005));
}

#[test]
fn a_renamed_person_moves_to_the_new_name() {
    let f = fx(Some(shared()));
    f.signed_in_before("tim", UID, PASSWORD, 3);
    f.params(v1()).login(signed_in("timur", UID, false, 1));
    assert_eq!(f.answer(0, "plasmalogin", "timur", PASSWORD), Answer::Ok);
    let d = &f.svc.paths.userdb;
    assert_eq!(userdb::uid_of(d, "tim"), None);
    assert_eq!(userdb::name_of(d, UID).as_deref(), Some("timur"));
    assert!(f.entry("tim").is_none());
    assert!(f.entry("timur").is_some());
}

// ── offline ─────────────────────────────────────────────────────────────────

#[test]
fn offline_the_cache_signs_in_without_a_code() {
    for at_params in [true, false] {
        let f = fx(Some(shared()));
        f.signed_in_before("timur", UID, PASSWORD, 13);
        if at_params {
            f.params(unreachable());
        } else {
            f.params(v1()).login(unreachable());
        }
        assert_eq!(f.answer(0, "plasmalogin", "timur", PASSWORD), Answer::Ok);
        assert_eq!(*f.home.made.lock().unwrap(), ["timur"]);
        // No session to hand over, and the entry is not renewed.
        assert!(f.handed.0.lock().unwrap().is_empty());
        assert_eq!(f.entry("timur").unwrap().signed_in_at, NOW - 13 * DAY);
    }
}

#[test]
fn offline_a_wrong_password_an_old_entry_or_none_is_refused() {
    let f = fx(Some(shared()));
    f.signed_in_before("timur", UID, PASSWORD, 1);
    f.params(unreachable());
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", "wrong password 1"),
        refused(Reason::Credentials)
    );

    let f = fx(Some(shared()));
    f.signed_in_before("timur", UID, PASSWORD, 14);
    f.params(unreachable());
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", PASSWORD),
        refused(Reason::Offline)
    );

    let f = fx(Some(shared()));
    f.params(unreachable());
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", PASSWORD),
        refused(Reason::Offline)
    );
    assert!(f.home.made.lock().unwrap().is_empty());
}

#[test]
fn offline_the_collections_days_now_cap_the_entrys() {
    let mut people = shared();
    people["offline_days"] = json!(3);
    let f = fx(Some(people));
    f.signed_in_before("timur", UID, PASSWORD, 4);
    f.params(unreachable());
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", PASSWORD),
        refused(Reason::Offline)
    );
}

#[test]
fn offline_an_admin_the_check_in_demoted_stays_demoted() {
    let f = fx(Some(shared()));
    f.signed_in_before("bob", UID, PASSWORD, 1);
    let mut e = f.entry("bob").unwrap();
    e.device_admin = true;
    cache::write(&f.svc.paths.cache, &FakeCreds, &e).unwrap();
    f.params(unreachable());
    assert_eq!(f.answer(0, "plasmalogin", "bob", PASSWORD), Answer::Ok);
    assert!(userdb::admins(&f.svc.paths.userdb).is_empty());
}

// ── a refusal is final ──────────────────────────────────────────────────────

#[test]
fn never_the_cache_after_a_refusal() {
    for r in [
        Reason::Credentials,
        Reason::RateLimited,
        Reason::Inactive,
        Reason::NotMember,
        Reason::SsoRequired,
        Reason::SecondFactorSetup,
        Reason::NotAllowed,
        Reason::Revoked,
        Reason::Unavailable,
    ] {
        let f = fx(Some(shared()));
        f.signed_in_before("timur", UID, PASSWORD, 1);
        f.params(v1()).login(Online::Refused(r));
        assert_eq!(
            f.answer(0, "plasmalogin", "timur", PASSWORD),
            refused(r),
            "{r:?}"
        );
        assert!(f.home.made.lock().unwrap().is_empty(), "{r:?}");
    }
    // Refused at params too.
    let f = fx(Some(shared()));
    f.signed_in_before("timur", UID, PASSWORD, 1);
    f.params(Online::Refused(Reason::RateLimited));
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", PASSWORD),
        refused(Reason::RateLimited)
    );
}

#[test]
fn credentials_for_the_password_the_cache_knows_make_it_stale() {
    let f = fx(Some(shared()));
    f.signed_in_before("timur", UID, PASSWORD, 1);
    f.params(v1()).login(Online::Refused(Reason::Credentials));
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", PASSWORD),
        refused(Reason::Credentials)
    );
    assert!(f.entry("timur").is_none());
}

#[test]
fn credentials_for_another_password_leave_the_cache() {
    // Or anyone typing at the login screen could wipe a person's offline
    // sign-in.
    let f = fx(Some(shared()));
    f.signed_in_before("timur", UID, PASSWORD, 1);
    f.params(v1()).login(Online::Refused(Reason::Credentials));
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", "a guess 12345"),
        refused(Reason::Credentials)
    );
    assert!(f.entry("timur").is_some());
}

#[test]
fn a_person_the_server_says_has_left_loses_their_cache() {
    for r in [
        Reason::NotMember,
        Reason::Inactive,
        Reason::SsoRequired,
        Reason::NotAllowed,
    ] {
        let f = fx(Some(shared()));
        f.signed_in_before("timur", UID, PASSWORD, 1);
        f.params(v1()).login(Online::Refused(r));
        f.answer(0, "plasmalogin", "timur", "whatever 1");
        assert!(f.entry("timur").is_none(), "{r:?}");
        // Their records stay, for brief 29's cleanup.
        assert_eq!(userdb::uid_of(&f.svc.paths.userdb, "timur"), Some(UID));
    }
    for r in [
        Reason::RateLimited,
        Reason::SecondFactorSetup,
        Reason::Revoked,
    ] {
        let f = fx(Some(shared()));
        f.signed_in_before("timur", UID, PASSWORD, 1);
        f.params(v1()).login(Online::Refused(r));
        f.answer(0, "plasmalogin", "timur", "whatever 1");
        assert!(f.entry("timur").is_some(), "{r:?}");
    }
}

// ── the device's say ────────────────────────────────────────────────────────

#[test]
fn an_assigned_device_refuses_others_without_asking_the_server() {
    let f = fx(Some(assigned_to("timur")));
    f.signed_in_before("bob", 21_002, PASSWORD, 1);
    assert_eq!(
        f.answer(0, "plasmalogin", "bob", PASSWORD),
        refused(Reason::NotAllowed)
    );
    assert_eq!(
        f.answer(0, "kde", "bob", PASSWORD),
        refused(Reason::NotAllowed)
    );
    assert!(f.door.calls().is_empty());
    // And bob's offline sign-in is gone.
    assert!(f.entry("bob").is_none());

    // The assigned person and an admin go on.
    f.params(v1()).login(signed_in("timur", UID, false, 1));
    assert_eq!(f.answer(0, "plasmalogin", "timur", PASSWORD), Answer::Ok);
    f.params(v1()).login(signed_in("ada", 21_003, true, 1));
    assert_eq!(f.answer(0, "plasmalogin", "ada", PASSWORD), Answer::Ok);
}

#[test]
fn a_shared_device_asks_the_server_for_anyone() {
    let f = fx(Some(shared()));
    f.params(v1()).login(Online::Refused(Reason::Credentials));
    assert_eq!(
        f.answer(0, "plasmalogin", "stranger", PASSWORD),
        refused(Reason::Credentials)
    );
    assert_eq!(f.door.calls()[0], Call::Params("stranger".into()));
}

#[test]
fn before_the_first_check_in_nobody_signs_in() {
    let f = fx(None);
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", PASSWORD),
        refused(Reason::NotReady)
    );
    assert_eq!(f.svc.account(0, "kde", "timur"), refused(Reason::NotReady));
    assert!(f.door.calls().is_empty());
}

#[test]
fn before_enrolment_the_login_screen_is_not_ready() {
    let mut f = fx(Some(shared()));
    f.svc.door = Box::new(|| None);
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", PASSWORD),
        refused(Reason::NotReady)
    );
}

// ── names ───────────────────────────────────────────────────────────────────

#[test]
fn a_local_account_is_pam_unixs() {
    let f = fx(Some(assigned_to("timur")));
    for service in ["plasmalogin", "sudo", "kde"] {
        assert_eq!(
            f.answer(0, service, "polkitd", "x"),
            refused(Reason::NotMauvely)
        );
        assert_eq!(
            f.svc.account(0, service, "polkitd"),
            refused(Reason::NotMauvely)
        );
    }
    assert!(f.door.calls().is_empty());
}

#[test]
fn names_nobody_could_have_are_unknown_and_some_cannot_sign_in_to_a_computer() {
    let f = fx(Some(shared()));
    for name in ["Timur", "ab", "tim.suez", "-rf", "a_b"] {
        assert_eq!(
            f.answer(0, "plasmalogin", name, PASSWORD),
            refused(Reason::UnknownUser),
            "{name}"
        );
    }
    for name in ["0tim", &"a".repeat(32)] {
        assert_eq!(
            f.answer(0, "plasmalogin", name, PASSWORD),
            refused(Reason::BadUsername),
            "{name}"
        );
    }
    assert!(f.door.calls().is_empty());
}

#[test]
fn an_empty_password_is_wrong_without_asking() {
    let f = fx(Some(shared()));
    assert_eq!(
        f.answer(0, "plasmalogin", "timur", ""),
        refused(Reason::Credentials)
    );
    assert!(f.door.calls().is_empty());
}

// ── who may ask ─────────────────────────────────────────────────────────────

#[test]
fn only_root_may_ask_for_the_login_screen() {
    let f = fx(Some(shared()));
    f.signed_in_before("timur", UID, PASSWORD, 1);
    assert_eq!(
        f.answer(UID, "plasmalogin", "timur", PASSWORD),
        refused(Reason::Forbidden)
    );
    assert_eq!(
        f.svc.account(UID, "plasmalogin", "timur"),
        refused(Reason::Forbidden)
    );
    assert!(f.door.calls().is_empty());
}

#[test]
fn a_person_may_ask_only_about_themselves() {
    let f = fx(Some(shared()));
    f.signed_in_before("timur", UID, PASSWORD, 1);
    f.signed_in_before("ada", 21_002, "adas password 1", 1);
    // The lock screen, as timur.
    assert_eq!(f.answer(UID, "kde", "timur", PASSWORD), Answer::Ok);
    assert_eq!(f.svc.account(UID, "kde", "timur"), Answer::Ok);
    // About ada, as timur: refused, right password or not.
    assert_eq!(
        f.answer(UID, "kde", "ada", "adas password 1"),
        refused(Reason::Forbidden)
    );
    assert_eq!(f.svc.account(UID, "kde", "ada"), refused(Reason::Forbidden));
    // About somebody with no account here.
    assert_eq!(
        f.answer(UID, "kde", "nobody", "x"),
        refused(Reason::UnknownUser)
    );
    // Root may ask about anyone.
    assert_eq!(f.answer(0, "sudo", "ada", "adas password 1"), Answer::Ok);
}

// ── every other service: the cache only ─────────────────────────────────────

#[test]
fn unlocking_sudo_and_polkit_check_the_cache_and_never_the_server() {
    let f = fx(Some(shared()));
    // An entry far older than offlineDays still unlocks: that limit is the
    // login screen's.
    f.signed_in_before("timur", UID, PASSWORD, 40);
    for service in ["kde", "sudo", "polkit-1", "login", "su", "kde-fingerprint"] {
        assert_eq!(
            f.answer(0, service, "timur", PASSWORD),
            Answer::Ok,
            "{service}"
        );
        assert_eq!(
            f.answer(0, service, "timur", "wrong password 1"),
            refused(Reason::Credentials),
            "{service}"
        );
    }
    assert!(f.door.calls().is_empty());
    assert!(f.home.made.lock().unwrap().is_empty());
    assert!(f.handed.0.lock().unwrap().is_empty());
}

#[test]
fn without_an_entry_the_other_services_send_people_to_the_login_screen() {
    let f = fx(Some(shared()));
    userdb::write(
        &f.svc.paths.userdb,
        &Person {
            username: "timur".into(),
            uid: UID,
            real_name: "T".into(),
            device_admin: true,
        },
    )
    .unwrap();
    assert_eq!(
        f.answer(0, "sudo", "timur", PASSWORD),
        refused(Reason::NotCached)
    );
    assert_eq!(
        f.answer(UID, "kde", "timur", PASSWORD),
        refused(Reason::NotCached)
    );
    assert!(f.door.calls().is_empty());
}

#[test]
fn only_the_login_screen_asks_for_a_code() {
    // Even when the server would: the other services never reach it.
    let f = fx(Some(shared()));
    f.signed_in_before("timur", UID, PASSWORD, 1);
    f.params(v1()).login(challenge("totp"));
    for service in ["kde", "sudo", "polkit-1", "login"] {
        assert!(matches!(
            f.auth(0, service, "timur", PASSWORD),
            Auth::Done(Answer::Ok, None)
        ));
    }
    assert!(matches!(
        f.auth(0, "plasmalogin", "timur", PASSWORD),
        Auth::Code(_)
    ));
}

// ── account ─────────────────────────────────────────────────────────────────

#[test]
fn text_logins_are_for_device_admins() {
    let f = fx(Some(shared()));
    f.signed_in_before("timur", UID, PASSWORD, 1);
    f.signed_in_before("ada", 21_002, PASSWORD, 1);
    assert_eq!(
        f.svc.account(0, "login", "timur"),
        refused(Reason::TextLogin)
    );
    assert_eq!(f.svc.account(0, "login", "ada"), Answer::Ok);
    for service in ["plasmalogin", "kde", "sudo", "polkit-1", "crond"] {
        assert_eq!(f.svc.account(0, service, "timur"), Answer::Ok, "{service}");
    }
}

#[test]
fn account_needs_a_cache_entry_and_the_devices_say() {
    let f = fx(Some(assigned_to("timur")));
    assert_eq!(
        f.svc.account(0, "sudo", "timur"),
        refused(Reason::NotCached)
    );
    f.signed_in_before("timur", UID, PASSWORD, 1);
    assert_eq!(f.svc.account(0, "sudo", "timur"), Answer::Ok);
    f.signed_in_before("bob", 21_002, PASSWORD, 1);
    assert_eq!(f.svc.account(0, "sudo", "bob"), refused(Reason::NotAllowed));
    assert_eq!(
        f.svc.account(0, "sudo", "Bob"),
        refused(Reason::UnknownUser)
    );
}

// ── what the server is sent ─────────────────────────────────────────────────

#[test]
fn the_cache_is_never_sent_to_the_server() {
    use crate::fake::FakeServer;
    use crate::login::door::Devices;
    use ed25519_dalek::SigningKey;

    // The real door, against a fake website-devices, for a person who has a
    // cache entry already.
    let f = fx(Some(shared()));
    f.signed_in_before("timur", UID, PASSWORD, 1);
    let old = f.entry("timur").unwrap();
    let server = FakeServer::start(vec![
        (200, format!(r#"{{"kdfVersion":1,"authSalt":"{SALT}"}}"#)),
        (
            200,
            r#"{"step":"code","challenge":"ch_1","factor":"totp","expiresAt":1800000600}"#.into(),
        ),
        (
            200,
            json!({
                "step": "signed_in",
                "session": { "token": "tok_os", "expiresAt": NOW + 90 * DAY },
                "person": { "username": "timur", "handle": "timur.suez", "name": "Timur Inal",
                            "uid": UID, "gid": UID, "deviceAdmin": false, "kdfVersion": 1,
                            "emailIsPlaceholder": false },
                "offlineDays": 14
            })
            .to_string(),
        ),
    ]);
    let door: Arc<dyn Door> = Arc::new(Devices::new(
        &server.base,
        "dev_1",
        SigningKey::from_bytes(&[3; 32]),
    ));
    let mut f = f;
    f.svc.door = Box::new(move || Some(Arc::clone(&door)));
    let Auth::Code(pending) = f.auth(0, "plasmalogin", "timur", PASSWORD) else {
        panic!()
    };
    assert_eq!(f.svc.code(pending, "123456").0, Answer::Ok);
    let new = f.entry("timur").unwrap();

    let sent: Vec<u8> = server.requests().into_iter().flat_map(|r| r.body).collect();
    let sent = String::from_utf8(sent).unwrap();
    for v in [&old.verifier, &new.verifier] {
        assert!(!sent.contains(&v.hash), "a verifier was sent");
        assert!(!sent.contains(&v.salt), "a verifier's salt was sent");
    }
    // What was sent is the authSecret, and never the password.
    assert!(sent.contains(SECRET));
    assert!(!sent.contains(PASSWORD));
}
