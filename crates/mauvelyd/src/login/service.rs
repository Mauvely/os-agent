//! What the login service does with each request, over traits for
//! everything outside it, so every rule is tested without root, a TPM, the
//! network or PAM.
//!
//! **`auth`**, in this order:
//! 1. **The caller.** Only uid 0 may ask for the login screen
//!    (`plasmalogin`). Any other uid may ask only about the person whose uid
//!    it is.
//! 2. **The name.** A local account that is not one of ours is `not_mauvely`:
//!    `pam_unix` judges it. A name no Mauvely person could have is
//!    `unknown_user`; one a computer cannot use, `bad_username`.
//! 3. **The device's say** (`desired.people`), before anything is sent: on an
//!    assigned device, only the assigned person and the device admins.
//! 4. **The login screen** checks online: `params`, the KDF (version 1) or
//!    the password itself (0), `login`, then `code` when the server asks.
//!    Only when the server cannot be reached does it try the cache, and only
//!    an entry younger than its `offlineDays`. A refusal is final.
//! 5. **Every other service** (the lock screen, sudo, polkit, text logins)
//!    checks the cache and never the server.
//!
//! **Signed in online:** the person's userdb records, their home, their cache
//! entry, then the `os` session for `mauvely-session`. A version 0 account is
//! upgraded after the answer is sent.
//!
//! **`account`:** the same caller, name and device rules, then a cache entry;
//! text logins (`login`) only for device admins (brief 28).

use std::io::Read;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::LoginPaths;
use super::cache::{self, Entry};
use super::door::{Door, Online, SignedIn, Step};
use super::handoff::{self, HandOff};
use super::kdf::{self, Verifier};
use super::names::{Names, fits_computer, is_username};
use super::people::{self, People};
use super::userdb::{self, Person};
use super::wire::{Answer, Reason, code_info};
use crate::creds::Sealer;

/// The login screen's PAM service: the only one that goes online, and the
/// only one asked for a code.
pub const LOGIN_SCREEN: &str = "plasmalogin";
/// Text consoles.
pub const TEXT_LOGIN: &str = "login";

/// The uids website-devices hands out (`org_uids`). Anything else is not a
/// person's.
pub const UIDS: std::ops::RangeInclusive<u32> = 20_000..=59_999;

/// How long a wrong password against the cache waits before it is answered.
const FAILURE_DELAY: Duration = Duration::from_secs(2);

/// Makes a person's home: os-image's `mauvely-home@.service`.
pub trait Home: Send + Sync {
    fn make(&self, username: &str) -> Result<(), String>;
}

/// `systemctl start mauvely-home@<username>.service`, waited for.
pub struct SystemdHome;

const HOME_TIMEOUT: Duration = Duration::from_secs(20);

pub fn home_argv(username: &str) -> Vec<String> {
    vec![
        "systemctl".into(),
        "start".into(),
        "--no-ask-password".into(),
        format!("mauvely-home@{username}.service"),
    ]
}

impl Home for SystemdHome {
    fn make(&self, username: &str) -> Result<(), String> {
        if !fits_computer(username) {
            return Err(format!("{username:?} is not a username"));
        }
        run_until(&home_argv(username), HOME_TIMEOUT)
    }
}

/// Runs `argv`, and kills it after `limit`. Its stderr's tail is the error.
fn run_until(argv: &[String], limit: Duration) -> Result<(), String> {
    let mut child = Command::new(&argv[0])
        .args(&argv[1..])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{}: {e}", argv[0]))?;
    let deadline = Instant::now() + limit;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{}: no answer in {}s", argv[0], limit.as_secs()));
            }
            Err(e) => return Err(format!("{}: {e}", argv[0])),
        }
    };
    if status.success() {
        return Ok(());
    }
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    let chars: Vec<char> = stderr.trim().chars().collect();
    let tail: String = chars[chars.len().saturating_sub(300)..].iter().collect();
    Err(format!("{}: {status}: {tail}", argv[0]))
}

/// Hands a session to the person's `mauvely-session`: `handoff::write` into
/// `/run/mauvely/login`, in the service.
pub trait HandOver: Send + Sync {
    fn hand_over(&self, uid: u32, session: &HandOff) -> Result<(), crate::Error>;
}

/// The real one, into `paths.handoff`, staged in `paths.staging`.
pub struct RunDir {
    pub dir: std::path::PathBuf,
    pub staging: std::path::PathBuf,
}

impl HandOver for RunDir {
    fn hand_over(&self, uid: u32, session: &HandOff) -> Result<(), crate::Error> {
        handoff::write(&self.dir, &self.staging, uid, uid, session)
    }
}

/// The server, once the agent has loaded the device's key; `None` before.
pub type DoorSlot = Box<dyn Fn() -> Option<Arc<dyn Door>> + Send + Sync>;

pub struct Service {
    pub paths: LoginPaths,
    pub sealer: Box<dyn Sealer>,
    pub names: Box<dyn Names>,
    pub home: Box<dyn Home>,
    pub hand_over: Box<dyn HandOver>,
    pub door: DoorSlot,
    /// Unix seconds.
    pub clock: Box<dyn Fn() -> u64 + Send + Sync>,
    /// Waits before a wrong password is answered; tests do not.
    pub delay: Box<dyn Fn(Duration) + Send + Sync>,
}

/// What an `auth` came to.
pub enum Auth {
    /// Answer, then close; then the upgrade, if there is one.
    Done(Answer, Option<Upgrade>),
    /// Answer `code`, then wait for it.
    Code(Pending),
}

/// A sign-in waiting for its code. Holds the password for the cache and a
/// version 0 upgrade; wiped when dropped.
pub struct Pending {
    pub info: &'static str,
    /// Unix seconds: the challenge's own expiry.
    pub expires_at: u64,
    challenge: Zeroizing<String>,
    username: String,
    password: Zeroizing<String>,
    door: Arc<dyn Door>,
}

/// A version 0 account's move onto Argon2id, after the answer is sent.
pub struct Upgrade {
    door: Arc<dyn Door>,
    username: String,
    token: Zeroizing<String>,
    password: Zeroizing<String>,
}

/// Which way the online check went, for the log.
enum Via {
    Online,
    Offline,
}

impl Service {
    /// `auth`: the password, and at the login screen maybe a code to come.
    pub fn auth(
        &self,
        peer: u32,
        service: &str,
        username: &str,
        password: Zeroizing<String>,
    ) -> Auth {
        let outcome = self.try_auth(peer, service, username, password);
        let who = self.who(username);
        match &outcome {
            Auth::Code(_) => eprintln!("login: {service}: {who}: a code is asked"),
            Auth::Done(Answer::Refused(r), _) => {
                eprintln!(
                    "login: {service}: {who}, uid {peer} asking: refused, {}",
                    r.code()
                )
            }
            Auth::Done(..) => eprintln!("login: {service}: {who}: signed in"),
        }
        outcome
    }

    fn try_auth(
        &self,
        peer: u32,
        service: &str,
        username: &str,
        password: Zeroizing<String>,
    ) -> Auth {
        let done = |r: Reason| Auth::Done(Answer::Refused(r), None);
        if service == LOGIN_SCREEN && peer != 0 {
            return done(Reason::Forbidden);
        }
        if let Err(r) = self.name(peer, username) {
            return done(r);
        }
        let people = match self.allowed(username) {
            Ok(p) => p,
            Err(r) => return done(r),
        };
        if password.is_empty() {
            return done(Reason::Credentials);
        }
        if service == LOGIN_SCREEN {
            self.online(username, password, &people)
        } else {
            Auth::Done(self.cached(username, &password), None)
        }
    }

    /// The person behind a name, for the log: a typed name that is not a
    /// person here may be a password typed in the wrong box.
    fn who(&self, username: &str) -> String {
        if userdb::uid_of(&self.paths.userdb, username).is_some() {
            username.to_owned()
        } else {
            "a name with no account here".into()
        }
    }

    /// Steps 1 and 2: whether this caller may ask about this name, and
    /// whether it is a Mauvely name at all.
    fn name(&self, peer: u32, username: &str) -> Result<(), Reason> {
        let ours = userdb::uid_of(&self.paths.userdb, username);
        if let Some(uid) = self.names.user(username)
            && ours != Some(uid)
        {
            return Err(Reason::NotMauvely);
        }
        if !is_username(username) {
            return Err(Reason::UnknownUser);
        }
        if peer != 0 {
            match ours {
                None => return Err(Reason::UnknownUser),
                Some(uid) if uid != peer => return Err(Reason::Forbidden),
                Some(_) => {}
            }
        }
        if !fits_computer(username) {
            return Err(Reason::BadUsername);
        }
        Ok(())
    }

    /// Step 3: the device's say. Someone it no longer allows loses their
    /// cache entry here too.
    fn allowed(&self, username: &str) -> Result<People, Reason> {
        let people = people::load(&self.paths).ok_or(Reason::NotReady)?;
        if !people.allows(username) {
            self.forget(username, "this computer no longer allows them");
            return Err(Reason::NotAllowed);
        }
        Ok(people)
    }

    fn forget(&self, username: &str, why: &str) {
        match cache::remove(&self.paths.cache, username) {
            Ok(true) => eprintln!("login: {username}: offline sign-in removed: {why}"),
            Ok(false) => {}
            Err(e) => eprintln!("login: {e}"),
        }
    }

    /// Step 5: the cache, and nothing else.
    fn cached(&self, username: &str, password: &str) -> Answer {
        let Some(entry) = cache::read(&self.paths.cache, &*self.sealer, username) else {
            return Answer::Refused(Reason::NotCached);
        };
        match entry.verifier.check(password.as_bytes()) {
            Some(true) => Answer::Ok,
            Some(false) => {
                (self.delay)(FAILURE_DELAY);
                Answer::Refused(Reason::Credentials)
            }
            None => Answer::Refused(Reason::Busy),
        }
    }

    /// Step 4: the login screen.
    fn online(&self, username: &str, password: Zeroizing<String>, people: &People) -> Auth {
        let done = |a: Answer| Auth::Done(a, None);
        let Some(door) = (self.door)() else {
            return done(Answer::Refused(Reason::NotReady));
        };
        let params = match door.params(username) {
            Online::Answer(p) => p,
            Online::Refused(r) => return done(self.refused(username, &password, r)),
            Online::Unreachable(why) => {
                return done(self.offline(username, &password, people, &why));
            }
        };
        let secret = match (params.kdf_version, params.auth_salt.as_deref()) {
            (1, Some(salt)) => match kdf::auth_secret(password.as_bytes(), salt, kdf::SERVER) {
                Some(s) => s,
                None => return done(Answer::Refused(Reason::Unavailable)),
            },
            _ => password.clone(),
        };
        match door.login(username, params.kdf_version, &secret) {
            Online::Answer(Step::Code {
                challenge,
                factor,
                expires_at,
            }) => Auth::Code(Pending {
                info: code_info(&factor),
                expires_at,
                challenge,
                username: username.to_owned(),
                password,
                door,
            }),
            Online::Answer(Step::SignedIn(s)) => {
                self.signed_in(username, password, s, people, door)
            }
            Online::Refused(r) => done(self.refused(username, &password, r)),
            Online::Unreachable(why) => done(self.offline(username, &password, people, &why)),
        }
    }

    /// The code, for a sign-in waiting on it. There is no cache to fall back
    /// to here: the person tries again, and offline gets the cache then.
    pub fn code(&self, pending: Pending, code: &str) -> (Answer, Option<Upgrade>) {
        let username = pending.username.clone();
        let result = self.try_code(pending, code);
        let who = self.who(&username);
        match &result.0 {
            Answer::Refused(r) => eprintln!(
                "login: {LOGIN_SCREEN}: {who}: the code: refused, {}",
                r.code()
            ),
            _ => eprintln!("login: {LOGIN_SCREEN}: {who}: signed in"),
        }
        result
    }

    fn try_code(&self, pending: Pending, code: &str) -> (Answer, Option<Upgrade>) {
        let refused = |r| (Answer::Refused(r), None);
        if code.is_empty() {
            return refused(Reason::Code);
        }
        if (self.clock)() > pending.expires_at {
            return refused(Reason::Expired);
        }
        let Some(people) = people::load(&self.paths) else {
            return refused(Reason::NotReady);
        };
        let Pending {
            challenge,
            username,
            password,
            door,
            ..
        } = pending;
        match door.code(&challenge, code) {
            Online::Answer(Step::SignedIn(s)) => {
                match self.signed_in(&username, password, s, &people, door) {
                    Auth::Done(a, u) => (a, u),
                    Auth::Code(_) => refused(Reason::Unavailable),
                }
            }
            // A second code is not in the contract.
            Online::Answer(Step::Code { .. }) => refused(Reason::Unavailable),
            Online::Refused(r) => (self.refused(&username, &password, r), None),
            Online::Unreachable(why) => {
                eprintln!("login: the server can't be reached at the code: {why}");
                refused(Reason::Unreachable)
            }
        }
    }

    /// The server refused. A refusal is never answered from the cache; some
    /// make the cache entry stale, and it goes.
    fn refused(&self, username: &str, password: &str, r: Reason) -> Answer {
        match r {
            // The password the cache knows is no longer the account's: it was
            // changed, or the account is gone. Not for any wrong password, or
            // a stranger typing one could wipe a person's offline sign-in.
            Reason::Credentials => {
                if let Some(entry) = cache::read(&self.paths.cache, &*self.sealer, username)
                    && entry.verifier.check(password.as_bytes()) == Some(true)
                {
                    self.forget(username, "the server no longer takes that password");
                }
            }
            Reason::NotMember | Reason::Inactive | Reason::SsoRequired | Reason::NotAllowed => {
                self.forget(username, r.code());
            }
            _ => {}
        }
        Answer::Refused(r)
    }

    /// The server can't be reached: the cache, at the login screen only.
    fn offline(&self, username: &str, password: &str, people: &People, why: &str) -> Answer {
        eprintln!("login: the server can't be reached ({why}); trying this computer's sign-in");
        let Some(entry) = cache::read(&self.paths.cache, &*self.sealer, username) else {
            return Answer::Refused(Reason::Offline);
        };
        if !entry.fresh((self.clock)(), Some(people.offline_days)) {
            return Answer::Refused(Reason::Offline);
        }
        match entry.verifier.check(password.as_bytes()) {
            Some(true) => {}
            Some(false) => return Answer::Refused(Reason::Credentials),
            None => return Answer::Refused(Reason::Busy),
        }
        let person = Person {
            username: username.to_owned(),
            uid: entry.uid,
            real_name: entry.name.clone(),
            // Never more than the check-in says now.
            device_admin: entry.device_admin && people.is_admin(username),
        };
        match self.settle(&person, Via::Offline) {
            Ok(()) => Answer::Ok,
            Err(r) => Answer::Refused(r),
        }
    }

    /// Signed in online: records, home, cache, then the hand-off.
    fn signed_in(
        &self,
        username: &str,
        password: Zeroizing<String>,
        s: SignedIn,
        people: &People,
        door: Arc<dyn Door>,
    ) -> Auth {
        let done = |r| Auth::Done(Answer::Refused(r), None);
        let p = &s.person;
        // The person the server signed in must be the one who typed, in this
        // organisation, on a uid of its range: anything else is not used.
        if p.username != username
            || p.handle != format!("{username}.{}", people.org.slug)
            || !UIDS.contains(&p.uid)
            || p.gid != p.uid
        {
            eprintln!(
                "login: the server signed in someone other than who typed, or on uid {}",
                p.uid
            );
            return done(Reason::Unavailable);
        }
        let person = Person {
            username: username.to_owned(),
            uid: p.uid,
            real_name: p.name.clone(),
            device_admin: p.device_admin,
        };
        if let Err(r) = self.settle(&person, Via::Online) {
            return done(r);
        }
        let Some(verifier) = Verifier::new(password.as_bytes()) else {
            return done(Reason::Busy);
        };
        let entry = Entry {
            username: username.to_owned(),
            handle: p.handle.clone(),
            uid: p.uid,
            name: p.name.clone(),
            device_admin: p.device_admin,
            offline_days: s.offline_days,
            signed_in_at: (self.clock)(),
            verifier,
        };
        if let Err(e) = cache::write(&self.paths.cache, &*self.sealer, &entry) {
            eprintln!("login: {username}: the offline sign-in could not be kept: {e}");
            return done(Reason::Internal);
        }
        match door.accounts() {
            Some(origin) => {
                let h = HandOff {
                    v: 1,
                    token: &s.session.token,
                    expires_at: s.session.expires_at,
                    origin,
                    handle: &p.handle,
                };
                if let Err(e) = self.hand_over.hand_over(p.uid, &h) {
                    eprintln!("login: {username}: the session could not be handed over: {e}");
                }
            }
            None => eprintln!(
                "login: {username}: no accounts service is known, so no session is handed over"
            ),
        }
        let upgrade = (p.kdf_version == 0).then(|| Upgrade {
            door,
            username: username.to_owned(),
            token: Zeroizing::new(s.session.token.clone()),
            password,
        });
        Auth::Done(Answer::Ok, upgrade)
    }

    /// The person's records and home. A name or uid that is somebody else's on
    /// this machine is never taken over.
    fn settle(&self, person: &Person, via: Via) -> Result<(), Reason> {
        let dir = &self.paths.userdb;
        let (name, uid) = (person.username.as_str(), person.uid);
        // Renamed: the same uid had another name here. Its records and its
        // cache go; its home stays where it was.
        if let Some(old) = userdb::name_of(dir, uid)
            && old != name
        {
            eprintln!("login: uid {uid} was {old} here and is now {name}");
            if let Err(e) = userdb::remove_person(dir, &old) {
                eprintln!("login: {e}");
                return Err(Reason::Internal);
            }
            self.forget(&old, "renamed");
        }
        let taken = |found: Option<String>| found.is_some_and(|n| n != name);
        let other = |found: Option<u32>| found.is_some_and(|u| u != uid);
        if taken(self.names.uid(uid))
            || taken(self.names.gid(uid))
            || other(self.names.user(name))
            || other(self.names.group(name))
        {
            eprintln!("login: {name} or uid {uid} already belongs to another account here");
            return Err(Reason::Internal);
        }
        if let Err(e) = userdb::write(dir, person) {
            eprintln!("login: {name}: {e}");
            return Err(Reason::Internal);
        }
        if let Err(e) = self.home.make(name) {
            eprintln!("login: {name}: the home could not be made: {e}");
            return Err(Reason::Internal);
        }
        if let Via::Offline = via {
            eprintln!("login: {name}: signed in offline");
        }
        Ok(())
    }

    /// `account`: may this person use this service now.
    pub fn account(&self, peer: u32, service: &str, username: &str) -> Answer {
        let answer = self.try_account(peer, service, username);
        if let Answer::Refused(r) = &answer
            && *r != Reason::NotMauvely
        {
            eprintln!(
                "login: {service}: account for {}: refused, {}",
                self.who(username),
                r.code()
            );
        }
        answer
    }

    fn try_account(&self, peer: u32, service: &str, username: &str) -> Answer {
        if service == LOGIN_SCREEN && peer != 0 {
            return Answer::Refused(Reason::Forbidden);
        }
        if let Err(r) = self.name(peer, username) {
            return Answer::Refused(r);
        }
        let people = match self.allowed(username) {
            Ok(p) => p,
            Err(r) => return Answer::Refused(r),
        };
        if !cache::path(&self.paths.cache, username).exists() {
            return Answer::Refused(Reason::NotCached);
        }
        if service == TEXT_LOGIN && !people.is_admin(username) {
            return Answer::Refused(Reason::TextLogin);
        }
        Answer::Ok
    }

    /// A version 0 account's upgrade: a fresh salt, the secret derived from
    /// the password, `POST /api/auth/kdf` with the new session. Only logged.
    pub fn upgrade(&self, u: Upgrade) {
        let salt = kdf::new_salt();
        let Some(secret) = kdf::auth_secret(u.password.as_bytes(), &salt, kdf::SERVER) else {
            eprintln!("login: {}: account upgrade: could not derive", u.username);
            return;
        };
        match u.door.upgrade(&u.token, &u.password, &salt, &secret) {
            Ok(()) => eprintln!(
                "login: {}: account upgraded to the current sign-in",
                u.username
            ),
            Err(e) => eprintln!("login: {}: account upgrade failed: {e}", u.username),
        }
    }
}

#[cfg(test)]
pub(crate) mod tests;
