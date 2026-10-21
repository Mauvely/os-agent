//! The sign-in broker (brief 22, S2). It holds this computer's `os` session,
//! linked once per local user, and answers Mauvely apps and the browsers on
//! `$XDG_RUNTIME_DIR/mauvely/broker` with sessions the server mints from it.
//! `docs/broker.md` has the protocol and the threat model.
//!
//! | Module | Holds |
//! |---|---|
//! | `caller` | Who may ask for what: pure |
//! | `peer` | Finding the caller: `SO_PEERCRED`, `SO_PEERPIDFD`, `/proc` |
//! | `wire` | Suite's framing, the requests and the answers |
//! | `accounts` | website-main: the device link, the mints, `/api/auth/me` |
//! | `seal` | The `os` session at rest, through `systemd-creds --user` |
//! | `socket` | The socket, its directory, and one thread per caller |

pub mod accounts;
pub mod caller;
pub mod peer;
pub mod seal;
pub mod socket;
pub mod wire;

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use accounts::{Accounts, Alive, Minted, Poll};
use caller::{Ask, Caller, Grant};
use seal::{OsSession, Store};
use wire::{Granted, Reason, Request};

use crate::Error;

/// What the broker needs from the graphical session. The offer and the code
/// are windows where `kdialog` can show them and notifications where it
/// cannot; either way each replaces the one before.
pub trait Desktop: Send + Sync {
    /// "Sign in to Mauvely", with a Sign in button.
    fn offer(&self) -> Result<(), Error>;
    /// The code to type into the link page.
    fn show_code(&self, code: &str) -> Result<(), Error>;
    /// "Signed in to Mauvely as <email>", so a wrong account is seen.
    fn signed_in(&self, email: &str) -> Result<(), Error>;
    /// Takes the code away once it is no use.
    fn withdraw(&self);
    /// Opens `url` in the person's default browser.
    fn open(&self, url: &str) -> Result<(), Error>;
}

/// Time, so tests need not wait for it.
pub trait Clock: Send + Sync {
    /// Unix seconds.
    fn now(&self) -> u64;
    fn sleep(&self, d: Duration);
}

pub struct RealClock;

impl Clock for RealClock {
    fn now(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    fn sleep(&self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// A session minted for one caller, kept to answer it again.
struct Cached {
    session: Minted,
    minted_at: u64,
}

/// A minted session is answered from the cache until a tenth of its life,
/// or five minutes, before it expires, whichever is sooner. Then it is
/// minted again.
fn stale_after(minted_at: u64, expires_at: u64) -> u64 {
    let margin = (expires_at.saturating_sub(minted_at) / 10).min(300);
    expires_at.saturating_sub(margin)
}

type Slot = Arc<Mutex<Option<Cached>>>;

pub struct Broker {
    accounts: Accounts,
    store: Store,
    hostname: String,
    desktop: Box<dyn Desktop>,
    clock: Box<dyn Clock>,
    /// The `os` session. Its lock also covers the file, so a link and a
    /// sign-out never interleave there.
    os: Mutex<Option<OsSession>>,
    /// One slot per app key and per browser. A caller holds its slot while
    /// it mints, so two callers asking at once get one mint.
    cache: Mutex<HashMap<String, Slot>>,
    linking: AtomicBool,
    offer_wanted: AtomicBool,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    // A thread that panicked holding it left nothing half-written that
    // matters more than staying up.
    m.lock().unwrap_or_else(|e| e.into_inner())
}

impl Broker {
    pub fn new(
        accounts: Accounts,
        store: Store,
        hostname: String,
        desktop: Box<dyn Desktop>,
        clock: Box<dyn Clock>,
    ) -> Self {
        Broker {
            accounts,
            store,
            hostname,
            desktop,
            clock,
            os: Mutex::new(None),
            cache: Mutex::new(HashMap::new()),
            linking: AtomicBool::new(false),
            offer_wanted: AtomicBool::new(false),
        }
    }

    /// Reads the stored `os` session. With none, or one that has expired, a
    /// link is to be offered. A file that does not unseal is kept, in case
    /// that is passing, and a link is offered all the same.
    pub fn load(&self) {
        let mut os = lock(&self.os);
        match self.store.load() {
            // Linked to another accounts service: /etc/mauvely/server
            // changed. Its token is not sent to this one.
            Ok(Some(s)) if s.origin != self.accounts.origin() => {
                eprintln!(
                    "mauvely-session: broker: this computer's sign-in is for {:?}, not {:?}",
                    s.origin,
                    self.accounts.origin()
                );
                if let Err(e) = self.store.forget() {
                    eprintln!("mauvely-session: broker: {e}");
                }
            }
            Ok(Some(s)) if s.expires_at > self.clock.now() => {
                eprintln!("mauvely-session: broker: this computer is signed in");
                *os = Some(s);
                return;
            }
            Ok(Some(_)) => {
                eprintln!("mauvely-session: broker: this computer's sign-in has expired");
                if let Err(e) = self.store.forget() {
                    eprintln!("mauvely-session: broker: {e}");
                }
            }
            Ok(None) => {}
            Err(e) => eprintln!("mauvely-session: broker: {e}"),
        }
        self.offer_wanted.store(true, Ordering::SeqCst);
    }

    /// Shows the link offer if one is due and nothing has made it moot.
    pub fn offer_if_wanted(&self) {
        if self.linking.load(Ordering::SeqCst) || lock(&self.os).is_some() {
            return;
        }
        if !self.offer_wanted.swap(false, Ordering::SeqCst) {
            return;
        }
        if let Err(e) = self.desktop.offer() {
            eprintln!("mauvely-session: broker: could not offer to sign in: {e}");
            self.offer_wanted.store(true, Ordering::SeqCst);
        }
    }

    /// One exchange: the caller's line in, the answer line out. Every
    /// answer and refusal is logged, and no token ever is.
    pub fn answer(&self, caller: &Caller, line: &[u8]) -> Vec<u8> {
        let who = caller.describe();
        let request = match wire::parse(line) {
            Ok(r) => r,
            Err(reason) => {
                eprintln!("mauvely-session: broker: refused {who}: {}", reason.code());
                return wire::refused(&reason);
            }
        };
        let (ask, label, what) = match &request {
            Request::Token { client, label } => (
                Ask::Token(client),
                label.as_deref(),
                // The caller's own text: escaped, and cut to the server's
                // limit on a client name.
                format!(
                    "a session for {:?}",
                    client.chars().take(40).collect::<String>()
                ),
            ),
            Request::Browser => (Ask::Browser, None, "a browser session".into()),
        };
        let grant = match caller::authorise(caller, ask) {
            Ok(g) => g,
            Err(refusal) => {
                eprintln!(
                    "mauvely-session: broker: refused {what} to {who}: {}",
                    refusal.why()
                );
                return wire::refused(&match refusal {
                    caller::Refusal::UnknownClient => Reason::UnknownClient,
                    _ => Reason::Forbidden,
                });
            }
        };
        match self.session_for(&grant, label) {
            Ok((session, how)) => {
                eprintln!("mauvely-session: broker: {what} to {who}: {how}");
                wire::granted(&Granted {
                    token: &session.token,
                    expires_at: session.expires_at,
                    email: &session.email,
                    origin: self.accounts.origin(),
                })
            }
            Err(reason) => {
                eprintln!(
                    "mauvely-session: broker: {what} to {who}: not answered, {}",
                    reason.code()
                );
                wire::refused(&reason)
            }
        }
    }

    /// A session for `grant`: the cached one while it is fresh and the server
    /// still takes it, or a new mint.
    fn session_for(
        &self,
        grant: &Grant,
        label: Option<&str>,
    ) -> Result<(Minted, &'static str), Reason> {
        let os = self.current().ok_or(Reason::SignedOut)?;
        let slot = self.slot(grant);
        let mut cached = lock(&slot);
        if let Some(c) = cached.as_ref() {
            // "Could not tell" keeps it: it has not expired, and a caller
            // that cannot reach the server could not use a new one either.
            if self.clock.now() < stale_after(c.minted_at, c.session.expires_at)
                && self.accounts.alive(&c.session.token) != Alive::No
            {
                return Ok((c.session.clone(), "from the cache"));
            }
        }
        *cached = None;
        let minted = match grant {
            Grant::App(key) => self.accounts.mint_app(&os.token, key, label),
            Grant::Browser(id) => {
                let label = browser_label(id, &self.hostname);
                self.accounts.mint_browser(&os.token, label.as_deref())
            }
        };
        match minted {
            Ok(session) => {
                *cached = Some(Cached {
                    session: session.clone(),
                    minted_at: self.clock.now(),
                });
                Ok((session, "minted"))
            }
            Err(Reason::SignedOut) => {
                drop(cached);
                self.sign_out(&os.token, "the server no longer takes it");
                Err(Reason::SignedOut)
            }
            Err(reason) => Err(reason),
        }
    }

    /// The `os` session while it has not expired.
    fn current(&self) -> Option<OsSession> {
        let session = lock(&self.os).clone()?;
        if session.expires_at > self.clock.now() {
            return Some(session);
        }
        self.sign_out(&session.token, "it has expired");
        None
    }

    fn slot(&self, grant: &Grant) -> Slot {
        let key = match grant {
            Grant::App(key) => format!("app:{key}"),
            Grant::Browser(id) => format!("browser:{id}"),
        };
        Arc::clone(lock(&self.cache).entry(key).or_default())
    }

    /// Forgets the `os` session `token`, and what was minted from it, then
    /// offers to link again. Does nothing when a link has already replaced
    /// it.
    fn sign_out(&self, token: &str, why: &str) {
        {
            let mut os = lock(&self.os);
            if os.as_ref().map(|s| s.token.as_str()) != Some(token) {
                return;
            }
            *os = None;
            if let Err(e) = self.store.forget() {
                eprintln!("mauvely-session: broker: {e}");
            }
        }
        lock(&self.cache).clear();
        eprintln!("mauvely-session: broker: this computer's sign-in has ended: {why}");
        self.offer_wanted.store(true, Ordering::SeqCst);
        self.offer_if_wanted();
    }

    /// Links this computer: a device link as client `os`, approved by the
    /// person in their browser. Blocks until it is approved, declined or
    /// expired. One at a time; a second call while one runs, or once this
    /// computer is signed in, returns at once.
    pub fn link(&self) {
        // An offer clicked after a link already succeeded.
        if lock(&self.os).is_some() {
            return;
        }
        if self.linking.swap(true, Ordering::SeqCst) {
            return;
        }
        let result = self.run_link();
        self.linking.store(false, Ordering::SeqCst);
        match result {
            Ok(email) => {
                eprintln!("mauvely-session: broker: this computer is signed in");
                // Which account, so one that is not the person's is seen at
                // once.
                if let Err(e) = self.desktop.signed_in(&email) {
                    eprintln!("mauvely-session: broker: {e}");
                }
            }
            Err(Link::NotStarted(e)) => {
                // The person asked and nothing happened, so ask again.
                eprintln!("mauvely-session: broker: could not start signing in: {e}");
                self.offer_wanted.store(true, Ordering::SeqCst);
                self.offer_if_wanted();
            }
            Err(Link::Ended(code)) => {
                eprintln!("mauvely-session: broker: signing in ended: {code}");
                self.desktop.withdraw();
            }
        }
    }

    /// The account's address, once linked.
    fn run_link(&self) -> Result<String, Link> {
        let name = match self.hostname.as_str() {
            "" => "Mauvely OS".to_owned(),
            host => format!("Mauvely OS on {host}"),
        };
        let started = self.accounts.start(&name).map_err(Link::NotStarted)?;
        // The code is shown to the person, never put in the page's address.
        self.desktop
            .show_code(&started.user_code)
            .map_err(|e| Link::NotStarted(format!("showing the code: {e}")))?;
        self.desktop
            .open(&started.link)
            .map_err(|e| Link::NotStarted(format!("opening the browser: {e}")))?;
        let deadline = self.clock.now() + started.expires_in;
        let mut interval = started.interval;
        loop {
            self.clock.sleep(Duration::from_secs(interval));
            if self.clock.now() > deadline {
                return Err(Link::Ended("expired_token".into()));
            }
            match self.accounts.poll(&started.device_code) {
                Poll::Pending | Poll::Retry => {}
                Poll::SlowDown => interval = interval.max(15),
                Poll::Stop(code) => return Err(Link::Ended(code)),
                Poll::Done(minted) => {
                    let email = minted.email.clone();
                    self.adopt(OsSession::new(minted, self.accounts.origin()));
                    return Ok(email);
                }
            }
        }
    }

    /// Takes a new `os` session. One that cannot be sealed is still used
    /// until this login ends: the person has just approved it.
    fn adopt(&self, session: OsSession) {
        {
            let mut os = lock(&self.os);
            if let Err(e) = self.store.save(&session) {
                eprintln!("mauvely-session: broker: kept for this login only: {e}");
            }
            *os = Some(session);
        }
        lock(&self.cache).clear();
    }
}

enum Link {
    NotStarted(String),
    Ended(String),
}

/// What the Devices tab calls a browser's session.
fn browser_label(id: &str, hostname: &str) -> Option<String> {
    let name = match id {
        "org.mozilla.firefox" => "Firefox",
        "org.chromium.Chromium" => "Chromium",
        _ => return None,
    };
    (!hostname.is_empty()).then(|| format!("{name} on {hostname}"))
}

#[cfg(test)]
pub mod testing;

#[cfg(test)]
mod tests;
