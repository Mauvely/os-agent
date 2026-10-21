//! Test doubles for the broker: a `tiny_http` accounts server answering
//! canned replies, a desktop that counts, a clock that moves only when told.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::JoinHandle;
use std::time::Duration;

use super::accounts::Accounts;
use super::caller::{Caller, Sandbox};
use super::seal::tests::{FakeSeal, temp_dir};
use super::seal::{OsSession, Store};
use super::{Broker, Clock, Desktop};
use crate::Error;

/// The fake clock's start.
pub const NOW: u64 = 1_800_000_000;
pub const OS_TOKEN: &str = "tok_os";

pub fn system_app(id: &str) -> Caller {
    Caller::Sandbox(Sandbox {
        app: id.into(),
        app_path: format!("/var/lib/flatpak/app/{id}/x86_64/stable/c0ffee/files"),
    })
}

pub fn compose() -> Caller {
    system_app("com.mauvely.compose")
}

pub fn firefox() -> Caller {
    system_app("org.mozilla.firefox")
}

#[derive(Default)]
pub struct FakeDesktop {
    pub offers: AtomicUsize,
    pub opened: Mutex<Vec<String>>,
    pub open_fails: AtomicBool,
}

impl Desktop for Arc<FakeDesktop> {
    fn offer(&self) -> Result<(), Error> {
        self.offers.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }

    fn open(&self, url: &str) -> Result<(), Error> {
        if self.open_fails.load(Ordering::SeqCst) {
            return Err("no browser".into());
        }
        self.opened.lock().unwrap().push(url.into());
        Ok(())
    }
}

pub struct FakeClock(pub AtomicU64);

impl FakeClock {
    pub fn advance(&self, secs: u64) {
        self.0.fetch_add(secs, Ordering::SeqCst);
    }
}

impl Clock for Arc<FakeClock> {
    fn now(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }

    fn sleep(&self, d: Duration) {
        self.advance(d.as_secs());
    }
}

/// One request the fake server received.
#[derive(Debug)]
pub struct Captured {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Captured {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn json(&self) -> serde_json::Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    /// `POST /path`, for comparing a whole sequence at a glance.
    pub fn line(&self) -> String {
        format!("{} {}", self.method, self.url)
    }
}

/// Answers each request with the next canned reply, then stops. `{BASE}`
/// in a reply is its own origin.
pub struct FakeServer {
    pub base: String,
    rx: mpsc::Receiver<Captured>,
    thread: Option<JoinHandle<()>>,
}

impl FakeServer {
    pub fn start(replies: Vec<(u16, String)>) -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let base = format!("http://127.0.0.1:{port}");
        let replies: Vec<(u16, String)> = replies
            .into_iter()
            .map(|(status, body)| (status, body.replace("{BASE}", &base)))
            .collect();
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            for (status, body) in replies {
                let Ok(Some(mut req)) = server.recv_timeout(Duration::from_secs(10)) else {
                    return;
                };
                let mut bytes = Vec::new();
                req.as_reader().read_to_end(&mut bytes).unwrap();
                let _ = tx.send(Captured {
                    method: req.method().as_str().to_owned(),
                    url: req.url().to_owned(),
                    headers: req
                        .headers()
                        .iter()
                        .map(|h| (h.field.as_str().as_str().to_owned(), h.value.to_string()))
                        .collect(),
                    body: bytes,
                });
                let resp = tiny_http::Response::from_string(body)
                    .with_status_code(status)
                    .with_header(
                        "Content-Type: application/json"
                            .parse::<tiny_http::Header>()
                            .unwrap(),
                    );
                let _ = req.respond(resp);
            }
        });
        FakeServer {
            base,
            rx,
            thread: Some(thread),
        }
    }

    /// Everything received. Waits for the server to answer all its replies.
    pub fn requests(mut self) -> Vec<Captured> {
        drop(self.thread.take().map(JoinHandle::join));
        self.rx.try_iter().collect()
    }
}

pub struct Fixture {
    pub broker: Arc<Broker>,
    pub desktop: Arc<FakeDesktop>,
    pub clock: Arc<FakeClock>,
    pub store: PathBuf,
    pub base: String,
    server: Option<FakeServer>,
    dir: PathBuf,
}

impl Fixture {
    /// Nothing stored: signed out. `load` has run.
    pub fn new(replies: Vec<(u16, String)>) -> Self {
        Self::with(replies, None)
    }

    /// `tok_os` stored, a day from expiring. `load` has run.
    pub fn signed_in(replies: Vec<(u16, String)>) -> Self {
        Self::with(
            replies,
            Some(OsSession {
                token: OS_TOKEN.into(),
                expires_at: NOW + 86_400,
                email: "ada@example.com".into(),
            }),
        )
    }

    pub fn with(replies: Vec<(u16, String)>, stored: Option<OsSession>) -> Self {
        let server = FakeServer::start(replies);
        let dir = temp_dir("broker");
        let store = dir.join("mauvely/os.cred");
        if let Some(s) = &stored {
            Store::new(store.clone(), Box::new(FakeSeal))
                .save(s)
                .unwrap();
        }
        let desktop = Arc::new(FakeDesktop::default());
        let clock = Arc::new(FakeClock(AtomicU64::new(NOW)));
        let broker = Arc::new(Broker::new(
            Accounts::new(&server.base),
            Store::new(store.clone(), Box::new(FakeSeal)),
            "testhost".into(),
            Box::new(Arc::clone(&desktop)),
            Box::new(Arc::clone(&clock)),
        ));
        broker.load();
        Fixture {
            broker,
            desktop,
            clock,
            store,
            base: server.base.clone(),
            server: Some(server),
            dir,
        }
    }

    /// A 200 from a mint or a claim: `token`, expiring `lifetime` seconds
    /// from the fake clock's start.
    pub fn minted(token: &str, lifetime: u64) -> String {
        format!(
            r#"{{"token":"{token}","expiresAt":{},"user":{{"id":"usr_1","email":"ada@example.com","name":"Ada"}},"plan":"pro"}}"#,
            NOW + lifetime
        )
    }

    pub fn offers(&self) -> usize {
        self.desktop.offers.load(Ordering::SeqCst)
    }

    /// Asks as `caller`, and returns the answer parsed.
    pub fn ask(&self, caller: &Caller, line: &str) -> serde_json::Value {
        let reply = self.broker.answer(caller, line.as_bytes());
        assert_eq!(reply.last(), Some(&b'\n'));
        serde_json::from_slice(&reply).unwrap()
    }

    /// What the fake server received. Waits for it to have answered all its
    /// replies.
    pub fn requests(&mut self) -> Vec<Captured> {
        self.server
            .take()
            .map(FakeServer::requests)
            .unwrap_or_default()
    }

    /// The stored session, unsealed.
    pub fn stored(&self) -> Option<OsSession> {
        Store::new(self.store.clone(), Box::new(FakeSeal))
            .load()
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}
