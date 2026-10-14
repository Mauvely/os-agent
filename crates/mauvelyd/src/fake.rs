//! Test doubles: flatpak, bootc and systemd-creds without root, a TPM or the
//! tools, a throwaway directory, and a fake HTTP server.

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::mpsc;
use std::thread::JoinHandle;
use std::time::Duration;

use crate::Error;
use crate::bootc::{self, Bootc};
use crate::creds::Creds;
use crate::flatpak::{App, Flatpak, Remote};

pub fn app(id: &str, remote: &str) -> App {
    App {
        id: id.into(),
        branch: "stable".into(),
        remote: remote.into(),
    }
}

fn fail(what: String) -> Error {
    Error::Command {
        program: "flatpak".into(),
        detail: what,
    }
}

#[derive(Default)]
struct FlatpakState {
    system: Vec<App>,
    user: Vec<App>,
    remotes: Vec<Remote>,
    failing: Vec<String>,
    log: Vec<String>,
}

/// Behaves like the real CLI where reconcile depends on it: installs need the
/// remote, uninstalls need the app, and a remote with apps cannot be deleted.
#[derive(Default)]
pub struct FakeFlatpak(RefCell<FlatpakState>);

impl FakeFlatpak {
    pub fn add_system(&self, a: App) {
        self.0.borrow_mut().system.push(a);
    }
    pub fn add_user(&self, a: App) {
        self.0.borrow_mut().user.push(a);
    }
    pub fn add_remote(&self, name: &str, url: &str) {
        self.0.borrow_mut().remotes.push(Remote {
            name: name.into(),
            url: url.into(),
        });
    }
    pub fn fail_install(&self, id: &str) {
        self.0.borrow_mut().failing.push(id.into());
    }
    pub fn log(&self) -> Vec<String> {
        self.0.borrow().log.clone()
    }
    pub fn clear_log(&self) {
        self.0.borrow_mut().log.clear();
    }
    pub fn system_has(&self, id: &str) -> bool {
        self.0.borrow().system.iter().any(|a| a.id == id)
    }
    pub fn user_has(&self, id: &str) -> bool {
        self.0.borrow().user.iter().any(|a| a.id == id)
    }
    pub fn remote_names(&self) -> Vec<String> {
        self.0
            .borrow()
            .remotes
            .iter()
            .map(|r| r.name.clone())
            .collect()
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl Flatpak for FakeFlatpak {
    fn installed(&self) -> Result<Vec<App>, Error> {
        Ok(self.0.borrow().system.clone())
    }

    fn remotes(&self) -> Result<Vec<Remote>, Error> {
        Ok(self.0.borrow().remotes.clone())
    }

    fn remote_add(&self, name: &str, url: &str, gpg_key: &[u8]) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        s.log
            .push(format!("remote-add {name} {url} key={}", hex(gpg_key)));
        if !s.remotes.iter().any(|r| r.name == name) {
            s.remotes.push(Remote {
                name: name.into(),
                url: url.into(),
            });
        }
        Ok(())
    }

    fn remote_modify(&self, name: &str, url: &str, gpg_key: &[u8]) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        s.log
            .push(format!("remote-modify {name} {url} key={}", hex(gpg_key)));
        let r = s
            .remotes
            .iter_mut()
            .find(|r| r.name == name)
            .ok_or_else(|| fail(format!("no remote {name}")))?;
        r.url = url.into();
        Ok(())
    }

    fn remote_delete(&self, name: &str) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        s.log.push(format!("remote-delete {name}"));
        if s.system.iter().any(|a| a.remote == name) {
            return Err(fail(format!("remote {name} has installed refs")));
        }
        s.remotes.retain(|r| r.name != name);
        Ok(())
    }

    fn install(&self, remote: &str, id: &str, branch: &str) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        s.log.push(format!("install {remote} {id}//{branch}"));
        if s.failing.iter().any(|f| f == id) {
            return Err(fail(format!("error: {id} failed to download")));
        }
        if !s.remotes.iter().any(|r| r.name == remote) {
            return Err(fail(format!("error: no remote {remote}")));
        }
        s.system.push(App {
            id: id.into(),
            branch: branch.into(),
            remote: remote.into(),
        });
        Ok(())
    }

    fn uninstall(&self, id: &str, branch: &str) -> Result<(), Error> {
        let mut s = self.0.borrow_mut();
        s.log.push(format!("uninstall {id}//{branch}"));
        let before = s.system.len();
        s.system.retain(|a| !a.is(id, branch));
        if s.system.len() == before {
            return Err(fail(format!("error: {id}//{branch} not installed")));
        }
        Ok(())
    }
}

pub struct FakeBootc {
    status: RefCell<Option<bootc::Status>>,
    switches: RefCell<Vec<String>>,
    upgrades: RefCell<usize>,
}

impl FakeBootc {
    pub fn booted(image: &str) -> Self {
        FakeBootc {
            status: RefCell::new(Some(bootc::Status {
                booted_image: Some(image.into()),
                booted_digest: Some("sha256:0000".into()),
                staged_image: None,
            })),
            switches: RefCell::default(),
            upgrades: RefCell::default(),
        }
    }

    /// `bootc status` fails.
    pub fn broken() -> Self {
        FakeBootc {
            status: RefCell::new(None),
            switches: RefCell::default(),
            upgrades: RefCell::default(),
        }
    }

    pub fn switches(&self) -> Vec<String> {
        self.switches.borrow().clone()
    }

    /// How many times `bootc upgrade` ran. The fake's registry never has a
    /// newer build, so an upgrade stages nothing.
    pub fn upgrades(&self) -> usize {
        *self.upgrades.borrow()
    }
}

impl Bootc for FakeBootc {
    fn status(&self) -> Result<bootc::Status, Error> {
        self.status.borrow().clone().ok_or_else(|| Error::Command {
            program: "bootc".into(),
            detail: "not a bootc host".into(),
        })
    }

    fn switch(&self, image: &str) -> Result<(), Error> {
        self.switches.borrow_mut().push(image.into());
        if let Some(s) = self.status.borrow_mut().as_mut() {
            s.staged_image = Some(image.into());
        }
        Ok(())
    }

    fn upgrade(&self) -> Result<(), Error> {
        *self.upgrades.borrow_mut() += 1;
        Ok(())
    }
}

/// Reversible, and visibly not the plain seed.
pub struct FakeCreds;

const SEALED: &[u8] = b"sealed:";

impl Creds for FakeCreds {
    fn seal(&self, secret: &[u8]) -> Result<Vec<u8>, Error> {
        Ok([SEALED, &secret.iter().map(|b| b ^ 0xa5).collect::<Vec<_>>()].concat())
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, Error> {
        let body = sealed.strip_prefix(SEALED).ok_or_else(|| Error::Command {
            program: "systemd-creds".into(),
            detail: "bad credential".into(),
        })?;
        Ok(body.iter().map(|b| b ^ 0xa5).collect())
    }
}

/// A directory removed on drop.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new() -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let path = std::env::temp_dir().join(format!(
            "mauvelyd-test-{}-{}-{:08x}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            rand::random::<u32>()
        ));
        std::fs::create_dir_all(&path).unwrap();
        TempDir(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
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
}

/// Answers each request with the next canned reply, then stops.
pub struct FakeServer {
    pub base: String,
    rx: mpsc::Receiver<Captured>,
    thread: Option<JoinHandle<()>>,
}

impl FakeServer {
    pub fn start(replies: Vec<(u16, String)>) -> Self {
        let server = tiny_http::Server::http("127.0.0.1:0").unwrap();
        let port = server.server_addr().to_ip().unwrap().port();
        let (tx, rx) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            for (status, body) in replies {
                let Ok(Some(mut req)) = server.recv_timeout(Duration::from_secs(10)) else {
                    return;
                };
                let mut bytes = Vec::new();
                req.as_reader().read_to_end(&mut bytes).unwrap();
                let captured = Captured {
                    method: req.method().as_str().to_owned(),
                    url: req.url().to_owned(),
                    headers: req
                        .headers()
                        .iter()
                        .map(|h| {
                            (
                                h.field.as_str().as_str().to_owned(),
                                h.value.as_str().to_owned(),
                            )
                        })
                        .collect(),
                    body: bytes,
                };
                let _ = tx.send(captured);
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
            base: format!("http://127.0.0.1:{port}"),
            rx,
            thread: Some(thread),
        }
    }

    /// Everything received so far. Waits for the server thread to finish.
    pub fn requests(mut self) -> Vec<Captured> {
        drop(self.thread.take().map(JoinHandle::join));
        self.rx.try_iter().collect()
    }
}
