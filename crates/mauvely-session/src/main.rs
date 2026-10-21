//! `mauvely-session`, the Mauvely OS helper in each graphical session. It
//! runs as the person, from `dist/mauvely-session.service`.
//!
//! It does two things:
//! - when an update is staged, it says once that a restart finishes it, and
//!   restarts when asked (brief 22, U2);
//! - it is the sign-in broker: it links this computer to the person's
//!   Mauvely account once, then signs the Mauvely apps and the browsers in
//!   from that (brief 22, S2, in `broker`).

mod broker;
mod staged;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use zbus::blocking::Connection;
use zbus::zvariant::{OwnedObjectPath, Value};

use broker::accounts::{self, Accounts};
use broker::seal::{Store, SystemdCreds};
use broker::{Broker, RealClock, peer, socket};

pub type Error = Box<dyn std::error::Error + Send + Sync>;

const POLL: Duration = Duration::from_secs(300);
const RESTART: &str = "restart";
const SIGN_IN: &str = "sign-in";

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications",
    gen_async = false
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: &str) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "org.freedesktop.login1.Manager",
    default_service = "org.freedesktop.login1",
    default_path = "/org/freedesktop/login1",
    gen_async = false
)]
trait Login {
    fn reboot(&self, interactive: bool) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "org.freedesktop.portal.OpenURI",
    default_service = "org.freedesktop.portal.Desktop",
    default_path = "/org/freedesktop/portal/desktop",
    gen_async = false
)]
trait OpenUri {
    #[zbus(name = "OpenURI")]
    fn open_uri(
        &self,
        parent_window: &str,
        uri: &str,
        options: HashMap<&str, Value<'_>>,
    ) -> zbus::Result<OwnedObjectPath>;
}

fn main() -> ExitCode {
    let Err(e) = run();
    eprintln!("mauvely-session: {e}");
    ExitCode::FAILURE
}

fn run() -> Result<std::convert::Infallible, Error> {
    let state = state_home().ok_or("neither XDG_STATE_HOME nor HOME is an absolute path")?;
    let memory = state.join("mauvely/notified");
    let session = Connection::session()?;
    let notifications = NotificationsProxy::new(&session)?;
    let login = LoginProxy::new(&Connection::system()?)?;

    // The ids of the notifications on screen. Subscribed before the first
    // one is shown, so no click is missed.
    let shown = Arc::new(AtomicU32::new(0));
    let offered = Arc::new(AtomicU32::new(0));
    let clicks = notifications.receive_action_invoked()?;
    let broker = start_broker(&session, &notifications, &offered, &state);

    let restart_on_screen = Arc::clone(&shown);
    let offer_on_screen = Arc::clone(&offered);
    let linker = broker.clone();
    std::thread::spawn(move || {
        for click in clicks {
            let Ok(args) = click.args() else { continue };
            if args.action_key == RESTART && args.id == restart_on_screen.load(Ordering::Relaxed) {
                // Interactive: polkit may ask, as when another user is
                // logged in.
                if let Err(e) = login.reboot(true) {
                    eprintln!("mauvely-session: reboot: {e}");
                }
            } else if args.action_key == SIGN_IN
                && args.id == offer_on_screen.load(Ordering::Relaxed)
                && let Some(broker) = &linker
            {
                // Waits for the person to approve, for up to the link's
                // ten minutes, so not on this thread.
                let broker = Arc::clone(broker);
                std::thread::spawn(move || broker.link());
            }
        }
        // The session bus is gone. Exit, and systemd starts us again.
        eprintln!("mauvely-session: the session bus closed");
        std::process::exit(1);
    });

    loop {
        if let Some(broker) = &broker {
            broker.offer_if_wanted();
        }
        let result = rpm_ostree_status().and_then(|json| {
            staged::check(&json, &memory, &mut || {
                let id = notifications.notify(
                    "Mauvely OS",
                    shown.load(Ordering::Relaxed),
                    "system-software-update",
                    "Restart to finish updating",
                    "",
                    &[RESTART, "Restart"],
                    HashMap::new(),
                    // Stays until dismissed: the Restart button has to be
                    // there when the person is ready.
                    0,
                )?;
                shown.store(id, Ordering::Relaxed);
                Ok(())
            })
        });
        if let Err(e) = result {
            eprintln!("mauvely-session: {e}");
        }
        std::thread::sleep(POLL);
    }
}

/// The sign-in broker, listening, or `None` when this computer cannot have
/// one: a device server with no known accounts service, or no runtime
/// directory. The rest of the helper carries on without it.
fn start_broker(
    session: &Connection,
    notifications: &NotificationsProxy<'static>,
    offered: &Arc<AtomicU32>,
    state: &Path,
) -> Option<Arc<Broker>> {
    let started = (|| -> Result<Arc<Broker>, Error> {
        let path = config_dir().join("server");
        let server =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let origin = accounts::origin_for(&server)?;
        let runtime = absolute("XDG_RUNTIME_DIR").ok_or("XDG_RUNTIME_DIR is not set")?;
        let listener = socket::listen(&runtime.join("mauvely"))?;
        let desktop = SessionDesktop {
            notifications: notifications.clone(),
            portal: OpenUriProxy::new(session).ok(),
            offered: Arc::clone(offered),
        };
        let broker = Arc::new(Broker::new(
            Accounts::new(&origin),
            Store::new(state.join("mauvely/os.cred"), Box::new(SystemdCreds)),
            hostname(),
            Box::new(desktop),
            Box::new(RealClock),
        ));
        broker.load();
        let serving = Arc::clone(&broker);
        std::thread::Builder::new()
            .name("broker".into())
            .spawn(move || {
                let e = socket::serve(listener, serving, peer::identify);
                // Exit, and systemd starts us again with a new socket.
                eprintln!("mauvely-session: broker: {e}");
                std::process::exit(1);
            })?;
        eprintln!("mauvely-session: broker: listening, for {origin}");
        Ok(broker)
    })();
    started
        .inspect_err(|e| eprintln!("mauvely-session: the sign-in broker is off: {e}"))
        .ok()
}

/// The broker's way into the graphical session.
struct SessionDesktop {
    notifications: NotificationsProxy<'static>,
    portal: Option<OpenUriProxy<'static>>,
    /// The id of the offer on screen, for the click handler.
    offered: Arc<AtomicU32>,
}

impl broker::Desktop for SessionDesktop {
    fn offer(&self) -> Result<(), Error> {
        let id = self.notifications.notify(
            "Mauvely OS",
            self.offered.load(Ordering::Relaxed),
            "user-identity",
            "Sign in to Mauvely",
            "",
            &[SIGN_IN, "Sign in"],
            HashMap::new(),
            // Stays until dismissed, like the restart.
            0,
        )?;
        self.offered.store(id, Ordering::Relaxed);
        Ok(())
    }

    /// Through the OpenURI portal, or `xdg-open` when there is none.
    fn open(&self, url: &str) -> Result<(), Error> {
        if url.starts_with('-') {
            return Err(format!("{url:?} is not a page").into());
        }
        if let Some(portal) = &self.portal {
            match portal.open_uri("", url, HashMap::new()) {
                Ok(_) => return Ok(()),
                Err(e) => eprintln!("mauvely-session: the portal did not open it: {e}"),
            }
        }
        let status = Command::new("xdg-open")
            .arg(url)
            .stdin(Stdio::null())
            .status()?;
        if !status.success() {
            return Err(format!("xdg-open: {status}").into());
        }
        Ok(())
    }
}

/// `rpm-ostree status --json`. It needs no privilege: rpm-ostreed answers
/// over the system bus.
fn rpm_ostree_status() -> Result<Vec<u8>, Error> {
    let out = Command::new("rpm-ostree")
        .args(["status", "--json"])
        .stdin(Stdio::null())
        .output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("rpm-ostree status: {}: {}", out.status, stderr.trim()).into());
    }
    Ok(out.stdout)
}

fn absolute(var: &str) -> Option<PathBuf> {
    std::env::var_os(var)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
}

/// `$XDG_STATE_HOME`, or `~/.local/state`. A relative path is ignored, as
/// the base directory spec says.
fn state_home() -> Option<PathBuf> {
    absolute("XDG_STATE_HOME").or_else(|| absolute("HOME").map(|h| h.join(".local/state")))
}

/// `/etc/mauvely`, or `MAUVELY_CONFIG_DIR`, as for mauvelyd.
fn config_dir() -> PathBuf {
    std::env::var_os("MAUVELY_CONFIG_DIR")
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/mauvely"))
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_owned())
        .unwrap_or_default()
}
