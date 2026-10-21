//! `mauvely-session`, the Mauvely OS helper in each graphical session. It
//! runs as the person, from `dist/mauvely-session.service`.
//!
//! It does three things:
//! - when an update is staged, it says once that a restart finishes it, and
//!   restarts when asked (brief 22, U2);
//! - it is the sign-in broker: it links this computer to the person's
//!   Mauvely account once, then signs the Mauvely apps and the browsers in
//!   from that (brief 22, S2, in `broker`);
//! - when the agent has installed an app, it says once that the app is ready,
//!   and opens it when asked (`ready`).

mod broker;
mod ready;
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
const OPEN: &str = "open";

/// How often the agent's list of installs is looked at: the person is
/// waiting for the app, unlike for an update.
const READY_POLL: Duration = Duration::from_secs(5);
/// What `mauvelyd` writes, and where flatpak exports each system app's
/// desktop file.
const INSTALLED: &str = "/run/mauvely/installed.json";
const APPLICATIONS: &str = "/var/lib/flatpak/exports/share/applications";

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

    fn close_notification(&self, id: u32) -> zbus::Result<()>;

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
    let openable = Arc::new(ready::Openable::default());
    let open_on_screen = Arc::clone(&openable);
    std::thread::spawn(move || {
        for click in clicks {
            let Ok(args) = click.args() else { continue };
            if args.action_key == OPEN
                && let Some(desktop) = open_on_screen.take(args.id)
            {
                // The launcher is quick, but not on this thread.
                std::thread::spawn(move || {
                    if let Err(e) = ready::launch(&desktop) {
                        eprintln!("mauvely-session: could not open {}: {e}", desktop.display());
                    }
                });
            } else if args.action_key == RESTART
                && args.id == restart_on_screen.load(Ordering::Relaxed)
            {
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

    let tell = notifications.clone();
    let ready_memory = state.join("mauvely/ready");
    std::thread::spawn(move || tell_apps_are_ready(&tell, &ready_memory, &openable));

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

/// Looks every few seconds at what the agent has installed, and says which
/// apps are ready.
fn tell_apps_are_ready(
    notifications: &NotificationsProxy<'static>,
    memory: &Path,
    openable: &ready::Openable,
) -> ! {
    let mut last_error = String::new();
    loop {
        let result = ready::check(
            Path::new(INSTALLED),
            memory,
            Path::new(APPLICATIONS),
            &mut |message| {
                let desktop = message.desktop();
                let actions: &[&str] = if desktop.is_some() {
                    &[OPEN, "Open"]
                } else {
                    &[]
                };
                let id = notifications.notify(
                    "Mauvely OS",
                    0,
                    message.icon(),
                    &message.summary(),
                    "",
                    actions,
                    HashMap::new(),
                    // The server's own: this is news, not something to act on
                    // later.
                    -1,
                )?;
                if let Some(desktop) = desktop {
                    openable.add(id, desktop);
                }
                Ok(())
            },
        );
        // Looked at every few seconds, so an error is said when it changes.
        match result {
            Ok(()) => last_error.clear(),
            Err(e) if e.to_string() != last_error => {
                eprintln!("mauvely-session: apps ready: {e}");
                last_error = e.to_string();
            }
            Err(_) => {}
        }
        std::thread::sleep(READY_POLL);
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
        // Listens, tries again when it cannot, and listens again when the
        // socket is replaced.
        std::thread::Builder::new()
            .name("broker".into())
            .spawn(move || socket::serve(&runtime.join("mauvely"), serving, peer::identify))?;
        eprintln!("mauvely-session: broker: for {origin}");
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
    /// The id of the sign-in notification on screen, for the click handler.
    /// The offer, the code and the confirmation replace one another.
    offered: Arc<AtomicU32>,
}

impl SessionDesktop {
    fn show(&self, summary: &str, body: &str, actions: &[&str], timeout: i32) -> Result<(), Error> {
        let id = self.notifications.notify(
            "Mauvely OS",
            self.offered.load(Ordering::Relaxed),
            "user-identity",
            summary,
            body,
            actions,
            HashMap::new(),
            timeout,
        )?;
        self.offered.store(id, Ordering::Relaxed);
        Ok(())
    }
}

impl broker::Desktop for SessionDesktop {
    /// Stays until dismissed, like the restart.
    fn offer(&self) -> Result<(), Error> {
        self.show("Sign in to Mauvely", "", &[SIGN_IN, "Sign in"], 0)
    }

    /// Stays while the person types it.
    fn show_code(&self, code: &str) -> Result<(), Error> {
        self.show("Enter this code to sign in", code, &[], 0)
    }

    fn signed_in(&self, email: &str) -> Result<(), Error> {
        let summary = match email {
            "" => "Signed in to Mauvely".to_owned(),
            email => format!("Signed in to Mauvely as {email}"),
        };
        self.show(&summary, "", &[], -1)
    }

    fn withdraw(&self) {
        let id = self.offered.load(Ordering::Relaxed);
        if id != 0
            && let Err(e) = self.notifications.close_notification(id)
        {
            eprintln!("mauvely-session: could not take the code away: {e}");
        }
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

/// `/etc/mauvely`.
fn config_dir() -> PathBuf {
    config_dir_from(
        std::env::var_os("MAUVELY_CONFIG_DIR"),
        cfg!(debug_assertions),
    )
}

/// `MAUVELY_CONFIG_DIR` moves it in a debug build only. In a release build
/// the environment, which `~/.config/environment.d/` sets, would choose the
/// server the `os` token is sent to.
fn config_dir_from(env: Option<std::ffi::OsString>, honour: bool) -> PathBuf {
    env.filter(|v| honour && !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/mauvely"))
}

/// Makes `dir`, and any parent missing, `0700`, as the base directory spec
/// asks, and tightens `dir` to `0700` if it is not.
pub(crate) fn private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;
    let mode = std::fs::metadata(dir)?.permissions().mode();
    if mode & 0o777 != 0o700 {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|h| h.trim().to_owned())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn the_config_dir_moves_only_in_debug_builds() {
        let moved = Some(std::ffi::OsString::from("/tmp/elsewhere"));
        assert_eq!(
            config_dir_from(moved.clone(), true),
            Path::new("/tmp/elsewhere")
        );
        assert_eq!(config_dir_from(moved, false), Path::new("/etc/mauvely"));
        assert_eq!(config_dir_from(None, true), Path::new("/etc/mauvely"));
        assert_eq!(
            config_dir_from(Some("".into()), true),
            Path::new("/etc/mauvely")
        );
    }

    #[test]
    fn a_private_dir_is_0700() {
        let base = std::env::temp_dir().join(format!("mauvely-private-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let dir = base.join("state/mauvely");
        private_dir(&dir).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&dir), 0o700);
        assert_eq!(mode(&base.join("state")), 0o700);
        // One made by someone else first, with the umask's mode.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        private_dir(&dir).unwrap();
        assert_eq!(mode(&dir), 0o700);
        std::fs::remove_dir_all(&base).unwrap();
    }
}
