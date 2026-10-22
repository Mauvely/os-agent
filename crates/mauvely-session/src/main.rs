//! `mauvely-session`, the Mauvely OS helper in each graphical session. It
//! runs as the person, from `dist/mauvely-session.service`.
//!
//! It does five things:
//! - when an update is staged, it says once that a restart finishes it, and
//!   restarts when asked (brief 22, U2);
//! - it is the sign-in broker: it links this computer to the person's
//!   Mauvely account once, in the sign-in window (`signin`), then signs the
//!   Mauvely apps and the browsers in from that (brief 22, S2, in `broker`);
//! - when the agent has installed an app, it says once that the app is ready,
//!   and opens it when asked (`ready`);
//! - when the collection's desktop preset changes, it puts the person on it,
//!   once (`look`, brief 25);
//! - it puts the browser extension's native host where Firefox and Chromium
//!   look for it, so the extension can ask the broker for the browser's
//!   session (`browserhost`, brief 22, S4).

mod broker;
mod browserhost;
mod dialog;
mod look;
mod ready;
mod signin;
mod staged;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use zbus::blocking::Connection;
use zbus::zvariant::{OwnedObjectPath, Value};

use broker::accounts::{self, Accounts};
use broker::seal::{Store, SystemdCreds};
use broker::{Broker, RealClock, login, peer, socket};
use dialog::{Answer, Dialogs};
use signin::{Ended, Signin};

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
    if std::env::args().nth(1).as_deref() == Some("--before-shell") {
        return before_shell();
    }
    let Err(e) = run();
    eprintln!("mauvely-session: {e}");
    ExitCode::FAILURE
}

/// `mauvely-look.service`, at each sign-in before Plasma's shell starts: the
/// collection's preset, and a panel reset the admin asked for. Never fails the
/// sign-in: what goes wrong is said, and tried again at the next one.
fn before_shell() -> ExitCode {
    let result = (|| -> Result<bool, Error> {
        let state = state_home().ok_or("neither XDG_STATE_HOME nor HOME is an absolute path")?;
        let config = config_home().ok_or("neither XDG_CONFIG_HOME nor HOME is an absolute path")?;
        let session = Connection::session()?;
        let plasma = look::Plasma::new(&session, config, &state);
        look::check(
            Path::new(look::POLICY),
            &state.join("mauvely/look"),
            &plasma,
            look::When::BeforeShell,
        )
    })();
    match result {
        Ok(true) => eprintln!("mauvely-session: the collection's desktop preset is applied"),
        Ok(false) => {}
        Err(e) => eprintln!("mauvely-session: desktop preset, before the shell: {e}"),
    }
    ExitCode::SUCCESS
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
    let (asked, answers) = mpsc::channel();
    let broker = start_broker(&session, &notifications, &offered, &state, asked);

    // The sign-in window opening, or "Open the sign-in page" in the offer
    // window (the same as the Sign in button of the notification it stands
    // in for); or the sign-in window closed.
    let answering = broker.clone();
    std::thread::spawn(move || {
        for answer in answers {
            let Some(broker) = &answering else { continue };
            match answer {
                Asked::Link => {
                    let broker = Arc::clone(broker);
                    std::thread::spawn(move || broker.link());
                }
                Asked::Later => broker.closed(),
            }
        }
    });

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

    let config = config_home().ok_or("neither XDG_CONFIG_HOME nor HOME is an absolute path")?;
    let plasma = look::Plasma::new(&session, config, &state);
    let look_memory = state.join("mauvely/look");
    let mut host_error = String::new();
    loop {
        place_browser_host(&mut host_error);
        match look::check(
            Path::new(look::POLICY),
            &look_memory,
            &plasma,
            look::When::Session,
        ) {
            Ok(true) => eprintln!("mauvely-session: the collection's desktop preset is applied"),
            Ok(false) => {}
            Err(e) => eprintln!("mauvely-session: desktop preset: {e}"),
        }
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

/// The browser extension's host, in each browser's own directory. An error is
/// said when it changes, not every five minutes.
fn place_browser_host(last_error: &mut String) {
    let Some(home) = absolute("HOME") else {
        return;
    };
    match browserhost::place(
        Path::new(browserhost::SOURCE),
        &home,
        &browserhost::BROWSERS,
    ) {
        Ok(written) => {
            last_error.clear();
            for path in written {
                eprintln!("mauvely-session: browser host: wrote {}", path.display());
            }
        }
        Err(e) if e.to_string() != *last_error => {
            eprintln!("mauvely-session: browser host: {e}");
            *last_error = e.to_string();
        }
        Err(_) => {}
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
    asked: mpsc::Sender<Asked>,
) -> Option<Arc<Broker>> {
    let started = (|| -> Result<Arc<Broker>, Error> {
        let path = config_dir().join("server");
        let server =
            std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        let origin = accounts::origin_for(&server)?;
        let runtime = absolute("XDG_RUNTIME_DIR").ok_or("XDG_RUNTIME_DIR is not set")?;
        let desktop = Arc::new(SessionDesktop {
            notice: Notice {
                notifications: notifications.clone(),
                offered: Arc::clone(offered),
            },
            portal: OpenUriProxy::new(session).ok(),
            signin: Signin::new(signin_program()),
            origin: origin.clone(),
            dialogs: Dialogs::new(dialog::PROGRAM),
            asked,
        });
        let broker = Arc::new(Broker::new(
            Accounts::new(&origin),
            Store::new(state.join("mauvely/os.cred"), Box::new(SystemdCreds)),
            hostname(),
            Box::new(desktop),
            Box::new(RealClock),
            // The session a Mauvely login made, which mauvelyd hands over.
            Box::new(login::HandOff::for_me()),
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

/// What the session tells the broker about the sign-in.
enum Asked {
    /// Start a link: the sign-in window is opening, or the person picked
    /// "Open the sign-in page".
    Link,
    /// The person closed the sign-in window.
    Later,
}

/// The broker's way into the graphical session, best first: the sign-in
/// window (`signin`), which is the offer and the code at once; `kdialog`
/// windows for the offer and the code (`dialog`); notifications.
struct SessionDesktop {
    notice: Notice,
    portal: Option<OpenUriProxy<'static>>,
    signin: Signin,
    /// The accounts origin, for the sign-in window.
    origin: String,
    dialogs: Dialogs,
    asked: mpsc::Sender<Asked>,
}

/// The sign-in notifications, which replace one another.
#[derive(Clone)]
struct Notice {
    notifications: NotificationsProxy<'static>,
    /// The id of the sign-in notification on screen, for the click handler.
    /// The offer, the code and the confirmation replace one another.
    offered: Arc<AtomicU32>,
}

impl Notice {
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

    /// Stays until dismissed, like the restart.
    fn offer(&self) -> Result<(), Error> {
        self.show("Sign in to Mauvely", "", &[SIGN_IN, "Sign in"], 0)
    }

    /// Stays while the person types it.
    fn code(&self, code: &str) -> Result<(), Error> {
        self.show("Enter this code to sign in", code, &[], 0)
    }
}

impl SessionDesktop {
    /// A window that stays while the person types the code. The code goes to
    /// kdialog on its standard input, never in an argv (`dialog`).
    fn show_code(&self, code: &str) -> Result<(), Error> {
        let (notice, text) = (self.notice.clone(), code.to_owned());
        let shown = self.dialogs.show_code(code, move || {
            eprintln!("mauvely-session: the code window failed");
            if let Err(e) = notice.code(&text) {
                eprintln!("mauvely-session: {e}");
            }
        });
        match shown {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!("mauvely-session: no code window: {e}");
                self.notice.code(code)
            }
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

    /// The code window, then the page in the browser: the way before the
    /// sign-in window, and its fallback.
    fn show_code_and_open(&self, code: &str, page: &str) -> Result<(), Error> {
        self.show_code(code)?;
        self.open(page)
    }
}

impl broker::Desktop for Arc<SessionDesktop> {
    /// The sign-in window is the offer: it shows the real sign-in, so the link
    /// starts at once and the window opens with its code. Without the window,
    /// or when `ask`, a window with two buttons, where "Later" and closing it
    /// leave things as dismissing the notification did.
    fn offer(&self, ask: bool) -> Result<(), Error> {
        if !ask && self.signin.available() {
            return self
                .asked
                .send(Asked::Link)
                .map_err(|_| "the session is stopping".into());
        }
        let asked = self.asked.clone();
        let notice = self.notice.clone();
        let shown = self.dialogs.offer(move |answer| match answer {
            Answer::Accepted => {
                let _ = asked.send(Asked::Link);
            }
            Answer::Dismissed => {}
            // kdialog crashed with nothing shown.
            Answer::Failed => {
                eprintln!("mauvely-session: the sign-in window failed");
                if let Err(e) = notice.offer() {
                    eprintln!("mauvely-session: {e}");
                }
            }
        });
        match shown {
            Ok(()) => Ok(()),
            Err(e) => {
                eprintln!("mauvely-session: no sign-in window: {e}");
                self.notice.offer()
            }
        }
    }

    /// The sign-in window, with the code on its standard input. When it is
    /// not installed, cannot start, or fails later, the code window and the
    /// browser, as before it.
    fn show_link(&self, code: &str, page: &str) -> Result<(), Error> {
        if self.signin.available() {
            let desktop = Arc::clone(self);
            let (code_, page_) = (code.to_owned(), page.to_owned());
            let shown = self
                .signin
                .show(code, &self.origin, move |ended| match ended {
                    Ended::Later => {
                        let _ = desktop.asked.send(Asked::Later);
                    }
                    Ended::Failed => {
                        eprintln!("mauvely-session: the sign-in window failed");
                        if let Err(e) = desktop.show_code_and_open(&code_, &page_) {
                            eprintln!("mauvely-session: {e}");
                        }
                    }
                });
            match shown {
                Ok(()) => return Ok(()),
                Err(e) => eprintln!("mauvely-session: no sign-in window: {e}"),
            }
        }
        self.show_code_and_open(code, page)
    }

    /// The link is claimed: the sign-in window signs its own session out and
    /// goes, and the confirmation is a notification.
    fn signed_in(&self, email: &str) -> Result<(), Error> {
        self.signin.finish();
        self.dialogs.close();
        let summary = match email {
            "" => "Signed in to Mauvely".to_owned(),
            email => format!("Signed in to Mauvely as {email}"),
        };
        self.notice.show(&summary, "", &[], -1)
    }

    fn withdraw(&self) {
        self.signin.finish();
        self.dialogs.close();
        let id = self.notice.offered.load(Ordering::Relaxed);
        if id != 0
            && let Err(e) = self.notice.notifications.close_notification(id)
        {
            eprintln!("mauvely-session: could not take the code away: {e}");
        }
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

fn config_home() -> Option<PathBuf> {
    absolute("XDG_CONFIG_HOME").or_else(|| absolute("HOME").map(|h| h.join(".config")))
}

/// `/etc/mauvely`.
fn config_dir() -> PathBuf {
    config_dir_from(
        std::env::var_os("MAUVELY_CONFIG_DIR"),
        cfg!(debug_assertions),
    )
}

/// `/usr/bin/mauvely-signin`.
fn signin_program() -> PathBuf {
    signin_program_from(std::env::var_os("MAUVELY_SIGNIN"), cfg!(debug_assertions))
}

/// `MAUVELY_SIGNIN` moves it in a debug build only, for the same reason as
/// `MAUVELY_CONFIG_DIR`: in a release build the environment would choose the
/// program the code is handed to.
fn signin_program_from(env: Option<std::ffi::OsString>, honour: bool) -> PathBuf {
    env.filter(|v| honour && !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(signin::PROGRAM))
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
    fn the_signin_program_moves_only_in_debug_builds() {
        let moved = Some(std::ffi::OsString::from("/tmp/fake-signin"));
        assert_eq!(
            signin_program_from(moved.clone(), true),
            Path::new("/tmp/fake-signin")
        );
        assert_eq!(
            signin_program_from(moved, false),
            Path::new("/usr/bin/mauvely-signin")
        );
        assert_eq!(
            signin_program_from(None, true),
            Path::new("/usr/bin/mauvely-signin")
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
