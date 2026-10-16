//! `mauvely-session`, the Mauvely OS helper in each graphical session. It
//! runs as the person, from `dist/mauvely-session.service`.
//!
//! For now it does one thing: when an update is staged, it says once that a
//! restart finishes it, and restarts when asked (brief 22, U2).

mod staged;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use zbus::blocking::Connection;
use zbus::zvariant::Value;

pub type Error = Box<dyn std::error::Error + Send + Sync>;

const POLL: Duration = Duration::from_secs(300);
const RESTART: &str = "restart";

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

fn main() -> ExitCode {
    let Err(e) = run();
    eprintln!("mauvely-session: {e}");
    ExitCode::FAILURE
}

fn run() -> Result<std::convert::Infallible, Error> {
    let memory = state_home()
        .ok_or("neither XDG_STATE_HOME nor HOME is an absolute path")?
        .join("mauvely/notified");
    let session = Connection::session()?;
    let notifications = NotificationsProxy::new(&session)?;
    let login = LoginProxy::new(&Connection::system()?)?;

    // The id of the notification on screen. Subscribed before the first one
    // is shown, so no click is missed.
    let shown = Arc::new(AtomicU32::new(0));
    let clicks = notifications.receive_action_invoked()?;
    let on_screen = Arc::clone(&shown);
    std::thread::spawn(move || {
        for click in clicks {
            let Ok(args) = click.args() else { continue };
            if args.action_key == RESTART && args.id == on_screen.load(Ordering::Relaxed) {
                // Interactive: polkit may ask, as when another user is
                // logged in.
                if let Err(e) = login.reboot(true) {
                    eprintln!("mauvely-session: reboot: {e}");
                }
            }
        }
        // The session bus is gone. Exit, and systemd starts us again.
        eprintln!("mauvely-session: the session bus closed");
        std::process::exit(1);
    });

    loop {
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

/// `$XDG_STATE_HOME`, or `~/.local/state`. A relative path is ignored, as
/// the base directory spec says.
fn state_home() -> Option<PathBuf> {
    let absolute = |var: &str| {
        std::env::var_os(var)
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
    };
    absolute("XDG_STATE_HOME").or_else(|| absolute("HOME").map(|h| h.join(".local/state")))
}
