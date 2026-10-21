//! "<App> is ready": the person is told, once, when `mauvelyd` has installed
//! an app.
//!
//! The agent writes `/run/mauvely/installed.json` (root's, everyone reads it):
//! the last 50 apps it installed since boot, oldest first, each
//! `{"id", "branch", "at"}`. This module reads it as the person, and remembers
//! under `$XDG_STATE_HOME/mauvely/ready` which installs have been shown. An
//! install is one line there, `<id> <branch> <at>`, so an app removed and
//! installed again is a new one.
//!
//! The first look at a person's state finds no memory. Everything installed
//! until then is remembered and not shown, so a new machine does not open with
//! a pile of notices.

use std::collections::HashSet;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Mutex;

use serde::Deserialize;

use crate::Error;

/// More than this many new apps at once are one notification, "5 apps are
/// ready", with nothing to open.
pub const EACH_UP_TO: usize = 3;

/// The agent keeps 50 installs of about 90 bytes. Anything past this is not
/// its file.
const MAX_FILE: u64 = 64 * 1024;

/// An app that is ready, and the exported desktop file that opens it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ready {
    pub name: String,
    pub icon: Option<String>,
    pub desktop: PathBuf,
}

/// What to tell the person.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// "<name> is ready", with Open.
    App(Ready),
    /// "<n> apps are ready".
    Several(usize),
}

/// What a notification with no icon of its own shows.
const GENERIC_ICON: &str = "system-software-install";

/// The most characters of an app's name that are shown.
const NAME_MAX: usize = 60;

impl Message {
    pub fn summary(&self) -> String {
        match self {
            Message::App(ready) => format!("{} is ready", ready.name),
            Message::Several(n) => format!("{n} apps are ready"),
        }
    }

    pub fn icon(&self) -> &str {
        match self {
            Message::App(Ready {
                icon: Some(icon), ..
            }) => icon,
            _ => GENERIC_ICON,
        }
    }

    /// The desktop file Open launches, for a message that has an Open.
    pub fn desktop(&self) -> Option<&Path> {
        match self {
            Message::App(ready) => Some(&ready.desktop),
            Message::Several(_) => None,
        }
    }
}

#[derive(Deserialize)]
struct File {
    installs: Vec<Install>,
}

#[derive(Deserialize)]
struct Install {
    id: String,
    branch: String,
    at: u64,
}

impl Install {
    /// What the memory holds for it. An id has no space, so this reads back.
    fn key(&self) -> String {
        format!("{} {} {}", self.id, self.branch, self.at)
    }

    /// The id becomes a file name and the line a memory, from a file that a
    /// daemon wrote out of a server's list. Flatpak's ids and branches are
    /// letters, digits, `_`, `-` and `.`; anything else is not an install.
    fn valid(&self) -> bool {
        let word = |s: &str| {
            !s.is_empty()
                && s.len() <= 255
                && !s.starts_with(['-', '.'])
                && !s.contains("..")
                && s.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
        };
        word(&self.id) && word(&self.branch)
    }
}

/// How many notifications with an Open are remembered.
const OPENABLE_MAX: usize = 50;

/// The notifications on screen that have an Open, by their ids, for the
/// click that arrives with only an id. The last 50.
#[derive(Default)]
pub struct Openable(Mutex<Vec<(u32, PathBuf)>>);

impl Openable {
    pub fn add(&self, id: u32, desktop: &Path) {
        let mut all = self.lock();
        all.push((id, desktop.to_owned()));
        let extra = all.len().saturating_sub(OPENABLE_MAX);
        all.drain(..extra);
    }

    /// The desktop file for `id`, once.
    pub fn take(&self, id: u32) -> Option<PathBuf> {
        let mut all = self.lock();
        let at = all.iter().position(|(i, _)| *i == id)?;
        Some(all.remove(at).1)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<(u32, PathBuf)>> {
        // Nothing half-written to fear: a list.
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One look at what the agent has installed. New apps are told with `notify`
/// and remembered once told; one `notify` fails on is tried again next time.
pub fn check(
    installed: &Path,
    memory: &Path,
    applications: &Path,
    notify: &mut dyn FnMut(&Message) -> Result<(), Error>,
) -> Result<(), Error> {
    let installs = read_installs(installed)?;
    let Some(told) = read_memory(memory)? else {
        // This person's first look: all of it was there before.
        return write_memory(
            memory,
            &installs.iter().map(Install::key).collect::<Vec<_>>(),
        );
    };

    // What the memory keeps is what the file still holds, so it cannot grow.
    let mut seen: Vec<String> = installs
        .iter()
        .map(Install::key)
        .filter(|k| told.contains(k))
        .collect();
    let mut fresh = Vec::new();
    for install in installs.iter().filter(|i| !told.contains(&i.key())) {
        match ready(applications, install) {
            Some(ready) => fresh.push((install.key(), ready)),
            // Nothing to open: not an app a person starts.
            None => seen.push(install.key()),
        }
    }

    if fresh.len() > EACH_UP_TO {
        notify(&Message::Several(fresh.len()))?;
        seen.extend(fresh.into_iter().map(|(key, _)| key));
    } else {
        for (key, ready) in fresh {
            if let Err(e) = notify(&Message::App(ready)) {
                // The ones told stay told.
                let _ = write_memory(memory, &seen);
                return Err(e);
            }
            seen.push(key);
        }
    }
    if seen.iter().collect::<HashSet<_>>() == told.iter().collect::<HashSet<_>>() {
        return Ok(());
    }
    write_memory(memory, &seen)
}

fn read_installs(path: &Path) -> Result<Vec<Install>, Error> {
    let file = match fs::File::open(path) {
        Ok(f) => f,
        // The agent has installed nothing since boot.
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", path.display()).into()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    if bytes.len() as u64 > MAX_FILE {
        return Err(format!("{}: larger than {MAX_FILE} bytes", path.display()).into());
    }
    let file: File =
        serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(file.installs.into_iter().filter(Install::valid).collect())
}

fn read_memory(path: &Path) -> Result<Option<HashSet<String>>, Error> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text.lines().map(str::to_owned).collect())),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{}: {e}", path.display()).into()),
    }
}

/// Written whole and renamed, so a crash leaves the old one and not half of a
/// new one, which would show a pile of apps again.
fn write_memory(path: &Path, keys: &[String]) -> Result<(), Error> {
    if let Some(dir) = path.parent() {
        crate::private_dir(dir)?;
    }
    let tmp = path.with_extension("tmp");
    let _ = fs::remove_file(&tmp);
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)?;
    for key in keys {
        writeln!(file, "{key}")?;
    }
    drop(file);
    fs::rename(&tmp, path)?;
    Ok(())
}

/// The app's name and icon from its exported desktop file.
fn ready(applications: &Path, install: &Install) -> Option<Ready> {
    let desktop = applications.join(format!("{}.desktop", install.id));
    let mut bytes = Vec::new();
    fs::File::open(&desktop)
        .ok()?
        .take(MAX_FILE)
        .read_to_end(&mut bytes)
        .ok()?;
    let text = String::from_utf8_lossy(&bytes);

    // `Name=` and `Icon=` of the `[Desktop Entry]` group: not `Name[de]=`,
    // and not an action's.
    let (mut name, mut icon) = (None, None);
    let mut in_entry = false;
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
        } else if let (true, Some((key, value))) = (in_entry, line.split_once('=')) {
            match key.trim() {
                "Name" => name = name.or_else(|| Some(value.trim())),
                "Icon" => icon = icon.or_else(|| Some(value.trim())),
                _ => {}
            }
        }
    }
    let clean = |s: &str| -> String { s.chars().filter(|c| !c.is_control()).collect() };
    let name: String = clean(name?).trim().chars().take(NAME_MAX).collect();
    let icon = icon.map(clean).filter(|i| !i.is_empty());
    (!name.is_empty()).then_some(Ready {
        name,
        icon,
        desktop,
    })
}

/// The argv that opens an app from its exported desktop file. `gio launch`
/// takes the file itself, so it needs neither the file to be on the search
/// path nor a display. `kioclient exec`, KDE's own, asks "This will start the
/// program: … click Cancel" for a file it does not find in an applications
/// directory of its own search path (seen with the exports left off
/// `XDG_DATA_DIRS`). The app moves itself into its own systemd scope when
/// `flatpak run` starts, so it does not end with this helper.
pub fn launch_argv(desktop: &Path) -> Vec<String> {
    vec![
        "gio".into(),
        "launch".into(),
        desktop.to_string_lossy().into_owned(),
    ]
}

/// Opens the app, and waits for the launcher, not the app.
pub fn launch(desktop: &Path) -> Result<(), Error> {
    run_argv(&launch_argv(desktop))
}

fn run_argv(argv: &[String]) -> Result<(), Error> {
    let (program, args) = argv.split_first().ok_or("an empty command")?;
    let status = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .status()
        .map_err(|e| format!("{program}: {e}"))?;
    if !status.success() {
        return Err(format!("{program}: {status}").into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::seal::tests::temp_dir;
    use std::os::unix::fs::PermissionsExt;

    /// A state directory, a run directory and an exports directory.
    struct Rig {
        dir: PathBuf,
        installed: PathBuf,
        memory: PathBuf,
        applications: PathBuf,
    }

    impl Rig {
        fn new() -> Self {
            let dir = temp_dir("ready");
            let rig = Rig {
                installed: dir.join("run/installed.json"),
                memory: dir.join("state/mauvely/ready"),
                applications: dir.join("exports/share/applications"),
                dir,
            };
            fs::create_dir_all(rig.installed.parent().unwrap()).unwrap();
            fs::create_dir_all(&rig.applications).unwrap();
            rig
        }

        /// What the agent wrote: `(id, branch, at)`.
        fn installs(&self, list: &[(&str, &str, u64)]) {
            let installs: Vec<serde_json::Value> = list
                .iter()
                .map(|(id, branch, at)| serde_json::json!({ "id": id, "branch": branch, "at": at }))
                .collect();
            fs::write(
                &self.installed,
                serde_json::json!({ "installs": installs }).to_string(),
            )
            .unwrap();
        }

        /// An exported desktop file, as flatpak writes one.
        fn app(&self, id: &str, name: &str) {
            fs::write(
                self.applications.join(format!("{id}.desktop")),
                format!(
                    "[Desktop Entry]\nName={name}\nName[de]=Deutsch\nExec=/usr/bin/flatpak run {id}\n\
                     Icon={id}\nType=Application\n\n[Desktop Action new-window]\nName=New window\n"
                ),
            )
            .unwrap();
        }

        fn look(&self) -> Vec<Message> {
            let mut told = Vec::new();
            check(
                &self.installed,
                &self.memory,
                &self.applications,
                &mut |m| {
                    told.push(m.clone());
                    Ok(())
                },
            )
            .unwrap();
            told
        }

        fn summaries(&self) -> Vec<String> {
            self.look().iter().map(Message::summary).collect()
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    #[test]
    fn the_first_look_shows_nothing_and_remembers_what_is_there() {
        let rig = Rig::new();
        rig.app("org.mozilla.firefox", "Firefox");
        rig.installs(&[("org.mozilla.firefox", "stable", 100)]);
        // Installed before this person's first login.
        assert!(rig.look().is_empty());
        assert!(rig.memory.exists());
        // So it is not shown on the look after, either.
        assert!(rig.look().is_empty());

        // The next one is.
        rig.app("org.kde.kate", "Kate");
        rig.installs(&[
            ("org.mozilla.firefox", "stable", 100),
            ("org.kde.kate", "stable", 200),
        ]);
        assert_eq!(rig.summaries(), ["Kate is ready"]);
    }

    #[test]
    fn nothing_installed_yet_is_still_a_first_look() {
        let rig = Rig::new();
        // No installed.json at all: the agent has not installed anything.
        assert!(rig.look().is_empty());
        assert!(rig.memory.exists(), "the first look is over");

        rig.app("org.kde.kate", "Kate");
        rig.installs(&[("org.kde.kate", "stable", 200)]);
        assert_eq!(rig.summaries(), ["Kate is ready"]);
    }

    #[test]
    fn an_install_is_shown_once_and_a_new_install_of_the_app_is_shown_again() {
        let rig = Rig::new();
        rig.look();
        rig.app("org.kde.kate", "Kate");
        rig.installs(&[("org.kde.kate", "stable", 200)]);
        assert_eq!(rig.summaries(), ["Kate is ready"]);
        for _ in 0..3 {
            assert!(rig.look().is_empty());
        }
        // Removed and installed again, later: a new line in the file.
        rig.installs(&[
            ("org.kde.kate", "stable", 200),
            ("org.kde.kate", "stable", 900),
        ]);
        assert_eq!(rig.summaries(), ["Kate is ready"]);
        assert!(rig.look().is_empty());
        // Another branch of it is another app.
        rig.installs(&[
            ("org.kde.kate", "stable", 200),
            ("org.kde.kate", "stable", 900),
            ("org.kde.kate", "beta", 900),
        ]);
        assert_eq!(rig.summaries(), ["Kate is ready"]);
    }

    #[test]
    fn what_is_shown_is_remembered_for_the_next_session() {
        let rig = Rig::new();
        rig.look();
        rig.app("org.kde.kate", "Kate");
        rig.installs(&[("org.kde.kate", "stable", 200)]);
        rig.look();
        // The memory is on disk, one line each, and private: the person's.
        assert_eq!(
            fs::read_to_string(&rig.memory).unwrap(),
            "org.kde.kate stable 200\n"
        );
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&rig.memory), 0o600);
        assert_eq!(mode(rig.memory.parent().unwrap()), 0o700);
        assert!(!rig.memory.with_extension("tmp").exists());
    }

    #[test]
    fn a_look_with_nothing_new_does_not_write_the_memory() {
        use std::os::unix::fs::MetadataExt;
        let rig = Rig::new();
        rig.look();
        rig.app("org.kde.kate", "Kate");
        rig.installs(&[("org.kde.kate", "stable", 200)]);
        rig.look();
        // It looks every few seconds: a rename each time would be a write to
        // the person's disk all day. A new file has a new inode.
        let inode = fs::metadata(&rig.memory).unwrap().ino();
        for _ in 0..3 {
            rig.look();
        }
        assert_eq!(fs::metadata(&rig.memory).unwrap().ino(), inode);
    }

    #[test]
    fn the_memory_lets_go_of_what_the_file_no_longer_holds() {
        let rig = Rig::new();
        rig.look();
        rig.app("org.kde.kate", "Kate");
        rig.app("org.mozilla.firefox", "Firefox");
        rig.installs(&[
            ("org.kde.kate", "stable", 200),
            ("org.mozilla.firefox", "stable", 300),
        ]);
        rig.look();
        // A reboot empties /run, and the agent starts a new file.
        rig.installs(&[("org.mozilla.firefox", "stable", 5000)]);
        assert_eq!(rig.summaries(), ["Firefox is ready"]);
        assert_eq!(
            fs::read_to_string(&rig.memory).unwrap(),
            "org.mozilla.firefox stable 5000\n"
        );
    }

    #[test]
    fn up_to_three_apps_are_one_notification_each() {
        let rig = Rig::new();
        rig.look();
        for (id, name) in [("a.A", "Alpha"), ("b.B", "Beta"), ("c.C", "Gamma")] {
            rig.app(id, name);
        }
        rig.installs(&[
            ("a.A", "stable", 1),
            ("b.B", "stable", 1),
            ("c.C", "stable", 1),
        ]);
        let told = rig.look();
        assert_eq!(EACH_UP_TO, 3);
        assert_eq!(
            told.iter().map(Message::summary).collect::<Vec<_>>(),
            ["Alpha is ready", "Beta is ready", "Gamma is ready"]
        );
        // Each can be opened, and opens its own.
        assert_eq!(
            told[1].desktop().unwrap(),
            rig.applications.join("b.B.desktop")
        );
        assert_eq!(told[1].icon(), "b.B");
    }

    #[test]
    fn more_than_three_apps_are_one_notification_that_says_how_many() {
        let rig = Rig::new();
        rig.look();
        let ids = ["a.A", "b.B", "c.C", "d.D", "e.E"];
        for id in ids {
            rig.app(id, id);
        }
        let list: Vec<(&str, &str, u64)> = ids.iter().map(|id| (*id, "stable", 7)).collect();
        rig.installs(&list);
        let told = rig.look();
        assert_eq!(told, [Message::Several(5)]);
        assert_eq!(told[0].summary(), "5 apps are ready");
        assert!(told[0].desktop().is_none(), "there is nothing to open");
        // All five are told: none comes back.
        assert!(rig.look().is_empty());
    }

    #[test]
    fn an_app_with_nothing_to_open_is_remembered_and_not_shown() {
        let rig = Rig::new();
        rig.look();
        // No exported desktop file for it, and one with no name.
        fs::write(
            rig.applications.join("org.example.Nameless.desktop"),
            "[Desktop Entry]\nType=Application\n",
        )
        .unwrap();
        rig.app("org.kde.kate", "Kate");
        rig.installs(&[
            ("org.example.Cli", "stable", 1),
            ("org.example.Nameless", "stable", 1),
            ("org.kde.kate", "stable", 1),
        ]);
        assert_eq!(rig.summaries(), ["Kate is ready"]);
        assert!(rig.look().is_empty());
        let memory = fs::read_to_string(&rig.memory).unwrap();
        assert_eq!(memory.lines().count(), 3, "{memory}");
    }

    #[test]
    fn a_notification_that_failed_is_tried_again_and_a_shown_one_is_not_repeated() {
        let rig = Rig::new();
        rig.look();
        rig.app("a.A", "Alpha");
        rig.app("b.B", "Beta");
        rig.installs(&[("a.A", "stable", 1), ("b.B", "stable", 1)]);

        // The second one fails: no notification server.
        let mut told = Vec::new();
        let result = check(&rig.installed, &rig.memory, &rig.applications, &mut |m| {
            if told.len() == 1 {
                return Err("no notification server".into());
            }
            told.push(m.summary());
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(told, ["Alpha is ready"]);

        // Next time: Beta only.
        assert_eq!(rig.summaries(), ["Beta is ready"]);
        assert!(rig.look().is_empty());

        // And a summary that failed is tried again whole.
        let ids = ["a.A", "b.B", "c.C", "d.D", "e.E"];
        for id in ids {
            rig.app(id, id);
        }
        let more: Vec<(&str, &str, u64)> = ids.iter().map(|id| (*id, "stable", 2)).collect();
        rig.installs(&more);
        let failed = check(&rig.installed, &rig.memory, &rig.applications, &mut |_| {
            Err("no notification server".into())
        });
        assert!(failed.is_err());
        assert_eq!(rig.look(), [Message::Several(5)]);
    }

    #[test]
    fn an_id_that_could_name_another_file_is_never_read() {
        let rig = Rig::new();
        rig.look();
        // A file outside the exports directory, with a name.
        fs::write(
            rig.applications.join("../evil.desktop"),
            "[Desktop Entry]\nName=Evil\n",
        )
        .unwrap();
        fs::write(
            rig.dir.join("exports/escape.desktop"),
            "[Desktop Entry]\nName=Escape\n",
        )
        .unwrap();
        rig.installs(&[
            ("../evil", "stable", 1),
            ("../../escape", "stable", 1),
            ("sub/dir", "stable", 1),
            ("-oops", "stable", 1),
            (".hidden", "stable", 1),
            ("a..b", "stable", 1),
            ("", "stable", 1),
            ("a b", "stable", 1),
            ("org.kde.kate", "../x", 1),
            ("org.kde.kate", "", 1),
        ]);
        rig.app("org.kde.kate", "Kate");
        assert!(rig.look().is_empty());
        // Not even remembered: they are not installs.
        assert_eq!(fs::read_to_string(&rig.memory).unwrap(), "");
    }

    #[test]
    fn a_name_is_made_safe_to_show() {
        let rig = Rig::new();
        rig.look();
        fs::write(
            rig.applications.join("a.A.desktop"),
            "[Desktop Entry]\nName=  Bad\u{7}\u{1b}[31mName \t \n",
        )
        .unwrap();
        fs::write(
            rig.applications.join("b.B.desktop"),
            format!("[Desktop Entry]\nName={}\n", "é".repeat(200)),
        )
        .unwrap();
        rig.installs(&[("a.A", "stable", 1), ("b.B", "stable", 1)]);
        let s = rig.summaries();
        assert_eq!(s[0], "Bad[31mName is ready");
        assert_eq!(s[1], format!("{} is ready", "é".repeat(60)));
    }

    #[test]
    fn only_the_desktop_entrys_own_name_and_icon_count() {
        let rig = Rig::new();
        rig.look();
        // The action's Name comes first in the file here, and a localised
        // one before the plain one.
        fs::write(
            rig.applications.join("a.A.desktop"),
            "[Desktop Action x]\nName=Action\nIcon=action-icon\n\n[Desktop Entry]\n\
             Name[fr]=Français\nName=Alpha\nIcon=alpha\nIcon[fr]=alpha-fr\n",
        )
        .unwrap();
        rig.installs(&[("a.A", "stable", 1)]);
        let told = rig.look();
        assert_eq!(told[0].summary(), "Alpha is ready");
        assert_eq!(told[0].icon(), "alpha");

        // No Icon: a generic one.
        fs::write(
            rig.applications.join("b.B.desktop"),
            "[Desktop Entry]\nName=Beta\n",
        )
        .unwrap();
        rig.installs(&[("a.A", "stable", 1), ("b.B", "stable", 1)]);
        assert_eq!(rig.look()[0].icon(), "system-software-install");
    }

    #[test]
    fn a_file_that_is_too_large_or_not_json_is_an_error_and_changes_nothing() {
        let rig = Rig::new();
        rig.look();
        let before = fs::read_to_string(&rig.memory).unwrap();
        let try_it = |rig: &Rig| {
            check(&rig.installed, &rig.memory, &rig.applications, &mut |_| {
                panic!("nothing is told")
            })
        };

        fs::write(&rig.installed, "{ not json").unwrap();
        assert!(try_it(&rig).is_err());
        fs::write(&rig.installed, r#"{"installs":[{"id":"a.A"}]}"#).unwrap();
        assert!(try_it(&rig).is_err());
        // Valid, and one byte over: refused for its size alone.
        let mut big = br#"{"installs":[]}"#.to_vec();
        big.resize(MAX_FILE as usize + 1, b' ');
        fs::write(&rig.installed, &big).unwrap();
        assert!(try_it(&rig).is_err());
        assert_eq!(fs::read_to_string(&rig.memory).unwrap(), before);

        // A file at the limit is read.
        big.pop();
        fs::write(&rig.installed, big).unwrap();
        assert!(try_it(&rig).is_ok());
    }

    #[test]
    fn the_launcher_is_given_the_desktop_file_and_nothing_else_to_read_as_an_option() {
        let path =
            Path::new("/var/lib/flatpak/exports/share/applications/com.mauvely.compose.desktop");
        assert_eq!(
            launch_argv(path),
            [
                "gio",
                "launch",
                "/var/lib/flatpak/exports/share/applications/com.mauvely.compose.desktop"
            ]
        );
    }

    #[test]
    fn open_launches_what_its_own_notification_was_for_once() {
        let on_screen = Openable::default();
        on_screen.add(7, Path::new("/a.desktop"));
        on_screen.add(8, Path::new("/b.desktop"));
        // Another notification's id, or a click twice: nothing.
        assert_eq!(on_screen.take(9), None);
        assert_eq!(on_screen.take(8).as_deref(), Some(Path::new("/b.desktop")));
        assert_eq!(on_screen.take(8), None);
        assert_eq!(on_screen.take(7).as_deref(), Some(Path::new("/a.desktop")));
    }

    #[test]
    fn the_notifications_that_can_be_opened_are_bounded() {
        let on_screen = Openable::default();
        for id in 1..=60 {
            on_screen.add(id, Path::new("/x.desktop"));
        }
        // The oldest are let go.
        assert_eq!(on_screen.take(10), None);
        assert!(on_screen.take(11).is_some());
        assert!(on_screen.take(60).is_some());
    }

    #[test]
    fn running_an_argv_waits_for_it_and_reports_failure() {
        // Not `launch`: the real launcher would open an app on the desktop
        // this runs on.
        let argv = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        assert!(run_argv(&argv(&["true"])).is_ok());
        assert!(run_argv(&argv(&["false"])).is_err());
        assert!(run_argv(&argv(&["/nonexistent/gio", "launch"])).is_err());
    }
}
