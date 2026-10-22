//! The collection's desktop preset (brief 25, phase 3), applied to this person
//! once for each change.
//!
//! `mauvelyd` writes `/var/lib/mauvely-desktop/policy.json` (root's, everyone
//! reads it): `{"version", "preset", "lock": {"look", "layout"}}`, beside the
//! Kiosk files that pin the look and freeze the layout. The version moves when
//! the admin picks another preset or locks the look. This module remembers under
//! `$XDG_STATE_HOME/mauvely/look` the version, preset and look lock it last
//! applied, and applies the preset when any of them differs:
//! - a machine moved to a collection with another preset is applied too;
//! - the look unlocked is applied again, unlocked. While it was locked, the
//!   keys the policy pinned could not be written to the person's own config,
//!   and a stale value there (switching on under Plasma, say) would come back
//!   with the lock gone. Seen on the dev VM, 2026-10-22. The person was held to
//!   the preset all along, so nothing they chose is lost.
//!
//! A new account has no memory, so it is applied at the first sign-in.
//!
//! **Two moments.** `mauvely-look.service` runs this once at each sign-in,
//! before Plasma's shell starts (`--before-shell`); the session's own loop
//! looks every few minutes after that.
//!
//! **Panels** (brief 25, Timur 2026-10-22): a preset change keeps people's
//! panels, and an admin can reset them to the preset's layout. The policy's
//! `panels_version` moves for a reset, and is remembered beside the rest.
//! - **A reset happens before the shell starts:** the person's layout is set
//!   aside, and the shell lays out the preset's, as it does for a new account.
//!   A running shell with the layout locked refuses a layout, and says nothing:
//!   `plasma-apply-lookandfeel --resetLayout` exits 0 and changes nothing
//!   (tried on the dev VM, 2026-10-22). So a reset waits for the next sign-in.
//! - **The window settings** a preset carries (the title-bar buttons, Breeze's
//!   corner radius and menu opacity) are applied from its `layoutdefaults`,
//!   and KWin is told to read them again. Plasma 6.7's
//!   `plasma-apply-lookandfeel` applies no `layoutdefaults` (tried on the dev
//!   VM); the preset's layout script writes the same keys, for System
//!   Settings' own switch.
//!
//! Applying is what System Settings does: `plasma-apply-lookandfeel`, which
//! writes the theme's settings into the person's own config. Unlocked, they can
//! change it afterwards; locked, the Kiosk files keep them from it.
//!
//! Mauvely is light by day and dark at night. Its light theme is applied, the
//! three switching keys are written unless the lock already pins them, and
//! Plasma's switcher (the kded module `lookandfeelautoswitcher`) is restarted:
//! it reads its keys only when they change or it starts, and then puts on the
//! theme for the time of day. Plasma's apply turns switching off, and the
//! restart stops the switcher before its next change of light. The restart is
//! a courtesy: without it, the next sign-in does the same.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::Deserialize;

use crate::Error;

/// What `mauvelyd` writes.
pub const POLICY: &str = "/var/lib/mauvely-desktop/policy.json";

/// The global themes, as `mauvelyd`'s `desktop` names them.
pub const MAUVELY_LIGHT: &str = "com.mauvely.light.desktop";
pub const MAUVELY_DARK: &str = "com.mauvely.dark.desktop";
pub const PLASMA: &str = "com.mauvely.plasma.desktop";

/// Plasma's day and night switcher, a kded module.
pub const SWITCHER: &str = "lookandfeelautoswitcher";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    Mauvely,
    Plasma,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
pub struct Locks {
    pub look: bool,
    pub layout: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Policy {
    pub version: u64,
    pub preset: Option<Preset>,
    pub lock: Locks,
    /// Moves when the admin resets everyone's panels. 0 from an agent older
    /// than it.
    #[serde(default)]
    pub panels_version: u64,
}

impl Policy {
    /// What is remembered of the look once it is applied:
    /// `<version> <preset> <look>`. The memory adds `panels_version`.
    fn stamp(&self) -> String {
        let preset = match self.preset {
            Some(Preset::Mauvely) => "mauvely",
            Some(Preset::Plasma) => "plasma",
            None => "none",
        };
        let look = if self.lock.look { "locked" } else { "open" };
        format!("{} {preset} {look}", self.version)
    }
}

/// When a look is taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum When {
    /// At a sign-in, before Plasma's shell starts: the one moment panels can
    /// be reset.
    BeforeShell,
    /// During the session.
    Session,
}

/// The desktop's tools, so the order of things can be tested without Plasma.
pub trait Look {
    /// Puts the person on a global theme.
    fn apply(&self, theme: &str) -> Result<(), Error>;
    /// The theme's window settings from its `layoutdefaults`, which Plasma's
    /// apply does not write.
    fn window(&self, theme: &str) -> Result<(), Error>;
    /// Sets the person's panel layout aside, so the shell lays out the
    /// preset's when it starts.
    fn set_panels_aside(&self) -> Result<(), Error>;
    /// Writes a key of the `[KDE]` group in the person's `kdeglobals`.
    fn set(&self, key: &str, value: &str) -> Result<(), Error>;
    /// Restarts Plasma's day and night switcher.
    fn restart_switcher(&self) -> Result<(), Error>;
}

/// One look at the policy. Applies the preset when the policy is new to this
/// person, and says whether it did. A failed apply is not remembered, so it is
/// tried again at the next look.
pub fn check(policy: &Path, memory: &Path, look: &dyn Look, when: When) -> Result<bool, Error> {
    let policy: Policy = match fs::read(policy) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", policy.display()))?
        }
        // No agent, or one from before the policy.
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("{}: {e}", policy.display()).into()),
    };
    let stamp = policy.stamp();
    let remembered = match fs::read_to_string(memory) {
        Ok(text) => remembered(&text),
        Err(e) if e.kind() == ErrorKind::NotFound => None,
        Err(e) => return Err(e.into()),
    };
    let look_due = remembered.as_ref().is_none_or(|(look, _)| *look != stamp);
    let panels_due = when == When::BeforeShell
        && remembered
            .as_ref()
            .is_some_and(|(_, panels)| *panels != policy.panels_version);
    if !look_due && !panels_due {
        return Ok(false);
    }
    let applied = match policy.preset {
        Some(preset) => {
            apply(preset, policy.lock.look, look)?;
            if panels_due {
                look.set_panels_aside()?;
            }
            true
        }
        None => false,
    };
    // A reset still owed, during a session, stays owed for the next sign-in.
    // A new account owes none: its first shell lays out the preset it was just
    // put on. With no preset there is nothing to reset to.
    let panels = match &remembered {
        Some((_, owed)) if !panels_due && policy.preset.is_some() => *owed,
        _ => policy.panels_version,
    };
    if let Some(dir) = memory.parent() {
        crate::private_dir(dir)?;
    }
    fs::write(memory, format!("{stamp} {panels}\n"))?;
    Ok(applied)
}

/// The memory's look stamp and panels version. A memory from before panels
/// has no fourth field, and those panels were never reset: 0.
fn remembered(text: &str) -> Option<(String, u64)> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    if fields.len() < 3 {
        return None;
    }
    let panels = fields.get(3).and_then(|p| p.parse().ok()).unwrap_or(0);
    Some((fields[..3].join(" "), panels))
}

fn apply(preset: Preset, look_locked: bool, look: &dyn Look) -> Result<(), Error> {
    let theme = match preset {
        Preset::Mauvely => MAUVELY_LIGHT,
        Preset::Plasma => PLASMA,
    };
    look.apply(theme)?;
    look.window(theme)?;
    match preset {
        Preset::Mauvely => {
            // Locked, the policy already holds them, and a write would fail.
            if !look_locked {
                look.set("DefaultLightLookAndFeel", MAUVELY_LIGHT)?;
                look.set("DefaultDarkLookAndFeel", MAUVELY_DARK)?;
                look.set("AutomaticLookAndFeel", "true")?;
            }
        }
        Preset::Plasma => {}
    }
    if let Err(e) = look.restart_switcher() {
        eprintln!("mauvely-session: the day and night switcher was not restarted: {e}");
    }
    Ok(())
}

#[zbus::proxy(
    interface = "org.kde.kded6",
    default_service = "org.kde.kded6",
    default_path = "/kded",
    gen_async = false
)]
trait Kded {
    // kded's methods are camelCase; zbus would ask for `LoadModule`, which
    // kded answers with UnknownMethod (seen on the dev VM, 2026-10-22).
    #[zbus(name = "loadModule")]
    fn load_module(&self, obj: &str) -> zbus::Result<bool>;
    #[zbus(name = "unloadModule")]
    fn unload_module(&self, obj: &str) -> zbus::Result<bool>;
}

#[zbus::proxy(
    interface = "org.kde.KWin",
    default_service = "org.kde.KWin",
    default_path = "/KWin",
    gen_async = false
)]
trait KWin {
    #[zbus(name = "reconfigure")]
    fn reconfigure(&self) -> zbus::Result<()>;
}

/// The shell's layout, in the person's config: what a reset sets aside.
pub const PANEL_FILES: [&str; 2] = ["plasma-org.kde.plasma.desktop-appletsrc", "plasmashellrc"];

/// Plasma's own tools, by argv, and kded and KWin over the session bus.
pub struct Plasma {
    kded: Option<KdedProxy<'static>>,
    kwin: Option<KWinProxy<'static>>,
    /// The person's `$XDG_CONFIG_HOME`, and where a reset keeps the layout it
    /// set aside.
    config: PathBuf,
    aside: PathBuf,
}

impl Plasma {
    pub fn new(session: &zbus::blocking::Connection, config: PathBuf, state: &Path) -> Self {
        Plasma {
            kded: KdedProxy::new(session).ok(),
            kwin: KWinProxy::new(session).ok(),
            config,
            aside: state.join("mauvely/panels-before-reset"),
        }
    }
}

pub fn apply_argv(theme: &str) -> Vec<String> {
    ["plasma-apply-lookandfeel", "-a", theme]
        .map(String::from)
        .to_vec()
}

/// Moves the layout files from `config` into `aside`, replacing what an earlier
/// reset kept there. A file that is not there is fine: a layout never saved.
pub fn panels_aside(config: &Path, aside: &Path) -> Result<(), Error> {
    if let Some(parent) = aside.parent() {
        crate::private_dir(parent)?;
    }
    crate::private_dir(aside)?;
    for name in PANEL_FILES {
        let from = config.join(name);
        match fs::rename(&from, aside.join(name)) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let _ = fs::remove_file(aside.join(name));
            }
            Err(e) => return Err(format!("{}: {e}", from.display()).into()),
        }
    }
    Ok(())
}

/// One key a `layoutdefaults` sets: `[file][group]…` then `key=value`.
#[derive(Debug, PartialEq, Eq)]
pub struct LayoutDefault {
    pub file: String,
    pub groups: Vec<String>,
    pub key: String,
    pub value: String,
}

/// A look-and-feel package's `layoutdefaults`. A section that names no group,
/// or a file that is not a plain name, is skipped, as is a key with Kiosk or
/// locale markers.
pub fn layout_defaults(text: &str) -> Vec<LayoutDefault> {
    let mut out = Vec::new();
    let mut section: Option<(String, Vec<String>)> = None;
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(inner) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            let mut parts = inner.split("][").map(str::to_owned);
            let file = parts.next().unwrap_or_default();
            let groups: Vec<String> = parts.collect();
            let plain =
                !file.is_empty() && !file.contains(['/', '\\']) && file != "." && file != "..";
            section = (plain && !groups.is_empty() && groups.iter().all(|g| !g.is_empty()))
                .then_some((file, groups));
            continue;
        }
        let (Some((file, groups)), Some((key, value))) = (&section, line.split_once('=')) else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() || key.contains('[') {
            continue;
        }
        out.push(LayoutDefault {
            file: file.clone(),
            groups: groups.clone(),
            key: key.to_owned(),
            value: value.trim().to_owned(),
        });
    }
    out
}

/// `kwriteconfig6` for one default. The value goes after `--`: Breeze's own
/// corner radius is `-1`, which would otherwise read as an option.
pub fn default_argv(d: &LayoutDefault) -> Vec<String> {
    let mut argv = vec!["kwriteconfig6".to_owned(), "--file".into(), d.file.clone()];
    for group in &d.groups {
        argv.push("--group".into());
        argv.push(group.clone());
    }
    argv.extend(["--key".into(), d.key.clone(), "--".into(), d.value.clone()]);
    argv
}

/// Where Plasma finds a theme's file: the person's own data first, then the
/// system's, as `plasma-apply-lookandfeel` looks.
pub fn package_file(bases: &[PathBuf], theme: &str, name: &str) -> Option<PathBuf> {
    bases
        .iter()
        .map(|b| {
            b.join("plasma/look-and-feel")
                .join(theme)
                .join("contents")
                .join(name)
        })
        .find(|p| p.is_file())
}

/// `$XDG_DATA_HOME`, then `$XDG_DATA_DIRS`, with the spec's defaults.
fn data_bases() -> Vec<PathBuf> {
    let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
    let home = var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .or_else(|| var("HOME").map(|h| PathBuf::from(h).join(".local/share")));
    let dirs = var("XDG_DATA_DIRS").unwrap_or_else(|| "/usr/local/share:/usr/share".into());
    home.into_iter()
        .chain(dirs.split(':').filter(|d| !d.is_empty()).map(PathBuf::from))
        .collect()
}

pub fn set_argv(key: &str, value: &str) -> Vec<String> {
    [
        "kwriteconfig6",
        "--file",
        "kdeglobals",
        "--group",
        "KDE",
        "--key",
        key,
        value,
    ]
    .map(String::from)
    .to_vec()
}

impl Look for Plasma {
    fn apply(&self, theme: &str) -> Result<(), Error> {
        run(&apply_argv(theme))
    }

    fn set_panels_aside(&self) -> Result<(), Error> {
        panels_aside(&self.config, &self.aside)
    }

    fn window(&self, theme: &str) -> Result<(), Error> {
        let Some(path) = package_file(&data_bases(), theme, "layoutdefaults") else {
            return Ok(());
        };
        let text = fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        for d in layout_defaults(&text) {
            run(&default_argv(&d))?;
        }
        // KWin reads its decoration settings again; without it, at the next
        // sign-in.
        if let Some(kwin) = &self.kwin
            && let Err(e) = kwin.reconfigure()
        {
            eprintln!("mauvely-session: KWin was not told to reconfigure: {e}");
        }
        Ok(())
    }

    fn set(&self, key: &str, value: &str) -> Result<(), Error> {
        run(&set_argv(key, value))
    }

    fn restart_switcher(&self) -> Result<(), Error> {
        let kded = self.kded.as_ref().ok_or("no kded on the session bus")?;
        // Unloading one that is not loaded answers false, which is fine.
        kded.unload_module(SWITCHER)?;
        if !kded.load_module(SWITCHER)? {
            return Err(format!("kded did not load {SWITCHER}").into());
        }
        Ok(())
    }
}

/// Runs an argv and waits. Its output goes to the journal with ours.
fn run(argv: &[String]) -> Result<(), Error> {
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
    use std::cell::RefCell;
    use std::path::PathBuf;

    #[derive(Default)]
    struct Fake {
        calls: RefCell<Vec<String>>,
        fail_apply: bool,
        fail_restart: bool,
        fail_aside: bool,
    }

    impl Look for Fake {
        fn apply(&self, theme: &str) -> Result<(), Error> {
            self.calls.borrow_mut().push(format!("apply {theme}"));
            if self.fail_apply {
                return Err("plasma-apply-lookandfeel: exit status: 1".into());
            }
            Ok(())
        }
        fn window(&self, theme: &str) -> Result<(), Error> {
            self.calls.borrow_mut().push(format!("window {theme}"));
            Ok(())
        }
        fn set_panels_aside(&self) -> Result<(), Error> {
            self.calls.borrow_mut().push("aside".into());
            if self.fail_aside {
                return Err("plasmashellrc: Permission denied".into());
            }
            Ok(())
        }
        fn set(&self, key: &str, value: &str) -> Result<(), Error> {
            self.calls.borrow_mut().push(format!("set {key}={value}"));
            Ok(())
        }
        fn restart_switcher(&self) -> Result<(), Error> {
            self.calls.borrow_mut().push("restart".into());
            if self.fail_restart {
                return Err("no kded on the session bus".into());
            }
            Ok(())
        }
    }

    impl Fake {
        fn take(&self) -> Vec<String> {
            self.calls.borrow_mut().drain(..).collect()
        }
    }

    struct Rig {
        dir: PathBuf,
    }

    impl Rig {
        fn new() -> Self {
            Rig {
                dir: temp_dir("look"),
            }
        }
        fn policy(&self) -> PathBuf {
            self.dir.join("desktop/policy.json")
        }
        fn memory(&self) -> PathBuf {
            self.dir.join("state/mauvely/look")
        }
        /// Exactly what mauvelyd writes.
        fn write(&self, version: u64, preset: &str, look: bool) {
            self.write_panels(version, preset, look, 0);
        }
        fn write_panels(&self, version: u64, preset: &str, look: bool, panels: u64) {
            fs::create_dir_all(self.dir.join("desktop")).unwrap();
            fs::write(
                self.policy(),
                format!(
                    "{{\"version\":{version},\"preset\":{preset},\"lock\":{{\"look\":{look},\"layout\":false}},\"panels_version\":{panels}}}\n"
                ),
            )
            .unwrap();
        }
        /// An account that already has the preset, as remembered.
        fn remember(&self, line: &str) {
            fs::create_dir_all(self.dir.join("state/mauvely")).unwrap();
            fs::write(self.memory(), line).unwrap();
        }
        fn check(&self, look: &Fake) -> Result<bool, Error> {
            check(&self.policy(), &self.memory(), look, When::Session)
        }
        fn check_at_sign_in(&self, look: &Fake) -> Result<bool, Error> {
            check(&self.policy(), &self.memory(), look, When::BeforeShell)
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    /// The preset applied, keeping panels.
    const MAUVELY_UNLOCKED: [&str; 6] = [
        "apply com.mauvely.light.desktop",
        "window com.mauvely.light.desktop",
        "set DefaultLightLookAndFeel=com.mauvely.light.desktop",
        "set DefaultDarkLookAndFeel=com.mauvely.dark.desktop",
        "set AutomaticLookAndFeel=true",
        "restart",
    ];

    #[test]
    fn nothing_without_a_policy() {
        let rig = Rig::new();
        let look = Fake::default();
        assert!(!rig.check(&look).unwrap());
        assert!(look.take().is_empty());
        assert!(!rig.memory().exists());
    }

    #[test]
    fn a_new_account_is_put_on_the_preset_once() {
        let rig = Rig::new();
        rig.write(1, "\"mauvely\"", false);
        let look = Fake::default();
        assert!(rig.check(&look).unwrap());
        assert_eq!(look.take(), MAUVELY_UNLOCKED);
        assert_eq!(
            fs::read_to_string(rig.memory()).unwrap(),
            "1 mauvely open 0\n"
        );
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(rig.dir.join("state/mauvely"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o700);

        assert!(!rig.check(&look).unwrap());
        assert!(look.take().is_empty());
    }

    #[test]
    fn a_new_version_applies_again_and_so_does_another_preset_at_the_same_one() {
        let rig = Rig::new();
        let look = Fake::default();
        rig.write(1, "\"mauvely\"", false);
        rig.check(&look).unwrap();
        look.take();

        rig.write(2, "\"mauvely\"", true);
        assert!(rig.check(&look).unwrap());
        // Locked, the switching keys are the policy's. Panels are kept.
        assert_eq!(
            look.take(),
            [
                "apply com.mauvely.light.desktop",
                "window com.mauvely.light.desktop",
                "restart"
            ]
        );

        // Moved to a collection whose version happens to be the same.
        rig.write(2, "\"plasma\"", true);
        assert!(rig.check(&look).unwrap());
        assert_eq!(
            look.take(),
            [
                "apply com.mauvely.plasma.desktop",
                "window com.mauvely.plasma.desktop",
                "restart"
            ]
        );
        assert_eq!(
            fs::read_to_string(rig.memory()).unwrap(),
            "2 plasma locked 0\n"
        );
    }

    #[test]
    fn the_look_unlocked_is_applied_again_unlocked_and_once() {
        let rig = Rig::new();
        let look = Fake::default();
        rig.write(4, "\"mauvely\"", true);
        rig.check(&look).unwrap();
        assert_eq!(
            look.take(),
            [
                "apply com.mauvely.light.desktop",
                "window com.mauvely.light.desktop",
                "restart"
            ]
        );

        // The server does not move the version for an unlock.
        rig.write(4, "\"mauvely\"", false);
        assert!(rig.check(&look).unwrap());
        assert_eq!(look.take(), MAUVELY_UNLOCKED);
        assert_eq!(
            fs::read_to_string(rig.memory()).unwrap(),
            "4 mauvely open 0\n"
        );
        assert!(!rig.check(&look).unwrap());
        assert!(look.take().is_empty());
    }

    #[test]
    fn no_preset_applies_nothing_and_a_later_one_still_does() {
        let rig = Rig::new();
        let look = Fake::default();
        rig.write(0, "null", true);
        assert!(!rig.check(&look).unwrap());
        assert!(look.take().is_empty());
        assert_eq!(
            fs::read_to_string(rig.memory()).unwrap(),
            "0 none locked 0\n"
        );

        // Somebody who has been signing in all along keeps their panels.
        rig.write(1, "\"plasma\"", true);
        assert!(rig.check(&look).unwrap());
        assert_eq!(
            look.take(),
            [
                "apply com.mauvely.plasma.desktop",
                "window com.mauvely.plasma.desktop",
                "restart"
            ]
        );
    }

    #[test]
    fn a_failed_apply_is_not_remembered_and_is_tried_again() {
        let rig = Rig::new();
        rig.write(1, "\"plasma\"", false);
        let failing = Fake {
            fail_apply: true,
            ..Fake::default()
        };
        assert!(rig.check(&failing).is_err());
        assert!(!rig.memory().exists());
        assert_eq!(failing.take(), ["apply com.mauvely.plasma.desktop"]);

        let look = Fake::default();
        assert!(rig.check(&look).unwrap());
        assert_eq!(
            look.take(),
            [
                "apply com.mauvely.plasma.desktop",
                "window com.mauvely.plasma.desktop",
                "restart"
            ]
        );
    }

    #[test]
    fn a_switcher_that_does_not_restart_does_not_undo_the_apply() {
        let rig = Rig::new();
        rig.write(1, "\"mauvely\"", false);
        let look = Fake {
            fail_restart: true,
            ..Fake::default()
        };
        assert!(rig.check(&look).unwrap());
        assert_eq!(look.take(), MAUVELY_UNLOCKED);
        assert_eq!(
            fs::read_to_string(rig.memory()).unwrap(),
            "1 mauvely open 0\n"
        );
    }

    #[test]
    fn a_policy_it_cannot_read_applies_nothing() {
        let rig = Rig::new();
        let look = Fake::default();
        for garbled in [
            "{ not json",
            r#"{"version":1,"preset":"classic","lock":{"look":false,"layout":false}}"#,
        ] {
            fs::create_dir_all(rig.dir.join("desktop")).unwrap();
            fs::write(rig.policy(), garbled).unwrap();
            assert!(rig.check(&look).is_err(), "{garbled}");
        }
        assert!(look.take().is_empty());
        assert!(!rig.memory().exists());
    }

    #[test]
    fn plasmas_own_tools_by_argv() {
        assert_eq!(
            apply_argv(MAUVELY_LIGHT),
            [
                "plasma-apply-lookandfeel",
                "-a",
                "com.mauvely.light.desktop"
            ]
        );
        assert_eq!(
            set_argv("AutomaticLookAndFeel", "true"),
            [
                "kwriteconfig6",
                "--file",
                "kdeglobals",
                "--group",
                "KDE",
                "--key",
                "AutomaticLookAndFeel",
                "true"
            ]
        );
    }

    #[test]
    fn a_reset_waits_for_the_next_sign_in_and_happens_once() {
        let rig = Rig::new();
        let look = Fake::default();
        // What the session before panels remembered: three fields. The
        // upgrade applies nothing, at a sign-in or after.
        rig.remember("3 plasma open\n");
        rig.write(3, "\"plasma\"", false);
        assert!(!rig.check_at_sign_in(&look).unwrap());
        assert!(!rig.check(&look).unwrap());
        assert!(look.take().is_empty());

        // The admin resets panels. A running shell can't take it.
        rig.write_panels(3, "\"plasma\"", false, 1);
        assert!(!rig.check(&look).unwrap());
        assert!(look.take().is_empty());

        // A preset change meanwhile is applied, and the reset is still owed.
        rig.write_panels(4, "\"mauvely\"", false, 1);
        assert!(rig.check(&look).unwrap());
        assert_eq!(look.take(), MAUVELY_UNLOCKED);
        assert_eq!(
            fs::read_to_string(rig.memory()).unwrap(),
            "4 mauvely open 0\n"
        );

        // At the next sign-in, before the shell: the preset, then its layout
        // set aside for the shell to lay out the preset's. Applied first, so a
        // failed apply leaves the person's panels where they were.
        assert!(rig.check_at_sign_in(&look).unwrap());
        assert_eq!(
            look.take(),
            [
                "apply com.mauvely.light.desktop",
                "window com.mauvely.light.desktop",
                "set DefaultLightLookAndFeel=com.mauvely.light.desktop",
                "set DefaultDarkLookAndFeel=com.mauvely.dark.desktop",
                "set AutomaticLookAndFeel=true",
                "restart",
                "aside"
            ]
        );
        assert_eq!(
            fs::read_to_string(rig.memory()).unwrap(),
            "4 mauvely open 1\n"
        );
        assert!(!rig.check_at_sign_in(&look).unwrap());
        assert!(!rig.check(&look).unwrap());
        assert!(look.take().is_empty());
    }

    #[test]
    fn a_new_account_owes_no_reset() {
        let rig = Rig::new();
        let look = Fake::default();
        rig.write_panels(2, "\"plasma\"", true, 5);
        assert!(rig.check_at_sign_in(&look).unwrap());
        assert_eq!(
            look.take(),
            [
                "apply com.mauvely.plasma.desktop",
                "window com.mauvely.plasma.desktop",
                "restart"
            ]
        );
        assert_eq!(
            fs::read_to_string(rig.memory()).unwrap(),
            "2 plasma locked 5\n"
        );
    }

    #[test]
    fn a_reset_that_cannot_set_the_layout_aside_is_tried_again() {
        let rig = Rig::new();
        rig.remember("3 mauvely open 0\n");
        rig.write_panels(3, "\"mauvely\"", false, 1);
        let stuck = Fake {
            fail_aside: true,
            ..Fake::default()
        };
        assert!(rig.check_at_sign_in(&stuck).is_err());
        assert_eq!(
            fs::read_to_string(rig.memory()).unwrap(),
            "3 mauvely open 0\n"
        );
        let look = Fake::default();
        assert!(rig.check_at_sign_in(&look).unwrap());
        assert!(look.take().contains(&"aside".to_owned()));
    }

    #[test]
    fn the_layout_is_set_aside_replacing_the_last_one_kept() {
        let rig = Rig::new();
        let config = rig.dir.join("config");
        let aside = rig.dir.join("state/mauvely/panels-before-reset");
        fs::create_dir_all(&config).unwrap();
        fs::write(config.join(PANEL_FILES[0]), "new layout").unwrap();
        fs::create_dir_all(&aside).unwrap();
        fs::write(aside.join(PANEL_FILES[0]), "older layout").unwrap();
        fs::write(aside.join(PANEL_FILES[1]), "older shell").unwrap();
        // No plasmashellrc: a layout never saved is fine.
        panels_aside(&config, &aside).unwrap();
        assert!(!config.join(PANEL_FILES[0]).exists());
        assert_eq!(
            fs::read_to_string(aside.join(PANEL_FILES[0])).unwrap(),
            "new layout"
        );
        assert!(!aside.join(PANEL_FILES[1]).exists());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&aside).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[test]
    fn layoutdefaults_become_kwriteconfig_calls() {
        let text = "# The Plasma preset's window settings.\n\
            [kwinrc][org.kde.kdecoration2]\n\
            ButtonsOnLeft=MSE\n\
            ButtonsOnRight=HIAX\n\
            \n\
            [breezerc][Common]\n\
            CornerRadius=-1\n\
            [breezerc][Style]\n\
            MenuOpacity=100\n\
            [kwinrc]\n\
            NoGroup=1\n\
            [../evil][G]\n\
            K=v\n\
            [kdeglobals][KDE]\n\
            Pinned[$i]=x\n\
            Empty=\n";
        let all = layout_defaults(text);
        let argv: Vec<Vec<String>> = all.iter().map(default_argv).collect();
        assert_eq!(
            argv,
            [
                [
                    "kwriteconfig6",
                    "--file",
                    "kwinrc",
                    "--group",
                    "org.kde.kdecoration2",
                    "--key",
                    "ButtonsOnLeft",
                    "--",
                    "MSE"
                ],
                [
                    "kwriteconfig6",
                    "--file",
                    "kwinrc",
                    "--group",
                    "org.kde.kdecoration2",
                    "--key",
                    "ButtonsOnRight",
                    "--",
                    "HIAX"
                ],
                [
                    "kwriteconfig6",
                    "--file",
                    "breezerc",
                    "--group",
                    "Common",
                    "--key",
                    "CornerRadius",
                    "--",
                    "-1"
                ],
                [
                    "kwriteconfig6",
                    "--file",
                    "breezerc",
                    "--group",
                    "Style",
                    "--key",
                    "MenuOpacity",
                    "--",
                    "100"
                ],
                [
                    "kwriteconfig6",
                    "--file",
                    "kdeglobals",
                    "--group",
                    "KDE",
                    "--key",
                    "Empty",
                    "--",
                    ""
                ],
            ]
            .map(|a| a.map(String::from).to_vec())
        );
    }

    #[test]
    fn a_themes_file_is_the_persons_own_first() {
        let rig = Rig::new();
        let home = rig.dir.join("home");
        let usr = rig.dir.join("usr");
        let at = |base: &Path| {
            base.join("plasma/look-and-feel")
                .join(PLASMA)
                .join("contents/layoutdefaults")
        };
        fs::create_dir_all(at(&usr).parent().unwrap()).unwrap();
        fs::write(at(&usr), "").unwrap();
        let bases = [home.clone(), usr.clone()];
        assert_eq!(
            package_file(&bases, PLASMA, "layoutdefaults"),
            Some(at(&usr))
        );
        fs::create_dir_all(at(&home).parent().unwrap()).unwrap();
        fs::write(at(&home), "").unwrap();
        assert_eq!(
            package_file(&bases, PLASMA, "layoutdefaults"),
            Some(at(&home))
        );
        assert_eq!(package_file(&bases, MAUVELY_DARK, "layoutdefaults"), None);
    }
}
