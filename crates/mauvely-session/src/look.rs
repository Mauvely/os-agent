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
use std::path::Path;
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
}

impl Policy {
    /// What is remembered once it is applied: `<version> <preset> <look>`.
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

/// The desktop's tools, so the order of things can be tested without Plasma.
pub trait Look {
    /// Puts the person on a global theme.
    fn apply(&self, theme: &str) -> Result<(), Error>;
    /// Writes a key of the `[KDE]` group in the person's `kdeglobals`.
    fn set(&self, key: &str, value: &str) -> Result<(), Error>;
    /// Restarts Plasma's day and night switcher.
    fn restart_switcher(&self) -> Result<(), Error>;
}

/// One look at the policy. Applies the preset when the policy is new to this
/// person, and says whether it did. A failed apply is not remembered, so it is
/// tried again at the next look.
pub fn check(policy: &Path, memory: &Path, look: &dyn Look) -> Result<bool, Error> {
    let policy: Policy = match fs::read(policy) {
        Ok(bytes) => {
            serde_json::from_slice(&bytes).map_err(|e| format!("{}: {e}", policy.display()))?
        }
        // No agent, or one from before the policy.
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(format!("{}: {e}", policy.display()).into()),
    };
    let stamp = policy.stamp();
    match fs::read_to_string(memory) {
        Ok(applied) if applied.trim() == stamp => return Ok(false),
        Err(e) if e.kind() != ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    let applied = match policy.preset {
        Some(preset) => {
            apply(preset, policy.lock.look, look)?;
            true
        }
        None => false,
    };
    if let Some(dir) = memory.parent() {
        crate::private_dir(dir)?;
    }
    fs::write(memory, format!("{stamp}\n"))?;
    Ok(applied)
}

fn apply(preset: Preset, look_locked: bool, look: &dyn Look) -> Result<(), Error> {
    match preset {
        Preset::Mauvely => {
            look.apply(MAUVELY_LIGHT)?;
            // Locked, the policy already holds them, and a write would fail.
            if !look_locked {
                look.set("DefaultLightLookAndFeel", MAUVELY_LIGHT)?;
                look.set("DefaultDarkLookAndFeel", MAUVELY_DARK)?;
                look.set("AutomaticLookAndFeel", "true")?;
            }
        }
        Preset::Plasma => look.apply(PLASMA)?,
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
    fn load_module(&self, obj: &str) -> zbus::Result<bool>;
    fn unload_module(&self, obj: &str) -> zbus::Result<bool>;
}

/// Plasma's own tools, by argv, and kded over the session bus.
pub struct Plasma {
    kded: Option<KdedProxy<'static>>,
}

impl Plasma {
    pub fn new(session: &zbus::blocking::Connection) -> Self {
        Plasma {
            kded: KdedProxy::new(session).ok(),
        }
    }
}

pub fn apply_argv(theme: &str) -> Vec<String> {
    ["plasma-apply-lookandfeel", "-a", theme]
        .map(String::from)
        .to_vec()
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
    }

    impl Look for Fake {
        fn apply(&self, theme: &str) -> Result<(), Error> {
            self.calls.borrow_mut().push(format!("apply {theme}"));
            if self.fail_apply {
                return Err("plasma-apply-lookandfeel: exit status: 1".into());
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
            fs::create_dir_all(self.dir.join("desktop")).unwrap();
            fs::write(
                self.policy(),
                format!(
                    "{{\"version\":{version},\"preset\":{preset},\"lock\":{{\"look\":{look},\"layout\":false}}}}\n"
                ),
            )
            .unwrap();
        }
        fn check(&self, look: &Fake) -> Result<bool, Error> {
            check(&self.policy(), &self.memory(), look)
        }
    }

    impl Drop for Rig {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.dir);
        }
    }

    const MAUVELY_UNLOCKED: [&str; 5] = [
        "apply com.mauvely.light.desktop",
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
            "1 mauvely open\n"
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
        // Locked, the switching keys are the policy's.
        assert_eq!(look.take(), ["apply com.mauvely.light.desktop", "restart"]);

        // Moved to a collection whose version happens to be the same.
        rig.write(2, "\"plasma\"", true);
        assert!(rig.check(&look).unwrap());
        assert_eq!(look.take(), ["apply com.mauvely.plasma.desktop", "restart"]);
        assert_eq!(
            fs::read_to_string(rig.memory()).unwrap(),
            "2 plasma locked\n"
        );
    }

    #[test]
    fn the_look_unlocked_is_applied_again_unlocked_and_once() {
        let rig = Rig::new();
        let look = Fake::default();
        rig.write(4, "\"mauvely\"", true);
        rig.check(&look).unwrap();
        assert_eq!(look.take(), ["apply com.mauvely.light.desktop", "restart"]);

        // The server does not move the version for an unlock.
        rig.write(4, "\"mauvely\"", false);
        assert!(rig.check(&look).unwrap());
        assert_eq!(look.take(), MAUVELY_UNLOCKED);
        assert_eq!(
            fs::read_to_string(rig.memory()).unwrap(),
            "4 mauvely open\n"
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
        assert_eq!(fs::read_to_string(rig.memory()).unwrap(), "0 none locked\n");

        rig.write(1, "\"plasma\"", true);
        assert!(rig.check(&look).unwrap());
        assert_eq!(look.take(), ["apply com.mauvely.plasma.desktop", "restart"]);
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
        assert_eq!(look.take(), ["apply com.mauvely.plasma.desktop", "restart"]);
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
            "1 mauvely open\n"
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
}
