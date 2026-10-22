//! The collection's say over the desktop look (brief 25, phase 3), written as
//! KDE configuration into a directory of the agent's own:
//!
//! - `xdg/kdeglobals`, which the image puts in every session's
//!   `XDG_CONFIG_DIRS`, above `/etc/xdg` and below `~/.config/kdedefaults`.
//!   Since kdedefaults and the person's own files come later, a key that has
//!   to hold is marked immutable, KDE Kiosk's `[$i]`;
//! - `policy.json`, for mauvely-session, which applies the preset once for
//!   each `version`.
//!
//! The directory is root's and everyone's to read, as both files are.
//!
//! What each part does on Plasma 6.7 (tried on the dev VM, 2026-10-22):
//! - **Mauvely** switches between its light and dark global themes on Plasma's
//!   schedule. The switcher writes `LookAndFeelPackage` at each change, so the
//!   look lock pins the three switching keys and never that one: pinned, the
//!   switcher could not go back to light.
//! - **Plasma** is one global theme with switching off; locked, both pinned.
//! - **The look lock** also takes System Settings' look pages away.
//! - **The layout lock** makes the whole shell system-immutable: no edit mode,
//!   no adding, moving or removing panels or widgets, no pinning apps to the
//!   taskbar or unpinning them, and Plasma's scripting refuses too. With the look locked as well, widgets and the desktop can't
//!   be configured either, which is what keeps the desktop's own wallpaper
//!   dialog shut. Plasma can't hide that dialog from a desktop that isn't
//!   locked.
//!
//! Kiosk keeps the settings out of reach in Plasma's own tools. A person with a
//! shell can still go around it.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::state::write_atomic;

pub const MAUVELY_LIGHT: &str = "com.mauvely.light.desktop";
pub const MAUVELY_DARK: &str = "com.mauvely.dark.desktop";
pub const PLASMA: &str = "com.mauvely.plasma.desktop";

/// System Settings' pages for the look, by their Plasma 6.7 plugin ids:
/// global theme, colours, Plasma style, application style, window
/// decorations and Breeze's own decoration settings, icons, cursors, fonts,
/// wallpaper and splash screen.
pub const LOOK_MODULES: [&str; 11] = [
    "kcm_lookandfeel",
    "kcm_colors",
    "kcm_desktoptheme",
    "kcm_style",
    "kcm_kwindecoration",
    "kcm_breezedecoration",
    "kcm_icons",
    "kcm_cursortheme",
    "kcm_fonts",
    "kcm_wallpaper",
    "kcm_splashscreen",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Preset {
    Mauvely,
    Plasma,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Locks {
    pub look: bool,
    pub layout: bool,
}

/// `desired.desktop` from the check-in answer, and `policy.json` as written.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Policy {
    pub version: u64,
    /// `None` leaves the image's default alone.
    pub preset: Option<Preset>,
    pub lock: Locks,
}

impl Policy {
    /// A preset this agent does not know is an error, and the files stay as
    /// they were.
    pub fn from_answer(value: &serde_json::Value) -> Result<Self, Error> {
        serde_json::from_value(value.clone()).map_err(|e| Error::json("desired.desktop", e))
    }

    /// The `kdeglobals` this policy needs, or `None` when it asks for nothing.
    pub fn kdeglobals(&self) -> Option<String> {
        if self.preset.is_none() && !self.lock.look && !self.lock.layout {
            return None;
        }
        // A key the look lock pins.
        let pin = |key: &str| {
            if self.lock.look {
                format!("{key}[$i]")
            } else {
                key.to_owned()
            }
        };
        let mut text = String::from(
            "# Written by mauvelyd from the collection's desktop policy. Changes here are\n\
             # replaced at the next check-in.\n",
        );
        match self.preset {
            Some(Preset::Mauvely) => {
                text += &format!(
                    "\n[KDE]\n{}=true\n{}={MAUVELY_DARK}\n{}={MAUVELY_LIGHT}\nLookAndFeelPackage={MAUVELY_LIGHT}\n",
                    pin("AutomaticLookAndFeel"),
                    pin("DefaultDarkLookAndFeel"),
                    pin("DefaultLightLookAndFeel"),
                );
            }
            Some(Preset::Plasma) => {
                text += &format!(
                    "\n[KDE]\n{}=false\n{}={PLASMA}\n",
                    pin("AutomaticLookAndFeel"),
                    pin("LookAndFeelPackage"),
                );
            }
            None => {}
        }
        if self.lock.layout {
            text += "\n[KDE Action Restrictions][$i]\nplasma/plasmashell/unlockedDesktop=false\n";
            if self.lock.look {
                text += "plasma/allow_configure_when_locked=false\n";
            }
        }
        if self.lock.look {
            text += "\n[KDE Control Module Restrictions][$i]\n";
            for module in LOOK_MODULES {
                text += &format!("{module}=false\n");
            }
        }
        Some(text)
    }
}

/// Brings `dir` to `policy`, and says whether anything changed. A file that
/// already says the same is left alone.
pub fn apply(dir: &Path, policy: &Policy) -> Result<bool, Error> {
    let xdg = dir.join("xdg");
    public_dir(dir)?;
    public_dir(&xdg)?;

    let mut changed = false;
    let kdeglobals = xdg.join("kdeglobals");
    match policy.kdeglobals() {
        Some(text) => changed |= write_if_changed(&kdeglobals, text.as_bytes())?,
        None => match fs::remove_file(&kdeglobals) {
            Ok(()) => changed = true,
            Err(e) if e.kind() == ErrorKind::NotFound => {}
            Err(e) => return Err(Error::io(&kdeglobals, e)),
        },
    }
    let mut json = serde_json::to_vec(policy).map_err(|e| Error::json("policy.json", e))?;
    json.push(b'\n');
    changed |= write_if_changed(&dir.join("policy.json"), &json)?;
    Ok(changed)
}

fn write_if_changed(path: &Path, bytes: &[u8]) -> Result<bool, Error> {
    if fs::read(path).is_ok_and(|old| old == bytes) {
        return Ok(false);
    }
    write_atomic(path, bytes, 0o644)?;
    Ok(true)
}

/// Makes `dir` `0755`, and puts it back to `0755` if it is not.
fn public_dir(dir: &Path) -> Result<(), Error> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o755)
        .create(dir)
        .map_err(|e| Error::io(dir, e))?;
    let mode = fs::metadata(dir)
        .map_err(|e| Error::io(dir, e))?
        .permissions()
        .mode();
    if mode & 0o7777 != 0o755 {
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))
            .map_err(|e| Error::io(dir, e))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::TempDir;
    use serde_json::json;

    fn policy(preset: Option<Preset>, look: bool, layout: bool) -> Policy {
        Policy {
            version: 3,
            preset,
            lock: Locks { look, layout },
        }
    }

    const HEAD: &str = "# Written by mauvelyd from the collection's desktop policy. Changes here are\n# replaced at the next check-in.\n";
    const MODULES: &str = "\n[KDE Control Module Restrictions][$i]\nkcm_lookandfeel=false\nkcm_colors=false\nkcm_desktoptheme=false\nkcm_style=false\nkcm_kwindecoration=false\nkcm_breezedecoration=false\nkcm_icons=false\nkcm_cursortheme=false\nkcm_fonts=false\nkcm_wallpaper=false\nkcm_splashscreen=false\n";

    #[test]
    fn reads_the_answer_and_refuses_what_it_does_not_know() {
        let p = Policy::from_answer(
            &json!({"preset": "mauvely", "lock": {"look": true, "layout": false}, "version": 7}),
        )
        .unwrap();
        assert_eq!(
            p,
            Policy {
                version: 7,
                preset: Some(Preset::Mauvely),
                lock: Locks {
                    look: true,
                    layout: false
                }
            }
        );
        let none = json!({"preset": null, "lock": {"look": false, "layout": false}, "version": 0});
        assert_eq!(Policy::from_answer(&none).unwrap().preset, None);

        for bad in [
            json!({"preset": "classic", "lock": {"look": false, "layout": false}, "version": 1}),
            json!({"preset": "Mauvely", "lock": {"look": false, "layout": false}, "version": 1}),
            json!({"preset": "plasma", "lock": {"look": "yes", "layout": false}, "version": 1}),
            json!({"preset": "plasma", "lock": {"look": true, "layout": false}}),
            json!({"preset": "plasma", "version": 1}),
            json!("plasma"),
        ] {
            assert!(Policy::from_answer(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn says_nothing_with_no_preset_and_no_lock() {
        assert_eq!(policy(None, false, false).kdeglobals(), None);
    }

    #[test]
    fn mauvely_switches_by_day_and_night_and_the_lock_pins_the_switch() {
        assert_eq!(
            policy(Some(Preset::Mauvely), false, false)
                .kdeglobals()
                .unwrap(),
            format!(
                "{HEAD}\n[KDE]\nAutomaticLookAndFeel=true\nDefaultDarkLookAndFeel=com.mauvely.dark.desktop\nDefaultLightLookAndFeel=com.mauvely.light.desktop\nLookAndFeelPackage=com.mauvely.light.desktop\n"
            )
        );
        // LookAndFeelPackage is never pinned: the switcher writes it.
        assert_eq!(
            policy(Some(Preset::Mauvely), true, false)
                .kdeglobals()
                .unwrap(),
            format!(
                "{HEAD}\n[KDE]\nAutomaticLookAndFeel[$i]=true\nDefaultDarkLookAndFeel[$i]=com.mauvely.dark.desktop\nDefaultLightLookAndFeel[$i]=com.mauvely.light.desktop\nLookAndFeelPackage=com.mauvely.light.desktop\n{MODULES}"
            )
        );
    }

    #[test]
    fn plasma_turns_switching_off_and_the_lock_pins_both() {
        assert_eq!(
            policy(Some(Preset::Plasma), false, false)
                .kdeglobals()
                .unwrap(),
            format!(
                "{HEAD}\n[KDE]\nAutomaticLookAndFeel=false\nLookAndFeelPackage=com.mauvely.plasma.desktop\n"
            )
        );
        assert_eq!(
            policy(Some(Preset::Plasma), true, false)
                .kdeglobals()
                .unwrap(),
            format!(
                "{HEAD}\n[KDE]\nAutomaticLookAndFeel[$i]=false\nLookAndFeelPackage[$i]=com.mauvely.plasma.desktop\n{MODULES}"
            )
        );
    }

    #[test]
    fn the_layout_lock_freezes_the_shell_and_with_the_look_its_settings_too() {
        assert_eq!(
            policy(None, false, true).kdeglobals().unwrap(),
            format!(
                "{HEAD}\n[KDE Action Restrictions][$i]\nplasma/plasmashell/unlockedDesktop=false\n"
            )
        );
        assert_eq!(
            policy(Some(Preset::Plasma), true, true)
                .kdeglobals()
                .unwrap(),
            format!(
                "{HEAD}\n[KDE]\nAutomaticLookAndFeel[$i]=false\nLookAndFeelPackage[$i]=com.mauvely.plasma.desktop\n\n[KDE Action Restrictions][$i]\nplasma/plasmashell/unlockedDesktop=false\nplasma/allow_configure_when_locked=false\n{MODULES}"
            )
        );
    }

    #[test]
    fn the_look_locked_with_no_preset_pins_nothing_and_takes_the_pages() {
        assert_eq!(
            policy(None, true, false).kdeglobals().unwrap(),
            format!("{HEAD}{MODULES}")
        );
    }

    fn mode(p: &Path) -> u32 {
        fs::metadata(p).unwrap().permissions().mode() & 0o7777
    }

    #[test]
    fn writes_both_files_for_everyone_to_read_and_only_when_they_change() {
        let tmp = TempDir::new();
        let dir = tmp.path().join("mauvely-desktop");
        let locked = policy(Some(Preset::Mauvely), true, true);

        assert!(apply(&dir, &locked).unwrap());
        let kdeglobals = dir.join("xdg/kdeglobals");
        assert_eq!(
            fs::read_to_string(&kdeglobals).unwrap(),
            locked.kdeglobals().unwrap()
        );
        let written: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("policy.json")).unwrap()).unwrap();
        assert_eq!(
            written,
            json!({"version": 3, "preset": "mauvely", "lock": {"look": true, "layout": true}})
        );
        assert_eq!(mode(&dir), 0o755);
        assert_eq!(mode(&dir.join("xdg")), 0o755);
        assert_eq!(mode(&kdeglobals), 0o644);
        assert_eq!(mode(&dir.join("policy.json")), 0o644);
        assert!(!dir.join("policy.json.tmp").exists());

        // The same again changes nothing, not even the files' times.
        let before = fs::metadata(&kdeglobals).unwrap().modified().unwrap();
        assert!(!apply(&dir, &locked).unwrap());
        assert_eq!(
            fs::metadata(&kdeglobals).unwrap().modified().unwrap(),
            before
        );

        // A new version alone rewrites policy.json, for the sessions.
        let again = Policy {
            version: 4,
            ..locked.clone()
        };
        assert!(apply(&dir, &again).unwrap());
        assert!(
            fs::read_to_string(dir.join("policy.json"))
                .unwrap()
                .contains("\"version\":4")
        );
    }

    #[test]
    fn nothing_to_say_removes_kdeglobals_and_keeps_the_version() {
        let tmp = TempDir::new();
        let dir = tmp.path().join("mauvely-desktop");
        apply(&dir, &policy(Some(Preset::Plasma), true, false)).unwrap();
        assert!(apply(&dir, &policy(None, false, false)).unwrap());
        assert!(!dir.join("xdg/kdeglobals").exists());
        assert!(dir.join("xdg").is_dir());
        let written: serde_json::Value =
            serde_json::from_slice(&fs::read(dir.join("policy.json")).unwrap()).unwrap();
        assert_eq!(written["preset"], serde_json::Value::Null);
        assert!(!apply(&dir, &policy(None, false, false)).unwrap());
    }

    #[test]
    fn puts_a_directory_someone_tightened_back_to_0755() {
        let tmp = TempDir::new();
        let dir = tmp.path().join("mauvely-desktop");
        fs::create_dir_all(dir.join("xdg")).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(dir.join("xdg"), fs::Permissions::from_mode(0o750)).unwrap();
        apply(&dir, &policy(None, true, false)).unwrap();
        assert_eq!(mode(&dir), 0o755);
        assert_eq!(mode(&dir.join("xdg")), 0o755);
    }

    #[test]
    fn the_unit_lets_the_agent_write_its_directory() {
        // /var/lib/mauvely-desktop is outside StateDirectory=, which is 0700.
        // Without ProtectSystem= all of /var is writable; with it, the
        // directory has to be named.
        let unit = include_str!("../../../dist/mauvelyd.service");
        let protects = unit.lines().any(|l| l.starts_with("ProtectSystem="));
        let named = unit
            .lines()
            .any(|l| l.starts_with("ReadWritePaths=") && l.contains("/var/lib/mauvely-desktop"));
        assert!(!protects || named);
        assert!(unit.lines().any(|l| l == "StateDirectoryMode=0700"));
    }
}
