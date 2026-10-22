//! The browser extension's native messaging host, put where each browser looks
//! for it (brief 22, S4). `docs/browser.md` has the design.
//!
//! The Flathub browsers read native messaging manifests only from their own
//! data directories, inside their sandboxes, and run only what they can see
//! there. So at login, and every few minutes after, the host binary the image
//! ships is copied into each browser's directory beside a manifest naming it
//! and the one extension that may start it:
//!
//! | Browser | Directory, under `~/.var/app/<id>/` |
//! |---|---|
//! | Firefox | `.mozilla/native-messaging-hosts/` (the sandbox's `~/.mozilla`) |
//! | Chromium | `config/chromium/NativeMessagingHosts/` (its `$XDG_CONFIG_HOME/chromium`) |
//!
//! Both browsers, whether installed or not, as Plasma's own browser
//! integration does: a browser the agent installs later then finds its host at
//! its first start, with nothing to wait for. A file is written only when it
//! differs, through a new file and a rename, so neither browser ever reads half
//! of one. Nothing is written through a symbolic link: the browsers can write
//! these directories, and the person's other files are not theirs.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde_json::json;

use crate::Error;

/// Where the image puts the host (os-image's Containerfile).
pub const SOURCE: &str = "/usr/libexec/mauvely/mauvely-browser-host";

/// The host's name, which the extension asks for (`browser/extension/src/signin.js`).
pub const NAME: &str = "com.mauvely.browser";

/// The binary's name beside each manifest.
const BINARY: &str = "mauvely-browser-host";

/// The Firefox extension's id (`browser/extension/manifest.firefox.json`). AMO
/// signs it under this id; it does not depend on any key.
pub const FIREFOX_EXTENSION: &str = "os-signin@mauvely.com";

/// The Chromium extension, by its id: the public key in
/// `browser/extension/manifest.chromium.json`, hashed. **A throwaway key's for
/// now**: the CRX signing key Timur provides replaces that key and so this id,
/// and a test fails until both agree.
pub const CHROMIUM_ORIGIN: &str = "chrome-extension://ioajmohlalajkifjboclbjlinkkogcej/";

/// One browser: where it looks, and how its manifest names the extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Browser {
    pub id: &'static str,
    /// Below `~/.var/app/<id>/`.
    pub dir: &'static str,
    /// The manifest's allow-list: its key, and the one entry in it.
    pub allow_key: &'static str,
    pub allow: &'static str,
}

pub const BROWSERS: [Browser; 2] = [
    Browser {
        id: "org.chromium.Chromium",
        dir: "config/chromium/NativeMessagingHosts",
        allow_key: "allowed_origins",
        allow: CHROMIUM_ORIGIN,
    },
    Browser {
        id: "org.mozilla.firefox",
        dir: ".mozilla/native-messaging-hosts",
        allow_key: "allowed_extensions",
        allow: FIREFOX_EXTENSION,
    },
];

impl Browser {
    /// The directory as the browser sees it. Flatpak mounts `~/.var/app/<id>`
    /// at the same path inside the sandbox, so the manifest's `path` is this
    /// one plus the binary's name.
    pub fn dir_in(&self, home: &Path) -> PathBuf {
        home.join(".var/app").join(self.id).join(self.dir)
    }

    pub fn manifest(&self, dir: &Path) -> Vec<u8> {
        let mut manifest = json!({
            "name": NAME,
            "description": "Mauvely OS sign-in",
            "path": dir.join(BINARY),
            "type": "stdio",
        });
        manifest[self.allow_key] = json!([self.allow]);
        let mut text = serde_json::to_vec_pretty(&manifest).expect("a manifest serialises");
        text.push(b'\n');
        text
    }
}

/// Puts the host and its manifest in each browser's directory under `home`.
/// Returns what it wrote, for the log; nothing when everything was in place.
/// Without the image's host there is nothing to place, and nothing is done.
pub fn place(source: &Path, home: &Path, browsers: &[Browser]) -> Result<Vec<PathBuf>, Error> {
    let binary = match fs::read(source) {
        Ok(b) => b,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(format!("{}: {e}", source.display()).into()),
    };
    let mut written = Vec::new();
    let mut failed = Vec::new();
    for browser in browsers {
        match place_one(browser, &binary, home) {
            Ok(mut w) => written.append(&mut w),
            Err(e) => failed.push(format!("{}: {e}", browser.id)),
        }
    }
    if failed.is_empty() {
        Ok(written)
    } else {
        Err(failed.join("; ").into())
    }
}

fn place_one(browser: &Browser, binary: &[u8], home: &Path) -> Result<Vec<PathBuf>, Error> {
    let dir = browser.dir_in(home);
    make_dirs(&home.join(".var"), &dir)?;
    let mut written = Vec::new();
    for (name, bytes, mode) in [
        (BINARY.to_owned(), binary.to_vec(), 0o755),
        (format!("{NAME}.json"), browser.manifest(&dir), 0o644),
    ] {
        let path = dir.join(&name);
        if write_if_changed(&path, &bytes, mode)? {
            written.push(path);
        }
    }
    Ok(written)
}

/// Makes `dir` and every directory between `base` and it, refusing a symbolic
/// link at any of them. `base` itself (`~/.var`) is made too.
fn make_dirs(base: &Path, dir: &Path) -> Result<(), Error> {
    let below = dir
        .strip_prefix(base)
        .map_err(|_| format!("{} is not under {}", dir.display(), base.display()))?;
    let mut at = base.to_path_buf();
    let mut dirs = vec![at.clone()];
    for part in below.components() {
        at.push(part);
        dirs.push(at.clone());
    }
    for at in dirs {
        match fs::symlink_metadata(&at) {
            Ok(m) if m.file_type().is_symlink() => {
                return Err(format!("{} is a symbolic link", at.display()).into());
            }
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(format!("{} is not a directory", at.display()).into()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => fs::create_dir(&at)?,
            Err(e) => return Err(format!("{}: {e}", at.display()).into()),
        }
    }
    Ok(())
}

/// Writes `bytes` to `path` with `mode` unless it already holds exactly that.
/// Through a new file beside it and a rename, which replaces a symbolic link
/// rather than following it.
fn write_if_changed(path: &Path, bytes: &[u8], mode: u32) -> Result<bool, Error> {
    if let Ok(m) = fs::symlink_metadata(path)
        && m.is_file()
        && m.permissions().mode() & 0o777 == mode
        && fs::read(path).is_ok_and(|old| old == bytes)
    {
        return Ok(false);
    }
    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("file");
    let tmp = path.with_file_name(format!(".{name}.new"));
    // A leftover, or something planted: unlinked, never followed.
    match fs::remove_file(&tmp) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)?;
    file.write_all(bytes)?;
    // The umask may have taken bits away.
    file.set_permissions(fs::Permissions::from_mode(mode))?;
    file.sync_all()?;
    drop(file);
    fs::rename(&tmp, path)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("mauvely-browserhost-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("home")).unwrap();
        fs::write(dir.join("host"), b"\x7fELF the host").unwrap();
        dir
    }

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn puts_the_host_where_each_browser_looks() {
        let t = scratch("place");
        let home = t.join("home");
        let written = place(&t.join("host"), &home, &BROWSERS).unwrap();
        assert_eq!(written.len(), 4);

        let firefox = home.join(".var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts");
        let chromium =
            home.join(".var/app/org.chromium.Chromium/config/chromium/NativeMessagingHosts");
        for dir in [&firefox, &chromium] {
            assert_eq!(fs::read(dir.join(BINARY)).unwrap(), b"\x7fELF the host");
            assert_eq!(mode(&dir.join(BINARY)), 0o755);
            assert_eq!(mode(&dir.join("com.mauvely.browser.json")), 0o644);
        }
        let read = |dir: &Path| -> serde_json::Value {
            serde_json::from_slice(&fs::read(dir.join("com.mauvely.browser.json")).unwrap())
                .unwrap()
        };
        assert_eq!(
            read(&firefox),
            json!({
                "name": "com.mauvely.browser",
                "description": "Mauvely OS sign-in",
                "path": firefox.join("mauvely-browser-host"),
                "type": "stdio",
                "allowed_extensions": ["os-signin@mauvely.com"],
            })
        );
        assert_eq!(
            read(&chromium),
            json!({
                "name": "com.mauvely.browser",
                "description": "Mauvely OS sign-in",
                "path": chromium.join("mauvely-browser-host"),
                "type": "stdio",
                "allowed_origins": ["chrome-extension://ioajmohlalajkifjboclbjlinkkogcej/"],
            })
        );
        // No leftovers.
        assert_eq!(fs::read_dir(&firefox).unwrap().count(), 2);
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn writes_only_what_changed() {
        let t = scratch("again");
        let home = t.join("home");
        place(&t.join("host"), &home, &BROWSERS).unwrap();
        assert!(place(&t.join("host"), &home, &BROWSERS).unwrap().is_empty());

        // A new image's host replaces both copies, and nothing else.
        fs::write(t.join("host"), b"\x7fELF a newer host").unwrap();
        let written = place(&t.join("host"), &home, &BROWSERS).unwrap();
        assert_eq!(written.len(), 2);
        assert!(written.iter().all(|p| p.ends_with(BINARY)));

        // A copy changed in place, or its mode, is put back.
        let ff = BROWSERS[1].dir_in(&home);
        fs::write(ff.join(BINARY), b"something else").unwrap();
        fs::set_permissions(
            ff.join("com.mauvely.browser.json"),
            fs::Permissions::from_mode(0o666),
        )
        .unwrap();
        assert_eq!(place(&t.join("host"), &home, &BROWSERS).unwrap().len(), 2);
        assert_eq!(fs::read(ff.join(BINARY)).unwrap(), b"\x7fELF a newer host");
        assert_eq!(mode(&ff.join("com.mauvely.browser.json")), 0o644);
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn without_the_images_host_nothing_is_done() {
        let t = scratch("nohost");
        let home = t.join("home");
        assert!(
            place(&t.join("missing"), &home, &BROWSERS)
                .unwrap()
                .is_empty()
        );
        assert!(!home.join(".var").exists());
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn never_writes_through_a_link() {
        let t = scratch("links");
        let home = t.join("home");
        let elsewhere = t.join("elsewhere");
        fs::create_dir_all(&elsewhere).unwrap();
        fs::write(elsewhere.join("precious"), b"mine").unwrap();

        // A directory on the way that is a link: refused for that browser, and
        // the other one is still placed.
        let ff = BROWSERS[1].dir_in(&home);
        fs::create_dir_all(ff.parent().unwrap()).unwrap();
        symlink(&elsewhere, &ff).unwrap();
        let e = place(&t.join("host"), &home, &BROWSERS)
            .unwrap_err()
            .to_string();
        assert!(
            e.contains("org.mozilla.firefox") && e.contains("symbolic link"),
            "{e}"
        );
        assert_eq!(fs::read_dir(&elsewhere).unwrap().count(), 1);
        assert!(BROWSERS[0].dir_in(&home).join(BINARY).is_file());
        fs::remove_file(&ff).unwrap();

        // The files themselves, and the new file beside them, as links: each
        // is replaced, and what it pointed at is untouched.
        fs::create_dir_all(&ff).unwrap();
        symlink(elsewhere.join("precious"), ff.join(BINARY)).unwrap();
        symlink(
            elsewhere.join("precious"),
            ff.join(".com.mauvely.browser.json.new"),
        )
        .unwrap();
        place(&t.join("host"), &home, &BROWSERS).unwrap();
        assert_eq!(fs::read(elsewhere.join("precious")).unwrap(), b"mine");
        assert!(
            !fs::symlink_metadata(ff.join(BINARY))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(ff.join(BINARY)).unwrap(), b"\x7fELF the host");
        assert!(!ff.join(".com.mauvely.browser.json.new").exists());
        fs::remove_dir_all(&t).unwrap();
    }

    #[test]
    fn modes_survive_a_strict_umask() {
        let t = scratch("umask");
        let home = t.join("home");
        let old = unsafe { libc::umask(0o077) };
        let result = place(&t.join("host"), &home, &BROWSERS);
        unsafe { libc::umask(old) };
        result.unwrap();
        let dir = BROWSERS[0].dir_in(&home);
        assert_eq!(mode(&dir.join(BINARY)), 0o755);
        assert_eq!(mode(&dir.join("com.mauvely.browser.json")), 0o644);
        fs::remove_dir_all(&t).unwrap();
    }

    /// The ids here are the extension's: its manifests, its key and its
    /// source. A new CRX key changes the Chromium one, and this fails until
    /// `CHROMIUM_ORIGIN` follows.
    #[test]
    fn the_ids_are_the_extensions() {
        use base64::Engine;
        use sha2::Digest;
        let manifest = |name: &str| -> serde_json::Value {
            let path = Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../browser/extension")
                .join(name);
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap()
        };
        let chromium = manifest("manifest.chromium.json");
        let der = base64::engine::general_purpose::STANDARD
            .decode(chromium["key"].as_str().unwrap())
            .unwrap();
        let id: String = sha2::Sha256::digest(&der)[..16]
            .iter()
            .flat_map(|b| [b >> 4, b & 0xf])
            .map(|n| (b'a' + n) as char)
            .collect();
        assert_eq!(CHROMIUM_ORIGIN, format!("chrome-extension://{id}/"));
        assert_eq!(BROWSERS[0].allow, CHROMIUM_ORIGIN);

        let firefox = manifest("manifest.firefox.json");
        assert_eq!(
            firefox["browser_specific_settings"]["gecko"]["id"],
            FIREFOX_EXTENSION
        );
        let source = fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../browser/extension/src/signin.js"),
        )
        .unwrap();
        assert!(
            source.contains(&format!("'{NAME}'")),
            "the extension asks for {NAME}"
        );
    }

    #[test]
    fn the_browsers_are_the_brokers() {
        let ids: Vec<&str> = BROWSERS.iter().map(|b| b.id).collect();
        let mut theirs = crate::broker::caller::BROWSERS.to_vec();
        theirs.sort();
        assert_eq!(ids, theirs);
    }
}
