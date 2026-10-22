//! The offline cache: one entry per person who signed in here online, in
//! `/var/lib/mauvely/people/<username>.cred`, `0600` in a `0700` directory.
//!
//! An entry holds who the person is and a verifier of their password
//! (`kdf::Verifier`): Argon2id with its own salt and parameters, never the
//! `authSecret`, so a stolen entry cannot sign anybody in to Mauvely. It is
//! sealed whole with `systemd-creds`, as the device key is, under the name
//! `mauvely-person-<username>`: with a TPM, a copied disk cannot even be
//! guessed against, which matters because the password also opens the
//! person's Cloud vault (plan 23). An entry renamed to another person's file
//! does not unseal.
//!
//! The login screen uses an entry only when the server cannot be reached,
//! and while it is younger than its `offlineDays`. Every other service (the
//! lock screen, sudo, polkit, text logins) checks the password against it
//! and nothing else.

use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use super::kdf::Verifier;
use crate::Error;
use crate::creds::Sealer;
use crate::state::write_private;

const DAY: u64 = 86_400;
/// A clock this far behind the last online sign-in is not trusted with the
/// age of an entry.
const SKEW: u64 = 300;

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Entry {
    pub username: String,
    pub handle: String,
    pub uid: u32,
    pub name: String,
    pub device_admin: bool,
    /// The collection's, at that sign-in.
    pub offline_days: u32,
    /// The last online sign-in, Unix seconds.
    pub signed_in_at: u64,
    pub verifier: Verifier,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("username", &self.username)
            .field("uid", &self.uid)
            .field("offline_days", &self.offline_days)
            .field("signed_in_at", &self.signed_in_at)
            .finish_non_exhaustive()
    }
}

impl Entry {
    /// Whether it may sign the person in offline at `now`: younger than its
    /// own `offlineDays`, and than `cap`, the collection's now, when that is
    /// fewer. A clock set before the sign-in it records is not trusted.
    pub fn fresh(&self, now: u64, cap: Option<u32>) -> bool {
        let days = cap.map_or(self.offline_days, |c| c.min(self.offline_days));
        now + SKEW >= self.signed_in_at && now < self.signed_in_at + u64::from(days) * DAY
    }
}

fn credential(username: &str) -> String {
    format!("mauvely-person-{username}")
}

pub fn path(dir: &Path, username: &str) -> PathBuf {
    dir.join(format!("{username}.cred"))
}

/// The entry for `username`. One that does not unseal or parse is logged and
/// taken as none: the person then signs in online, which replaces it.
pub fn read(dir: &Path, sealer: &dyn Sealer, username: &str) -> Option<Entry> {
    let path = path(dir, username);
    let sealed = match fs::read(&path) {
        Ok(b) => b,
        Err(e) if e.kind() == ErrorKind::NotFound => return None,
        Err(e) => {
            eprintln!("login: {}: {e}", path.display());
            return None;
        }
    };
    let plain = match sealer.unseal_as(&credential(username), &sealed) {
        Ok(p) => zeroize::Zeroizing::new(p),
        Err(e) => {
            eprintln!("login: {}: does not unseal: {e}", path.display());
            return None;
        }
    };
    match serde_json::from_slice::<Entry>(&plain) {
        Ok(entry) if entry.username == username => Some(entry),
        Ok(_) => {
            eprintln!("login: {}: holds another person", path.display());
            None
        }
        Err(e) => {
            eprintln!("login: {}: not an entry: {e}", path.display());
            None
        }
    }
}

/// Seals and writes `entry`, replacing the person's last one.
pub fn write(dir: &Path, sealer: &dyn Sealer, entry: &Entry) -> Result<(), Error> {
    let plain = zeroize::Zeroizing::new(
        serde_json::to_vec(entry).map_err(|e| Error::json("cache entry", e))?,
    );
    let sealed = sealer.seal_as(&credential(&entry.username), &plain)?;
    private_dir(dir)?;
    write_private(&path(dir, &entry.username), &sealed)
}

/// Removes the entry for `username`. True when there was one.
pub fn remove(dir: &Path, username: &str) -> Result<bool, Error> {
    let path = path(dir, username);
    match fs::remove_file(&path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io(&path, e)),
    }
}

/// Whose entries there are.
pub fn names(dir: &Path) -> Vec<String> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|f| f.strip_suffix(".cred").map(str::to_owned))
        .collect();
    names.sort();
    names
}

/// The cache's directory, `0700` whatever the umask.
fn private_dir(dir: &Path) -> Result<(), Error> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    match fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
    {
        Ok(()) => {}
        Err(e) => return Err(Error::io(dir, e)),
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| Error::io(dir, e))
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use crate::fake::{FakeCreds, TempDir};
    use std::os::unix::fs::PermissionsExt;

    pub fn entry(username: &str, password: &str, at: u64) -> Entry {
        Entry {
            username: username.into(),
            handle: format!("{username}.suez"),
            uid: 21001,
            name: "Timur Inal".into(),
            device_admin: false,
            offline_days: 14,
            signed_in_at: at,
            verifier: Verifier::new(password.as_bytes()).unwrap(),
        }
    }

    #[test]
    fn an_entry_is_sealed_private_and_comes_back() {
        let dir = TempDir::new();
        let d = dir.path().join("people");
        let e = entry("timur", "pw 1234567", 1000);
        write(&d, &FakeCreds, &e).unwrap();
        assert_eq!(read(&d, &FakeCreds, "timur"), Some(e.clone()));
        let raw = fs::read(path(&d, "timur")).unwrap();
        assert!(raw.starts_with(b"sealed[mauvely-person-timur]:"));
        assert!(
            !raw.windows(e.verifier.hash.len())
                .any(|w| w == e.verifier.hash.as_bytes())
        );
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path(&d, "timur")), 0o600);
        assert_eq!(mode(&d), 0o700);
        assert_eq!(names(&d), ["timur"]);
        assert!(!format!("{e:?}").contains(&e.verifier.hash));

        assert!(remove(&d, "timur").unwrap());
        assert!(!remove(&d, "timur").unwrap());
        assert_eq!(read(&d, &FakeCreds, "timur"), None);
    }

    #[test]
    fn an_entry_moved_to_another_name_does_not_unseal() {
        let dir = TempDir::new();
        let d = dir.path();
        write(d, &FakeCreds, &entry("timur", "pw 1234567", 1000)).unwrap();
        fs::rename(path(d, "timur"), path(d, "ada")).unwrap();
        assert_eq!(read(d, &FakeCreds, "ada"), None);
        fs::write(path(d, "ada"), b"garbage").unwrap();
        assert_eq!(read(d, &FakeCreds, "ada"), None);
    }

    #[test]
    fn freshness() {
        let e = entry("timur", "pw 1234567", 1_000_000);
        let day = 86_400;
        assert!(e.fresh(1_000_000, None));
        assert!(e.fresh(1_000_000 + 14 * day - 1, None));
        assert!(!e.fresh(1_000_000 + 14 * day, None));
        // The collection's days now, when fewer.
        assert!(e.fresh(1_000_000 + 2 * day, Some(3)));
        assert!(!e.fresh(1_000_000 + 3 * day, Some(3)));
        assert!(e.fresh(1_000_000 + 13 * day, Some(30)));
        assert!(!e.fresh(1_000_000, Some(0)));
        // A clock before the sign-in is not believed.
        assert!(e.fresh(1_000_000 - 60, None));
        assert!(!e.fresh(1_000_000 - 3600, None));
    }
}
