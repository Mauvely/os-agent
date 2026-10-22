//! The `os` session a login made, handed to the person's `mauvely-session`
//! through `/run/mauvely/login/<uid>`: `0600`, the person's, written to a
//! private name and renamed into place. mauvely-session reads it, seals it
//! with `systemd-creds --user` as it seals a linked session, and deletes it
//! (`mauvely-session/src/broker/login.rs`).
//!
//! ```json
//! {"v":1,"token":"…","expiresAt":1771200000,"origin":"https://mauvely.com","handle":"timur.suez"}
//! ```
//!
//! **The directory is `01733`, root's**, like `/tmp` without the listing: the
//! person must be able to delete their own file, and the sticky bit stops
//! them deleting anybody else's. Anyone can create a name in it, so:
//! - the file is written under `/run/mauvely/.login-<uid>.tmp`, where only
//!   root writes, and renamed in, which replaces whatever another user put at
//!   that name;
//! - mauvely-session takes only a regular file of its own uid, mode `0600`,
//!   opened without following a link.
//!
//! Another user can still put a directory at someone's name, and then the
//! rename fails: that person signs in, and is offered the sign-in window.
//!
//! The token is never logged.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt, fchown};
use std::path::Path;

use serde::Serialize;

use crate::Error;

pub const DIR_MODE: u32 = 0o1733;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct HandOff<'a> {
    pub v: u32,
    pub token: &'a str,
    pub expires_at: u64,
    pub origin: &'a str,
    pub handle: &'a str,
}

impl std::fmt::Debug for HandOff<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HandOff")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("origin", &self.origin)
            .field("handle", &self.handle)
            .finish()
    }
}

/// Makes `dir` with `DIR_MODE`, and sets it when it is there.
pub fn prepare(dir: &Path) -> Result<(), Error> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(e) => return Err(Error::io(dir, e)),
    }
    let meta = fs::symlink_metadata(dir).map_err(|e| Error::io(dir, e))?;
    if !meta.is_dir() {
        return Err(Error::Invalid(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE)).map_err(|e| Error::io(dir, e))
}

/// Writes the session for `uid` (whose group is `gid`) into `dir`, staged in
/// `staging`, which must be on the same filesystem and writable by root
/// alone.
pub fn write(dir: &Path, staging: &Path, uid: u32, gid: u32, h: &HandOff) -> Result<(), Error> {
    prepare(dir)?;
    let mut bytes =
        zeroize::Zeroizing::new(serde_json::to_vec(h).map_err(|e| Error::json("hand-off", e))?);
    bytes.push(b'\n');
    let tmp = staging.join(format!(".login-{uid}.tmp"));
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)
        .map_err(|e| Error::io(&tmp, e))?;
    let written = f
        .set_permissions(fs::Permissions::from_mode(0o600))
        .and_then(|_| fchown(&f, Some(uid), Some(gid)))
        .and_then(|_| f.write_all(&bytes))
        .and_then(|_| f.sync_all());
    let target = dir.join(uid.to_string());
    let renamed = written.and_then(|_| fs::rename(&tmp, &target));
    if let Err(e) = renamed {
        let _ = fs::remove_file(&tmp);
        return Err(Error::io(&target, e));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::TempDir;
    use std::os::unix::fs::MetadataExt;

    fn me() -> (u32, u32) {
        // SAFETY: getuid and getgid cannot fail and touch no memory.
        unsafe { (libc::getuid(), libc::getgid()) }
    }

    fn session() -> HandOff<'static> {
        HandOff {
            v: 1,
            token: "tok_os_secret",
            expires_at: 1_771_200_000,
            origin: "https://mauvely.com",
            handle: "timur.suez",
        }
    }

    #[test]
    fn the_file_is_the_persons_0600_in_a_sticky_directory() {
        let dir = TempDir::new();
        let login = dir.path().join("login");
        let (uid, gid) = me();
        write(&login, dir.path(), uid, gid, &session()).unwrap();

        let file = login.join(uid.to_string());
        let meta = fs::symlink_metadata(&file).unwrap();
        assert!(meta.is_file());
        assert_eq!(meta.mode() & 0o7777, 0o600);
        assert_eq!((meta.uid(), meta.gid()), (uid, gid));
        assert_eq!(fs::metadata(&login).unwrap().mode() & 0o7777, 0o1733);
        assert_eq!(
            fs::read_to_string(&file).unwrap(),
            "{\"v\":1,\"token\":\"tok_os_secret\",\"expiresAt\":1771200000,\
             \"origin\":\"https://mauvely.com\",\"handle\":\"timur.suez\"}\n"
        );
        // Staged privately, and nothing left behind.
        assert!(!dir.path().join(format!(".login-{uid}.tmp")).exists());
        assert!(!format!("{:?}", session()).contains("tok_os_secret"));
    }

    #[test]
    fn whatever_was_at_the_name_is_replaced() {
        let dir = TempDir::new();
        let login = dir.path().join("login");
        let (uid, gid) = me();
        prepare(&login).unwrap();
        let file = login.join(uid.to_string());
        // A link somebody planted, pointing at a file of theirs.
        let planted = dir.path().join("planted");
        fs::write(&planted, "theirs").unwrap();
        std::os::unix::fs::symlink(&planted, &file).unwrap();
        // And a link at the staging name.
        std::os::unix::fs::symlink(&planted, dir.path().join(format!(".login-{uid}.tmp"))).unwrap();
        write(&login, dir.path(), uid, gid, &session()).unwrap();
        assert!(fs::symlink_metadata(&file).unwrap().is_file());
        assert_eq!(fs::read_to_string(&planted).unwrap(), "theirs");
    }

    #[test]
    fn a_directory_at_the_name_fails_it_and_leaves_nothing_staged() {
        let dir = TempDir::new();
        let login = dir.path().join("login");
        let (uid, gid) = me();
        fs::create_dir_all(login.join(uid.to_string()).join("x")).unwrap();
        assert!(write(&login, dir.path(), uid, gid, &session()).is_err());
        assert!(!dir.path().join(format!(".login-{uid}.tmp")).exists());
    }
}
