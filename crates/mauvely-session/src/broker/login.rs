//! Milestone 2's `LoginSession`: the `os` session the person's login made,
//! which `mauvelyd` hands over in `/run/mauvely/login/<uid>` (its
//! `login::handoff`). Read once, at start, then deleted; the broker seals it
//! as it seals a linked session, so the sign-in window is never offered.
//!
//! ```json
//! {"v":1,"token":"…","expiresAt":1771200000,"origin":"https://mauvely.com","handle":"timur.suez"}
//! ```
//!
//! The directory is `01733`: anyone can put a name in it. So only a regular
//! file of this uid, mode `0600`, opened without following a link, is taken.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Read};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use serde::Deserialize;

use super::LoginSession;
use super::seal::OsSession;

const DIR: &str = "/run/mauvely/login";
const MAX: u64 = 4096;

pub struct HandOff {
    path: PathBuf,
    uid: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct File {
    v: u32,
    token: String,
    expires_at: u64,
    origin: String,
    handle: String,
}

impl HandOff {
    /// This user's: `/run/mauvely/login/<uid>`.
    pub fn for_me() -> Self {
        // SAFETY: geteuid cannot fail and touches no memory.
        let uid = unsafe { libc::geteuid() };
        HandOff::at(PathBuf::from(DIR).join(uid.to_string()), uid)
    }

    pub fn at(path: PathBuf, uid: u32) -> Self {
        HandOff { path, uid }
    }

    fn read(&self) -> Result<Option<OsSession>, String> {
        let shown = self.path.display();
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(&self.path);
        let file = match file {
            Ok(f) => f,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{shown}: {e}")),
        };
        let meta = file.metadata().map_err(|e| format!("{shown}: {e}"))?;
        if !meta.is_file() || meta.uid() != self.uid || meta.mode() & 0o7777 != 0o600 {
            return Err(format!("{shown}: not this user's own file, 0600"));
        }
        if meta.len() > MAX {
            return Err(format!("{shown}: too large"));
        }
        let mut bytes = Vec::new();
        file.take(MAX)
            .read_to_end(&mut bytes)
            .map_err(|e| format!("{shown}: {e}"))?;
        // Ours, so gone whatever it holds: a session is handed over once.
        if let Err(e) = fs::remove_file(&self.path) {
            eprintln!("mauvely-session: broker: {shown}: {e}");
        }
        let parsed: File =
            serde_json::from_slice(&bytes).map_err(|e| format!("{shown}: not a session: {e}"))?;
        if parsed.v != 1 || parsed.token.is_empty() {
            return Err(format!("{shown}: not a session"));
        }
        Ok(Some(OsSession {
            token: parsed.token,
            expires_at: parsed.expires_at,
            // The login does not say the address; the handle is who it is.
            email: parsed.handle,
            origin: parsed.origin,
        }))
    }
}

impl LoginSession for HandOff {
    fn session(&self) -> Option<OsSession> {
        self.read()
            .inspect_err(|e| eprintln!("mauvely-session: broker: the login's session: {e}"))
            .ok()
            .flatten()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::seal::tests::temp_dir;
    use std::os::unix::fs::PermissionsExt;

    fn me() -> u32 {
        // SAFETY: as in `for_me`.
        unsafe { libc::geteuid() }
    }

    const FILE: &str = r#"{"v":1,"token":"tok_login","expiresAt":1771200000,"origin":"https://mauvely.com","handle":"timur.suez"}"#;

    fn put(path: &std::path::Path, text: &str, mode: u32) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, text).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn the_logins_session_is_taken_once() {
        let dir = temp_dir("handoff");
        let path = dir.join(me().to_string());
        put(&path, FILE, 0o600);
        let h = HandOff::at(path.clone(), me());
        let s = h.session().unwrap();
        assert_eq!(s.token, "tok_login");
        assert_eq!(s.expires_at, 1_771_200_000);
        assert_eq!(s.origin, "https://mauvely.com");
        assert_eq!(s.email, "timur.suez");
        // Deleted: the next look finds nothing.
        assert!(!path.exists());
        assert!(h.session().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn nothing_there_is_no_session() {
        let dir = temp_dir("handoff-none");
        assert!(HandOff::at(dir.join("1000"), me()).session().is_none());
    }

    #[test]
    fn only_this_users_own_0600_file_is_taken() {
        let dir = temp_dir("handoff-wrong");
        let path = dir.join(me().to_string());
        // Readable by others.
        put(&path, FILE, 0o644);
        assert!(HandOff::at(path.clone(), me()).session().is_none());
        assert!(path.exists(), "a file that was refused is left");
        // Another uid's (the file is ours, so pretend to be someone else).
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(HandOff::at(path.clone(), me() + 1).session().is_none());
        // A link to a session somewhere else.
        let elsewhere = dir.join("elsewhere");
        fs::rename(&path, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &path).unwrap();
        assert!(HandOff::at(path.clone(), me()).session().is_none());
        assert!(elsewhere.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_garbled_file_is_no_session_and_is_gone() {
        let dir = temp_dir("handoff-garbled");
        let path = dir.join(me().to_string());
        for text in [
            "nope",
            r#"{"v":2,"token":"t","expiresAt":1,"origin":"o","handle":"h"}"#,
        ] {
            put(&path, text, 0o600);
            assert!(HandOff::at(path.clone(), me()).session().is_none());
            assert!(!path.exists());
        }
        put(&path, &"x".repeat(5000), 0o600);
        assert!(HandOff::at(path.clone(), me()).session().is_none());
        fs::remove_dir_all(&dir).unwrap();
    }
}
