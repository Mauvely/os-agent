//! Usernames, and the machine's own accounts.
//!
//! A person types the name half of their handle, `timur` for `timur.suez`.
//! Two rules apply:
//! - **website-devices'** (`lib/username.ts`, itself website-main's
//!   `HANDLE_NAME_RE`): 3 to 32 of `[a-z0-9-]`, starting and ending with a
//!   letter or digit. Mirrored here, not copied.
//! - **A computer's**: systemd's strict user name rule, which also names the
//!   `/etc/userdb` files: it must start with a letter, and fit utmp's 31
//!   characters. A Mauvely name that passes the first and not this one (a
//!   leading digit, or 32 characters) cannot sign in to a computer yet;
//!   mapping it is a later decision (brief 26, "Usernames").
//!
//! Local accounts are looked up through NSS, as every program on the machine
//! sees them: `/etc/passwd`, `/usr/lib/passwd` (altfiles, where Fedora Atomic
//! keeps its system users), and userdb.

use std::ffi::{CStr, CString};

/// website-devices' rule, mirrored.
pub fn is_username(s: &str) -> bool {
    let b = s.as_bytes();
    let edge = |c: u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (3..=32).contains(&b.len())
        && edge(b[0])
        && edge(b[b.len() - 1])
        && b.iter().all(|&c| edge(c) || c == b'-')
}

/// Whether a computer can use it: a Mauvely name that starts with a letter
/// and fits in 31 characters.
pub fn fits_computer(s: &str) -> bool {
    is_username(s) && s.len() <= 31 && s.as_bytes()[0].is_ascii_lowercase()
}

/// The machine's accounts, as NSS answers.
pub trait Names: Send + Sync {
    /// The uid of user `name`.
    fn user(&self, name: &str) -> Option<u32>;
    /// The name of the user with `uid`.
    fn uid(&self, uid: u32) -> Option<String>;
    /// The gid of group `name`.
    fn group(&self, name: &str) -> Option<u32>;
    /// The name of the group with `gid`.
    fn gid(&self, gid: u32) -> Option<String>;
}

/// glibc's NSS, through the reentrant calls.
pub struct Nss;

/// Big enough for any one passwd or group entry on this machine; a longer
/// one (`ERANGE`) is retried once at 64 KiB.
const BUF: usize = 4096;

impl Names for Nss {
    fn user(&self, name: &str) -> Option<u32> {
        let name = CString::new(name).ok()?;
        lookup(
            |pwd: *mut libc::passwd, buf: &mut [u8], out: *mut *mut libc::passwd| {
                // SAFETY: `name` is a NUL-terminated string that outlives the
                // call; `pwd`, `buf` and `out` point at storage `lookup` owns for
                // the duration of the call, `buf.len()` is its true length.
                unsafe {
                    libc::getpwnam_r(name.as_ptr(), pwd, buf.as_mut_ptr().cast(), buf.len(), out)
                }
            },
        )
        .map(|p: libc::passwd| p.pw_uid)
    }

    fn uid(&self, uid: u32) -> Option<String> {
        let mut name = None;
        lookup(
            |pwd: *mut libc::passwd, buf: &mut [u8], out: *mut *mut libc::passwd| {
                // SAFETY: as in `user`.
                let rc =
                    unsafe { libc::getpwuid_r(uid, pwd, buf.as_mut_ptr().cast(), buf.len(), out) };
                // SAFETY: on success with a result, `pw_name` points into `buf`,
                // a NUL-terminated string, and `buf` is still alive here.
                if rc == 0 && unsafe { !(*out).is_null() } {
                    name = Some(
                        unsafe { CStr::from_ptr((*pwd).pw_name) }
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
                rc
            },
        )?;
        name
    }

    fn group(&self, name: &str) -> Option<u32> {
        let name = CString::new(name).ok()?;
        lookup(
            |grp: *mut libc::group, buf: &mut [u8], out: *mut *mut libc::group| {
                // SAFETY: as in `user`.
                unsafe {
                    libc::getgrnam_r(name.as_ptr(), grp, buf.as_mut_ptr().cast(), buf.len(), out)
                }
            },
        )
        .map(|g: libc::group| g.gr_gid)
    }

    fn gid(&self, gid: u32) -> Option<String> {
        let mut name = None;
        lookup(
            |grp: *mut libc::group, buf: &mut [u8], out: *mut *mut libc::group| {
                // SAFETY: as in `user`.
                let rc =
                    unsafe { libc::getgrgid_r(gid, grp, buf.as_mut_ptr().cast(), buf.len(), out) };
                // SAFETY: as in `uid`.
                if rc == 0 && unsafe { !(*out).is_null() } {
                    name = Some(
                        unsafe { CStr::from_ptr((*grp).gr_name) }
                            .to_string_lossy()
                            .into_owned(),
                    );
                }
                rc
            },
        )?;
        name
    }
}

/// Calls a `get*_r` function with a zeroed entry and a buffer, growing the
/// buffer once on `ERANGE`. The entry is returned by value only for its
/// numeric fields: its pointers point into a buffer that is gone by then.
fn lookup<T: Copy>(mut call: impl FnMut(*mut T, &mut [u8], *mut *mut T) -> i32) -> Option<T> {
    for size in [BUF, 65_536] {
        // SAFETY: `passwd` and `group` are plain C structs of integers and
        // pointers, for which all-zero is a valid value.
        let mut entry: T = unsafe { std::mem::zeroed() };
        let mut buf = vec![0u8; size];
        let mut out: *mut T = std::ptr::null_mut();
        let rc = call(&mut entry, &mut buf, &mut out);
        if rc == libc::ERANGE {
            continue;
        }
        return (rc == 0 && !out.is_null()).then_some(entry);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn website_devices_rule() {
        for ok in ["tim", "timur", "a-b", "0ab", "ab0", &"a".repeat(32)] {
            assert!(is_username(ok), "{ok}");
        }
        for bad in [
            "",
            "ab",
            "Timur",
            "-ab",
            "ab-",
            "a_b",
            "a.b",
            "tim ur",
            "tïmur",
            &"a".repeat(33),
        ] {
            assert!(!is_username(bad), "{bad}");
        }
    }

    #[test]
    fn a_computer_needs_a_letter_first_and_at_most_31() {
        assert!(fits_computer("timur"));
        assert!(fits_computer("a-0"));
        assert!(fits_computer(&"a".repeat(31)));
        assert!(!fits_computer(&"a".repeat(32)));
        assert!(!fits_computer("0ab"));
        assert!(!fits_computer("Timur"));
    }

    #[test]
    fn nss_finds_root_and_not_a_made_up_name() {
        // Every machine this runs on has root at 0, and no user by this name.
        assert_eq!(Nss.user("root"), Some(0));
        assert_eq!(Nss.uid(0).as_deref(), Some("root"));
        assert_eq!(Nss.group("root"), Some(0));
        assert_eq!(Nss.gid(0).as_deref(), Some("root"));
        assert_eq!(Nss.user("mauvely-no-such-user-x7"), None);
        assert_eq!(Nss.group("mauvely-no-such-group-x7"), None);
        assert_eq!(Nss.user("nul\0byte"), None);
    }
}
