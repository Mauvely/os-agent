//! Who is on the other end of the socket: `SO_PEERCRED` for the pid,
//! `SO_PEERPIDFD` so that pid cannot be another process by the time it is
//! read, then `/proc/<pid>/root/.flatpak-info`. Needs no privilege for a
//! peer of the same uid (brief 22's S0, spike 2).
//!
//! The order is the guard against pid reuse:
//! 1. the pid and a pidfd for it, both fixed when the peer connected;
//! 2. `/proc/<pid>` opened as a directory. That descriptor stays bound to
//!    the process it was opened for, and fails once it is gone;
//! 3. the pidfd still names that pid, so the process was alive after step 2
//!    and the directory is its own and not a newcomer's;
//! 4. `root/.flatpak-info` read through the directory;
//! 5. the pidfd still names that pid.
//!
//! A kernel without `SO_PEERPIDFD` (before 6.5) is refused rather than
//! trusted.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::net::UnixStream;

use super::caller::{Caller, parse_flatpak_info};

/// `.flatpak-info` is a few kilobytes. Anything far larger is not one.
const MAX_INFO: u64 = 64 * 1024;

pub fn identify(stream: &UnixStream) -> Caller {
    look(stream.as_raw_fd()).unwrap_or_else(Caller::Unknown)
}

fn look(socket: RawFd) -> Result<Caller, String> {
    let cred = peer_cred(socket).map_err(|e| format!("SO_PEERCRED: {e}"))?;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    if cred.uid != me {
        return Err(format!("uid {}", cred.uid));
    }
    // 0 when the peer's pid is not visible in this pid namespace.
    if cred.pid <= 0 {
        return Err("no pid in this namespace".into());
    }
    let pid = cred.pid;
    let pidfd = peer_pidfd(socket).map_err(|e| format!("SO_PEERPIDFD: {e}"))?;
    let dir = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_PATH | libc::O_DIRECTORY | libc::O_CLOEXEC)
        .open(format!("/proc/{pid}"))
        .map_err(|e| format!("/proc/{pid}: {e}"))?;
    let before = pidfd_pid(&pidfd);
    let info = read_info(&dir);
    let after = pidfd_pid(&pidfd);
    Ok(judge(pid, before, after, info))
}

/// The decision, given what was read. `before` and `after` are the pid the
/// pidfd named either side of the read, `None` once the process is gone.
fn judge(pid: i32, before: Option<i32>, after: Option<i32>, info: io::Result<String>) -> Caller {
    if before != Some(pid) || after != Some(pid) {
        return Caller::Unknown("it exited while it was identified".into());
    }
    match info {
        Ok(text) => match parse_flatpak_info(&text) {
            Ok(sandbox) => Caller::Sandbox(sandbox),
            Err(e) => Caller::Unknown(format!(".flatpak-info: {e}")),
        },
        Err(e) if e.kind() == ErrorKind::NotFound => Caller::Host,
        Err(e) => Caller::Unknown(format!(".flatpak-info: {e}")),
    }
}

/// `root/.flatpak-info` under the peer's `/proc` directory: through the
/// peer's own root, so its mount namespace. Not a symlink, not a FIFO (the
/// open does not wait for a writer), a regular file of a sane size.
fn read_info(dir: &File) -> io::Result<String> {
    // SAFETY: a valid directory descriptor and a NUL-terminated path.
    let fd = unsafe {
        libc::openat(
            dir.as_raw_fd(),
            c"root/.flatpak-info".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NOCTTY | libc::O_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: openat just returned this descriptor, and nothing else owns it.
    let file = unsafe { File::from_raw_fd(fd) };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(ErrorKind::InvalidData, "not a regular file"));
    }
    let mut text = String::new();
    file.take(MAX_INFO + 1).read_to_string(&mut text)?;
    if text.len() as u64 > MAX_INFO {
        return Err(io::Error::new(ErrorKind::InvalidData, "too large"));
    }
    Ok(text)
}

fn peer_cred(socket: RawFd) -> io::Result<libc::ucred> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `cred` and `len` are valid for writes of the size passed.
    let r = unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    if len as usize != size_of::<libc::ucred>() {
        return Err(io::Error::other("a short answer"));
    }
    Ok(cred)
}

fn peer_pidfd(socket: RawFd) -> io::Result<OwnedFd> {
    let mut pidfd: libc::c_int = -1;
    let mut len = size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `pidfd` and `len` are valid for writes of the size passed.
    let r = unsafe {
        libc::getsockopt(
            socket,
            libc::SOL_SOCKET,
            libc::SO_PEERPIDFD,
            (&raw mut pidfd).cast(),
            &mut len,
        )
    };
    if r != 0 {
        return Err(io::Error::last_os_error());
    }
    if pidfd < 0 {
        return Err(io::Error::other("no descriptor"));
    }
    // SAFETY: the kernel just handed us this descriptor, and nothing else
    // owns it.
    Ok(unsafe { OwnedFd::from_raw_fd(pidfd) })
}

/// The pid a pidfd names now, in this pid namespace, or `None` when the
/// process has exited.
fn pidfd_pid(pidfd: &OwnedFd) -> Option<i32> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", pidfd.as_raw_fd())).ok()?;
    fdinfo_pid(&text)
}

/// The `Pid:` line of a pidfd's fdinfo. The kernel writes -1 there once the
/// process is reaped.
fn fdinfo_pid(text: &str) -> Option<i32> {
    text.lines()
        .find_map(|l| l.strip_prefix("Pid:"))
        .and_then(|v| v.trim().parse().ok())
        .filter(|p| *p > 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::caller::Sandbox;
    use std::os::unix::net::UnixListener;
    use std::path::Path;
    use std::process::Command;

    const INFO: &str = "[Application]\nname=org.mozilla.firefox\n\n[Instance]\n\
        app-path=/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/c/files\n";

    #[test]
    fn reads_the_pid_from_fdinfo() {
        let fdinfo =
            "pos:\t0\nflags:\t02000002\nmnt_id:\t16\nino:\t2076\nPid:\t4242\nNSpid:\t4242\n";
        assert_eq!(fdinfo_pid(fdinfo), Some(4242));
        assert_eq!(fdinfo_pid("Pid:\t-1\nNSpid:\t-1\n"), None);
        assert_eq!(fdinfo_pid("Pid:\t0\n"), None);
        assert_eq!(fdinfo_pid("pos:\t0\n"), None);
        assert_eq!(fdinfo_pid("Pid:\tabc\n"), None);
    }

    #[test]
    fn the_process_must_outlive_the_read() {
        let ok = || Ok(INFO.to_owned());
        let firefox = Caller::Sandbox(Sandbox {
            app: "org.mozilla.firefox".into(),
            app_path: "/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/c/files".into(),
        });
        assert_eq!(judge(7, Some(7), Some(7), ok()), firefox);

        // Gone before, or after: what was read may be someone else's.
        for (before, after) in [(None, Some(7)), (Some(7), None), (None, None)] {
            assert!(matches!(judge(7, before, after, ok()), Caller::Unknown(_)));
        }
        // The pidfd names another pid than SO_PEERCRED did.
        assert!(matches!(
            judge(7, Some(8), Some(8), ok()),
            Caller::Unknown(_)
        ));
        // No file means the host, but only while the process is alive.
        let missing = || Err(io::Error::from(ErrorKind::NotFound));
        assert_eq!(judge(7, Some(7), Some(7), missing()), Caller::Host);
        assert!(matches!(
            judge(7, Some(7), None, missing()),
            Caller::Unknown(_)
        ));
        // Any other failure, or a file that does not parse: unidentified.
        let denied = Err(io::Error::from(ErrorKind::PermissionDenied));
        assert!(matches!(
            judge(7, Some(7), Some(7), denied),
            Caller::Unknown(_)
        ));
        assert!(matches!(
            judge(7, Some(7), Some(7), Ok("[Application]\n".into())),
            Caller::Unknown(_)
        ));
    }

    #[test]
    fn this_process_is_a_host_process() {
        let (a, _b) = UnixStream::pair().unwrap();
        let caller = identify(&a);
        if Path::new("/.flatpak-info").exists() {
            // Running the tests inside a Flatpak.
            assert!(!matches!(caller, Caller::Host), "{caller:?}");
        } else {
            assert_eq!(caller, Caller::Host);
        }
    }

    /// The child half of the next test: connects, then exits. Does nothing
    /// in an ordinary run.
    #[test]
    fn child_connects_and_exits() {
        if let Some(path) = std::env::var_os("MAUVELY_TEST_CONNECT") {
            let _ = UnixStream::connect(path);
            std::process::exit(0);
        }
    }

    #[test]
    fn a_peer_that_has_exited_is_not_identified() {
        let dir = std::env::temp_dir().join(format!(
            "mauvely-peer-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let status = Command::new(std::env::current_exe().unwrap())
            .args([
                "broker::peer::tests::child_connects_and_exits",
                "--exact",
                "--test-threads=1",
            ])
            .env("MAUVELY_TEST_CONNECT", &path)
            .output()
            .unwrap()
            .status;
        assert!(status.success());
        // Reaped by now. Its connection is still waiting to be accepted.
        let (stream, _) = listener.accept().unwrap();
        let caller = identify(&stream);
        assert!(matches!(caller, Caller::Unknown(_)), "{caller:?}");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
