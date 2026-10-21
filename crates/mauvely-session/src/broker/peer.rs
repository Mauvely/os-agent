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
//! 4. `root/.flatpak-info` read, and `root/app` looked at, through the
//!    directory;
//! 5. the pidfd still names that pid.
//!
//! Then, on this side: the sandbox's `/app` must be the very directory its
//! `app-path` names (device and inode), and a system install's deploy file
//! says which remote it came from.
//!
//! A kernel without `SO_PEERPIDFD` (before 6.5) is refused rather than
//! trusted.

use std::fs::{File, OpenOptions};
use std::io::{self, ErrorKind, Read};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::net::UnixStream;
use std::path::Path;

use super::caller::{
    Caller, Info, Sandbox, clean_absolute, deploy_origin, parse_flatpak_info, system_install,
    well_formed_id,
};

/// `.flatpak-info` is a few kilobytes. Anything far larger is not one.
const MAX_INFO: u64 = 64 * 1024;

/// A deploy file is a few hundred bytes.
const MAX_DEPLOY: u64 = 1024 * 1024;

/// A file's device and inode.
type FileId = (u64, u64);

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
    let app = id_at(&dir, c"root/app");
    let after = pidfd_pid(&pidfd);
    Ok(match judge(pid, before, after, info) {
        Ok(info) => Caller::Sandbox(on_disk(info, app)),
        Err(caller) => caller,
    })
}

/// The decision, given what was read: what the sandbox says of itself, or
/// the caller it is without one. `before` and `after` are the pid the pidfd
/// named either side of the read, `None` once the process is gone.
fn judge(
    pid: i32,
    before: Option<i32>,
    after: Option<i32>,
    info: io::Result<String>,
) -> Result<Info, Caller> {
    if before != Some(pid) || after != Some(pid) {
        return Err(Caller::Unknown("it exited while it was identified".into()));
    }
    match info {
        Ok(text) => {
            parse_flatpak_info(&text).map_err(|e| Caller::Unknown(format!(".flatpak-info: {e}")))
        }
        Err(e) if e.kind() == ErrorKind::NotFound => Err(Caller::Host),
        Err(e) => Err(Caller::Unknown(format!(".flatpak-info: {e}"))),
    }
}

/// What the disk says about `info`. `app` is the sandbox's `/app`, as seen
/// through its root.
fn on_disk(info: Info, app: Option<FileId>) -> Sandbox {
    let path = Path::new(&info.app_path);
    let app_mounted = clean_absolute(&info.app_path) && app.is_some() && file_id(path) == app;
    // Only a system install's deploy is read: that path is root's, so
    // nothing the caller chose is opened.
    let origin = (well_formed_id(&info.app) && system_install(&info.app, &info.app_path))
        .then(|| path.parent().map(|d| d.join("deploy")))
        .flatten()
        .and_then(|deploy| read_deploy(&deploy));
    Sandbox {
        app: info.app,
        app_path: info.app_path,
        app_mounted,
        origin,
    }
}

/// The device and inode of `path` under `dir`, not following a symlink at
/// the end. Used for the sandbox's `/app`, as `root/app` under its `/proc`
/// directory.
fn id_at(dir: &File, path: &std::ffi::CStr) -> Option<FileId> {
    // SAFETY: an all-zero `stat` is a valid value to be overwritten.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: a valid directory descriptor, a NUL-terminated path, and
    // `st` valid for writes.
    let r = unsafe {
        libc::fstatat(
            dir.as_raw_fd(),
            path.as_ptr(),
            &mut st,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    (r == 0).then_some((st.st_dev, st.st_ino))
}

/// The device and inode at `path`, not following a symlink at the end.
fn file_id(path: &Path) -> Option<FileId> {
    let m = std::fs::symlink_metadata(path).ok()?;
    Some((m.dev(), m.ino()))
}

/// The origin named in a deploy file. Not a symlink, not a FIFO, a regular
/// file of a sane size.
fn read_deploy(path: &Path) -> Option<String> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_NOCTTY)
        .open(path)
        .ok()?;
    if !file.metadata().ok()?.is_file() {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_DEPLOY + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > MAX_DEPLOY {
        return None;
    }
    deploy_origin(&bytes)
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
    use std::os::unix::net::UnixListener;
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
        let firefox = Info {
            app: "org.mozilla.firefox".into(),
            app_path: "/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/c/files".into(),
        };
        assert_eq!(judge(7, Some(7), Some(7), ok()), Ok(firefox));

        let unknown = |r: Result<Info, Caller>| matches!(r, Err(Caller::Unknown(_)));
        // Gone before, or after: what was read may be someone else's.
        for (before, after) in [(None, Some(7)), (Some(7), None), (None, None)] {
            assert!(unknown(judge(7, before, after, ok())));
        }
        // The pidfd names another pid than SO_PEERCRED did.
        assert!(unknown(judge(7, Some(8), Some(8), ok())));
        // No file means the host, but only while the process is alive.
        let missing = || Err(io::Error::from(ErrorKind::NotFound));
        assert_eq!(judge(7, Some(7), Some(7), missing()), Err(Caller::Host));
        assert!(unknown(judge(7, Some(7), None, missing())));
        // Any other failure, or a file that does not parse: unidentified.
        let denied = Err(io::Error::from(ErrorKind::PermissionDenied));
        assert!(unknown(judge(7, Some(7), Some(7), denied)));
        assert!(unknown(judge(
            7,
            Some(7),
            Some(7),
            Ok("[Application]\n".into())
        )));
    }

    fn scratch(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "mauvely-peer-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn the_sandboxes_app_is_compared_on_disk() {
        let dir = scratch("disk");
        let files = dir.join("files");
        let other = dir.join("other");
        std::fs::create_dir_all(&files).unwrap();
        std::fs::create_dir_all(&other).unwrap();
        let info = |path: &Path| Info {
            app: "org.mozilla.firefox".into(),
            app_path: path.to_str().unwrap().into(),
        };
        assert!(on_disk(info(&files), file_id(&files)).app_mounted);
        // Another directory, nothing at all, or a path that walks about.
        assert!(!on_disk(info(&files), file_id(&other)).app_mounted);
        assert!(!on_disk(info(&files), None).app_mounted);
        let walk = dir.join("other/../files");
        assert!(!on_disk(info(&walk), file_id(&files)).app_mounted);

        // Not a system install: its deploy is not read, whatever is there.
        std::fs::copy(
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/fixtures/deploy-firefox-flathub"
            ),
            dir.join("deploy"),
        )
        .unwrap();
        assert_eq!(on_disk(info(&files), file_id(&files)).origin, None);

        // Through /proc/self/root, this process's own root, a directory is
        // the same one. A symlink is itself, not where it points.
        let proc_dir = File::open("/proc/self").unwrap();
        let tmp = id_at(&proc_dir, c"root/tmp");
        assert!(tmp.is_some());
        assert_eq!(tmp, file_id(Path::new("/tmp")));
        std::os::unix::fs::symlink(&files, dir.join("link")).unwrap();
        let scratch_dir = File::open(&dir).unwrap();
        assert_eq!(id_at(&scratch_dir, c"link"), file_id(&dir.join("link")));
        assert_ne!(id_at(&scratch_dir, c"link"), file_id(&files));
        assert_eq!(id_at(&scratch_dir, c"missing"), None);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_deploy_is_read_only_from_a_plain_file() {
        let real = Path::new(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/deploy-firefox-flathub"
        ));
        assert_eq!(read_deploy(real).as_deref(), Some("flathub"));
        let dir = scratch("deploy");
        assert_eq!(read_deploy(&dir.join("missing")), None);
        assert_eq!(read_deploy(&dir), None);
        // A FIFO: the open does not wait for a writer.
        let fifo = dir.join("fifo");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);
        assert_eq!(read_deploy(&fifo), None);
        // A symlink to a real one.
        let link = dir.join("link");
        std::os::unix::fs::symlink(real, &link).unwrap();
        assert_eq!(read_deploy(&link), None);
        std::fs::remove_dir_all(&dir).unwrap();
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
