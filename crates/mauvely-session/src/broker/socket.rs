//! `$XDG_RUNTIME_DIR/mauvely/broker`: the socket, in a `0700` directory, and
//! one thread per caller.
//!
//! The directory is made once and never removed. A Flatpak granted
//! `xdg-run/mauvely` bind-mounts it when it starts, so a directory made
//! again would leave every running app holding the old one.
//!
//! An app granted the directory read-write (anything but exactly
//! `xdg-run/mauvely:ro`) can unlink the socket and listen in its place. So
//! the socket's device and inode are recorded when it is bound and checked
//! at every tick and after every caller; when something else is there, it is
//! cleared away and the broker listens again. That bounds how long a
//! squatter answers, and cannot stop it answering in between: the fix for
//! that is a directory the person cannot write (HANDOFF).

use std::fs::{self, Permissions};
use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::Broker;
use super::caller::Caller;
use super::wire::{self, Reason};

/// How long a caller has to send its line. The answer may then take as long
/// as the server does; the mint's own timeouts bound that.
const IDLE: Duration = Duration::from_secs(5);

/// How often the socket is checked, and a failed listen tried again.
const TICK: Duration = Duration::from_secs(2);

/// Callers served at once. A caller over this is told `busy`.
pub const MAX_CALLERS: usize = 16;

/// A file's device and inode.
type FileId = (u64, u64);

/// Makes the directory if needed, clears whatever is at `broker`, listens,
/// and records what was bound.
pub fn listen(dir: &Path) -> io::Result<(UnixListener, FileId)> {
    prepare(dir)?;
    let path = dir.join("broker");
    clear(&path)?;
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, Permissions::from_mode(0o600))?;
    let id = socket_id(&path).ok_or_else(|| io::Error::other("the socket went as it was made"))?;
    Ok((listener, id))
}

/// The directory: ours, a real directory, `0700`.
fn prepare(dir: &Path) -> io::Result<()> {
    match fs::DirBuilder::new().mode(0o700).create(dir) {
        Err(e) if e.kind() != ErrorKind::AlreadyExists => return Err(e),
        _ => {}
    }
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() {
        return Err(io::Error::other(format!(
            "{} is not a directory",
            dir.display()
        )));
    }
    // SAFETY: geteuid has no preconditions and cannot fail.
    let me = unsafe { libc::geteuid() };
    if meta.uid() != me {
        return Err(io::Error::other(format!(
            "{} belongs to uid {}",
            dir.display(),
            meta.uid()
        )));
    }
    if meta.mode() & 0o777 != 0o700 {
        fs::set_permissions(dir, Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Removes whatever is at `path`: a socket left by an earlier run, or
/// anything put there in its place. Inside the person's own `0700`
/// directory, all of it is the person's.
fn clear(path: &Path) -> io::Result<()> {
    let removed = match fs::symlink_metadata(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        // Does not follow symlinks inside it.
        Ok(m) if m.is_dir() => fs::remove_dir_all(path),
        Ok(_) => fs::remove_file(path),
    };
    match removed {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

/// The socket at `path`, if a socket is there.
fn socket_id(path: &Path) -> Option<FileId> {
    let m = fs::symlink_metadata(path).ok()?;
    m.file_type().is_socket().then_some((m.dev(), m.ino()))
}

/// Serves callers in `dir`, for ever. `identify` is `peer::identify`
/// outside tests.
pub fn serve(dir: &Path, broker: Arc<Broker>, identify: fn(&UnixStream) -> Caller) {
    serve_with(dir, &broker, identify, TICK, &AtomicBool::new(false));
}

fn serve_with(
    dir: &Path,
    broker: &Arc<Broker>,
    identify: fn(&UnixStream) -> Caller,
    tick: Duration,
    stop: &AtomicBool,
) {
    let active = Arc::new(AtomicUsize::new(0));
    let mut said = String::new();
    while !stop.load(Ordering::SeqCst) {
        let (listener, id) = match listen(dir) {
            Ok(bound) => bound,
            Err(e) => {
                // Once per different failure, not once a tick.
                let e = e.to_string();
                if e != said {
                    eprintln!("mauvely-session: broker: cannot listen, trying again: {e}");
                    said = e;
                }
                std::thread::sleep(tick);
                continue;
            }
        };
        said.clear();
        eprintln!("mauvely-session: broker: listening");
        serve_while_ours(
            &listener,
            id,
            &dir.join("broker"),
            broker,
            identify,
            tick,
            stop,
            &active,
        );
    }
}

/// Serves `listener` until the socket at `path` is no longer the one bound.
#[allow(clippy::too_many_arguments)]
fn serve_while_ours(
    listener: &UnixListener,
    id: FileId,
    path: &Path,
    broker: &Arc<Broker>,
    identify: fn(&UnixStream) -> Caller,
    tick: Duration,
    stop: &AtomicBool,
    active: &Arc<AtomicUsize>,
) {
    if listener.set_nonblocking(true).is_err() {
        return;
    }
    while !stop.load(Ordering::SeqCst) {
        if !still_ours(path, id) {
            eprintln!("mauvely-session: broker: something replaced the socket; listening again");
            return;
        }
        if !readable(listener, tick) {
            continue;
        }
        loop {
            let stream = match listener.accept() {
                Ok((stream, _)) => stream,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                // A caller gone before it was accepted, or out of
                // descriptors for a moment.
                Err(_) => break,
            };
            if stream.set_nonblocking(false).is_err() {
                continue;
            }
            dispatch(stream, broker, identify, active);
        }
    }
}

fn still_ours(path: &Path, id: FileId) -> bool {
    socket_id(path) == Some(id)
}

/// Whether a caller is waiting, waiting at most `tick`.
fn readable(listener: &UnixListener, tick: Duration) -> bool {
    let mut fd = libc::pollfd {
        fd: listener.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    let ms = libc::c_int::try_from(tick.as_millis()).unwrap_or(libc::c_int::MAX);
    // SAFETY: one valid pollfd, and its count.
    unsafe { libc::poll(&mut fd, 1, ms) > 0 }
}

fn dispatch(
    stream: UnixStream,
    broker: &Arc<Broker>,
    identify: fn(&UnixStream) -> Caller,
    active: &Arc<AtomicUsize>,
) {
    let Some(serving) = Serving::start(active) else {
        refuse_busy(stream);
        return;
    };
    let broker = Arc::clone(broker);
    let spawned = std::thread::Builder::new()
        .name("broker caller".into())
        .spawn(move || {
            let _serving = serving;
            handle(stream, &broker, identify);
        });
    if let Err(e) = spawned {
        eprintln!("mauvely-session: broker: {e}");
    }
}

/// One caller being served; the count goes down when it is dropped, however
/// its thread ends.
struct Serving(Arc<AtomicUsize>);

impl Serving {
    fn start(active: &Arc<AtomicUsize>) -> Option<Self> {
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CALLERS {
            active.fetch_sub(1, Ordering::SeqCst);
            return None;
        }
        Some(Serving(Arc::clone(active)))
    }
}

impl Drop for Serving {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

fn refuse_busy(mut stream: UnixStream) {
    eprintln!("mauvely-session: broker: refused a caller: busy");
    let _ = stream.set_write_timeout(Some(IDLE));
    let _ = stream.write_all(&wire::refused(&Reason::Busy));
    let _ = stream.shutdown(Shutdown::Both);
}

fn handle(mut stream: UnixStream, broker: &Broker, identify: fn(&UnixStream) -> Caller) {
    // First, while the caller is certainly still there.
    let caller = identify(&stream);
    let _ = stream.set_write_timeout(Some(IDLE));
    // Nothing it could say would be answered, so it does not hold a place
    // while it says it.
    if matches!(caller, Caller::Host | Caller::Unknown(_)) {
        eprintln!(
            "mauvely-session: broker: refused {}: forbidden",
            caller.describe()
        );
        let _ = stream.write_all(&wire::refused(&Reason::Forbidden));
        let _ = stream.shutdown(Shutdown::Both);
        return;
    }
    let reply = match read_line(&mut stream, Instant::now() + IDLE) {
        Ok(line) => broker.answer(&caller, &line),
        Err(Line::TooLarge) => {
            eprintln!(
                "mauvely-session: broker: refused {}: too_large",
                caller.describe()
            );
            wire::refused(&Reason::TooLarge)
        }
        // Said nothing in time, or went away: there is no one to answer.
        Err(Line::Gone) => return,
    };
    let _ = stream.write_all(&reply);
    let _ = stream.shutdown(Shutdown::Both);
}

enum Line {
    TooLarge,
    /// Timed out, or the caller went away.
    Gone,
}

/// One request line, up to the newline or the end of the stream, and no
/// longer than `wire::MAX_LINE`. All of it by `deadline`.
fn read_line(stream: &mut UnixStream, deadline: Instant) -> Result<Vec<u8>, Line> {
    let mut line = Vec::new();
    let mut buf = [0u8; 1024];
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(Line::Gone);
        }
        stream
            .set_read_timeout(Some(left))
            .map_err(|_| Line::Gone)?;
        let n = stream.read(&mut buf).map_err(|_| Line::Gone)?;
        let chunk = &buf[..n];
        let end = chunk.iter().position(|b| *b == b'\n');
        line.extend_from_slice(&chunk[..end.unwrap_or(n)]);
        if line.len() > wire::MAX_LINE {
            return Err(Line::TooLarge);
        }
        if n == 0 || end.is_some() {
            return Ok(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::broker::seal::tests::temp_dir;
    use crate::broker::testing::{Fixture, compose};
    use std::io::BufRead;
    use std::os::unix::fs::symlink;
    use std::path::PathBuf;

    const QUICK: Duration = Duration::from_millis(50);

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().mode() & 0o777
    }

    /// The broker serving `dir` on a thread, until dropped.
    struct Serving {
        stop: Arc<AtomicBool>,
        thread: Option<std::thread::JoinHandle<()>>,
        _f: Fixture,
    }

    impl Serving {
        fn start(dir: &Path, f: Fixture, identify: fn(&UnixStream) -> Caller) -> Self {
            let stop = Arc::new(AtomicBool::new(false));
            let (dir, broker, flag) = (dir.to_owned(), Arc::clone(&f.broker), Arc::clone(&stop));
            let thread =
                std::thread::spawn(move || serve_with(&dir, &broker, identify, QUICK, &flag));
            Serving {
                stop,
                thread: Some(thread),
                _f: f,
            }
        }
    }

    impl Drop for Serving {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            if let Some(t) = self.thread.take() {
                let _ = t.join();
            }
        }
    }

    /// One exchange, or `None` when nothing answers within a second.
    fn try_exchange(path: &Path, request: &[u8]) -> Option<String> {
        let mut s = UnixStream::connect(path).ok()?;
        s.set_read_timeout(Some(Duration::from_secs(1))).ok()?;
        s.write_all(request).ok()?;
        let mut reply = String::new();
        io::BufReader::new(s).read_line(&mut reply).ok()?;
        (!reply.is_empty()).then_some(reply)
    }

    fn exchange(path: &Path, request: &[u8]) -> String {
        try_exchange(path, request).expect("an answer")
    }

    /// Asks until the broker answers, for up to five seconds.
    fn until_answered(path: &Path) -> String {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(reply) = try_exchange(path, b"{\"v\":2,\"op\":\"browser\"}\n") {
                return reply;
            }
            assert!(Instant::now() < deadline, "nothing answered");
            std::thread::sleep(QUICK);
        }
    }

    fn reason(reply: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(reply).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["ok"], false);
        v["reason"].as_str().unwrap().to_owned()
    }

    /// A directory whose parent goes when the test ends, so a broker still
    /// running cannot make it again.
    fn run_dir(tag: &str) -> (PathBuf, PathBuf) {
        let base = temp_dir(tag);
        fs::create_dir_all(&base).unwrap();
        let dir = base.join("mauvely");
        (base, dir)
    }

    #[test]
    fn the_socket_is_private() {
        let (base, sock) = run_dir("socket");
        let (_listener, id) = listen(&sock).unwrap();
        assert_eq!(mode(&sock), 0o700);
        assert_eq!(mode(&sock.join("broker")), 0o600);
        assert_eq!(socket_id(&sock.join("broker")), Some(id));

        // Again, with the old socket left behind and the mode loosened: the
        // same directory, tightened, and a new socket in it.
        fs::set_permissions(&sock, Permissions::from_mode(0o755)).unwrap();
        let ino = fs::metadata(&sock).unwrap().ino();
        let (_listener, again) = listen(&sock).unwrap();
        assert_ne!(again, id);
        assert_eq!(mode(&sock), 0o700);
        assert_eq!(fs::metadata(&sock).unwrap().ino(), ino);
        UnixStream::connect(sock.join("broker")).unwrap();
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_symlink_or_a_file_is_not_the_directory() {
        let (base, _) = run_dir("socket-link");
        fs::create_dir_all(base.join("elsewhere")).unwrap();
        symlink(base.join("elsewhere"), base.join("mauvely")).unwrap();
        assert!(listen(&base.join("mauvely")).is_err());
        fs::write(base.join("file"), b"").unwrap();
        assert!(listen(&base.join("file")).is_err());
        assert!(!base.join("elsewhere/broker").exists());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn one_line_each_way_then_closed() {
        let f = Fixture::signed_in(vec![(200, Fixture::minted("tok_compose", 3600))]);
        let (base, dir) = run_dir("serve");
        let _serving = Serving::start(&dir, f, |_| compose());
        let path = dir.join("broker");
        until_answered(&path);

        let reply = exchange(
            &path,
            b"{\"v\":1,\"op\":\"token\",\"client\":\"compose\"}\n",
        );
        let v: serde_json::Value = serde_json::from_str(&reply).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["token"], "tok_compose");

        // No newline: the end of the stream ends the line.
        let mut s = UnixStream::connect(&path).unwrap();
        s.write_all(br#"{"v":1,"op":"nope"}"#).unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        let mut reply = String::new();
        s.read_to_string(&mut reply).unwrap();
        assert_eq!(reply.matches('\n').count(), 1);
        assert_eq!(reason(&reply), "unknown_op");

        // Too long.
        let mut long = vec![b'x'; wire::MAX_LINE + 1];
        long.push(b'\n');
        assert_eq!(reason(&exchange(&path, &long)), "too_large");
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn callers_over_the_limit_are_told_busy() {
        let (base, dir) = run_dir("busy");
        let _serving = Serving::start(&dir, Fixture::signed_in(vec![]), |_| compose());
        let path = dir.join("broker");
        until_answered(&path);

        // Each says nothing, so each holds its place until it closes.
        let quiet: Vec<UnixStream> = (0..MAX_CALLERS)
            .map(|_| UnixStream::connect(&path).unwrap())
            .collect();
        std::thread::sleep(QUICK * 4);
        let reply = exchange(&path, b"{\"v\":1,\"op\":\"browser\"}\n");
        assert_eq!(reason(&reply), "busy");

        // Once they go, there is room again.
        drop(quiet);
        assert_eq!(reason(&until_answered(&path)), "version");
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn host_and_unknown_callers_are_refused_before_they_speak() {
        for (tag, identify) in [
            (
                "early-host",
                (|_: &UnixStream| Caller::Host) as fn(&UnixStream) -> Caller,
            ),
            ("early-unknown", |_: &UnixStream| {
                Caller::Unknown("exited".into())
            }),
        ] {
            let (base, dir) = run_dir(tag);
            let _serving = Serving::start(&dir, Fixture::signed_in(vec![]), identify);
            let path = dir.join("broker");
            until_answered(&path);
            // Sends nothing, and still has its answer well before the five
            // seconds a caller gets to speak.
            let s = UnixStream::connect(&path).unwrap();
            s.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
            let mut reply = String::new();
            io::BufReader::new(s).read_line(&mut reply).unwrap();
            assert_eq!(reason(&reply), "forbidden");
            fs::remove_dir_all(&base).unwrap();
        }
    }

    #[test]
    fn a_squatter_is_cleared_away() {
        let (base, dir) = run_dir("squat");
        let _serving = Serving::start(&dir, Fixture::signed_in(vec![]), |_| compose());
        let path = dir.join("broker");
        until_answered(&path);

        // An app with the directory read-write takes the name.
        fs::remove_file(&path).unwrap();
        let squatter = UnixListener::bind(&path).unwrap();
        let theirs = socket_id(&path).unwrap();
        // The broker notices, clears it and listens again; then it, not the
        // squatter, answers.
        assert_eq!(reason(&until_answered(&path)), "version");
        assert_ne!(socket_id(&path), Some(theirs));
        drop(squatter);

        // A directory in its place does not stop it either.
        fs::remove_file(&path).unwrap();
        fs::create_dir_all(path.join("inside")).unwrap();
        fs::write(path.join("inside/file"), b"x").unwrap();
        assert_eq!(reason(&until_answered(&path)), "version");
        assert!(socket_id(&path).is_some());
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_failed_listen_is_tried_again() {
        let (base, dir) = run_dir("retry");
        // Not a directory yet: listening fails.
        fs::write(&dir, b"").unwrap();
        let _serving = Serving::start(&dir, Fixture::signed_in(vec![]), |_| compose());
        std::thread::sleep(QUICK * 3);
        assert!(!dir.is_dir());
        fs::remove_file(&dir).unwrap();
        assert_eq!(reason(&until_answered(&dir.join("broker"))), "version");
        fs::remove_dir_all(&base).unwrap();
    }
}
