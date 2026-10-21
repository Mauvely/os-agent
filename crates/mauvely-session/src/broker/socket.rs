//! `$XDG_RUNTIME_DIR/mauvely/broker`: the socket, in a `0700` directory, and
//! one thread per caller.
//!
//! The directory is made once and never removed. A Flatpak granted
//! `xdg-run/mauvely` bind-mounts it when it starts, so a directory made
//! again would leave every running app holding the old one.

use std::fs::{self, Permissions};
use std::io::{self, ErrorKind, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::Broker;
use super::caller::Caller;
use super::wire::{self, Reason};

/// How long a caller has to send its line. The answer may then take as long
/// as the server does; the mint's own timeouts bound that.
const IDLE: Duration = Duration::from_secs(5);

/// Callers served at once. A caller over this is told `busy`.
pub const MAX_CALLERS: usize = 16;

/// Makes the directory if needed, and listens. A socket left by an earlier
/// run is replaced.
pub fn listen(dir: &Path) -> io::Result<UnixListener> {
    prepare(dir)?;
    let path = dir.join("broker");
    match fs::remove_file(&path) {
        Err(e) if e.kind() != ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, Permissions::from_mode(0o600))?;
    Ok(listener)
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

/// Serves callers until the listener fails. `identify` is `peer::identify`
/// outside tests.
pub fn serve(
    listener: UnixListener,
    broker: Arc<Broker>,
    identify: fn(&UnixStream) -> Caller,
) -> io::Error {
    let active = Arc::new(AtomicUsize::new(0));
    loop {
        let stream = match listener.accept() {
            Ok((stream, _)) => stream,
            // Out of descriptors, or a caller gone before it was accepted.
            Err(e) if e.kind() == ErrorKind::ConnectionAborted => continue,
            Err(e) if e.raw_os_error() == Some(libc::EMFILE) => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return e,
        };
        let serving = Serving::start(&active);
        if serving.is_none() {
            refuse_busy(stream);
            continue;
        }
        let broker = Arc::clone(&broker);
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

    fn mode(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().mode() & 0o777
    }

    #[test]
    fn the_socket_is_private() {
        let dir = temp_dir("socket");
        fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("mauvely");
        let _listener = listen(&sock).unwrap();
        assert_eq!(mode(&sock), 0o700);
        assert_eq!(mode(&sock.join("broker")), 0o600);

        // Again, with the old socket left behind and the mode loosened: the
        // same directory, tightened, and a new socket in it.
        fs::set_permissions(&sock, Permissions::from_mode(0o755)).unwrap();
        let ino = fs::metadata(&sock).unwrap().ino();
        let _listener = listen(&sock).unwrap();
        assert_eq!(mode(&sock), 0o700);
        assert_eq!(fs::metadata(&sock).unwrap().ino(), ino);
        UnixStream::connect(sock.join("broker")).unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_symlink_or_a_file_is_not_the_directory() {
        let dir = temp_dir("socket-link");
        fs::create_dir_all(dir.join("elsewhere")).unwrap();
        symlink(dir.join("elsewhere"), dir.join("mauvely")).unwrap();
        assert!(listen(&dir.join("mauvely")).is_err());
        fs::write(dir.join("file"), b"").unwrap();
        assert!(listen(&dir.join("file")).is_err());
        assert!(!dir.join("elsewhere/broker").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    fn exchange(path: &Path, request: &[u8]) -> String {
        let mut s = UnixStream::connect(path).unwrap();
        s.write_all(request).unwrap();
        let mut reply = String::new();
        io::BufReader::new(s).read_line(&mut reply).unwrap();
        reply
    }

    fn reason(reply: &str) -> String {
        let v: serde_json::Value = serde_json::from_str(reply).unwrap();
        assert_eq!(v["v"], 1);
        assert_eq!(v["ok"], false);
        v["reason"].as_str().unwrap().to_owned()
    }

    #[test]
    fn one_line_each_way_then_closed() {
        let f = Fixture::signed_in(vec![(200, Fixture::minted("tok_compose", 3600))]);
        let dir = temp_dir("serve");
        let listener = listen(&dir).unwrap();
        let broker = Arc::clone(&f.broker);
        std::thread::spawn(move || serve(listener, broker, |_| compose()));
        let path = dir.join("broker");

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
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn callers_over_the_limit_are_told_busy() {
        let f = Fixture::signed_in(vec![]);
        let dir = temp_dir("busy");
        let listener = listen(&dir).unwrap();
        let broker = Arc::clone(&f.broker);
        std::thread::spawn(move || serve(listener, broker, |_| compose()));
        let path = dir.join("broker");

        // Each says nothing, so each holds its place until it closes.
        let quiet: Vec<UnixStream> = (0..MAX_CALLERS)
            .map(|_| UnixStream::connect(&path).unwrap())
            .collect();
        let reply = exchange(&path, b"{\"v\":1,\"op\":\"browser\"}\n");
        assert_eq!(reason(&reply), "busy");

        // Once they go, there is room again.
        drop(quiet);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let reply = exchange(&path, b"{\"v\":2,\"op\":\"browser\"}\n");
            if reason(&reply) == "version" {
                break;
            }
            assert!(Instant::now() < deadline, "{reply}");
            std::thread::sleep(Duration::from_millis(20));
        }
        fs::remove_dir_all(&dir).unwrap();
    }
}
