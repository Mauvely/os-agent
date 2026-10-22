//! The one thing this module talks to: mauvelyd's login socket. One
//! connection per authentication, one JSON line each way. mauvelyd's side,
//! and the protocol, is `crates/mauvelyd/src/login/wire.rs`.
//!
//! Fails fast and closed: a socket that is missing or refuses is an error at
//! once; a full listen queue waits `CONNECT` at most; a daemon that accepts
//! and says nothing, the caller's timeout.

use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// The socket.
pub const SOCKET: &str = "/run/mauvely/auth.sock";
/// Waiting for a place in the daemon's listen queue.
const CONNECT: Duration = Duration::from_secs(5);
const WRITE: Duration = Duration::from_secs(5);
/// An answer is a short line.
const MAX_ANSWER: usize = 4096;

/// What the daemon answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Ok,
    /// Ask the person for a code: say `info`, then prompt with `prompt`.
    Code {
        prompt: String,
        info: String,
    },
    Refused {
        reason: String,
        message: String,
    },
}

#[derive(Deserialize)]
struct Line {
    result: String,
    prompt: Option<String>,
    info: Option<String>,
    reason: Option<String>,
    message: Option<String>,
}

/// Text from the daemon for the person: no control characters, at most 300
/// characters.
fn clean(s: Option<String>) -> String {
    s.unwrap_or_default()
        .chars()
        .filter(|c| !c.is_control())
        .take(300)
        .collect()
}

pub fn parse(line: &[u8]) -> Option<Answer> {
    let l: Line = serde_json::from_slice(line).ok()?;
    match l.result.as_str() {
        "ok" => Some(Answer::Ok),
        "code" => Some(Answer::Code {
            prompt: Some(clean(l.prompt)).filter(|p| !p.is_empty())?,
            info: clean(l.info),
        }),
        "refused" => Some(Answer::Refused {
            reason: clean(l.reason),
            message: clean(l.message),
        }),
        _ => None,
    }
}

#[derive(Serialize)]
#[serde(tag = "op", rename_all = "lowercase")]
pub enum Request<'a> {
    Auth {
        service: &'a str,
        username: &'a str,
        password: &'a str,
    },
    Code {
        code: &'a str,
    },
    Account {
        service: &'a str,
        username: &'a str,
    },
}

#[derive(Serialize)]
struct Versioned<'a> {
    v: u32,
    #[serde(flatten)]
    request: &'a Request<'a>,
}

/// The request as a line, in a buffer big enough from the start that it is
/// never moved, so the password in it is in one place, wiped on drop.
pub fn line(request: &Request) -> Zeroizing<Vec<u8>> {
    let secret = match request {
        Request::Auth { password, .. } => password.len(),
        Request::Code { code } => code.len(),
        Request::Account { .. } => 0,
    };
    let mut out = Zeroizing::new(Vec::with_capacity(secret * 6 + 512));
    serde_json::to_writer(&mut *out, &Versioned { v: 1, request }).expect("always serialises");
    out.push(b'\n');
    out
}

#[derive(Debug)]
pub enum Error {
    /// The socket is missing, refused, or the daemon was not heard in time.
    Unreachable(io::Error),
    /// It answered something that is not the protocol.
    Garbled,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Unreachable(e) => write!(f, "{e}"),
            Error::Garbled => f.write_str("an answer that is not the protocol"),
        }
    }
}

/// A connection to the daemon.
pub struct Conn {
    stream: UnixStream,
    read: Vec<u8>,
}

impl Conn {
    pub fn open(path: &Path) -> Result<Conn, Error> {
        let stream = connect(path, CONNECT).map_err(Error::Unreachable)?;
        stream
            .set_write_timeout(Some(WRITE))
            .map_err(Error::Unreachable)?;
        Ok(Conn {
            stream,
            read: Vec::with_capacity(MAX_ANSWER),
        })
    }

    /// Sends `line` and waits at most `wait` for the answer.
    pub fn ask(&mut self, line: &[u8], wait: Duration) -> Result<Answer, Error> {
        self.stream.write_all(line).map_err(Error::Unreachable)?;
        let deadline = Instant::now() + wait;
        let mut chunk = [0u8; 512];
        loop {
            if let Some(at) = self.read.iter().position(|&b| b == b'\n') {
                let answer = parse(&self.read[..at]).ok_or(Error::Garbled);
                self.read.drain(..=at);
                return answer;
            }
            if self.read.len() >= MAX_ANSWER {
                return Err(Error::Garbled);
            }
            let left = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or_else(|| Error::Unreachable(io::ErrorKind::TimedOut.into()))?;
            self.stream
                .set_read_timeout(Some(left))
                .map_err(Error::Unreachable)?;
            match self.stream.read(&mut chunk) {
                Ok(0) => return Err(Error::Unreachable(io::ErrorKind::UnexpectedEof.into())),
                Ok(n) => self.read.extend_from_slice(&chunk[..n]),
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(Error::Unreachable(e)),
            }
        }
    }
}

/// A Unix stream connected to `path`. `SO_SNDTIMEO` is set before
/// `connect`, which Linux honours for a full listen queue, so a daemon that
/// has stopped accepting cannot hold the login for ever.
fn connect(path: &Path, wait: Duration) -> io::Result<UnixStream> {
    let bytes = path.as_os_str().as_bytes();
    // SAFETY: sockaddr_un is plain data; all-zero is a valid, empty address.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if bytes.len() >= addr.sun_path.len() || bytes.contains(&0) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, src) in addr.sun_path.iter_mut().zip(bytes) {
        *dst = *src as libc::c_char;
    }
    // SAFETY: socket() takes no pointers; a negative result is checked.
    let fd = unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is a socket just made and owned by nobody else; OwnedFd
    // closes it on every path from here.
    let fd = unsafe { OwnedFd::from_raw_fd(fd) };
    let tv = libc::timeval {
        tv_sec: wait.as_secs() as libc::time_t,
        tv_usec: wait.subsec_micros() as libc::suseconds_t,
    };
    use std::os::fd::AsRawFd;
    // SAFETY: `tv` is a valid timeval for the length given, and lives
    // through the call.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            (&tv as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + bytes.len() + 1;
    loop {
        // SAFETY: `addr` is a sockaddr_un holding a NUL-terminated path, and
        // `len` does not exceed its size.
        let rc = unsafe {
            libc::connect(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_un).cast(),
                len as libc::socklen_t,
            )
        };
        if rc == 0 {
            break;
        }
        let e = io::Error::last_os_error();
        if e.kind() != io::ErrorKind::Interrupted {
            return Err(e);
        }
    }
    Ok(UnixStream::from(fd))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    use std::os::unix::net::UnixListener;

    #[test]
    fn requests_are_the_protocols_lines() {
        let l = line(&Request::Auth {
            service: "plasmalogin",
            username: "timur",
            password: "pa\"ss",
        });
        assert_eq!(
            std::str::from_utf8(&l).unwrap(),
            "{\"v\":1,\"op\":\"auth\",\"service\":\"plasmalogin\",\"username\":\"timur\",\"password\":\"pa\\\"ss\"}\n"
        );
        assert_eq!(
            std::str::from_utf8(&line(&Request::Code { code: "123456" })).unwrap(),
            "{\"v\":1,\"op\":\"code\",\"code\":\"123456\"}\n"
        );
        assert_eq!(
            std::str::from_utf8(&line(&Request::Account {
                service: "sudo",
                username: "timur"
            }))
            .unwrap(),
            "{\"v\":1,\"op\":\"account\",\"service\":\"sudo\",\"username\":\"timur\"}\n"
        );
    }

    #[test]
    fn a_password_line_is_never_moved_while_it_is_written() {
        // Escaping can make it six times longer; the buffer was big enough.
        let password = "\u{1}".repeat(600);
        let l = line(&Request::Auth {
            service: "kde",
            username: "a",
            password: &password,
        });
        assert!(l.len() <= l.capacity());
        assert!(l.capacity() == password.len() * 6 + 512);
    }

    #[test]
    fn answers_parse() {
        assert_eq!(parse(br#"{"result":"ok"}"#), Some(Answer::Ok));
        assert_eq!(
            parse(br#"{"result":"code","prompt":"Code","info":"Enter the code."}"#),
            Some(Answer::Code {
                prompt: "Code".into(),
                info: "Enter the code.".into()
            })
        );
        assert_eq!(
            parse(br#"{"result":"refused","reason":"credentials","message":"Wrong\u0007 name."}"#),
            Some(Answer::Refused {
                reason: "credentials".into(),
                message: "Wrong name.".into()
            })
        );
        assert_eq!(parse(br#"{"result":"code","info":"x"}"#), None);
        assert_eq!(parse(br#"{"result":"maybe"}"#), None);
        assert_eq!(parse(b"nope"), None);
    }

    fn temp(tag: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("pam-mauvely-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn a_missing_socket_fails_at_once() {
        let dir = temp("missing");
        let start = Instant::now();
        assert!(matches!(
            Conn::open(&dir.join("auth.sock")),
            Err(Error::Unreachable(_))
        ));
        // A socket nobody listens on any more.
        let path = dir.join("dead.sock");
        drop(UnixListener::bind(&path).unwrap());
        assert!(matches!(Conn::open(&path), Err(Error::Unreachable(_))));
        assert!(start.elapsed() < Duration::from_secs(1));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_silent_daemon_is_given_up_on() {
        let dir = temp("silent");
        let path = dir.join("auth.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let mut conn = Conn::open(&path).unwrap();
        let start = Instant::now();
        let got = conn.ask(b"{}\n", Duration::from_millis(200));
        assert!(matches!(got, Err(Error::Unreachable(_))), "{got:?}");
        assert!(start.elapsed() < Duration::from_secs(2));
        drop(listener);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn one_connection_carries_the_password_then_the_code() {
        let dir = temp("two");
        let path = dir.join("auth.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut r = BufReader::new(s.try_clone().unwrap());
            let mut w = s;
            let mut got = Vec::new();
            for answer in [
                "{\"result\":\"code\",\"prompt\":\"Code\",\"info\":\"i\"}\n",
                "{\"result\":\"ok\"}\n",
            ] {
                let mut l = String::new();
                r.read_line(&mut l).unwrap();
                got.push(l);
                w.write_all(answer.as_bytes()).unwrap();
            }
            got
        });
        let mut conn = Conn::open(&path).unwrap();
        let a = conn
            .ask(
                &line(&Request::Auth {
                    service: "plasmalogin",
                    username: "timur",
                    password: "pw",
                }),
                Duration::from_secs(5),
            )
            .unwrap();
        assert!(matches!(a, Answer::Code { .. }));
        let a = conn
            .ask(&line(&Request::Code { code: "1" }), Duration::from_secs(5))
            .unwrap();
        assert_eq!(a, Answer::Ok);
        let got = server.join().unwrap();
        assert!(got[0].contains("\"op\":\"auth\""));
        assert!(got[1].contains("\"op\":\"code\""));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_garbled_or_endless_answer_is_refused() {
        let dir = temp("garbled");
        let path = dir.join("auth.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let server = std::thread::spawn(move || {
            for reply in [b"<html>\n".to_vec(), vec![b'a'; MAX_ANSWER + 10]] {
                let (mut s, _) = listener.accept().unwrap();
                let mut l = String::new();
                BufReader::new(s.try_clone().unwrap())
                    .read_line(&mut l)
                    .unwrap();
                let _ = s.write_all(&reply);
            }
        });
        for _ in 0..2 {
            let mut conn = Conn::open(&path).unwrap();
            assert!(matches!(
                conn.ask(b"{}\n", Duration::from_secs(5)),
                Err(Error::Garbled)
            ));
        }
        server.join().unwrap();
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
