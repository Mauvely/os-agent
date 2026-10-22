//! `/run/mauvely/auth.sock`: root's, `0666`, so any process may connect; who
//! it is decides what it may ask (`SO_PEERCRED`, in `service`). One thread per
//! connection, one authentication per connection. No async runtime.
//!
//! | Limit | |
//! |---|---|
//! | Connections at once | 32; then `busy` |
//! | From one uid other than root | 4; then `busy` |
//! | The first line | 10 s, 8 KiB |
//! | The code | 5 minutes, and never past its challenge's expiry |
//! | Writing an answer | 5 s |

use std::collections::HashMap;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use super::service::{Auth, Service};
use super::wire::{self, Answer, MAX_LINE, Reason, Request};
use crate::Error;

pub const MAX_CONNECTIONS: usize = 32;
pub const PER_UID: usize = 4;
pub const FIRST_LINE: Duration = Duration::from_secs(10);
pub const CODE_WAIT: Duration = Duration::from_secs(300);
const WRITE_WAIT: Duration = Duration::from_secs(5);

/// Binds the socket, replacing a stale one: `0666`, in a directory made if
/// it is missing.
pub fn bind(path: &Path) -> Result<UnixListener, Error> {
    if let Some(dir) = path.parent() {
        fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
    }
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_socket() => {
            fs::remove_file(path).map_err(|e| Error::io(path, e))?;
        }
        Ok(_) => {
            return Err(Error::Invalid(format!(
                "{} is there and is not a socket",
                path.display()
            )));
        }
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(Error::io(path, e)),
    }
    let listener = UnixListener::bind(path).map_err(|e| Error::io(path, e))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o666)).map_err(|e| Error::io(path, e))?;
    Ok(listener)
}

/// Accepts for ever, a thread per connection.
pub fn serve(listener: UnixListener, service: Arc<Service>) {
    let slots = Arc::new(Slots::default());
    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("login: accept: {e}");
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
        };
        let Some(uid) = peer_uid(&stream) else {
            eprintln!("login: a caller whose uid could not be read was refused");
            continue;
        };
        let Some(slot) = Slots::take(&slots, uid) else {
            refuse_now(stream, Reason::Busy);
            continue;
        };
        let service = Arc::clone(&service);
        let spawned = std::thread::Builder::new()
            .name("login".into())
            .spawn(move || {
                let _slot = slot;
                handle(stream, uid, &service);
            });
        if let Err(e) = spawned {
            eprintln!("login: could not start a thread: {e}");
        }
    }
}

/// The connecting process's uid, as the kernel recorded it at `connect`: its
/// effective uid, so `sudo`, `su` and polkit's setuid helper are root here.
pub fn peer_uid(stream: &UnixStream) -> Option<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: the fd is the stream's and open for the call; `cred` and `len`
    // are valid for writes, and `len` holds `cred`'s true size.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast(),
            &mut len,
        )
    };
    (rc == 0 && len as usize == std::mem::size_of::<libc::ucred>()).then_some(cred.uid)
}

fn refuse_now(mut stream: UnixStream, r: Reason) {
    let _ = stream.set_write_timeout(Some(Duration::from_secs(1)));
    let _ = stream.write_all(&wire::line(&Answer::Refused(r)));
}

/// Connections being served, by uid.
#[derive(Default)]
struct Slots(Mutex<HashMap<u32, usize>>);

struct Slot {
    slots: Arc<Slots>,
    uid: u32,
}

impl Slots {
    fn take(slots: &Arc<Slots>, uid: u32) -> Option<Slot> {
        let mut held = slots.0.lock().unwrap_or_else(|e| e.into_inner());
        let total: usize = held.values().sum();
        let mine = held.get(&uid).copied().unwrap_or(0);
        if total >= MAX_CONNECTIONS || (uid != 0 && mine >= PER_UID) {
            return None;
        }
        *held.entry(uid).or_default() += 1;
        Some(Slot {
            slots: Arc::clone(slots),
            uid,
        })
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        let mut held = self.slots.0.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(n) = held.get_mut(&self.uid) {
            *n -= 1;
            if *n == 0 {
                held.remove(&self.uid);
            }
        }
    }
}

/// One authentication.
pub fn handle(mut stream: UnixStream, uid: u32, service: &Service) {
    let _ = stream.set_write_timeout(Some(WRITE_WAIT));
    let mut lines = Lines::default();
    let request = match lines.next(&mut stream, Instant::now() + FIRST_LINE) {
        Ok(line) => wire::parse(&line),
        Err(Ended::TooLong) => Err(Reason::BadRequest),
        Err(Ended::Gone) => return,
    };
    let request = match request {
        Ok(r) => r,
        Err(r) => {
            send(&mut stream, &Answer::Refused(r));
            return;
        }
    };
    match request {
        Request::Auth {
            service: pam,
            username,
            password,
        } => match service.auth(uid, &pam, &username, password) {
            Auth::Done(answer, upgrade) => {
                send(&mut stream, &answer);
                drop(stream);
                if let Some(u) = upgrade {
                    service.upgrade(u);
                }
            }
            Auth::Code(pending) => {
                if !send(&mut stream, &Answer::Code { info: pending.info }) {
                    return;
                }
                let left = pending.expires_at.saturating_sub((service.clock)());
                let wait = CODE_WAIT.min(Duration::from_secs(left));
                let code = match lines.next(&mut stream, Instant::now() + wait) {
                    Ok(line) => wire::parse(&line),
                    Err(Ended::TooLong) => Err(Reason::BadRequest),
                    Err(Ended::Gone) => return,
                };
                let (answer, upgrade) = match code {
                    Ok(Request::Code { code }) => service.code(pending, &code),
                    Ok(_) => (Answer::Refused(Reason::BadRequest), None),
                    Err(r) => (Answer::Refused(r), None),
                };
                send(&mut stream, &answer);
                drop(stream);
                if let Some(u) = upgrade {
                    service.upgrade(u);
                }
            }
        },
        // A code with nothing waiting for it.
        Request::Code { .. } => {
            send(&mut stream, &Answer::Refused(Reason::BadRequest));
        }
        Request::Account {
            service: pam,
            username,
        } => {
            send(&mut stream, &service.account(uid, &pam, &username));
        }
    }
}

fn send(stream: &mut UnixStream, answer: &Answer) -> bool {
    stream.write_all(&wire::line(answer)).is_ok()
}

#[derive(Debug)]
enum Ended {
    /// Closed, or silent past the deadline.
    Gone,
    TooLong,
}

/// Reads lines into one buffer that never grows past `MAX_LINE` and is wiped
/// when dropped: it holds the password.
struct Lines {
    buf: Zeroizing<Vec<u8>>,
}

impl Default for Lines {
    fn default() -> Self {
        Lines {
            buf: Zeroizing::new(Vec::with_capacity(MAX_LINE + 1024)),
        }
    }
}

impl Lines {
    /// The next line, without its newline, before `deadline`.
    fn next(
        &mut self,
        stream: &mut UnixStream,
        deadline: Instant,
    ) -> Result<Zeroizing<Vec<u8>>, Ended> {
        let mut chunk = Zeroizing::new([0u8; 1024]);
        loop {
            if let Some(at) = self.buf.iter().position(|&b| b == b'\n') {
                let line = Zeroizing::new(self.buf[..at].to_vec());
                // Shift what follows down, in place, and wipe the tail.
                let rest = self.buf.len() - at - 1;
                self.buf.copy_within(at + 1.., 0);
                let len = self.buf.len();
                self.buf[rest..len].fill(0);
                self.buf.truncate(rest);
                return Ok(line);
            }
            if self.buf.len() > MAX_LINE {
                return Err(Ended::TooLong);
            }
            let left = deadline
                .checked_duration_since(Instant::now())
                .filter(|d| !d.is_zero())
                .ok_or(Ended::Gone)?;
            stream
                .set_read_timeout(Some(left))
                .map_err(|_| Ended::Gone)?;
            let n = match stream.read(&mut chunk[..]) {
                Ok(0) => return Err(Ended::Gone),
                Ok(n) => n,
                Err(e) if e.kind() == ErrorKind::Interrupted => continue,
                Err(_) => return Err(Ended::Gone),
            };
            let room = (MAX_LINE + 1024).saturating_sub(self.buf.len());
            self.buf.extend_from_slice(&chunk[..n.min(room)]);
        }
    }
}

#[cfg(test)]
mod tests;
