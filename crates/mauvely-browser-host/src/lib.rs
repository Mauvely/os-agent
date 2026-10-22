//! The native messaging host of the Mauvely OS browser extension (brief 22,
//! S4). The browser starts it inside its own Flatpak sandbox; it frames the
//! extension's messages onto the sign-in broker's socket and the broker's
//! answers back. `docs/browser.md` has the whole design.
//!
//! ```text
//! extension → host   {"op":"origin"}   or   {"op":"browser"}
//! host → broker      {"v":1,"op":"origin"}\n   or   {"v":1,"op":"browser"}\n
//! broker → host      one JSON line (docs/broker.md)
//! host → extension   {"ok":true,"origin":"https://mauvely.com"}
//!                    {"ok":true,"token":"…","expiresAt":1771200000,"origin":"https://mauvely.com"}
//!                    {"ok":false,"reason":"signed_out"}
//! ```
//!
//! - **Browser side:** native messaging, a 4-byte length in native byte order
//!   and that many bytes of UTF-8 JSON, both ways.
//! - **Broker side:** Suite's framing, one line each way, then the socket
//!   closes.
//! - **What it asks:** only the two ops above, in lines it writes itself. Nothing
//!   the extension sends reaches the broker.
//! - **What it passes back:** the token, its expiry and the origin, each checked;
//!   nothing else (no address, no single sign-on link). Anything it does not
//!   understand is `bad_response`.
//! - **Never logged:** the token. Nothing the broker says is written to
//!   standard error.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

use serde_json::{Value, json};

/// The longest message taken from the extension. Its messages are a few bytes.
pub const MAX_REQUEST: usize = 1024;

/// The longest line taken from the broker: its own limit on a line.
pub const MAX_LINE: usize = 4096;

/// The accounts origins a cookie may be set for. The broker can also answer
/// the local stack's `http://localhost:8787`; the extension has no permission
/// there, so the host refuses it too.
pub const ORIGINS: [&str; 2] = ["https://mauvely.com", "https://mauvely.dev"];

/// The broker answers within about 11 s: a 3 s check of a cached session, then
/// an 8 s mint.
pub const BROKER_TIMEOUT: Duration = Duration::from_secs(15);

/// What the extension may ask.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Which accounts origin this computer uses. Mints nothing.
    Origin,
    /// A browser session.
    Browser,
}

impl Op {
    /// The broker's request, written here, never copied from the extension.
    pub fn line(self) -> &'static [u8] {
        match self {
            Op::Origin => b"{\"v\":1,\"op\":\"origin\"}\n",
            Op::Browser => b"{\"v\":1,\"op\":\"browser\"}\n",
        }
    }
}

/// One message from the extension: a JSON object whose `op` is `origin` or
/// `browser`. Anything else is `unknown_op`.
pub fn parse(message: &[u8]) -> Option<Op> {
    let value: Value = serde_json::from_slice(message).ok()?;
    match value.as_object()?.get("op")?.as_str()? {
        "origin" => Some(Op::Origin),
        "browser" => Some(Op::Browser),
        _ => None,
    }
}

/// A refusal, as the extension gets it.
pub fn refused(reason: &str) -> Value {
    json!({ "ok": false, "reason": reason })
}

/// What the extension gets for the broker's answer `line` to `op`: only the
/// fields it needs, each checked, or `bad_response`.
pub fn reduce(op: Op, line: &[u8]) -> Value {
    reduce_checked(op, line).unwrap_or_else(|| refused("bad_response"))
}

fn reduce_checked(op: Op, line: &[u8]) -> Option<Value> {
    if line.len() > MAX_LINE {
        return None;
    }
    let value: Value = serde_json::from_slice(line.trim_ascii()).ok()?;
    let answer = value.as_object()?;
    if answer.get("v")?.as_i64()? != 1 {
        return None;
    }
    if !answer.get("ok")?.as_bool()? {
        let reason = answer.get("reason")?.as_str()?;
        return reason_ok(reason).then(|| refused(reason));
    }
    let origin = answer.get("origin")?.as_str()?;
    if !ORIGINS.contains(&origin) {
        return None;
    }
    Some(match op {
        Op::Origin => json!({ "ok": true, "origin": origin }),
        Op::Browser => {
            let token = answer.get("token")?.as_str()?;
            let expires_at = answer.get("expiresAt")?.as_u64()?;
            if !token_ok(token) || !(1..=MAX_EXPIRY).contains(&expires_at) {
                return None;
            }
            json!({ "ok": true, "token": token, "expiresAt": expires_at, "origin": origin })
        }
    })
}

/// Unix seconds that JavaScript holds exactly, and well past any session.
const MAX_EXPIRY: u64 = (1 << 53) - 1;

/// website-main's tokens are 32 random bytes in base64url (43 characters).
/// Anything a cookie could not carry as it is, or of an odd length, is not one.
fn token_ok(token: &str) -> bool {
    (16..=256).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// The broker's reasons are short snake_case codes.
fn reason_ok(reason: &str) -> bool {
    (1..=32).contains(&reason.len()) && reason.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// Native messaging framing.
pub mod frame {
    use super::*;

    #[derive(Debug)]
    pub enum ReadError {
        /// Longer than the limit. Its body is not read, so the stream cannot be
        /// trusted after it.
        TooLarge(usize),
        Io(io::Error),
    }

    /// One message, or `None` when the browser closed the pipe between
    /// messages. The pipe closing inside one is an error.
    pub fn read(input: &mut impl Read, max: usize) -> Result<Option<Vec<u8>>, ReadError> {
        let mut prefix = [0u8; 4];
        let mut got = 0;
        while got < 4 {
            match input.read(&mut prefix[got..]) {
                Ok(0) if got == 0 => return Ok(None),
                Ok(0) => return Err(ReadError::Io(io::ErrorKind::UnexpectedEof.into())),
                Ok(n) => got += n,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(ReadError::Io(e)),
            }
        }
        let len = u32::from_ne_bytes(prefix) as usize;
        if len > max {
            return Err(ReadError::TooLarge(len));
        }
        let mut body = vec![0u8; len];
        input.read_exact(&mut body).map_err(ReadError::Io)?;
        Ok(Some(body))
    }

    /// One message, flushed.
    pub fn write(output: &mut impl Write, message: &[u8]) -> io::Result<()> {
        let len = u32::try_from(message.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "message too long"))?;
        output.write_all(&len.to_ne_bytes())?;
        output.write_all(message)?;
        output.flush()
    }
}

/// The broker, as the host sees it: one request line in, one answer line out.
pub trait Broker {
    fn ask(&self, line: &[u8]) -> io::Result<Vec<u8>>;
}

/// The broker's socket.
pub struct Socket {
    pub path: PathBuf,
    pub timeout: Duration,
}

impl Socket {
    /// `$XDG_RUNTIME_DIR/mauvely/broker`. Inside the sandbox that is the host's
    /// own runtime directory, which Flatpak sets; `xdg-run/mauvely` is granted
    /// to the browsers by the agent. `None` without an absolute directory.
    pub fn from_env() -> Option<Socket> {
        Socket::in_runtime(std::env::var_os("XDG_RUNTIME_DIR"))
    }

    fn in_runtime(dir: Option<std::ffi::OsString>) -> Option<Socket> {
        let runtime = PathBuf::from(dir?);
        runtime.is_absolute().then(|| Socket {
            path: runtime.join("mauvely/broker"),
            timeout: BROKER_TIMEOUT,
        })
    }
}

impl Broker for Socket {
    fn ask(&self, line: &[u8]) -> io::Result<Vec<u8>> {
        let mut stream = UnixStream::connect(&self.path)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        stream.write_all(line)?;
        read_line(&mut stream)
    }
}

/// One line of at most `MAX_LINE` bytes and its newline. A longer one is
/// returned long, for `reduce` to refuse; the rest is not read.
fn read_line(stream: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    BufReader::new(stream.take(MAX_LINE as u64 + 2)).read_until(b'\n', &mut line)?;
    Ok(line)
}

/// Answers the extension's messages on `input` until it closes the pipe.
///
/// A message over the limit is answered `too_large`, and the host stops: its
/// body was not read, so nothing after it can be framed. A broker that cannot
/// be reached, or does not answer in time, is `unavailable`.
pub fn serve(
    input: &mut impl Read,
    output: &mut impl Write,
    broker: Option<&dyn Broker>,
) -> io::Result<()> {
    loop {
        let message = match frame::read(input, MAX_REQUEST) {
            Ok(Some(m)) => m,
            Ok(None) => return Ok(()),
            Err(frame::ReadError::TooLarge(len)) => {
                frame::write(output, refused("too_large").to_string().as_bytes())?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("a message of {len} bytes"),
                ));
            }
            Err(frame::ReadError::Io(e)) => return Err(e),
        };
        let answer = match (parse(&message), broker) {
            (None, _) => refused("unknown_op"),
            (Some(_), None) => refused("unavailable"),
            (Some(op), Some(broker)) => match broker.ask(op.line()) {
                Ok(line) => reduce(op, &line),
                Err(e) => {
                    // The error is the socket's, never the broker's words.
                    eprintln!("mauvely-browser-host: the broker: {e}");
                    refused("unavailable")
                }
            },
        };
        frame::write(output, answer.to_string().as_bytes())?;
    }
}

#[cfg(test)]
mod tests;
