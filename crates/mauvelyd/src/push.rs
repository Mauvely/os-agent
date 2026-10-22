//! The push channel: one outbound WebSocket to this device's Durable Object in
//! website-devices, so a change in the console reaches the device at once
//! instead of at its next check-in. Brief 27's remote access will ride on it.
//!
//! It is `GET /api/agent/v2/socket`, signed as a check-in is (`signing`, over
//! `GET`, the path and an empty body). Tonight it carries one message,
//! `{"t":"checkin"}`, which [`run`] passes on as [`Push::CheckIn`] and the
//! check-in loop takes as "check in now" ([`Wake`]). Any other message is
//! ignored, so the server can add types later.
//!
//! It is an optimisation and nothing depends on it: if it never connects, the
//! agent checks in on its interval exactly as it did before it existed.
//!
//! - **Keepalive:** the text `ping` every 45 s, which the object answers `pong`
//!   without waking (`setWebSocketAutoResponse`). Text, not protocol Pings: a
//!   protocol Ping is answered by whatever terminates the socket below the
//!   object, so its Pong would not say the object still holds this socket.
//!   Nothing heard for two intervals, not even `pong`, and the connection is
//!   dead.
//! - **Reconnecting:** `schedule`'s backoff with jitter, as the check-in does.
//!   403 `revoked` stops it until the agent restarts. 404 or 426 is a server
//!   that predates the channel, asked again hourly.
//! - **One thread, blocking,** with a read timeout on the socket: no runtime.
//!   TLS is rustls on ring with webpki-roots, the stack `ureq` already uses.

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use serde::Deserialize;
use tungstenite::client::IntoClientRequest;
use tungstenite::handshake::HandshakeError;
use tungstenite::http::Uri;
use tungstenite::http::header::{HeaderName, HeaderValue, USER_AGENT};
use tungstenite::protocol::WebSocketConfig;
use tungstenite::{Error as WsError, Message, WebSocket};

use crate::schedule::{self, Backoff};
use crate::{api, signing};

/// What the server can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// Check in now.
    CheckIn,
}

/// Where the channel connects, and as whom. Holds the device key, so it has no
/// `Debug`.
pub struct Config {
    /// The server's origin, as `/etc/mauvely/server` gives it.
    pub server: String,
    pub device: String,
    pub key: SigningKey,
}

/// The channel's clocks. Tests shorten them.
#[derive(Debug, Clone)]
pub struct Timing {
    /// How often the text `ping` is sent.
    pub ping: Duration,
    /// Silence after which the connection is dead.
    pub dead_after: Duration,
    /// For the TCP connect and the upgrade.
    pub connect_timeout: Duration,
    /// Seconds before asking a server without the channel again.
    pub no_channel_s: u64,
}

impl Default for Timing {
    fn default() -> Self {
        Timing {
            ping: Duration::from_secs(45),
            dead_after: Duration::from_secs(90),
            connect_timeout: Duration::from_secs(30),
            no_channel_s: 3600,
        }
    }
}

/// Why [`run`] returned.
#[derive(Debug, PartialEq, Eq)]
pub enum Ended {
    /// The server answered the upgrade 403 `revoked`.
    Revoked,
    /// Nobody is listening for pushes any more.
    Unwanted,
}

/// Starts the channel on its own thread, and returns what the check-in loop
/// waits on. If the thread cannot start, the loop sleeps as it always did.
pub fn start(config: Config) -> Wake {
    let (tx, rx) = mpsc::channel();
    let spawned = thread::Builder::new()
        .name("push".into())
        .spawn(move || run(&config, &Timing::default(), &tx, &mut thread::sleep));
    match spawned {
        Ok(_) => Wake::new(rx),
        Err(e) => {
            eprintln!("push channel: could not start: {e}");
            Wake::new(mpsc::channel().1)
        }
    }
}

/// Connects, passes pushes on, and reconnects, until the device is revoked
/// or nobody is listening. Every wait between attempts goes through `sleep`.
pub fn run(
    config: &Config,
    timing: &Timing,
    pushes: &Sender<Push>,
    sleep: &mut dyn FnMut(Duration),
) -> Ended {
    let mut backoff = Backoff::default();
    loop {
        let wait = match connect(config, timing) {
            Ok(mut ws) => {
                backoff.reset();
                eprintln!("push channel: connected");
                match serve(&mut ws, timing, pushes) {
                    Served::Unwanted => return Ended::Unwanted,
                    Served::Dropped(why) => {
                        let wait = schedule::jitter(backoff.fail());
                        eprintln!("push channel: {why}; reconnecting in {}s", wait.as_secs());
                        wait
                    }
                }
            }
            Err(Refused::Revoked) => {
                eprintln!("push channel: this device has been revoked; not connecting again");
                return Ended::Revoked;
            }
            Err(Refused::NoChannel(status)) => {
                let wait = schedule::jitter(timing.no_channel_s);
                eprintln!(
                    "push channel: the server has none (HTTP {status}); asking again in {}s",
                    wait.as_secs()
                );
                wait
            }
            Err(Refused::Failed(why)) => {
                let wait = schedule::jitter(backoff.fail());
                eprintln!("push channel: {why}; retrying in {}s", wait.as_secs());
                wait
            }
        };
        sleep(wait);
    }
}

// ── waking the check-in loop ────────────────────────────────────────────────

/// Never two check-ins closer than this because of pushes.
pub const NUDGE_FLOOR: Duration = Duration::from_secs(5);

/// How a [`Wake::wait`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Woke {
    /// The time was up.
    Timer,
    /// A push said to check in now.
    Nudged,
}

/// What the check-in loop sleeps on: the time until its next check-in, cut
/// short by a push.
pub struct Wake {
    /// `None` once the channel has ended; then a wait is a plain sleep.
    rx: Option<Receiver<Push>>,
    floor: Duration,
}

impl Wake {
    pub fn new(rx: Receiver<Push>) -> Self {
        Wake::with_floor(rx, NUDGE_FLOOR)
    }

    pub fn with_floor(rx: Receiver<Push>, floor: Duration) -> Self {
        Wake {
            rx: Some(rx),
            floor,
        }
    }

    /// Waits `d`. When `nudgeable`, a push ends the wait early, but never
    /// sooner than the floor after it began, and pushes that arrive meanwhile
    /// are one. When not (after a failed check-in), pushes are let go and the
    /// whole of `d` is waited: a push never cuts a backoff short.
    pub fn wait(&mut self, d: Duration, nudgeable: bool) -> Woke {
        let start = Instant::now();
        let deadline = start + d;
        let earliest = (start + self.floor).min(deadline);
        let mut nudged = false;
        loop {
            let until = if nudged { earliest } else { deadline };
            let now = Instant::now();
            if now >= until {
                return if nudged { Woke::Nudged } else { Woke::Timer };
            }
            let Some(rx) = &self.rx else {
                thread::sleep(until - now);
                continue;
            };
            match rx.recv_timeout(until - now) {
                Ok(Push::CheckIn) => nudged |= nudgeable,
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => self.rx = None,
            }
        }
    }
}

// ── the connection ──────────────────────────────────────────────────────────

/// Why an upgrade did not become a socket.
#[derive(Debug, PartialEq, Eq)]
enum Refused {
    /// 403 `revoked`.
    Revoked,
    /// 404 or 426: the server has no push channel.
    NoChannel(u16),
    /// Anything else, tried again with backoff.
    Failed(String),
}

/// The socket's URL for a server origin: `wss` for `https`, `ws` for `http`.
fn socket_url(server: &str) -> Result<String, Refused> {
    if let Some(rest) = server.strip_prefix("https://") {
        Ok(format!("wss://{rest}{}", api::SOCKET_PATH))
    } else if let Some(rest) = server.strip_prefix("http://") {
        Ok(format!("ws://{rest}{}", api::SOCKET_PATH))
    } else {
        Err(Refused::Failed(format!("not an http(s) server: {server}")))
    }
}

/// A frame or message is at most this; the server sends a few bytes.
const MAX_MESSAGE: usize = 64 << 10;

fn connect(config: &Config, timing: &Timing) -> Result<WebSocket<Stream>, Refused> {
    let failed = |what: &str, e: &dyn std::fmt::Display| Refused::Failed(format!("{what}: {e}"));
    let url = socket_url(&config.server)?;
    let uri: Uri = url.parse().map_err(|e| failed("the server's URL", &e))?;
    let tls = uri.scheme_str() == Some("wss");
    let host = uri
        .host()
        .ok_or_else(|| Refused::Failed(format!("no host in {url}")))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });

    let mut request = uri
        .into_client_request()
        .map_err(|e| failed("the upgrade", &e))?;
    let nonce = signing::new_nonce().map_err(|e| failed("a nonce", &e))?;
    let signed = signing::headers(
        &config.key,
        Some(&config.device),
        "GET",
        api::SOCKET_PATH,
        api::now(),
        &nonce,
        b"",
    );
    let headers = request.headers_mut();
    for (name, value) in signed {
        let name = HeaderName::from_bytes(name.as_bytes()).map_err(|e| failed(name, &e))?;
        let value = HeaderValue::from_str(&value).map_err(|e| failed(name.as_str(), &e))?;
        headers.insert(name, value);
    }
    let agent = format!("mauvelyd/{}", crate::AGENT_VERSION);
    headers.insert(
        USER_AGENT,
        HeaderValue::from_str(&agent).map_err(|e| failed("user agent", &e))?,
    );

    let tcp = dial(&host, port, timing.connect_timeout)
        .map_err(|e| failed(&format!("connecting to {host}:{port}"), &e))?;
    // Bounds the handshake; serve() sets its own read timeout after.
    tcp.set_read_timeout(Some(timing.connect_timeout))
        .and_then(|()| tcp.set_write_timeout(Some(timing.connect_timeout)))
        .and_then(|()| tcp.set_nodelay(true))
        .map_err(|e| failed("the socket", &e))?;
    let stream = if tls {
        let name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|e| failed("the server's name", &e))?;
        let conn =
            rustls::ClientConnection::new(tls_config()?, name).map_err(|e| failed("TLS", &e))?;
        Stream::Tls(Box::new(rustls::StreamOwned::new(conn, tcp)))
    } else {
        Stream::Plain(tcp)
    };

    let ws_config = WebSocketConfig::default()
        .max_message_size(Some(MAX_MESSAGE))
        .max_frame_size(Some(MAX_MESSAGE));
    match tungstenite::client::client_with_config(request, stream, Some(ws_config)) {
        Ok((ws, _)) => Ok(ws),
        Err(HandshakeError::Failure(WsError::Http(response))) => Err(refusal(
            response.status().as_u16(),
            response.body().as_deref().unwrap_or_default(),
        )),
        Err(HandshakeError::Failure(e)) => Err(failed("the upgrade", &e)),
        Err(HandshakeError::Interrupted(_)) => Err(Refused::Failed("the upgrade timed out".into())),
    }
}

/// What a refused upgrade means. A 403 is a revocation when its body says so,
/// as for the check-in, or when no body came with it (the server's body can
/// arrive after the part of the answer the handshake reads); a 403 that names
/// another error is a failure like any other.
fn refusal(status: u16, body: &[u8]) -> Refused {
    #[derive(Deserialize)]
    struct Answer {
        error: Option<String>,
        reason: Option<String>,
    }
    let answer = serde_json::from_slice::<Answer>(body).ok();
    let error = answer.as_ref().and_then(|a| a.error.as_deref());
    match status {
        403 if body.is_empty() || error == Some("revoked") => Refused::Revoked,
        404 | 426 => Refused::NoChannel(status),
        _ => Refused::Failed(
            match (error, answer.as_ref().and_then(|a| a.reason.as_deref())) {
                (Some(e), Some(r)) => format!("the upgrade: {status} {e} ({r})"),
                (Some(e), None) => format!("the upgrade: {status} {e}"),
                _ => format!("the upgrade: HTTP {status}"),
            },
        ),
    }
}

fn dial(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let mut last = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no address")))
}

/// rustls with ring and the compiled-in webpki roots, built once.
fn tls_config() -> Result<Arc<rustls::ClientConfig>, Refused> {
    static CONFIG: OnceLock<Result<Arc<rustls::ClientConfig>, String>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
            };
            rustls::ClientConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .map(|b| Arc::new(b.with_root_certificates(roots).with_no_client_auth()))
            .map_err(|e| e.to_string())
        })
        .clone()
        .map_err(|e| Refused::Failed(format!("TLS: {e}")))
}

/// A TCP stream, or TLS over one.
enum Stream {
    Plain(TcpStream),
    Tls(Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>),
}

impl Stream {
    fn tcp(&self) -> &TcpStream {
        match self {
            Stream::Plain(s) => s,
            Stream::Tls(s) => &s.sock,
        }
    }
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.read(buf),
            Stream::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Stream::Plain(s) => s.write(buf),
            Stream::Tls(s) => s.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Stream::Plain(s) => s.flush(),
            Stream::Tls(s) => s.flush(),
        }
    }
}

// ── an open channel ─────────────────────────────────────────────────────────

enum Served {
    /// The connection ended, and why.
    Dropped(String),
    Unwanted,
}

/// A timeout on the socket, which only means it is time to look at the clock.
fn timed_out(e: &WsError) -> bool {
    matches!(e, WsError::Io(io) if matches!(io.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut))
}

/// Reads until the connection ends, pinging on time and passing pushes on.
fn serve(ws: &mut WebSocket<Stream>, timing: &Timing, pushes: &Sender<Push>) -> Served {
    let mut heard = Instant::now();
    let mut next_ping = heard + timing.ping;
    let mut closing = None;
    loop {
        let now = Instant::now();
        if now.duration_since(heard) >= timing.dead_after {
            return Served::Dropped(format!(
                "nothing heard for {}s",
                timing.dead_after.as_secs()
            ));
        }
        if now >= next_ping {
            match ws.send(Message::text("ping")) {
                Ok(()) => {}
                Err(e) if timed_out(&e) => {}
                Err(e) => return Served::Dropped(e.to_string()),
            }
            next_ping = now + timing.ping;
        }

        let wake = next_ping.min(heard + timing.dead_after);
        let wait = wake
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        if let Err(e) = ws.get_ref().tcp().set_read_timeout(Some(wait)) {
            return Served::Dropped(e.to_string());
        }
        match ws.read() {
            Ok(Message::Text(text)) => {
                heard = Instant::now();
                match parse(&text) {
                    Some(push) => {
                        if pushes.send(push).is_err() {
                            return Served::Unwanted;
                        }
                    }
                    None if text.as_str() == "pong" => {}
                    None => {
                        if cfg!(debug_assertions) {
                            eprintln!("push channel: ignored {:.80}", text.as_str());
                        }
                    }
                }
            }
            Ok(Message::Close(frame)) => {
                heard = Instant::now();
                closing = Some(frame.map_or_else(
                    || "closed by the server".to_owned(),
                    |f| format!("closed by the server: {} {}", u16::from(f.code), f.reason),
                ));
            }
            Ok(_) => heard = Instant::now(),
            Err(e) if timed_out(&e) => {}
            Err(WsError::ConnectionClosed) => {
                return Served::Dropped(closing.unwrap_or_else(|| "closed".into()));
            }
            Err(e) => return Served::Dropped(closing.unwrap_or_else(|| e.to_string())),
        }
    }
}

/// A server message: `{"t": …}`. `None` for one this agent does not know.
fn parse(text: &str) -> Option<Push> {
    #[derive(Deserialize)]
    struct Frame {
        t: String,
    }
    match serde_json::from_str::<Frame>(text).ok()?.t.as_str() {
        "checkin" => Some(Push::CheckIn),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::thread::JoinHandle;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signature, VerifyingKey};
    use tungstenite::handshake::server::{Request, Response};
    use tungstenite::http;

    use super::*;

    /// What the test server does with an accepted socket.
    type Script = Box<dyn FnOnce(&mut WebSocket<TcpStream>) + Send>;

    /// What one connection to the test server does.
    enum Answer {
        /// Refuse the upgrade with this status and body.
        Refuse(u16, &'static str),
        /// Accept it, then run this against the socket.
        Accept(Script),
    }

    fn accept(f: impl FnOnce(&mut WebSocket<TcpStream>) + Send + 'static) -> Answer {
        Answer::Accept(Box::new(f))
    }

    /// One upgrade request the test server saw.
    struct Seen {
        path: String,
        headers: Vec<(String, String)>,
        at: Instant,
    }

    impl Seen {
        fn header(&self, name: &str) -> &str {
            self.headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
                .unwrap_or_else(|| panic!("no {name}"))
        }
    }

    /// A loopback WebSocket server answering each connection in turn.
    struct Server {
        base: String,
        seen: Arc<Mutex<Vec<Seen>>>,
        thread: Option<JoinHandle<()>>,
    }

    impl Server {
        // The refusal's size is tungstenite's `Callback` signature, not ours.
        #[allow(clippy::result_large_err)]
        fn start(answers: Vec<Answer>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let base = format!("http://{}", listener.local_addr().unwrap());
            let seen = Arc::new(Mutex::new(Vec::new()));
            let log = Arc::clone(&seen);
            let thread = thread::spawn(move || {
                for answer in answers {
                    let Ok((stream, _)) = listener.accept() else {
                        return;
                    };
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .unwrap();
                    let refuse = match &answer {
                        Answer::Refuse(status, body) => Some((*status, *body)),
                        Answer::Accept(_) => None,
                    };
                    let log = Arc::clone(&log);
                    let callback = move |req: &Request, resp: Response| {
                        log.lock().unwrap().push(Seen {
                            path: req.uri().path().to_owned(),
                            headers: req
                                .headers()
                                .iter()
                                .map(|(n, v)| (n.to_string(), v.to_str().unwrap().to_owned()))
                                .collect(),
                            at: Instant::now(),
                        });
                        match refuse {
                            None => Ok(resp),
                            Some((status, body)) => Err(http::Response::builder()
                                .status(status)
                                .header("Content-Type", "application/json")
                                .header("Content-Length", body.len())
                                .body(Some(body.to_owned()))
                                .unwrap()),
                        }
                    };
                    let accepted = tungstenite::accept_hdr(stream, callback);
                    if let (Ok(mut ws), Answer::Accept(script)) = (accepted, answer) {
                        script(&mut ws);
                    }
                }
            });
            Server {
                base,
                seen,
                thread: Some(thread),
            }
        }

        /// Every upgrade seen. Waits for the server to finish its answers.
        fn seen(mut self) -> Vec<Seen> {
            drop(self.thread.take().map(JoinHandle::join));
            std::mem::take(&mut *self.seen.lock().unwrap())
        }
    }

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[5u8; 32])
    }

    fn config(server: &Server) -> Config {
        Config {
            server: server.base.clone(),
            device: "dev_1".into(),
            key: key(),
        }
    }

    fn fast() -> Timing {
        Timing {
            ping: Duration::from_millis(50),
            dead_after: Duration::from_millis(150),
            connect_timeout: Duration::from_secs(2),
            no_channel_s: 3600,
        }
    }

    /// Runs the channel against `server` with waits recorded, not slept. A
    /// run that keeps redialling is a failure, not a hang.
    fn go(server: &Server, tx: &Sender<Push>) -> (Ended, Vec<Duration>) {
        let mut sleeps = Vec::new();
        let ended = run(&config(server), &fast(), tx, &mut |d| {
            sleeps.push(d);
            assert!(sleeps.len() < 10, "still redialling: {sleeps:?}");
        });
        (ended, sleeps)
    }

    const REVOKED: &str = r#"{"error":"revoked"}"#;

    /// Reads until the client goes, or 3 s, keeping what it sent as text.
    fn listen(ws: &mut WebSocket<TcpStream>, answer_pings: bool) -> Vec<String> {
        let until = Instant::now() + Duration::from_secs(3);
        let mut got = Vec::new();
        while Instant::now() < until
            && let Ok(m) = ws.read()
        {
            if let Message::Text(t) = m {
                if answer_pings && t.as_str() == "ping" {
                    let _ = ws.send(Message::text("pong"));
                }
                got.push(t.as_str().to_owned());
            }
        }
        got
    }

    fn within(d: Duration, lo: f64, hi: f64) -> bool {
        (lo..=hi).contains(&d.as_secs_f64())
    }

    #[test]
    fn the_upgrade_is_signed_as_a_get_with_no_body() {
        let server = Server::start(vec![
            accept(|ws| drop(ws.close(None).and_then(|()| ws.flush()))),
            Answer::Refuse(403, REVOKED),
        ]);
        let (tx, _rx) = mpsc::channel();
        let (ended, _) = go(&server, &tx);
        assert_eq!(ended, Ended::Revoked);

        let seen = server.seen();
        assert_eq!(seen.len(), 2);
        let pk = VerifyingKey::from(&key());
        for s in &seen {
            assert_eq!(s.path, "/api/agent/v2/socket");
            assert_eq!(s.header("X-Mauvely-Device"), "dev_1");
            assert!(s.header("User-Agent").starts_with("mauvelyd/"));
            let ts: u64 = s.header("X-Mauvely-Timestamp").parse().unwrap();
            assert!(api::now().abs_diff(ts) < 60);
            let nonce = s.header("X-Mauvely-Nonce");
            assert_eq!(URL_SAFE_NO_PAD.decode(nonce).unwrap().len(), 16);
            // The message rebuilt from the brief, not from `signing`.
            let msg = format!(
                "mauvely-device-v1\nGET\n/api/agent/v2/socket\n{ts}\n{nonce}\n\
                 e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
            );
            let sig = URL_SAFE_NO_PAD
                .decode(s.header("X-Mauvely-Signature"))
                .unwrap();
            pk.verify_strict(msg.as_bytes(), &Signature::from_slice(&sig).unwrap())
                .expect("the upgrade's signature verifies");
        }
        // A fresh nonce each time.
        assert_ne!(
            seen[0].header("X-Mauvely-Nonce"),
            seen[1].header("X-Mauvely-Nonce")
        );
    }

    #[test]
    fn checkin_is_passed_on_and_anything_else_is_ignored() {
        let server = Server::start(vec![
            accept(|ws| {
                for m in [
                    Message::text(r#"{"t":"remote_desktop","id":"x"}"#),
                    Message::text("not json"),
                    Message::text(r#"{"no_t":1}"#),
                    Message::binary(vec![1, 2, 3]),
                    Message::text(r#"{"t":"checkin"}"#),
                    Message::text(r#"{"t":"checkin","later":"fields"}"#),
                ] {
                    ws.send(m).unwrap();
                }
                ws.close(None).unwrap();
                listen(ws, false);
            }),
            Answer::Refuse(403, REVOKED),
        ]);
        let (tx, rx) = mpsc::channel();
        let (ended, sleeps) = go(&server, &tx);
        assert_eq!(ended, Ended::Revoked);
        assert_eq!(
            rx.try_iter().collect::<Vec<_>>(),
            [Push::CheckIn, Push::CheckIn]
        );
        // Reconnected after the close on the schedule's first backoff.
        assert_eq!(sleeps.len(), 1);
        assert!(within(sleeps[0], 54.0, 66.0), "{sleeps:?}");
        drop(server.seen());
    }

    #[test]
    fn pong_keeps_it_open_and_silence_is_noticed_and_redialled() {
        let pinged = Arc::new(Mutex::new((Vec::new(), Vec::new())));
        let (a, b) = (Arc::clone(&pinged), Arc::clone(&pinged));
        let server = Server::start(vec![
            // Answers every ping for 0.5 s, more than three times dead_after,
            // then pushes and leaves.
            accept(move |ws| {
                let until = Instant::now() + Duration::from_millis(500);
                ws.get_ref()
                    .set_read_timeout(Some(Duration::from_millis(20)))
                    .unwrap();
                let mut got = Vec::new();
                while Instant::now() < until {
                    match ws.read() {
                        Ok(Message::Text(t)) => {
                            if t.as_str() == "ping" {
                                ws.send(Message::text("pong")).unwrap();
                            }
                            got.push(t.as_str().to_owned());
                        }
                        Ok(_) => {}
                        Err(e) if timed_out(&e) => {}
                        Err(e) => panic!("the client went: {e}"),
                    }
                }
                ws.send(Message::text(r#"{"t":"checkin"}"#)).unwrap();
                ws.close(None).unwrap();
                listen(ws, false);
                a.lock().unwrap().0 = got;
            }),
            // Never answers.
            accept(move |ws| b.lock().unwrap().1 = listen(ws, false)),
            Answer::Refuse(403, REVOKED),
        ]);
        let (tx, rx) = mpsc::channel();
        let (ended, sleeps) = go(&server, &tx);
        assert_eq!(ended, Ended::Revoked);
        let seen = server.seen();
        assert_eq!(seen.len(), 3);

        let (answered, silent) = std::mem::take(&mut *pinged.lock().unwrap());
        // Kept open through the pongs: pinged about every 50 ms, and the push
        // came through.
        assert!(answered.len() >= 6, "{answered:?}");
        assert!(answered.iter().all(|t| t == "ping"));
        assert_eq!(rx.try_iter().collect::<Vec<_>>(), [Push::CheckIn]);
        // Given up on after the silence, having pinged into it, and dialled
        // again: two reconnects, each after a backoff.
        assert!(!silent.is_empty() && silent.iter().all(|t| t == "ping"));
        assert_eq!(sleeps.len(), 2);
        let silence = seen[2].at - seen[1].at;
        assert!(
            silence >= Duration::from_millis(150) && silence < Duration::from_secs(2),
            "{silence:?}"
        );
    }

    #[test]
    fn a_403_revoked_stops_it_and_another_403_does_not() {
        for body in [REVOKED, ""] {
            let server = Server::start(vec![Answer::Refuse(403, body)]);
            let (tx, _rx) = mpsc::channel();
            assert_eq!(go(&server, &tx), (Ended::Revoked, vec![]), "{body:?}");
            drop(server.seen());
        }

        let server = Server::start(vec![
            Answer::Refuse(403, r#"{"error":"forbidden"}"#),
            Answer::Refuse(403, "<html>blocked</html>"),
            Answer::Refuse(403, REVOKED),
        ]);
        let (tx, _rx) = mpsc::channel();
        let (ended, sleeps) = go(&server, &tx);
        assert_eq!(ended, Ended::Revoked);
        assert_eq!(sleeps.len(), 2);
        assert!(within(sleeps[0], 54.0, 66.0) && within(sleeps[1], 108.0, 132.0));
        drop(server.seen());
    }

    #[test]
    fn a_server_without_the_channel_is_asked_again_hourly() {
        let server = Server::start(vec![
            Answer::Refuse(404, r#"{"error":{"code":"not_found"}}"#),
            Answer::Refuse(426, r#"{"error":"upgrade_required"}"#),
            Answer::Refuse(403, REVOKED),
        ]);
        let (tx, _rx) = mpsc::channel();
        let (ended, sleeps) = go(&server, &tx);
        assert_eq!(ended, Ended::Revoked);
        assert_eq!(sleeps.len(), 2);
        assert!(
            sleeps.iter().all(|&d| within(d, 3240.0, 3960.0)),
            "{sleeps:?}"
        );
        drop(server.seen());
    }

    #[test]
    fn other_refusals_back_off_and_a_connection_resets_the_backoff() {
        let server = Server::start(vec![
            Answer::Refuse(401, r#"{"error":"unauthorised","reason":"timestamp"}"#),
            Answer::Refuse(503, ""),
            Answer::Refuse(500, ""),
            accept(|ws| drop(ws.close(None).and_then(|()| ws.flush()))),
            Answer::Refuse(403, REVOKED),
        ]);
        let (tx, _rx) = mpsc::channel();
        let (ended, sleeps) = go(&server, &tx);
        assert_eq!(ended, Ended::Revoked);
        let secs: Vec<_> = sleeps.iter().map(Duration::as_secs_f64).collect();
        assert_eq!(secs.len(), 4);
        assert!((54.0..=66.0).contains(&secs[0]), "{secs:?}");
        assert!((108.0..=132.0).contains(&secs[1]), "{secs:?}");
        assert!((216.0..=264.0).contains(&secs[2]), "{secs:?}");
        // Connected, then dropped: from the start again.
        assert!((54.0..=66.0).contains(&secs[3]), "{secs:?}");
        drop(server.seen());
    }

    #[test]
    fn nobody_listening_ends_it() {
        let server = Server::start(vec![accept(|ws| {
            ws.send(Message::text(r#"{"t":"checkin"}"#)).unwrap();
            listen(ws, true);
        })]);
        let (tx, rx) = mpsc::channel();
        drop(rx);
        assert_eq!(go(&server, &tx), (Ended::Unwanted, vec![]));
        drop(server.seen());
    }

    #[test]
    fn urls() {
        let url = |s: &str| socket_url(s);
        assert_eq!(
            url("https://devices.mauvely.com").unwrap(),
            "wss://devices.mauvely.com/api/agent/v2/socket"
        );
        assert_eq!(
            url("http://10.0.2.2:8798").unwrap(),
            "ws://10.0.2.2:8798/api/agent/v2/socket"
        );
        assert!(url("devices.mauvely.com").is_err());
    }

    #[test]
    fn an_https_server_is_spoken_to_in_tls() {
        // No process-wide provider is installed: ring is passed explicitly.
        assert!(tls_config().unwrap().crypto_provider().cipher_suites.len() > 1);
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let first = thread::spawn(move || {
            let (mut s, _) = listener.accept().unwrap();
            let mut byte = [0u8; 3];
            s.read_exact(&mut byte).unwrap();
            byte
        });
        let cfg = Config {
            server: format!("https://localhost:{port}"),
            device: "dev_1".into(),
            key: key(),
        };
        // The server hangs up after the hello, so the handshake fails.
        assert!(matches!(connect(&cfg, &fast()), Err(Refused::Failed(_))));
        // A TLS handshake record, version 3.x: a ClientHello, not `GET`.
        let head = first.join().unwrap();
        assert_eq!((head[0], head[1]), (0x16, 0x03), "{head:?}");
    }

    // ── Wake ──

    fn ms(n: u64) -> Duration {
        Duration::from_millis(n)
    }

    #[test]
    fn a_push_cuts_the_wait_short_but_not_before_the_floor() {
        let (tx, rx) = mpsc::channel();
        let mut wake = Wake::with_floor(rx, ms(200));
        for _ in 0..5 {
            tx.send(Push::CheckIn).unwrap();
        }
        let start = Instant::now();
        assert_eq!(wake.wait(Duration::from_secs(30), true), Woke::Nudged);
        let took = start.elapsed();
        assert!(took >= ms(200) && took < ms(1000), "{took:?}");
        // The five were one.
        let start = Instant::now();
        assert_eq!(wake.wait(ms(150), true), Woke::Timer);
        assert!(start.elapsed() >= ms(150));
    }

    #[test]
    fn a_push_after_the_floor_wakes_it_at_once() {
        let (tx, rx) = mpsc::channel();
        let mut wake = Wake::with_floor(rx, ms(50));
        let start = Instant::now();
        let pusher = thread::spawn(move || {
            thread::sleep(ms(300));
            tx.send(Push::CheckIn).unwrap();
            tx
        });
        assert_eq!(wake.wait(Duration::from_secs(30), true), Woke::Nudged);
        let took = start.elapsed();
        assert!(took >= ms(300) && took < ms(1000), "{took:?}");
        drop(pusher.join());
    }

    #[test]
    fn a_push_never_cuts_a_backoff_short_and_is_let_go() {
        let (tx, rx) = mpsc::channel();
        let mut wake = Wake::with_floor(rx, ms(10));
        tx.send(Push::CheckIn).unwrap();
        let start = Instant::now();
        assert_eq!(wake.wait(ms(300), false), Woke::Timer);
        assert!(start.elapsed() >= ms(300));
        // Not carried into the next wait.
        assert_eq!(wake.wait(ms(100), true), Woke::Timer);
    }

    #[test]
    fn a_wait_is_never_longer_than_asked() {
        let (tx, rx) = mpsc::channel();
        let mut wake = Wake::with_floor(rx, Duration::from_secs(30));
        tx.send(Push::CheckIn).unwrap();
        let start = Instant::now();
        // The floor is longer than the wait: the wait wins.
        assert_eq!(wake.wait(ms(100), true), Woke::Nudged);
        assert!(start.elapsed() < ms(1000));
    }

    #[test]
    fn without_a_channel_a_wait_is_a_sleep() {
        let (tx, rx) = mpsc::channel();
        drop(tx);
        let mut wake = Wake::new(rx);
        for _ in 0..2 {
            let start = Instant::now();
            assert_eq!(wake.wait(ms(150), true), Woke::Timer);
            let took = start.elapsed();
            assert!(took >= ms(150) && took < ms(1000), "{took:?}");
        }
    }
}
