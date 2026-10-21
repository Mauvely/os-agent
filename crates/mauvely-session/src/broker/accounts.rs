//! The accounts service, website-main: the device link that signs this
//! computer in as client `os`, the two mints, and whether a session is still
//! live. Its contract is website-main's `docs/AUTH-BROKER.md`.
//!
//! Every answer is mapped by a pure function of the status and the body, so
//! the mapping is tested without a server; the HTTP is the thin part.

use std::fmt;
use std::time::Duration;

use serde_json::{Value, json};

use super::wire::Reason;

/// A quick look, so a cached session can still be answered in time: an app
/// waits 12 s for the whole exchange (`suitelink.cpp`).
const ALIVE_TIMEOUT: Duration = Duration::from_secs(3);
const MINT_TIMEOUT: Duration = Duration::from_secs(8);
const LINK_TIMEOUT: Duration = Duration::from_secs(15);

/// Every answer here is a small JSON object.
const MAX_BODY: u64 = 256 * 1024;

/// The accounts origin for the device server in `/etc/mauvely/server`.
///
/// - `https://devices.mauvely.com` is production: `https://mauvely.com`.
/// - `https://devices.mauvely.dev` is staging: `https://mauvely.dev`.
/// - The local stack runs website-devices on 8798 and website-main on 8787
///   beside it, so `http://<host>:8798` is `http://<host>:8787` for
///   `localhost`, `127.0.0.1`, `[::1]`, and `10.0.2.2`, the host as a qemu VM
///   sees it.
///
/// Anything else is refused: the `os` token is not sent to a host this
/// cannot name.
pub fn origin_for(server: &str) -> Result<String, String> {
    let server = server.trim().trim_end_matches('/');
    match server {
        "https://devices.mauvely.com" => return Ok("https://mauvely.com".into()),
        "https://devices.mauvely.dev" => return Ok("https://mauvely.dev".into()),
        _ => {}
    }
    if let Some(host) = server
        .strip_prefix("http://")
        .and_then(|h| h.strip_suffix(":8798"))
        .filter(|h| ["localhost", "127.0.0.1", "[::1]", "10.0.2.2"].contains(h))
    {
        return Ok(format!("http://{host}:8787"));
    }
    Err(format!("no accounts service is known for {server:?}"))
}

/// A session: the token is never printed, not even by `{:?}`.
#[derive(Clone, PartialEq, Eq)]
pub struct Minted {
    pub token: String,
    /// Unix seconds.
    pub expires_at: u64,
    pub email: String,
}

impl fmt::Debug for Minted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Minted")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("email", &self.email)
            .finish()
    }
}

/// A device link the person is to approve.
pub struct Started {
    pub device_code: String,
    /// The page that approves it, on the accounts origin.
    pub link: String,
    /// Seconds between polls.
    pub interval: u64,
    /// Seconds until the link expires.
    pub expires_in: u64,
}

/// One poll of a device link.
#[derive(Debug, PartialEq, Eq)]
pub enum Poll {
    Pending,
    SlowDown,
    Done(Minted),
    /// Over: declined, expired, spent, or not understood. The code, for the
    /// log.
    Stop(String),
    /// The server could not be reached or failed. Ask again.
    Retry,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Alive {
    Yes,
    No,
    /// Could not tell.
    Unknown,
}

pub struct Accounts {
    origin: String,
    agent: ureq::Agent,
}

impl Accounts {
    /// `origin` is from `origin_for`.
    pub fn new(origin: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .user_agent(format!("mauvely-session/{}", env!("CARGO_PKG_VERSION")))
            .build()
            .into();
        Accounts {
            origin: origin.to_owned(),
            agent,
        }
    }

    pub fn origin(&self) -> &str {
        &self.origin
    }

    /// `POST /api/auth/device/start` as client `os`.
    pub fn start(&self, device_name: &str) -> Result<Started, String> {
        let body = json!({
            "client": "os",
            "clientVersion": env!("CARGO_PKG_VERSION"),
            "deviceName": device_name,
        });
        let (status, text) = self.post("/api/auth/device/start", None, &body, LINK_TIMEOUT)?;
        start_outcome(status, &text, &self.origin)
    }

    /// `POST /api/auth/device/token`.
    pub fn poll(&self, device_code: &str) -> Poll {
        let body = json!({ "deviceCode": device_code });
        match self.post("/api/auth/device/token", None, &body, LINK_TIMEOUT) {
            Ok((status, text)) => poll_outcome(status, &text),
            Err(_) => Poll::Retry,
        }
    }

    /// `POST /api/auth/apps/token`, as the `os` session.
    pub fn mint_app(
        &self,
        os_token: &str,
        client: &str,
        label: Option<&str>,
    ) -> Result<Minted, Reason> {
        let mut body = json!({ "client": client });
        if let Some(label) = label {
            body["deviceLabel"] = json!(label);
        }
        self.mint("/api/auth/apps/token", os_token, &body)
    }

    /// `POST /api/auth/browser/token`, as the `os` session.
    pub fn mint_browser(&self, os_token: &str, label: Option<&str>) -> Result<Minted, Reason> {
        let body = match label {
            Some(label) => json!({ "deviceLabel": label }),
            None => json!({}),
        };
        self.mint("/api/auth/browser/token", os_token, &body)
    }

    fn mint(&self, path: &str, os_token: &str, body: &Value) -> Result<Minted, Reason> {
        match self.post(path, Some(os_token), body, MINT_TIMEOUT) {
            Ok((status, text)) => mint_outcome(status, &text, &self.origin),
            Err(e) => {
                eprintln!("mauvely-session: broker: {path}: {e}");
                Err(Reason::Unreachable)
            }
        }
    }

    /// `GET /api/auth/me` with `token`: whether it is still a session.
    pub fn alive(&self, token: &str) -> Alive {
        let url = format!("{}/api/auth/me", self.origin);
        let result = self
            .agent
            .get(&url)
            .config()
            .timeout_global(Some(ALIVE_TIMEOUT))
            .build()
            .header("Authorization", format!("Bearer {token}"))
            .call();
        match result.map_err(|e| e.to_string()).and_then(read) {
            Ok((status, text)) => alive_outcome(status, &text),
            Err(_) => Alive::Unknown,
        }
    }

    /// Any status is an answer; only a transport failure is an error.
    fn post(
        &self,
        path: &str,
        bearer: Option<&str>,
        body: &Value,
        timeout: Duration,
    ) -> Result<(u16, String), String> {
        let mut req = self
            .agent
            .post(format!("{}{path}", self.origin))
            .config()
            .timeout_global(Some(timeout))
            .build()
            .header("Content-Type", "application/json");
        if let Some(token) = bearer {
            req = req.header("Authorization", format!("Bearer {token}"));
        }
        req.send(body.to_string().as_bytes())
            .map_err(|e| format!("POST {path}: {e}"))
            .and_then(read)
    }
}

fn read(mut resp: ureq::http::Response<ureq::Body>) -> Result<(u16, String), String> {
    let status = resp.status().as_u16();
    let text = resp
        .body_mut()
        .with_config()
        .limit(MAX_BODY)
        .read_to_string()
        .map_err(|e| format!("reading the answer: {e}"))?;
    Ok((status, text))
}

/// website-main's errors are `{ error: { code, message, … } }`.
fn error_of(body: &str) -> Value {
    serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("error").cloned())
        .unwrap_or(Value::Null)
}

fn error_code(body: &str) -> Option<String> {
    error_of(body)
        .get("code")
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Printable ASCII and no spaces: safe in a header, a log line and an argv.
fn plain(s: &str) -> bool {
    !s.is_empty() && s.len() <= 2048 && s.bytes().all(|b| b.is_ascii_graphic())
}

/// A session from a 200 of the claim or of either mint: the same shape.
fn minted(body: &str) -> Option<Minted> {
    let v: Value = serde_json::from_str(body).ok()?;
    let token = v.get("token")?.as_str()?;
    let expires_at = v.get("expiresAt")?.as_u64().filter(|t| *t > 0)?;
    let email = v
        .get("user")
        .and_then(|u| u.get("email"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    plain(token).then(|| Minted {
        token: token.to_owned(),
        expires_at,
        email: email.to_owned(),
    })
}

pub fn mint_outcome(status: u16, body: &str, origin: &str) -> Result<Minted, Reason> {
    match status {
        200 => minted(body).ok_or(Reason::BadResponse),
        // The `os` session is revoked or has expired.
        401 => Err(Reason::SignedOut),
        403 => Err(match error_code(body).as_deref() {
            Some("sso_required") => sso_required(body, origin).unwrap_or(Reason::BadResponse),
            Some("app_not_allowed") => Reason::AppNotAllowed,
            _ => Reason::Refused,
        }),
        429 => Err(Reason::RateLimited),
        500..=599 => Err(Reason::Unreachable),
        _ => Err(Reason::Refused),
    }
}

/// `org` and `start` from the server's `sso_required`. `start` is a path on
/// the accounts origin; the caller is given it whole.
fn sso_required(body: &str, origin: &str) -> Option<Reason> {
    let error = error_of(body);
    let org = error.get("org")?.as_str().filter(|o| plain(o))?;
    let start = error
        .get("start")?
        .as_str()
        .filter(|s| plain(s) && s.starts_with('/') && !s.starts_with("//"))?;
    Some(Reason::SsoRequired {
        org: org.to_owned(),
        start: format!("{origin}{start}"),
    })
}

pub fn start_outcome(status: u16, body: &str, origin: &str) -> Result<Started, String> {
    if status != 200 {
        return Err(error_code(body).unwrap_or_else(|| format!("HTTP {status}")));
    }
    let v: Value = serde_json::from_str(body).map_err(|_| "not JSON")?;
    let text = |k: &str| v.get(k).and_then(Value::as_str).filter(|s| plain(s));
    let device_code = text("deviceCode").ok_or("no deviceCode")?;
    // The server builds it from its own origin. Opened only when that is
    // the origin this computer belongs to.
    let link = text("verificationUriComplete")
        .filter(|l| l.strip_prefix(origin).is_some_and(|p| p.starts_with('/')))
        .ok_or("no verificationUriComplete on the accounts origin")?;
    Ok(Started {
        device_code: device_code.to_owned(),
        link: link.to_owned(),
        interval: v
            .get("interval")
            .and_then(Value::as_u64)
            .unwrap_or(5)
            .clamp(2, 60),
        expires_in: v
            .get("expiresIn")
            .and_then(Value::as_u64)
            .unwrap_or(600)
            .clamp(60, 1800),
    })
}

/// As the CLI and Suite poll: 202 and failures are "not yet", 429 slows
/// down, and any other refusal ends it.
pub fn poll_outcome(status: u16, body: &str) -> Poll {
    match status {
        202 => Poll::Pending,
        200 => minted(body).map_or_else(|| Poll::Stop("bad_response".into()), Poll::Done),
        429 => Poll::SlowDown,
        500..=599 => Poll::Retry,
        _ => match error_code(body).as_deref() {
            Some("authorization_pending") => Poll::Pending,
            Some("slow_down") => Poll::SlowDown,
            Some(code) => Poll::Stop(code.to_owned()),
            None => Poll::Stop(format!("HTTP {status}")),
        },
    }
}

/// `/api/auth/me` answers 200 either way, with `user` null when the token
/// is not a session.
pub fn alive_outcome(status: u16, body: &str) -> Alive {
    match status {
        200 => match serde_json::from_str::<Value>(body)
            .ok()
            .and_then(|v| v.get("user").cloned())
        {
            Some(Value::Object(_)) => Alive::Yes,
            Some(Value::Null) => Alive::No,
            _ => Alive::Unknown,
        },
        401 => Alive::No,
        _ => Alive::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ORIGIN: &str = "https://mauvely.com";
    const OK: &str = r#"{"token":"tok_abc","expiresAt":1771200000,
        "user":{"id":"usr_1","email":"ada@example.com","name":"Ada"},"plan":"pro"}"#;

    fn ada() -> Minted {
        Minted {
            token: "tok_abc".into(),
            expires_at: 1_771_200_000,
            email: "ada@example.com".into(),
        }
    }

    fn error(code: &str) -> String {
        format!(r#"{{"error":{{"code":"{code}","message":"No."}},"requestId":"r1"}}"#)
    }

    #[test]
    fn the_accounts_origin_follows_the_device_server() {
        for (server, origin) in [
            ("https://devices.mauvely.com", "https://mauvely.com"),
            ("https://devices.mauvely.com/\n", "https://mauvely.com"),
            ("https://devices.mauvely.dev", "https://mauvely.dev"),
            ("http://localhost:8798", "http://localhost:8787"),
            ("http://127.0.0.1:8798/", "http://127.0.0.1:8787"),
            ("http://[::1]:8798", "http://[::1]:8787"),
            ("http://10.0.2.2:8798", "http://10.0.2.2:8787"),
        ] {
            assert_eq!(origin_for(server).as_deref(), Ok(origin), "{server}");
        }
        for server in [
            "",
            "devices.mauvely.com",
            "http://devices.mauvely.com",
            "https://devices.mauvely.com.evil.example",
            "https://devices.mauvely.com:8443",
            "https://devices.mauvely.com/api",
            "https://evil.example/devices.mauvely.com",
            "https://mauvely.com",
            "https://devices.mauvely.org",
            "https://localhost:8798",
            "http://localhost:8799",
            "http://192.168.1.10:8798",
            "http://localhost.evil.example:8798",
            "http://user@localhost:8798",
        ] {
            assert!(origin_for(server).is_err(), "{server}");
        }
    }

    #[test]
    fn a_minted_session_is_never_printed() {
        let shown = format!("{:?}", ada());
        assert!(!shown.contains("tok_abc"), "{shown}");
        assert!(shown.contains("ada@example.com"));
    }

    #[test]
    fn mint_answers() {
        assert_eq!(mint_outcome(200, OK, ORIGIN), Ok(ada()));
        // A 200 that is not a session.
        for body in [
            "",
            "<html>",
            r#"{"token":"","expiresAt":1}"#,
            r#"{"token":"a b","expiresAt":1}"#,
            r#"{"token":"a\nb","expiresAt":1}"#,
            r#"{"token":"tok"}"#,
            r#"{"token":"tok","expiresAt":0}"#,
            r#"{"token":"tok","expiresAt":"1771200000"}"#,
            r#"{"token":7,"expiresAt":1}"#,
        ] {
            assert_eq!(
                mint_outcome(200, body, ORIGIN),
                Err(Reason::BadResponse),
                "{body}"
            );
        }
        assert_eq!(
            mint_outcome(401, &error("unauthorized"), ORIGIN),
            Err(Reason::SignedOut)
        );
        assert_eq!(mint_outcome(401, "", ORIGIN), Err(Reason::SignedOut));
        assert_eq!(
            mint_outcome(403, &error("forbidden"), ORIGIN),
            Err(Reason::Refused)
        );
        assert_eq!(
            mint_outcome(403, &error("app_not_allowed"), ORIGIN),
            Err(Reason::AppNotAllowed)
        );
        assert_eq!(mint_outcome(403, "", ORIGIN), Err(Reason::Refused));
        assert_eq!(
            mint_outcome(429, &error("rate_limited"), ORIGIN),
            Err(Reason::RateLimited)
        );
        assert_eq!(
            mint_outcome(400, &error("unknown_client"), ORIGIN),
            Err(Reason::Refused)
        );
        assert_eq!(mint_outcome(404, "", ORIGIN), Err(Reason::Refused));
        assert_eq!(mint_outcome(502, "", ORIGIN), Err(Reason::Unreachable));
    }

    #[test]
    fn sso_required_carries_where_to_go() {
        let body = r#"{"error":{"code":"sso_required","message":"Your organisation signs you in with single sign-on.",
            "org":"northgate","start":"/api/auth/sso/start?org=northgate"},"requestId":"r1"}"#;
        assert_eq!(
            mint_outcome(403, body, ORIGIN),
            Err(Reason::SsoRequired {
                org: "northgate".into(),
                start: "https://mauvely.com/api/auth/sso/start?org=northgate".into()
            })
        );
        // `start` is a path on the accounts origin, or it is not used.
        for start in [
            "https://evil.example/x",
            "//evil.example/x",
            "api/auth/sso/start",
            "/a b",
            "",
        ] {
            let body = format!(
                r#"{{"error":{{"code":"sso_required","org":"northgate","start":"{start}"}}}}"#
            );
            assert_eq!(
                mint_outcome(403, &body, ORIGIN),
                Err(Reason::BadResponse),
                "{start}"
            );
        }
        let no_org = r#"{"error":{"code":"sso_required","start":"/api/auth/sso/start"}}"#;
        assert_eq!(mint_outcome(403, no_org, ORIGIN), Err(Reason::BadResponse));
    }

    #[test]
    fn start_answers() {
        let body = r#"{"deviceCode":"dc_secret","userCode":"ABCD-EFGH",
            "verificationUri":"https://mauvely.com/link",
            "verificationUriComplete":"https://mauvely.com/link?code=ABCD-EFGH",
            "interval":5,"expiresIn":600}"#;
        let s = start_outcome(200, body, ORIGIN).unwrap();
        assert_eq!(s.device_code, "dc_secret");
        assert_eq!(s.link, "https://mauvely.com/link?code=ABCD-EFGH");
        assert_eq!((s.interval, s.expires_in), (5, 600));

        // Defaults, and bounds on what the server asks for.
        let s = start_outcome(
            200,
            r#"{"deviceCode":"d","verificationUriComplete":"https://mauvely.com/link?code=A","interval":0,"expiresIn":99999}"#,
            ORIGIN,
        )
        .unwrap();
        assert_eq!((s.interval, s.expires_in), (2, 1800));

        // Only a page on this computer's accounts origin is opened.
        for link in [
            "https://evil.example/link?code=A",
            "https://mauvely.com.evil.example/link",
            "https://mauvely.comx/link",
            "http://mauvely.com/link",
            "-https://mauvely.com/link",
            "https://mauvely.com/link?code=A B",
        ] {
            let body = format!(r#"{{"deviceCode":"d","verificationUriComplete":"{link}"}}"#);
            assert!(start_outcome(200, &body, ORIGIN).is_err(), "{link}");
        }
        assert!(
            start_outcome(
                200,
                r#"{"verificationUriComplete":"https://mauvely.com/l"}"#,
                ORIGIN
            )
            .is_err()
        );
        assert_eq!(
            start_outcome(429, &error("rate_limited"), ORIGIN)
                .err()
                .as_deref(),
            Some("rate_limited")
        );
        assert_eq!(
            start_outcome(502, "", ORIGIN).err().as_deref(),
            Some("HTTP 502")
        );
    }

    #[test]
    fn poll_answers() {
        assert_eq!(
            poll_outcome(202, r#"{"status":"pending","interval":5}"#),
            Poll::Pending
        );
        assert_eq!(poll_outcome(200, OK), Poll::Done(ada()));
        assert_eq!(poll_outcome(200, "{}"), Poll::Stop("bad_response".into()));
        assert_eq!(poll_outcome(429, ""), Poll::SlowDown);
        assert_eq!(poll_outcome(503, ""), Poll::Retry);
        for code in ["expired_token", "access_denied", "invalid_code"] {
            assert_eq!(poll_outcome(400, &error(code)), Poll::Stop(code.into()));
        }
        assert_eq!(
            poll_outcome(400, &error("authorization_pending")),
            Poll::Pending
        );
        assert_eq!(poll_outcome(400, &error("slow_down")), Poll::SlowDown);
        assert_eq!(poll_outcome(404, ""), Poll::Stop("HTTP 404".into()));
    }

    #[test]
    fn alive_answers() {
        assert_eq!(alive_outcome(200, r#"{"user":{"id":"usr_1"}}"#), Alive::Yes);
        assert_eq!(
            alive_outcome(200, r#"{"user":null,"totpSatisfied":false}"#),
            Alive::No
        );
        assert_eq!(alive_outcome(401, ""), Alive::No);
        assert_eq!(alive_outcome(200, "<html>"), Alive::Unknown);
        assert_eq!(alive_outcome(200, "{}"), Alive::Unknown);
        assert_eq!(alive_outcome(503, ""), Alive::Unknown);
    }
}
