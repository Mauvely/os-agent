//! The login door: website-devices' three device-signed `v2` routes
//! (`worker/routes/login.ts` there), and website-main's `POST /api/auth/kdf`
//! for a version 0 account's upgrade (`docs/OS-LOGIN.md` there).
//!
//! Every answer is sorted by a pure function of the status and the body
//! (`sort`), so the mapping is tested without a server:
//!
//! | Answer | Here |
//! |---|---|
//! | 200 | the answer, if it has the contract's shape; otherwise `unavailable` |
//! | 401, 403, 429 with a refusal of the person (`credentials`, `code`, `expired`, `inactive`, `not_member`, `sso_required`, `second_factor_setup`, `not_allowed`, `rate_limited`, `revoked`) | that refusal |
//! | 404 (a server without the door), 5xx, a network error, a timeout | **unreachable**: the login screen may use the cache |
//! | anything else (`unauthorised`, `bad_request`, …) | `unavailable`, a refusal |
//!
//! Only "unreachable" ever lets the cache sign a person in. A refusal never
//! does, whatever the cache says.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::wire::Reason;
use crate::api::{self, Client};

pub const PARAMS_PATH: &str = "/api/agent/v2/login/params";
pub const LOGIN_PATH: &str = "/api/agent/v2/login";
pub const CODE_PATH: &str = "/api/agent/v2/login/code";
pub const KDF_PATH: &str = "/api/auth/kdf";

/// Each call's limit. The login screen waits for all of them, and
/// `pam_mauvely` waits 60 s for an answer.
pub const PARAMS_TIMEOUT: Duration = Duration::from_secs(10);
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(15);
const UPGRADE_TIMEOUT: Duration = Duration::from_secs(15);

/// What a call to the server came to.
#[derive(Debug, PartialEq, Eq)]
pub enum Online<T> {
    Answer(T),
    Refused(Reason),
    /// Not a decision about the person: why, for the log.
    Unreachable(String),
}

impl<T> Online<T> {
    fn map<U>(self, f: impl FnOnce(T) -> Option<U>) -> Online<U> {
        match self {
            Online::Answer(t) => f(t).map_or(Online::Refused(Reason::Unavailable), Online::Answer),
            Online::Refused(r) => Online::Refused(r),
            Online::Unreachable(why) => Online::Unreachable(why),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Params {
    pub kdf_version: u8,
    pub auth_salt: Option<String>,
}

/// The person, as the server tells it at a sign-in.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Person {
    pub username: String,
    pub handle: String,
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub device_admin: bool,
    pub kdf_version: u8,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub token: String,
    pub expires_at: u64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SignedIn {
    pub session: Session,
    pub person: Person,
    pub offline_days: u32,
}

/// What the password or the code led to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// A second factor: `factor` is `totp` or `email`.
    Code {
        challenge: Zeroizing<String>,
        factor: String,
        expires_at: u64,
    },
    SignedIn(SignedIn),
}

/// The server, as the login service sees it.
pub trait Door: Send + Sync {
    fn params(&self, username: &str) -> Online<Params>;
    /// `secret` is the `authSecret` for version 1, the password for 0.
    fn login(&self, username: &str, kdf_version: u8, secret: &str) -> Online<Step>;
    fn code(&self, challenge: &str, code: &str) -> Online<Step>;
    /// The accounts origin a session it makes belongs to, when this computer
    /// knows one.
    fn accounts(&self) -> Option<&str>;
    /// Moves a version 0 account onto Argon2id, with the session it just
    /// made. The answer is only logged.
    fn upgrade(&self, token: &str, password: &str, salt: &str, secret: &str) -> Result<(), String>;
}

/// Sorts a reply (`None` for a transport failure) into an answer, a refusal,
/// or unreachable.
pub fn sort(reply: Result<api::Reply, String>) -> Online<Value> {
    let reply = match reply {
        Ok(r) => r,
        Err(why) => return Online::Unreachable(why),
    };
    match reply.status {
        200 => match serde_json::from_str::<Value>(&reply.body) {
            Ok(v) if v.is_object() => Online::Answer(v),
            _ => Online::Refused(Reason::Unavailable),
        },
        401 | 403 | 429 => match Reason::from_server(&reply.error_code()) {
            Some(r) => Online::Refused(r),
            None => Online::Refused(Reason::Unavailable),
        },
        404 => Online::Unreachable("the server has no login door".into()),
        500..=599 => Online::Unreachable(format!("HTTP {}: {}", reply.status, reply.error_code())),
        _ => Online::Refused(Reason::Unavailable),
    }
}

/// A sign-in step from a 200's body.
pub fn step(v: Value) -> Option<Step> {
    match v.get("step")?.as_str()? {
        "code" => {
            let challenge = v.get("challenge")?.as_str().filter(|c| !c.is_empty())?;
            let factor = v.get("factor")?.as_str()?;
            if factor != "totp" && factor != "email" {
                return None;
            }
            Some(Step::Code {
                challenge: Zeroizing::new(challenge.to_owned()),
                factor: factor.to_owned(),
                expires_at: v.get("expiresAt")?.as_u64()?,
            })
        }
        "signed_in" => {
            let s: SignedIn = serde_json::from_value(v).ok()?;
            (!s.session.token.is_empty()).then_some(Step::SignedIn(s))
        }
        _ => None,
    }
}

fn params(v: Value) -> Option<Params> {
    let p: Params = serde_json::from_value(v).ok()?;
    match (p.kdf_version, &p.auth_salt) {
        (1, Some(_)) | (0, _) => Some(p),
        _ => None,
    }
}

/// The real door: this device's key, over `api::Client`.
pub struct Devices {
    params: Client,
    login: Client,
    device: String,
    key: SigningKey,
    accounts: Option<String>,
    upgrade: ureq::Agent,
}

impl Devices {
    pub fn new(server: &str, device: &str, key: SigningKey) -> Self {
        Devices {
            params: Client::with_timeout(server, PARAMS_TIMEOUT),
            login: Client::with_timeout(server, LOGIN_TIMEOUT),
            device: device.to_owned(),
            key,
            accounts: accounts_origin(server),
            upgrade: ureq::Agent::config_builder()
                .http_status_as_error(false)
                .max_redirects(0)
                .timeout_global(Some(UPGRADE_TIMEOUT))
                .user_agent(format!("mauvelyd/{}", crate::AGENT_VERSION))
                .build()
                .into(),
        }
    }

    fn post(&self, client: &Client, path: &str, body: &[u8]) -> Online<Value> {
        sort(
            client
                .post(path, &self.key, Some(&self.device), body)
                .map_err(|e| e.to_string()),
        )
    }
}

/// `value` as JSON, in a buffer big enough from the start that it never
/// moves, so the secret in it is in one place, wiped when it is dropped.
/// (ureq's and rustls' own buffers are theirs.)
fn body<T: Serialize>(value: &T, secret: usize) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(secret * 6 + 512));
    serde_json::to_writer(&mut *out, value).expect("always serialises");
    out
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LoginBody<'a> {
    username: &'a str,
    kdf_version: u8,
    secret: &'a str,
}

#[derive(Serialize)]
struct CodeBody<'a> {
    challenge: &'a str,
    code: &'a str,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct UpgradeBody<'a> {
    password: &'a str,
    auth_salt: &'a str,
    auth_secret: &'a str,
}

impl Door for Devices {
    fn params(&self, username: &str) -> Online<Params> {
        let b = body(&json!({ "username": username }), 0);
        self.post(&self.params, PARAMS_PATH, &b).map(params)
    }

    fn login(&self, username: &str, kdf_version: u8, secret: &str) -> Online<Step> {
        let b = body(
            &LoginBody {
                username,
                kdf_version,
                secret,
            },
            secret.len(),
        );
        self.post(&self.login, LOGIN_PATH, &b).map(step)
    }

    fn code(&self, challenge: &str, code: &str) -> Online<Step> {
        let b = body(&CodeBody { challenge, code }, challenge.len() + code.len());
        self.post(&self.login, CODE_PATH, &b).map(step)
    }

    fn accounts(&self) -> Option<&str> {
        self.accounts.as_deref()
    }

    fn upgrade(&self, token: &str, password: &str, salt: &str, secret: &str) -> Result<(), String> {
        let origin = self
            .accounts
            .as_deref()
            .ok_or("no accounts service is known")?;
        let body = body(
            &UpgradeBody {
                password,
                auth_salt: salt,
                auth_secret: secret,
            },
            password.len() + secret.len(),
        );
        let mut resp = self
            .upgrade
            .post(format!("{origin}{KDF_PATH}"))
            .header("Content-Type", "application/json")
            .header("Authorization", format!("Bearer {token}"))
            .send(&body[..])
            .map_err(|e| format!("POST {KDF_PATH}: {e}"))?;
        let status = resp.status().as_u16();
        let text = resp
            .body_mut()
            .with_config()
            .limit(64 * 1024)
            .read_to_string()
            .unwrap_or_default();
        let reply = api::Reply { status, body: text };
        match status {
            200 => Ok(()),
            _ => Err(format!("POST {KDF_PATH}: {}", reply.error_code())),
        }
    }
}

/// The accounts origin for the device server in `/etc/mauvely/server`.
/// mauvely-session's `broker::accounts::origin_for` holds the same table;
/// change both together.
pub fn accounts_origin(server: &str) -> Option<String> {
    let server = server.trim().trim_end_matches('/');
    match server {
        "https://devices.mauvely.com" => return Some("https://mauvely.com".into()),
        "https://devices.mauvely.dev" => return Some("https://mauvely.dev".into()),
        _ => {}
    }
    let host = server.strip_prefix("http://")?.strip_suffix(":8798")?;
    ["localhost", "127.0.0.1", "[::1]", "10.0.2.2"]
        .contains(&host)
        .then(|| format!("http://{host}:8787"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeServer;

    fn reply(status: u16, body: &str) -> Result<api::Reply, String> {
        Ok(api::Reply {
            status,
            body: body.into(),
        })
    }

    fn signed_in() -> String {
        json!({
            "step": "signed_in",
            "session": { "token": "tok_os", "expiresAt": 1_771_200_000u64 },
            "person": { "username": "timur", "handle": "timur.suez", "name": "Timur Inal",
                        "uid": 21001, "gid": 21001, "deviceAdmin": true, "kdfVersion": 0,
                        "emailIsPlaceholder": false },
            "offlineDays": 14
        })
        .to_string()
    }

    #[test]
    fn refusals_of_the_person_pass_through() {
        for (status, code) in [
            (401, "credentials"),
            (401, "code"),
            (401, "expired"),
            (403, "inactive"),
            (403, "not_member"),
            (403, "sso_required"),
            (403, "second_factor_setup"),
            (403, "not_allowed"),
            (403, "revoked"),
            (429, "rate_limited"),
        ] {
            let body = format!(r#"{{"error":"{code}"}}"#);
            match sort(reply(status, &body)) {
                Online::Refused(r) => assert_eq!(r.code(), code),
                other => panic!("{status} {code}: {other:?}"),
            }
        }
    }

    #[test]
    fn only_an_unreachable_server_is_unreachable() {
        for r in [
            Err("connection refused".to_owned()),
            reply(500, "{}"),
            reply(502, r#"{"error":"unavailable"}"#),
            reply(503, r#"{"error":"not_ready"}"#),
            reply(503, r#"{"error":"no_uid"}"#),
            reply(404, "<html>"),
        ] {
            assert!(matches!(sort(r), Online::Unreachable(_)));
        }
        // The server decided something, or answered nonsense: never the cache.
        for r in [
            reply(401, r#"{"error":"unauthorised","reason":"timestamp"}"#),
            reply(400, r#"{"error":"bad_username"}"#),
            reply(413, "{}"),
            reply(403, "<html>blocked</html>"),
            reply(200, "not json"),
            reply(200, "[]"),
            reply(302, ""),
        ] {
            assert_eq!(sort(r), Online::Refused(Reason::Unavailable));
        }
    }

    #[test]
    fn steps_parse() {
        let code = step(
            json!({ "step": "code", "challenge": "ch_1", "factor": "email", "expiresAt": 99 }),
        )
        .unwrap();
        assert_eq!(
            code,
            Step::Code {
                challenge: Zeroizing::new("ch_1".into()),
                factor: "email".into(),
                expires_at: 99
            }
        );
        let Step::SignedIn(s) = step(serde_json::from_str(&signed_in()).unwrap()).unwrap() else {
            panic!()
        };
        assert_eq!(s.person.uid, 21001);
        assert!(s.person.device_admin);
        assert_eq!(s.offline_days, 14);
        assert!(!format!("{s:?}").contains("tok_os"));
        // Not the contract's shape.
        for bad in [
            json!({ "step": "code", "challenge": "", "factor": "totp", "expiresAt": 1 }),
            json!({ "step": "code", "challenge": "c", "factor": "sms", "expiresAt": 1 }),
            json!({ "step": "signed_in", "session": { "token": "", "expiresAt": 1 } }),
            json!({ "step": "done" }),
        ] {
            assert_eq!(step(bad), None);
        }
    }

    #[test]
    fn the_door_signs_each_call_as_this_device() {
        let server = FakeServer::start(vec![
            (
                200,
                r#"{"kdfVersion":1,"authSalt":"AAAAAAAAAAAAAAAAAAAAAA=="}"#.into(),
            ),
            (
                200,
                r#"{"step":"code","challenge":"ch_1","factor":"totp","expiresAt":9}"#.into(),
            ),
            (200, signed_in()),
            (401, r#"{"error":"credentials"}"#.into()),
        ]);
        let door = Devices::new(&server.base, "dev_1", SigningKey::from_bytes(&[7; 32]));
        assert_eq!(
            door.params("timur"),
            Online::Answer(Params {
                kdf_version: 1,
                auth_salt: Some("AAAAAAAAAAAAAAAAAAAAAA==".into())
            })
        );
        assert!(matches!(
            door.login("timur", 1, "c2VjcmV0"),
            Online::Answer(Step::Code { .. })
        ));
        assert!(matches!(
            door.code("ch_1", "123456"),
            Online::Answer(Step::SignedIn(_))
        ));
        assert_eq!(
            door.login("timur", 0, "pw"),
            Online::Refused(Reason::Credentials)
        );
        let reqs = server.requests();
        let paths: Vec<_> = reqs.iter().map(|r| r.url.as_str()).collect();
        assert_eq!(paths, [PARAMS_PATH, LOGIN_PATH, CODE_PATH, LOGIN_PATH]);
        for r in &reqs {
            assert_eq!(r.method, "POST");
            assert_eq!(r.header("X-Mauvely-Device"), Some("dev_1"));
            assert!(r.header("X-Mauvely-Signature").is_some());
        }
        let body = |i: usize| serde_json::from_slice::<Value>(&reqs[i].body).unwrap();
        assert_eq!(body(0), json!({ "username": "timur" }));
        assert_eq!(
            body(1),
            json!({ "username": "timur", "kdfVersion": 1, "secret": "c2VjcmV0" })
        );
        assert_eq!(body(2), json!({ "challenge": "ch_1", "code": "123456" }));
    }

    #[test]
    fn a_door_nobody_answers_is_unreachable() {
        // A port nothing listens on.
        let door = Devices::new(
            "http://127.0.0.1:9",
            "dev_1",
            SigningKey::from_bytes(&[7; 32]),
        );
        assert!(matches!(door.params("timur"), Online::Unreachable(_)));
    }

    #[test]
    fn the_accounts_origins_match_mauvely_sessions() {
        for (server, origin) in [
            ("https://devices.mauvely.com", "https://mauvely.com"),
            ("https://devices.mauvely.dev/", "https://mauvely.dev"),
            ("http://localhost:8798", "http://localhost:8787"),
            ("http://10.0.2.2:8798", "http://10.0.2.2:8787"),
        ] {
            assert_eq!(accounts_origin(server).as_deref(), Some(origin));
        }
        for server in [
            "https://devices.mauvely.com.evil.example",
            "http://devices.mauvely.com",
            "http://example.com:8798",
        ] {
            assert_eq!(accounts_origin(server), None);
        }
    }
}
