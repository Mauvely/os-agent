//! The agent API v1: the wire types and a signed blocking client.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::Error;
use crate::facts::Hardware;
use crate::signing;

pub const ENROL_PATH: &str = "/api/agent/v1/enrol";
pub const CHECKIN_PATH: &str = "/api/agent/v1/checkin";

#[derive(Debug, Serialize)]
pub struct EnrolRequest<'a> {
    pub token: &'a str,
    pub public_key: String,
    pub hostname: &'a str,
    pub serial: Option<&'a str>,
    pub hardware: &'a Hardware,
    pub os: OsInfo<'a>,
    pub agent_version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct OsInfo<'a> {
    pub booted_image: Option<&'a str>,
    pub booted_digest: Option<&'a str>,
}

#[derive(Debug, Deserialize)]
pub struct EnrolResponse {
    pub device_id: String,
    pub org: Org,
}

#[derive(Debug, Deserialize)]
pub struct Org {
    pub slug: String,
}

#[derive(Debug, Serialize)]
pub struct CheckinRequest<'a> {
    pub booted_image: Option<&'a str>,
    pub booted_digest: Option<&'a str>,
    pub staged_image: Option<&'a str>,
    pub remotes: Vec<&'a str>,
    pub flatpaks: Vec<FlatpakReport<'a>>,
    pub last_apply: &'a LastApply,
    pub agent_version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct FlatpakReport<'a> {
    pub id: &'a str,
    pub branch: &'a str,
    pub remote: &'a str,
    pub managed: bool,
}

/// `last_apply.failed` holds at most this many apps, the first ones.
pub const MAX_FAILED: usize = 50;
/// And each `error` at most this many characters, counted in UTF-16 units as
/// the server counts them, so one that is "too long" there never is here.
pub const MAX_FAILED_ERROR: usize = 500;

/// An app whose install, update or removal failed in an apply: its Flatpak id
/// and branch, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FailedApp {
    pub id: String,
    pub branch: String,
    pub error: String,
}

/// The outcome of the previous reconcile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastApply {
    pub ok: bool,
    /// Every failure as text. `failed` says which apps, where that is known.
    pub errors: Vec<String>,
    /// Left out when empty, as a check-in was before it existed.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub failed: Vec<FailedApp>,
}

impl LastApply {
    pub fn from_errors(errors: Vec<String>) -> Self {
        Self::new(errors, Vec::new())
    }

    /// `failed` is cut to `MAX_FAILED` apps and their errors to
    /// `MAX_FAILED_ERROR` characters. Each is also in `errors`, which is not
    /// cut here.
    pub fn new(errors: Vec<String>, failed: Vec<FailedApp>) -> Self {
        LastApply {
            ok: errors.is_empty(),
            errors,
            failed: failed
                .into_iter()
                .take(MAX_FAILED)
                .map(|f| FailedApp {
                    error: cut(&f.error, MAX_FAILED_ERROR),
                    ..f
                })
                .collect(),
        }
    }
}

/// `s` cut to at most `max` UTF-16 units, never inside a character.
fn cut(s: &str, max: usize) -> String {
    let mut units = 0;
    s.chars()
        .take_while(|c| {
            units += c.len_utf16();
            units <= max
        })
        .collect()
}

impl Default for LastApply {
    fn default() -> Self {
        LastApply::from_errors(Vec::new())
    }
}

#[derive(Debug, Deserialize)]
pub struct CheckinResponse {
    pub desired: Desired,
    pub interval_s: u64,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct Desired {
    pub image: Option<DesiredImage>,
    pub remotes: Vec<DesiredRemote>,
    pub apps: Vec<DesiredApp>,
    /// The collection's desktop policy (brief 25), read by `desktop`. Kept as
    /// JSON here so that one this agent cannot read fails only itself, never
    /// the rest of the answer. `None` from a server that predates it.
    #[serde(default)]
    pub desktop: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DesiredImage {
    #[serde(rename = "ref")]
    pub reference: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DesiredRemote {
    pub name: String,
    pub url: String,
    /// Base64 (standard alphabet) of the binary public key.
    pub gpg_key: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DesiredApp {
    pub id: String,
    pub branch: String,
    pub remote: String,
    pub state: AppState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AppState {
    Installed,
    Absent,
}

/// A response: its status and body.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub body: String,
}

impl Reply {
    /// `error` from a `{"error": "…"}` body, for logging.
    pub fn error_code(&self) -> String {
        serde_json::from_str::<serde_json::Value>(&self.body)
            .ok()
            .and_then(|v| v.get("error")?.as_str().map(str::to_owned))
            .unwrap_or_else(|| format!("HTTP {}", self.status))
    }
}

pub struct Client {
    base: String,
    agent: ureq::Agent,
}

impl Client {
    /// `base` is the server's origin, without a trailing slash.
    pub fn new(base: &str) -> Self {
        let agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .timeout_global(Some(Duration::from_secs(60)))
            .user_agent(format!("mauvelyd/{}", crate::AGENT_VERSION))
            .build()
            .into();
        Client {
            base: base.to_owned(),
            agent,
        }
    }

    /// POSTs a signed JSON body. Any status is a reply; only a transport
    /// failure is an error.
    pub fn post(
        &self,
        path: &str,
        key: &SigningKey,
        device: Option<&str>,
        body: &[u8],
    ) -> Result<Reply, Error> {
        let nonce = signing::new_nonce()?;
        let headers = signing::headers(key, device, "POST", path, now(), &nonce, body);
        let mut req = self
            .agent
            .post(format!("{}{path}", self.base))
            .header("Content-Type", "application/json");
        for (name, value) in headers {
            req = req.header(name, value);
        }
        let mut resp = req
            .send(body)
            .map_err(|e| Error::Http(format!("POST {path}: {e}")))?;
        let status = resp.status().as_u16();
        let body = resp
            .body_mut()
            .read_to_string()
            .map_err(|e| Error::Http(format!("POST {path}: reading the answer: {e}")))?;
        Ok(Reply { status, body })
    }
}

/// Unix seconds.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_brief_example() {
        let body = r#"{
          "device_id": "dev_1",
          "desired": {
            "image": { "ref": "ghcr.io/mauvely/os:stable" },
            "remotes": [{ "name": "mauvely", "url": "https://flatpak.mauvely.com/repo",
                          "gpg_key": "AAEC" }],
            "apps": [{ "id": "com.mauvely.compose", "branch": "stable",
                       "remote": "mauvely", "state": "installed" },
                     { "id": "org.mozilla.firefox", "branch": "stable",
                       "remote": "flathub", "state": "absent" }]
          },
          "interval_s": 900,
          "server_time": 1760400000
        }"#;
        let r: CheckinResponse = serde_json::from_str(body).unwrap();
        assert_eq!(r.interval_s, 900);
        assert_eq!(
            r.desired.image.unwrap().reference,
            "ghcr.io/mauvely/os:stable"
        );
        assert_eq!(r.desired.apps[1].state, AppState::Absent);

        let r: CheckinResponse = serde_json::from_str(
            r#"{"desired":{"image":null,"remotes":[],"apps":[]},"interval_s":60}"#,
        )
        .unwrap();
        assert!(r.desired.image.is_none());
    }

    fn failed(id: &str, error: &str) -> FailedApp {
        FailedApp {
            id: id.into(),
            branch: "stable".into(),
            error: error.into(),
        }
    }

    #[test]
    fn failed_apps_are_left_out_when_there_are_none() {
        // The shape every check-in had before `failed` existed.
        let json = serde_json::to_value(LastApply::default()).unwrap();
        assert_eq!(json, serde_json::json!({ "ok": true, "errors": [] }));
        let json = serde_json::to_value(LastApply::from_errors(vec!["x".into()])).unwrap();
        assert_eq!(json, serde_json::json!({ "ok": false, "errors": ["x"] }));
    }

    #[test]
    fn failed_apps_are_reported_beside_the_errors() {
        let apply = LastApply::new(
            vec!["install org.broken.App//stable: no".into()],
            vec![failed("org.broken.App", "no")],
        );
        assert!(!apply.ok);
        assert_eq!(
            serde_json::to_value(&apply).unwrap(),
            serde_json::json!({
                "ok": false,
                "errors": ["install org.broken.App//stable: no"],
                "failed": [{ "id": "org.broken.App", "branch": "stable", "error": "no" }]
            })
        );
    }

    #[test]
    fn at_most_fifty_failed_apps_are_kept_the_first_ones() {
        let many = (0..60)
            .map(|i| failed(&format!("org.example.App{i}"), "no"))
            .collect();
        let apply = LastApply::new(Vec::new(), many);
        assert_eq!(apply.failed.len(), MAX_FAILED);
        assert_eq!(MAX_FAILED, 50);
        assert_eq!(apply.failed[0].id, "org.example.App0");
        assert_eq!(apply.failed[49].id, "org.example.App49");
    }

    #[test]
    fn a_failed_apps_error_is_cut_to_500_characters_as_javascript_counts_them() {
        let cut = |s: &str| {
            LastApply::new(Vec::new(), vec![failed("a.b.C", s)]).failed[0]
                .error
                .clone()
        };
        assert_eq!(cut("short"), "short");
        assert_eq!(cut(&"a".repeat(500)), "a".repeat(500));
        assert_eq!(cut(&"a".repeat(900)), "a".repeat(500));
        // The server counts UTF-16 units, so an emoji is two: 250 of them.
        assert_eq!(cut(&"😀".repeat(400)), "😀".repeat(250));
        // A pair is never split to make the number.
        assert_eq!(cut(&format!("{}😀", "a".repeat(499))), "a".repeat(499));
        // Characters, not bytes: 600 two-byte letters are cut at 500.
        assert_eq!(cut(&"é".repeat(600)), "é".repeat(500));
    }

    #[test]
    fn error_codes() {
        let r = Reply {
            status: 403,
            body: r#"{"error":"revoked"}"#.into(),
        };
        assert_eq!(r.error_code(), "revoked");
        let r = Reply {
            status: 502,
            body: "<html>".into(),
        };
        assert_eq!(r.error_code(), "HTTP 502");
    }
}
