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

/// The outcome of the previous reconcile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LastApply {
    pub ok: bool,
    pub errors: Vec<String>,
}

impl LastApply {
    pub fn from_errors(errors: Vec<String>) -> Self {
        LastApply {
            ok: errors.is_empty(),
            errors,
        }
    }
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
            "apps": [{ "id": "net.mauvely.compose", "branch": "stable",
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
