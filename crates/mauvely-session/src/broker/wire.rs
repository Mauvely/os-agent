//! The broker's wire format: Suite's (`suite/docs/auth-broker.md`), one JSON
//! object per line each way, then the socket closes. `docs/broker.md` has
//! the whole protocol.
//!
//! ```text
//! → {"v":1,"op":"token","client":"compose","label":"Compose on ada-laptop"}
//! → {"v":1,"op":"browser"}
//! ← {"v":1,"ok":true,"token":"…","expiresAt":1771200000,"email":"…","origin":"https://mauvely.com"}
//! ← {"v":1,"ok":false,"reason":"signed_out"}
//! ← {"v":1,"ok":false,"reason":"sso_required","org":"northgate",
//!    "start":"https://mauvely.com/api/auth/sso/start?org=northgate"}
//! ```

use serde::Deserialize;
use serde_json::{Value, json};

pub const VERSION: i64 = 1;

/// A request is one short line. Anything longer is not one of ours.
pub const MAX_LINE: usize = 4096;

/// The Devices tab's label is at most this long on the server.
const MAX_LABEL: usize = 120;

/// One request line, read loosely: a field of the wrong type is as good as
/// absent, and `check` turns the result down.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct Raw {
    v: Value,
    op: Value,
    client: Value,
    label: Value,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    /// An app session for `client`, labelled `label` in the Devices tab.
    Token {
        client: String,
        label: Option<String>,
    },
    /// A browser session.
    Browser,
}

/// Parses one line. The refusal is the `reason` to answer with.
///
/// The op is checked before the version, as Suite does: an app that speaks
/// an op this broker does not know is told so, which it can act on.
pub fn parse(line: &[u8]) -> Result<Request, Reason> {
    let raw: Raw = serde_json::from_slice(line.trim_ascii()).unwrap_or_default();
    let text = |v: &Value| v.as_str().unwrap_or_default().to_owned();
    let op = text(&raw.op);
    if op != "token" && op != "browser" {
        return Err(Reason::UnknownOp);
    }
    if raw.v.as_i64() != Some(VERSION) {
        return Err(Reason::Version);
    }
    Ok(match op.as_str() {
        "token" => Request::Token {
            client: text(&raw.client),
            label: label(&text(&raw.label)),
        },
        _ => Request::Browser,
    })
}

/// What the Devices tab will call the session: control characters dropped,
/// trimmed, at most 120 UTF-16 units as the server counts them, nothing when
/// that leaves nothing.
fn label(text: &str) -> Option<String> {
    let clean: String = text.chars().filter(|c| !c.is_control()).collect();
    let mut units = 0;
    let cut: String = clean
        .trim()
        .chars()
        .take_while(|c| {
            units += c.len_utf16();
            units <= MAX_LABEL
        })
        .collect();
    let cut = cut.trim();
    (!cut.is_empty()).then(|| cut.to_owned())
}

/// Why a request was not answered with a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reason {
    UnknownOp,
    Version,
    TooLarge,
    /// The broker is serving as many callers as it will.
    Busy,
    /// Not a client the server mints.
    UnknownClient,
    /// This caller may not have it.
    Forbidden,
    /// This computer is not linked to an account, or the link has ended.
    SignedOut,
    /// The organisation signs its people in with single sign-on, and this
    /// computer's link was not approved from one. `start` is absolute.
    SsoRequired {
        org: String,
        start: String,
    },
    /// The organisation has turned that app off for this account.
    AppNotAllowed,
    RateLimited,
    /// The server said no for another reason.
    Refused,
    /// The server could not be reached, or failed.
    Unreachable,
    /// The server answered something this broker does not understand.
    BadResponse,
}

impl Reason {
    pub fn code(&self) -> &'static str {
        match self {
            Reason::UnknownOp => "unknown_op",
            Reason::Version => "version",
            Reason::TooLarge => "too_large",
            Reason::Busy => "busy",
            Reason::UnknownClient => "unknown_client",
            Reason::Forbidden => "forbidden",
            Reason::SignedOut => "signed_out",
            Reason::SsoRequired { .. } => "sso_required",
            Reason::AppNotAllowed => "app_not_allowed",
            Reason::RateLimited => "rate_limited",
            Reason::Refused => "refused",
            Reason::Unreachable => "unreachable",
            Reason::BadResponse => "bad_response",
        }
    }
}

/// A session handed to the caller.
pub struct Granted<'a> {
    pub token: &'a str,
    pub expires_at: u64,
    pub email: &'a str,
    pub origin: &'a str,
}

pub fn granted(g: &Granted) -> Vec<u8> {
    line(json!({
        "v": VERSION,
        "ok": true,
        "token": g.token,
        "expiresAt": g.expires_at,
        "email": g.email,
        "origin": g.origin,
    }))
}

pub fn refused(reason: &Reason) -> Vec<u8> {
    let mut out = json!({ "v": VERSION, "ok": false, "reason": reason.code() });
    if let Reason::SsoRequired { org, start } = reason {
        out["org"] = json!(org);
        out["start"] = json!(start);
    }
    line(out)
}

fn line(value: Value) -> Vec<u8> {
    let mut bytes = value.to_string().into_bytes();
    bytes.push(b'\n');
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(bytes: &[u8]) -> Value {
        assert_eq!(bytes.last(), Some(&b'\n'));
        assert_eq!(bytes.iter().filter(|b| **b == b'\n').count(), 1);
        serde_json::from_slice(bytes).unwrap()
    }

    #[test]
    fn reads_suites_requests() {
        assert_eq!(
            parse(br#"{"v":1,"op":"token","client":"compose","label":"Compose on Arch"}"#),
            Ok(Request::Token {
                client: "compose".into(),
                label: Some("Compose on Arch".into())
            })
        );
        assert_eq!(
            parse(b"{\"v\":1,\"op\":\"token\",\"client\":\"mail\"}\n"),
            Ok(Request::Token {
                client: "mail".into(),
                label: None
            })
        );
        assert_eq!(parse(br#"{"v":1,"op":"browser"}"#), Ok(Request::Browser));
        // A client on browser is ignored: the browser is the caller.
        assert_eq!(
            parse(br#"{"v":1,"op":"browser","client":"compose"}"#),
            Ok(Request::Browser)
        );
    }

    #[test]
    fn refuses_in_suites_order() {
        for line in [
            &b""[..],
            b"not json",
            b"[]",
            b"null",
            br#"{"v":1}"#,
            br#"{"v":1,"op":"cloud-link","client":"snap"}"#,
            br#"{"v":1,"op":"TOKEN","client":"compose"}"#,
            br#"{"v":1,"op":1}"#,
            // The op first, even when the version is wrong too.
            br#"{"v":2,"op":"nope"}"#,
        ] {
            assert_eq!(parse(line), Err(Reason::UnknownOp), "{line:?}");
        }
        for line in [
            &br#"{"op":"token","client":"compose"}"#[..],
            br#"{"v":2,"op":"token","client":"compose"}"#,
            br#"{"v":"1","op":"browser"}"#,
            br#"{"v":1.5,"op":"browser"}"#,
        ] {
            assert_eq!(parse(line), Err(Reason::Version), "{line:?}");
        }
        // A client of the wrong type is no client; the caller check refuses it.
        assert_eq!(
            parse(br#"{"v":1,"op":"token","client":7}"#),
            Ok(Request::Token {
                client: String::new(),
                label: None
            })
        );
    }

    #[test]
    fn labels_are_cleaned() {
        assert_eq!(
            label("  Compose\n on\u{7} Arch "),
            Some("Compose on Arch".into())
        );
        assert_eq!(label("\n\t "), None);
        assert_eq!(label(&"é".repeat(300)).unwrap().chars().count(), MAX_LABEL);
    }

    /// The server's limit is JavaScript's `length` after `trim()`: UTF-16
    /// units. A label over it fails the whole mint with `invalid_field`.
    #[test]
    fn labels_fit_the_servers_count() {
        let units = |s: &str| s.encode_utf16().count();
        let emoji = "\u{1F600}";
        let cut = label(&format!("{}{emoji}", "a".repeat(119))).unwrap();
        assert_eq!(cut, "a".repeat(119));
        let cut = label(&emoji.repeat(61)).unwrap();
        assert_eq!(units(&cut), MAX_LABEL);
        // Trimmed before it is counted, and after it is cut.
        let cut = label(&format!("   {}", "b".repeat(120))).unwrap();
        assert_eq!(cut, "b".repeat(120));
        let cut = label(&format!("{} c", "b".repeat(119))).unwrap();
        assert_eq!(cut, "b".repeat(119));
        for text in [
            &"x".repeat(500),
            &emoji.repeat(100),
            &"\u{10000}a".repeat(70),
        ] {
            assert!(units(&label(text).unwrap()) <= MAX_LABEL);
        }
    }

    #[test]
    fn answers_in_suites_shape() {
        let ok = read(&granted(&Granted {
            token: "tok",
            expires_at: 1_771_200_000,
            email: "ada@example.com",
            origin: "https://mauvely.com",
        }));
        assert_eq!(
            ok,
            json!({"v":1,"ok":true,"token":"tok","expiresAt":1_771_200_000u64,
                   "email":"ada@example.com","origin":"https://mauvely.com"})
        );
        assert_eq!(
            read(&refused(&Reason::SignedOut)),
            json!({"v":1,"ok":false,"reason":"signed_out"})
        );
        assert_eq!(
            read(&refused(&Reason::SsoRequired {
                org: "northgate".into(),
                start: "https://mauvely.com/api/auth/sso/start?org=northgate".into()
            })),
            json!({"v":1,"ok":false,"reason":"sso_required","org":"northgate",
                   "start":"https://mauvely.com/api/auth/sso/start?org=northgate"})
        );
    }
}
