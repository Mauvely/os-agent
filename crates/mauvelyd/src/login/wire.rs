//! The login socket's protocol, version 1: one JSON object per line each way,
//! one connection per authentication. `pam_mauvely` is the only client; its
//! copy of the reasons is `crates/pam-mauvely/src/wire.rs`.
//!
//! ```text
//! → {"v":1,"op":"auth","service":"plasmalogin","username":"timur","password":"…"}
//! ← {"result":"ok"}
//!  | {"result":"code","prompt":"Code","info":"Enter the code from your authenticator app."}
//!  | {"result":"refused","reason":"credentials","message":"Wrong name or password."}
//! → {"v":1,"op":"code","code":"123456"}              (only after "code")
//! ← {"result":"ok"} | {"result":"refused",…}
//! → {"v":1,"op":"account","service":"…","username":"…"}
//! ← {"result":"ok"} | {"result":"refused",…}
//! ```
//!
//! Unknown fields are ignored, so a client may send more; a field named here is
//! never renamed.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// A request line, the password and its JSON escaping included.
pub const MAX_LINE: usize = 8192;
/// A password, in bytes. website-main's longest is 200 characters, 800 bytes
/// at most in UTF-8.
pub const MAX_PASSWORD: usize = 4096;
/// A PAM service name, a username, a code.
pub const MAX_FIELD: usize = 64;

/// What a client asks.
#[derive(PartialEq, Eq)]
pub enum Request {
    Auth {
        service: String,
        username: String,
        password: Zeroizing<String>,
    },
    Code {
        code: Zeroizing<String>,
    },
    Account {
        service: String,
        username: String,
    },
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::Auth {
                service, username, ..
            } => f
                .debug_struct("Auth")
                .field("service", service)
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Request::Code { .. } => f.debug_struct("Code").field("code", &"<redacted>").finish(),
            Request::Account { service, username } => f
                .debug_struct("Account")
                .field("service", service)
                .field("username", username)
                .finish(),
        }
    }
}

/// The line as sent. Its strings are wiped when it is dropped.
#[derive(Deserialize)]
struct Line {
    v: Option<u64>,
    op: Option<String>,
    service: Option<String>,
    username: Option<String>,
    password: Option<Zeroizing<String>>,
    code: Option<Zeroizing<String>>,
}

/// Parses one request line, without its newline. The caller wipes `line`.
pub fn parse(line: &[u8]) -> Result<Request, Reason> {
    if line.len() > MAX_LINE {
        return Err(Reason::BadRequest);
    }
    let parsed: Line = serde_json::from_slice(line).map_err(|_| Reason::BadRequest)?;
    if parsed.v != Some(1) {
        return Err(Reason::Version);
    }
    let field = |v: Option<String>| -> Result<String, Reason> {
        match v {
            Some(s)
                if !s.is_empty() && s.len() <= MAX_FIELD && !s.chars().any(char::is_control) =>
            {
                Ok(s)
            }
            _ => Err(Reason::BadRequest),
        }
    };
    match parsed.op.as_deref() {
        Some("auth") => {
            let password = parsed.password.ok_or(Reason::BadRequest)?;
            if password.len() > MAX_PASSWORD {
                return Err(Reason::BadRequest);
            }
            Ok(Request::Auth {
                service: field(parsed.service)?,
                username: field(parsed.username)?,
                password,
            })
        }
        Some("code") => {
            let code = parsed.code.ok_or(Reason::BadRequest)?;
            if code.len() > MAX_FIELD {
                return Err(Reason::BadRequest);
            }
            Ok(Request::Code { code })
        }
        Some("account") => Ok(Request::Account {
            service: field(parsed.service)?,
            username: field(parsed.username)?,
        }),
        _ => Err(Reason::BadRequest),
    }
}

/// Why a request was refused. Each has a code for `pam_mauvely` and the logs,
/// and one sentence for the person, which the module passes on with
/// `pam_error`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// A wrong password, online or against the cache.
    Credentials,
    /// A wrong code.
    Code,
    /// The code's challenge is spent, used up or too old.
    Expired,
    /// Not a name anybody could sign in with here.
    UnknownUser,
    /// A Mauvely name that a computer cannot use (a leading digit, or 32
    /// characters).
    BadUsername,
    /// A local account that is not a Mauvely person: `pam_unix` decides.
    NotMauvely,
    /// The device's say, or the server's: assigned to somebody else.
    NotAllowed,
    /// The caller may not ask about this person.
    Forbidden,
    Inactive,
    NotMember,
    SsoRequired,
    SecondFactorSetup,
    RateLimited,
    /// This computer has been revoked.
    Revoked,
    /// The server could not be reached, and the cache cannot sign them in.
    Offline,
    /// The server could not be reached at the code.
    Unreachable,
    /// The server answered something this agent cannot use.
    Unavailable,
    /// No cache entry, at a service that checks only the cache.
    NotCached,
    /// A text console, for somebody who is not a device admin.
    TextLogin,
    /// No `desired.people` yet: not enrolled, or never checked in with a
    /// server that sends it.
    NotReady,
    Busy,
    /// Something on this computer failed: the records, the home, the cache.
    Internal,
    BadRequest,
    Version,
}

impl Reason {
    pub fn code(self) -> &'static str {
        match self {
            Reason::Credentials => "credentials",
            Reason::Code => "code",
            Reason::Expired => "expired",
            Reason::UnknownUser => "unknown_user",
            Reason::BadUsername => "bad_username",
            Reason::NotMauvely => "not_mauvely",
            Reason::NotAllowed => "not_allowed",
            Reason::Forbidden => "forbidden",
            Reason::Inactive => "inactive",
            Reason::NotMember => "not_member",
            Reason::SsoRequired => "sso_required",
            Reason::SecondFactorSetup => "second_factor_setup",
            Reason::RateLimited => "rate_limited",
            Reason::Revoked => "revoked",
            Reason::Offline => "offline",
            Reason::Unreachable => "unreachable",
            Reason::Unavailable => "unavailable",
            Reason::NotCached => "not_cached",
            Reason::TextLogin => "text_login",
            Reason::NotReady => "not_ready",
            Reason::Busy => "busy",
            Reason::Internal => "internal",
            Reason::BadRequest => "bad_request",
            Reason::Version => "version",
        }
    }

    /// For the person. Plain, and said once (the design system's CONTENT
    /// FUNDAMENTALS). Never the English word for the password's prompt in a
    /// question: the patched login screen takes that for the password.
    pub fn message(self) -> &'static str {
        match self {
            Reason::Credentials | Reason::UnknownUser => "Wrong name or password.",
            Reason::Code => "That code isn't right.",
            Reason::Expired => "That code has expired. Sign in again.",
            Reason::BadUsername => "This name can't be used to sign in to a computer.",
            Reason::NotMauvely => "",
            Reason::NotAllowed => "This computer is assigned to someone else.",
            Reason::Forbidden => "You can only sign in as yourself here.",
            Reason::Inactive => "Your account is switched off.",
            Reason::NotMember => "You're no longer a member of this organisation.",
            Reason::SsoRequired => {
                "Your organisation signs you in with single sign-on, which this computer can't do yet."
            }
            Reason::SecondFactorSetup => {
                "Set up an authenticator app in your Mauvely account, then sign in here."
            }
            Reason::RateLimited => "Too many attempts. Try again in a few minutes.",
            Reason::Revoked => "This computer has been removed from your organisation.",
            Reason::Offline => "Connect to the internet to sign in.",
            Reason::Unreachable => "Mauvely can't be reached. Sign in again.",
            Reason::Unavailable => "Mauvely can't sign you in right now. Try again later.",
            Reason::NotCached => "Sign in at the login screen first.",
            Reason::TextLogin => "Sign in at the login screen.",
            Reason::NotReady => "This computer isn't ready for Mauvely accounts yet.",
            Reason::Busy => "This computer is busy. Try again.",
            Reason::Internal | Reason::BadRequest | Reason::Version => {
                "Something went wrong on this computer. Try again."
            }
        }
    }

    /// A refusal the server gave, by its error code. `None` for a code that
    /// is not a refusal of the person.
    pub fn from_server(code: &str) -> Option<Reason> {
        Some(match code {
            "credentials" => Reason::Credentials,
            "code" => Reason::Code,
            "expired" => Reason::Expired,
            "inactive" => Reason::Inactive,
            "not_member" => Reason::NotMember,
            "sso_required" => Reason::SsoRequired,
            "second_factor_setup" => Reason::SecondFactorSetup,
            "not_allowed" => Reason::NotAllowed,
            "rate_limited" => Reason::RateLimited,
            "revoked" => Reason::Revoked,
            _ => return None,
        })
    }
}

/// The prompt for the second question. Not "one-time password": the patched
/// login screen answers any prompt holding the word with the password.
pub const CODE_PROMPT: &str = "Code";

/// Which code, from where, for the line above the prompt.
pub fn code_info(factor: &str) -> &'static str {
    match factor {
        "email" => "Enter the code we emailed you.",
        _ => "Enter the code from your authenticator app.",
    }
}

/// An answer line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Ok,
    Code { info: &'static str },
    Refused(Reason),
}

#[derive(Serialize)]
#[serde(tag = "result", rename_all = "lowercase")]
enum Out<'a> {
    Ok,
    Code { prompt: &'a str, info: &'a str },
    Refused { reason: &'a str, message: &'a str },
}

/// The answer as a line, with its newline.
pub fn line(answer: &Answer) -> Vec<u8> {
    let out = match answer {
        Answer::Ok => Out::Ok,
        Answer::Code { info } => Out::Code {
            prompt: CODE_PROMPT,
            info,
        },
        Answer::Refused(r) => Out::Refused {
            reason: r.code(),
            message: r.message(),
        },
    };
    let mut bytes = serde_json::to_vec(&out).expect("an answer always serialises");
    bytes.push(b'\n');
    bytes
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(a: &Answer) -> String {
        String::from_utf8(line(a)).unwrap()
    }

    #[test]
    fn answers_are_the_fixed_lines() {
        assert_eq!(text(&Answer::Ok), "{\"result\":\"ok\"}\n");
        assert_eq!(
            text(&Answer::Code {
                info: code_info("totp")
            }),
            "{\"result\":\"code\",\"prompt\":\"Code\",\"info\":\"Enter the code from your authenticator app.\"}\n"
        );
        assert_eq!(
            text(&Answer::Code {
                info: code_info("email")
            }),
            "{\"result\":\"code\",\"prompt\":\"Code\",\"info\":\"Enter the code we emailed you.\"}\n"
        );
        assert_eq!(
            text(&Answer::Refused(Reason::Credentials)),
            "{\"result\":\"refused\",\"reason\":\"credentials\",\"message\":\"Wrong name or password.\"}\n"
        );
    }

    #[test]
    fn requests_parse() {
        let auth = parse(
            br#"{"v":1,"op":"auth","service":"plasmalogin","username":"timur","password":"p w"}"#,
        )
        .unwrap();
        match auth {
            Request::Auth {
                service,
                username,
                password,
            } => {
                assert_eq!(service, "plasmalogin");
                assert_eq!(username, "timur");
                assert_eq!(password.as_str(), "p w");
            }
            other => panic!("{other:?}"),
        }
        assert!(matches!(
            parse(br#"{"v":1,"op":"code","code":"123456"}"#).unwrap(),
            Request::Code { code } if code.as_str() == "123456"
        ));
        assert_eq!(
            parse(br#"{"v":1,"op":"account","service":"sudo","username":"timur","extra":true}"#)
                .unwrap(),
            Request::Account {
                service: "sudo".into(),
                username: "timur".into()
            }
        );
    }

    #[test]
    fn a_password_is_never_printed() {
        let auth =
            parse(br#"{"v":1,"op":"auth","service":"kde","username":"a","password":"hunter2"}"#)
                .unwrap();
        assert!(!format!("{auth:?}").contains("hunter2"));
        let code = parse(br#"{"v":1,"op":"code","code":"424242"}"#).unwrap();
        assert!(!format!("{code:?}").contains("424242"));
    }

    #[test]
    fn bad_requests_are_refused() {
        let bad = |l: &[u8]| parse(l).unwrap_err();
        assert_eq!(bad(b"not json"), Reason::BadRequest);
        assert_eq!(bad(br#"{"op":"auth"}"#), Reason::Version);
        assert_eq!(bad(br#"{"v":2,"op":"auth"}"#), Reason::Version);
        assert_eq!(bad(br#"{"v":1,"op":"steal"}"#), Reason::BadRequest);
        assert_eq!(
            bad(br#"{"v":1,"op":"auth","service":"kde","username":"a"}"#),
            Reason::BadRequest
        );
        assert_eq!(
            bad(br#"{"v":1,"op":"auth","service":"","username":"a","password":"x"}"#),
            Reason::BadRequest
        );
        assert_eq!(
            bad(br#"{"v":1,"op":"auth","service":"kde","username":"a\nb","password":"x"}"#),
            Reason::BadRequest
        );
        let long = format!(
            r#"{{"v":1,"op":"account","service":"kde","username":"{}"}}"#,
            "a".repeat(MAX_FIELD + 1)
        );
        assert_eq!(bad(long.as_bytes()), Reason::BadRequest);
        let long = format!(
            r#"{{"v":1,"op":"auth","service":"kde","username":"a","password":"{}"}}"#,
            "a".repeat(MAX_PASSWORD + 1)
        );
        assert_eq!(bad(long.as_bytes()), Reason::BadRequest);
        assert_eq!(bad(&vec![b' '; MAX_LINE + 1]), Reason::BadRequest);
    }

    #[test]
    fn a_long_password_in_another_script_fits() {
        // website-main's longest, 200 CJK characters: 600 bytes.
        let password = "密".repeat(200);
        let l = format!(
            r#"{{"v":1,"op":"auth","service":"plasmalogin","username":"a","password":"{password}"}}"#
        );
        assert!(
            matches!(parse(l.as_bytes()).unwrap(), Request::Auth { password: p, .. } if *p == password)
        );
    }

    #[test]
    fn the_servers_refusals_are_known_and_nothing_else_is() {
        for code in [
            "credentials",
            "code",
            "expired",
            "inactive",
            "not_member",
            "sso_required",
            "second_factor_setup",
            "not_allowed",
            "rate_limited",
            "revoked",
        ] {
            assert_eq!(Reason::from_server(code).unwrap().code(), code);
        }
        for code in [
            "unauthorised",
            "unavailable",
            "not_ready",
            "bad_request",
            "",
        ] {
            assert_eq!(Reason::from_server(code), None);
        }
    }

    #[test]
    fn no_message_says_password_in_a_way_the_greeter_would_take_for_the_prompt() {
        // Only the prompt matters to the greeter, but keep the word out of
        // every line the module shows, so a later prompt built from one cannot
        // carry it.
        assert!(!CODE_PROMPT.to_lowercase().contains("password"));
        assert!(!code_info("totp").to_lowercase().contains("password"));
        assert!(!code_info("email").to_lowercase().contains("password"));
    }
}
