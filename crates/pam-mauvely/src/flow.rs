//! What the module does, over `Pam`, so it is tested without libpam.
//!
//! **Return codes**, against the authselect profile brief 26 drafts
//! (`pam_localuser` first, so a local account never gets here, then this
//! module as `[success=done ignore=ignore default=die]`, then `pam_unix`):
//!
//! | Answer | auth | account | In the stack |
//! |---|---|---|---|
//! | `ok` | `PAM_SUCCESS` | `PAM_SUCCESS` | done: signed in |
//! | `not_mauvely`: an account NSS knows that is not a Mauvely person (Fedora Atomic's system users live in `/usr/lib/passwd`, which `pam_localuser` does not read) | `PAM_IGNORE` | `PAM_IGNORE` | on to `pam_unix`, with the password already in `PAM_AUTHTOK` |
//! | `credentials`, `code`, `expired`, `rate_limited` | `PAM_AUTH_ERR` | | die; sudo asks again |
//! | `unknown_user`, `bad_username` | `PAM_USER_UNKNOWN` | `PAM_USER_UNKNOWN` | die: nobody else could sign them in |
//! | `not_allowed`, `forbidden`, `inactive`, `not_member`, `sso_required`, `second_factor_setup`, `revoked`, `text_login` | `PAM_PERM_DENIED` | `PAM_PERM_DENIED` | die |
//! | `offline`, `unreachable`, `unavailable`, `not_cached`, `not_ready`, `busy`, or the daemon missing, silent or garbled | `PAM_AUTHINFO_UNAVAIL` | `PAM_AUTHINFO_UNAVAIL` (`not_cached`: `PAM_PERM_DENIED`) | die, at once |
//! | `internal`, `bad_request`, `version` | `PAM_SYSTEM_ERR` | `PAM_SYSTEM_ERR` | die |
//! | anything else | `PAM_AUTH_ERR` | `PAM_PERM_DENIED` | die |
//!
//! Every refusal but `not_mauvely` is said to the person with `pam_error`,
//! unless the caller asked for `PAM_SILENT`.

use std::path::Path;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::client::{self, Answer, Conn, Request};

pub const PAM_SUCCESS: i32 = 0;
pub const PAM_SYSTEM_ERR: i32 = 4;
pub const PAM_PERM_DENIED: i32 = 6;
pub const PAM_AUTH_ERR: i32 = 7;
pub const PAM_AUTHINFO_UNAVAIL: i32 = 9;
pub const PAM_USER_UNKNOWN: i32 = 10;
pub const PAM_CONV_ERR: i32 = 19;
pub const PAM_IGNORE: i32 = 25;

/// The login screen: the only service the daemon takes online, which can
/// take a network round trip or three.
const LOGIN_SCREEN: &str = "plasmalogin";
const ONLINE_WAIT: Duration = Duration::from_secs(60);
/// Everything else is answered from this computer.
const LOCAL_WAIT: Duration = Duration::from_secs(20);

/// What the module needs from PAM. Each `Err` is the PAM code to return.
pub trait Pam {
    fn service(&self) -> Result<String, i32>;
    fn user(&self) -> Result<String, i32>;
    /// The password: an earlier module's, or asked for.
    fn password(&self) -> Result<Zeroizing<String>, i32>;
    /// A hidden answer to `prompt`.
    fn secret(&self, prompt: &str) -> Result<Zeroizing<String>, i32>;
    fn info(&self, text: &str);
    fn error(&self, text: &str);
    /// For the system log.
    fn log(&self, text: &str);
}

pub fn auth_code(reason: &str) -> i32 {
    match reason {
        "credentials" | "code" | "expired" | "rate_limited" => PAM_AUTH_ERR,
        "unknown_user" | "bad_username" => PAM_USER_UNKNOWN,
        "not_mauvely" => PAM_IGNORE,
        "not_allowed"
        | "forbidden"
        | "inactive"
        | "not_member"
        | "sso_required"
        | "second_factor_setup"
        | "revoked"
        | "text_login" => PAM_PERM_DENIED,
        "offline" | "unreachable" | "unavailable" | "not_cached" | "not_ready" | "busy" => {
            PAM_AUTHINFO_UNAVAIL
        }
        "internal" | "bad_request" | "version" => PAM_SYSTEM_ERR,
        _ => PAM_AUTH_ERR,
    }
}

pub fn account_code(reason: &str) -> i32 {
    match reason {
        "unknown_user" | "bad_username" => PAM_USER_UNKNOWN,
        "not_mauvely" => PAM_IGNORE,
        "not_ready" | "busy" | "unavailable" => PAM_AUTHINFO_UNAVAIL,
        "internal" | "bad_request" | "version" => PAM_SYSTEM_ERR,
        _ => PAM_PERM_DENIED,
    }
}

fn wait_for(service: &str) -> Duration {
    if service == LOGIN_SCREEN {
        ONLINE_WAIT
    } else {
        LOCAL_WAIT
    }
}

fn unreachable(pam: &dyn Pam, e: &client::Error) -> i32 {
    pam.log(&format!("mauvelyd could not be asked: {e}"));
    PAM_AUTHINFO_UNAVAIL
}

fn refused(pam: &dyn Pam, silent: bool, reason: &str, message: &str, code: i32) -> i32 {
    if reason != "not_mauvely" {
        pam.log(&format!("refused: {reason}"));
        if !silent && !message.is_empty() {
            pam.error(message);
        }
    }
    code
}

/// `pam_sm_authenticate`.
pub fn authenticate(pam: &dyn Pam, socket: &Path, silent: bool) -> i32 {
    let service = match pam.service() {
        Ok(s) => s,
        Err(code) => return code,
    };
    let username = match pam.user() {
        Ok(u) => u,
        Err(code) => return code,
    };
    let password = match pam.password() {
        Ok(p) => p,
        Err(code) => return code,
    };
    let mut conn = match Conn::open(socket) {
        Ok(c) => c,
        Err(e) => return unreachable(pam, &e),
    };
    let wait = wait_for(&service);
    let request = client::line(&Request::Auth {
        service: &service,
        username: &username,
        password: &password,
    });
    drop(password);
    let answer = match conn.ask(&request, wait) {
        Ok(a) => a,
        Err(e) => return unreachable(pam, &e),
    };
    drop(request);
    let (prompt, info) = match answer {
        Answer::Ok => return PAM_SUCCESS,
        Answer::Refused { reason, message } => {
            return refused(pam, silent, &reason, &message, auth_code(&reason));
        }
        Answer::Code { prompt, info } => (prompt, info),
    };
    if !silent && !info.is_empty() {
        pam.info(&info);
    }
    let code = match pam.secret(&prompt) {
        Ok(c) if !c.is_empty() => c,
        // Nothing typed: the question is refused, and so is the login.
        Ok(_) => return PAM_AUTH_ERR,
        Err(_) => return PAM_CONV_ERR,
    };
    let request = client::line(&Request::Code { code: &code });
    drop(code);
    match conn.ask(&request, wait) {
        Ok(Answer::Ok) => PAM_SUCCESS,
        Ok(Answer::Refused { reason, message }) => {
            refused(pam, silent, &reason, &message, auth_code(&reason))
        }
        // A second code is not the protocol.
        Ok(Answer::Code { .. }) => PAM_SYSTEM_ERR,
        Err(e) => unreachable(pam, &e),
    }
}

/// `pam_sm_acct_mgmt`.
pub fn account(pam: &dyn Pam, socket: &Path, silent: bool) -> i32 {
    let service = match pam.service() {
        Ok(s) => s,
        Err(code) => return code,
    };
    let username = match pam.user() {
        Ok(u) => u,
        Err(code) => return code,
    };
    let mut conn = match Conn::open(socket) {
        Ok(c) => c,
        Err(e) => return unreachable(pam, &e),
    };
    let request = client::line(&Request::Account {
        service: &service,
        username: &username,
    });
    match conn.ask(&request, LOCAL_WAIT) {
        Ok(Answer::Ok) => PAM_SUCCESS,
        Ok(Answer::Refused { reason, message }) => {
            refused(pam, silent, &reason, &message, account_code(&reason))
        }
        Ok(Answer::Code { .. }) => PAM_SYSTEM_ERR,
        Err(e) => unreachable(pam, &e),
    }
}

#[cfg(test)]
mod tests;
