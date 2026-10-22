//! The module's flow and every mapping, against a fake daemon on a real
//! socket and a fake PAM.

use std::cell::RefCell;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread::JoinHandle;
use std::time::Instant;

use serde_json::{Value, json};

use super::*;

/// What PAM would give and what the module said to it.
struct FakePam {
    service: &'static str,
    user: Result<&'static str, i32>,
    password: Result<&'static str, i32>,
    /// The answer to the code prompt.
    code: Result<&'static str, i32>,
    said: RefCell<Vec<String>>,
}

impl FakePam {
    fn new(service: &'static str) -> Self {
        FakePam {
            service,
            user: Ok("timur"),
            password: Ok("correct horse 1"),
            code: Ok("123456"),
            said: RefCell::default(),
        }
    }

    fn said(&self) -> Vec<String> {
        self.said.borrow().clone()
    }
}

impl Pam for FakePam {
    fn service(&self) -> Result<String, i32> {
        Ok(self.service.into())
    }
    fn user(&self) -> Result<String, i32> {
        self.user.map(str::to_owned)
    }
    fn password(&self) -> Result<Zeroizing<String>, i32> {
        self.password.map(|p| Zeroizing::new(p.into()))
    }
    fn secret(&self, prompt: &str) -> Result<Zeroizing<String>, i32> {
        self.said.borrow_mut().push(format!("prompt: {prompt}"));
        self.code.map(|c| Zeroizing::new(c.into()))
    }
    fn info(&self, text: &str) {
        self.said.borrow_mut().push(format!("info: {text}"));
    }
    fn error(&self, text: &str) {
        self.said.borrow_mut().push(format!("error: {text}"));
    }
    fn log(&self, _: &str) {}
}

/// A daemon that answers one connection with `answers`, one per line it
/// reads, and hands back the lines.
struct FakeDaemon {
    socket: PathBuf,
    dir: PathBuf,
    thread: Option<JoinHandle<Vec<Value>>>,
}

impl FakeDaemon {
    fn start(answers: Vec<Value>) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "pam-mauvely-flow-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("auth.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let thread = std::thread::spawn(move || {
            let (s, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(s.try_clone().unwrap());
            let mut writer = s;
            let mut got = Vec::new();
            for answer in answers {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap_or(0) == 0 {
                    break;
                }
                got.push(serde_json::from_str(&line).unwrap());
                if answer.is_null() {
                    // Hang up without a word.
                    break;
                }
                writer.write_all(format!("{answer}\n").as_bytes()).unwrap();
            }
            got
        });
        FakeDaemon {
            socket,
            dir,
            thread: Some(thread),
        }
    }

    fn lines(mut self) -> Vec<Value> {
        self.thread.take().unwrap().join().unwrap()
    }
}

impl Drop for FakeDaemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn ok() -> Value {
    json!({ "result": "ok" })
}

fn no(reason: &str) -> Value {
    json!({ "result": "refused", "reason": reason, "message": format!("Said for {reason}.") })
}

fn code() -> Value {
    json!({ "result": "code", "prompt": "Code", "info": "Enter the code from your authenticator app." })
}

#[test]
fn a_password_the_daemon_takes_signs_in() {
    let d = FakeDaemon::start(vec![ok()]);
    let pam = FakePam::new("sudo");
    assert_eq!(authenticate(&pam, &d.socket, false), PAM_SUCCESS);
    assert!(pam.said().is_empty());
    assert_eq!(
        d.lines(),
        [
            json!({ "v": 1, "op": "auth", "service": "sudo", "username": "timur",
                 "password": "correct horse 1" })
        ]
    );
}

#[test]
fn the_login_screen_says_which_code_then_asks_for_it_hidden() {
    let d = FakeDaemon::start(vec![code(), ok()]);
    let pam = FakePam::new("plasmalogin");
    assert_eq!(authenticate(&pam, &d.socket, false), PAM_SUCCESS);
    assert_eq!(
        pam.said(),
        [
            "info: Enter the code from your authenticator app.",
            "prompt: Code"
        ]
    );
    let lines = d.lines();
    assert_eq!(lines[1], json!({ "v": 1, "op": "code", "code": "123456" }));
}

#[test]
fn a_wrong_code_is_an_authentication_error_said_once() {
    let d = FakeDaemon::start(vec![code(), no("code")]);
    let pam = FakePam::new("plasmalogin");
    assert_eq!(authenticate(&pam, &d.socket, false), PAM_AUTH_ERR);
    assert_eq!(pam.said().last().unwrap(), "error: Said for code.");
}

#[test]
fn no_code_typed_refuses_without_sending_one() {
    let d = FakeDaemon::start(vec![code(), ok()]);
    let mut pam = FakePam::new("plasmalogin");
    pam.code = Ok("");
    assert_eq!(authenticate(&pam, &d.socket, false), PAM_AUTH_ERR);
    assert_eq!(d.lines().len(), 1);

    // No greeter to ask (autologin): the conversation fails.
    let d = FakeDaemon::start(vec![code(), ok()]);
    let mut pam = FakePam::new("plasmalogin");
    pam.code = Err(PAM_CONV_ERR);
    assert_eq!(authenticate(&pam, &d.socket, false), PAM_CONV_ERR);
    assert_eq!(d.lines().len(), 1);
}

#[test]
fn every_refusal_maps_to_its_code_and_is_said() {
    for (reason, want) in [
        ("credentials", PAM_AUTH_ERR),
        ("code", PAM_AUTH_ERR),
        ("expired", PAM_AUTH_ERR),
        ("rate_limited", PAM_AUTH_ERR),
        ("unknown_user", PAM_USER_UNKNOWN),
        ("bad_username", PAM_USER_UNKNOWN),
        ("not_allowed", PAM_PERM_DENIED),
        ("forbidden", PAM_PERM_DENIED),
        ("inactive", PAM_PERM_DENIED),
        ("not_member", PAM_PERM_DENIED),
        ("sso_required", PAM_PERM_DENIED),
        ("second_factor_setup", PAM_PERM_DENIED),
        ("revoked", PAM_PERM_DENIED),
        ("offline", PAM_AUTHINFO_UNAVAIL),
        ("unreachable", PAM_AUTHINFO_UNAVAIL),
        ("unavailable", PAM_AUTHINFO_UNAVAIL),
        ("not_cached", PAM_AUTHINFO_UNAVAIL),
        ("not_ready", PAM_AUTHINFO_UNAVAIL),
        ("busy", PAM_AUTHINFO_UNAVAIL),
        ("internal", PAM_SYSTEM_ERR),
        ("bad_request", PAM_SYSTEM_ERR),
        ("version", PAM_SYSTEM_ERR),
        ("something_new", PAM_AUTH_ERR),
    ] {
        let d = FakeDaemon::start(vec![no(reason)]);
        let pam = FakePam::new("plasmalogin");
        assert_eq!(authenticate(&pam, &d.socket, false), want, "{reason}");
        assert_eq!(
            pam.said(),
            [format!("error: Said for {reason}.")],
            "{reason}"
        );
    }
}

#[test]
fn a_local_account_is_left_to_pam_unix_without_a_word() {
    let d = FakeDaemon::start(vec![no("not_mauvely")]);
    let pam = FakePam::new("sudo");
    assert_eq!(authenticate(&pam, &d.socket, false), PAM_IGNORE);
    assert!(pam.said().is_empty());
    let d = FakeDaemon::start(vec![no("not_mauvely")]);
    assert_eq!(account(&pam, &d.socket, false), PAM_IGNORE);
}

#[test]
fn silent_says_nothing() {
    let d = FakeDaemon::start(vec![no("credentials")]);
    let pam = FakePam::new("sudo");
    assert_eq!(authenticate(&pam, &d.socket, true), PAM_AUTH_ERR);
    assert!(pam.said().is_empty());
    // The code is still asked: it is a question, not a message.
    let d = FakeDaemon::start(vec![code(), ok()]);
    let pam = FakePam::new("plasmalogin");
    assert_eq!(authenticate(&pam, &d.socket, true), PAM_SUCCESS);
    assert_eq!(pam.said(), ["prompt: Code"]);
}

#[test]
fn account_refusals_are_permission_denied() {
    for (reason, want) in [
        ("text_login", PAM_PERM_DENIED),
        ("not_cached", PAM_PERM_DENIED),
        ("not_allowed", PAM_PERM_DENIED),
        ("forbidden", PAM_PERM_DENIED),
        ("unknown_user", PAM_USER_UNKNOWN),
        ("not_ready", PAM_AUTHINFO_UNAVAIL),
        ("internal", PAM_SYSTEM_ERR),
        ("something_new", PAM_PERM_DENIED),
    ] {
        let d = FakeDaemon::start(vec![no(reason)]);
        let pam = FakePam::new("login");
        assert_eq!(account(&pam, &d.socket, false), want, "{reason}");
    }
    let d = FakeDaemon::start(vec![ok()]);
    let pam = FakePam::new("login");
    assert_eq!(account(&pam, &d.socket, false), PAM_SUCCESS);
    assert_eq!(
        d.lines(),
        [json!({ "v": 1, "op": "account", "service": "login", "username": "timur" })]
    );
}

#[test]
fn no_daemon_fails_closed_and_fast() {
    let dir = std::env::temp_dir().join(format!("pam-mauvely-none-{}", std::process::id()));
    let pam = FakePam::new("plasmalogin");
    let start = Instant::now();
    assert_eq!(
        authenticate(&pam, &dir.join("auth.sock"), false),
        PAM_AUTHINFO_UNAVAIL
    );
    assert_eq!(
        account(&pam, &dir.join("auth.sock"), false),
        PAM_AUTHINFO_UNAVAIL
    );
    assert!(start.elapsed().as_millis() < 500);
    assert!(pam.said().is_empty());
}

#[test]
fn a_daemon_that_hangs_up_or_garbles_fails_closed() {
    let d = FakeDaemon::start(vec![Value::Null]);
    assert_eq!(
        authenticate(&FakePam::new("kde"), &d.socket, false),
        PAM_AUTHINFO_UNAVAIL
    );
    let d = FakeDaemon::start(vec![json!({ "result": "yes" })]);
    assert_eq!(
        authenticate(&FakePam::new("kde"), &d.socket, false),
        PAM_AUTHINFO_UNAVAIL
    );
    // Hangs up at the code.
    let d = FakeDaemon::start(vec![code(), Value::Null]);
    assert_eq!(
        authenticate(&FakePam::new("plasmalogin"), &d.socket, false),
        PAM_AUTHINFO_UNAVAIL
    );
    // A second code is not the protocol.
    let d = FakeDaemon::start(vec![code(), code()]);
    assert_eq!(
        authenticate(&FakePam::new("plasmalogin"), &d.socket, false),
        PAM_SYSTEM_ERR
    );
}

#[test]
fn pams_own_failures_come_back_without_asking_the_daemon() {
    let dir = std::env::temp_dir().join(format!("pam-mauvely-unasked-{}", std::process::id()));
    let mut pam = FakePam::new("sudo");
    pam.user = Err(PAM_USER_UNKNOWN);
    assert_eq!(authenticate(&pam, &dir.join("x"), false), PAM_USER_UNKNOWN);
    let mut pam = FakePam::new("sudo");
    pam.password = Err(PAM_CONV_ERR);
    assert_eq!(authenticate(&pam, &dir.join("x"), false), PAM_CONV_ERR);
}

#[test]
fn the_login_screen_waits_longer_than_the_rest() {
    assert_eq!(wait_for("plasmalogin"), ONLINE_WAIT);
    for s in ["kde", "sudo", "polkit-1", "login"] {
        assert_eq!(wait_for(s), LOCAL_WAIT);
    }
    assert!(ONLINE_WAIT > LOCAL_WAIT);
}
