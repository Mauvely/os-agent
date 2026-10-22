//! The socket's side: lines, limits and the exchange, over real Unix
//! sockets.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;

use serde_json::Value;

use super::*;
use crate::fake::TempDir;
use crate::login::service::tests::{PASSWORD, UID, challenge, fx, shared, signed_in, v1};

fn me() -> u32 {
    // SAFETY: getuid cannot fail and touches no memory.
    unsafe { libc::getuid() }
}

/// Sends `lines`, one at a time, each after the answer to the one before,
/// and returns the answers.
fn exchange(client: &mut UnixStream, lines: &[&str]) -> Vec<Value> {
    let mut reader = BufReader::new(client.try_clone().unwrap());
    let mut answers = Vec::new();
    for l in lines {
        // The server may have closed already.
        if client.write_all(format!("{l}\n").as_bytes()).is_err() {
            break;
        }
        let mut answer = String::new();
        if reader.read_line(&mut answer).unwrap_or(0) == 0 {
            break;
        }
        answers.push(serde_json::from_str(&answer).unwrap());
    }
    answers
}

fn auth(service: &str, username: &str, password: &str) -> String {
    serde_json::json!({
        "v": 1, "op": "auth", "service": service, "username": username, "password": password
    })
    .to_string()
}

#[test]
fn the_password_then_the_code_on_one_connection() {
    let f = fx(Some(shared()));
    f.params(v1())
        .login(challenge("totp"))
        .code(signed_in("timur", UID, false, 1));
    let (mut client, server) = UnixStream::pair().unwrap();
    std::thread::scope(|s| {
        s.spawn(|| handle(server, 0, &f.svc));
        let answers = exchange(
            &mut client,
            &[
                &auth("plasmalogin", "timur", PASSWORD),
                r#"{"v":1,"op":"code","code":"123456"}"#,
            ],
        );
        assert_eq!(
            answers,
            [
                serde_json::json!({ "result": "code", "prompt": "Code",
                                    "info": "Enter the code from your authenticator app." }),
                serde_json::json!({ "result": "ok" }),
            ]
        );
    });
    assert!(f.entry("timur").is_some());
}

#[test]
fn a_refusal_carries_its_reason_and_sentence_then_the_connection_ends() {
    let f = fx(Some(shared()));
    let (mut client, server) = UnixStream::pair().unwrap();
    std::thread::scope(|s| {
        s.spawn(|| handle(server, 0, &f.svc));
        let answers = exchange(&mut client, &[&auth("sudo", "timur", PASSWORD), "{}"]);
        assert_eq!(
            answers,
            [
                serde_json::json!({ "result": "refused", "reason": "not_cached",
                                 "message": "Sign in at the login screen first." })
            ]
        );
    });
}

#[test]
fn account_is_one_line_each_way() {
    let f = fx(Some(shared()));
    f.signed_in_before("timur", UID, PASSWORD, 1);
    let (mut client, server) = UnixStream::pair().unwrap();
    std::thread::scope(|s| {
        s.spawn(|| handle(server, 0, &f.svc));
        let answers = exchange(
            &mut client,
            &[r#"{"v":1,"op":"account","service":"login","username":"timur"}"#],
        );
        assert_eq!(answers[0]["reason"], "text_login");
        assert_eq!(answers[0]["message"], "Sign in at the login screen.");
    });
}

#[test]
fn a_code_with_nothing_waiting_and_a_second_auth_are_bad_requests() {
    let f = fx(Some(shared()));
    for lines in [
        vec![r#"{"v":1,"op":"code","code":"123456"}"#.to_owned()],
        vec![
            auth("plasmalogin", "timur", PASSWORD),
            auth("plasmalogin", "timur", PASSWORD),
        ],
        vec!["not json".to_owned()],
        vec![r#"{"v":7,"op":"account","service":"kde","username":"timur"}"#.to_owned()],
    ] {
        f.params(v1()).login(challenge("totp"));
        let (mut client, server) = UnixStream::pair().unwrap();
        std::thread::scope(|s| {
            s.spawn(|| handle(server, 0, &f.svc));
            let lines: Vec<&str> = lines.iter().map(String::as_str).collect();
            let answers = exchange(&mut client, &lines);
            let last = answers.last().unwrap();
            assert_eq!(last["result"], "refused");
            assert!(
                ["bad_request", "version"].contains(&last["reason"].as_str().unwrap()),
                "{last}"
            );
        });
    }
}

#[test]
fn a_line_too_long_is_refused_without_waiting_for_its_end() {
    let f = fx(Some(shared()));
    let (mut client, server) = UnixStream::pair().unwrap();
    std::thread::scope(|s| {
        s.spawn(|| handle(server, 0, &f.svc));
        client.write_all(&vec![b'a'; MAX_LINE + 2048]).unwrap();
        let mut answer = String::new();
        BufReader::new(&client).read_line(&mut answer).unwrap();
        assert!(answer.contains("bad_request"), "{answer}");
    });
}

#[test]
fn a_client_that_goes_away_mid_code_leaves_nothing_behind() {
    let f = fx(Some(shared()));
    f.params(v1()).login(challenge("totp"));
    let (mut client, server) = UnixStream::pair().unwrap();
    std::thread::scope(|s| {
        let served = s.spawn(|| handle(server, 0, &f.svc));
        let answers = exchange(&mut client, &[&auth("plasmalogin", "timur", PASSWORD)]);
        assert_eq!(answers[0]["result"], "code");
        drop(client);
        served.join().unwrap();
    });
    assert!(f.entry("timur").is_none());
}

#[test]
fn lines_arrive_whole_and_in_pieces() {
    let (mut a, mut b) = UnixStream::pair().unwrap();
    let mut lines = Lines::default();
    a.write_all(b"one\ntw").unwrap();
    let deadline = Instant::now() + Duration::from_secs(2);
    assert_eq!(&**lines.next(&mut b, deadline).unwrap(), b"one");
    a.write_all(b"o\n").unwrap();
    assert_eq!(&**lines.next(&mut b, deadline).unwrap(), b"two");
    // Silent past the deadline.
    assert!(matches!(
        lines.next(&mut b, Instant::now() + Duration::from_millis(50)),
        Err(Ended::Gone)
    ));
    // Closed.
    drop(a);
    assert!(matches!(
        lines.next(&mut b, Instant::now() + Duration::from_secs(1)),
        Err(Ended::Gone)
    ));
    // The buffer never grows past its first allocation.
    assert_eq!(lines.buf.capacity(), MAX_LINE + 1024);
}

#[test]
fn the_socket_is_everyones_to_connect_to_and_knows_who_connected() {
    let dir = TempDir::new();
    let path = dir.path().join("run/auth.sock");
    let listener = bind(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o666);
    let client = UnixStream::connect(&path).unwrap();
    let (server, _) = listener.accept().unwrap();
    assert_eq!(peer_uid(&server), Some(me()));
    drop(client);

    // A stale socket is replaced; anything else at the name is not.
    drop(listener);
    bind(&path).unwrap();
    let file = dir.path().join("run/not-a-socket");
    std::fs::write(&file, "x").unwrap();
    assert!(bind(&file).is_err());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "x");
}

#[test]
fn each_uid_but_root_gets_four_connections_and_everyone_thirty_two() {
    let slots = Arc::new(Slots::default());
    let mut held: Vec<Slot> = (0..PER_UID)
        .map(|_| Slots::take(&slots, 1000).unwrap())
        .collect();
    assert!(Slots::take(&slots, 1000).is_none());
    // Another person, and root, are not held up by it.
    held.push(Slots::take(&slots, 1001).unwrap());
    while held.len() < MAX_CONNECTIONS {
        held.push(Slots::take(&slots, 0).unwrap());
    }
    assert!(Slots::take(&slots, 0).is_none());
    // A connection that ends gives its place back.
    held.swap_remove(0);
    assert!(Slots::take(&slots, 1000).is_some());
}

#[test]
fn a_full_house_is_told_it_is_busy() {
    let (mut client, server) = UnixStream::pair().unwrap();
    refuse_now(server, Reason::Busy);
    let mut answer = String::new();
    BufReader::new(&mut client).read_line(&mut answer).unwrap();
    assert!(answer.contains("\"busy\""), "{answer}");
}
