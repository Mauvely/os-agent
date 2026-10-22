//! The built binary, as a browser starts it: frames on its standard input and
//! output, and the broker at `$XDG_RUNTIME_DIR/mauvely/broker`.

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixListener;
use std::process::{Command, Stdio};

const TOKEN: &str = "s3cr3t_tok_0123456789abcdefABCDEF-_012345678";

fn frame(message: &[u8]) -> Vec<u8> {
    let mut out = (message.len() as u32).to_ne_bytes().to_vec();
    out.extend_from_slice(message);
    out
}

#[test]
fn answers_a_browser_and_never_logs_the_token() {
    let runtime = std::env::temp_dir().join(format!("mauvely-host-bin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&runtime);
    std::fs::create_dir_all(runtime.join("mauvely")).unwrap();
    let listener = UnixListener::bind(runtime.join("mauvely/broker")).unwrap();
    let broker = std::thread::spawn(move || {
        let mut asked = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(&mut stream).read_line(&mut line).unwrap();
            let answer = if line.contains("origin") {
                "{\"v\":1,\"ok\":true,\"origin\":\"https://mauvely.com\"}\n".to_owned()
            } else {
                format!(
                    "{{\"v\":1,\"ok\":true,\"token\":\"{TOKEN}\",\"expiresAt\":1771200000,\
                     \"email\":\"ada@example.com\",\"origin\":\"https://mauvely.com\"}}\n"
                )
            };
            stream.write_all(answer.as_bytes()).unwrap();
            asked.push(line);
        }
        asked
    });

    let mut child = Command::new(env!("CARGO_BIN_EXE_mauvely-browser-host"))
        // As Chromium starts it.
        .arg("chrome-extension://abcdefghijklmnopabcdefghijklmnop/")
        .env_clear()
        .env("XDG_RUNTIME_DIR", &runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(&frame(br#"{"op":"origin"}"#)).unwrap();
    stdin.write_all(&frame(br#"{"op":"browser"}"#)).unwrap();
    drop(stdin);
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());

    let mut stdout = &out.stdout[..];
    let mut answers = Vec::new();
    while !stdout.is_empty() {
        let mut len = [0u8; 4];
        stdout.read_exact(&mut len).unwrap();
        let mut body = vec![0u8; u32::from_ne_bytes(len) as usize];
        stdout.read_exact(&mut body).unwrap();
        answers.push(serde_json::from_slice::<serde_json::Value>(&body).unwrap());
    }
    assert_eq!(answers[0]["origin"], "https://mauvely.com");
    assert_eq!(answers[1]["token"], TOKEN);
    assert!(answers[1].get("email").is_none());
    assert_eq!(
        broker.join().unwrap(),
        [
            "{\"v\":1,\"op\":\"origin\"}\n",
            "{\"v\":1,\"op\":\"browser\"}\n"
        ]
    );
    assert!(!String::from_utf8_lossy(&out.stderr).contains(TOKEN));
    std::fs::remove_dir_all(&runtime).unwrap();
}

#[test]
fn a_broker_that_is_not_running_is_unavailable() {
    let runtime = std::env::temp_dir().join(format!("mauvely-host-none-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&runtime);
    std::fs::create_dir_all(&runtime).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_mauvely-browser-host"))
        .env_clear()
        .env("XDG_RUNTIME_DIR", &runtime)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(&frame(br#"{"op":"browser"}"#))
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success());
    assert_eq!(&out.stdout[4..], br#"{"ok":false,"reason":"unavailable"}"#);
    std::fs::remove_dir_all(&runtime).unwrap();
}
