//! Spike S0 native messaging host. Std only, built static (see build-host.sh).
//!
//! Speaks the WebExtensions native messaging framing (u32 native-endian length, then JSON) on
//! stdin/stdout and answers every message with an echo plus what the process can see of its
//! own sandbox. If a broker socket exists it also asks it one line, which makes this the whole
//! chain: extension -> host (inside the browser's sandbox) -> broker socket.
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len() + 2);
    o.push('"');
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

fn opt(s: Option<String>) -> String {
    s.map(|v| esc(&v)).unwrap_or_else(|| "null".into())
}

fn flatpak_field(info: &str, key: &str) -> Option<String> {
    info.lines()
        .find_map(|l| l.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
        .map(|s| s.to_string())
}

fn ask_broker(dir: &str) -> String {
    let path = format!("{dir}/broker");
    let mut s = match UnixStream::connect(&path) {
        Ok(s) => s,
        Err(e) => return format!("{{\"path\":{},\"error\":{}}}", esc(&path), esc(&e.to_string())),
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = s.write_all(b"{\"v\":1,\"op\":\"token\",\"client\":\"s0\"}\n");
    let mut buf = Vec::new();
    let mut b = [0u8; 1];
    while let Ok(1) = s.read(&mut b) {
        if b[0] == b'\n' {
            break;
        }
        buf.push(b[0]);
        if buf.len() > 65536 {
            break;
        }
    }
    format!(
        "{{\"path\":{},\"reply\":{}}}",
        esc(&path),
        esc(&String::from_utf8_lossy(&buf))
    )
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    loop {
        let mut len = [0u8; 4];
        if stdin.read_exact(&mut len).is_err() {
            return; // browser closed the pipe
        }
        let n = u32::from_ne_bytes(len) as usize;
        if n > 1 << 20 {
            return;
        }
        let mut msg = vec![0u8; n];
        if stdin.read_exact(&mut msg).is_err() {
            return;
        }
        let msg = String::from_utf8_lossy(&msg).to_string();

        let info = std::fs::read_to_string("/.flatpak-info").ok();
        let xdg = std::env::var("XDG_RUNTIME_DIR").unwrap_or_default();
        let pid = std::process::id();
        let ppid = std::fs::read_to_string("/proc/self/stat")
            .ok()
            .and_then(|s| s.rsplit(')').next().map(|r| r.trim().to_string()))
            .and_then(|r| r.split(' ').nth(1).map(|p| p.to_string()))
            .unwrap_or_default();
        let parent_comm = std::fs::read_to_string(format!("/proc/{ppid}/comm"))
            .ok()
            .map(|s| s.trim().to_string());
        let brokers: Vec<String> = ["mauvely", "mauvely-s0"]
            .iter()
            .map(|d| ask_broker(&format!("{xdg}/{d}")))
            .collect();
        let argv_json: Vec<String> = argv.iter().map(|a| esc(a)).collect();
        let reply = format!(
            "{{\"echo\":{},\"host\":{{\"pid\":{},\"ppid\":{},\"parent_comm\":{},\"argv\":[{}],\"home\":{},\"xdg_runtime_dir\":{},\"exe\":{},\"cwd\":{},\"has_flatpak_info\":{},\"flatpak_app\":{},\"flatpak_runtime\":{},\"flatpak_app_path\":{},\"brokers\":[{}]}}}}",
            // the extension sends valid JSON; embed it verbatim, falling back to a string
            if msg.trim_start().starts_with(['{', '[', '"']) { msg.clone() } else { esc(&msg) },
            pid,
            esc(&ppid),
            opt(parent_comm),
            argv_json.join(","),
            opt(std::env::var("HOME").ok()),
            esc(&xdg),
            opt(std::fs::read_link("/proc/self/exe").ok().map(|p| p.display().to_string())),
            opt(std::env::current_dir().ok().map(|p| p.display().to_string())),
            info.is_some(),
            opt(info.as_deref().and_then(|i| flatpak_field(i, "name"))),
            opt(info.as_deref().and_then(|i| flatpak_field(i, "runtime"))),
            opt(info.as_deref().and_then(|i| flatpak_field(i, "app-path"))),
            brokers.join(","),
        );
        let b = reply.as_bytes();
        if stdout.write_all(&(b.len() as u32).to_ne_bytes()).is_err()
            || stdout.write_all(b).is_err()
            || stdout.flush().is_err()
        {
            return;
        }
    }
}
