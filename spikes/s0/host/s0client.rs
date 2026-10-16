//! Spike S0 socket client. Std only, built static.
//! usage: s0client <socket path> [line]   -> prints the reply line, or "ERR <errno text>"
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let path = a.get(1).expect("socket path");
    let line = a.get(2).cloned().unwrap_or_else(|| "{\"v\":1,\"op\":\"token\",\"client\":\"s0\"}".into());
    match UnixStream::connect(path) {
        Err(e) => {
            println!("ERR connect {path}: {e}");
            std::process::exit(2);
        }
        Ok(mut s) => {
            let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
            s.write_all(line.as_bytes()).unwrap();
            s.write_all(b"\n").unwrap();
            let mut out = Vec::new();
            let mut b = [0u8; 1];
            while let Ok(1) = s.read(&mut b) {
                if b[0] == b'\n' {
                    break;
                }
                out.push(b[0]);
            }
            println!("{}", String::from_utf8_lossy(&out));
        }
    }
}
