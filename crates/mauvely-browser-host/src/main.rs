//! `mauvely-browser-host`: started by Firefox or Chromium, inside its Flatpak
//! sandbox, for the Mauvely OS extension. The browser passes the caller's
//! extension or origin as arguments; the browser has already checked them
//! against the manifest's allow-list, and the broker checks the sandbox, so
//! they are not read here.

use std::process::ExitCode;

use mauvely_browser_host::{Broker, Socket, serve};

fn main() -> ExitCode {
    let socket = Socket::from_env();
    if socket.is_none() {
        eprintln!("mauvely-browser-host: XDG_RUNTIME_DIR is not an absolute path");
    }
    let broker = socket.as_ref().map(|s| s as &dyn Broker);
    match serve(
        &mut std::io::stdin().lock(),
        &mut std::io::stdout().lock(),
        broker,
    ) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mauvely-browser-host: {e}");
            ExitCode::FAILURE
        }
    }
}
