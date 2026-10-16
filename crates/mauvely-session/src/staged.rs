//! Whether an update is staged, read from `rpm-ostree status --json`, and
//! the rule that says so once per staged deployment.
//!
//! `deployments` is rpm-ostreed's `Deployments` property. rpm-ostree sets
//! `checksum` and `staged` on every entry (`deployment_populate_variant` in
//! its `rust/src/daemon.rs`), and ostree stages at most one deployment.

use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use serde::Deserialize;

use crate::Error;

#[derive(Deserialize)]
struct Status {
    deployments: Vec<Deployment>,
}

#[derive(Deserialize)]
struct Deployment {
    checksum: String,
    staged: bool,
}

/// The staged deployment's checksum, or `None` when nothing is staged.
pub fn staged(status_json: &[u8]) -> Result<Option<String>, Error> {
    let status: Status = serde_json::from_slice(status_json)?;
    Ok(status
        .deployments
        .into_iter()
        .find(|d| d.staged)
        .map(|d| d.checksum))
}

/// One look at the machine. A staged deployment is announced with `notify`,
/// unless `memory` holds its checksum, and remembered once announced. With
/// nothing staged the memory is cleared, so a deployment discarded and then
/// staged again is announced again.
pub fn check(
    status_json: &[u8],
    memory: &Path,
    notify: &mut dyn FnMut() -> Result<(), Error>,
) -> Result<(), Error> {
    let Some(checksum) = staged(status_json)? else {
        return match fs::remove_file(memory) {
            Err(e) if e.kind() != ErrorKind::NotFound => Err(e.into()),
            _ => Ok(()),
        };
    };
    match fs::read_to_string(memory) {
        Ok(told) if told.trim() == checksum => return Ok(()),
        Err(e) if e.kind() != ErrorKind::NotFound => return Err(e.into()),
        _ => {}
    }
    notify()?;
    if let Some(dir) = memory.parent() {
        fs::create_dir_all(dir)?;
    }
    fs::write(memory, format!("{checksum}\n"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const STAGED: &[u8] = include_bytes!("../fixtures/status-staged.json");
    const BOOTED: &[u8] = include_bytes!("../fixtures/status-booted.json");
    const NEXT: &str = "5b1a4e0c9d7f3a2b8e6c4d1f0a9b8c7d6e5f4a3b2c1d0e9f8a7b6c5d4e3f2a1b";

    #[test]
    fn finds_the_staged_deployment() {
        assert_eq!(staged(STAGED).unwrap().as_deref(), Some(NEXT));
        assert_eq!(staged(BOOTED).unwrap(), None);
        assert!(staged(b"not json").is_err());
        assert!(staged(br#"{"deployments":[{"checksum":"aa"}]}"#).is_err());
    }

    #[test]
    fn says_it_once_per_staged_deployment() {
        let dir = std::env::temp_dir().join(format!(
            "mauvely-session-test-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let memory = dir.join("mauvely/notified");
        let mut told = 0;
        let mut look = |json: &[u8]| {
            check(json, &memory, &mut || {
                told += 1;
                Ok(())
            })
            .unwrap()
        };

        look(BOOTED);
        look(STAGED);
        look(STAGED);
        // Remembered on disk, so a new session does not say it again.
        assert_eq!(fs::read_to_string(&memory).unwrap(), format!("{NEXT}\n"));
        look(STAGED);

        // Discarded, then staged again: said again.
        look(BOOTED);
        assert!(!memory.exists());
        look(STAGED);
        drop(look);
        assert_eq!(told, 2);

        // A notification that failed is tried again next time.
        fs::remove_file(&memory).unwrap();
        let failed = check(
            STAGED,
            &memory,
            &mut || Err("no notification server".into()),
        );
        assert!(failed.is_err());
        assert!(!memory.exists());

        fs::remove_dir_all(&dir).unwrap();
    }
}
