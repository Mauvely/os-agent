//! The login service (brief 26, Mauvely OS milestone 2): signing in at the
//! computer with a Mauvely account. `pam_mauvely` asks it, over
//! `/run/mauvely/auth.sock`, and it owns the rest: the KDF, the online check
//! through website-devices' login door, the offline cache, the person's
//! userdb records and home, and handing their `os` session to
//! `mauvely-session`. `docs/login.md` has the protocol and the rules.
//!
//! | Module | Holds |
//! |---|---|
//! | `wire` | The protocol: requests, answers, refusal reasons and their sentences |
//! | `socket` | The socket, `SO_PEERCRED`, the limits, a thread per connection |
//! | `service` | What `auth`, `code` and `account` do: the rules, over the traits below |
//! | `people` | `desired.people`: the device's say, and the greeter's file |
//! | `names` | Usernames, and the machine's own accounts through NSS |
//! | `door` | website-devices' login door and website-main's KDF upgrade |
//! | `kdf` | Argon2id: the `authSecret`, and the cache's verifier |
//! | `cache` | The offline cache, sealed per person |
//! | `userdb` | `/etc/userdb` drop-ins |
//! | `handoff` | `/run/mauvely/login/<uid>` |

pub mod cache;
pub mod door;
pub mod handoff;
pub mod kdf;
pub mod names;
pub mod people;
pub mod service;
pub mod socket;
pub mod userdb;
pub mod wire;

use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use ed25519_dalek::SigningKey;
use zeroize::Zeroizing;

use crate::Error;
use crate::creds::{Creds, SystemdCreds};
use crate::state::{self, Device, Paths};

/// `mauvelyd login`: the login service, in a process and a unit of its own
/// (`dist/mauvely-login.service`), so it is there before the login screen
/// and never waits for the network, as the agent's check-ins do. Binds the
/// socket and serves it until the process ends.
pub fn serve(paths: &Paths, tpm2: bool) -> Result<(), Error> {
    let login = LoginPaths::new(paths);
    let listener = socket::bind(&login.socket)?;
    if let Err(e) = handoff::prepare(&login.handoff) {
        eprintln!("login: {e}");
    }
    let service = Arc::new(service::Service {
        hand_over: Box::new(service::RunDir {
            dir: login.handoff.clone(),
            staging: login.staging.clone(),
        }),
        paths: login,
        sealer: Box::new(SystemdCreds { tpm2 }),
        names: Box::new(names::Nss),
        home: Box::new(service::SystemdHome),
        door: server(paths.clone(), SystemdCreds { tpm2 }),
        clock: Box::new(crate::api::now),
        delay: Box::new(std::thread::sleep),
    });
    eprintln!(
        "login: listening on {}",
        paths.run_dir.join("auth.sock").display()
    );
    socket::serve(listener, service);
    Ok(())
}

/// The server, as this device: loaded at the first online sign-in that
/// finds the device enrolled, then kept. Before enrolment, `None`.
fn server(paths: Paths, creds: SystemdCreds) -> service::DoorSlot {
    let loaded: OnceLock<Arc<dyn door::Door>> = OnceLock::new();
    Box::new(move || {
        if let Some(d) = loaded.get() {
            return Some(Arc::clone(d));
        }
        match load(&paths, &creds) {
            Ok(d) => Some(Arc::clone(loaded.get_or_init(|| d))),
            Err(e) => {
                eprintln!("login: the server can't be asked: {e}");
                None
            }
        }
    })
}

/// The device's server, id and key, as the agent left them.
fn load(paths: &Paths, creds: &dyn Creds) -> Result<Arc<dyn door::Door>, Error> {
    let server = state::read_server(paths)?;
    let device = state::read_json::<Device>(&paths.device())?
        .ok_or_else(|| Error::Invalid("not enrolled".into()))?;
    let path = paths.key();
    let sealed = std::fs::read(&path).map_err(|e| Error::io(&path, e))?;
    let seed = Zeroizing::new(creds.unseal(&sealed)?);
    let seed: [u8; 32] = seed[..]
        .try_into()
        .map_err(|_| Error::Invalid(format!("{}: not a 32-byte seed", path.display())))?;
    Ok(Arc::new(door::Devices::new(
        &server,
        &device.device_id,
        SigningKey::from_bytes(&seed),
    )))
}

/// Where the login service keeps things.
#[derive(Debug, Clone)]
pub struct LoginPaths {
    /// `/run/mauvely/auth.sock`.
    pub socket: PathBuf,
    /// `/run/mauvely/login`, the hand-off directory.
    pub handoff: PathBuf,
    /// `/run/mauvely`, root's alone, where a hand-off is staged.
    pub staging: PathBuf,
    /// `/var/lib/mauvely/people.json`: `desired.people` as last received.
    pub people: PathBuf,
    /// `/var/lib/mauvely/people/`: the offline cache.
    pub cache: PathBuf,
    /// `/var/lib/mauvely-desktop/people.json`: the login screen's part.
    pub greeter: PathBuf,
    /// `/etc/userdb`.
    pub userdb: PathBuf,
}

impl LoginPaths {
    /// Beside the agent's own files.
    pub fn new(paths: &Paths) -> Self {
        LoginPaths {
            socket: paths.run_dir.join("auth.sock"),
            handoff: paths.run_dir.join("login"),
            staging: paths.run_dir.clone(),
            people: paths.state_dir.join("people.json"),
            cache: paths.state_dir.join("people"),
            greeter: paths.desktop_dir.join("people.json"),
            userdb: paths.userdb_dir.clone(),
        }
    }
}

#[cfg(test)]
pub mod testing {
    use super::*;
    use crate::fake::TempDir;

    /// Every path under `dir`.
    pub fn paths(dir: &TempDir) -> LoginPaths {
        let paths = Paths {
            config_dir: dir.path().join("etc"),
            state_dir: dir.path().join("state"),
            run_dir: dir.path().join("run"),
            desktop_dir: dir.path().join("desktop"),
            userdb_dir: dir.path().join("userdb"),
        };
        std::fs::create_dir_all(&paths.run_dir).unwrap();
        LoginPaths::new(&paths)
    }

    #[test]
    fn the_server_is_loaded_once_the_device_is_enrolled() {
        use crate::fake::FakeCreds;
        let dir = TempDir::new();
        let paths = Paths {
            config_dir: dir.path().join("etc"),
            state_dir: dir.path().join("state"),
            run_dir: dir.path().join("run"),
            desktop_dir: dir.path().join("desktop"),
            userdb_dir: dir.path().join("userdb"),
        };
        std::fs::create_dir_all(&paths.config_dir).unwrap();
        std::fs::write(paths.server(), "https://devices.mauvely.com\n").unwrap();
        // Not enrolled yet.
        assert!(load(&paths, &FakeCreds).is_err());
        state::write_private(&paths.key(), &FakeCreds.seal(&[9; 32]).unwrap()).unwrap();
        state::write_json(
            &paths.device(),
            &Device {
                device_id: "dev_1".into(),
                org_slug: "suez".into(),
            },
        )
        .unwrap();
        let door = load(&paths, &FakeCreds).unwrap();
        assert_eq!(door.accounts(), Some("https://mauvely.com"));
        // A key that is not 32 bytes is refused.
        state::write_private(&paths.key(), &FakeCreds.seal(&[9; 31]).unwrap()).unwrap();
        assert!(load(&paths, &FakeCreds).is_err());
    }

    #[test]
    fn the_unit_comes_before_the_login_screen_and_not_after_the_network() {
        let unit = include_str!("../../../../dist/mauvely-login.service");
        let has = |line: &str| unit.lines().any(|l| l == line);
        for line in [
            "ExecStart=/usr/bin/mauvelyd login",
            "Before=display-manager.service",
            "RuntimeDirectory=mauvely",
            "RuntimeDirectoryMode=0755",
            "RuntimeDirectoryPreserve=yes",
            "StateDirectory=mauvely",
            "StateDirectoryMode=0700",
        ] {
            assert!(has(line), "{line} is not in the unit");
        }
        assert!(
            unit.lines()
                .filter(|l| !l.starts_with('#'))
                .all(|l| !l.contains("network-online")),
            "it waits for the network"
        );
        // The agent's unit agrees on the two directories they share.
        let agent = include_str!("../../../../dist/mauvelyd.service");
        for line in [
            "RuntimeDirectoryMode=0755",
            "RuntimeDirectoryPreserve=yes",
            "StateDirectoryMode=0700",
        ] {
            assert!(
                agent.lines().any(|l| l == line),
                "{line} is not in mauvelyd.service"
            );
        }
    }

    #[test]
    fn the_paths_are_the_briefs() {
        let paths = Paths {
            config_dir: "/etc/mauvely".into(),
            state_dir: "/var/lib/mauvely".into(),
            run_dir: "/run/mauvely".into(),
            desktop_dir: "/var/lib/mauvely-desktop".into(),
            userdb_dir: "/etc/userdb".into(),
        };
        let p = LoginPaths::new(&paths);
        assert_eq!(p.socket, PathBuf::from("/run/mauvely/auth.sock"));
        assert_eq!(p.handoff, PathBuf::from("/run/mauvely/login"));
        assert_eq!(p.people, PathBuf::from("/var/lib/mauvely/people.json"));
        assert_eq!(p.cache, PathBuf::from("/var/lib/mauvely/people"));
        assert_eq!(
            p.greeter,
            PathBuf::from("/var/lib/mauvely-desktop/people.json")
        );
        assert_eq!(p.userdb, PathBuf::from("/etc/userdb"));
    }
}
