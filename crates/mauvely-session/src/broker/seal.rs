//! The `os` session at rest: sealed with `systemd-creds --user`, in
//! `$XDG_STATE_HOME/mauvely/os.cred`.
//!
//! Unprivileged, `systemd-creds` asks the root `systemd-creds` service over
//! varlink, which always seals a user-scoped credential with its automatic
//! key: the host secret and, where there is one, the TPM, bound to this
//! user's uid and name and the machine id (`vl_method_encrypt` in systemd's
//! `src/creds/creds.c`, v258). `--with-key` cannot change that, and
//! `--with-key=tpm2` alone is refused in user scope, so none is passed.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

use super::accounts::Minted;
use crate::Error;

/// Embedded in the credential; decrypting checks it.
const NAME: &str = "--name=mauvely-os";

pub trait Seal: Send + Sync {
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>, Error>;
    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, Error>;
}

/// The real `systemd-creds`. The session goes in on stdin and comes out on
/// stdout: never an argument, never a file in the clear.
pub struct SystemdCreds;

impl Seal for SystemdCreds {
    fn seal(&self, plain: &[u8]) -> Result<Vec<u8>, Error> {
        run(&seal_argv(), plain)
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, Error> {
        run(&unseal_argv(), sealed)
    }
}

fn seal_argv() -> [&'static str; 6] {
    ["systemd-creds", "--user", "encrypt", NAME, "-", "-"]
}

fn unseal_argv() -> [&'static str; 6] {
    ["systemd-creds", "--user", "decrypt", NAME, "-", "-"]
}

/// Runs `argv` with `input` on stdin and returns stdout. A failure carries
/// stderr, which for `systemd-creds` never holds the secret.
fn run(argv: &[&str], input: &[u8]) -> Result<Vec<u8>, Error> {
    let (program, args) = argv.split_first().expect("argv is never empty");
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("{program}: {e}"))?;
    // A few kilobytes at most, well under a pipe buffer, so writing all of
    // it before reading cannot deadlock.
    let mut stdin = child.stdin.take().expect("stdin is piped");
    stdin
        .write_all(input)
        .map_err(|e| format!("{program}: {e}"))?;
    drop(stdin);
    let out = child
        .wait_with_output()
        .map_err(|e| format!("{program}: {e}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        return Err(format!("{program}: {}: {}", out.status, stderr.trim()).into());
    }
    Ok(out.stdout)
}

/// The `os` session. Sealed whole, so its expiry and address are not
/// readable from the file either.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsSession {
    pub token: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: u64,
    pub email: String,
}

impl From<Minted> for OsSession {
    fn from(m: Minted) -> Self {
        OsSession {
            token: m.token,
            expires_at: m.expires_at,
            email: m.email,
        }
    }
}

impl std::fmt::Debug for OsSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OsSession")
            .field("token", &"<redacted>")
            .field("expires_at", &self.expires_at)
            .field("email", &self.email)
            .finish()
    }
}

pub struct Store {
    path: PathBuf,
    seal: Box<dyn Seal>,
}

impl Store {
    pub fn new(path: PathBuf, seal: Box<dyn Seal>) -> Self {
        Store { path, seal }
    }

    /// The stored session, or `None` when there is none.
    pub fn load(&self) -> Result<Option<OsSession>, Error> {
        let sealed = match fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("{}: {e}", self.path.display()).into()),
        };
        let plain = self.seal.unseal(&sealed)?;
        let session = serde_json::from_slice(&plain)
            .map_err(|e| format!("{}: not a session: {e}", self.path.display()))?;
        Ok(Some(session))
    }

    pub fn save(&self, session: &OsSession) -> Result<(), Error> {
        let plain = serde_json::to_vec(session)?;
        let sealed = self.seal.seal(&plain)?;
        write_private(&self.path, &sealed)
    }

    pub fn forget(&self) -> Result<(), Error> {
        match fs::remove_file(&self.path) {
            Err(e) if e.kind() != ErrorKind::NotFound => {
                Err(format!("{}: {e}", self.path.display()).into())
            }
            _ => Ok(()),
        }
    }
}

/// Writes `bytes` to `path` atomically, readable by its owner only, in a
/// directory only its owner can enter.
fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp);
    let failed = |e: std::io::Error| format!("{}: {e}", tmp.display());
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(failed)?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(failed)?;
    fs::rename(&tmp, path).map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(())
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// Reversible, and visibly not the plain text.
    pub struct FakeSeal;

    const SEALED: &[u8] = b"sealed:";

    impl Seal for FakeSeal {
        fn seal(&self, plain: &[u8]) -> Result<Vec<u8>, Error> {
            Ok([SEALED, &plain.iter().map(|b| b ^ 0xa5).collect::<Vec<_>>()].concat())
        }

        fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, Error> {
            let body = sealed.strip_prefix(SEALED).ok_or("bad credential")?;
            Ok(body.iter().map(|b| b ^ 0xa5).collect())
        }
    }

    pub fn temp_dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU32, Ordering};
        static N: AtomicU32 = AtomicU32::new(0);
        let dir = std::env::temp_dir().join(format!(
            "mauvely-session-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    #[test]
    fn the_session_travels_on_stdin_only() {
        assert_eq!(
            seal_argv(),
            [
                "systemd-creds",
                "--user",
                "encrypt",
                "--name=mauvely-os",
                "-",
                "-"
            ]
        );
        assert_eq!(
            unseal_argv(),
            [
                "systemd-creds",
                "--user",
                "decrypt",
                "--name=mauvely-os",
                "-",
                "-"
            ]
        );
        // `run` feeds stdin and reports failure.
        assert_eq!(run(&["cat"], b"secret").unwrap(), b"secret");
        let err = run(&["sh", "-c", "echo oops >&2; exit 3"], b"").unwrap_err();
        assert!(err.to_string().contains("oops"), "{err}");
        assert!(run(&["/nonexistent/systemd-creds"], b"").is_err());
    }

    #[test]
    fn stores_sealed_and_private() {
        let dir = temp_dir("store");
        let store = Store::new(dir.join("mauvely/os.cred"), Box::new(FakeSeal));
        assert_eq!(store.load().unwrap(), None);
        let session = OsSession {
            token: "tok_os".into(),
            expires_at: 1_771_200_000,
            email: "ada@example.com".into(),
        };
        store.save(&session).unwrap();
        assert_eq!(store.load().unwrap(), Some(session.clone()));

        let raw = fs::read(&store.path).unwrap();
        assert!(raw.starts_with(SEALED));
        assert!(!raw.windows(6).any(|w| w == b"tok_os"));
        let mode = |p: &Path| fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&store.path), 0o600);
        assert_eq!(mode(store.path.parent().unwrap()), 0o700);
        assert!(!format!("{session:?}").contains("tok_os"));

        store.forget().unwrap();
        assert_eq!(store.load().unwrap(), None);
        store.forget().unwrap();

        // A file that does not unseal is an error, not "no session".
        fs::write(&store.path, b"garbage").unwrap();
        assert!(store.load().is_err());
        fs::remove_dir_all(&dir).unwrap();
    }
}
