//! Configuration in `/etc/mauvely`, state in `/var/lib/mauvely`.
//!
//! Both directories can be moved with `MAUVELY_CONFIG_DIR` and
//! `MAUVELY_STATE_DIR`, which is how tests run without root.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::Error;
use crate::flatpak::App;

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
}

impl Paths {
    pub fn from_env() -> Self {
        let dir = |var: &str, default: &str| {
            std::env::var_os(var)
                .filter(|v| !v.is_empty())
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(default))
        };
        Paths {
            config_dir: dir("MAUVELY_CONFIG_DIR", "/etc/mauvely"),
            state_dir: dir("MAUVELY_STATE_DIR", "/var/lib/mauvely"),
        }
    }

    /// The server's base URL.
    pub fn server(&self) -> PathBuf {
        self.config_dir.join("server")
    }

    /// The enrolment token, deleted once enrolment succeeds.
    pub fn enrol(&self) -> PathBuf {
        self.config_dir.join("enrol")
    }

    pub fn device(&self) -> PathBuf {
        self.state_dir.join("device.json")
    }

    /// The sealed 32-byte seed.
    pub fn key(&self) -> PathBuf {
        self.state_dir.join("key.cred")
    }

    pub fn managed(&self) -> PathBuf {
        self.state_dir.join("managed.json")
    }

    /// When the last check-in succeeded, for `mauvelyd status`.
    pub fn status(&self) -> PathBuf {
        self.state_dir.join("status.json")
    }
}

/// Who this device is, from the enrolment answer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub device_id: String,
    pub org_slug: String,
}

/// What the agent itself installed or added: the only apps it removes when
/// they are unlisted, and the only remotes it ever deletes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Managed {
    pub apps: Vec<App>,
    pub remotes: Vec<ManagedRemote>,
    /// When system Flatpaks were last updated without an error, in Unix
    /// seconds. 0 is never, as in a file written before updates existed.
    #[serde(default)]
    pub flatpaks_updated: u64,
}

/// A remote the agent has configured.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedRemote {
    pub name: String,
    /// True when the agent added it, rather than updating one already there.
    /// Only these are deleted.
    pub added: bool,
    /// SHA-256 of the URL and key last applied, so an unchanged remote is
    /// left alone.
    pub applied: String,
}

impl Managed {
    pub fn has_app(&self, id: &str, branch: &str) -> bool {
        self.apps.iter().any(|a| a.is(id, branch))
    }

    pub fn remote(&self, name: &str) -> Option<&ManagedRemote> {
        self.remotes.iter().find(|r| r.name == name)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Status {
    pub last_checkin: u64,
}

/// The base URL, without a trailing slash.
pub fn read_server(paths: &Paths) -> Result<String, Error> {
    let path = paths.server();
    let text = fs::read_to_string(&path).map_err(|e| Error::io(&path, e))?;
    let url = text.trim().trim_end_matches('/');
    if !(url.starts_with("https://") || url.starts_with("http://")) {
        return Err(Error::Invalid(format!(
            "{}: expected an http(s) URL",
            path.display()
        )));
    }
    Ok(url.to_owned())
}

/// The enrolment token, or `None` when there is none.
pub fn read_token(paths: &Paths) -> Result<Option<String>, Error> {
    let path = paths.enrol();
    match fs::read_to_string(&path) {
        Ok(t) if t.trim().is_empty() => Ok(None),
        Ok(t) => Ok(Some(t.trim().to_owned())),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(&path, e)),
    }
}

pub fn delete_token(paths: &Paths) -> Result<(), Error> {
    let path = paths.enrol();
    match fs::remove_file(&path) {
        Err(e) if e.kind() != ErrorKind::NotFound => Err(Error::io(&path, e)),
        _ => Ok(()),
    }
}

/// Reads a JSON file, or `None` when it does not exist.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, Error> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| Error::json(path.display().to_string(), e)),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
        Err(e) => Err(Error::io(path, e)),
    }
}

pub fn write_json<T: Serialize>(path: &Path, value: &T) -> Result<(), Error> {
    let mut bytes =
        serde_json::to_vec_pretty(value).map_err(|e| Error::json(path.display().to_string(), e))?;
    bytes.push(b'\n');
    write_private(path, &bytes)
}

/// Writes `bytes` to `path` atomically, readable by its owner only.
pub fn write_private(path: &Path, bytes: &[u8]) -> Result<(), Error> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(|e| Error::io(&tmp, e))?;
    f.write_all(bytes)
        .and_then(|_| f.sync_all())
        .map_err(|e| Error::io(&tmp, e))?;
    fs::rename(&tmp, path).map_err(|e| Error::io(path, e))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::TempDir;
    use std::os::unix::fs::PermissionsExt;

    fn paths(dir: &TempDir) -> Paths {
        Paths {
            config_dir: dir.path().join("etc"),
            state_dir: dir.path().join("state"),
        }
    }

    #[test]
    fn server_url_is_trimmed() {
        let dir = TempDir::new();
        let p = paths(&dir);
        fs::create_dir_all(&p.config_dir).unwrap();
        fs::write(p.server(), "http://10.0.2.2:8798/\n").unwrap();
        assert_eq!(read_server(&p).unwrap(), "http://10.0.2.2:8798");
        fs::write(p.server(), "devices.mauvely.com\n").unwrap();
        assert!(read_server(&p).is_err());
    }

    #[test]
    fn token_round_trip() {
        let dir = TempDir::new();
        let p = paths(&dir);
        assert_eq!(read_token(&p).unwrap(), None);
        fs::create_dir_all(&p.config_dir).unwrap();
        fs::write(p.enrol(), "mvd_abc\n").unwrap();
        assert_eq!(read_token(&p).unwrap().as_deref(), Some("mvd_abc"));
        delete_token(&p).unwrap();
        assert!(!p.enrol().exists());
        delete_token(&p).unwrap();
    }

    #[test]
    fn json_is_written_privately_and_atomically() {
        let dir = TempDir::new();
        let p = paths(&dir);
        assert_eq!(read_json::<Device>(&p.device()).unwrap(), None);
        let d = Device {
            device_id: "dev_1".into(),
            org_slug: "northgate".into(),
        };
        write_json(&p.device(), &d).unwrap();
        assert_eq!(read_json::<Device>(&p.device()).unwrap(), Some(d));
        let mode = fs::metadata(p.device()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(!p.state_dir.join("device.json.tmp").exists());
    }
}
