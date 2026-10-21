//! Configuration in `/etc/mauvely`, state in `/var/lib/mauvely`, and what the
//! people logged in may read in `/run/mauvely`.
//!
//! The directories can be moved with `MAUVELY_CONFIG_DIR`, `MAUVELY_STATE_DIR`
//! and `MAUVELY_RUN_DIR`, which is how tests run without root.

use std::fs::{self, OpenOptions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize, de::DeserializeOwned};

use crate::Error;
use crate::flatpak::App;

#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub state_dir: PathBuf,
    /// `/run/mauvely`, which `dist/mauvelyd.service` makes `0755`. Its files
    /// are root's, and everyone's to read.
    pub run_dir: PathBuf,
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
            run_dir: dir("MAUVELY_RUN_DIR", "/run/mauvely"),
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

    /// The apps installed since boot, for mauvely-session to say are ready.
    pub fn installed(&self) -> PathBuf {
        self.run_dir.join("installed.json")
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
    /// The browsers granted mauvely-session's broker socket.
    #[serde(default)]
    pub granted: Vec<String>,
}

/// An app the agent installed, and when, in Unix seconds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Install {
    pub id: String,
    pub branch: String,
    pub at: u64,
}

/// `/run/mauvely/installed.json`, oldest first.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Installs {
    pub installs: Vec<Install>,
}

/// The file holds this many installs, the last ones.
pub const MAX_INSTALLS: usize = 50;

/// Adds `apps`, installed at `now`, to `installed.json`, and keeps the last
/// `MAX_INSTALLS`. A file that does not parse is replaced: it holds nothing
/// but a courtesy.
pub fn record_installs(paths: &Paths, apps: &[App], now: u64) -> Result<(), Error> {
    if apps.is_empty() {
        return Ok(());
    }
    let mut file = read_json::<Installs>(&paths.installed())
        .ok()
        .flatten()
        .unwrap_or_default();
    file.installs.extend(apps.iter().map(|a| Install {
        id: a.id.clone(),
        branch: a.branch.clone(),
        at: now,
    }));
    let extra = file.installs.len().saturating_sub(MAX_INSTALLS);
    file.installs.drain(..extra);
    let mut bytes = serde_json::to_vec(&file)
        .map_err(|e| Error::json(paths.installed().display().to_string(), e))?;
    bytes.push(b'\n');
    write_atomic(&paths.installed(), &bytes, 0o644)
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
    write_atomic(path, bytes, 0o600)
}

/// Writes `bytes` to `path` atomically, with exactly `mode` whatever the
/// umask.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) -> Result<(), Error> {
    let dir = path.parent().unwrap_or(Path::new("."));
    fs::create_dir_all(dir).map_err(|e| Error::io(dir, e))?;
    let mut tmp = path.as_os_str().to_owned();
    tmp.push(".tmp");
    let tmp = PathBuf::from(tmp);
    let _ = fs::remove_file(&tmp);
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .open(&tmp)
        .map_err(|e| Error::io(&tmp, e))?;
    f.set_permissions(fs::Permissions::from_mode(mode))
        .and_then(|_| f.write_all(bytes))
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
            run_dir: dir.path().join("run"),
        }
    }

    fn app(id: &str) -> App {
        App {
            id: id.into(),
            branch: "stable".into(),
            remote: "flathub".into(),
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

    fn install(id: &str, at: u64) -> Install {
        Install {
            id: id.into(),
            branch: "stable".into(),
            at,
        }
    }

    fn recorded(p: &Paths) -> Vec<Install> {
        read_json::<Installs>(&p.installed())
            .unwrap()
            .unwrap()
            .installs
    }

    #[test]
    fn installs_are_recorded_for_everyone_to_read_and_atomically() {
        let dir = TempDir::new();
        let p = paths(&dir);
        record_installs(
            &p,
            &[app("com.mauvely.compose"), app("org.mozilla.firefox")],
            100,
        )
        .unwrap();

        // Exactly the shape mauvely-session reads.
        let text = fs::read_to_string(p.installed()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            value,
            serde_json::json!({ "installs": [
                { "id": "com.mauvely.compose", "branch": "stable", "at": 100 },
                { "id": "org.mozilla.firefox", "branch": "stable", "at": 100 },
            ]})
        );
        // Readable by the people who are not root, and by nobody to write.
        let mode = fs::metadata(p.installed()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o644);
        assert!(!p.run_dir.join("installed.json.tmp").exists());

        // Later installs are added after them.
        record_installs(&p, &[app("org.kde.kate")], 200).unwrap();
        assert_eq!(
            recorded(&p),
            [
                install("com.mauvely.compose", 100),
                install("org.mozilla.firefox", 100),
                install("org.kde.kate", 200)
            ]
        );
    }

    #[test]
    fn only_the_last_fifty_installs_are_kept() {
        let dir = TempDir::new();
        let p = paths(&dir);
        for i in 0..60 {
            record_installs(&p, &[app(&format!("org.example.App{i:02}"))], 1000 + i).unwrap();
        }
        let kept = recorded(&p);
        assert_eq!(kept.len(), MAX_INSTALLS);
        assert_eq!(MAX_INSTALLS, 50);
        assert_eq!(kept[0], install("org.example.App10", 1010));
        assert_eq!(kept[49], install("org.example.App59", 1059));

        // One call with more than fifty keeps the last fifty of them too.
        let many: Vec<App> = (0..70)
            .map(|i| app(&format!("org.example.B{i:02}")))
            .collect();
        record_installs(&p, &many, 2000).unwrap();
        let kept = recorded(&p);
        assert_eq!(kept.len(), 50);
        assert_eq!(kept[0].id, "org.example.B20");
        assert_eq!(kept[49].id, "org.example.B69");
    }

    #[test]
    fn nothing_installed_writes_nothing_and_a_garbled_file_is_replaced() {
        let dir = TempDir::new();
        let p = paths(&dir);
        record_installs(&p, &[], 100).unwrap();
        assert!(!p.run_dir.exists());

        fs::create_dir_all(&p.run_dir).unwrap();
        fs::write(p.installed(), "{ not json").unwrap();
        record_installs(&p, &[app("org.kde.kate")], 100).unwrap();
        assert_eq!(recorded(&p), [install("org.kde.kate", 100)]);
    }

    #[test]
    fn the_unit_gives_the_agent_a_run_directory_everyone_can_read_that_stays() {
        // Without the mode the people who are not root cannot open the file;
        // without Preserve, a restart of the agent empties it.
        let unit = include_str!("../../../dist/mauvelyd.service");
        for line in [
            "RuntimeDirectory=mauvely",
            "RuntimeDirectoryMode=0755",
            "RuntimeDirectoryPreserve=yes",
        ] {
            assert!(unit.lines().any(|l| l == line), "{line} is not in the unit");
        }
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
