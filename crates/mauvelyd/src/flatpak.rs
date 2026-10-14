//! System Flatpak installs. Every command carries `--system`, so a user's own
//! `--user` installs are never listed and never touched.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::command::{argv, operand, run};

/// An installed app, or one the agent installed. `remote` is the origin.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct App {
    pub id: String,
    pub branch: String,
    pub remote: String,
}

impl App {
    pub fn is(&self, id: &str, branch: &str) -> bool {
        self.id == id && self.branch == branch
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Remote {
    pub name: String,
    pub url: String,
}

pub trait Flatpak {
    /// System-wide apps (not runtimes).
    fn installed(&self) -> Result<Vec<App>, Error>;
    /// System-wide remotes, disabled ones included.
    fn remotes(&self) -> Result<Vec<Remote>, Error>;
    /// `gpg_key` is the binary public key.
    fn remote_add(&self, name: &str, url: &str, gpg_key: &[u8]) -> Result<(), Error>;
    fn remote_modify(&self, name: &str, url: &str, gpg_key: &[u8]) -> Result<(), Error>;
    fn remote_delete(&self, name: &str) -> Result<(), Error>;
    fn install(&self, remote: &str, id: &str, branch: &str) -> Result<(), Error>;
    fn uninstall(&self, id: &str, branch: &str) -> Result<(), Error>;
}

/// The real `flatpak` CLI.
pub struct SystemFlatpak;

impl Flatpak for SystemFlatpak {
    fn installed(&self) -> Result<Vec<App>, Error> {
        parse_installed(&run(&list_argv(), None)?)
    }

    fn remotes(&self) -> Result<Vec<Remote>, Error> {
        parse_remotes(&run(&remotes_argv(), None)?)
    }

    fn remote_add(&self, name: &str, url: &str, gpg_key: &[u8]) -> Result<(), Error> {
        let key = KeyFile::write(gpg_key)?;
        run(&remote_add_argv(name, url, &key.path)?, None).map(drop)
    }

    fn remote_modify(&self, name: &str, url: &str, gpg_key: &[u8]) -> Result<(), Error> {
        let key = KeyFile::write(gpg_key)?;
        run(&remote_modify_argv(name, url, &key.path)?, None).map(drop)
    }

    fn remote_delete(&self, name: &str) -> Result<(), Error> {
        run(&remote_delete_argv(name)?, None).map(drop)
    }

    fn install(&self, remote: &str, id: &str, branch: &str) -> Result<(), Error> {
        run(&install_argv(remote, id, branch)?, None).map(drop)
    }

    fn uninstall(&self, id: &str, branch: &str) -> Result<(), Error> {
        run(&uninstall_argv(id, branch)?, None).map(drop)
    }
}

pub(crate) fn list_argv() -> Vec<String> {
    argv(&[
        "flatpak",
        "list",
        "--system",
        "--app",
        "--columns=application,branch,origin",
    ])
}

pub(crate) fn remotes_argv() -> Vec<String> {
    argv(&[
        "flatpak",
        "remotes",
        "--system",
        "--show-disabled",
        "--columns=name,url",
    ])
}

pub(crate) fn remote_add_argv(
    name: &str,
    url: &str,
    key: &std::path::Path,
) -> Result<Vec<String>, Error> {
    operand("remote", name)?;
    operand("remote URL", url)?;
    Ok(vec![
        "flatpak".into(),
        "remote-add".into(),
        "--system".into(),
        "--if-not-exists".into(),
        format!("--gpg-import={}", key.display()),
        name.into(),
        url.into(),
    ])
}

pub(crate) fn remote_modify_argv(
    name: &str,
    url: &str,
    key: &std::path::Path,
) -> Result<Vec<String>, Error> {
    operand("remote", name)?;
    operand("remote URL", url)?;
    // A remote the server lists is one it means to use, so a disabled one
    // already on the machine is enabled.
    Ok(vec![
        "flatpak".into(),
        "remote-modify".into(),
        "--system".into(),
        "--enable".into(),
        format!("--url={url}"),
        format!("--gpg-import={}", key.display()),
        name.into(),
    ])
}

pub(crate) fn remote_delete_argv(name: &str) -> Result<Vec<String>, Error> {
    operand("remote", name)?;
    Ok(argv(&["flatpak", "remote-delete", "--system", name]))
}

pub(crate) fn install_argv(remote: &str, id: &str, branch: &str) -> Result<Vec<String>, Error> {
    operand("remote", remote)?;
    let r = app_ref(id, branch)?;
    Ok(argv(&[
        "flatpak",
        "install",
        "--system",
        "-y",
        "--noninteractive",
        remote,
        &r,
    ]))
}

pub(crate) fn uninstall_argv(id: &str, branch: &str) -> Result<Vec<String>, Error> {
    let r = app_ref(id, branch)?;
    Ok(argv(&[
        "flatpak",
        "uninstall",
        "--system",
        "-y",
        "--noninteractive",
        &r,
    ]))
}

/// `id//branch`, the partial ref `flatpak install` and `uninstall` take.
fn app_ref(id: &str, branch: &str) -> Result<String, Error> {
    operand("app", id)?;
    operand("branch", branch)?;
    if id.contains('/') || branch.contains('/') {
        return Err(Error::Invalid(format!(
            "app {id:?} branch {branch:?} is not valid"
        )));
    }
    Ok(format!("{id}//{branch}"))
}

/// `flatpak list --columns=…` prints one tab-separated row per app, and no
/// header when stdout is not a terminal.
pub(crate) fn parse_installed(stdout: &[u8]) -> Result<Vec<App>, Error> {
    rows(stdout, 3)?
        .into_iter()
        .map(|f| {
            Ok(App {
                id: f[0].into(),
                branch: f[1].into(),
                remote: f[2].into(),
            })
        })
        .collect()
}

pub(crate) fn parse_remotes(stdout: &[u8]) -> Result<Vec<Remote>, Error> {
    rows(stdout, 2)?
        .into_iter()
        .map(|f| {
            Ok(Remote {
                name: f[0].into(),
                url: f[1].into(),
            })
        })
        .collect()
}

fn rows(stdout: &[u8], columns: usize) -> Result<Vec<Vec<&str>>, Error> {
    let text = std::str::from_utf8(stdout)
        .map_err(|_| Error::Invalid("flatpak printed invalid UTF-8".into()))?;
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| {
            let f: Vec<&str> = l.split('\t').map(str::trim).collect();
            if f.len() == columns {
                Ok(f)
            } else {
                Err(Error::Invalid(format!("unexpected flatpak output: {l:?}")))
            }
        })
        .collect()
}

/// The GPG key, written to a private temporary file for `--gpg-import` and
/// removed when dropped.
struct KeyFile {
    path: PathBuf,
}

impl KeyFile {
    fn write(key: &[u8]) -> Result<Self, Error> {
        let suffix: u64 = rand::random();
        let path =
            std::env::temp_dir().join(format!("mauvelyd-{}-{suffix:016x}.gpg", std::process::id()));
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|e| Error::io(&path, e))?;
        let file = KeyFile { path };
        f.write_all(key).map_err(|e| Error::io(&file.path, e))?;
        Ok(file)
    }
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn every_command_is_system_wide() {
        let key = Path::new("/tmp/k.gpg");
        let all = [
            list_argv(),
            remotes_argv(),
            remote_add_argv("mauvely", "https://flatpak.mauvely.com/repo", key).unwrap(),
            remote_modify_argv("mauvely", "https://flatpak.mauvely.com/repo", key).unwrap(),
            remote_delete_argv("mauvely").unwrap(),
            install_argv("flathub", "org.mozilla.firefox", "stable").unwrap(),
            uninstall_argv("org.mozilla.firefox", "stable").unwrap(),
        ];
        for a in &all {
            assert_eq!(a[0], "flatpak");
            assert!(a.iter().any(|s| s == "--system"), "{a:?}");
            assert!(!a.iter().any(|s| s == "--user"), "{a:?}");
        }
    }

    #[test]
    fn argv_shapes() {
        assert_eq!(
            install_argv("mauvely", "com.mauvely.compose", "stable").unwrap(),
            [
                "flatpak",
                "install",
                "--system",
                "-y",
                "--noninteractive",
                "mauvely",
                "com.mauvely.compose//stable"
            ]
        );
        assert_eq!(
            uninstall_argv("org.mozilla.firefox", "stable").unwrap(),
            [
                "flatpak",
                "uninstall",
                "--system",
                "-y",
                "--noninteractive",
                "org.mozilla.firefox//stable"
            ]
        );
        assert_eq!(
            remote_add_argv(
                "flathub",
                "https://dl.flathub.org/repo/",
                Path::new("/tmp/k")
            )
            .unwrap(),
            [
                "flatpak",
                "remote-add",
                "--system",
                "--if-not-exists",
                "--gpg-import=/tmp/k",
                "flathub",
                "https://dl.flathub.org/repo/"
            ]
        );
        assert_eq!(
            remote_modify_argv(
                "flathub",
                "https://dl.flathub.org/repo/",
                Path::new("/tmp/k")
            )
            .unwrap(),
            [
                "flatpak",
                "remote-modify",
                "--system",
                "--enable",
                "--url=https://dl.flathub.org/repo/",
                "--gpg-import=/tmp/k",
                "flathub"
            ]
        );
    }

    #[test]
    fn server_values_cannot_become_options() {
        assert!(install_argv("--no-deps", "a.b", "stable").is_err());
        assert!(install_argv("flathub", "-a.b", "stable").is_err());
        assert!(install_argv("flathub", "a.b", "x/y").is_err());
        assert!(uninstall_argv("a.b", "").is_err());
        assert!(remote_delete_argv("--force").is_err());
    }

    #[test]
    fn parses_list_output() {
        let out = b"org.mozilla.firefox\tstable\tflathub\ncom.mauvely.compose\tstable\tmauvely\n";
        let apps = parse_installed(out).unwrap();
        assert_eq!(apps.len(), 2);
        assert_eq!(
            apps[1],
            App {
                id: "com.mauvely.compose".into(),
                branch: "stable".into(),
                remote: "mauvely".into()
            }
        );
        assert!(parse_installed(b"").unwrap().is_empty());
        assert!(parse_installed(b"just-one-column\n").is_err());
    }

    #[test]
    fn parses_remotes_output() {
        let r = parse_remotes(b"flathub\thttps://dl.flathub.org/repo/\n").unwrap();
        assert_eq!(
            r,
            [Remote {
                name: "flathub".into(),
                url: "https://dl.flathub.org/repo/".into()
            }]
        );
    }

    #[test]
    fn key_file_is_private_and_removed() {
        use std::os::unix::fs::PermissionsExt;
        let path = {
            let k = KeyFile::write(b"key").unwrap();
            let meta = fs::metadata(&k.path).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o600);
            assert_eq!(fs::read(&k.path).unwrap(), b"key");
            k.path.clone()
        };
        assert!(!path.exists());
    }
}
