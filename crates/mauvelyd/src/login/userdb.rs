//! People as systemd userdb drop-ins in `/etc/userdb` (brief 26, spike 3):
//! nss-systemd serves them to every program, with nothing of ours running.
//!
//! For `timur`, uid and gid 21001:
//!
//! | File | What |
//! |---|---|
//! | `timur.user` | The user record, `0644` |
//! | `21001.user` | A symlink to it, for lookups by uid |
//! | `timur.group` | The person's own group, `0644` |
//! | `21001.group` | A symlink to it |
//! | `timur:timur.membership` | `{}`: the primary group, which nss-systemd(8) asks for |
//! | `timur:wheel.membership` | `{}`, exactly while they are a device admin |
//!
//! Each is written to a `.tmp` name and renamed, and only when it differs
//! from what is there. A record is ours when its `service` is `SERVICE`;
//! nothing here touches a record that is not.

use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Error;
use crate::state::write_atomic;

/// Marks a record as mauvelyd's.
pub const SERVICE: &str = "com.mauvely.Users";
/// The group device admins join, for sudo and polkit.
pub const ADMIN_GROUP: &str = "wheel";

/// A person, as the records hold them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Person {
    pub username: String,
    /// The uid, and the gid of their own group.
    pub uid: u32,
    pub real_name: String,
    pub device_admin: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UserRecord {
    user_name: String,
    uid: u32,
    gid: u32,
    disposition: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    real_name: String,
    home_directory: String,
    shell: String,
    #[serde(default)]
    service: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GroupRecord<'a> {
    group_name: &'a str,
    gid: u32,
    disposition: &'a str,
    service: &'a str,
}

/// `realName` may not hold a control character or a colon (it becomes a
/// GECOS field), and is cut at 120 characters.
fn real_name(name: &str) -> String {
    name.chars()
        .filter(|c| !c.is_control() && *c != ':')
        .take(120)
        .collect::<String>()
        .trim()
        .to_owned()
}

/// The user record's exact bytes.
pub fn user_json(p: &Person) -> Vec<u8> {
    let record = UserRecord {
        user_name: p.username.clone(),
        uid: p.uid,
        gid: p.uid,
        disposition: "regular".into(),
        real_name: real_name(&p.real_name),
        home_directory: format!("/home/{}", p.username),
        shell: "/bin/bash".into(),
        service: SERVICE.into(),
    };
    let mut bytes = serde_json::to_vec(&record).expect("a record always serialises");
    bytes.push(b'\n');
    bytes
}

/// The group record's exact bytes.
pub fn group_json(p: &Person) -> Vec<u8> {
    let record = GroupRecord {
        group_name: &p.username,
        gid: p.uid,
        disposition: "regular",
        service: SERVICE,
    };
    let mut bytes = serde_json::to_vec(&record).expect("a record always serialises");
    bytes.push(b'\n');
    bytes
}

const MEMBERSHIP: &[u8] = b"{}\n";

fn user_file(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.user"))
}

fn membership(dir: &Path, user: &str, group: &str) -> PathBuf {
    dir.join(format!("{user}:{group}.membership"))
}

/// Our record for `username`: its uid. `None` when there is none, or it is not
/// ours.
pub fn uid_of(dir: &Path, username: &str) -> Option<u32> {
    let bytes = fs::read(user_file(dir, username)).ok()?;
    let record: UserRecord = serde_json::from_slice(&bytes).ok()?;
    (record.service == SERVICE && record.user_name == username).then_some(record.uid)
}

/// The name our `<uid>.user` symlink points at, if it is ours.
pub fn name_of(dir: &Path, uid: u32) -> Option<String> {
    let target = fs::read_link(dir.join(format!("{uid}.user"))).ok()?;
    let name = target.to_str()?.strip_suffix(".user")?.to_owned();
    (uid_of(dir, &name) == Some(uid)).then_some(name)
}

/// Writes the person's records, those that differ. True when anything was
/// written or removed.
pub fn write(dir: &Path, p: &Person) -> Result<bool, Error> {
    let mut changed = false;
    changed |= put(&user_file(dir, &p.username), &user_json(p))?;
    changed |= put(&dir.join(format!("{}.group", p.username)), &group_json(p))?;
    changed |= link(
        dir,
        &format!("{}.user", p.uid),
        &format!("{}.user", p.username),
    )?;
    changed |= link(
        dir,
        &format!("{}.group", p.uid),
        &format!("{}.group", p.username),
    )?;
    changed |= put(&membership(dir, &p.username, &p.username), MEMBERSHIP)?;
    let admin = membership(dir, &p.username, ADMIN_GROUP);
    if p.device_admin {
        changed |= put(&admin, MEMBERSHIP)?;
    } else {
        changed |= remove(&admin)?;
    }
    Ok(changed)
}

/// Takes `username` out of the admin group. True when they were in it.
pub fn drop_admin(dir: &Path, username: &str) -> Result<bool, Error> {
    if uid_of(dir, username).is_none() {
        return Ok(false);
    }
    remove(&membership(dir, username, ADMIN_GROUP))
}

/// Our people in the admin group.
pub fn admins(dir: &Path) -> Vec<String> {
    let suffix = format!(":{ADMIN_GROUP}.membership");
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter_map(|f| f.strip_suffix(&suffix).map(str::to_owned))
        .filter(|name| uid_of(dir, name).is_some())
        .collect();
    names.sort();
    names
}

/// Removes every record of ours for `username`: for a person whose uid now
/// has another name. Records that are not ours are left.
pub fn remove_person(dir: &Path, username: &str) -> Result<(), Error> {
    let Some(uid) = uid_of(dir, username) else {
        return Ok(());
    };
    for kind in ["user", "group"] {
        let path = dir.join(format!("{uid}.{kind}"));
        let target = format!("{username}.{kind}");
        if fs::read_link(&path).ok().as_deref() == Some(Path::new(&target)) {
            remove(&path)?;
        }
    }
    let prefix = format!("{username}:");
    if let Ok(entries) = fs::read_dir(dir) {
        for e in entries.flatten() {
            let file = e.file_name();
            let file = file.to_string_lossy();
            if file.starts_with(&prefix) && file.ends_with(".membership") {
                remove(&e.path())?;
            }
        }
    }
    remove(&dir.join(format!("{username}.group")))?;
    remove(&user_file(dir, username))?;
    Ok(())
}

/// Writes `bytes` to `path` when it holds anything else, `0644`.
fn put(path: &Path, bytes: &[u8]) -> Result<bool, Error> {
    if fs::read(path).ok().as_deref() == Some(bytes) {
        return Ok(false);
    }
    write_atomic(path, bytes, 0o644)?;
    Ok(true)
}

/// Points `dir/name` at `target`, replacing what is there in one rename.
fn link(dir: &Path, name: &str, target: &str) -> Result<bool, Error> {
    let path = dir.join(name);
    if fs::read_link(&path).ok().as_deref() == Some(Path::new(target)) {
        return Ok(false);
    }
    let tmp = dir.join(format!("{name}.tmp"));
    let _ = fs::remove_file(&tmp);
    symlink(target, &tmp).map_err(|e| Error::io(&tmp, e))?;
    fs::rename(&tmp, &path).map_err(|e| Error::io(&path, e))?;
    Ok(true)
}

fn remove(path: &Path) -> Result<bool, Error> {
    match fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == ErrorKind::NotFound => Ok(false),
        Err(e) => Err(Error::io(path, e)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::TempDir;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    fn timur(admin: bool) -> Person {
        Person {
            username: "timur".into(),
            uid: 21001,
            real_name: "Timur Inal".into(),
            device_admin: admin,
        }
    }

    fn files(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn the_records_exact_json() {
        assert_eq!(
            String::from_utf8(user_json(&timur(false))).unwrap(),
            "{\"userName\":\"timur\",\"uid\":21001,\"gid\":21001,\"disposition\":\"regular\",\
             \"realName\":\"Timur Inal\",\"homeDirectory\":\"/home/timur\",\"shell\":\"/bin/bash\",\
             \"service\":\"com.mauvely.Users\"}\n"
        );
        assert_eq!(
            String::from_utf8(group_json(&timur(false))).unwrap(),
            "{\"groupName\":\"timur\",\"gid\":21001,\"disposition\":\"regular\",\
             \"service\":\"com.mauvely.Users\"}\n"
        );
    }

    #[test]
    fn a_real_name_cannot_break_a_passwd_line() {
        let mut p = timur(false);
        p.real_name = "Ti:mur\n\u{7}Inal ".into();
        let json: serde_json::Value = serde_json::from_slice(&user_json(&p)).unwrap();
        assert_eq!(json["realName"], "TimurInal");
        p.real_name = "  ".into();
        let json: serde_json::Value = serde_json::from_slice(&user_json(&p)).unwrap();
        assert!(json.get("realName").is_none());
    }

    #[test]
    fn writes_the_records_links_and_memberships() {
        let dir = TempDir::new();
        let d = dir.path();
        assert!(write(d, &timur(true)).unwrap());
        assert_eq!(
            files(d),
            [
                "21001.group",
                "21001.user",
                "timur.group",
                "timur.user",
                "timur:timur.membership",
                "timur:wheel.membership"
            ]
        );
        assert_eq!(
            fs::read_link(d.join("21001.user")).unwrap(),
            Path::new("timur.user")
        );
        assert_eq!(
            fs::read_link(d.join("21001.group")).unwrap(),
            Path::new("timur.group")
        );
        assert_eq!(fs::read(d.join("timur:wheel.membership")).unwrap(), b"{}\n");
        for f in ["timur.user", "timur.group", "timur:timur.membership"] {
            let mode = fs::metadata(d.join(f)).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o644, "{f}");
        }
        assert_eq!(uid_of(d, "timur"), Some(21001));
        assert_eq!(name_of(d, 21001).as_deref(), Some("timur"));
        assert_eq!(admins(d), ["timur"]);
    }

    #[test]
    fn only_what_changed_is_written() {
        let dir = TempDir::new();
        let d = dir.path();
        write(d, &timur(false)).unwrap();
        let ino = fs::metadata(d.join("timur.user")).unwrap().ino();
        assert!(!write(d, &timur(false)).unwrap());
        assert_eq!(fs::metadata(d.join("timur.user")).unwrap().ino(), ino);
        // Becoming an admin adds the membership and nothing else.
        assert!(write(d, &timur(true)).unwrap());
        assert_eq!(fs::metadata(d.join("timur.user")).unwrap().ino(), ino);
        assert!(d.join("timur:wheel.membership").exists());
        // And stopping takes it away.
        assert!(write(d, &timur(false)).unwrap());
        assert!(!d.join("timur:wheel.membership").exists());
        // A changed name is a new file, renamed into place.
        let mut renamed = timur(false);
        renamed.real_name = "Timur I.".into();
        assert!(write(d, &renamed).unwrap());
        assert_ne!(fs::metadata(d.join("timur.user")).unwrap().ino(), ino);
        assert!(files(d).iter().all(|f| !f.ends_with(".tmp")));
    }

    #[test]
    fn a_record_that_is_not_ours_is_not_taken_for_ours() {
        let dir = TempDir::new();
        let d = dir.path();
        fs::write(
            d.join("someone.user"),
            r#"{"userName":"someone","uid":5000,"gid":5000,"disposition":"regular","homeDirectory":"/x","shell":"/bin/sh"}"#,
        )
        .unwrap();
        symlink("someone.user", d.join("5000.user")).unwrap();
        fs::write(d.join("someone:wheel.membership"), "{}").unwrap();
        assert_eq!(uid_of(d, "someone"), None);
        assert_eq!(name_of(d, 5000), None);
        assert!(admins(d).is_empty());
        assert!(!drop_admin(d, "someone").unwrap());
        assert!(d.join("someone:wheel.membership").exists());
        remove_person(d, "someone").unwrap();
        assert!(d.join("someone.user").exists());
    }

    #[test]
    fn a_person_can_be_removed_whole() {
        let dir = TempDir::new();
        let d = dir.path();
        write(d, &timur(true)).unwrap();
        let other = Person {
            username: "ada".into(),
            uid: 21002,
            real_name: "Ada".into(),
            device_admin: false,
        };
        write(d, &other).unwrap();
        remove_person(d, "timur").unwrap();
        assert_eq!(
            files(d),
            [
                "21002.group",
                "21002.user",
                "ada.group",
                "ada.user",
                "ada:ada.membership"
            ]
        );
    }

    #[test]
    fn an_admin_can_be_dropped() {
        let dir = TempDir::new();
        let d = dir.path();
        write(d, &timur(true)).unwrap();
        assert!(drop_admin(d, "timur").unwrap());
        assert!(!drop_admin(d, "timur").unwrap());
        assert!(admins(d).is_empty());
        assert!(d.join("timur.user").exists());
    }
}
