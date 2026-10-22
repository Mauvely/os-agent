//! The device's say over who signs in (brief 26): `desired.people` in each
//! check-in answer.
//!
//! ```json
//! {"mode":"assigned","assigned":{"username":"timur","name":"Timur Inal"},
//!  "admins":["ada"],"org":{"name":"Suez","slug":"suez"},"offline_days":14}
//! ```
//!
//! - **Shared**: anyone with a valid username, as website-devices decides.
//! - **Assigned**: the assigned person and the organisation's device admins.
//!   `assigned` is null when that person is no longer a member, and then only
//!   the admins.
//!
//! Kept whole in `/var/lib/mauvely/people.json` (`0600`), where the login
//! service reads it for each request, and so across reboots and offline. The
//! login screen's part, without the admins, is
//! `/var/lib/mauvely-desktop/people.json` (`0644`).

use std::fs;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::names::is_username;
use super::{LoginPaths, cache, userdb};
use crate::Error;
use crate::state::{self, write_atomic};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Shared,
    Assigned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Assigned {
    pub username: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Org {
    pub name: String,
    pub slug: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct People {
    pub mode: Mode,
    pub assigned: Option<Assigned>,
    pub admins: Vec<String>,
    pub org: Org,
    pub offline_days: u32,
}

impl People {
    /// From the check-in answer. Names that are not usernames are dropped: an
    /// `assigned` one becomes nobody, an admin one is not an admin.
    pub fn from_answer(value: &Value) -> Result<People, String> {
        let mut p: People = serde_json::from_value(value.clone()).map_err(|e| e.to_string())?;
        p.assigned = p.assigned.filter(|a| is_username(&a.username));
        p.admins.retain(|a| is_username(a));
        if p.mode == Mode::Shared {
            p.assigned = None;
        }
        Ok(p)
    }

    /// Whether `username` may sign in at this device. Usernames only: whether
    /// they are an active member is the server's to say.
    pub fn allows(&self, username: &str) -> bool {
        if !is_username(username) {
            return false;
        }
        match self.mode {
            Mode::Shared => true,
            Mode::Assigned => {
                self.is_admin(username)
                    || self
                        .assigned
                        .as_ref()
                        .is_some_and(|a| a.username == username)
            }
        }
    }

    pub fn is_admin(&self, username: &str) -> bool {
        self.admins.iter().any(|a| a == username)
    }
}

/// The last `desired.people`, or `None` before the first one.
pub fn load(paths: &LoginPaths) -> Option<People> {
    match state::read_json::<People>(&paths.people) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("login: {e}");
            None
        }
    }
}

/// What the login screen reads.
#[derive(Serialize)]
struct Greeter<'a> {
    mode: Mode,
    assigned: Option<&'a Assigned>,
    org: &'a Org,
}

/// The greeter's file's exact bytes: the mode, who is assigned, and the
/// organisation. Never the admins.
pub fn greeter_json(p: &People) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(&Greeter {
        mode: p.mode,
        assigned: p.assigned.as_ref(),
        org: &p.org,
    })
    .expect("always serialises");
    bytes.push(b'\n');
    bytes
}

/// What a check-in changed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Applied {
    /// The people file or the greeter's changed.
    pub changed: bool,
    /// Cache entries removed: people this device no longer allows.
    pub forgotten: Vec<String>,
    /// People taken out of the admin group.
    pub demoted: Vec<String>,
}

/// Applies `desired.people` from a check-in: keeps it, writes the greeter's
/// part, forgets the cache of anyone it no longer allows, and takes anyone no
/// longer a device admin out of the admin group. Their records and home stay.
pub fn apply(paths: &LoginPaths, value: &Value) -> Result<Applied, Error> {
    let people = People::from_answer(value).map_err(Error::Invalid)?;
    let mut applied = Applied::default();

    if load(paths).as_ref() != Some(&people) {
        state::write_json(&paths.people, &people)?;
        applied.changed = true;
    }
    let greeter = greeter_json(&people);
    if fs::read(&paths.greeter).ok() != Some(greeter.clone()) {
        write_atomic(&paths.greeter, &greeter, 0o644)?;
        applied.changed = true;
    }

    for name in cache::names(&paths.cache) {
        if !people.allows(&name) && cache::remove(&paths.cache, &name)? {
            applied.forgotten.push(name);
        }
    }
    for name in userdb::admins(&paths.userdb) {
        if !people.is_admin(&name) && userdb::drop_admin(&paths.userdb, &name)? {
            applied.demoted.push(name);
        }
    }
    Ok(applied)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeCreds, TempDir};
    use crate::login::cache::tests::entry;
    use crate::login::testing::paths;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt;
    use std::path::Path;

    fn assigned() -> Value {
        json!({
            "mode": "assigned",
            "assigned": { "username": "timur", "name": "Timur Inal" },
            "admins": ["ada"],
            "org": { "name": "Suez", "slug": "suez" },
            "offline_days": 14
        })
    }

    fn shared() -> Value {
        json!({
            "mode": "shared", "assigned": null, "admins": ["ada"],
            "org": { "name": "Suez", "slug": "suez" }, "offline_days": 7
        })
    }

    #[test]
    fn an_assigned_device_takes_its_person_and_the_admins() {
        let p = People::from_answer(&assigned()).unwrap();
        assert!(p.allows("timur"));
        assert!(p.allows("ada"));
        assert!(!p.allows("bob"));
        assert!(!p.allows("Timur"));
    }

    #[test]
    fn an_assigned_device_whose_person_left_takes_only_the_admins() {
        let mut v = assigned();
        v["assigned"] = Value::Null;
        let p = People::from_answer(&v).unwrap();
        assert!(!p.allows("timur"));
        assert!(p.allows("ada"));
    }

    #[test]
    fn a_shared_device_takes_any_valid_username() {
        let p = People::from_answer(&shared()).unwrap();
        assert!(p.allows("timur"));
        assert!(p.allows("bob"));
        assert!(p.allows("0bob"));
        assert!(!p.allows("ab"));
        assert!(!p.allows("Bob"));
        assert!(!p.allows("bob.suez"));
    }

    #[test]
    fn names_that_are_not_usernames_count_for_nothing() {
        let mut v = assigned();
        v["assigned"]["username"] = json!("../etc");
        v["admins"] = json!(["ada", "Root", ""]);
        let p = People::from_answer(&v).unwrap();
        assert_eq!(p.assigned, None);
        assert_eq!(p.admins, ["ada"]);
        assert!(People::from_answer(&json!({ "mode": "everyone" })).is_err());
    }

    #[test]
    fn the_check_in_keeps_it_and_tells_the_greeter_without_the_admins() {
        let dir = TempDir::new();
        let p = paths(&dir);
        let applied = apply(&p, &assigned()).unwrap();
        assert!(applied.changed);
        assert_eq!(load(&p), Some(People::from_answer(&assigned()).unwrap()));
        let mode = |f: &Path| fs::metadata(f).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&p.people), 0o600);
        assert_eq!(mode(&p.greeter), 0o644);
        assert_eq!(
            fs::read_to_string(&p.greeter).unwrap(),
            "{\"mode\":\"assigned\",\"assigned\":{\"username\":\"timur\",\"name\":\"Timur Inal\"},\
             \"org\":{\"name\":\"Suez\",\"slug\":\"suez\"}}\n"
        );
        // Nothing changed, nothing written.
        assert!(!apply(&p, &assigned()).unwrap().changed);

        apply(&p, &shared()).unwrap();
        assert_eq!(
            fs::read_to_string(&p.greeter).unwrap(),
            "{\"mode\":\"shared\",\"assigned\":null,\"org\":{\"name\":\"Suez\",\"slug\":\"suez\"}}\n"
        );
    }

    #[test]
    fn a_reassigned_device_forgets_the_last_person_offline() {
        let dir = TempDir::new();
        let p = paths(&dir);
        for name in ["timur", "ada", "bob"] {
            cache::write(&p.cache, &FakeCreds, &entry(name, "pw 1234567", 1000)).unwrap();
        }
        // Shared: everyone stays.
        assert!(apply(&p, &shared()).unwrap().forgotten.is_empty());
        // Assigned to timur, with ada an admin: bob goes.
        assert_eq!(apply(&p, &assigned()).unwrap().forgotten, ["bob"]);
        // Reassigned to somebody else: timur goes too, ada stays.
        let mut v = assigned();
        v["assigned"]["username"] = json!("carol");
        assert_eq!(apply(&p, &v).unwrap().forgotten, ["timur"]);
        assert_eq!(cache::names(&p.cache), ["ada"]);
    }

    #[test]
    fn an_admin_no_longer_listed_leaves_the_admin_group() {
        let dir = TempDir::new();
        let p = paths(&dir);
        let person = |name: &str, uid| userdb::Person {
            username: name.into(),
            uid,
            real_name: name.into(),
            device_admin: true,
        };
        userdb::write(&p.userdb, &person("ada", 21001)).unwrap();
        userdb::write(&p.userdb, &person("bob", 21002)).unwrap();
        assert_eq!(apply(&p, &shared()).unwrap().demoted, ["bob"]);
        assert_eq!(userdb::admins(&p.userdb), ["ada"]);
        // Their records stay.
        assert_eq!(userdb::uid_of(&p.userdb, "bob"), Some(21002));
    }

    #[test]
    fn an_answer_it_cannot_read_changes_nothing() {
        let dir = TempDir::new();
        let p = paths(&dir);
        apply(&p, &assigned()).unwrap();
        assert!(apply(&p, &json!({ "mode": 3 })).is_err());
        assert_eq!(load(&p), Some(People::from_answer(&assigned()).unwrap()));
    }
}
