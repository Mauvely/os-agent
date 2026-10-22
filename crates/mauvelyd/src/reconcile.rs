//! Bringing the machine to what the server asked for (brief 19, "How the
//! agent reconciles").
//!
//! Order: remotes are added and updated first, so the apps can come from
//! them. Then apps are installed, then removed. Remotes the agent added and no
//! longer wants are deleted after the apps, because flatpak refuses to delete a
//! remote that still has refs installed from it. The image is staged last.
//!
//! One failure never stops the rest: every error is collected for the next
//! check-in's `last_apply`.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

use crate::api::{AppState, Desired, FailedApp, LastApply};
use crate::bootc::{self, Bootc};
use crate::flatpak::{App, Flatpak, Remote};
use crate::signing::sha256_hex;
use crate::state::{Managed, ManagedRemote};

/// What the machine looked like at check-in. `image` is `None` when
/// `bootc status` failed.
#[derive(Debug, Clone, Default)]
pub struct Inventory {
    pub apps: Vec<App>,
    pub remotes: Vec<Remote>,
    pub image: Option<bootc::Status>,
}

/// The browsers mauvely-session's broker answers `browser` to. Its own list,
/// `broker::caller::BROWSERS`, must name the same ones.
pub const BROWSERS: [&str; 2] = ["org.chromium.Chromium", "org.mozilla.firefox"];

/// What one reconcile did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// For the next check-in.
    pub last_apply: LastApply,
    /// The apps that were installed, in order, and not the ones that were
    /// already there or failed.
    pub installed: Vec<App>,
}

pub fn reconcile(
    desired: &Desired,
    inventory: &Inventory,
    managed: &mut Managed,
    flatpak: &dyn Flatpak,
    bootc: &dyn Bootc,
) -> Applied {
    let mut errors = Vec::new();
    let mut failed = Vec::new();
    let mut installed_now = Vec::new();
    let mut installed = inventory.apps.clone();
    let mut remotes: Vec<String> = inventory.remotes.iter().map(|r| r.name.clone()).collect();

    // Remotes: add, or update when the URL or key changed.
    for want in &desired.remotes {
        let fingerprint = sha256_hex(format!("{}\n{}", want.url, want.gpg_key).as_bytes());
        let present = inventory.remotes.iter().find(|r| r.name == want.name);
        let known = managed.remote(&want.name);
        let current = present.is_some_and(|p| p.url == want.url)
            && known.is_some_and(|k| k.applied == fingerprint);
        if current {
            continue;
        }
        let key = match STANDARD.decode(want.gpg_key.trim()) {
            Ok(k) => k,
            Err(e) => {
                errors.push(format!("remote {}: gpg_key is not base64: {e}", want.name));
                continue;
            }
        };
        let (result, added) = match present {
            None => (flatpak.remote_add(&want.name, &want.url, &key), true),
            Some(_) => (
                flatpak.remote_modify(&want.name, &want.url, &key),
                known.is_some_and(|k| k.added),
            ),
        };
        match result {
            Ok(()) => {
                managed.remotes.retain(|r| r.name != want.name);
                managed.remotes.push(ManagedRemote {
                    name: want.name.clone(),
                    added,
                    applied: fingerprint,
                });
                if present.is_none() {
                    remotes.push(want.name.clone());
                }
            }
            Err(e) => errors.push(format!("remote {}: {e}", want.name)),
        }
    }

    // Apps to install. An app already installed counts, whatever its origin.
    for app in desired
        .apps
        .iter()
        .filter(|a| a.state == AppState::Installed)
    {
        if installed.iter().any(|i| i.is(&app.id, &app.branch)) {
            continue;
        }
        match flatpak.install(&app.remote, &app.id, &app.branch) {
            Ok(()) => {
                let new = App {
                    id: app.id.clone(),
                    branch: app.branch.clone(),
                    remote: app.remote.clone(),
                };
                if !managed.has_app(&app.id, &app.branch) {
                    managed.apps.push(new.clone());
                }
                installed.push(new.clone());
                installed_now.push(new);
            }
            Err(e) => {
                errors.push(format!("install {}//{}: {e}", app.id, app.branch));
                failed.push(FailedApp {
                    id: app.id.clone(),
                    branch: app.branch.clone(),
                    error: e.to_string(),
                });
            }
        }
    }

    // Apps to remove: everything marked absent, managed or not, and every
    // managed app the server no longer lists.
    let mut remove: Vec<(String, String)> = desired
        .apps
        .iter()
        .filter(|a| a.state == AppState::Absent)
        .map(|a| (a.id.clone(), a.branch.clone()))
        .collect();
    for m in &managed.apps {
        if !desired.apps.iter().any(|a| m.is(&a.id, &a.branch)) {
            remove.push((m.id.clone(), m.branch.clone()));
        }
    }
    for (id, branch) in remove {
        if !installed.iter().any(|i| i.is(&id, &branch)) {
            continue;
        }
        match flatpak.uninstall(&id, &branch) {
            Ok(()) => installed.retain(|i| !i.is(&id, &branch)),
            Err(e) => {
                errors.push(format!("uninstall {id}//{branch}: {e}"));
                failed.push(FailedApp {
                    id,
                    branch,
                    error: e.to_string(),
                });
            }
        }
    }
    // The agent manages only what it installed and is still there.
    managed
        .apps
        .retain(|m| installed.iter().any(|i| i.is(&m.id, &m.branch)));

    // Each system browser may reach mauvely-session's broker (brief 22, S2),
    // whoever installed it. Granted once; a browser removed and installed
    // again is granted again.
    for id in BROWSERS {
        if !installed.iter().any(|i| i.id == id) {
            managed.granted.retain(|g| g != id);
            continue;
        }
        if managed.granted.iter().any(|g| g == id) {
            continue;
        }
        match flatpak.grant_broker(id) {
            Ok(()) => managed.granted.push(id.into()),
            Err(e) => errors.push(format!("override {id}: {e}")),
        }
    }

    // Remotes the agent added and the server no longer lists.
    let unlisted: Vec<String> = managed
        .remotes
        .iter()
        .filter(|m| m.added && !desired.remotes.iter().any(|d| d.name == m.name))
        .map(|m| m.name.clone())
        .collect();
    for name in unlisted {
        if !remotes.contains(&name) {
            continue;
        }
        match flatpak.remote_delete(&name) {
            Ok(()) => remotes.retain(|r| *r != name),
            Err(e) => errors.push(format!("remote-delete {name}: {e}")),
        }
    }
    managed.remotes.retain(|m| remotes.contains(&m.name));

    // The image. A different one is switched to. The booted one is upgraded,
    // which stages a newer build under the same tag when the registry has one:
    // that is how a device on `stable` gets the next stable. Either way it is
    // staged once and then left to wait for a reboot. Never applied, never
    // rebooted.
    if let Some(want) = &desired.image {
        let want = want.reference.as_str();
        match &inventory.image {
            None => errors.push("image: bootc status is unavailable".into()),
            Some(s) if s.staged_update() == Some(want) => {}
            Some(s) if s.booted_image.as_deref() == Some(want) && s.staged_update().is_none() => {
                if let Err(e) = bootc.upgrade() {
                    errors.push(format!("bootc upgrade {want}: {e}"));
                }
            }
            // The booted image is wanted, but another is staged over it, as
            // when a collection moves back from next to stable. An upgrade
            // follows the staged image, so that is discarded first.
            Some(s) if s.booted_image.as_deref() == Some(want) => match bootc.discard_staged() {
                Ok(()) => {
                    if let Err(e) = bootc.upgrade() {
                        errors.push(format!("bootc upgrade {want}: {e}"));
                    }
                }
                Err(e) => errors.push(format!(
                    "discard staged {}: {e}",
                    s.staged_update().unwrap_or_default()
                )),
            },
            Some(_) => {
                if let Err(e) = bootc.switch(want) {
                    errors.push(format!("bootc switch {want}: {e}"));
                }
            }
        }
    }

    Applied {
        last_apply: LastApply::new(errors, failed),
        installed: installed_now,
    }
}

/// System Flatpaks are updated at most this often (brief 22, U2).
pub const FLATPAK_UPDATE_S: u64 = 6 * 3600;

/// `flatpak update`, then `flatpak uninstall --unused`, when the last run
/// that succeeded is `FLATPAK_UPDATE_S` old. The agent calls it after
/// `reconcile`, so it never runs during an install. A failed run is tried
/// again at the next check-in. `apps` are the installed apps, for naming the
/// one an update failed on.
pub fn update_flatpaks(
    managed: &mut Managed,
    flatpak: &dyn Flatpak,
    now: u64,
    apps: &[App],
) -> LastApply {
    // Either way round: a clock set back does not stop updates for good.
    if now.abs_diff(managed.flatpaks_updated) < FLATPAK_UPDATE_S {
        return LastApply::default();
    }
    let mut errors = Vec::new();
    let mut failed = Vec::new();
    if let Err(e) = flatpak.update() {
        let detail = e.to_string();
        // One update covers every app, and flatpak says which it failed on
        // as "Failed to update <name>: …" (`flatpak-cli-transaction.c`,
        // 1.18.4). A runtime, or an error with no name, names no app.
        failed.extend(
            apps.iter()
                .filter(|a| detail.contains(&format!("Failed to update {}: ", a.id)))
                .map(|a| FailedApp {
                    id: a.id.clone(),
                    branch: a.branch.clone(),
                    error: detail.clone(),
                }),
        );
        errors.push(format!("flatpak update: {detail}"));
    }
    if let Err(e) = flatpak.uninstall_unused() {
        errors.push(format!("flatpak uninstall --unused: {e}"));
    }
    if errors.is_empty() {
        managed.flatpaks_updated = now;
    }
    LastApply::new(errors, failed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::{DesiredApp, DesiredImage, DesiredRemote};
    use crate::fake::{FakeBootc, FakeFlatpak, app};

    const KEY_B64: &str = "AAECAw==";

    fn remote(name: &str) -> DesiredRemote {
        DesiredRemote {
            name: name.into(),
            url: format!("https://{name}.example/repo"),
            gpg_key: KEY_B64.into(),
        }
    }

    fn want(id: &str, remote: &str, state: AppState) -> DesiredApp {
        DesiredApp {
            id: id.into(),
            branch: "stable".into(),
            remote: remote.into(),
            state,
        }
    }

    /// Takes the inventory from the fake, as the agent does at check-in.
    fn run(
        desired: &Desired,
        fp: &FakeFlatpak,
        bc: &FakeBootc,
        managed: &mut Managed,
    ) -> LastApply {
        run_all(desired, fp, bc, managed).last_apply
    }

    fn run_all(
        desired: &Desired,
        fp: &FakeFlatpak,
        bc: &FakeBootc,
        managed: &mut Managed,
    ) -> Applied {
        let inv = Inventory {
            apps: fp.installed().unwrap(),
            remotes: fp.remotes().unwrap(),
            image: bc.status().ok(),
        };
        reconcile(desired, &inv, managed, fp, bc)
    }

    #[test]
    fn installs_and_records_as_managed() {
        let fp = FakeFlatpak::default();
        let bc = FakeBootc::booted("img:stable");
        let mut managed = Managed::default();
        let desired = Desired {
            image: None,
            remotes: vec![remote("mauvely")],
            apps: vec![want("com.mauvely.compose", "mauvely", AppState::Installed)],
            desktop: None,
        };
        let r = run(&desired, &fp, &bc, &mut managed);
        assert_eq!(r, LastApply::default());
        assert_eq!(
            fp.log(),
            [
                "remote-add mauvely https://mauvely.example/repo key=00010203",
                "install mauvely com.mauvely.compose//stable",
            ]
        );
        assert!(managed.has_app("com.mauvely.compose", "stable"));
        assert!(managed.remote("mauvely").unwrap().added);
    }

    #[test]
    fn second_pass_is_a_no_op() {
        let fp = FakeFlatpak::default();
        let bc = FakeBootc::booted("img:stable");
        let mut managed = Managed::default();
        let desired = Desired {
            image: Some(DesiredImage {
                reference: "img:stable".into(),
            }),
            remotes: vec![remote("mauvely")],
            apps: vec![want("com.mauvely.compose", "mauvely", AppState::Installed)],
            desktop: None,
        };
        run(&desired, &fp, &bc, &mut managed);
        fp.clear_log();
        let before = managed.clone();
        let r = run(&desired, &fp, &bc, &mut managed);
        assert!(r.ok);
        assert!(fp.log().is_empty(), "{:?}", fp.log());
        assert!(bc.switches().is_empty());
        assert_eq!(managed, before);
    }

    #[test]
    fn unlisted_managed_apps_are_removed_and_others_kept() {
        let fp = FakeFlatpak::default();
        fp.add_system(app("org.kde.kate", "flathub")); // a user's own, unmanaged
        let bc = FakeBootc::booted("img:stable");
        let mut managed = Managed::default();
        let mut desired = Desired {
            image: None,
            remotes: vec![remote("flathub")],
            apps: vec![
                want("org.mozilla.firefox", "flathub", AppState::Installed),
                want(
                    "org.onlyoffice.desktopeditors",
                    "flathub",
                    AppState::Installed,
                ),
            ],
            desktop: None,
        };
        run(&desired, &fp, &bc, &mut managed);
        fp.clear_log();

        desired.apps.remove(1);
        let r = run(&desired, &fp, &bc, &mut managed);
        assert!(r.ok);
        assert_eq!(
            fp.log(),
            ["uninstall org.onlyoffice.desktopeditors//stable"]
        );
        assert!(!managed.has_app("org.onlyoffice.desktopeditors", "stable"));
        assert!(fp.system_has("org.kde.kate"));
        assert!(fp.system_has("org.mozilla.firefox"));
    }

    #[test]
    fn absent_removes_an_unmanaged_app() {
        let fp = FakeFlatpak::default();
        fp.add_system(app("com.example.Game", "flathub"));
        let bc = FakeBootc::booted("img:stable");
        let mut managed = Managed::default();
        let desired = Desired {
            image: None,
            remotes: vec![],
            apps: vec![want("com.example.Game", "flathub", AppState::Absent)],
            desktop: None,
        };
        let r = run(&desired, &fp, &bc, &mut managed);
        assert!(r.ok);
        assert_eq!(fp.log(), ["uninstall com.example.Game//stable"]);
        assert!(!fp.system_has("com.example.Game"));
    }

    #[test]
    fn user_installs_are_never_touched() {
        let fp = FakeFlatpak::default();
        fp.add_user(app("com.example.Game", "flathub"));
        let bc = FakeBootc::booted("img:stable");
        let mut managed = Managed::default();
        let desired = Desired {
            image: None,
            remotes: vec![],
            apps: vec![want("com.example.Game", "flathub", AppState::Absent)],
            desktop: None,
        };
        let r = run(&desired, &fp, &bc, &mut managed);
        assert!(r.ok);
        assert!(fp.log().is_empty(), "{:?}", fp.log());
        assert!(fp.user_has("com.example.Game"));
    }

    #[test]
    fn a_failed_install_does_not_stop_the_rest() {
        let fp = FakeFlatpak::default();
        fp.fail_install("org.broken.App");
        fp.add_system(app("com.example.Game", "flathub"));
        let bc = FakeBootc::booted("img:stable");
        let mut managed = Managed::default();
        let desired = Desired {
            image: Some(DesiredImage {
                reference: "img:next".into(),
            }),
            remotes: vec![remote("flathub")],
            apps: vec![
                want("org.broken.App", "flathub", AppState::Installed),
                want("org.mozilla.firefox", "flathub", AppState::Installed),
                want("com.example.Game", "flathub", AppState::Absent),
            ],
            desktop: None,
        };
        let r = run(&desired, &fp, &bc, &mut managed);
        assert!(!r.ok);
        assert_eq!(r.errors.len(), 1);
        assert!(
            r.errors[0].starts_with("install org.broken.App//stable:"),
            "{:?}",
            r.errors
        );
        assert!(fp.system_has("org.mozilla.firefox"));
        assert!(!fp.system_has("com.example.Game"));
        assert!(!managed.has_app("org.broken.App", "stable"));
        assert_eq!(bc.switches(), ["img:next"]);
    }

    #[test]
    fn a_kernel_argument_change_does_not_hold_back_the_upgrade() {
        // mauvely-seal stages the booted image again with new kernel
        // arguments. Read as an update, it parked every upgrade until a clean
        // reboot.
        let fp = FakeFlatpak::default();
        let mut managed = Managed::default();
        let desired = Desired {
            image: Some(DesiredImage {
                reference: "img:stable".into(),
            }),
            ..Desired::default()
        };
        let bc = FakeBootc::kargs_staged("img:stable");
        let r = run(&desired, &fp, &bc, &mut managed);
        assert!(r.ok);
        assert_eq!(bc.upgrades(), 1);
        assert_eq!(bc.discards(), 0, "the kernel-argument change is kept");
        assert!(bc.switches().is_empty());
    }

    #[test]
    fn image_is_switched_or_upgraded_then_left_staged() {
        let fp = FakeFlatpak::default();
        let mut managed = Managed::default();
        let desired = |r: &str| Desired {
            image: Some(DesiredImage {
                reference: r.into(),
            }),
            ..Desired::default()
        };

        // Same as booted: asks for a newer build of it at every check-in,
        // and never switches.
        let bc = FakeBootc::booted("img:stable");
        run(&desired("img:stable"), &fp, &bc, &mut managed);
        run(&desired("img:stable"), &fp, &bc, &mut managed);
        assert!(bc.switches().is_empty());
        assert_eq!(bc.upgrades(), 2);

        // Different: staged once, then left alone while it waits for a reboot.
        run(&desired("img:next"), &fp, &bc, &mut managed);
        assert_eq!(bc.switches(), ["img:next"]);
        run(&desired("img:next"), &fp, &bc, &mut managed);
        assert_eq!(bc.switches(), ["img:next"]);

        // Back to the booted one with img:next still staged: img:next is
        // discarded, then the booted one upgraded. No switch.
        assert_eq!(bc.discards(), 0);
        let r = run(&desired("img:stable"), &fp, &bc, &mut managed);
        assert!(r.ok);
        assert_eq!(bc.discards(), 1);
        assert_eq!(bc.status().unwrap().staged_image, None);
        assert_eq!(bc.switches(), ["img:next"]);
        assert_eq!(bc.upgrades(), 3);

        // No image wanted: leave it.
        run(&Desired::default(), &fp, &bc, &mut managed);
        assert_eq!(bc.switches(), ["img:next"]);
        assert_eq!(bc.upgrades(), 3);
        assert_eq!(bc.discards(), 1);

        // A newer build of the booted image is already staged: left alone.
        let bc = FakeBootc::booted("img:stable");
        bc.switch("img:stable").unwrap();
        run(&desired("img:stable"), &fp, &bc, &mut managed);
        assert_eq!(bc.upgrades(), 0);
        assert_eq!(bc.discards(), 0);

        // bootc status failed: nothing staged, and it is reported.
        let broken = FakeBootc::broken();
        let r = run(&desired("img:next"), &fp, &broken, &mut managed);
        assert!(broken.switches().is_empty());
        assert!(!r.ok);
    }

    #[test]
    fn remotes_are_updated_only_on_change_and_deleted_only_if_added() {
        let fp = FakeFlatpak::default();
        fp.add_remote("fedora", "https://registry.fedoraproject.org/");
        fp.add_remote("flathub", "https://dl.flathub.org/repo/");
        let bc = FakeBootc::booted("img:stable");
        let mut managed = Managed::default();
        let mut desired = Desired {
            image: None,
            remotes: vec![remote("mauvely"), remote("flathub")],
            apps: vec![],
            desktop: None,
        };
        run(&desired, &fp, &bc, &mut managed);
        assert_eq!(
            fp.log(),
            [
                "remote-add mauvely https://mauvely.example/repo key=00010203",
                "remote-modify flathub https://flathub.example/repo key=00010203",
            ]
        );
        assert!(!managed.remote("flathub").unwrap().added);

        // A new key for mauvely: updated, and only it.
        fp.clear_log();
        desired.remotes[0].gpg_key = "BAUG".into();
        run(&desired, &fp, &bc, &mut managed);
        assert_eq!(
            fp.log(),
            ["remote-modify mauvely https://mauvely.example/repo key=040506"]
        );
        assert!(managed.remote("mauvely").unwrap().added);

        // Nothing listed: only the remote the agent added goes.
        fp.clear_log();
        desired.remotes.clear();
        run(&desired, &fp, &bc, &mut managed);
        assert_eq!(fp.log(), ["remote-delete mauvely"]);
        assert!(fp.remote_names().contains(&"flathub".to_string()));
        assert!(fp.remote_names().contains(&"fedora".to_string()));
    }

    #[test]
    fn a_bad_key_is_reported_and_the_rest_goes_on() {
        let fp = FakeFlatpak::default();
        let bc = FakeBootc::booted("img:stable");
        let mut managed = Managed::default();
        let mut bad = remote("bad");
        bad.gpg_key = "not base64!".into();
        let desired = Desired {
            image: None,
            remotes: vec![bad, remote("flathub")],
            apps: vec![],
            desktop: None,
        };
        let r = run(&desired, &fp, &bc, &mut managed);
        assert_eq!(r.errors.len(), 1);
        assert!(fp.remote_names().contains(&"flathub".to_string()));
    }

    #[test]
    fn system_browsers_are_granted_the_broker_once() {
        let fp = FakeFlatpak::default();
        let bc = FakeBootc::booted("img:stable");
        let mut managed = Managed::default();
        // Installed before the agent knew about the broker, or by someone
        // else: granted all the same.
        fp.add_system(app("org.chromium.Chromium", "flathub"));
        // A person's own install: never.
        fp.add_user(app("org.mozilla.firefox", "flathub"));
        let mut desired = Desired {
            image: None,
            remotes: vec![remote("flathub")],
            apps: vec![
                want("org.mozilla.firefox", "flathub", AppState::Installed),
                want("com.mauvely.compose", "flathub", AppState::Installed),
            ],
            desktop: None,
        };
        let r = run(&desired, &fp, &bc, &mut managed);
        assert!(r.ok, "{:?}", r.errors);
        let overrides: Vec<String> = fp
            .log()
            .into_iter()
            .filter(|l| l.starts_with("override"))
            .collect();
        assert_eq!(
            overrides,
            [
                "override org.chromium.Chromium",
                "override org.mozilla.firefox"
            ]
        );
        assert_eq!(
            managed.granted,
            ["org.chromium.Chromium", "org.mozilla.firefox"]
        );

        // Once.
        fp.clear_log();
        run(&desired, &fp, &bc, &mut managed);
        assert!(fp.log().is_empty(), "{:?}", fp.log());

        // Removed, then installed again: granted again.
        desired.apps[0].state = AppState::Absent;
        run(&desired, &fp, &bc, &mut managed);
        assert_eq!(managed.granted, ["org.chromium.Chromium"]);
        fp.clear_log();
        desired.apps[0].state = AppState::Installed;
        run(&desired, &fp, &bc, &mut managed);
        assert_eq!(
            fp.log(),
            [
                "install flathub org.mozilla.firefox//stable",
                "override org.mozilla.firefox"
            ]
        );
    }

    #[test]
    fn a_failed_grant_is_reported_and_tried_again() {
        let fp = FakeFlatpak::default();
        let bc = FakeBootc::booted("img:stable");
        let mut managed = Managed::default();
        fp.add_system(app("org.mozilla.firefox", "flathub"));
        fp.fail_grant(true);
        let r = run(&Desired::default(), &fp, &bc, &mut managed);
        assert_eq!(r.errors.len(), 1);
        assert!(
            r.errors[0].starts_with("override org.mozilla.firefox:"),
            "{:?}",
            r.errors
        );
        assert!(managed.granted.is_empty());

        fp.fail_grant(false);
        fp.clear_log();
        assert!(run(&Desired::default(), &fp, &bc, &mut managed).ok);
        assert_eq!(fp.log(), ["override org.mozilla.firefox"]);
        assert_eq!(managed.granted, ["org.mozilla.firefox"]);
    }

    #[test]
    fn flatpaks_are_updated_at_most_every_six_hours() {
        const T: u64 = 1_760_400_000;
        let fp = FakeFlatpak::default();
        let mut managed = Managed::default();

        // Never updated: update, then remove what nothing uses.
        assert!(update_flatpaks(&mut managed, &fp, T, &[]).errors.is_empty());
        assert_eq!(fp.log(), ["update", "uninstall --unused"]);
        assert_eq!(managed.flatpaks_updated, T);

        // Not again inside six hours.
        fp.clear_log();
        assert!(
            update_flatpaks(&mut managed, &fp, T + FLATPAK_UPDATE_S - 1, &[])
                .errors
                .is_empty()
        );
        assert!(fp.log().is_empty(), "{:?}", fp.log());

        // A failure is reported, not recorded, and tried again next time.
        fp.fail_update(true);
        let later = T + FLATPAK_UPDATE_S;
        let errors = update_flatpaks(&mut managed, &fp, later, &[]).errors;
        assert_eq!(errors.len(), 1);
        assert!(errors[0].starts_with("flatpak update:"), "{errors:?}");
        assert_eq!(fp.log(), ["update", "uninstall --unused"]);
        assert_eq!(managed.flatpaks_updated, T);
        fp.fail_update(false);
        assert!(
            update_flatpaks(&mut managed, &fp, later + 900, &[])
                .errors
                .is_empty()
        );
        assert_eq!(managed.flatpaks_updated, later + 900);

        // A clock set back by more than the interval does not stop updates.
        fp.clear_log();
        assert!(
            update_flatpaks(&mut managed, &fp, T - FLATPAK_UPDATE_S, &[])
                .errors
                .is_empty()
        );
        assert_eq!(fp.log(), ["update", "uninstall --unused"]);
    }

    #[test]
    fn a_failed_install_and_a_failed_removal_name_their_apps() {
        let fp = FakeFlatpak::default();
        fp.fail_install("org.broken.App");
        fp.add_system(app("com.example.Stuck", "flathub"));
        fp.fail_uninstall("com.example.Stuck");
        let bc = FakeBootc::booted("img:stable");
        let mut managed = Managed::default();
        let desired = Desired {
            image: None,
            remotes: vec![remote("flathub")],
            apps: vec![
                want("org.broken.App", "flathub", AppState::Installed),
                want("org.mozilla.firefox", "flathub", AppState::Installed),
                want("com.example.Stuck", "flathub", AppState::Absent),
            ],
            desktop: None,
        };
        let r = run(&desired, &fp, &bc, &mut managed);

        // The text list is what it was.
        assert_eq!(r.errors.len(), 2, "{:?}", r.errors);
        assert!(r.errors[0].starts_with("install org.broken.App//stable:"));
        assert!(r.errors[1].starts_with("uninstall com.example.Stuck//stable:"));

        // And the apps are named, in the order they failed, with the cause
        // alone and not the "install …:" prefix.
        let named: Vec<(&str, &str)> = r
            .failed
            .iter()
            .map(|f| (f.id.as_str(), f.branch.as_str()))
            .collect();
        assert_eq!(
            named,
            [
                ("org.broken.App", "stable"),
                ("com.example.Stuck", "stable")
            ]
        );
        assert!(
            r.failed[0].error.contains("failed to download"),
            "{:?}",
            r.failed
        );
        assert!(r.failed[1].error.contains("is in use"), "{:?}", r.failed);
        // The one that worked is not in it.
        assert!(fp.system_has("org.mozilla.firefox"));
        assert!(r.failed.iter().all(|f| f.id != "org.mozilla.firefox"));
    }

    #[test]
    fn a_failure_that_is_not_an_app_is_an_error_without_a_failed_app() {
        let fp = FakeFlatpak::default();
        fp.add_system(app("org.mozilla.firefox", "flathub"));
        fp.fail_grant(true);
        let bc = FakeBootc::booted("img:stable");
        let mut bad = remote("bad");
        bad.gpg_key = "not base64!".into();
        let desired = Desired {
            image: Some(DesiredImage {
                reference: "img:next".into(),
            }),
            remotes: vec![bad],
            apps: vec![],
            desktop: None,
        };
        let r = run(&desired, &fp, &bc, &mut Managed::default());
        assert_eq!(r.errors.len(), 2, "{:?}", r.errors);
        assert!(r.failed.is_empty(), "{:?}", r.failed);
    }

    #[test]
    fn what_was_installed_is_listed_and_what_failed_or_was_there_is_not() {
        let fp = FakeFlatpak::default();
        fp.fail_install("org.broken.App");
        fp.add_system(app("org.kde.kate", "flathub"));
        let bc = FakeBootc::booted("img:stable");
        let mut managed = Managed::default();
        let desired = Desired {
            image: None,
            remotes: vec![remote("flathub")],
            apps: vec![
                want("org.kde.kate", "flathub", AppState::Installed),
                want("org.broken.App", "flathub", AppState::Installed),
                want("org.mozilla.firefox", "flathub", AppState::Installed),
                want("com.mauvely.compose", "flathub", AppState::Installed),
            ],
            desktop: None,
        };
        let r = run_all(&desired, &fp, &bc, &mut managed);
        assert_eq!(
            r.installed,
            [
                app("org.mozilla.firefox", "flathub"),
                app("com.mauvely.compose", "flathub")
            ]
        );

        // The next pass has nothing to install.
        assert!(
            run_all(&desired, &fp, &bc, &mut managed)
                .installed
                .is_empty()
        );

        // An app the agent already manages, taken off by someone and put back
        // by the agent, is installed again and listed again.
        fp.uninstall("com.mauvely.compose", "stable").unwrap();
        let r = run_all(&desired, &fp, &bc, &mut managed);
        assert_eq!(r.installed, [app("com.mauvely.compose", "flathub")]);
    }

    #[test]
    fn a_failed_update_names_an_installed_app_when_flatpak_does() {
        const T: u64 = 1_760_400_000;
        let apps = [
            app("org.mozilla.firefox", "flathub"),
            app("org.mozilla.firefox.Extra", "flathub"),
            app("org.kde.kate", "flathub"),
        ];
        let update = |detail: &str| {
            let fp = FakeFlatpak::default();
            fp.fail_update_saying(detail);
            update_flatpaks(&mut Managed::default(), &fp, T, &apps)
        };

        // The line flatpak prints for its first failed operation
        // (`flatpak-cli-transaction.c`, "Failed to update %s: ").
        let r = update(
            "exit status: 1: Warning: Error pulling from repo\n\
             error: Failed to update org.mozilla.firefox: Server returned status 503",
        );
        assert_eq!(r.errors.len(), 1);
        assert_eq!(r.failed.len(), 1, "{:?}", r.failed);
        assert_eq!(r.failed[0].id, "org.mozilla.firefox");
        assert_eq!(r.failed[0].branch, "stable");
        assert!(r.failed[0].error.contains("Server returned status 503"));

        // An id that is the start of another's is not named by the other's.
        let r = update("exit status: 1: error: Failed to update org.mozilla.firefox.Extra: no");
        let ids: Vec<&str> = r.failed.iter().map(|f| f.id.as_str()).collect();
        assert_eq!(ids, ["org.mozilla.firefox.Extra"]);

        // A runtime, or no name at all: an error, and no app to blame.
        for detail in [
            "exit status: 1: error: Failed to update org.freedesktop.Platform: no",
            "exit status: 1: error: unable to load summary",
        ] {
            let r = update(detail);
            assert_eq!(r.errors.len(), 1);
            assert!(r.failed.is_empty(), "{detail}: {:?}", r.failed);
        }
    }
}
