//! The OS image, through `bootc`, and `rpm-ostree` for the one step bootc
//! has no command for. The agent only ever stages: it never applies an image
//! and never reboots.

use serde_json::Value;

use crate::Error;
use crate::command::{argv, operand, run};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Status {
    pub booted_image: Option<String>,
    pub booted_digest: Option<String>,
    pub staged_image: Option<String>,
    pub staged_digest: Option<String>,
}

impl Status {
    /// The staged image when it is an update. `None` when nothing is staged,
    /// or when what is staged is the booted image at the booted digest: a
    /// kernel-argument change, which is what mauvely-seal's `rpm-ostree kargs`
    /// stages on the first boot. Read as an update, that parked every upgrade
    /// behind it until a clean reboot, and a machine only ever powered off
    /// hard never updated.
    pub fn staged_update(&self) -> Option<&str> {
        let kargs_only = self.staged_digest.is_some()
            && self.staged_digest == self.booted_digest
            && self.staged_image == self.booted_image;
        if kargs_only {
            None
        } else {
            self.staged_image.as_deref()
        }
    }
}

pub trait Bootc {
    fn status(&self) -> Result<Status, Error>;
    /// Stages `image` for the next boot.
    fn switch(&self, image: &str) -> Result<(), Error>;
    /// Stages a newer build of the image the host already follows, when the
    /// registry has one, and does nothing when it has not.
    fn upgrade(&self) -> Result<(), Error>;
    /// Drops the staged deployment, so the next boot is the booted image
    /// again.
    fn discard_staged(&self) -> Result<(), Error>;
}

/// The real `bootc` CLI.
pub struct SystemBootc;

/// `bootc` with `args`, run in PID 1's mount namespace rather than the
/// service's own.
///
/// `mauvelyd.service`'s sandboxing (`PrivateTmp`, `ProtectHome`) gives the
/// agent a mount namespace of its own, and every `bootc upgrade` run in such a
/// namespace leaves its storage bind mounts behind, doubled by propagation:
/// 1, 3, 7, 15, 31 after five runs. Within an hour of one-minute check-ins the
/// namespace reached the kernel's `fs.mount-max` and every upgrade failed with
/// "No space left on device" (Timur's VM, 2026-10-21). Run in the host's
/// namespace, bootc cleans up after itself, as it does from a shell. The rest
/// of the agent stays sandboxed.
pub(crate) fn bootc_argv(args: &[&str]) -> Vec<String> {
    let mut v = argv(&["nsenter", "--mount=/proc/1/ns/mnt", "--", "bootc"]);
    v.extend(args.iter().map(|a| (*a).to_owned()));
    v
}

impl Bootc for SystemBootc {
    fn status(&self) -> Result<Status, Error> {
        parse_status(&run(&bootc_argv(&["status", "--json"]), None)?)
    }

    fn switch(&self, image: &str) -> Result<(), Error> {
        run(&switch_argv(image)?, None).map(drop)
    }

    fn upgrade(&self) -> Result<(), Error> {
        run(&upgrade_argv(), None).map(drop)
    }

    fn discard_staged(&self) -> Result<(), Error> {
        run(&discard_staged_argv(), None).map(drop)
    }
}

pub(crate) fn switch_argv(image: &str) -> Result<Vec<String>, Error> {
    operand("image", image)?;
    // Without `--apply`, `bootc switch` stages and leaves the reboot to the
    // machine's own schedule.
    Ok(bootc_argv(&["switch", image]))
}

pub(crate) fn upgrade_argv() -> Vec<String> {
    // The same: no `--apply`, so it stages and never reboots.
    bootc_argv(&["upgrade"])
}

pub(crate) fn discard_staged_argv() -> Vec<String> {
    // bootc 1.16 has no command for this: `bootc rollback` drops the staged
    // deployment but also makes the rollback one the default. rpm-ostree,
    // which Kinoite ships beside bootc, drops only the staged one, on the
    // same ostree sysroot.
    argv(&["rpm-ostree", "cleanup", "--pending"])
}

/// Reads the `BootcHost` document `bootc status --json` prints. A machine not
/// booted from a container image has no `status.booted.image`.
pub(crate) fn parse_status(stdout: &[u8]) -> Result<Status, Error> {
    let v: Value = serde_json::from_slice(stdout).map_err(|e| Error::json("bootc status", e))?;
    let s = |ptr: &str| v.pointer(ptr).and_then(Value::as_str).map(str::to_owned);
    Ok(Status {
        booted_image: s("/status/booted/image/image/image"),
        booted_digest: s("/status/booted/image/imageDigest"),
        staged_image: s("/status/staged/image/image/image"),
        staged_digest: s("/status/staged/image/imageDigest"),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = r#"{
      "apiVersion": "org.containers.bootc/v1",
      "kind": "BootcHost",
      "metadata": { "name": "host" },
      "spec": { "image": { "image": "ghcr.io/mauvely/os:stable", "transport": "registry" } },
      "status": {
        "staged": {
          "image": {
            "image": { "image": "ghcr.io/mauvely/os:next", "transport": "registry" },
            "version": "42.20261014.0",
            "timestamp": null,
            "imageDigest": "sha256:2222"
          },
          "pinned": false
        },
        "booted": {
          "image": {
            "image": { "image": "ghcr.io/mauvely/os:stable", "transport": "registry" },
            "version": "42.20261001.0",
            "timestamp": null,
            "imageDigest": "sha256:1111"
          },
          "cachedUpdate": null,
          "incompatible": false,
          "pinned": false
        },
        "rollback": null,
        "type": "bootcHost"
      }
    }"#;

    #[test]
    fn parses_booted_and_staged() {
        let s = parse_status(STATUS.as_bytes()).unwrap();
        assert_eq!(s.booted_image.as_deref(), Some("ghcr.io/mauvely/os:stable"));
        assert_eq!(s.booted_digest.as_deref(), Some("sha256:1111"));
        assert_eq!(s.staged_image.as_deref(), Some("ghcr.io/mauvely/os:next"));
    }

    #[test]
    fn nothing_staged() {
        let s = parse_status(br#"{"status":{"staged":null,"booted":{"image":null}}}"#).unwrap();
        assert_eq!(s, Status::default());
        assert!(parse_status(b"not json").is_err());
    }

    #[test]
    fn switch_never_applies() {
        assert_eq!(
            switch_argv("ghcr.io/mauvely/os:next").unwrap(),
            [
                "nsenter",
                "--mount=/proc/1/ns/mnt",
                "--",
                "bootc",
                "switch",
                "ghcr.io/mauvely/os:next"
            ]
        );
        assert!(switch_argv("--apply").is_err());
        assert_eq!(
            upgrade_argv(),
            [
                "nsenter",
                "--mount=/proc/1/ns/mnt",
                "--",
                "bootc",
                "upgrade"
            ]
        );
        // Every bootc command leaves the service's mount namespace: run inside
        // it, each upgrade doubles bootc's leftover mounts until mounts fail.
        assert_eq!(
            bootc_argv(&["status", "--json"]),
            [
                "nsenter",
                "--mount=/proc/1/ns/mnt",
                "--",
                "bootc",
                "status",
                "--json"
            ]
        );
        assert_eq!(
            discard_staged_argv(),
            ["rpm-ostree", "cleanup", "--pending"]
        );
    }

    // `bootc status --format=json` from bootc 1.16.13 on the first Proxmox
    // install (2026-10-21), on `stable`, in the three states that matter.
    const REAL_CLEAN: &str = include_str!("../fixtures/bootc/clean.json");
    const REAL_OTHER_STAGED: &str = include_str!("../fixtures/bootc/other-staged.json");
    const REAL_KARGS_STAGED: &str = include_str!("../fixtures/bootc/kargs-staged.json");

    #[test]
    fn real_status_with_nothing_staged() {
        let s = parse_status(REAL_CLEAN.as_bytes()).unwrap();
        assert_eq!(s.booted_image.as_deref(), Some("ghcr.io/mauvely/os:stable"));
        assert!(
            s.booted_digest
                .as_deref()
                .unwrap()
                .starts_with("sha256:1862d543")
        );
        assert_eq!(s.staged_image, None);
        assert_eq!(s.staged_update(), None);
    }

    #[test]
    fn real_status_with_another_image_staged() {
        let s = parse_status(REAL_OTHER_STAGED.as_bytes()).unwrap();
        assert_eq!(s.staged_image.as_deref(), Some("ghcr.io/mauvely/os:next"));
        assert!(
            s.staged_digest
                .as_deref()
                .unwrap()
                .starts_with("sha256:0e39a3a5")
        );
        assert_eq!(s.staged_update(), Some("ghcr.io/mauvely/os:next"));
    }

    #[test]
    fn a_kernel_argument_change_is_not_an_update() {
        // `rpm-ostree kargs --append`, as mauvely-seal runs it: the booted
        // image again, at the booted digest.
        let s = parse_status(REAL_KARGS_STAGED.as_bytes()).unwrap();
        assert_eq!(s.staged_image, s.booted_image);
        assert_eq!(s.staged_digest, s.booted_digest);
        assert_eq!(s.staged_update(), None);
    }

    #[test]
    fn a_newer_build_of_the_booted_image_is_an_update() {
        let s = Status {
            booted_image: Some("ghcr.io/mauvely/os:stable".into()),
            booted_digest: Some("sha256:1111".into()),
            staged_image: Some("ghcr.io/mauvely/os:stable".into()),
            staged_digest: Some("sha256:2222".into()),
        };
        assert_eq!(s.staged_update(), Some("ghcr.io/mauvely/os:stable"));
    }
}
