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

impl Bootc for SystemBootc {
    fn status(&self) -> Result<Status, Error> {
        parse_status(&run(&argv(&["bootc", "status", "--json"]), None)?)
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
    Ok(argv(&["bootc", "switch", image]))
}

pub(crate) fn upgrade_argv() -> Vec<String> {
    // The same: no `--apply`, so it stages and never reboots.
    argv(&["bootc", "upgrade"])
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
            ["bootc", "switch", "ghcr.io/mauvely/os:next"]
        );
        assert!(switch_argv("--apply").is_err());
        assert_eq!(upgrade_argv(), ["bootc", "upgrade"]);
        assert_eq!(
            discard_staged_argv(),
            ["rpm-ostree", "cleanup", "--pending"]
        );
    }
}
