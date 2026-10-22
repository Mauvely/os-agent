//! Sealing the device key at rest with `systemd-creds`.

use crate::Error;
use crate::command::{argv, run};

/// The name embedded in the credential; decryption checks it.
const NAME: &str = "--name=mauvely-device-key";

pub trait Creds {
    fn seal(&self, secret: &[u8]) -> Result<Vec<u8>, Error>;
    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, Error>;
}

/// The real `systemd-creds`. The secret travels over stdin and stdout, never
/// through a file or an argument.
pub struct SystemdCreds {
    /// Whether `/dev/tpmrm0` exists. Without a TPM the host key is used.
    pub tpm2: bool,
}

impl Creds for SystemdCreds {
    fn seal(&self, secret: &[u8]) -> Result<Vec<u8>, Error> {
        run(&seal_argv(self.tpm2), Some(secret))
    }

    fn unseal(&self, sealed: &[u8]) -> Result<Vec<u8>, Error> {
        run(&unseal_argv(), Some(sealed))
    }
}

pub(crate) fn seal_argv(tpm2: bool) -> Vec<String> {
    argv(&["systemd-creds", "encrypt", NAME, key(tpm2), "-", "-"])
}

pub(crate) fn unseal_argv() -> Vec<String> {
    argv(&["systemd-creds", "decrypt", NAME, "-", "-"])
}

fn key(tpm2: bool) -> &'static str {
    if tpm2 {
        "--with-key=tpm2"
    } else {
        "--with-key=host"
    }
}

/// Sealing under a name of the caller's, which decrypting checks: the login
/// service's offline cache, one credential per person. Shared between
/// threads.
pub trait Sealer: Send + Sync {
    fn seal_as(&self, name: &str, secret: &[u8]) -> Result<Vec<u8>, Error>;
    fn unseal_as(&self, name: &str, sealed: &[u8]) -> Result<Vec<u8>, Error>;
}

impl Sealer for SystemdCreds {
    fn seal_as(&self, name: &str, secret: &[u8]) -> Result<Vec<u8>, Error> {
        run(&named_seal_argv(self.tpm2, name)?, Some(secret))
    }

    fn unseal_as(&self, name: &str, sealed: &[u8]) -> Result<Vec<u8>, Error> {
        run(&named_unseal_argv(name)?, Some(sealed))
    }
}

/// A name of `[a-z0-9-]`, so it is one argument and never an option.
fn named(name: &str) -> Result<String, Error> {
    let plain = name
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
    if !plain || name.is_empty() || name.starts_with('-') || name.len() > 64 {
        return Err(Error::Invalid(format!(
            "credential name {name:?} is not valid"
        )));
    }
    Ok(format!("--name={name}"))
}

pub(crate) fn named_seal_argv(tpm2: bool, name: &str) -> Result<Vec<String>, Error> {
    let name = named(name)?;
    Ok(argv(&[
        "systemd-creds",
        "encrypt",
        &name,
        key(tpm2),
        "-",
        "-",
    ]))
}

pub(crate) fn named_unseal_argv(name: &str) -> Result<Vec<String>, Error> {
    let name = named(name)?;
    Ok(argv(&["systemd-creds", "decrypt", &name, "-", "-"]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tpm_when_present_host_otherwise() {
        assert_eq!(
            seal_argv(true),
            [
                "systemd-creds",
                "encrypt",
                "--name=mauvely-device-key",
                "--with-key=tpm2",
                "-",
                "-"
            ]
        );
        assert_eq!(seal_argv(false)[3], "--with-key=host");
        assert_eq!(
            unseal_argv(),
            [
                "systemd-creds",
                "decrypt",
                "--name=mauvely-device-key",
                "-",
                "-"
            ]
        );
    }

    #[test]
    fn a_named_credential_carries_its_name_and_nothing_else() {
        assert_eq!(
            named_seal_argv(true, "mauvely-person-timur").unwrap(),
            [
                "systemd-creds",
                "encrypt",
                "--name=mauvely-person-timur",
                "--with-key=tpm2",
                "-",
                "-"
            ]
        );
        assert_eq!(named_seal_argv(false, "a").unwrap()[3], "--with-key=host");
        assert_eq!(
            named_unseal_argv("mauvely-person-timur").unwrap(),
            [
                "systemd-creds",
                "decrypt",
                "--name=mauvely-person-timur",
                "-",
                "-"
            ]
        );
        for bad in ["", "-x", "a b", "a/b", "A", "a=b"] {
            assert!(named_seal_argv(true, bad).is_err(), "{bad:?}");
            assert!(named_unseal_argv(bad).is_err(), "{bad:?}");
        }
    }
}
