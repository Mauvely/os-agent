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
    let key = if tpm2 {
        "--with-key=tpm2"
    } else {
        "--with-key=host"
    };
    argv(&["systemd-creds", "encrypt", NAME, key, "-", "-"])
}

pub(crate) fn unseal_argv() -> Vec<String> {
    argv(&["systemd-creds", "decrypt", NAME, "-", "-"])
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
}
