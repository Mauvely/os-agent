//! Hardware facts sent once, at enrolment.

use std::fs;
use std::path::Path;

use serde::Serialize;

pub const TPM_DEVICE: &str = "/dev/tpmrm0";
const SECURE_BOOT_VAR: &str =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Hardware {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub cpu: Option<String>,
    pub memory_mb: Option<u64>,
    pub tpm2: bool,
    pub secure_boot: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    pub hostname: String,
    pub serial: Option<String>,
    pub hardware: Hardware,
}

pub fn tpm2_present() -> bool {
    Path::new(TPM_DEVICE).exists()
}

/// Reads this machine. Anything unreadable is `None` (the DMI serial is
/// readable by root only).
pub fn collect() -> Facts {
    let text = |p: &str| {
        fs::read_to_string(p)
            .ok()
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
    };
    Facts {
        hostname: text("/proc/sys/kernel/hostname").unwrap_or_default(),
        serial: text("/sys/class/dmi/id/product_serial"),
        hardware: Hardware {
            vendor: text("/sys/class/dmi/id/sys_vendor"),
            model: text("/sys/class/dmi/id/product_name"),
            cpu: text("/proc/cpuinfo").and_then(|s| cpu_model(&s)),
            memory_mb: text("/proc/meminfo").and_then(|s| memory_mb(&s)),
            tpm2: tpm2_present(),
            secure_boot: fs::read(SECURE_BOOT_VAR)
                .map(|v| secure_boot(&v))
                .unwrap_or(false),
        },
    }
}

/// The first `model name` in `/proc/cpuinfo`.
fn cpu_model(cpuinfo: &str) -> Option<String> {
    cpuinfo.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim() == "model name").then(|| v.trim().to_owned())
    })
}

/// `MemTotal` from `/proc/meminfo`, in MiB.
fn memory_mb(meminfo: &str) -> Option<u64> {
    let line = meminfo.lines().find(|l| l.starts_with("MemTotal:"))?;
    let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
    Some(kb / 1024)
}

/// An efivar is four bytes of attributes, then the value. `SecureBoot` is one
/// byte, 1 when enabled.
fn secure_boot(efivar: &[u8]) -> bool {
    efivar.get(4) == Some(&1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_cpuinfo() {
        let s = "processor\t: 0\nvendor_id\t: AuthenticAMD\nmodel name\t: AMD Ryzen 9 7900X 12-Core Processor\n";
        assert_eq!(
            cpu_model(s).as_deref(),
            Some("AMD Ryzen 9 7900X 12-Core Processor")
        );
        assert_eq!(cpu_model("processor : 0\n"), None);
    }

    #[test]
    fn parses_meminfo() {
        assert_eq!(
            memory_mb("MemTotal:       16384000 kB\nMemFree: 1 kB\n"),
            Some(16000)
        );
        assert_eq!(memory_mb("MemFree: 1 kB\n"), None);
    }

    #[test]
    fn parses_secure_boot_var() {
        assert!(secure_boot(&[6, 0, 0, 0, 1]));
        assert!(!secure_boot(&[6, 0, 0, 0, 0]));
        assert!(!secure_boot(&[6, 0, 0]));
    }
}
