//! Argon2id, twice over:
//!
//! - **The `authSecret`** a version 1 account signs in with, derived exactly
//!   as website-main's browser does (`web/src/lib/kdf.ts`): Argon2id v19,
//!   m=65536 KiB, t=3, p=1, 32 bytes, over the password's UTF-8 bytes as typed
//!   and the account's `auth_salt`, both base64 with padding. Held to
//!   website-main's vectors, copied to `tests/vectors/kdf.json`.
//! - **The offline cache's verifier**, with a fresh random salt and parameters
//!   of its own (t=4), and associated data naming it. So a verifier is never an
//!   `authSecret`, and a copied cache cannot be replayed to the server.
//!
//! Each derivation holds 64 MiB for about half a second, so at most
//! `PERMITS` run at once (`Gate`), whoever asks.

use std::sync::{Condvar, Mutex};
use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

/// Argon2id's parameters: memory in KiB, passes, lanes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Params {
    pub m: u32,
    pub t: u32,
    pub p: u32,
}

/// website-main's `DEFAULT_KDF_PARAMS`. The login door does not send
/// parameters, so these are the ones.
pub const SERVER: Params = Params {
    m: 65536,
    t: 3,
    p: 1,
};

/// The cache's own.
pub const CACHE: Params = Params {
    m: 65536,
    t: 4,
    p: 1,
};

/// Associated data in every verifier, so even the server's salt would not
/// make one an `authSecret`.
const CACHE_DATA: &[u8] = b"mauvely-os offline cache v1";

/// website-main's `KDF_PARAM_BOUNDS`, inclusive. A verifier read back is held
/// to them too, so a damaged file cannot ask for gigabytes.
fn sane(p: Params) -> bool {
    (19_456..=262_144).contains(&p.m) && (2..=10).contains(&p.t) && (1..=4).contains(&p.p)
}

/// The `authSecret` for `password` against the account's `salt`, base64.
/// `None` for an empty password, a salt that is not 16 bytes of standard
/// base64, parameters out of bounds, or a gate that stayed shut.
pub fn auth_secret(password: &[u8], salt: &str, params: Params) -> Option<Zeroizing<String>> {
    if password.is_empty() || !sane(params) {
        return None;
    }
    let salt = STANDARD.decode(salt).ok().filter(|s| s.len() == 16)?;
    let out = derive(password, &salt, params, None)?;
    Some(Zeroizing::new(STANDARD.encode(out.as_slice())))
}

/// A fresh 16-byte salt, base64, as website-main's `newAuthSalt`.
pub fn new_salt() -> String {
    STANDARD.encode(rand::random::<[u8; 16]>())
}

/// What the offline cache keeps instead of the password.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verifier {
    pub params: Params,
    /// 16 random bytes, base64.
    pub salt: String,
    /// 32 bytes, base64.
    pub hash: String,
}

impl std::fmt::Debug for Verifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Verifier")
            .field("params", &self.params)
            .finish_non_exhaustive()
    }
}

impl Verifier {
    /// A verifier for `password`, with a fresh salt.
    pub fn new(password: &[u8]) -> Option<Verifier> {
        if password.is_empty() {
            return None;
        }
        let salt = rand::random::<[u8; 16]>();
        let hash = derive(password, &salt, CACHE, Some(CACHE_DATA))?;
        Some(Verifier {
            params: CACHE,
            salt: STANDARD.encode(salt),
            hash: STANDARD.encode(hash.as_slice()),
        })
    }

    /// Whether `password` is the one this was made from, compared in constant
    /// time. `None` when it could not be checked (the gate stayed shut).
    pub fn check(&self, password: &[u8]) -> Option<bool> {
        if password.is_empty() || !sane(self.params) {
            return Some(false);
        }
        let (Ok(salt), Ok(want)) = (STANDARD.decode(&self.salt), STANDARD.decode(&self.hash))
        else {
            return Some(false);
        };
        if !(8..=64).contains(&salt.len()) || want.len() != 32 {
            return Some(false);
        }
        let got = derive(password, &salt, self.params, Some(CACHE_DATA))?;
        Some(got.iter().zip(&want).fold(0u8, |acc, (a, b)| acc | (a ^ b)) == 0)
    }
}

/// Argon2id v19, 32 bytes, behind the gate.
fn derive(
    password: &[u8],
    salt: &[u8],
    p: Params,
    data: Option<&[u8]>,
) -> Option<Zeroizing<[u8; 32]>> {
    let mut builder = ParamsBuilder::new();
    builder.m_cost(p.m).t_cost(p.t).p_cost(p.p).output_len(32);
    if let Some(data) = data {
        builder.data(AssociatedData::new(data).ok()?);
    }
    let params = builder.build().ok()?;
    let _permit = GATE.enter(GATE_WAIT)?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password, salt, out.as_mut_slice())
        .ok()?;
    Some(out)
}

/// Derivations at once.
const PERMITS: usize = 2;
/// How long one waits for a turn before giving up.
const GATE_WAIT: Duration = Duration::from_secs(20);

static GATE: Gate = Gate {
    free: Mutex::new(PERMITS),
    freed: Condvar::new(),
};

/// A counting semaphore.
struct Gate {
    free: Mutex<usize>,
    freed: Condvar,
}

struct Permit<'a>(&'a Gate);

impl Gate {
    fn enter(&self, wait: Duration) -> Option<Permit<'_>> {
        let deadline = Instant::now() + wait;
        let mut free = self.free.lock().unwrap_or_else(|e| e.into_inner());
        while *free == 0 {
            let left = deadline.checked_duration_since(Instant::now())?;
            free = self
                .freed
                .wait_timeout(free, left)
                .unwrap_or_else(|e| e.into_inner())
                .0;
        }
        *free -= 1;
        Some(Permit(self))
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        *self.0.free.lock().unwrap_or_else(|e| e.into_inner()) += 1;
        self.0.freed.notify_one();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn vectors() -> Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/vectors/kdf.json");
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn every_vector_from_website_main() {
        let doc = vectors();
        assert_eq!(doc["argon2"]["variant"], "argon2id");
        assert_eq!(doc["argon2"]["version"], 19);
        assert_eq!(doc["argon2"]["hashLength"], 32);
        let default: Params = serde_json::from_value(doc["defaultParams"].clone()).unwrap();
        assert_eq!(default, SERVER);

        let vectors = doc["vectors"].as_array().unwrap();
        assert_eq!(vectors.len(), 15);
        for v in vectors {
            let note = v["note"].as_str().unwrap();
            let password = v["password"].as_str().unwrap();
            // The bytes as typed: not normalised, not trimmed.
            assert_eq!(
                password.as_bytes(),
                hex(v["passwordUtf8Hex"].as_str().unwrap()),
                "{note}"
            );
            let params: Params = serde_json::from_value(v["params"].clone()).unwrap();
            let got = auth_secret(password.as_bytes(), v["salt"].as_str().unwrap(), params)
                .unwrap_or_else(|| panic!("{note}: refused"));
            assert_eq!(got.as_str(), v["authSecret"].as_str().unwrap(), "{note}");
        }
        for v in doc["refused"].as_array().unwrap() {
            let password = v["password"].as_str().unwrap();
            assert!(
                auth_secret(password.as_bytes(), v["salt"].as_str().unwrap(), SERVER).is_none(),
                "{}",
                v["note"]
            );
        }
    }

    #[test]
    fn the_bounds_are_website_mains() {
        let b = &vectors()["bounds"];
        let n = |k: &str, e: &str| b[k][e].as_u64().unwrap() as u32;
        let p = |m, t, p| Params { m, t, p };
        assert!(sane(p(n("m", "min"), n("t", "min"), n("p", "min"))));
        assert!(sane(p(n("m", "max"), n("t", "max"), n("p", "max"))));
        assert!(!sane(p(n("m", "min") - 1, 3, 1)));
        assert!(!sane(p(n("m", "max") + 1, 3, 1)));
        assert!(!sane(p(65536, n("t", "min") - 1, 1)));
        assert!(!sane(p(65536, n("t", "max") + 1, 1)));
        assert!(!sane(p(65536, 3, n("p", "min") - 1)));
        assert!(!sane(p(65536, 3, n("p", "max") + 1)));
        assert!(sane(SERVER) && sane(CACHE));
        // And nothing is derived outside them.
        assert!(auth_secret(b"pw", "AAAAAAAAAAAAAAAAAAAAAA==", p(1024, 1, 1)).is_none());
    }

    #[test]
    fn a_salt_that_is_not_sixteen_bytes_of_base64_is_refused() {
        for salt in [
            "",
            "AAAA",
            "AAAAAAAAAAAAAAAAAAAAAAAA",
            "not base64!",
            "AAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(
                auth_secret(b"password 1", salt, SERVER).is_none(),
                "{salt:?}"
            );
        }
    }

    #[test]
    fn a_verifier_checks_its_password_and_no_other() {
        let v = Verifier::new(b"correct horse battery staple 1").unwrap();
        assert_eq!(v.params, CACHE);
        assert_eq!(v.check(b"correct horse battery staple 1"), Some(true));
        assert_eq!(v.check(b"correct horse battery staple 2"), Some(false));
        assert_eq!(v.check(b""), Some(false));
        // Fresh salt each time.
        let w = Verifier::new(b"correct horse battery staple 1").unwrap();
        assert_ne!(v.salt, w.salt);
        assert_ne!(v.hash, w.hash);
        assert!(!format!("{v:?}").contains(&v.hash));
        assert!(Verifier::new(b"").is_none());
    }

    #[test]
    fn a_verifier_is_never_the_auth_secret() {
        // Even forced onto the server's salt and parameters, the associated
        // data keeps it from being the secret the server takes.
        let salt = "nEF+AtVjuB9K4DfGiF0SqQ==";
        let secret = auth_secret(b"correct horse battery staple 1", salt, SERVER).unwrap();
        let forced = derive(
            b"correct horse battery staple 1",
            &STANDARD.decode(salt).unwrap(),
            SERVER,
            Some(CACHE_DATA),
        )
        .unwrap();
        assert_ne!(STANDARD.encode(forced.as_slice()), *secret);
    }

    #[test]
    fn a_damaged_verifier_never_matches() {
        let v = Verifier::new(b"pw 1234567").unwrap();
        let mut bad = v.clone();
        bad.params.m = 1 << 30;
        assert_eq!(bad.check(b"pw 1234567"), Some(false));
        let mut bad = v.clone();
        bad.hash = "AAAA".into();
        assert_eq!(bad.check(b"pw 1234567"), Some(false));
        let mut bad = v.clone();
        bad.salt = "*".into();
        assert_eq!(bad.check(b"pw 1234567"), Some(false));
    }

    #[test]
    fn the_gate_lets_two_through_and_makes_a_third_wait() {
        let gate = Gate {
            free: Mutex::new(2),
            freed: Condvar::new(),
        };
        let a = gate.enter(Duration::from_millis(10)).unwrap();
        let _b = gate.enter(Duration::from_millis(10)).unwrap();
        assert!(gate.enter(Duration::from_millis(30)).is_none());
        drop(a);
        assert!(gate.enter(Duration::from_millis(10)).is_some());
    }

    #[test]
    fn new_salts_are_sixteen_random_bytes() {
        let (a, b) = (new_salt(), new_salt());
        assert_ne!(a, b);
        assert_eq!(STANDARD.decode(&a).unwrap().len(), 16);
        // website-main's isValidAuthSalt.
        assert_eq!(a.len(), 24);
        assert!(a.ends_with("=="));
    }
}
