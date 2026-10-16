//! Enrolment and the check-in loop.

use std::time::Duration;

use ed25519_dalek::SigningKey;

use crate::api::{
    self, CheckinRequest, CheckinResponse, Client, EnrolRequest, EnrolResponse, FlatpakReport,
    LastApply, OsInfo,
};
use crate::bootc::Bootc;
use crate::creds::Creds;
use crate::facts::Facts;
use crate::flatpak::Flatpak;
use crate::reconcile::{Inventory, reconcile, update_flatpaks};
use crate::schedule::{self, Backoff};
use crate::state::{self, Device, Managed, Paths, Status};
use crate::{AGENT_VERSION, Error, signing};

/// The machine's tools.
pub struct Host<'a> {
    pub flatpak: &'a dyn Flatpak,
    pub bootc: &'a dyn Bootc,
    pub creds: &'a dyn Creds,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Enrolment {
    /// Enrolled now, or already.
    Enrolled(Device),
    /// No token in the enrolment file.
    NoToken,
    /// The server refused, with its error code. The token is kept.
    Refused(String),
}

/// One enrolment attempt. Each attempt uses a fresh key, sealed to disk
/// before it is sent, so a key the server accepted is never lost.
pub fn enrol(paths: &Paths, host: &Host, facts: &Facts) -> Result<Enrolment, Error> {
    if let Some(device) = state::read_json::<Device>(&paths.device())? {
        return Ok(Enrolment::Enrolled(device));
    }
    let Some(token) = state::read_token(paths)? else {
        return Ok(Enrolment::NoToken);
    };
    let server = state::read_server(paths)?;

    let seed = signing::new_seed()?;
    let sealed = host.creds.seal(&seed)?;
    state::write_private(&paths.key(), &sealed)?;
    let key = SigningKey::from_bytes(&seed);

    let image = host
        .bootc
        .status()
        .inspect_err(|e| eprintln!("bootc status failed: {e}"))
        .unwrap_or_default();
    let body = EnrolRequest {
        token: &token,
        public_key: signing::public_key(&key),
        hostname: &facts.hostname,
        serial: facts.serial.as_deref(),
        hardware: &facts.hardware,
        os: OsInfo {
            booted_image: image.booted_image.as_deref(),
            booted_digest: image.booted_digest.as_deref(),
        },
        agent_version: AGENT_VERSION,
    };
    let body = serde_json::to_vec(&body).map_err(|e| Error::json("enrol body", e))?;
    let reply = Client::new(&server).post(api::ENROL_PATH, &key, None, &body)?;
    match reply.status {
        201 => {
            let r: EnrolResponse =
                serde_json::from_str(&reply.body).map_err(|e| Error::json("enrol answer", e))?;
            let device = Device {
                device_id: r.device_id,
                org_slug: r.org.slug,
            };
            state::write_json(&paths.device(), &device)?;
            state::delete_token(paths)?;
            Ok(Enrolment::Enrolled(device))
        }
        401 | 409 => Ok(Enrolment::Refused(reply.error_code())),
        _ => Err(Error::Http(format!("enrol: {}", reply.error_code()))),
    }
}

/// What one check-in led to.
#[derive(Debug, PartialEq, Eq)]
pub enum Tick {
    /// Check in again after this long.
    Sleep(Duration),
    /// The server revoked this device. Stop checking in.
    Revoked,
}

enum Outcome {
    Applied { interval_s: u64 },
    Revoked,
}

/// An enrolled device, ready to check in.
pub struct Agent<'a> {
    paths: Paths,
    host: Host<'a>,
    client: Client,
    key: SigningKey,
    device: Device,
    managed: Managed,
    last_apply: LastApply,
    backoff: Backoff,
}

impl<'a> Agent<'a> {
    pub fn load(paths: Paths, host: Host<'a>) -> Result<Self, Error> {
        let server = state::read_server(&paths)?;
        let device = state::read_json::<Device>(&paths.device())?
            .ok_or_else(|| Error::Invalid("not enrolled".into()))?;
        let key_path = paths.key();
        let sealed = std::fs::read(&key_path).map_err(|e| Error::io(&key_path, e))?;
        let seed: [u8; 32] =
            host.creds.unseal(&sealed)?.try_into().map_err(|_| {
                Error::Invalid(format!("{}: not a 32-byte seed", key_path.display()))
            })?;
        let managed = state::read_json::<Managed>(&paths.managed())?.unwrap_or_default();
        Ok(Agent {
            client: Client::new(&server),
            key: SigningKey::from_bytes(&seed),
            paths,
            host,
            device,
            managed,
            last_apply: LastApply::default(),
            backoff: Backoff::default(),
        })
    }

    pub fn device(&self) -> &Device {
        &self.device
    }

    /// Checks in once, reconciles, and says when to come back.
    pub fn tick(&mut self) -> Tick {
        match self.checkin() {
            Ok(Outcome::Applied { interval_s }) => {
                self.backoff.reset();
                for e in &self.last_apply.errors {
                    eprintln!("apply: {e}");
                }
                Tick::Sleep(schedule::jitter(schedule::interval(interval_s)))
            }
            Ok(Outcome::Revoked) => Tick::Revoked,
            Err(e) => {
                let wait = schedule::jitter(self.backoff.fail());
                eprintln!("check-in failed: {e}; retrying in {}s", wait.as_secs());
                Tick::Sleep(wait)
            }
        }
    }

    fn checkin(&mut self) -> Result<Outcome, Error> {
        let host = &self.host;
        let inventory = Inventory {
            apps: host.flatpak.installed()?,
            remotes: host.flatpak.remotes()?,
            image: host
                .bootc
                .status()
                .inspect_err(|e| eprintln!("bootc status failed: {e}"))
                .ok(),
        };
        let image = inventory.image.clone().unwrap_or_default();
        let body = CheckinRequest {
            booted_image: image.booted_image.as_deref(),
            booted_digest: image.booted_digest.as_deref(),
            staged_image: image.staged_image.as_deref(),
            remotes: inventory.remotes.iter().map(|r| r.name.as_str()).collect(),
            flatpaks: inventory
                .apps
                .iter()
                .map(|a| FlatpakReport {
                    id: &a.id,
                    branch: &a.branch,
                    remote: &a.remote,
                    managed: self.managed.has_app(&a.id, &a.branch),
                })
                .collect(),
            last_apply: &self.last_apply,
            agent_version: AGENT_VERSION,
        };
        let body = serde_json::to_vec(&body).map_err(|e| Error::json("check-in body", e))?;
        let reply = self.client.post(
            api::CHECKIN_PATH,
            &self.key,
            Some(&self.device.device_id),
            &body,
        )?;
        match reply.status {
            200 => {}
            403 if reply.error_code() == "revoked" => return Ok(Outcome::Revoked),
            _ => return Err(Error::Http(format!("check-in: {}", reply.error_code()))),
        }
        let answer: CheckinResponse =
            serde_json::from_str(&reply.body).map_err(|e| Error::json("check-in answer", e))?;
        let status = Status {
            last_checkin: api::now(),
        };
        if let Err(e) = state::write_json(&self.paths.status(), &status) {
            eprintln!("{e}");
        }

        let mut result = reconcile(
            &answer.desired,
            &inventory,
            &mut self.managed,
            host.flatpak,
            host.bootc,
        );
        let updates = update_flatpaks(&mut self.managed, host.flatpak, api::now());
        result = LastApply::from_errors([result.errors, updates].concat());
        if let Err(e) = state::write_json(&self.paths.managed(), &self.managed) {
            result = LastApply::from_errors([result.errors, vec![e.to_string()]].concat());
        }
        self.last_apply = result;
        Ok(Outcome::Applied {
            interval_s: answer.interval_s,
        })
    }
}

/// The service: enrols, retrying with backoff, then checks in until the
/// device is revoked. Returns only on revocation or a fatal error.
pub fn run(
    paths: &Paths,
    host: Host,
    facts: &dyn Fn() -> Facts,
    sleep: &mut dyn FnMut(Duration),
) -> Result<(), Error> {
    let mut backoff = Backoff::default();
    let mut said_no_token = false;
    loop {
        match enrol(paths, &host, &facts()) {
            Ok(Enrolment::Enrolled(_)) => break,
            Ok(Enrolment::NoToken) => {
                if !said_no_token {
                    eprintln!("not enrolled, and no token in {}", paths.enrol().display());
                    said_no_token = true;
                }
            }
            Ok(Enrolment::Refused(code)) => {
                eprintln!("enrolment refused: {code}; the token is kept")
            }
            Err(e) => eprintln!("enrolment failed: {e}"),
        }
        sleep(schedule::jitter(backoff.fail()));
    }

    let mut agent = Agent::load(paths.clone(), host)?;
    eprintln!(
        "device {} in {}, checking in",
        agent.device.device_id, agent.device.org_slug
    );
    loop {
        match agent.tick() {
            Tick::Sleep(d) => sleep(d),
            Tick::Revoked => {
                eprintln!("this device has been revoked; no longer checking in");
                return Ok(());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::Duration;

    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
    use serde_json::Value;

    use super::*;
    use crate::facts::Hardware;
    use crate::fake::{Captured, FakeBootc, FakeCreds, FakeFlatpak, FakeServer, TempDir, app};

    const TOKEN: &str = "mvd_secret_token_value";
    const ENROLLED: &str = r#"{"device_id":"dev_1","org":{"id":"org_1","slug":"northgate"},"collection_id":null,"server_time":1760400000}"#;

    fn setup(dir: &TempDir, server: &str, token: Option<&str>) -> Paths {
        let paths = Paths {
            config_dir: dir.path().join("etc"),
            state_dir: dir.path().join("state"),
        };
        fs::create_dir_all(&paths.config_dir).unwrap();
        fs::write(paths.server(), format!("{server}\n")).unwrap();
        if let Some(t) = token {
            fs::write(paths.enrol(), format!("{t}\n")).unwrap();
        }
        paths
    }

    fn facts() -> Facts {
        Facts {
            hostname: "office-07".into(),
            serial: Some("SN-0042".into()),
            hardware: Hardware {
                vendor: Some("QEMU".into()),
                model: Some("Standard PC".into()),
                cpu: Some("Virtual CPU".into()),
                memory_mb: Some(8192),
                tpm2: true,
                secure_boot: true,
            },
        }
    }

    /// Checks the signature against `public_key`, rebuilding the message from
    /// the brief rather than from `signing::message`.
    fn verify(req: &Captured, public_key: &str) {
        let h = |n: &str| req.header(n).unwrap_or_else(|| panic!("missing {n}"));
        let ts: u64 = h("X-Mauvely-Timestamp").parse().unwrap();
        assert!(api::now().abs_diff(ts) < 60, "timestamp {ts} is not now");
        let nonce = h("X-Mauvely-Nonce");
        assert_eq!(URL_SAFE_NO_PAD.decode(nonce).unwrap().len(), 16);
        let msg = format!(
            "mauvely-device-v1\n{}\n{}\n{ts}\n{nonce}\n{}",
            req.method,
            req.url,
            signing::sha256_hex(&req.body)
        );
        let pk: [u8; 32] = URL_SAFE_NO_PAD
            .decode(public_key)
            .unwrap()
            .try_into()
            .unwrap();
        let sig = Signature::from_slice(&URL_SAFE_NO_PAD.decode(h("X-Mauvely-Signature")).unwrap())
            .unwrap();
        VerifyingKey::from_bytes(&pk)
            .unwrap()
            .verify_strict(msg.as_bytes(), &sig)
            .expect("signature verifies");
    }

    fn body(req: &Captured) -> Value {
        serde_json::from_slice(&req.body).unwrap()
    }

    /// An enrolled state directory, as a 201 leaves it.
    fn enrolled(dir: &TempDir, server: &str) -> (Paths, SigningKey) {
        let paths = setup(dir, server, None);
        let seed = [9u8; 32];
        state::write_private(&paths.key(), &FakeCreds.seal(&seed).unwrap()).unwrap();
        state::write_json(
            &paths.device(),
            &Device {
                device_id: "dev_1".into(),
                org_slug: "northgate".into(),
            },
        )
        .unwrap();
        (paths, SigningKey::from_bytes(&seed))
    }

    #[test]
    fn enrol_201_stores_the_device_and_deletes_the_token() {
        let server = FakeServer::start(vec![(201, ENROLLED.into())]);
        let dir = TempDir::new();
        let paths = setup(&dir, &server.base, Some(TOKEN));
        let (fp, bc) = (
            FakeFlatpak::default(),
            FakeBootc::booted("ghcr.io/mauvely/os:stable"),
        );
        let host = Host {
            flatpak: &fp,
            bootc: &bc,
            creds: &FakeCreds,
        };

        let out = enrol(&paths, &host, &facts()).unwrap();
        assert_eq!(
            out,
            Enrolment::Enrolled(Device {
                device_id: "dev_1".into(),
                org_slug: "northgate".into()
            })
        );
        assert!(!paths.enrol().exists(), "token deleted");
        assert!(paths.device().exists());

        let reqs = server.requests();
        assert_eq!(reqs.len(), 1);
        let req = &reqs[0];
        assert_eq!(
            (req.method.as_str(), req.url.as_str()),
            ("POST", "/api/agent/v1/enrol")
        );
        assert_eq!(req.header("X-Mauvely-Device"), None);
        let b = body(req);
        let pk = b["public_key"].as_str().unwrap();
        verify(req, pk);
        assert_eq!(b["token"], TOKEN);
        assert_eq!(b["hostname"], "office-07");
        assert_eq!(b["serial"], "SN-0042");
        assert_eq!(b["hardware"]["memory_mb"], 8192);
        assert_eq!(b["hardware"]["tpm2"], true);
        assert_eq!(b["hardware"]["secure_boot"], true);
        assert_eq!(b["os"]["booted_image"], "ghcr.io/mauvely/os:stable");
        assert_eq!(b["os"]["booted_digest"], "sha256:0000");
        assert_eq!(b["agent_version"], AGENT_VERSION);

        // The sealed key on disk is the key that signed.
        let sealed = fs::read(paths.key()).unwrap();
        let seed: [u8; 32] = FakeCreds.unseal(&sealed).unwrap().try_into().unwrap();
        assert_eq!(signing::public_key(&SigningKey::from_bytes(&seed)), pk);

        // Enrolled already: no request, and the key is not replaced.
        let again = enrol(&paths, &host, &facts()).unwrap();
        assert!(matches!(again, Enrolment::Enrolled(_)));
        assert_eq!(fs::read(paths.key()).unwrap(), sealed);
    }

    #[test]
    fn enrol_refusals_keep_the_token() {
        for (status, code) in [(401, "invalid_token"), (409, "key_in_use")] {
            let server = FakeServer::start(vec![(status, format!(r#"{{"error":"{code}"}}"#))]);
            let dir = TempDir::new();
            let paths = setup(&dir, &server.base, Some(TOKEN));
            let (fp, bc) = (FakeFlatpak::default(), FakeBootc::booted("img"));
            let host = Host {
                flatpak: &fp,
                bootc: &bc,
                creds: &FakeCreds,
            };

            let out = enrol(&paths, &host, &facts()).unwrap();
            assert_eq!(out, Enrolment::Refused(code.into()));
            assert_eq!(state::read_token(&paths).unwrap().as_deref(), Some(TOKEN));
            assert!(!paths.device().exists());
            assert_eq!(server.requests().len(), 1);
        }
    }

    #[test]
    fn enrol_without_a_token_sends_nothing() {
        let dir = TempDir::new();
        // Nothing listens here; a request would fail the test.
        let paths = setup(&dir, "http://127.0.0.1:9", None);
        let (fp, bc) = (FakeFlatpak::default(), FakeBootc::booted("img"));
        let host = Host {
            flatpak: &fp,
            bootc: &bc,
            creds: &FakeCreds,
        };
        assert_eq!(enrol(&paths, &host, &facts()).unwrap(), Enrolment::NoToken);
        assert!(!paths.key().exists());
    }

    #[test]
    fn checkin_reconciles_and_reports_the_result_next_time() {
        let desired = r#"{
          "device_id": "dev_1",
          "desired": {
            "image": { "ref": "img:next" },
            "remotes": [{ "name": "flathub", "url": "https://dl.flathub.org/repo/", "gpg_key": "AAEC" }],
            "apps": [{ "id": "org.mozilla.firefox", "branch": "stable", "remote": "flathub", "state": "installed" },
                     { "id": "org.broken.App", "branch": "stable", "remote": "flathub", "state": "installed" }]
          },
          "interval_s": 900,
          "server_time": 1760400000
        }"#;
        let server = FakeServer::start(vec![(200, desired.into()), (200, desired.into())]);
        let dir = TempDir::new();
        let (paths, key) = enrolled(&dir, &server.base);
        let fp = FakeFlatpak::default();
        fp.fail_install("org.broken.App");
        fp.add_system(app("org.kde.kate", "fedora"));
        let bc = FakeBootc::booted("img:stable");
        let host = Host {
            flatpak: &fp,
            bootc: &bc,
            creds: &FakeCreds,
        };
        let mut agent = Agent::load(paths.clone(), host).unwrap();

        let Tick::Sleep(d) = agent.tick() else {
            panic!("revoked")
        };
        assert!(
            d >= Duration::from_secs(810) && d <= Duration::from_secs(990),
            "{d:?}"
        );
        assert!(fp.system_has("org.mozilla.firefox"));
        assert_eq!(bc.switches(), ["img:next"]);
        let managed: Managed = state::read_json(&paths.managed()).unwrap().unwrap();
        assert!(managed.has_app("org.mozilla.firefox", "stable"));
        assert!(
            state::read_json::<Status>(&paths.status())
                .unwrap()
                .is_some()
        );

        agent.tick();
        let reqs = server.requests();
        assert_eq!(reqs.len(), 2);
        let pk = signing::public_key(&key);
        for r in &reqs {
            assert_eq!(
                (r.method.as_str(), r.url.as_str()),
                ("POST", "/api/agent/v1/checkin")
            );
            assert_eq!(r.header("X-Mauvely-Device"), Some("dev_1"));
            verify(r, &pk);
        }

        let first = body(&reqs[0]);
        assert_eq!(
            first["last_apply"],
            serde_json::json!({ "ok": true, "errors": [] })
        );
        assert_eq!(first["booted_image"], "img:stable");
        assert_eq!(first["staged_image"], Value::Null);
        assert_eq!(first["flatpaks"][0]["id"], "org.kde.kate");
        assert_eq!(first["flatpaks"][0]["managed"], false);

        let second = body(&reqs[1]);
        assert_eq!(second["last_apply"]["ok"], false);
        let errors = second["last_apply"]["errors"].as_array().unwrap();
        assert_eq!(errors.len(), 1);
        assert!(errors[0].as_str().unwrap().contains("org.broken.App"));
        assert_eq!(second["staged_image"], "img:next");
        assert_eq!(second["remotes"], serde_json::json!(["flathub"]));
        let firefox = second["flatpaks"]
            .as_array()
            .unwrap()
            .iter()
            .find(|f| f["id"] == "org.mozilla.firefox")
            .unwrap();
        assert_eq!(firefox["managed"], true);
        assert_eq!(firefox["remote"], "flathub");
        assert_eq!(second["agent_version"], AGENT_VERSION);
    }

    #[test]
    fn flatpaks_update_after_the_installs_and_not_again_after_a_restart() {
        let desired = r#"{"device_id":"dev_1","desired":{"image":null,
          "remotes":[{ "name": "flathub", "url": "https://dl.flathub.org/repo/", "gpg_key": "AAEC" }],
          "apps":[{ "id": "org.mozilla.firefox", "branch": "stable", "remote": "flathub", "state": "installed" }]},
          "interval_s":900}"#;
        let server = FakeServer::start(vec![(200, desired.into()); 3]);
        let dir = TempDir::new();
        let (paths, _) = enrolled(&dir, &server.base);
        let (fp, bc) = (FakeFlatpak::default(), FakeBootc::booted("img"));
        fp.fail_update(true);
        let mut agent = Agent::load(
            paths.clone(),
            Host {
                flatpak: &fp,
                bootc: &bc,
                creds: &FakeCreds,
            },
        )
        .unwrap();

        // The update comes after the install, and fails.
        agent.tick();
        assert_eq!(
            fp.log(),
            [
                "remote-add flathub https://dl.flathub.org/repo/ key=000102",
                "install flathub org.mozilla.firefox//stable",
                "update",
                "uninstall --unused",
            ]
        );

        // So it is tried again at the next check-in, and succeeds.
        fp.clear_log();
        fp.fail_update(false);
        agent.tick();
        assert_eq!(fp.log(), ["update", "uninstall --unused"]);
        let managed: Managed = state::read_json(&paths.managed()).unwrap().unwrap();
        assert!(managed.flatpaks_updated > 0);

        // A restart inside six hours does not run it again.
        fp.clear_log();
        let mut agent = Agent::load(
            paths,
            Host {
                flatpak: &fp,
                bootc: &bc,
                creds: &FakeCreds,
            },
        )
        .unwrap();
        agent.tick();
        assert!(fp.log().is_empty(), "{:?}", fp.log());

        let reqs = server.requests();
        assert_eq!(reqs.len(), 3);
        let errors = body(&reqs[1])["last_apply"]["errors"].clone();
        assert_eq!(errors.as_array().unwrap().len(), 1, "{errors}");
        assert!(errors[0].as_str().unwrap().starts_with("flatpak update:"));
    }

    #[test]
    fn an_unreachable_server_backs_off_and_a_success_resets() {
        let ok = r#"{"device_id":"dev_1","desired":{"image":null,"remotes":[],"apps":[]},"interval_s":30}"#;
        let server = FakeServer::start(vec![
            (503, "".into()),
            (502, "<html>".into()),
            (403, r#"{"error":"forbidden"}"#.into()),
            (200, ok.into()),
        ]);
        let dir = TempDir::new();
        let (paths, _) = enrolled(&dir, &server.base);
        let (fp, bc) = (FakeFlatpak::default(), FakeBootc::booted("img"));
        let mut agent = Agent::load(
            paths,
            Host {
                flatpak: &fp,
                bootc: &bc,
                creds: &FakeCreds,
            },
        )
        .unwrap();

        let secs = |t: Tick| match t {
            Tick::Sleep(d) => d.as_secs_f64(),
            Tick::Revoked => panic!("revoked"),
        };
        let a = secs(agent.tick());
        let b = secs(agent.tick());
        // A 403 that is not `revoked` is a failure, not a revocation.
        let c = secs(agent.tick());
        assert!((54.0..=66.0).contains(&a), "{a}");
        assert!((108.0..=132.0).contains(&b), "{b}");
        assert!((216.0..=264.0).contains(&c), "{c}");
        // interval_s 30 is floored to 60.
        let d = secs(agent.tick());
        assert!((54.0..=66.0).contains(&d), "{d}");
        assert_eq!(server.requests().len(), 4);

        // Nothing listening at all.
        let dir = TempDir::new();
        let (paths, _) = enrolled(&dir, "http://127.0.0.1:9");
        let mut agent = Agent::load(
            paths,
            Host {
                flatpak: &fp,
                bootc: &bc,
                creds: &FakeCreds,
            },
        )
        .unwrap();
        let e = secs(agent.tick());
        assert!((54.0..=66.0).contains(&e), "{e}");
    }

    #[test]
    fn run_enrols_then_stops_when_revoked() {
        let server = FakeServer::start(vec![
            (401, r#"{"error":"invalid_token"}"#.into()),
            (201, ENROLLED.into()),
            (403, r#"{"error":"revoked"}"#.into()),
        ]);
        let dir = TempDir::new();
        let paths = setup(&dir, &server.base, Some(TOKEN));
        let fp = FakeFlatpak::default();
        fp.add_system(app("org.kde.kate", "fedora"));
        let bc = FakeBootc::booted("img");
        let host = Host {
            flatpak: &fp,
            bootc: &bc,
            creds: &FakeCreds,
        };

        let mut sleeps = Vec::new();
        run(&paths, host, &facts, &mut |d| sleeps.push(d)).unwrap();

        // One backoff after the refusal; none after the revocation.
        assert_eq!(sleeps.len(), 1);
        assert!(sleeps[0] >= Duration::from_secs(54) && sleeps[0] <= Duration::from_secs(66));
        assert!(!paths.enrol().exists());
        let reqs = server.requests();
        let urls: Vec<_> = reqs.iter().map(|r| r.url.as_str()).collect();
        assert_eq!(
            urls,
            [
                "/api/agent/v1/enrol",
                "/api/agent/v1/enrol",
                "/api/agent/v1/checkin"
            ]
        );
        // The two attempts used different keys.
        assert_ne!(body(&reqs[0])["public_key"], body(&reqs[1])["public_key"]);
        // Revoked: the machine is left as it is.
        assert!(fp.log().is_empty());
        assert!(fp.system_has("org.kde.kate"));
    }
}
