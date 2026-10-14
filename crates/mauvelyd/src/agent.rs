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
use crate::reconcile::{Inventory, reconcile};
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
        let seed: [u8; 32] = host
            .creds
            .unseal(&sealed)?
            .try_into()
            .map_err(|_| Error::Invalid(format!("{}: not a 32-byte seed", key_path.display())))?;
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
                let wait = schedule::jitter(self.backoff.next());
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
        sleep(schedule::jitter(backoff.next()));
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
