use std::process::ExitCode;
use std::time::Duration;

use mauvelyd::agent::{self, Enrolment, Host};
use mauvelyd::bootc::SystemBootc;
use mauvelyd::creds::SystemdCreds;
use mauvelyd::flatpak::SystemFlatpak;
use mauvelyd::state::{self, Device, Paths, Status};
use mauvelyd::{AGENT_VERSION, api, facts, push};

const USAGE: &str = "usage: mauvelyd run | enrol | status | --version

  run      the service: enrol if needed, then check in
  enrol    one enrolment attempt, in the foreground
  status   device, server and last check-in

MAUVELY_CONFIG_DIR (default /etc/mauvely) and MAUVELY_STATE_DIR
(default /var/lib/mauvely) move the files.";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let paths = Paths::from_env();
    let creds = SystemdCreds {
        tpm2: facts::tpm2_present(),
    };
    let host = Host {
        flatpak: &SystemFlatpak,
        bootc: &SystemBootc,
        creds: &creds,
    };
    let result = match args.iter().map(String::as_str).collect::<Vec<_>>()[..] {
        ["run"] => run(&paths, host),
        ["enrol"] => enrol(&paths, host),
        ["status"] => status(&paths),
        ["--version"] => {
            println!("mauvelyd {AGENT_VERSION}");
            Ok(())
        }
        ["--help" | "-h"] => {
            println!("{USAGE}");
            Ok(())
        }
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("mauvelyd: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run(paths: &Paths, host: Host) -> Result<(), mauvelyd::Error> {
    eprintln!("mauvelyd {AGENT_VERSION} starting");
    agent::run(
        paths,
        host,
        &facts::collect,
        &mut std::thread::sleep,
        &mut push::start,
    )?;
    // Revoked. Stay up and idle, so systemd does not restart us into
    // checking in again; the machine is left as it is.
    loop {
        std::thread::sleep(Duration::from_secs(86_400));
    }
}

fn enrol(paths: &Paths, host: Host) -> Result<(), mauvelyd::Error> {
    match agent::enrol(paths, &host, &facts::collect())? {
        Enrolment::Enrolled(d) => {
            println!("enrolled: {} in {}", d.device_id, d.org_slug);
            Ok(())
        }
        Enrolment::NoToken => Err(mauvelyd::Error::Invalid(format!(
            "no enrolment token in {}",
            paths.enrol().display()
        ))),
        Enrolment::Refused(code) => Err(mauvelyd::Error::Invalid(format!(
            "the server refused enrolment: {code}; the token is kept"
        ))),
    }
}

fn status(paths: &Paths) -> Result<(), mauvelyd::Error> {
    let server = state::read_server(paths).unwrap_or_else(|e| format!("unset ({e})"));
    println!("server:        {server}");
    match state::read_json::<Device>(&paths.device())? {
        Some(d) => {
            println!("device:        {}", d.device_id);
            println!("organisation:  {}", d.org_slug);
        }
        None => {
            let token = if state::read_token(paths)?.is_some() {
                "a token is waiting"
            } else {
                "no token"
            };
            println!("device:        not enrolled ({token})");
        }
    }
    let last = match state::read_json::<Status>(&paths.status())? {
        Some(s) => format!(
            "{} ({}s ago)",
            utc(s.last_checkin),
            api::now().saturating_sub(s.last_checkin)
        ),
        None => "never".into(),
    };
    println!("last check-in: {last}");
    Ok(())
}

/// Unix seconds as `YYYY-MM-DD hh:mm:ss UTC`.
fn utc(secs: u64) -> String {
    // Howard Hinnant's civil_from_days.
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn utc_dates() {
        assert_eq!(super::utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(super::utc(1_760_400_000), "2025-10-14 00:00:00 UTC");
        assert_eq!(super::utc(951_782_400), "2000-02-29 00:00:00 UTC");
    }
}
