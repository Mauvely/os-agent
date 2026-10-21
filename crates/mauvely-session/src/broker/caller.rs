//! Who may ask the broker for what. Pure: `peer` finds the caller, and this
//! decides.
//!
//! The identity is the Flatpak sandbox the caller runs in, read from its
//! `/.flatpak-info`, and the installation it came from, read from that file's
//! `app-path`. Not the binary: the browsers' native host runs inside the
//! browser's sandbox and is the browser here (brief 22's S0, design note 5).
//! `docs/broker.md` has what each check stops and what it cannot.

use std::collections::HashMap;

/// The clients the broker mints app sessions for: website-main's
/// `KNOWN_CLIENTS` (`worker/routes/device.ts`) without the two brokers,
/// `suite` and `os`, which the server never mints. Never narrower than the
/// server's list: a refusal here only shows as the app opening a browser.
pub const BROKERABLE: [&str; 8] = [
    "assist", "cli", "compose", "mail", "office", "relay", "review", "snap",
];

/// The browsers `browser` is answered to. mauvelyd's `reconcile::BROWSERS`
/// grants them the socket and must name the same ones.
pub const BROWSERS: [&str; 2] = ["org.chromium.Chromium", "org.mozilla.firefox"];

/// The system installation. Only root writes here, and the agent installs
/// only here (`flatpak --system`).
const SYSTEM_APPS: &str = "/var/lib/flatpak/app/";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Caller {
    /// Not in a Flatpak sandbox: its root has no `.flatpak-info`.
    Host,
    /// What its `/.flatpak-info` says.
    Sandbox(Sandbox),
    /// Gone, unreadable or malformed. The reason is for the log.
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sandbox {
    /// `[Application] name`.
    pub app: String,
    /// `[Instance] app-path`: the deploy's `files` directory, which names the
    /// installation.
    pub app_path: String,
}

impl Caller {
    /// For the log.
    pub fn describe(&self) -> String {
        match self {
            Caller::Host => "a host process".into(),
            Caller::Sandbox(s) => s.app.clone(),
            Caller::Unknown(why) => format!("an unidentified process ({why})"),
        }
    }
}

/// What the caller asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ask<'a> {
    /// An app session for this client key.
    Token(&'a str),
    /// A browser session.
    Browser,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Grant {
    /// An app session for this client key.
    App(&'static str),
    /// A browser session for this browser's app id.
    Browser(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// The client is not one the server mints for.
    UnknownClient,
    /// Everything below is `forbidden` on the wire.
    Host,
    Unidentified(String),
    /// Asked for what its app id may not have.
    NotAllowed(String),
    /// The right app id, but not from the system installation.
    NotSystem {
        app: String,
        app_path: String,
    },
}

impl Refusal {
    /// For the log. The caller is told `unknown_client` or `forbidden`.
    pub fn why(&self) -> String {
        match self {
            Refusal::UnknownClient => "not a client the server mints".into(),
            Refusal::Host => "not in a Flatpak sandbox".into(),
            Refusal::Unidentified(why) => why.clone(),
            Refusal::NotAllowed(app) => format!("{app} may not ask for it"),
            Refusal::NotSystem { app_path, .. } => {
                format!("not a system install ({app_path})")
            }
        }
    }
}

/// Whether `caller` may have what it asked for.
///
/// - A Mauvely app is `com.mauvely.<key>`, installed system-wide, and asks
///   only for its own `<key>`.
/// - `browser` goes only to a system-wide Firefox or Chromium.
/// - Nothing else is answered: host processes, `--user` installs, any other
///   app, and a caller that could not be identified.
pub fn authorise(caller: &Caller, ask: Ask) -> Result<Grant, Refusal> {
    // Before the caller, as Suite's broker does: a key the server would
    // refuse is refused whoever asks.
    let key = match ask {
        Ask::Token(client) => Some(
            *BROKERABLE
                .iter()
                .find(|k| **k == client)
                .ok_or(Refusal::UnknownClient)?,
        ),
        Ask::Browser => None,
    };
    let sandbox = match caller {
        Caller::Host => return Err(Refusal::Host),
        Caller::Unknown(why) => return Err(Refusal::Unidentified(why.clone())),
        Caller::Sandbox(s) => s,
    };
    let not_allowed = || Refusal::NotAllowed(sandbox.app.clone());
    // The id is ours, from the lists above, never built from the caller's
    // file, so the path check below compares against a known prefix.
    let (grant, id) = match key {
        Some(key) => (Grant::App(key), format!("com.mauvely.{key}")),
        None => {
            let id = *BROWSERS
                .iter()
                .find(|b| **b == sandbox.app)
                .ok_or_else(not_allowed)?;
            (Grant::Browser(id), id.to_owned())
        }
    };
    if sandbox.app != id {
        return Err(not_allowed());
    }
    if !system_install(&id, &sandbox.app_path) {
        return Err(Refusal::NotSystem {
            app: sandbox.app.clone(),
            app_path: sandbox.app_path.clone(),
        });
    }
    Ok(grant)
}

/// Whether `app_path` is a deploy of `id` in the system installation:
/// `/var/lib/flatpak/app/<id>/` and at least one plain component below it.
/// A user install, another app's directory, a lookalike id
/// (`<id>-evil`), and any `.`, `..` or empty component are refused.
pub fn system_install(id: &str, app_path: &str) -> bool {
    let Some(rest) = app_path
        .strip_prefix(SYSTEM_APPS)
        .and_then(|r| r.strip_prefix(id))
        .and_then(|r| r.strip_prefix('/'))
    else {
        return false;
    };
    !rest.is_empty()
        && rest
            .split('/')
            .all(|c| !c.is_empty() && c != "." && c != ".." && !c.contains('\0'))
}

/// Reads a `.flatpak-info`. It is a GLib key file that flatpak writes; this
/// reads it strictly and fails on anything GLib would not load, and on a
/// group or key given twice, which flatpak never writes.
pub fn parse_flatpak_info(text: &str) -> Result<Sandbox, String> {
    let file = KeyFile::parse(text)?;
    let app = file
        .string("Application", "name")?
        .ok_or("no [Application] name")?;
    let app_path = file
        .string("Instance", "app-path")?
        .ok_or("no [Instance] app-path")?;
    if app.is_empty() || app_path.is_empty() {
        return Err("an empty name or app-path".into());
    }
    Ok(Sandbox { app, app_path })
}

/// The raw values, by group and key. Values are unescaped only when read, as
/// GLib does: an odd escape in a value nobody reads is not an error.
struct KeyFile<'a> {
    values: HashMap<(&'a str, &'a str), &'a str>,
}

impl<'a> KeyFile<'a> {
    fn parse(text: &'a str) -> Result<Self, String> {
        let mut values = HashMap::new();
        let mut groups: Vec<&str> = Vec::new();
        for raw in text.split('\n') {
            let line = raw.strip_suffix('\r').unwrap_or(raw).trim_start();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(group) = line.strip_prefix('[') {
                let name = group
                    .strip_suffix(']')
                    .filter(|n| !n.is_empty() && !n.contains(['[', ']']))
                    .ok_or_else(|| format!("a bad group line: {line:?}"))?;
                if groups.contains(&name) {
                    return Err(format!("[{name}] appears twice"));
                }
                groups.push(name);
                continue;
            }
            let group = *groups.last().ok_or("a key before any group")?;
            let (key, value) = line
                .split_once('=')
                .ok_or_else(|| format!("a line that is not a key: {line:?}"))?;
            let key = key.trim_end();
            if key.is_empty() {
                return Err("an empty key".into());
            }
            if values.insert((group, key), value.trim_start()).is_some() {
                return Err(format!("{key} appears twice in [{group}]"));
            }
        }
        Ok(KeyFile { values })
    }

    fn string(&self, group: &str, key: &str) -> Result<Option<String>, String> {
        self.values
            .get(&(group, key))
            .map(|v| unescape(v).ok_or_else(|| format!("a bad escape in {key}")))
            .transpose()
    }
}

/// GLib's string escapes: `\s`, `\n`, `\t`, `\r` and `\\`. Anything else is
/// refused rather than guessed at.
fn unescape(value: &str) -> Option<String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        out.push(match chars.next()? {
            's' => ' ',
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            '\\' => '\\',
            _ => return None,
        });
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A real `/.flatpak-info`, from a user install (S0, spike 2).
    const USER_REAL: &str = include_str!("../../fixtures/flatpak-info-user-real.ini");

    const COMMIT: &str = "9c1e95bd09dbd35ed7e9e861258c7376594bb3318b9d1fa85902ccf68d0b6ff1";

    fn system(id: &str) -> String {
        format!("/var/lib/flatpak/app/{id}/x86_64/stable/{COMMIT}/files")
    }

    fn sandbox(app: &str, app_path: &str) -> Caller {
        Caller::Sandbox(Sandbox {
            app: app.into(),
            app_path: app_path.into(),
        })
    }

    fn info(app: &str, app_path: &str) -> String {
        format!(
            "[Application]\nname={app}\nruntime=runtime/org.freedesktop.Platform/x86_64/25.08\n\n\
             [Instance]\ninstance-id=1\napp-path={app_path}\nbranch=stable\n"
        )
    }

    #[test]
    fn a_mauvely_app_gets_its_own_key_only() {
        for key in BROKERABLE {
            let id = format!("com.mauvely.{key}");
            let me = sandbox(&id, &system(&id));
            assert_eq!(authorise(&me, Ask::Token(key)), Ok(Grant::App(key)));
            for other in BROKERABLE.iter().filter(|k| **k != key) {
                assert_eq!(
                    authorise(&me, Ask::Token(other)),
                    Err(Refusal::NotAllowed(id.clone())),
                    "{id} asking for {other}"
                );
            }
            assert_eq!(
                authorise(&me, Ask::Browser),
                Err(Refusal::NotAllowed(id.clone()))
            );
        }
    }

    #[test]
    fn only_the_servers_clients_are_brokered() {
        let compose = sandbox("com.mauvely.compose", &system("com.mauvely.compose"));
        // The brokers, apps the server has no client for, and lookalikes.
        for client in ["suite", "os", "play", "sotto", "", "Compose", "compose "] {
            assert_eq!(
                authorise(&compose, Ask::Token(client)),
                Err(Refusal::UnknownClient),
                "{client:?}"
            );
        }
        // Refused before the caller is looked at, as Suite does.
        let suite = sandbox("com.mauvely.suite", &system("com.mauvely.suite"));
        assert_eq!(
            authorise(&suite, Ask::Token("suite")),
            Err(Refusal::UnknownClient)
        );
        assert_eq!(
            authorise(&Caller::Host, Ask::Token("os")),
            Err(Refusal::UnknownClient)
        );
    }

    #[test]
    fn lookalike_app_ids_are_not_the_app() {
        for id in [
            "com.mauvely.compose.Devel",
            "com.mauvely.Compose",
            "com.mauvely.compose2",
            "net.mauvely.compose.app",
            "com.mauvely",
            "com.mauvely.",
            "xcom.mauvely.compose",
        ] {
            let caller = sandbox(id, &system(id));
            assert_eq!(
                authorise(&caller, Ask::Token("compose")),
                Err(Refusal::NotAllowed(id.into())),
                "{id}"
            );
        }
    }

    #[test]
    fn browser_goes_to_the_system_browsers_only() {
        for id in BROWSERS {
            let browser = sandbox(id, &system(id));
            assert_eq!(authorise(&browser, Ask::Browser), Ok(Grant::Browser(id)));
            // And they get nothing else.
            assert_eq!(
                authorise(&browser, Ask::Token("compose")),
                Err(Refusal::NotAllowed(id.into()))
            );
        }
        for id in [
            "org.mozilla.Firefox",
            "org.mozilla.firefox.Devel",
            "org.mozilla.firefox_beta",
            "org.chromium.Chromium.Extension.mauvely",
            "com.google.Chrome",
            "io.gitlab.librewolf-community",
            "com.brave.Browser",
            "org.kde.falkon",
        ] {
            assert_eq!(
                authorise(&sandbox(id, &system(id)), Ask::Browser),
                Err(Refusal::NotAllowed(id.into())),
                "{id}"
            );
        }
    }

    #[test]
    fn host_and_unidentified_callers_get_nothing() {
        for ask in [Ask::Token("compose"), Ask::Browser] {
            assert_eq!(authorise(&Caller::Host, ask), Err(Refusal::Host));
            assert_eq!(
                authorise(&Caller::Unknown("exited".into()), ask),
                Err(Refusal::Unidentified("exited".into()))
            );
        }
    }

    #[test]
    fn a_user_install_is_not_the_system_one() {
        // A user install presents the same app id; only the path differs.
        let home = "/home/ada/.local/share/flatpak/app";
        for (id, ask) in [
            ("org.mozilla.firefox", Ask::Browser),
            ("org.chromium.Chromium", Ask::Browser),
            ("com.mauvely.compose", Ask::Token("compose")),
        ] {
            let path = format!("{home}/{id}/x86_64/stable/{COMMIT}/files");
            assert_eq!(
                authorise(&sandbox(id, &path), ask),
                Err(Refusal::NotSystem {
                    app: id.into(),
                    app_path: path.clone()
                })
            );
        }
        // The real one from S0 parses, and is refused for the same reason.
        let real = parse_flatpak_info(USER_REAL).unwrap();
        assert_eq!(real.app, "com.mauvely.s0granted");
        assert!(
            real.app_path
                .starts_with("/home/timuri/.cache/mauvely-flatpak/user/app/")
        );
        assert!(!system_install(&real.app, &real.app_path));
    }

    #[test]
    fn the_install_path_is_checked_exactly() {
        let id = "org.mozilla.firefox";
        assert!(system_install(id, &system(id)));
        assert!(system_install(
            id,
            "/var/lib/flatpak/app/org.mozilla.firefox/x"
        ));
        for path in [
            // Another app's deploy, and a lookalike directory.
            "/var/lib/flatpak/app/org.kde.kate/x86_64/stable/c/files",
            "/var/lib/flatpak/app/org.mozilla.firefox-evil/x86_64/stable/c/files",
            "/var/lib/flatpak/app/org.mozilla.firefoxx/x86_64/stable/c/files",
            // Nothing below the app's directory.
            "/var/lib/flatpak/app/org.mozilla.firefox",
            "/var/lib/flatpak/app/org.mozilla.firefox/",
            // Walking out of it.
            "/var/lib/flatpak/app/org.mozilla.firefox/../../../../home/ada/.local/share/flatpak/app/org.mozilla.firefox/x86_64/stable/c/files",
            "/var/lib/flatpak/app/org.mozilla.firefox/x86_64/../../org.kde.kate/x86_64/stable/c/files",
            "/var/lib/flatpak/app/org.mozilla.firefox/./x86_64/stable/c/files",
            "/var/lib/flatpak/app/org.mozilla.firefox//x86_64/stable/c/files",
            "/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/c/files/",
            // Not that installation, or not absolute.
            "/var/lib/flatpak/runtime/org.mozilla.firefox/x86_64/stable/c/files",
            "/var/lib/flatpakx/app/org.mozilla.firefox/x86_64/stable/c/files",
            "/run/host/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/c/files",
            "var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/c/files",
            "//var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/c/files",
            "/var/lib/flatpak/app/org.mozilla.firefox/x86_64/stable/c\0/files",
            "",
        ] {
            assert!(!system_install(id, path), "{path:?}");
        }
    }

    #[test]
    fn parses_what_flatpak_writes() {
        let s = parse_flatpak_info(&info("org.mozilla.firefox", &system("org.mozilla.firefox")))
            .unwrap();
        assert_eq!(
            s,
            Sandbox {
                app: "org.mozilla.firefox".into(),
                app_path: system("org.mozilla.firefox")
            }
        );
        // Comments, blank lines, CRLF, spaces around `=`, and GLib's escapes.
        let s = parse_flatpak_info(
            "# written by flatpak\r\n[Application]\r\n  name = org.mozilla.firefox\r\n\r\n\
             [Instance]\r\napp-path=/var/lib/flatpak/app/org.mozilla.firefox/a\\sb/c\r\n",
        )
        .unwrap();
        assert_eq!(s.app, "org.mozilla.firefox");
        assert_eq!(s.app_path, "/var/lib/flatpak/app/org.mozilla.firefox/a b/c");
        // An odd escape in a key nobody reads does not matter.
        assert!(
            parse_flatpak_info(&format!("{}\n[Environment]\nX=a\\qb\n", info("a.b", "/p"))).is_ok()
        );
    }

    #[test]
    fn anything_odd_fails_closed() {
        let good = info("org.mozilla.firefox", &system("org.mozilla.firefox"));
        for bad in [
            String::new(),
            // A runtime sandbox has [Runtime], not [Application].
            good.replace("[Application]", "[Runtime]"),
            good.replace("name=", "nom="),
            good.replace("app-path=", "runtime-path="),
            good.replace("name=org.mozilla.firefox", "name="),
            // Given twice: which one would GLib believe?
            good.replace(
                "name=org.mozilla.firefox\n",
                "name=org.mozilla.firefox\nname=com.mauvely.compose\n",
            ),
            format!("{good}[Application]\nname=com.mauvely.compose\n"),
            format!("{good}[Instance]\nextra=1\n"),
            good.replace(
                "app-path=",
                "app-path=/var/lib/flatpak/app/org.mozilla.firefox/x\napp-path=",
            ),
            // Lines GLib refuses to load.
            format!("name=x\n{good}"),
            format!("{good}garbage\n"),
            format!("{good}[Broken\n"),
            format!("{good}[]\n"),
            format!("{good}=value\n"),
            // Escapes in what is read.
            good.replace("app-path=/", "app-path=\\x/"),
            good.replace("name=org.mozilla.firefox", "name=org.mozilla.firefox\\"),
        ] {
            assert!(parse_flatpak_info(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn the_two_lists_are_sorted_and_distinct() {
        // Edited by hand beside the server's list; keep them easy to compare.
        assert!(BROKERABLE.windows(2).all(|w| w[0] < w[1]));
        assert!(BROWSERS.windows(2).all(|w| w[0] < w[1]));
        assert!(!BROKERABLE.contains(&"suite") && !BROKERABLE.contains(&"os"));
    }
}
