# os-agent

`mauvelyd`, the Mauvely OS device agent, and `mauvely-session`, its helper in
each graphical session, in Rust.

The design and the frozen agent API (enrolment, signed check-ins) are in brief
19: `Website/website-internal/docs/launch/plans/19-mauvely-os.md` in the
Mauvely superproject.

**One v2 path sits beside v1: the push channel, `GET /api/agent/v2/socket`**
(2026-10-22). A WebSocket to the device's Durable Object in website-devices,
signed as a check-in is, over `GET`, that path and an empty body. The agent
sends the text `ping` every 45 s and expects `pong`; the server sends
`{"t":"checkin"}`, which checks in now. Unknown types are ignored, so the
server may add them (brief 27 will). 403 `revoked` stops the channel until a
restart, 404 or 426 means a server without it (asked hourly), and the server
closes with 4000 when a newer connection replaces this one and 4003 on a
revoke. website-devices' `CLAUDE.md` has the server side. **The channel is an
optimisation:** if it never connects, the agent checks in on its interval
exactly as before.

- **The server side** is `Website/website-devices`.
- **The signing vectors** in `tests/vectors/` are shared with it. Change both
  sides together.

## Layout

A Cargo workspace with four crates, and the browser extension beside it:
- `crates/mauvelyd`: a library holding the logic and a thin binary
  (`main.rs`). The service unit is `dist/mauvelyd.service`. `mauvelyd login`
  is the login service (brief 26), in a unit of its own,
  `dist/mauvely-login.service`: `docs/login.md`.
- `crates/pam-mauvely`: `pam_mauvely`, a `cdylib` built to
  `target/release/libpam_mauvely.so`, which talks to the login service and
  nothing else (`docs/login.md`).
- `crates/mauvely-session`: a binary, run as the person by the user unit
  `dist/mauvely-session.service`. It tells them when a restart finishes an
  update (brief 22, U2), is the sign-in broker (S2): `docs/broker.md`, and
  says when an app the agent installed is ready. At each sign-in,
  `dist/mauvely-look.service` runs it once with `--before-shell`, before
  Plasma's shell starts: the one moment a panel reset can happen.
- `crates/mauvely-browser-host`: the browser extension's native messaging
  host (brief 22, S4), a static musl binary the browsers run inside their
  sandboxes. `docs/browser.md`.
- `browser/`: the extension (`browser/extension/`, Manifest V3, one source for
  Firefox and Chromium) and `package.py`, which makes the CRX, the signed XPI
  and both browsers' policies for os-image.

`mauvelyd`'s modules:

| Module | Holds |
|---|---|
| `signing` | The `mauvely-device-v1` message and the `X-Mauvely-*` headers |
| `api` | The wire types and the signed `ureq` client |
| `flatpak`, `bootc`, `creds` | A trait each, the real CLI behind it, and its argv builders and output parsers |
| `reconcile` | Brief 19's reconcile rules, as one function over the traits, and brief 22's Flatpak updates |
| `desktop` | Brief 25's desktop policy as KDE Kiosk files in `/var/lib/mauvely-desktop/` (`xdg/kdeglobals`, which the image puts in `XDG_CONFIG_DIRS`, and `policy.json` for mauvely-session) |
| `agent` | Enrolment, one check-in (`Agent::tick`) and the service loop (`run`) |
| `push` | The push channel: one thread on a blocking `tungstenite` socket (TLS is rustls on ring with webpki-roots, as `ureq`), reconnecting on `schedule`'s backoff, and `Wake`, what `run` sleeps on: its interval, cut short by `{"t":"checkin"}` but never within 5 s of the last check-in, and never during a backoff |
| `login` | The login service: `wire` (the protocol), `socket` (`SO_PEERCRED`, limits, a thread per connection), `service` (the rules of `auth`, `code` and `account`), `people` (`desired.people` and the greeter's file), `names` (usernames, NSS), `door` (website-devices' login door, website-main's KDF upgrade), `kdf` (Argon2id), `cache` (the sealed offline cache), `userdb` (`/etc/userdb` drop-ins), `handoff` (`/run/mauvely/login/<uid>`) |
| `state`, `facts`, `schedule` | Files on disk (`/etc/mauvely`, `/var/lib/mauvely`, and `/run/mauvely/installed.json`, which everyone reads), hardware facts, backoff and jitter |
| `fake` | Test doubles and a `tiny_http` fake server, test builds only |

`mauvely-session`'s modules:

| Module | Holds |
|---|---|
| `staged` | Whether an update is staged, and saying so once |
| `ready` | "<App> is ready": the agent's `/run/mauvely/installed.json`, what this person has been told, and Open |
| `look` | The collection's desktop preset, applied once per change of `/var/lib/mauvely-desktop/policy.json` with `plasma-apply-lookandfeel` and the preset's `layoutdefaults`, and a panel reset before the shell starts, behind a trait |
| `browserhost` | The browser extension's native host, copied with its manifest into each browser's `~/.var/app` directory at login and every 5 minutes |
| `signin` | The sign-in window, `/usr/bin/mauvely-signin` (os-installer's `signin/`): started with the code on stdin, told to finish after the claim, `closed` read back |
| `dialog` | The sign-in offer and code as `kdialog` windows, where the sign-in window is missing or fails; the code goes to kdialog on stdin |
| `broker::caller` | Who may ask the broker for what, pure |
| `broker::peer` | Finding the caller: `SO_PEERCRED`, `SO_PEERPIDFD`, `/proc/<pid>/root/.flatpak-info`, its `/app` on disk, the deploy's remote |
| `broker::wire`, `broker::socket` | Suite's framing; the socket and a thread per caller |
| `broker::accounts`, `broker::seal` | website-main's device link and mints; the `os` session at rest |
| `broker::login` | The `os` session a Mauvely login made, handed over by `mauvelyd` |
| `broker::testing` | Test doubles and a `tiny_http` fake server, test builds only |

## Rules

- **The daemon runs as root.** Every external command goes through a trait, so
  it can be faked in tests: `flatpak`, `bootc` (and `rpm-ostree`, behind the
  same trait), `systemd-creds`. Never shell out with an interpolated string:
  argv vectors only, built by small functions that are tested without running
  anything.
- **A value from the server that starts with `-` is refused** before it
  reaches an argv (`command::operand`).
- **Only `--system` Flatpak commands.** A user's `--user` installs are never
  listed or touched.
- **`pam_mauvely` never touches the network, opens no file and starts no
  thread.** It talks to `/run/mauvely/auth.sock` and fails fast and closed
  (`PAM_AUTHINFO_UNAVAIL`) when the daemon is missing or silent. No panic
  crosses into C (`catch_unwind`), every FFI call has its `SAFETY` comment,
  and our copies of the password and code are wiped. `PAM_AUTHTOK` stays
  set for the wallet modules after it. Its `socket=` argument works in debug
  builds only.
- **The login socket's rules** (`docs/login.md`):
  - who asks is `SO_PEERCRED`'s effective uid: root about anyone, any other
    uid only about the person whose uid it is, and only root for
    `plasmalogin`;
  - **only `plasmalogin` goes online, and only it asks for a code.** Every
    other service checks the offline cache and never the server;
  - **the cache only when the server cannot be reached**, at the login
    screen, within its `offlineDays`: never after a refusal;
  - the device's say (`desired.people`) before anything is sent;
  - the cache's verifier is never the `authSecret`, and the cache is never
    sent anywhere;
  - a name NSS knows that is not ours is `not_mauvely` (`PAM_IGNORE`); a name
    on no list is never ignored;
  - the field names and reasons are fixed: os-image's greeter and session
    rely on them. Add, never rename.
  - Each rule has a test that fails when it is broken; change a rule with its
    test.
- **`mauvelyd login` runs in its own unit, before the display manager**, and
  never waits for the network: the agent's unit does. They share files, not
  memory.
- **`tests/vectors/kdf.json` is a copy of website-main's
  `shared/vectors/kdf.json`.** Do not edit it here; copy it over when it
  changes.
- **userdb records are ours only with `"service": "com.mauvely.Users"`.**
  Nothing touches a record without it, and a uid or name another account has
  is never taken over.
- **Never log a device key, an enrolment token, a session token, a password
  or a code.** The
  seed and the `os` session travel to `systemd-creds` over stdin, never as an
  argument or a file. The broker's session types print `<redacted>` for
  `{:?}`.
- **The device-link code never reaches an argv or a URL**, which every local
  user can read, and with it approve the link for their own account. The
  sign-in window gets it as a JSON line on stdin and has no arguments
  (`signin`); the kdialog code window is `kdialog --textbox -`, fed on stdin
  (`dialog`). Only the sign-in window's own page carries it in its address,
  inside its own process.
- **The sign-in window signs its session out only after the claim.**
  website-main re-checks the approving session when the broker's poll claims
  the link, so `finish` comes from `signed_in` and `withdraw`, never earlier.
- **`MAUVELY_SIGNIN` moves `/usr/bin/mauvely-signin` in debug builds only**,
  like `MAUVELY_CONFIG_DIR`.
- **`cargo test` must pass** without root, a TPM, flatpak, PAM or network.
  `tests/login/` holds the real PAM runs (local, and in Kinoite with podman).
  `cargo clippy --all-targets -- -D warnings` stays clean; code is
  `cargo fmt`-formatted.
- **No async runtime.** It is one loop, and it blocks. `mauvely-session` uses
  zbus's blocking API, which runs zbus's own executor thread; no tokio.
  `mauvelyd`'s push channel is one more blocking thread, with a read timeout.
- **One TLS stack: rustls with `ring` and the compiled-in `webpki-roots`.**
  `ureq` and the push channel share it. Never aws-lc or native-tls: check
  `cargo tree -i aws-lc-rs` (and `-i openssl-sys`) finds nothing after adding
  a crate.
- **`mauvely-session` runs as the person, never as root.** It changes nothing
  on the machine but its own files in `$XDG_STATE_HOME/mauvely/` and its
  socket in `$XDG_RUNTIME_DIR/mauvely/`, asks logind for a reboot only when
  the person clicks Restart, and opens an app only when they click Open. The
  exceptions are the desktop preset (`look`), which writes the person's own
  KDE config through Plasma's tools, once per change an admin makes, and the
  browser host (`browserhost`): the binary and its manifest in each browser's
  own `~/.var/app/<id>/` native messaging directory, and nothing else there.
- **`/var/lib/mauvely-desktop` is the agent's, not `/var/lib/mauvely`**, which
  systemd keeps `0700` (`StateDirectoryMode`), so nobody else could read a
  policy under it. It is `0755` with `0644` files, written by `desktop`, and
  stays across boots so a lock holds on a machine that starts offline. A
  `ProtectSystem=` in `dist/mauvelyd.service` would need `ReadWritePaths=` for
  it; a test reads the unit for that.
- **`broker::caller` is the broker's security boundary.** Change it with its
  tests. `BROKERABLE` is never narrower than website-main's `KNOWN_CLIENTS`
  without `suite` and `os`, and `BROWSERS` names the same browsers as
  mauvelyd's `reconcile::BROWSERS`.
- **The browser extension fetches nothing and holds no remote code.** Its
  permissions are `nativeMessaging`, `cookies` and the two accounts domains,
  and a test holds them there. It sets a cookie only for the origin the host
  names, and the host passes on only `https://mauvely.com` and
  `https://mauvely.dev`.
- **`mauvely-browser-host` is std and serde_json, and never touches the
  network.** It runs inside the browser's sandbox from the person's
  `~/.var/app`, so it is built static for `x86_64-unknown-linux-musl`
  (`docs/browser.md`). It never logs what the broker says.
- **The Chromium extension's id is its key.** `manifest.chromium.json`'s `key`
  is a throwaway key's public half until the real `CRX_SIGNING_KEY` exists; a
  new key means a new `key` there and a new `browserhost::CHROMIUM_ORIGIN`
  (`docs/browser.md`, "The ids"). Bump `version` in both manifests with any
  change to the extension: AMO signs a version once.
- The extension's and the packaging's tests are not cargo's:
  `node --test browser/extension/test/*.test.cjs` and
  `python3 -I browser/test_package.py`.
- `CARGO_BUILD_JOBS=24` at most here, 8 on CI.

## Handing off

`HANDOFF.md` is overwritten each session. It holds what is half-done, what was
tried and rejected, and what compiles but has never run.
