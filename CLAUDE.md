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

A Cargo workspace with two crates:
- `crates/mauvelyd`: a library holding the logic and a thin binary
  (`main.rs`). The service unit is `dist/mauvelyd.service`.
- `crates/mauvely-session`: a binary, run as the person by the user unit
  `dist/mauvely-session.service`. It tells them when a restart finishes an
  update (brief 22, U2), is the sign-in broker (S2): `docs/broker.md`, and
  says when an app the agent installed is ready.

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
| `state`, `facts`, `schedule` | Files on disk (`/etc/mauvely`, `/var/lib/mauvely`, and `/run/mauvely/installed.json`, which everyone reads), hardware facts, backoff and jitter |
| `fake` | Test doubles and a `tiny_http` fake server, test builds only |

`mauvely-session`'s modules:

| Module | Holds |
|---|---|
| `staged` | Whether an update is staged, and saying so once |
| `ready` | "<App> is ready": the agent's `/run/mauvely/installed.json`, what this person has been told, and Open |
| `look` | The collection's desktop preset, applied once per change of `/var/lib/mauvely-desktop/policy.json` with `plasma-apply-lookandfeel`, behind a trait |
| `signin` | The sign-in window, `/usr/bin/mauvely-signin` (os-installer's `signin/`): started with the code on stdin, told to finish after the claim, `closed` read back |
| `dialog` | The sign-in offer and code as `kdialog` windows, where the sign-in window is missing or fails; the code goes to kdialog on stdin |
| `broker::caller` | Who may ask the broker for what, pure |
| `broker::peer` | Finding the caller: `SO_PEERCRED`, `SO_PEERPIDFD`, `/proc/<pid>/root/.flatpak-info`, its `/app` on disk, the deploy's remote |
| `broker::wire`, `broker::socket` | Suite's framing; the socket and a thread per caller |
| `broker::accounts`, `broker::seal` | website-main's device link and mints; the `os` session at rest |
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
- **PAM and NSS modules never touch the network** (milestone 2). They talk to
  the daemon over its socket, and they fail fast and closed when it does not
  answer.
- **Never log a device key, an enrolment token or a session token.** The
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
- **`cargo test` must pass** without root, a TPM, flatpak or network.
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
  one exception is the desktop preset (`look`), which writes the person's own
  KDE config through Plasma's tools, once per change an admin makes.
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
- `CARGO_BUILD_JOBS=24` at most here, 8 on CI.

## Handing off

`HANDOFF.md` is overwritten each session. It holds what is half-done, what was
tried and rejected, and what compiles but has never run.
