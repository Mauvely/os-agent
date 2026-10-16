# os-agent

`mauvelyd`, the Mauvely OS device agent, and `mauvely-session`, its helper in
each graphical session, in Rust.

The design and the frozen agent API (enrolment, signed check-ins) are in brief
19: `Website/website-internal/docs/launch/plans/19-mauvely-os.md` in the
Mauvely superproject.

- **The server side** is `Website/website-devices`.
- **The signing vectors** in `tests/vectors/` are shared with it. Change both
  sides together.

## Layout

A Cargo workspace with two crates:
- `crates/mauvelyd`: a library holding the logic and a thin binary
  (`main.rs`). The service unit is `dist/mauvelyd.service`.
- `crates/mauvely-session`: a binary, run as the person by the user unit
  `dist/mauvely-session.service`. It tells them when a restart finishes an
  update (brief 22, U2); the SSO broker (S2) joins it later.

`mauvelyd`'s modules:

| Module | Holds |
|---|---|
| `signing` | The `mauvely-device-v1` message and the `X-Mauvely-*` headers |
| `api` | The wire types and the signed `ureq` client |
| `flatpak`, `bootc`, `creds` | A trait each, the real CLI behind it, and its argv builders and output parsers |
| `reconcile` | Brief 19's reconcile rules, as one function over the traits, and brief 22's Flatpak updates |
| `agent` | Enrolment, one check-in (`Agent::tick`) and the service loop (`run`) |
| `state`, `facts`, `schedule` | Files on disk, hardware facts, backoff and jitter |
| `fake` | Test doubles and a `tiny_http` fake server, test builds only |

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
- **Never log a device key or an enrolment token.** The seed travels to
  `systemd-creds` over stdin, never as an argument or a file.
- **`cargo test` must pass** without root, a TPM, flatpak or network.
  `cargo clippy --all-targets -- -D warnings` stays clean; code is
  `cargo fmt`-formatted.
- **No async runtime.** It is one loop, and it blocks. `mauvely-session` uses
  zbus's blocking API, which runs zbus's own executor thread; no tokio.
- **`mauvely-session` runs as the person, never as root.** It changes nothing
  on the machine but its own file in `$XDG_STATE_HOME/mauvely/`, and asks
  logind for a reboot only when the person clicks Restart.
- `CARGO_BUILD_JOBS=24` at most here, 8 on CI.

## Handing off

`HANDOFF.md` is overwritten each session. It holds what is half-done, what was
tried and rejected, and what compiles but has never run.
