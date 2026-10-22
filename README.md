# Mauvely OS agent

`mauvelyd` is the on-device daemon for Mauvely OS. It:
- enrols the device with the management server;
- checks in;
- installs, removes and updates Flatpaks;
- stages image updates.

`mauvely-session` runs in each graphical session, as the person. When an
update is staged it shows "Restart to finish updating" once, with a Restart
button. When the agent has installed an app it shows "<App> is ready" once,
with an Open button. It is also the sign-in broker: it links the computer to
the person's Mauvely account once, in a window that shows Mauvely's own
sign-in (`mauvely-signin`, from os-installer), then signs the Mauvely apps and
the browsers in from that (`docs/broker.md`). For the browsers it places the
native host of the Mauvely OS browser extension (`browser/`,
`crates/mauvely-browser-host`, `docs/browser.md`), which sets the
`mauvely_session` cookie from the computer's link.

People sign in at the login screen with their Mauvely account (milestone
2): `pam_mauvely` asks `mauvelyd login` over `/run/mauvely/auth.sock`, never
the network, and the login service checks online, keeps an offline cache,
writes the person's userdb records and hands their session to
`mauvely-session` (`docs/login.md`).

Written in Rust. Licensed under the GNU GPL, version 3 or later.

## Build and test

```sh
cargo build --release          # mauvelyd, mauvely-session, libpam_mauvely.so
cargo test                     # no root, TPM, flatpak or network needed
cargo clippy --all-targets -- -D warnings
node --test browser/extension/test/*.test.cjs   # the browser extension
python3 -I browser/test_package.py              # its packaging
```

The browser host is built static for the browsers' sandboxes:

```sh
cargo build --release --locked -p mauvely-browser-host --target x86_64-unknown-linux-musl
```

`CARGO_BUILD_JOBS=24` at most on a workstation, 8 on CI.

## Run

```sh
mauvelyd run       # the service: enrol if needed, then check in
mauvelyd login     # the login service, on /run/mauvely/auth.sock
mauvelyd enrol     # one enrolment attempt, in the foreground
mauvelyd status    # device, organisation, server and last check-in
```

It runs as root, from `dist/mauvelyd.service`.

| File | Holds |
|---|---|
| `/etc/mauvely/server` | The server's base URL, such as `https://devices.mauvely.com` |
| `/etc/mauvely/enrol` | The enrolment token. Deleted once enrolment succeeds |
| `/var/lib/mauvely/device.json` | The device id and organisation slug |
| `/var/lib/mauvely/key.cred` | The device's Ed25519 seed, sealed with `systemd-creds` |
| `/var/lib/mauvely/managed.json` | The apps and remotes the agent installed or configured, and when it last updated Flatpaks |
| `/var/lib/mauvely/status.json` | When the last check-in succeeded |
| `/run/mauvely/installed.json` | The last 50 apps installed since boot: `{"installs": [{"id", "branch", "at"}]}`, oldest first. Root's, readable by everyone |

`MAUVELY_CONFIG_DIR`, `MAUVELY_STATE_DIR` and `MAUVELY_RUN_DIR` move the
three directories, for trying it without root:

```sh
mkdir -p /tmp/mv/etc && echo http://localhost:8798 > /tmp/mv/etc/server
MAUVELY_CONFIG_DIR=/tmp/mv/etc MAUVELY_STATE_DIR=/tmp/mv/state mauvelyd status
```

Enrolment itself needs root, because sealing the key does.

## On the image

| | |
|---|---|
| Binary | `/usr/bin/mauvelyd` |
| Unit | `/usr/lib/systemd/system/mauvelyd.service`, enabled |
| Login unit | `/usr/lib/systemd/system/mauvely-login.service`, enabled |
| PAM module | `target/release/libpam_mauvely.so` as `/usr/lib64/security/pam_mauvely.so` |
| Session binary | `/usr/bin/mauvely-session` |
| Session unit | `/usr/lib/systemd/user/mauvely-session.service`, enabled globally (`systemctl --global enable`) |
| Tools it runs | `flatpak`, `bootc`, `rpm-ostree`, `systemd-creds` |

TLS roots are compiled in, so the image needs no CA bundle for the agent.

## How it works

The protocol is brief 19's agent API v1, in the Mauvely superproject at
`Website/website-internal/docs/launch/plans/19-mauvely-os.md`. Every request
is signed with the device key; `tests/vectors/signing.json` pins the format
and is shared with the server.

Each check-in reports the system Flatpaks, remotes and image, and how the
last apply went: `last_apply.errors`, and `last_apply.failed` naming the apps
whose install, update or removal failed (at most 50, each error cut to 500
characters). It then reconciles against the answer:
1. remotes are added, or updated when their URL or key changed;
2. apps marked `installed` are installed;
3. apps marked `absent` are removed, whoever installed them, and so are apps
   the agent installed that the server no longer lists;
4. remotes the agent added and the server no longer lists are deleted;
5. a different image is staged with `bootc switch`, and the booted one is
   upgraded with `bootc upgrade`. Another image staged over a wanted booted
   one is discarded first, with `rpm-ostree cleanup --pending`. The agent
   never reboots;
6. at most every 6 hours, system Flatpaks are updated, and runtimes no system
   app uses are removed;
7. each system Firefox and Chromium is granted the sign-in broker's socket,
   once (`flatpak override --system --filesystem=xdg-run/mauvely:ro`).

A user's own `--user` installs are never listed or touched. A failure in
one step is reported at the next check-in and does not stop the others.
