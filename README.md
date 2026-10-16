# Mauvely OS agent

`mauvelyd` is the on-device daemon for Mauvely OS. It:
- enrols the device with the management server;
- checks in;
- installs, removes and updates Flatpaks;
- stages image updates.

The login modules `pam_mauvely` and `nss_mauvely` follow in milestone 2. They
talk only to the daemon over a local socket, never to the network.

Written in Rust. Licensed under the GNU GPL, version 3 or later.

## Build and test

```sh
cargo build --release          # target/release/mauvelyd
cargo test                     # no root, TPM, flatpak or network needed
cargo clippy --all-targets -- -D warnings
```

`CARGO_BUILD_JOBS=24` at most on a workstation, 8 on CI.

## Run

```sh
mauvelyd run       # the service: enrol if needed, then check in
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

`MAUVELY_CONFIG_DIR` and `MAUVELY_STATE_DIR` move the two directories, for
trying it without root:

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
| Tools it runs | `flatpak`, `bootc`, `rpm-ostree`, `systemd-creds` |

TLS roots are compiled in, so the image needs no CA bundle for the agent.

## How it works

The protocol is brief 19's agent API v1, in the Mauvely superproject at
`Website/website-internal/docs/launch/plans/19-mauvely-os.md`. Every request
is signed with the device key; `tests/vectors/signing.json` pins the format
and is shared with the server.

Each check-in reports the system Flatpaks, remotes and image, then
reconciles against the answer:
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
   app uses are removed.

A user's own `--user` installs are never listed or touched. A failure in
one step is reported at the next check-in and does not stop the others.
