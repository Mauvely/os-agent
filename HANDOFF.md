# Handoff

2026-10-16. Brief 22's U2 is built: `mauvelyd` updates Flatpaks and discards
an unwanted staged image, and the new per-user `mauvely-session` says when a
restart finishes an update. `cargo test` passes (47: mauvelyd 43 + 1 + 1, the
signing vectors included; mauvely-session 2), clippy is clean, and
`cargo build --release --locked` builds both binaries. **Nothing in this
session has run on a real Mauvely OS machine.** The agent API is unchanged.

## What changed

- **Flatpak updates** (`reconcile::update_flatpaks`, called by `Agent` right
  after `reconcile`):
  - `flatpak update --system -y --noninteractive`, then
    `flatpak uninstall --system -y --noninteractive --unused`. The `-y`
    matches the install and uninstall argv; `--noninteractive` implies it.
  - At most every 6 h (`FLATPAK_UPDATE_S`). The time of the last run with no
    error is `flatpaks_updated` in `managed.json` (`serde(default)`, so M1
    files still load), so a restart does not rerun it.
  - A failed run is retried at the next check-in, not 6 h later. Its errors
    go into the next `last_apply.errors`.
  - It runs after the whole reconcile, the image step included, so a
    `bootc upgrade` download comes first in that check-in.
  - The clock test is `abs_diff`: a clock set back by more than 6 h runs it
    rather than waiting for the old time to come round.
- **A staged image that is not the wanted one is discarded.** When the booted
  ref is the wanted one and another is staged (a collection moved back from
  `next` to `stable`), the agent runs `rpm-ostree cleanup --pending`, then
  `bootc upgrade`. If the discard fails, nothing is upgraded and the error is
  reported. Still never `--apply`, never a reboot. M1's open item is closed.
- **`mauvely-session`** (`crates/mauvely-session`, `dist/mauvely-session.service`):
  - Every 5 minutes it runs `rpm-ostree status --json` as the person.
  - When a deployment is staged and its checksum is not the one in
    `$XDG_STATE_HOME/mauvely/notified` (`~/.local/state/…` by default), it
    shows one notification and writes the checksum. With nothing staged it
    deletes the file, so a deployment discarded and staged again is
    announced again.
  - The notification: app "Mauvely OS", icon `system-software-update`, title
    "Restart to finish updating", no body, one action "Restart". It never
    expires (timeout 0), because the button has to be there when the person
    is ready. It replaces the previous one it showed.
  - "Restart" calls `org.freedesktop.login1.Manager.Reboot(true)` on the
    system bus. A click is acted on only when its id is the notification on
    screen.
  - zbus 5 (blocking API, default features: zbus runs its own executor
    thread; no tokio). 89 crates in its tree; the stripped binary is 2.1 MB.
  - No broker code and no abstraction for S2.

## How the facts were checked

- **rpm-ostree's JSON**, from its source on GitHub (`main` at `e5f67f1`,
  2026-09-30, via `gh api`):
  - `rust/src/daemon.rs`, `deployment_populate_variant`, inserts `id`,
    `osname`, `checksum`, `serial`, `booted`, `staged`
    (`deployment.is_staged()`, on every entry), `pinned` and `unlocked`, and
    `finalization-locked` only on a locked staged entry.
  - `src/daemon/rpmostreed-deployment-utils.cxx` adds the container keys:
    `container-image-reference`, `-digest`, `version`, `timestamp`, and
    the package lists.
  - `src/app/rpmostree-builtin-status.cxx`: `--json` prints `deployments`,
    `transaction`, `cached-update` and `update-driver`. `deployments` is the
    Sysroot's `Deployments` property through `json_gvariant_serialize`.
    `rpmostreed-sysroot.cxx` builds it from `ostree_sysroot_get_deployments`,
    which lists a staged deployment first.
  - The id is `osname-checksum.serial` (`rust/src/deployment_utils.rs`).
  - **The fixtures are assembled from that code, not captured from a
    machine.** The parser reads only `deployments[].staged` and `.checksum`.
    On the first VM, capture `rpm-ostree status --json` with and without
    something staged and replace `crates/mauvely-session/fixtures/`.
- **bootc 1.16.13** (`crates/lib/src/cli.rs` and `status.rs` at tag
  `v1.16.13`):
  - No public command drops only the staged deployment. `bootc rollback`
    drops it but also makes the rollback deployment the default.
    `DeleteDeployment` is hidden and composefs-only.
  - The host spec comes from the staged deployment when there is one
    (`status.rs`, `let spec = staged.or(booted)`). That is why
    `bootc upgrade` would follow the staged image.
  - Rejected: `bootc switch <booted ref>`. The spec differs, so it pulls and
    stages a second copy of the booted image. The person would be asked to
    restart for nothing, and reconcile would see "staged == wanted" and stop
    upgrading until a reboot.
- **`rpm-ostree cleanup --pending`**
  (`src/daemon/rpmostreed-transaction-types.cxx`,
  `cleanup_transaction_execute`) rewrites the deployments without the
  pending one, then runs the base cleanup, which prunes the discarded
  image's objects. Kinoite ships both tools (P5's evidence ran each), and
  both work on the same ostree sysroot.
- **flatpak 1.18.4**, for `--unused`: `flatpak_dir_list_unused_refs` in
  `common/flatpak-dir.c`, and `app/flatpak-cli-transaction.c`. See below.
- **mauvely-session's D-Bus side** ran once against a private `dbus-daemon`
  standing in for both buses, with a fake notification server, a fake
  logind and a fake `rpm-ostree` printing the fixtures. It sent one `Notify`
  (`susssasa{sv}i`, as the spec has it). It sent exactly one `Reboot(true)`
  for three clicks: another id's, its own `default` and its own `restart`. A
  second run with the memory file sent nothing, and the booted-only fixture
  deleted the file. The harness is not committed.

## Never run for real

- **The discard** on a bootc host, and from inside `mauvelyd.service`'s
  hardening. It talks to rpm-ostreed over the system bus, which `AF_UNIX`
  allows. Try it in the VM: switch a collection to Next, let it stage, move
  it back to Stable, and check that `bootc status` shows nothing staged and
  then a newer stable if one exists.
- **The Flatpak update** against real remotes.
- **`rpm-ostree status --json` as an unprivileged user.** It is the usual
  way it runs on Fedora Atomic, but it was not tried here.
- **mauvely-session on Plasma:**
  - whether the notification server is up when the unit starts. A failed
    `Notify` is logged, and retried 5 minutes later;
  - how Plasma shows a timeout-0 notification;
  - that polkit allows `Reboot` with no prompt for a lone active session
    (`org.freedesktop.login1.reboot` is normally allowed for an active
    session).
- **The unit.** `systemd-analyze --user verify` passes but for the missing
  binary.
- Everything in M1's list still applies:
  - the `flatpak list` rows were never seen;
  - the `bootc status` shape is from bootc's schema;
  - systemd-creds has never sealed as root;
  - `mauvelyd.service`'s hardening was only seen working once, in T4 and
    P7.

## Needs a decision

- **`flatpak uninstall --system --unused` can break a person's `--user` app.**
  - flatpak counts a runtime as used if a system app uses it, or an app in
    the *calling user's* own installation. That user is root, whose home
    `ProtectHome` hides, and flatpak ignores the permission error.
  - A `--user` app reuses a system runtime rather than installing its own:
    the CLI's transaction adds the system installations as dependency
    sources. So a system runtime that only a person's `--user` app uses is
    removed, and that app stops starting until its runtime is installed
    again.
  - The brief asked for `--unused`, so it is in. The options: accept it; or
    drop `--unused` and accept old runtimes piling up; or forbid `--user`
    installs on managed machines.
- **Restart goes through logind, as the brief says.** logind's `Reboot` does
  not let open apps ask to save. Plasma's own path (Discover's restart
  notification uses the logout prompt, `org.kde.LogoutPrompt` on the session
  bus) does. Worth switching once it can be tried on Plasma. Check the
  interface name first.
- **The first login after install sees "Restart to finish updating".**
  mauvely-seal stages a kargs-only deployment before the first reboot
  (os-image `proof/p5/evidence-first-boot.txt`), and the session announces
  any staged deployment. A restart does finish something, but it is not an
  update.
- **Each poll D-Bus-activates rpm-ostreed**, which logs a client connecting
  and leaving: a few journal lines every 5 minutes per session.
- **A `finalization-locked` staged deployment** (`--download-only`) is
  announced too, though a restart would not apply it. The agent never stages
  that way.

## For os-image

Do not move `agent.ref` from here; the parent session does it.

- **The binary:**
  - the builder's `cargo build --release --locked` already builds both;
  - copy `target/release/mauvely-session` to `/usr/bin/mauvely-session`.
- **The user unit:**
  - copy `dist/mauvely-session.service` to
    `/usr/lib/systemd/user/mauvely-session.service`;
  - run `systemctl --global enable mauvely-session.service`, which links it
    into `graphical-session.target.wants`;
  - it starts only when `/etc/mauvely/server` exists, like the agent.
- **Keep:**
  - `rpm-ostree` and `rpm-ostreed.service`. The agent now runs
    `rpm-ostree cleanup --pending` as root, and the session runs
    `rpm-ostree status --json` as the person;
  - removing `plasma-discover-rpm-ostree` and masking
    `rpm-ostreed-automatic` stay right.
- **The builder's Rust:** zbus 5.19 needs Rust 1.87 or newer. Fedora 44's
  cargo is newer than that.

## Still true from M1

- **Flatpak remotes:**
  - remote deletion runs after the apps;
  - a remote the agent added is now deletable once `--unused` has removed
    its runtimes, one check-in after that run;
  - remote updates are detected by URL, plus a SHA-256 of URL and key in
    `managed.json`;
  - a filtered Flathub would still refuse apps outside the filter.
- **Apps match on id and branch.** Nothing migrates an app between remotes.
- **The image:**
  - a different ref is switched to;
  - the booted ref is upgraded;
  - either is staged once, then left until a reboot;
  - T4 (os-image `proof/t4/`) showed `bootc upgrade` and the signature
    policy on real bootc 1.16.13.
- **Enrolment and check-in:**
  - every enrolment attempt uses a fresh key;
  - backoff is 60 s, doubling, capped at 1 h, with ±10 % jitter after the
    cap;
  - a 403 means revoked only when the body says `revoked`;
  - the first check-in after a start reports `last_apply` as ok;
  - a failed `flatpak list` fails the check-in;
  - a failed `bootc status` sends nulls, and no image is staged;
  - `server_time` is ignored.
- **A key that no longer unseals** makes the service exit and restart every
  30 s. The way back is to delete `/var/lib/mauvely` and enrol again.
- **TLS roots are compiled in** (`webpki-roots`).
