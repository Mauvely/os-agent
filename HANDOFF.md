# Handoff

2026-10-14. P4 of brief 19 is built: `mauvelyd` enrols, checks in,
reconciles Flatpak remotes and apps, and stages images. `cargo test` passes
(43 tests), clippy is clean, and `cargo build --release` works. Nothing has
run on a real Mauvely OS machine yet; that is P7.

## Never run for real

Everything below is tested only against fakes, so treat it as unverified:
- **flatpak.** The argv is unit-tested. The list parser was written against
  `flatpak remotes` output on Flatpak 1.18.4 (tab-separated, no header when
  piped); `flatpak list` was empty on this machine, so its rows were never
  seen.
- **bootc.** The `bootc status --json` shape (`status.booted.image.image.image`,
  `…imageDigest`, `status.staged.image.image.image`) is from bootc's
  documented `BootcHost` schema, not captured from a host.
- **systemd-creds.** Run only as a normal user, where it fails as expected.
  Sealing as root, with and without a TPM, is untested. No PCRs are bound,
  which is current systemd's default when the image ships no
  `tpm2-pcr-public-key.pem`, so a Secure Boot key or dbx update cannot lock
  the agent out of its own key.
- **The unit.** `systemd-analyze verify` passes. Its hardening has never run
  against flatpak or bootc on Kinoite; each omission is commented in the
  file. If something is denied, `ProtectHome=yes` and
  `ProtectKernelTunables=yes` are the first suspects.
- **website-devices** had no code pushed when this was written, so the agent
  has never spoken to the real server.

## Choices where the brief was silent

Small, and none changes the wire format. Each is worth a look in P7.
- **Remote deletion runs after the apps**, not with the other remote steps.
  flatpak refuses to delete a remote that still has refs installed from it.
- **Unused runtimes are never removed.** So a remote the agent added still
  cannot be deleted while runtimes from it remain, and that error repeats in
  `last_apply` every check-in. `flatpak uninstall --unused` would fix it;
  it was left out as beyond the brief.
- **Remote updates are detected** by URL, plus a SHA-256 of URL and key in
  `managed.json`. A remote already on the machine (the image's Flathub) gets
  one `remote-modify --enable` the first time the server lists it. It is
  recorded `added: false` and never deleted.
- **A Flathub remote with a filter** would still refuse apps outside the
  filter. The agent does not clear filters. P5 should ship the image without
  Fedora's filtered or disabled Flathub, or the agent needs `--no-filter`.
- **Apps match on id and branch.** An app installed from another remote
  counts as installed, and nothing migrates it between remotes.
- **The image (since T4, 2026-10-14):**
  - A different ref is switched to.
  - The booted ref is upgraded (`bootc upgrade`). That stages a newer build
    under the same tag, and is how a device on `stable` gets the next stable.
  - Either is staged once, then left until a reboot. A newer build pushed
    while one is staged waits for the reboot after that.
  - Tried with real bootc 1.16.13 in os-image `proof/t4/`, without
    `mauvelyd`:
    - an upgrade with nothing new exits 0 and stages nothing;
    - an upgrade with a newer signed build stages it;
    - the image's policy refuses an unsigned one.
- **Still open:** if the desired ref goes back to the booted one while
  another image is staged, nothing happens. An upgrade then would follow the
  staged image, so the agent skips it. The staged image applies at the next
  reboot. That needs a decision (M3).
- **Every enrolment attempt uses a fresh key.** A 409 cannot repeat, and a
  201 lost in transit costs one token use.
- **Backoff** is 60 s, doubling, capped at 1 h. The ±10 % jitter applies
  after the cap, so a wait can reach 66 minutes.
- **A 403 means revoked only when the body says `revoked`.** Any other 403
  backs off.
- **The first check-in after a start** reports `last_apply` as ok. The
  result is kept in memory, not on disk.
- **`status.json`** is an extra state file, holding the last check-in time
  for `mauvelyd status`.
- **A failed `flatpak list`** fails the check-in, which backs off. Reconciling
  against a missing inventory would reinstall everything. A failed
  `bootc status` sends nulls, and no image is staged.
- **`server_time` is ignored.** A clock more than 300 s off gets 401s and
  backs off; the agent does not correct for skew.
- **Paths move by environment variable** (`MAUVELY_CONFIG_DIR`,
  `MAUVELY_STATE_DIR`), not flags.
- **A key that no longer unseals** (a cleared TPM, a lost
  `credential.secret`) makes the service exit and restart every 30 s. There
  is no automatic way back: delete `/var/lib/mauvely` and enrol again with a
  new token.
- **TLS roots are compiled in** (`webpki-roots`), not read from the system. A
  self-hosted server behind a private CA would not be trusted. That matters
  for `workerd` self-hosting in M4, not M1.

## For P5 (the image)

- **The binary** is `target/release/mauvelyd`. Build it in a builder stage of
  the Containerfile, because a binary from this machine needs glibc 2.39.
  Install it to `/usr/bin/mauvelyd`.
- **The unit** is `dist/mauvelyd.service`. Install it to
  `/usr/lib/systemd/system/` and enable it. It does not start without
  `/etc/mauvely/server`.
- **The tools it runs** are `flatpak`, `bootc` and `systemd-creds`. All three
  are in Kinoite.
- **The installer writes** `/etc/mauvely/server` and `/etc/mauvely/enrol`.
