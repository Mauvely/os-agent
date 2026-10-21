# Handoff

## 2026-10-21, later: the S2 review's fixes

An adversarial review of S2 (`669f0e0..aab49ba`) found the caller check held,
and five things that did not. Each is fixed test-first on `main`, and each
guard was sabotaged once to see a test fail (the directory-owner check is
still the one that cannot be: only root can make a directory we can write but
do not own). `cargo test` passes (mauvelyd 50 + 1 + 1, mauvely-session 69),
clippy is clean.

1. **Another local user could link this computer to their own account.** The
   page opened as `…/link?code=<code>`, so the code sat in `xdg-open`'s or the
   browser's argv, readable by every uid under `/proc`.
   - Now: `verificationUri` opens without the code (refused if it carries
     it), the notification becomes "Enter this code to sign in" with the code
     as its body, and on success "Signed in to Mauvely as <email>". A
     declined or expired link takes the code away.
   - Tests: `start_answers`, `linking_opens_the_page_then_seals_the_session`,
     `a_declined_or_expired_link_leaves_it_signed_out`.
2. **An app granted `xdg-run/mauvely` read-write could answer for the
   broker.** It could unlink the socket and listen in its place; a directory
   in its place stopped the broker for the whole login.
   - Now: the socket's (dev, ino) is recorded after bind and checked every
     2 s and after every caller; on a change the broker clears whatever is
     there (file or directory) and listens again. A failed listen is tried
     again every 2 s instead of turning the broker off.
   - Tests: `a_squatter_is_cleared_away`, `a_failed_listen_is_tried_again`.
     In the end-to-end run a real squatter answered `tok_mallory` for about
     2 s, then the broker had the name back.
   - **S3's finish-args must be exactly `--filesystem=xdg-run/mauvely:ro`.**
     Without `:ro` an app can squat between checks.
   - **Later, the robust fix:** a directory the person cannot write. A
     root-owned `/run/mauvely/<uid>/` (or similar), with `mauvelyd` binding
     the socket there and handing the listening descriptor to the person's
     `mauvely-session` (systemd socket activation per user, or `SCM_RIGHTS`
     over the agent's socket). Then no app, `:ro` or not, can replace it.
3. **The `os` token was not bound to its origin, and `MAUVELY_CONFIG_DIR`
   was honoured.** A changed server, or that variable set through
   `~/.config/environment.d/` by a home-writing sandbox, sent the 90-day token
   elsewhere, in clear for the dev origins.
   - Now: the origin is sealed with the session; a session for another origin
     is forgotten and linking offered. `MAUVELY_CONFIG_DIR` works in debug
     builds only.
   - Tests: `a_session_linked_to_another_server_is_dropped` (a session sealed
     before origins existed is dropped too),
     `the_config_dir_moves_only_in_debug_builds`.
4. **A 403 from `/api/auth/me` kept a cached session in service.**
   - Now: 401 and 403 from `/me` are both "gone", so the re-mint answers,
     for example, `app_not_allowed`.
   - Tests: `alive_answers`,
     `a_session_the_organisation_turned_off_is_not_answered_again`.
5. **`$XDG_STATE_HOME/mauvely` could be `0755`,** made first by `staged`.
   - Now: `private_dir` makes it, and any missing parent, `0700`, and
     tightens it when it exists; `staged` and `seal` both use it.
   - Tests: `a_private_dir_is_0700`, `stores_sealed_and_private`,
     `says_it_once_per_staged_deployment`.

**Hardening, also from the review:**
- **A Mauvely app must come from the `mauvely` remote.** The deploy's origin
  is read from `<app-path>/../deploy` (a GVariant `(ssasta{sv})`, first
  string), only for a system install. The reader is tested on three real
  deploy files from S0's installation, with 1- and 2-byte framing offsets,
  and on broken ones. The browsers' remote is not checked, as an organisation
  may mirror Flathub under another name.
- **The sandbox's `/app` must be its `app-path` on disk,** the same device and
  inode. It is looked at through `/proc/<pid>/root` inside the pid guard,
  without following a symlink. A `bwrap` forgery naming a system deploy that
  is not mounted is now refused.
- **Host and unidentified callers are refused before they speak,** so they do
  not hold one of the 16 places.
- **Labels are cut at 120 UTF-16 units,** as JavaScript counts after
  `trim()`. A longer one failed the whole mint with `invalid_field`.
- **`caller::BROWSERS` is tested against mauvelyd's `reconcile::BROWSERS`,**
  read from its source.
- **`docs/broker.md`'s threat model leads with the real boundary:** any
  process running as the person can unseal `os.cred` with
  `systemd-creds --user decrypt`. Confirmed again in the end-to-end run.

**End to end, again** (the same contained harness, a debug build so
`MAUVELY_CONFIG_DIR` works):
- the offer, the code in its own notification, `xdg-open` given
  `http://127.0.0.1:8787/link` with no code, then "Signed in to Mauvely as
  e2e@example.invalid";
- the state directory `0700`;
- `os.cred` unsealed by a plain same-uid `systemd-creds --user decrypt`;
- a host caller refused at once;
- the real user-installed Firefox refused as not a system install;
- the `bwrap` forgery refused ("its /app is not its app-path");
- a squatter answering for about 2 s, then the broker again;
- `/etc/mauvely/server` changed: the sealed session forgotten and the offer
  shown again;
- no token in the log.

It no longer shows a mint through the socket: nothing on this machine is a
system install, so no real caller passes. The mint paths are in the unit
tests, through `Broker::answer`.

**Left:**
- The root-owned socket directory above.
- **Copy:** "Enter this code to sign in" with the code as the body was
  chosen here. The link page calls it the "Code from the app".
- **The confirmation's account:** "Signed in to Mauvely as <email>" shows the
  claim's `user.email`. A link approved by another account is shown, not
  undone, and the person cannot sign it out from their own Devices tab. The
  only way back today is deleting `~/.local/state/mauvely/os.cred` and
  logging in again. A "Sign out" action on that notification is the obvious
  next step; not built, as nobody asked for it yet.

## 2026-10-21: verified on `mauvely-01`

Recorded from the parent session's check of Timur's VM, on production
`next` `sha256:617bf164…`, which carries agent `669f0e0`:
- os-image's slim initramfs (`1069b7b`) let the update finalise and boot,
  unlocking from the TPM;
- the move from `stable` to `next` went through GHCR under the signature
  policy;
- a staged `stable` over a booted `next` was discarded by
  `rpm-ostree cleanup --pending` from inside `mauvelyd.service`'s hardening,
  then `bootc upgrade` ran;
- with only a kernel-argument change staged, the agent still ran
  `bootc upgrade` and left the change staged;
- starting after `tuned` kept `tuned` and `tuned-ppd` up.

**Still unverified there:** Flatpak updates (the collection has no apps), and
mauvely-session's notification (nobody was signed in to Plasma).

## 2026-10-21: brief 22's S2, the sign-in broker

`mauvely-session` is now the sign-in broker, and `mauvelyd` grants the
browsers its socket. The protocol, the caller rules and the threat model are
in `docs/broker.md`; this section is what that file does not say.

- `51ff2bd` mauvelyd: each system Firefox and Chromium gets
  `flatpak override --system --filesystem=xdg-run/mauvely:ro <id>`, once,
  recorded in `managed.json`'s `granted`.
- `96784f2` mauvely-session: the broker (`crates/mauvely-session/src/broker/`).
- This commit: `docs/broker.md`, CLAUDE.md, README.

`cargo test` passes (mauvelyd 50 + 1 + 1, mauvely-session 53), clippy is
clean, `cargo build --release --locked` builds both. **Nothing here has run on
Mauvely OS, on Plasma, or against a real accounts service.** The agent API is
unchanged.

### Decisions made here

- **Cached, and checked before reuse.** The brief says cache until shortly
  before `expiresAt`, and answer a caller whose token was refused from a fresh
  mint. Those conflict when a session is revoked early (signed out in the
  page, revoked in the Devices tab): the cache would hand back the dead one.
  So each reuse first asks `GET /api/auth/me` with the cached token (3 s), and
  mints again when the server says it is gone. When the server cannot say,
  the cached one is answered. Not caching at all was the alternative: every
  browser restart would make a new 30-day session row.
- **Fresh** until a tenth of its life, or five minutes, before `expiresAt`. An
  organisation's one-hour limit gives a 55-minute cache.
- **`origin` in every granted answer.** S4 needs it for the cookie's domain,
  and an app can tell a staging device's token from a production one.
- **`sso_required`** is `{"v":1,"ok":false,"reason":"sso_required","org":…,
  "start":"<origin>/api/auth/sso/start?org=…"}`, `start` made absolute. The
  `os` session is kept: the server refused a mint, it did not revoke anything.
- **The browser label is the broker's**, "Firefox on <hostname>"; the
  caller's is ignored. The app label is passed on, as Suite does. The device
  link is "Mauvely OS on <hostname>".
- **`BROKERABLE` is the server's list exactly**, `review` and `cli` included,
  though neither ships as a Flatpak. Being narrower is the failure Suite has
  hit twice; being wider costs nothing, since only a root-installed
  `com.mauvely.<key>` is answered.
- **The grant covers every system Firefox and Chromium**, not only the ones
  the agent installed: those are exactly the ones the broker answers, and a
  machine whose agent installed a browser before this version is granted at
  its next check-in.
- **The offer comes back at every login while unlinked.** There is no "don't
  ask again". It also comes back after a 401, at the `os` session's expiry,
  and after a link that could not start or open the browser; not after one
  the person declined or let expire.
- **A session that cannot be sealed** (the `systemd-creds` service down) is
  kept in memory for that login, logged. A file that does not unseal is kept
  and linking is offered; a new link overwrites it, and the old `os` session
  is left on the server until it expires.
- **A kernel without `SO_PEERPIDFD` is refused**, not trusted with a re-check
  alone: without a pidfd there is nothing to re-check against. Fedora 44 is
  far past 6.5.
- **Not done, from S0's list:** checking that a browser's `app-extensions`
  names the Mauvely policy ref (note 4; the refs are S4's and do not exist
  yet), and reading the origin remote from `<app-path>/../deploy` (note 3; it
  is a local alias, not a trust anchor).

### Dependencies

No crate is new to `Cargo.lock`.
- **`libc`**, for `getsockopt(SO_PEERCRED)`, `getsockopt(SO_PEERPIDFD)`,
  `openat` and `geteuid`. std's `peer_cred` is unstable and has no pidfd.
  `libc` was already in mauvely-session's tree, under zbus.
- **`ureq`** (rustls, compiled-in roots), the client mauvelyd already uses.
  The stripped binary goes from 2.1 MB to 4.0 MB.
- **`tiny_http`**, tests only, as in mauvelyd.

### What was run

- **The caller checks**, mutated one at a time: removing each of the app id
  check, the system path check, the slash after the id, the `.`/`..` check,
  the host refusal, the duplicate group and key checks, the pidfd before and
  after, the `/api/auth/me` check, the staleness check, the 401 sign-out, the
  link's origin check, the local-host list and the symlinked directory check
  fails a test. The directory-owner check survives: only root can make a
  directory we can write but do not own, and faking it in a test would chmod a
  shared directory when tests run as root.
- **End to end, contained** (harness in the session scratchpad, not
  committed): the release binary in a private network namespace (so a fake
  accounts service could hold 127.0.0.1:8787, which another session's
  website-main holds here), a private `dbus-daemon` with no service activation
  for both buses, a fake notification server, fake `xdg-open` and
  `rpm-ostree`, and the **real** `systemd-creds --user`. It showed:
  1. the offer ("Sign in to Mauvely", icon `user-identity`, action `sign-in`,
     timeout 0); the click; the portal missing and `xdg-open` given the link;
     two polls; `os.cred` written `0600` in a `0700` directory, a real
     user-scoped credential;
  2. the socket `0700`/`0600`; a host process refused, "not in a Flatpak
     sandbox";
  3. **Flathub's Firefox 158 from S0's contained user installation, granted
     `xdg-run/mauvely:ro`, identified through `SO_PEERPIDFD` and its real
     `/.flatpak-info`, and refused: "not a system install
     (/home/timuri/.cache/mauvely-flatpak/user/app/org.mozilla.firefox/…)"**.
     Not granted, it gets `ENOENT`;
  4. a host process forging a system Firefox's `/.flatpak-info` with `bwrap`:
     answered, minted with "Firefox on timur-pc"; asked again, checked with
     `/api/auth/me` and answered from the cache; asking `token` for `compose`,
     refused;
  5. killed and restarted: the credential unsealed, and the next ask minted;
  6. the server answering 401: `signed_out`, `os.cred` deleted, the offer
     shown again;
  7. no token in the log.

  The callers ran in the broker's user namespace. Run from the initial one
  while the broker sat in a nested one, every caller was refused as
  unidentified (`EACCES` on `/proc/<pid>/root`: the kernel's ptrace check
  wants the reader in the target's user namespace or one owning it). In
  production the broker is in the initial namespace, which owns every
  sandbox's, as S0 showed. It failed closed, as it should.
- **Inside Flathub's Firefox** (flatpak 1.18.4): `unshare(CLONE_NEWUSER)`,
  `unshare(CLONE_NEWNS)` and `mount` all fail with `EPERM`, and
  `/.flatpak-info` is read-only. That is what stops a sandboxed app forging
  its identity.
- **Not run against website-main.** Never against mauvely.com or
  mauvely.dev. Not against the local stack either: another session's
  `workerd` holds 8787 with migrations pending on the shared store, and a
  device link needs a browser signed in to approve it.

### Never run

- On Mauvely OS: a **system-installed** browser or Mauvely app asking (only
  the forged one and a user install have), the agent's `flatpak override
  --system`, and the unit's environment.
- On Plasma: the notification and its action, the OpenURI portal, and
  `xdg-open` to a Flatpak default browser.
- Real mints, `/api/auth/me` with a real minted token, and TLS to the real
  origins.
- `systemd-creds --user` on Fedora 44: whether `systemd-creds.socket` is
  enabled there, and whether a TPM is used in user scope (on this machine the
  credential's header is the same for `auto`, `host` and `host+tpm2`, as the
  varlink service ignores the key; which key it chose was not read back).
- The browsers' nested sandboxes asking.
- A login where the notification server is not up yet: the offer fails, is
  logged, and is tried again at the next 5-minute tick.

### Open questions

- **`sso_required` leaves the link in place.** In the usual case enforcement
  revokes a non-SSO `os` session and the 401 relinks. In the rare one (an `os`
  session that outlived enforcement) every mint answers `sso_required` and
  nothing offers to relink. Offer linking on `sso_required` too, replacing
  the session on success?
- **Play and Sotto have no client in `KNOWN_CLIENTS`.** If S3 gives them the
  broker, website-main must add them first, or the broker answers
  `unknown_client`.
- **An app started before mauvely-session** has no broker until it restarts:
  flatpak binds `xdg-run/mauvely` only if it exists. See os-image below.
- **A clock far ahead** makes every cached session stale; each ask then mints
  until the server's rate limit answers. Mauvely OS runs chrony.

### For S3, the apps

Do not edit the apps from here; this is the exact change each needs.
- **finish-args:** exactly `--filesystem=xdg-run/mauvely:ro`. Without `:ro`
  the app can replace the socket (fixed later the same day, above).
- **App id:** `com.mauvely.<APP_KEY>`, installed system-wide by the agent.
  A `--user` install, a developer's build included, is `forbidden`, and the
  app falls back to its own device link.
- **suitelink:** when `/.flatpak-info` exists, connect to the path
  `$XDG_RUNTIME_DIR/mauvely/broker` (a name starting with `/` is a path to
  `QLocalSocket::connectToServer`), send
  `{"v":1,"op":"token","client":"<APP_KEY>","label":"…"}` and a newline, and
  read one line: Suite's answer, plus `origin`. Every refusal falls back to
  the device link, as today. `cloud-link` is `unknown_op` here.
- **Time:** the broker answers within about 11 s (a 3 s check, an 8 s mint);
  suitelink's 12 s fits. A second caller for the same key waits for the
  first.
- **Keys answered:** `assist`, `compose`, `mail`, `office`, `relay` (and
  `cli`, `review`, `snap`, which have no Flatpak).

### For S4, the browser extension and its native host

- The native host connects to `$XDG_RUNTIME_DIR/mauvely/broker` from inside
  the browser's sandbox and sends `{"v":1,"op":"browser"}`.
- The answer: `token`, `expiresAt` (Unix seconds; the cookie's lifetime is
  `expiresAt - now`), `email`, `origin`. The cookie's domain comes from
  `origin`: `https://mauvely.com` is `.mauvely.com`, `https://mauvely.dev` is
  `.mauvely.dev`, and the local stack's `http://localhost:8787` is
  host-only and not `Secure`.
- `sso_required`: open `start` in a tab. `signed_out`: nothing; the computer
  offers to link. `rate_limited`, `unreachable`: try later.
- Asking again after a sign-out in the page gets a new session.
- Each browser has its own session, ten mints an hour per `os` session.
- Only a system-installed Firefox or Chromium is answered, and the agent
  grants both. Anything in the browser's sandbox can ask; the native host is
  not told apart from the browser.

### For os-image

Do not move `agent.ref` from here; the parent session does it.
- Nothing new to copy: the same binary and user unit.
- **Check `systemd-creds.socket` is active** on the image. Sealing as the
  person goes through `/run/systemd/io.systemd.Credentials`; without it,
  linking works for that login only.
- **Worth adding:** `/usr/share/user-tmpfiles.d/mauvely.conf` with
  `d %t/mauvely 0700 - - -`, so the directory exists before any app starts.
  mauvely-session accepts a directory that is already there, if it is the
  person's, and tightens it to `0700`.

## 2026-10-21: first contact with a real install (Timur's Proxmox VM)

What `mauvely-01` (enrolled on production, org `suez`) showed, and what changed:

- **A kernel-argument change no longer holds back updates.** mauvely-seal's
  `rpm-ostree kargs` stages the booted image again, at the booted digest.
  `reconcile` compared image *names*, read that as "the wanted image is
  staged" and never upgraded until a clean reboot; a machine only ever
  powered off hard never updated. `bootc::Status::staged_update()` now
  ignores a staged deployment of the booted image at the booted digest, and
  the check-in reports `staged_image` through it too, so the console does not
  say "restart pending" for it. Fixtures in `crates/mauvelyd/fixtures/bootc/`
  are real `bootc status --format=json` output from the VM, in all three
  states; `crates/mauvely-session/fixtures/status-kargs-staged-real.json` is
  real `rpm-ostree status --json` (image manifests trimmed).
- **`mauvelyd.service` starts after `tuned.service`.** tuned sets kernel
  arguments through `bootc loader-entries` while it starts; behind the
  agent's `bootc switch` (over a minute) it timed out, dumped core, and took
  `tuned-ppd` (power profiles) down for that boot, every boot.
- **Not fixed here: `/boot` is too small for two kernels.** bootc's 510 MB
  `/boot` cannot hold Kinoite's 238 MB initramfs twice, so the VM's update to
  `next` failed at shutdown ("Installing kernel: regfile copy: No space left
  on device") and was staged again every boot. os-image's slim initramfs is
  the fix. Until it ships, the agent re-stages at every boot and
  mauvely-session would announce a restart that never finishes.
- **Not verified on the VM yet:** the upgrade with a kernel-argument change
  staged, against a registry that has a newer build. `bootc upgrade` takes
  its kernel arguments from the booted deployment, so the seal's change is
  dropped from that update and the seal stages it again on the next boot.
- **Worth doing next:** report a staged update that did not survive the
  reboot (`ostree-finalize-staged` failed, or the booted digest is not the
  one staged last time) in `last_apply.errors`, and stop mauvely-session
  announcing it again.

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
- **A staged deployment of the booted image is not announced** (fixed the
  same day). mauvely-seal stages a kargs-only one before the first reboot
  (os-image `proof/p5/evidence-first-boot.txt`), and the first login would
  have said "Restart to finish updating" for it. `staged::staged` now skips a
  staged checksum equal to the booted one, so a kargs-only change from
  `kargs.d` is not announced either.
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
