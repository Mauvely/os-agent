# Handoff

## 2026-10-22, late: brief 26, signing in with a Mauvely account

`mauvelyd login` (the login service) and `pam_mauvely` (a new crate,
`crates/pam-mauvely`) are built. `docs/login.md` has the protocol, the rules,
every refusal and the threat model; this is what it does not say. `cargo test`
passes (mauvelyd 184 + 1 + 1, pam-mauvely 19, mauvely-session 142,
mauvely-browser-host 15 + 2), clippy and fmt are clean, `cargo build
--release --locked` builds all four. New to `Cargo.lock`: `argon2` 0.6 (with
`blake2`, `base64ct`, `ctutils`), for mauvelyd; `libc` and `zeroize` were
already there. No aws-lc or openssl. `agent.ref` in os-image is not touched.

### Proved, short of the VM

- **Every rule in `cargo test`**, and each guard broken once to see a test
  fail: the peer rule (another person's name; the login screen for root
  only), the code only at `plasmalogin`, no fallback after a refusal, the
  assignment rule, the stale-cache rule, the server's uid range, local
  accounts to `pam_unix`, the offline days, and in the module
  `not_mauvely` to `PAM_IGNORE` and a missing daemon failing closed.
- **website-main's 15 KDF vectors** (`tests/vectors/kdf.json`, a copy of
  `shared/vectors/kdf.json` at website-main `dd50289`), and the empty password
  refused.
- **`tests/login/local.sh`**: the debug module through this machine's libpam
  (1.7.3, `pam_start_confdir`), against a fake daemon: 22 checks.
- **`tests/login/container.sh`**: the release module built in Fedora 44
  (pam 1.7.2, glibc 2.43), in Kinoite 44.20261019.0 as root, under an
  authselect `mauvely` vendor profile with **os-image's exact lines** (two
  `pam_localuser`, then `pam_mauvely`): the real `/usr/lib/pam.d/plasmalogin`
  with its code prompt, sudo, `login`, a system user from `/usr/lib/passwd`
  never reaching the daemon, the password reaching `pam_exec expose_authtok`
  after the substack (what the wallets need), and with the daemon down root
  and a local admin still signing in while a Mauvely name is refused with 9.
- **`tests/login/e2e.sh`**: the real `mauvelyd login` and the real module in
  Kinoite as root, the device key and the cache sealed by the real
  `systemd-creds` (host key), against `fake_devices.py`: 43 checks. `getent`
  and `id` saw the userdb records and `wheel`; the home was made through a
  fake `systemctl` that resolved the new user; the hand-off was `0600 timur`
  in a `1733` directory; the vector's `authSecret` was on the wire and the
  password was not; a version 0 account was upgraded with its new session;
  the lock screen worked as the person (`setpriv` to uid 21001) and refused
  them another person; a text console refused a non-admin; offline signed in
  without a code and handed nothing over; the log held no token, password or
  unknown typed name.

### Decisions the brief did not make

- **The login service is its own process and unit**,
  `dist/mauvely-login.service` (`mauvelyd login`, `Before=display-manager.service`,
  `Restart=always`). In the agent's process it would have waited for
  `network-online.target`, which offline (the cache's whole point) is up to a
  minute after the login screen is up; and a crash in the agent's reconcile
  would have taken logins down with it. The two share files, not memory: the
  service loads the device key itself at the first online sign-in after
  enrolment. **os-image must install and enable this unit.**
- **`not_mauvely`**: a name NSS knows that is not one of our records gets
  `PAM_IGNORE`, so `pam_unix` judges it. With os-image's stack this is only a
  backstop (a dynamic user, another service's userdb record); a name on no
  list is never ignored.
- **Usernames**: website-devices' rule, then systemd's strict one: a Mauvely
  name with a leading digit, or 32 characters, is `bad_username` ("This name
  can't be used to sign in to a computer."). Mapping them is left.
- **Offline**: only at the password step (a network error, a timeout, a 5xx,
  or a 404 from a server without the door); unreachable at the code is
  `unreachable`, and the retry goes offline. 401 `unauthorised` (say, a clock
  off by minutes) is a refusal, `unavailable`, not offline. `rate_limited` is a
  refusal (OS-LOGIN.md left it to us). The age limit is the stricter of the
  entry's `offlineDays` and the collection's now; a clock more than 5 minutes
  before the entry's sign-in is not believed.
- **The lock screen, sudo and polkit check the cache with no age limit**, or
  a person signed in for three weeks could not unlock.
- **The cache entry goes** on a `credentials` refusal only when the password
  typed is the one the cache knows (otherwise anyone could wipe a person's
  offline sign-in); always on `not_member`, `inactive`, `sso_required` and
  `not_allowed`; and when `desired.people` no longer allows them.
- **The cache is sealed** with `systemd-creds` (TPM2 where there is one) under
  `mauvely-person-<username>`: one decrypt per unlock. The password also opens
  the person's Cloud vault, so the verifier is worth keeping off a copied disk.
  Verifier: Argon2id, its own 16-byte salt, m=64 MiB, t=4, p=1, associated
  data `mauvely-os offline cache v1`.
- **A demoted admin leaves `wheel` at the next check-in**, not only at their
  next online sign-in; offline sign-in never re-promotes. Promotion still waits
  for an online sign-in, which writes the record.
- **Text logins ask `desired.people`'s admins**, the current list.
- **The primary group's membership file** (`timur:timur.membership`) is
  written too: nss-systemd(8) says drop-ins must carry it.
- **Records carry `"service": "com.mauvely.Users"`**, the mark of ours. A uid
  or name another account has is refused (`internal`), including a name one of
  our records holds on another uid (a handle reused by someone new). A uid
  that had another of our names is a rename: old records and cache go, the old
  home stays.
- **`realName`** loses control characters and colons, cut at 120.
- **The login's session replaces a stored one** in mauvely-session and is
  sealed into `os.cred` (it was held in memory only). `OsSession.email` holds
  the handle: the login answer has no address.
- **The hand-off directory is `01733`** so the person can delete their own
  file; the file is staged in `/run/mauvely` and renamed in, and
  mauvely-session takes only its own `0600` regular file without following a
  link. A directory another user plants at your name fails the hand-off
  (logged; that person gets the sign-in window).
- **Root only for `plasmalogin`**, on top of the peer rule: a person could
  otherwise mint sessions and write records from their own session.
- **Limits**: 32 connections, 4 per non-root uid, 2 Argon2 at once, a 2 s
  delay after a wrong password away from the login screen.
- **Logs** name a typed username only once it is a person here.
- **Messages** are in `wire.rs` and `docs/login.md`; the email factor's line
  is "Enter the code we emailed you."

### For os-image

Do not move `agent.ref` from here; the parent session does it.
- **Build**: `cargo build --release --locked` now also makes
  `target/release/libpam_mauvely.so`; the builder needs `pam-devel` (it links
  libpam). Install it as `/usr/lib64/security/pam_mauvely.so`. It exports
  `pam_sm_authenticate`, `pam_sm_acct_mgmt`, `pam_sm_setcred`, nothing else.
- **Units**: `dist/mauvely-login.service` to
  `/usr/lib/systemd/system/`, enabled. It shares `RuntimeDirectory=mauvely`
  (`0755`, preserved) and `StateDirectory=mauvely` (`0700`) with
  `mauvelyd.service`.
- **`mauvely-home@.service`**: started as `mauvely-home@<username>.service`,
  the plain name, after the userdb record is written; the agent waits 20 s.
- **Files**: `/run/mauvely/auth.sock` (`0666`), `/run/mauvely/login/`
  (`01733`, made by the service), `/run/mauvely/.login-<uid>.tmp` briefly,
  `/var/lib/mauvely/people.json` and `people/`, `/var/lib/mauvely-desktop/people.json`
  (`0644`, the greeter's), `/etc/userdb/*` (`0644` files and links).
- **`/etc/userdb` is `0700` on the image.** Root reads it, and nss-systemd in
  an unprivileged process goes through `systemd-userdbd`, so that must stay
  enabled (Fedora's default); `getent passwd <person>` as the person, on the
  VM, is the check. systemd's own docs want the records world-readable.
- **SELinux**: the service is `unconfined_service_t` (bin_t), creates the
  socket and `/run/mauvely/login`; mauvely-session (`unconfined_t`) reads and
  deletes the hand-off. Who connects: `xdm_t` (plasmalogin-helper),
  `local_login_t` (`login`), `policykit_auth_t`, `sshd_session_t`,
  `unconfined_t` (lock screen, sudo, su).

### Never run

- On the VM: the patched login screen against the real module and service,
  a real TPM sealing the cache, SELinux enforcing, the real
  `mauvely-home@.service`, `systemd-userdbd` serving the drop-ins to the
  person, and `mauvely-session` taking the hand-off in a real session.
- Against the real website-devices and website-main: only fakes. The fakes
  follow `worker/routes/login.ts` and `docs/OS-LOGIN.md`, read at
  website-devices and website-main `origin/main` on 2026-10-22.
- The `systemctl` path inside `mauvely-login.service`'s sandbox.

### Left

- **A person who leaves keeps their userdb record and home**: removing them is
  brief 29's reset or a later cleanup. On a shared device a removed member
  keeps their cache (so their lock screen and sudo) until they try the login
  screen online: `desired.people` does not list a shared device's members.
- **Usernames a computer can't use** (a leading digit, 32 characters) cannot
  sign in; mapping them is brief 26's open "Usernames" item.
- A version 0 account's upgrade is only logged when it fails; the next
  sign-in tries again.
- A login whose account phase fails after the hand-off leaves the session file
  in `/run` until the next login overwrites it or a reboot.

### Found, not changed

- `signin::tests::closed_by_the_person_is_later_and_it_waits_to_be_finished`
  failed once under a parallel build (read `inish` for `finish`) and passed
  six runs after: a timing flake in the fake window script.

## 2026-10-22, evening: brief 22's S4, the browser extension

Firefox and Chromium are signed in to mauvely.com from the computer's link.
`docs/browser.md` has the design; this is what it does not say. `cargo test`
passes (mauvely-browser-host 15 + 2, mauvely-session 137, mauvelyd 90 + 1 + 1),
clippy and fmt are clean, `node --test browser/extension/test/*.test.cjs` (17)
and `python3 -I browser/test_package.py` (13) pass. `Cargo.lock` gains only the
new crate; no dependency is new. `agent.ref` in os-image is not touched.

### What is new

- **`browser/extension/`**: Manifest V3, one source, a manifest per browser.
  Permissions `nativeMessaging`, `cookies`, `https://*.mauvely.com/*`,
  `https://*.mauvely.dev/*`; a test holds them there and finds no `fetch(`,
  `eval(` or the like in the source.
- **`crates/mauvely-browser-host`**: the native host. std and serde_json, static
  musl (476 KB, static-pie, no `NEEDED`, no interpreter).
- **`mauvely-session`**:
  - `browserhost` copies `/usr/libexec/mauvely/mauvely-browser-host` and writes
    `com.mauvely.browser.json` into both browsers' directories, at login and
    every 5 minutes;
  - the broker answers a new op, `origin`, to the browsers alone
    (`docs/broker.md`).
- **`browser/package.py`**: the CRX3 (packed and signed here, no Chromium), AMO
  signing, both policies. os-image's build runs it.

### Decisions the brief left open

- **How a sign-out is told from an expiry:** a removal of the domain cookie
  with cause `expired_overwrite` or `explicit`, while the cookie had more than
  60 s left, is a sign-out. `expired`, `evicted` or a removal at its expiry is
  asked for again at once; `overwrite` is a new value. Chromium reports the
  site's `Max-Age=0` as `expired_overwrite` and Firefox as `explicit`; both
  were seen on the VM through a real `Set-Cookie`.
- **"Until the browser restarts" is a session cookie,** `mauvely_os_held`, on
  the accounts host at `/.mauvely-os-extension/`, a path the site never serves.
  The background is stopped after half a minute idle in both browsers, so
  memory alone would not hold; a `storage` permission was not on the brief's
  list. The back-off note, `mauvely_os_wait`, is the same kind of cookie.
- **Back-off:** 1, 2, 5, 15, 30, then 60 minutes; reset by a success or a
  restart.
- **The extension needs the origin before it can look for the cookie**, and
  must not guess: so the broker's new `origin` op, which mints nothing. The
  host cannot read `/etc/mauvely/server` from inside the sandbox.
- **`sso_required` opens no tab** (`docs/broker.md` said it would). The page's
  own sign-in goes through the organisation; the host does not pass `start` on.
- **A page of the site that started loading without the cookie is reloaded**
  once it is set, so the first page after a browser start is signed in.
- **The host is placed for both browsers, installed or not,** as Plasma's own
  browser integration already does in the same directories on the VM.
- **Ids:** host `com.mauvely.browser`; Firefox `os-signin@mauvely.com`;
  Chromium `ioajmohlalajkifjboclbjlinkkogcej`, **the throwaway key's**. The
  key's private half is `~/.cache/mauvely-os/s4/crx-key.pem` on Timur's
  workstation, never in a repository.
- **Delivery is by the image, not refs in the Mauvely remote** (os-image's
  `HANDOFF.md`): unmanaged Flatpak extensions, bind-mounted from
  `/usr/share/mauvely/browser/`. The extension, its host and the broker then
  move together, and the agent installs nothing.

### Seen on `mauvely-01` (2026-10-22, `next` `sha256:1e1abf79…`, timuri linked to production)

The release `mauvely-session` built here (Fedora 44, as the image builds it) ran
as timuri's in place of the image's, with the host in `/usr/libexec/mauvely/`
(the transient `/usr` overlay), and the staged trees bind-mounted by the two
mount units (from `/run/systemd/system`, sourced from `/var/tmp`). Chromium
156.0.8078.47 was installed system-wide from Flathub for the run; the agent
granted it `xdg-run/mauvely:ro` on its own within a minute. Firefox 158.0.1 was
there. Everything was undone afterwards (os-image's `HANDOFF.md` lists it).
Screenshots and the journal lines are in the session scratchpad (`s4/shots/`),
not committed.

- **Placement:** at start the session wrote the host and manifest into
  `/var/home/timuri/.var/app/org.chromium.Chromium/config/chromium/NativeMessagingHosts/`
  and `…/org.mozilla.firefox/.mozilla/native-messaging-hosts/`, beside Plasma's
  `org.kde.plasma.browser_integration.json`.
- **Chromium, policy:** `chrome://policy` showed `ExtensionInstallForcelist`,
  Platform, Machine, Mandatory, OK; the extension was installed from the
  `file://` update manifest and the CRX this repo packs ("All forced extensions
  seem to be installed"), as "installed by your administrator".
- **Chromium, sign-in:** the extension asked `origin` then `browser`; the broker
  minted "Chromium on mauvely-01"; the cookie was `.mauvely.com`, `/`, Secure,
  HttpOnly, Lax, persistent to 2026-11-21. `https://mauvely.com/account`
  showed timuri's account (Timur Inal, timur.suez). A fresh profile started
  straight at `/account` was signed in on its first page.
- **Sign-out holds** (no sign-out on mauvely.com was made: a stand-in at
  `signout.mauvely.com`, mapped to the VM, answered with exactly
  `clearCookies()`'s two `Set-Cookie` headers): Chromium logged
  `signed out in the page (expired_overwrite)`, `/account` went to the sign-in
  page, and after the worker had been stopped a navigation asked only
  `origin`, minted nothing and stayed signed out. Closed and started again: one
  ask, the broker answered from its cache, signed in.
- **Refused:** an unpacked extension with another id got "Access to the
  specified native messaging host is forbidden"; the host run inside
  `io.mpv.Mpv` (system-wide from Flathub, granted `xdg-run/mauvely:ro` on the
  command line) was refused by the broker for both ops ("io.mpv.Mpv may not ask
  for it"), as were a host process and the runtime run as an app.
- **Firefox, policy:** `org.mozilla.firefox.systemconfig` mounted
  (`app-extensions=…systemconfig=local`), `Services.policies.status` 1,
  about:policies listed `ExtensionSettings`, "Not fully applied": the unsigned
  XPI was refused, `ERROR_SIGNEDSTATE_REQUIRED`, as expected without AMO.
- **Firefox, temporary add-on** (Marionette, scratch profile): minted "Firefox on
  mauvely-01", `/account` signed in; the stand-in's `Set-Cookie` was logged as
  `signed out in the page (explicit)` and held; after a restart (the temporary
  add-on installed again) it was signed in from the broker's cache. An
  unlisted temporary add-on got "No such native application".
- **Two mints in all** (one per browser), within the 10 an hour.
- **Unmanaged extensions, the details:** a *link* at
  `/var/lib/flatpak/extension/<name>` mounts for Firefox but not for Chromium,
  and makes every `flatpak run` print GLib criticals (Flatpak 1.18.4, GLib
  2.88.4); a dangling one is harmless for Chromium and would stop Firefox
  starting. A real directory, or a bind mount, works for both, silently.

### Never run

- **Release Firefox with an AMO-signed XPI**: force-installed by policy, its
  host permissions, `onStartup` after a restart. Needs Timur's AMO keys.
- **AMO itself**: `package.py` has run only against a fake on loopback.
- **An image carrying it on a machine**: the units from `/usr/lib/systemd/system`
  at boot, the trees from `/usr/share`, a new extension version arriving with
  an image (Chromium's update check, Firefox's newer-version install).
- **A real sign-out on mauvely.com** (not made, by rule), and so the broker's
  `/api/auth/me` check minting afresh after one; S2's tests cover that.
- **The broker refusing** (`signed_out`, `rate_limited`) on the VM: timuri is
  linked. The back-off is in the extension's tests.
- mauvely.dev (staging) devices; the session restore that keeps the hold past
  a restart.

### What Timur provides

- **`CRX_SIGNING_KEY`** (os-image Actions secret): an RSA key, PEM. It signs the
  CRX at each `next` build. **It changes the Chromium id**: its public half goes
  into `browser/extension/manifest.chromium.json` `key` and the new id into
  `browserhost::CHROMIUM_ORIGIN` (`docs/browser.md`, "The ids").
- **`AMO_JWT_ISSUER`, `AMO_JWT_SECRET`** (os-image Actions secrets): an
  addons.mozilla.org API key on the account that will own
  `os-signin@mauvely.com`. Used at each `next` build: the first signs the
  version (unlisted), later ones download it again.

## 2026-10-22, night: the push channel

`mauvelyd` keeps one WebSocket to its Durable Object in website-devices, so a
console change makes it check in at once (`push`). The server side is
website-devices `1766db3`, on its `staging` (not yet production). `cargo test`
passes, clippy and fmt are clean, `cargo build --release --locked` builds.
`agent.ref` in os-image is not touched.

### What it does

- **`push::start`** runs one thread: connect to `wss://<server>/api/agent/v2/socket`
  (`ws://` for an `http://` server) with the `X-Mauvely-*` headers from
  `signing`, over `GET` and an empty body; text `ping` every 45 s; dead after
  90 s of hearing nothing; `{"t":"checkin"}` goes into an `mpsc`.
- **`agent::run` sleeps on `push::Wake`** instead of `sleep`: `recv_timeout`
  on that channel. A push ends a wait after a successful check-in, but never
  sooner than 5 s after it (`NUDGE_FLOOR`), and pushes meanwhile are one. After
  a failed check-in (`Tick::Retry`, new) the backoff is waited whole and pushes
  are dropped. A channel that has ended makes every wait a plain sleep.
- **Reconnecting:** `schedule::Backoff` with jitter, reset by each successful
  upgrade, so a dropped connection redials in about 60 s. 404 or 426 is a
  server without the channel: asked again in about an hour, and the interval
  loop carries on exactly as before. 403 stops the thread until a restart.
- **Dependencies:** `tungstenite` 0.30 with `handshake` only, plus `rustls`
  (`ring`, `std`, `tls12`) and `webpki-roots`, the crates and provider `ureq`
  already pulls in. New to `Cargo.lock`: `tungstenite`, `sha1`,
  `data-encoding`. No aws-lc, openssl, native-tls or tokio anywhere in the
  workspace (`cargo tree -i` finds none). TLS is done here, not by
  tungstenite's TLS features, so the provider is passed explicitly and no
  process-wide default is needed.

### Decisions the brief did not make

- **When a 403 means revoked.** The check-in needs the body to say `revoked`.
  An upgrade's body is only what arrived with the headers (tungstenite's
  handshake keeps that tail), so here a 403 is revoked when the body says
  `revoked` **or there is no body**; a 403 naming another error, or an HTML
  block page, backs off like any failure.
- **Close codes are only logged.** 4003 (revoked) does not stop the thread;
  its reconnect is answered 403, which does. One authority for "stop".
- **The floor counts from the end of a check-in**, not its start, so a push
  that arrives during a long reconcile checks in 5 s after it.
- **Unknown messages are logged in debug builds only** (there is no log level
  here), up to 80 characters; `pong` never.
- **Messages are capped at 64 KiB** (`WebSocketConfig`); the server sends a
  few bytes.

### Verified how

- Loopback tests with tungstenite's server side: the upgrade's headers and
  signature (the message rebuilt from the brief, empty-body hash written out),
  a fresh nonce per attempt; `checkin` passed on and other types, non-JSON and
  binary ignored; pings answered keep it open past three dead intervals, and
  silence is noticed and redialled; 403 revoked and 403 with no body stop it,
  403 with another error or HTML backs off; 404 and 426 wait about an hour;
  backoff doubles and a connection resets it; nobody listening ends it;
  `https` speaks TLS. `Wake`: the floor, a push after the floor wakes at once,
  pushes coalesce, a backoff is not cut short, a wait is never longer than
  asked, an ended channel sleeps. `agent::run`: pushes check in on a 900 s
  interval within the floor, and the channel gets this device's server, id
  and key.
- Each guard broken once, and a test failed for each: the floor, the
  backoff rule, dead detection, pong as liveness, the 403 rule, 426, the
  backoff reset, protocol Pings instead of text, signing as POST or with a
  body, every message a push, the unwanted check. **Not caught by a test:**
  a `Wake` that kept spinning on a disconnected channel instead of dropping it
  (it still waits the right time, burning CPU); and `run` passing `Retry`
  waits as nudgeable (the glue is two lines; `Wake` itself is tested).
- **Against a real Worker:** website-devices under `wrangler dev` on a scratch
  store, driven by a scratch harness (session scratchpad, not committed) that
  runs this crate's `push::run`. workerd accepted the Rust signatures; two
  devices in a collection were each told of an assigned app, a desktop change
  and an unassignment, the moved one of its move, nobody of a rename; a
  second connection closed the first with 4000; the revoked one was told,
  closed with 4003, refused 403 on its reconnect and stopped. Against
  production (no route yet) it got 404 over real TLS through Cloudflare, with
  ring and the compiled-in roots, and waited an hour.
- **Against staging** (`devices.mauvely.dev`, website-devices `1766db3`), with
  a test device row written into the staging D1 and removed after: connected
  over TLS through Cloudflare, held up past its silence limit by `pong` alone,
  replaced with 4000, then refused 403 once the row was revoked and stopped;
  an unknown id got 401 and backed off.

### Never run

- The real `mauvelyd` with this code on a machine, under
  `dist/mauvelyd.service`'s sandbox (`RestrictAddressFamilies` already allows
  `AF_INET`/`AF_INET6`). No image carries it yet.
- A nudge reaching a device through the console's forwarder, and a staging
  deploy's sockets dropping and the fleet redialling.
- A laptop suspending with the socket open: the read timeout and the 90 s
  dead check should notice on resume, and nothing has shown it.

## 2026-10-22, later: the desktop policy (brief 25, phase 3)

`mauvelyd` writes a collection's desktop policy as KDE Kiosk files, and
`mauvely-session` puts each person on its preset once per change. The server
side is website-devices `dab8229` (on its `staging`): `desired.desktop:
{preset, lock: {look, layout}, version}` in every check-in answer. `cargo test`
passes, clippy and fmt are clean, `cargo build --release --locked` builds and
`Cargo.lock` is unchanged. `agent.ref` in os-image is not touched.

### What it does

- **`mauvelyd` (`desktop`)** writes `/var/lib/mauvely-desktop/xdg/kdeglobals`
  and `/var/lib/mauvely-desktop/policy.json`, root's, `0755`/`0644`, only when
  they change, and removes `kdeglobals` when the policy asks for nothing.
  `desired.desktop` is kept as JSON in `api::Desired` and parsed here, so one
  it cannot read (a preset added later) is a `desktop: …` error in the next
  `last_apply` and leaves the files as they were, rather than failing the
  whole answer. An answer without it (an older server) leaves them too.
- **The files:**
  - Mauvely: `AutomaticLookAndFeel=true`, the light and dark ids, and
    `LookAndFeelPackage` the light one. Locked, the three switching keys get
    `[$i]`; `LookAndFeelPackage` never does, because Plasma's switcher writes
    it at each change of light and would be stuck on the first one.
  - Plasma: `AutomaticLookAndFeel=false` and `LookAndFeelPackage=com.mauvely.plasma.desktop`,
    both `[$i]` when locked. That id is a stand-in until os-image's phase 2
    ships the package.
  - The look lock: `[KDE Control Module Restrictions][$i]` for the 11 ids in
    `desktop::LOOK_MODULES` (Plasma 6.7's; `kcm_style` and
    `kcm_breezedecoration` are additions to the brief's list).
  - The layout lock: `[KDE Action Restrictions][$i]
    plasma/plasmashell/unlockedDesktop=false`; with the look locked too,
    `plasma/allow_configure_when_locked=false`.
- **`mauvely-session` (`look`)** reads `policy.json` every 5 minutes (the main
  loop) and remembers `<version> <preset> <locked|open>` in
  `$XDG_STATE_HOME/mauvely/look`. When that differs and there is a preset:
  - Mauvely: `plasma-apply-lookandfeel -a com.mauvely.light.desktop`, then,
    unless the look is locked, `kwriteconfig6` for the three switching keys,
    then kded's `unloadModule`/`loadModule lookandfeelautoswitcher`, which
    picks dark at night;
  - Plasma: `plasma-apply-lookandfeel -a com.mauvely.plasma.desktop`, then the
    same restart, which stops the switcher.
  A failed apply is not remembered and is tried at the next look; a restart
  that fails is only logged.
- **The look lock is part of the memory, not only the version**, because the
  server does not bump the version on an unlock. While locked, the pinned keys
  can't be written to the person's own config (`kwriteconfig6` exits 2, by an
  absolute path too); a stale value there, such as switching left on under
  Plasma, came back once the lock went. Applying again, unlocked, writes them.

### Seen on the VM (`mauvely-01`, Plasma 6.7.5, 2026-10-22)

The files were written by hand, as `desktop` writes them, with
`XDG_CONFIG_DIRS` set the way phase 2's `/etc/profile.d` script will. All of it
was removed afterwards, and timuri's config restored.

- **Reaching the session:** both `/etc/environment.d/` and `/etc/profile.d/`
  put the directory in plasmashell's, KWin's, kded's and ksmserver's
  `XDG_CONFIG_DIRS`, after `~/.config/kdedefaults`.
- **Look locked:** System Settings' "Colours & Themes" held only System
  Sounds; "Text & Fonts" only Font Management; the Quick Settings page lost its
  global theme button. `kcmshell6 kcm_colors` showed "The module kcm_colors is
  disabled… by the system administrator."
- **Quick Settings' light/dark/automatic picker stays**, but changes nothing:
  under Mauvely the switch stays on; under Plasma, Apply stays greyed out.
- **`plasma-apply-lookandfeel` from a terminal gets through.** The pinned keys
  hold, but the theme's colours are applied. Under Mauvely the next change of
  light (or a switcher restart) puts it back; under Plasma nothing does. Kiosk
  is a convenience, as decided.
- **The session's sequence, by hand at 03:07:** light applied, switcher
  restarted, dark on.
- **Layout locked:** `PlasmaShell.immutable()` true, `editMode` can't be set,
  `evaluateScript` answers "Widgets are locked". The desktop menu has no Edit
  Mode or widgets; the panel has no menu; the launcher has none; a pinned
  task's menu has no Unpin. **So pinning and unpinning taskbar apps goes with
  the layout lock.**
- **The wallpaper:** both locked, the desktop menu has no "Desktop and
  Wallpaper". The look alone leaves it there, and Edit Mode, as expected.
- **Unlocked:** edit mode and the Colours page back after a plasmashell
  restart.

### Never run

- The real `mauvelyd` and `mauvely-session` with this code on a machine: no
  image carries it yet. The hand-written files carried the keys and groups
  the unit tests pin.
- A new account's first sign-in with the policy in place (startplasma reads
  `LookAndFeelPackage` from the policy directory; read from the source, not
  seen).
- `plasma-apply-lookandfeel -a com.mauvely.plasma.desktop` against phase 2's
  real package; a stand-in copy of Breeze was used.

### Locks take effect at the next sign-in

plasmashell reads the restriction when it loads, and System Settings when it
starts. Nothing restarts plasmashell for a lock.

## 2026-10-22: the sign-in window

`mauvely-session` now links the computer through `mauvely-signin`, os-installer's
new `signin/` (`95de683`), a frameless Mauvely window around website-main's
`/link?code=<code>&embed=os`. The kdialog windows and the notifications are its
fallbacks, unchanged. `docs/broker.md`, "Linking", has the flow;
`crates/mauvely-session/src/signin.rs` the process side. `cargo test` passes
(mauvely-session 113, mauvelyd 64 + 1 + 1), five runs in a row; clippy and fmt
are clean; `cargo build --release --locked` builds and `Cargo.lock` is
unchanged. No crate is new.

### What changed

- **`signin`**: starts `/usr/bin/mauvely-signin` with no arguments, writes
  `{"code","origin"}` and a newline on its stdin and keeps the pipe; reads
  `closed` from its stdout ("Later"); `finish()` writes `finish` and closes
  the pipe, and kills it five seconds later if it is still there. Exit 0 not
  asked for is "Later"; anything else, or a signal, is a failure.
- **`broker::Desktop`**: `offer(ask)` and `show_link(code, page)` replace
  `offer()`, `show_code()` and `open()`. With the window installed the offer
  starts the link at once, since the window is the offer and the code;
  `show_link` opens the window, or the kdialog code window and the browser.
- **The window finishes only after the claim**: from `signed_in` (the poll has
  claimed the link) and `withdraw` (declined, expired, closed). website-main
  re-checks the approving session at the claim, so the window's sign-out must
  come after it, or the link is burnt with `400 access_denied` (website-main
  `1379948`, docs/AUTH-BROKER.md, "The sign-in window").
- **Closing the window** sets `Broker::closed()`: the poll loop polls once
  more, claims a link approved just before, and otherwise ends it ("signing in
  ended: closed"), not offered again this login.
- **A link that could not start re-offers as a question** (`ask_first`), even
  with the window installed. Without that, a server unreachable at login
  would start a link, fail, and start again in a tight loop. Cleared once a
  link starts.
- **The fallback chain:** window not installed, the kdialog question then the
  kdialog code window and the browser, as before; window failing to start or
  later, the kdialog code window and the browser for the same link; kdialog
  missing or failing, notifications.
- **The milestone 2 seam:** `broker::LoginSession` (`NoLoginSession` today),
  asked in `Broker::load` before anything is shown. A session for this origin
  that has not expired is held for that login and nothing is offered.
  `docs/broker.md`, "Milestone 2", says what is left to M2.
- **`MAUVELY_SIGNIN`** moves the program, in debug builds only.

### Verified how

- Tests, with `fixtures/fake-signin.sh`: the first line and no argv or
  environment holding the code; finish as a line then the end of input, not
  reported; the end of input alone when the session goes; close is Later and
  the window waits to be finished; exits and crashes; a window that will not
  finish is killed; a new window finishes the old; not installed. Broker:
  ask-first after a failed start and cleared after a good one; close ends the
  link after one more poll; a link approved just before the close is still
  claimed; the login seam (taken, and refused for another origin or expired).
  Sabotaged one at a time, and a test failed for each: no `ask_first`, no
  final poll, no origin check on the login's session.
- **End to end** in the nested sway, harness in the session scratchpad
  (`signin-e2e/e2e/`, not committed): the debug `mauvely-session`, the real
  `mauvely-signin`, a fake accounts service on 127.0.0.1:8787 in a private
  network namespace, a private bus with no activation, a fake notification
  server, the real `systemd-creds --user` and `kdialog`. It showed:
  1. the window opening on its own at start, with the code; no process's argv
     or environment held the code, the window's WebEngine children included;
  2. sign-in, approve: the claim, then the window's sign-out carrying its
     cookie, the window gone, "Signed in to Mauvely as e2e@example.invalid",
     `os.cred` 0600;
  3. close without approving: one more poll, "signing in ended: closed", the
     window finished, nothing re-offered;
  4. approve and close at once, with an 8 s poll interval: the hidden window
     waited, the next poll claimed, then it signed out;
  5. a window that starts and exits 1: the kdialog code window (stdin, argv
     `--textbox - 380 150`) and `xdg-open` given `/link` without the code;
  6. no window installed: the kdialog question.

### Never run

- On Plasma or Mauvely OS, or against website-main's real pages. The image
  carrying it is built (os-image) and not booted.
- A real single sign-on, Google's refusal of embedded sign-in, passkeys.

### Found, not changed

- **A kdialog window outlives `mauvely-session`** when the session is killed:
  `dialog` never kills its child on exit. At a real logout the compositor
  goes, which should take kdialog with it, so it likely shows only in a
  harness. The sign-in window does not outlive it: its stdin closes and it
  finishes.

## 2026-10-21, late: bootc leaks mounts inside the service's sandbox

**Every `bootc` command now runs in PID 1's mount namespace**
(`bootc::bootc_argv`: `nsenter --mount=/proc/1/ns/mnt -- bootc …`).

- **What happened:** on Timur's VM, with one-minute check-ins, every
  `bootc upgrade` began failing with "No space left on device" about an hour in.
  No filesystem was full. The agent's mount namespace held 65,584 mounts:
  32,768 of `/run/bootc/storage` and 32,767 of `/sysroot/ostree/bootc/storage`.
  That hit `fs.mount-max` (100,000) on the next doubling.
- **The cause:** `mauvelyd.service`'s `PrivateTmp`/`ProtectHome` give it a
  private mount namespace. In any such namespace each `bootc upgrade` leaves
  its storage bind mounts behind, and propagation doubles them: 1, 3, 7, 15,
  31 after five runs (`systemd-run -p PrivateTmp=yes …`). Either option alone
  does it. Unsandboxed it stays 0.
- **The fix, proven on the VM:** with `nsenter --mount=/proc/1/ns/mnt` from
  inside the same sandbox, it stayed 0 in the sandbox and on the host over
  four upgrades, under SELinux enforcing (`unconfined_service_t`). The rest of
  the agent stays sandboxed.
- **Not changed:** `rpm-ostree` goes through rpm-ostreed over D-Bus and
  mounts nothing in the agent's namespace.
- **Worth reporting upstream to bootc:** a sandboxed caller leaks mounts
  exponentially. tuned's `bootc loader-entries` call at boot, which hung
  behind the agent and timed out, may be the same family.
- **Until an image with this ships,** a machine whose agent has made about
  fifteen `bootc upgrade` calls since its last restart can't upgrade. A reboot
  or `systemctl restart mauvelyd` clears it.

## 2026-10-21, evening: sign-in as windows, "<App> is ready", failed apps in the check-in

Four commits on `main` after `c6e1d21`: `6b29744` (failed list), `0da6ad1`
(ready), `ff760a1` (windows), `d0ac465` (`gio launch`), and the one that holds
this file and the docs. `cargo test` passes (mauvelyd 64 + 1 + 1, mauvely-session
96), clippy and fmt are clean, `cargo build --release --locked` builds both and
`Cargo.lock` is unchanged. `agent.ref` in os-image is not touched. The commits
end `Co-Authored-By: Claude Sonnet 5.5`, which is the model that wrote them; the
brief asked for Opus 5.5, as the older commits say.

### 1. The sign-in offer and the code are windows (`src/dialog.rs`)

- **The offer** is `kdialog --yesno`, "Link this computer to your Mauvely
  account.", buttons "Open the sign-in page" and "Later". `--yesno` is the only
  mode with a text and two buttons whose labels can be set. Exit 0 is the first
  button, 1 the second, 2 a closed window (all three seen with real kdialog
  26.08.2 in the nested sway). 0 starts the link, as the Sign in button did;
  1 and 2 do nothing, as dismissing the notification did.
- **The code** is `kdialog --textbox - 380 150`, shown once the link has
  started: "Enter this code to sign in" over the code in large type. It stays
  until the link is approved, declined or expires; its OK closes it and the link
  carries on.
- **Decision: the code is not in any argv.** `--yesno`/`--msgbox` take their
  text as an argument, which every uid can read under `/proc`: the thing the
  S2 review fix took out of `xdg-open`. `--textbox -` reads its text from
  stdin (kdialog's `widgets.cpp`, `file == "-"`). The price: the text box has
  one button, "OK", which kdialog cannot rename, so the code window is not the
  two-button window the brief pictured; and kdialog feeds what it reads to
  `QTextEdit::append`, which turns it into rich text when it looks like some
  (that is how the code comes out large). So only `[A-Za-z0-9-]{1,32}` is sent,
  and anything else is a notification. The end-to-end run looked at every
  process's argv while the code window was up: no code.
- **Fallback to the notifications**, which are unchanged: kdialog not found, the
  code not plainly a code, or kdialog dying (signal, or an exit status that is
  not 0, 1 or 2; Qt aborts without a display). A window that dies minutes in
  still falls back, from its waiting thread. Seen with a fake kdialog that is
  missing and one that crashes.
- One window at a time; a new window, the confirmation or the end of the link
  takes the old one down, and a window taken down here is never reported as an
  answer. A waiting thread polls `try_wait` every 100 ms so a kill and a wait
  cannot cross.
- **Seen for real** (nested sway, real kdialog, real `mauvely-session` debug
  build, fake accounts and fake notification server on a private bus): both
  windows drawn, "Open the sign-in page" started the link and opened the page
  without the code, OK on the code window left the link going, approval left no
  window and showed "Signed in to Mauvely as …". Screenshots are in the session
  scratchpad, not committed.
- **Not seen, and worth a look on Plasma:**
  - **The browser may cover the code window.** `run_link` shows the code, then
    opens the page; a browser that is not running yet maps its window a few
    seconds later and sits over a window with no always-on-top. If that is the
    experience, the options are showing the code after `open`, or a short wait
    between them; neither was done, as the broker's order is not mine to change
    on a guess.
  - KWin's placement and focus for a window started by a service with no
    activation token.
  - The red "no" icon kdialog puts on "Later" and the question-mark icon are
    kdialog's; `--icon` only sets the window icon.
- Tests: `dialog.rs` runs `fixtures/fake-kdialog.sh`, linked into a directory
  of its own. It is a link because a script written by one test thread while
  another forks fails with "text file busy"; that was a 40 % flake before.

### 2. "<App> is ready"

- **`mauvelyd`** writes `/run/mauvely/installed.json` after the reconcile, for
  each app `flatpak install` succeeded for (not one already there, not one that
  failed), through `reconcile`'s new `Applied { last_apply, installed }`:
  `{"installs":[{"id":"…","branch":"stable","at":1760400000}]}`, oldest first,
  the last 50, 0644, written to `.tmp` and renamed. A garbled file is replaced.
  A failure to write it is logged and is not an error of the apply.
  `dist/mauvelyd.service` has `RuntimeDirectory=mauvely`,
  `RuntimeDirectoryMode=0755`, `RuntimeDirectoryPreserve=yes`; a test reads the
  unit for them. `MAUVELY_RUN_DIR` moves it, like the other two.
- **`mauvely-session`** (`src/ready.rs`) looks every 5 s. "<name> is ready",
  icon from the desktop file's `Icon=` (else `system-software-install`), one
  action, Open, default timeout. Name and icon are the `[Desktop Entry]`
  group's own `Name=`/`Icon=` in
  `/var/lib/flatpak/exports/share/applications/<id>.desktop` (not `Name[de]`,
  not an action's), cleaned of control characters and cut at 60.
- **Several at once: up to 3 are one notification each; more is one "5 apps
  are ready" with no Open.** An Open needs one app to open, and a person who logs
  in after a night of installs is not buried.
- **Once per person:** `$XDG_STATE_HOME/mauvely/ready`, one `<id> <branch> <at>`
  per line, 0600 in the 0700 directory, written whole and renamed, pruned to
  what the agent's file still holds, and not rewritten when nothing changed. An
  app removed and installed again has a new `at`, so it is told again.
- **Before the first login: nothing.** No memory file means the first look,
  which only remembers what is there. Apps installed after a reboot but before
  a later login are told then: /run is empty at boot, so only installs since.
- An install with no exported desktop file, or one with no name, is remembered
  and not shown. An id or branch that is not `[A-Za-z0-9_.-]`, starts with `-` or
  `.`, or holds `..` is not an install at all (the id becomes a path); the agent's
  file larger than 64 KiB is refused. A read error is logged once, not every 5 s.
- **Open runs `gio launch <desktop file>`.** On Kinoite 44 the image has
  `gtk-launch`, `kioclient`, `kstart`, `flatpak`, `gio`. `kioclient exec`
  (first choice, KDE's own) shows an "untrusted launcher" dialog when the file is
  not in an applications directory on its own search path; seen in a nested
  session with the exports left off `XDG_DATA_DIRS`. `gio launch` takes the path,
  asks nothing and needs no display. `flatpak run` puts the app in its own
  `app-flatpak-<id>-<n>.scope`, so it does not end with the helper (flatpak 1.18.4
  source).
- **Not done:** the activation token. Plasma sends `ActivationToken` before
  `ActionInvoked`; passing it as `XDG_ACTIVATION_TOKEN` to the launcher would let
  KWin focus the new window. Without it the app may open behind the others.
  Untried on Plasma.
- **Not done:** localised names (`Name[de]`); the brief said `Name=`.
- Seen on a private bus, as above, with `/run` and `/var/lib/flatpak` as tmpfs in
  a private mount namespace: two apps already installed showed nothing; Compose
  became "Compose is ready" with Open; two clicks ran the launcher once; five at
  once were "5 apps are ready"; a restart told none of it again.

### 3. `last_apply.failed`

`{"ok", "errors", "failed": [{"id", "branch", "error"}]}`; `errors` is as it
was. At most 50 entries (the first), each `error` cut to 500 characters counted
in UTF-16 units, as the server counts them (website-devices' `reportedFailures`
does `slice(0, 500)`), never inside a character. Left out of the body when
empty, so a clean check-in is byte for byte what it was.
- **Install and removal failures name their app exactly.**
- **A failed `flatpak update` names an app only when flatpak's own line does:**
  `Failed to update <id>: ` (`flatpak-cli-transaction.c`, 1.18.4: printed for the
  first failed operation) matched against the installed apps. A runtime or an
  error with no name stays text only. **The format is from flatpak's source and a
  fixture written from it, not from a captured run**; if it never matches, the
  update half is silent, not wrong.
- Other failures (a remote, the image, a grant) are `errors` only.
- website-devices (`worker/lib/failures.ts`) takes this as it stands: it keeps
  the first 50, requires a three-element Flatpak id, a branch and a string error,
  keeps an id/branch once.

### Verified how

- Test-first for the pure parts; each guard sabotaged once and a test failed:
  the cap, the cut (UTF-16 and pair splitting), omitting `failed` when empty,
  install/removal/update naming, the install list (failures, already-there),
  the 50 limit, atomic and 0644 (under `umask 077` too), the unit's three lines;
  the first-look baseline, one-per-install, id validation (each rule), the three
  limit, name cleaning, group rules, the size cap, memory pruning, unchanged
  look not rewriting, the memory's modes, the launcher's argv; the dialog's code
  never in argv, the code check (length, `<`), exit statuses, failures, a window
  taken down not reported, replacement, close, stdin closed.
- Not sabotage-checkable: the `&` in the code check (an entity needs `;`, which
  is checked).
- The end-to-end harness is in the session scratchpad and is not committed
  (`e2e2/`): a private bus (own `DISPLAY` number), fake notification server that
  clicks on request, fake accounts in a network namespace, fake `kdialog`, `gio`,
  `xdg-open`, `rpm-ostree`, the **real** `systemd-creds --user`, and the debug
  `mauvely-session`. `MODE=overlay` for the ready path and the fallbacks,
  `MODE=hsway` for real kdialog in the nested sway.

### Never run

- On Plasma or Mauvely OS: anything above. In particular the notification's Open
  click, `gio launch` of a real exported Flatpak app from a user service, KWin
  with the two windows, and the unit with the three new lines (it passes
  `systemd-analyze verify` but for the missing binary).
- A real failing `flatpak update`.

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
     declined or expired link takes the code away. (Since the evening of the
     same day the offer and the code are kdialog windows first, and these
     notifications are the fallback; see the top section.)
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
