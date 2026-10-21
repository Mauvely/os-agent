# The sign-in broker

`mauvely-session` links this computer to the person's Mauvely account once,
then signs the Mauvely apps and the browsers in from that link. Brief 22, S2.
The code is `crates/mauvely-session/src/broker/`.

The server half is website-main's `docs/AUTH-BROKER.md`, § Mauvely OS. The
framing is Suite's broker (`suite/docs/auth-broker.md`), which the apps
already speak.

## Linking

Once per local user, until M2's login fills the same store.

1. At each graphical login with no `os` session, a notification: "Sign in to
   Mauvely", one action, "Sign in". It stays until dismissed.
2. "Sign in" starts a device link as client `os`
   (`POST /api/auth/device/start`) and opens its page in the default browser,
   through the OpenURI portal, or `xdg-open` when there is none. Only a page
   on the accounts origin is opened.
3. The broker polls `POST /api/auth/device/token` until the link is approved,
   declined or expired (ten minutes).
4. The `os` session is sealed with `systemd-creds --user encrypt`, stdin to
   stdout, into `$XDG_STATE_HOME/mauvely/os.cred` (mode `0600`, in a `0700`
   directory). Its expiry and address are sealed with it.

A link that cannot start, or a browser that cannot open, puts the offer back.
A declined or expired one does not, until the next login.

The `os` session ends, and the offer comes back, when a mint answers `401`
(revoked, signed out, expired on the server) or when its own expiry passes.
Everything minted from it is forgotten with it. A file that does not unseal is
kept, in case that passes, and the offer is shown; a new link replaces it.

### The accounts origin

From `/etc/mauvely/server`, which the installer writes:

| `/etc/mauvely/server` | Accounts origin |
|---|---|
| `https://devices.mauvely.com` | `https://mauvely.com` |
| `https://devices.mauvely.dev` | `https://mauvely.dev` |
| `http://<host>:8798`, `<host>` one of `localhost`, `127.0.0.1`, `[::1]`, `10.0.2.2` | `http://<host>:8787` |

The last row is the local stack: website-devices on 8798, website-main on 8787
beside it. `10.0.2.2` is the host as a qemu VM sees it. Anything else turns the
broker off, logged, and the rest of `mauvely-session` carries on.

### Sealing

Unprivileged, `systemd-creds` hands the work to the root `systemd-creds`
service over varlink. That service always seals a user-scoped credential with
its automatic key: the host secret, and the TPM where there is one, bound to
the user's uid and name and the machine id (`vl_method_encrypt` in systemd's
`src/creds/creds.c`, v258). `--with-key` cannot change that, and
`--with-key=tpm2` alone is refused in user scope, so none is passed.

## The socket

`$XDG_RUNTIME_DIR/mauvely/broker`: the directory `0700`, the socket `0600`,
both the person's. The directory is made once and never removed: a Flatpak
granted `xdg-run/mauvely` bind-mounts it when it starts, and a directory made
again would leave running apps holding the old one.

One JSON object per line each way, then the socket closes. A caller has five
seconds to send its line, of at most 4096 bytes. Sixteen callers are served
at once; the seventeenth is told `busy`.

### Requests

```jsonc
{"v":1,"op":"token","client":"compose","label":"Compose on ada-laptop"}
{"v":1,"op":"browser"}
```

- `token`: an app session for `client`. `label` is optional, and becomes the
  session's name in the Devices tab (control characters dropped, at most 120
  characters).
- `browser`: a browser session, for the extension to set as the
  `mauvely_session` cookie. Any `client` or `label` is ignored: the broker
  names it "Firefox on <hostname>" or "Chromium on <hostname>".

Suite's `cloud-link` op is not served here: `unknown_op`.

### Answers

```jsonc
{"v":1,"ok":true,"token":"…","expiresAt":1771200000,"email":"ada@example.com","origin":"https://mauvely.com"}
{"v":1,"ok":false,"reason":"signed_out"}
{"v":1,"ok":false,"reason":"sso_required","org":"northgate","start":"https://mauvely.com/api/auth/sso/start?org=northgate"}
```

`token`, `expiresAt` and `email` are Suite's. `origin` is new: the accounts
origin the token belongs to, so a caller built for another server can tell
that it is not its own.

| `reason` | Meaning | What the caller does |
|---|---|---|
| `unknown_op`, `version` | Not this protocol. The op is checked first, then `v` | Its own sign-in |
| `too_large` | Over 4096 bytes | Its own sign-in |
| `busy` | Sixteen callers already being served | Ask again shortly, or its own sign-in |
| `unknown_client` | Not a client the server mints (`suite`, `os`, or unknown) | Its own sign-in |
| `forbidden` | This caller may not have it (below) | Its own sign-in |
| `signed_out` | This computer is not linked, or the link has ended | Its own sign-in |
| `sso_required` | The organisation enforces single sign-on and this computer's link was not approved from one | The browser extension opens `start` in a tab, which signs the browser in through the organisation. An app does its own sign-in |
| `app_not_allowed` | The organisation has turned that app off for the account | Show nothing; its own sign-in will be refused the same way |
| `rate_limited` | The server's mint limit (30 app sessions an hour per account, 10 browser sessions an hour per `os` session) | Ask again later |
| `refused` | The server said no for another reason | Its own sign-in |
| `unreachable` | The server could not be reached, or failed | Ask again later |
| `bad_response` | The server answered something the broker does not understand | Its own sign-in |

`sso_required` keeps the link: the `os` session is not revoked, only refused
this mint.

## Who may ask

The caller is the process at the other end of the socket:

1. `SO_PEERCRED` gives its pid and uid; another uid is refused.
2. `SO_PEERPIDFD` gives a pidfd for the same process. A kernel without it
   (before 6.5) is refused rather than trusted.
3. `/proc/<pid>` is opened as a directory, then the pidfd must still name that
   pid, so the directory is the caller's and not a newcomer's that took its
   pid.
4. `root/.flatpak-info` is read through that directory: through the caller's
   own root. No symlink, no FIFO, a regular file under 64 KiB.
5. The pidfd must still name that pid.

No `.flatpak-info` is a host process. Anything unreadable, gone or malformed
is unidentified. Both are refused.

| Caller | `token` for key K | `browser` |
|---|---|---|
| `com.mauvely.K`, `app-path` under `/var/lib/flatpak/app/com.mauvely.K/` | yes, K only | no |
| `org.mozilla.firefox` or `org.chromium.Chromium`, `app-path` under `/var/lib/flatpak/app/<id>/` | no | yes |
| The same ids from a `--user` install, or any other path | no | no |
| Any other app id, lookalikes included (`com.mauvely.compose.Devel`, `org.mozilla.Firefox`) | no | no |
| A host process, or one not identified | no | no |

K is one of `assist`, `cli`, `compose`, `mail`, `office`, `relay`, `review`,
`snap`: website-main's `KNOWN_CLIENTS` without `suite` and `os`. A key outside
it is `unknown_client` whoever asks. `app-path` must be
`/var/lib/flatpak/app/<id>/` followed by at least one component, none of them
empty, `.` or `..`.

`.flatpak-info` is read strictly: anything GLib would not load, and a group or
key given twice, is unidentified. Values are unescaped only for the two keys
read, `[Application] name` and `[Instance] app-path`.

Every refusal is logged with the caller's app id and why, and every answer
with whether it was minted or cached. No token is ever logged.

### Reaching the socket

- **Mauvely apps:** `--filesystem=xdg-run/mauvely:ro` in their finish-args
  (S3). `:ro` is enough to connect.
- **Browsers:** `mauvelyd` runs
  `flatpak override --system --filesystem=xdg-run/mauvely:ro <id>` once for
  each system-installed Firefox and Chromium, whoever installed it, and again
  after one is removed and installed again (`reconcile::BROWSERS`, recorded in
  `managed.json`'s `granted`).

`--filesystem=host`, `host-os` and `home` do not reach `/run/user/<uid>`, but
an explicit `--filesystem=/run/user/<uid>/mauvely` does (S0, spike 2). Reaching
the socket is not the gate; the checks above are.

## Sessions

Each app key and each browser has one cached session, in memory only.

- **Mint:** `POST /api/auth/apps/token {client, deviceLabel?}` or
  `POST /api/auth/browser/token {deviceLabel?}`, with
  `Authorization: Bearer <os token>`. The server caps what it mints at the
  `os` session's expiry and the organisation's `session_hours`.
- **Fresh** until a tenth of its life, or five minutes, before `expiresAt`,
  whichever is sooner. A stale one is minted again without asking.
- **Checked** with `GET /api/auth/me` before each reuse. A session the server
  no longer takes (signed out in the page, revoked in the Devices tab) is
  minted again. When the server cannot say, the cached one is answered.
- Two callers asking for the same key at once get one mint.

So a caller whose token expired or was refused asks again, and gets a fresh
one. Nobody approves anything twice.

Freshness compares the server's `expiresAt` with this computer's clock. A
clock far ahead makes every cached session stale, and each ask mints, until
the server's rate limits answer instead.

## Threat model, as built

**What each check stops:**

- **The `0700` directory and `0600` socket** stop other local users. Their
  processes are refused by uid as well.
- **`.flatpak-info` read through the caller's root** stops a sandboxed app
  claiming another app's identity. Flatpak writes that file, mounts it
  read-only, and its seccomp filter refuses `unshare` of a user or mount
  namespace and `mount` (each checked from inside Flathub's Firefox,
  flatpak 1.18.4, 2026-10-21), so the app cannot build a root with a file of
  its own.
- **The pidfd either side of the read** stops a caller exiting and its pid
  being reused while it is identified.
- **The system path** stops a `--user` install, which presents the same app id
  from a directory the person can write. Only root writes
  `/var/lib/flatpak/app/`, and the agent installs only there.
- **The app id and the key** stop a Mauvely app asking for a sibling's session,
  and anything but a browser asking for a browser session.
- **The accounts origin** stops the `os` token going anywhere but the accounts
  service this computer is enrolled with. No redirect is followed; plain HTTP
  only on loopback and qemu's host address.
- **Sealing** stops the `os` session being read from a copied disk, another
  installation or another user: it is bound to the host secret, the TPM where
  there is one, the uid, the user name and the machine id.

**What it cannot stop:**

- **A host process running as the person.** It can forge `.flatpak-info` in a
  user namespace of its own (shown with `bwrap` against the real broker,
  2026-10-21), run a command inside a real sandbox
  (`flatpak run --command=… org.mozilla.firefox`), read `mauvely-session`'s
  memory, or ask `systemd-creds --user decrypt` for `os.cred` itself. Refusing
  host processes is attribution and a speed bump, not a wall, as Suite's
  broker says of its peer check. The person's own account is the trust
  boundary.
- **A sandbox that can become a host process.** An app allowed to talk to
  `org.freedesktop.Flatpak` (`flatpak-spawn --host`) is one. So, by the next
  login, is an app that can write the person's home (`~/.config/autostart`):
  Flathub's Chromium has `--filesystem=home`.
- **Anything inside a browser's sandbox is that browser** (S0, note 5). The
  native host is a child of the browser and is answered as the browser. So is
  any other native-messaging host registered for it, which anything that can
  write `~/.var/app/<browser>/` can add. The answer is a full browser session,
  capped as above and revocable; the sandbox is the boundary.
- **A caller allowed to ask can make the broker mint** up to the server's
  limits, for example by signing each session out and asking again, which
  uses up the hour's browser sessions.
- **Denial of service by a same-uid process:** sixteen idle connections hold
  every place for five seconds at a time.

## Keeping in step

- `caller::BROKERABLE` against `KNOWN_CLIENTS` in website-main's
  `worker/routes/device.ts`. Never narrower: a refusal here only shows as an
  app opening a browser, which looks like the fallback working.
- `caller::BROWSERS` against mauvelyd's `reconcile::BROWSERS`.
- The framing against Suite's `src/core/authbroker.cpp`. A new field is fine;
  a renamed one is not.
