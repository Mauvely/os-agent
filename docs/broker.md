# The sign-in broker

`mauvely-session` links this computer to the person's Mauvely account once,
then signs the Mauvely apps and the browsers in from that link. Brief 22, S2.
The code is `crates/mauvely-session/src/broker/`.

The server half is website-main's `docs/AUTH-BROKER.md`, § Mauvely OS. The
framing is Suite's broker (`suite/docs/auth-broker.md`), which the apps
already speak.

## Linking

Once per local user, until M2's login fills the same store.

1. At each graphical login with no `os` session, a window: "Sign in to
   Mauvely", "Link this computer to your Mauvely account.", with two buttons,
   "Open the sign-in page" and "Later". "Later" and closing the window leave
   it signed out until the next login. Where `kdialog` is missing or fails,
   the offer is a notification instead: "Sign in to Mauvely", one action,
   "Sign in", which stays until dismissed.
2. "Open the sign-in page" starts a device link as client `os`
   (`POST /api/auth/device/start`). A second window, "Enter this code to sign
   in" over the code in large type, stays up while the link is pending, and
   the link page opens in the default browser, through the OpenURI portal, or
   `xdg-open` when there is none. **The page opens without the code**:
   whatever opens it puts the address in an argv that every local user can
   read under `/proc`, and with the code any of them could approve the link
   for their own account. Only a page on the accounts origin is opened. The
   code window's OK closes it and nothing else: the link carries on, and the
   code is not shown again. Without a window, the code is the body of a
   notification.
3. The broker polls `POST /api/auth/device/token` until the link is approved,
   declined or expired (ten minutes). The code window goes when it ends.
4. A notification, "Signed in to Mauvely as <email>", so a link to an account
   that is not the person's is seen at once. This one is always a
   notification.
5. The `os` session is sealed with `systemd-creds --user encrypt`, stdin to
   stdout, into `$XDG_STATE_HOME/mauvely/os.cred` (mode `0600`, in a `0700`
   directory). Its expiry, address and accounts origin are sealed with it.

A link that cannot start, or a code or browser that cannot be shown, puts the
offer back. A declined or expired one takes the code away, and is offered
again at the next login.

The `os` session ends, and the offer comes back, when a mint answers `401`
(revoked, signed out, expired on the server), when its own expiry passes, or
when it was sealed for another accounts origin than this computer's now.
Everything minted from it is forgotten with it. A file that does not unseal is
kept, in case that passes, and the offer is shown; a new link replaces it.

### The windows

`mauvely-session/src/dialog.rs`. One window is up at a time: a new one, a
confirmation or the end of the link takes the old one down, and nothing is
said of a window this side closed.

| Window | kdialog | Why |
|---|---|---|
| The offer | `--yesno`, `--yes-label "Open the sign-in page"`, `--no-label "Later"` | The only mode with a text and two buttons whose names can be set. Its text is an argument, so it holds no code |
| The code | `--textbox -`, 380 by 150 | Reads its text from **standard input**. One button, "OK", which kdialog does not let us rename |

How a window ended is read from kdialog's exit status, which `--yesno` gives
as 0 for the first button, 1 for the second and 2 when the window is closed
(each seen in a nested sway, kdialog 26.08). 0 accepts the offer; 1 and 2
dismiss it. Anything else, or a signal, is a window that failed (Qt aborts
when it has no display): the notification takes its place. A window that
cannot be started at all, because kdialog is not there, is the same.

**The code never reaches an argv.** `--yesno` and `--msgbox` take their text
as an argument, and a window that showed the code that way would put it where
every local user can read it, which is what moving the page's address off
`xdg-open` was for. The code window is `--textbox -` instead: the code goes
down a pipe that only kdialog holds. kdialog sets what it reads as rich text
if it looks like some, which is how the code comes out large, so only a
string that is plainly a code (letters, digits and `-`, at most 32) is sent;
anything else is shown in a notification. The cost is a code window with one
button.

### The accounts origin

From `/etc/mauvely/server`, which the installer writes. `MAUVELY_CONFIG_DIR`
moves `/etc/mauvely` in a debug build only: in a release build the
environment, which `~/.config/environment.d/` sets, would choose where the
`os` token goes.

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

The same service decrypts it for any process of that uid. See the threat
model.

## The socket

`$XDG_RUNTIME_DIR/mauvely/broker`: the directory `0700`, the socket `0600`,
both the person's. The directory is made once and never removed: a Flatpak
granted `xdg-run/mauvely` bind-mounts it when it starts, and a directory made
again would leave running apps holding the old one.

The socket's device and inode are recorded when it is bound, and checked
every two seconds and after every caller. When something else holds the name
(an app granted the directory read-write can unlink it and listen there), the
broker clears whatever is there, file or directory, and listens again. A
listen that fails is tried again every two seconds.

One JSON object per line each way, then the socket closes. A host process, or
a caller that could not be identified, is answered `forbidden` at once,
before it says anything. Others have five seconds to send a line of at most
4096 bytes. Sixteen callers are served at once; the seventeenth is told
`busy`.

### Requests

```jsonc
{"v":1,"op":"token","client":"compose","label":"Compose on ada-laptop"}
{"v":1,"op":"browser"}
```

- `token`: an app session for `client`. `label` is optional, and becomes the
  session's name in the Devices tab: control characters dropped, trimmed,
  at most 120 UTF-16 units, as the server counts.
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
| `forbidden` | This caller may not have it (below). A host or unidentified caller gets it before anything is read | Its own sign-in |
| `unknown_op`, `version` | Not this protocol. The op is checked first, then `v` | Its own sign-in |
| `too_large` | Over 4096 bytes | Its own sign-in |
| `busy` | Sixteen callers already being served | Ask again shortly, or its own sign-in |
| `unknown_client` | Not a client the server mints (`suite`, `os`, or unknown) | Its own sign-in |
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
4. Through that directory, so through the caller's own root:
   `root/.flatpak-info` is read (no symlink, no FIFO, a regular file under
   64 KiB), and `root/app` is looked at, not followed if it is a symlink.
5. The pidfd must still name that pid.
6. On this side: the sandbox's `/app` must be the very directory its
   `app-path` names, the same device and inode. For a system install, the
   deploy file beside it (`<app-path>/../deploy`, a GVariant whose first
   string is the origin remote) says which remote it came from.

No `.flatpak-info` is a host process. Anything unreadable, gone or malformed
is unidentified. Both are refused.

| Caller | `token` for key K | `browser` |
|---|---|---|
| `com.mauvely.K`, `app-path` under `/var/lib/flatpak/app/com.mauvely.K/`, `/app` that deploy, from the remote `mauvely` | yes, K only | no |
| `org.mozilla.firefox` or `org.chromium.Chromium`, `app-path` under `/var/lib/flatpak/app/<id>/`, `/app` that deploy, from any remote | no | yes |
| `com.mauvely.K` system-wide from another remote (Flathub, say, which a wheel user can install from) | no | no |
| The same ids from a `--user` install, or any other path | no | no |
| Any other app id, lookalikes included (`com.mauvely.compose.Devel`, `org.mozilla.Firefox`) | no | no |
| A host process, or one not identified | no | no |

K is one of `assist`, `cli`, `compose`, `mail`, `office`, `relay`, `review`,
`snap`: website-main's `KNOWN_CLIENTS` without `suite` and `os`. A key outside
it is `unknown_client` whoever asks. `app-path` must be
`/var/lib/flatpak/app/<id>/` followed by at least one component, none of them
empty, `.` or `..`. The remote is the agent's, `mauvely`
(website-devices' `worker/lib/remotes.ts`); the browsers' is not checked,
since an organisation may mirror Flathub under another name.

`.flatpak-info` is read strictly: anything GLib would not load, and a group or
key given twice, is unidentified. Values are unescaped only for the two keys
read, `[Application] name` and `[Instance] app-path`.

Every refusal is logged with the caller's app id and why, and every answer
with whether it was minted or cached. No token is ever logged.

### Reaching the socket

- **Mauvely apps:** exactly `--filesystem=xdg-run/mauvely:ro` in their
  finish-args (S3). `:ro` is enough to connect, and without it the app can
  replace the socket.
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
  no longer takes (`user: null`, `401`, or `403`, as for an app the
  organisation has turned off) is minted again, and the mint says why when it
  fails. When the server cannot say, the cached one is answered.
- Two callers asking for the same key at once get one mint.

So a caller whose token expired or was refused asks again, and gets a fresh
one. Nobody approves anything twice.

Freshness compares the server's `expiresAt` with this computer's clock. A
clock far ahead makes every cached session stale, and each ask mints, until
the server's rate limits answer instead.

## Threat model, as built

**The boundary is the person's account.** Any process running as the person
can unseal `os.cred` with `systemd-creds --user decrypt`: the varlink service
decrypts a user-scoped credential for any process of that uid. A review
round-tripped it as a plain same-uid process on systemd 262, and so did the
2026-10-21 end-to-end run. Nothing the broker checks about a host process
gives more than that: a host process refused at the socket can take the `os`
session itself.

**What each check stops:**

- **The `0700` directory and `0600` socket** stop other local users. Their
  processes are refused by uid as well.
- **The page opening without its code** stops another local user, who can
  read every argv under `/proc`, approving this computer's link for their own
  account. "Signed in to Mauvely as <email>" shows the account linked, should
  anything else go wrong.
- **The code reaching kdialog on its standard input** stops the same thing
  through the window. The offer's argv is fixed text, and the code window's
  is `--textbox - 380 150`. Passing the code as the text of `--yesno` or
  `--msgbox` was the simpler window, and was rejected for this reason.
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
- **The sandbox's `/app` compared on disk** stops a `.flatpak-info` whose
  `app-path` names a system install the sandbox is not running. A sloppy
  forgery fails here (shown with `bwrap`, 2026-10-21); a careful one also
  bind-mounts that deploy.
- **The deploy's remote** stops a `com.mauvely.*` app installed system-wide
  from anywhere but the Mauvely remote.
- **The app id and the key** stop a Mauvely app asking for a sibling's session,
  and anything but a browser asking for a browser session.
- **The socket's identity, checked every two seconds and after every caller,**
  stops an app with the directory read-write answering for the broker for
  longer than that. In the 2026-10-21 run a squatter answered for about two
  seconds, then the broker had the name back.
- **The origin sealed with the session** stops a changed
  `/etc/mauvely/server`, or a moved configuration directory, sending the
  90-day token anywhere but where it was issued.
- **The accounts origin** stops the `os` token going anywhere but the accounts
  service this computer is enrolled with. No redirect is followed; plain HTTP
  only on loopback and qemu's host address.
- **Sealing** stops the `os` session being read from a copied disk, another
  installation or another user: it is bound to the host secret, the TPM where
  there is one, the uid, the user name and the machine id.

**What it cannot stop:**

- **A host process running as the person.** Beyond unsealing `os.cred`, it can
  forge `.flatpak-info` in a user namespace of its own, bind-mount a real
  deploy at `/app`, run a command inside a real sandbox
  (`flatpak run --command=… org.mozilla.firefox`), or read
  `mauvely-session`'s memory. Refusing host processes is attribution and a
  speed bump, as Suite's broker says of its peer check.
- **A sandbox that can become a host process.** An app allowed to talk to
  `org.freedesktop.Flatpak` (`flatpak-spawn --host`) is one. So, by the next
  login, is an app that can write the person's home (`~/.config/autostart`):
  Flathub's Chromium has `--filesystem=home`.
- **A squatter between checks.** An app granted `xdg-run/mauvely` read-write
  answers callers for up to two seconds at a time. Only `:ro` stops it;
  a directory the person cannot write would stop it for good (HANDOFF).
- **Anything inside a browser's sandbox is that browser** (S0, note 5). The
  native host is a child of the browser and is answered as the browser. So is
  any other native-messaging host registered for it, which anything that can
  write `~/.var/app/<browser>/` can add. The answer is a full browser session,
  capped as above and revocable; the sandbox is the boundary.
- **A caller allowed to ask can make the broker mint** up to the server's
  limits, for example by signing each session out and asking again, which
  uses up the hour's browser sessions.
- **Denial of service by a same-uid process:** sixteen idle connections from
  an identified sandbox hold every place for five seconds at a time.

## Keeping in step

- `caller::BROKERABLE` against `KNOWN_CLIENTS` in website-main's
  `worker/routes/device.ts`. Never narrower: a refusal here only shows as an
  app opening a browser, which looks like the fallback working.
- `caller::BROWSERS` against mauvelyd's `reconcile::BROWSERS`;
  `the_browsers_match_the_agents` fails when they differ.
- `caller::MAUVELY_REMOTE` against the remote name website-devices sends.
- The framing against Suite's `src/core/authbroker.cpp`. A new field is fine;
  a renamed one is not.
