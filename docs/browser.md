# The browser extension

Mauvely OS signs Firefox and Chromium in to mauvely.com with the account the
computer is linked to. Brief 22, S4. The broker it asks is `docs/broker.md`.

| Piece | Where | What it does |
|---|---|---|
| The extension | `browser/extension/` | Sets the `mauvely_session` cookie when it is missing |
| The native host | `crates/mauvely-browser-host` | Frames the extension's messages onto the broker's socket |
| Placing the host | `mauvely-session`, `browserhost` | Copies the host and its manifest into each browser's directory |
| The broker's `origin` op | `mauvely-session`, `broker` | Tells the extension which accounts origin this computer uses |
| Packaging | `browser/package.py` | The CRX, the signed XPI and both policies, for the image |
| Delivery | os-image, two mount units | Puts the policies and packages where the Flathub browsers read them |

```text
Firefox / Chromium (Flatpak sandbox)                 the person's session
┌──────────────────────────────────────┐
│ extension ── native messaging ──► mauvely-browser-host ──► $XDG_RUNTIME_DIR/mauvely/broker
│     │        (4-byte length, JSON)   │   (one JSON line)      mauvely-session ──► website-main
│     └── cookies API: .mauvely.com    │                        (POST /api/auth/browser/token)
└──────────────────────────────────────┘
```

## The extension

Manifest V3, one source (`src/signin.js`, `src/background.js`) and a manifest
per browser. `src/signin.js` holds all the logic; `src/background.js` wires it
to the browser's events.

**Permissions:** `nativeMessaging`, `cookies`, and the hosts
`https://*.mauvely.com/*` and `https://*.mauvely.dev/*`. Nothing else: no
`storage`, no `tabs`, no `alarms`, no content scripts. It fetches nothing and
loads no code; everything it learns comes from the host. No analytics. The
token is never logged.

**Which domain.** The host's `origin` answer, from the broker, which reads
`/etc/mauvely/server`: `https://mauvely.com` sets the cookie on
`.mauvely.com`, `https://mauvely.dev` on `.mauvely.dev`. Any other answer (the
local stack's `http://localhost:8787` included) sets nothing. The extension
never guesses, and a session whose `origin` differs from the one it learned is
not set.

**The cookie,** as website-main sets it (`worker/lib/session.ts`):
`mauvely_session`, `Domain=.mauvely.com`, `Path=/`, `Secure`, `HttpOnly`,
`SameSite=Lax`, expiring at the session's `expiresAt`. Any host-only
`mauvely_session` under the domain (on `mauvely.com` or a subdomain) is removed
when it is set: the browser would send it beside the new one, oldest first.

**When it asks.** Only when that domain cookie is missing, and then on:

- the browser starting, and the extension being installed or updated;
- a page of the accounts site (the domain or a subdomain, over https) starting
  to load. If that is what made it ask, the tab is reloaded once the cookie is
  set, so the page the person opened is signed in;
- the cookie expiring (removed with cause `expired` or `evicted`, or removed
  within 60 s of its own expiry).

**A sign-out holds until the browser restarts.** The site removing the cookie
before its expiry is a sign-out: website-main's `clearCookies()` answers
`/api/auth/signout` (and a password reset) with `Max-Age=0` for the host-only
and the domain cookie. Chromium reports that removal with cause
`expired_overwrite` and Firefox with `explicit`, both seen on the VM. The
person clearing cookies is `explicit` too, and is held the same way.
`overwrite` (a new value replacing the old) is not a removal at all.

**The extension's notes are cookies,** because it has no `storage` permission
and because a cookie without an expiry is exactly "until the browser
restarts". Both are host-only on the accounts host, `Secure`, `HttpOnly`,
`SameSite=Strict`, at the path `/.mauvely-os-extension/`, which the site never
serves, so neither is ever sent:

| Note | Value | Means |
|---|---|---|
| `mauvely_os_held` | `1` | The person signed out in the page. Ask nothing until the browser restarts |
| `mauvely_os_wait` | `<retry at>.<refusals>` | The broker refused. Ask again after the time, Unix seconds |

A Chromium service worker or a Firefox event page is stopped after half a
minute idle and loses its memory; the notes do not.

**When the broker refuses** (`signed_out`, `sso_required`, `rate_limited`,
`unreachable`, `forbidden`, …) nothing is set, and it asks again only after
1, 2, 5, 15, 30, then 60 minutes, until a success or a restart. A host that
cannot be started, or cannot say which origin, backs off the same way in
memory, since there is no domain to keep a note on.

**`sso_required` opens nothing.** `docs/broker.md` once said the extension
would open the answer's `start` in a tab. It does not: a tab opening by itself
at browser start is a surprise, and the extension never navigates anywhere. The
page's own sign-in takes the person through their organisation, and the host
does not pass `start` on.

**Not covered:** private windows (an extension is off there unless the person
allows it, and the cookie would not reach them anyway), Firefox containers and
first-party isolation (the default cookie store only), and a cookie that is
still there but that the server no longer takes (revoked from the Devices tab,
or with the computer's link): the extension cannot tell without fetching, so
the person sees a signed-out page until the cookie expires or they sign in. A
browser that restores its session keeps session cookies, so there the hold
outlasts a restart.

## The native host

`crates/mauvely-browser-host`, std and serde_json only, no network. The browser
starts it inside its own sandbox, from the person's `~/.var/app`, so it is built
as a static musl binary (`x86_64-unknown-linux-musl`, static-pie, about 470 KB)
that needs nothing from the runtime.

```text
extension → host   {"op":"origin"}   or   {"op":"browser"}
host → broker      {"v":1,"op":"origin"}\n   or   {"v":1,"op":"browser"}\n
host → extension   {"ok":true,"origin":"https://mauvely.com"}
                   {"ok":true,"token":"…","expiresAt":1771200000,"origin":"https://mauvely.com"}
                   {"ok":false,"reason":"signed_out"}
```

- **Framing:** native messaging (a 4-byte length in native byte order, then
  UTF-8 JSON) with the browser; one line each way with the broker.
- **It asks only those two ops,** in lines it writes itself. Nothing of the
  extension's message reaches the broker.
- **It passes on only** the token, `expiresAt` and the origin, each checked:
  the origin one of the two above, the token `[A-Za-z0-9_-]{16,256}`, the
  expiry a positive integer JavaScript holds exactly. The address, the
  organisation and the single sign-on link stay behind. Anything else is
  `bad_response`.
- **Limits, failing closed:** 1024 bytes from the extension (more is
  `too_large`, and the host exits: the body was not read, so nothing after it
  can be framed); 4096 bytes from the broker, the broker's own limit; 15 s for
  the broker, which answers within about 11.
- **Its own refusals:** `unknown_op`, `too_large`, `bad_response`, and
  `unavailable` when the socket is missing, refuses, or is silent.
- **Logs** only the socket's error to standard error, which the browser
  forwards to its own. Never anything the broker says.
- **Who may use it** is the browser's to say (`allowed_origins`,
  `allowed_extensions`); who is answered is the broker's (the sandbox's app
  id, `docs/broker.md`). Anything inside the browser's sandbox is the browser.

## Where the host goes

`mauvely-session` (`browserhost`) copies the image's
`/usr/libexec/mauvely/mauvely-browser-host` and writes the manifest
`com.mauvely.browser.json` beside it, at login and every 5 minutes, for both
browsers whether installed or not (as Plasma's own browser integration does,
into the same directories), so a browser the agent installs later finds it at
its first start:

| Browser | Directory | Allow-list |
|---|---|---|
| Firefox | `~/.var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts/` | `allowed_extensions: ["os-signin@mauvely.com"]` |
| Chromium | `~/.var/app/org.chromium.Chromium/config/chromium/NativeMessagingHosts/` | `allowed_origins: ["chrome-extension://<id>/"]` |

The manifest's `path` is the copy's own path, `$HOME` as the session has it
(`/var/home/<user>` on Mauvely OS): Flatpak mounts `~/.var/app/<id>` at the
same path inside the sandbox. A file is written only when it differs, as a new
file and a rename, so a browser never reads half of one, and never through a
symbolic link, since the browsers can write these directories. Without the
image's host nothing is written.

The S0 spike found a host inside a Flatpak extension works too (nothing
user-writable executed). The copy was kept, as the brief has it: it works for
both browsers the same way, and does not depend on the policy being there.

## The ids

| | Id | Fixed by |
|---|---|---|
| Native host | `com.mauvely.browser` | `HOST` in `src/signin.js`, `browserhost::NAME` |
| Firefox extension | `os-signin@mauvely.com` | `browser_specific_settings.gecko.id`; AMO signs it under this id |
| Chromium extension | `ioajmohlalajkifjboclbjlinkkogcej` (**throwaway**) | the public key in `manifest.chromium.json`'s `key` |

**A new CRX key changes the Chromium id.** The key in the manifest today is
the public half of a throwaway key that never left a test machine. When the
real `CRX_SIGNING_KEY` is made:

1. put its public half, base64 DER (`openssl pkey -in key.pem -pubout -outform
   DER | base64 -w0`), in `manifest.chromium.json`'s `key`;
2. set `browserhost::CHROMIUM_ORIGIN` to the new id
   (`python3 -I browser/package.py crx-id key.pem`);
   `the_ids_are_the_extensions` fails until both agree;
3. move `agent.ref` in os-image. The policy, `update.xml` and the CRX are made
   from the key at the image's build, so they follow.

`package.py` refuses a key whose public half is not the manifest's.

## Delivery: the policies

The Flathub browsers read policies only from inside their sandboxes, through
Flatpak extension points their manifests declare. Checked on the VM against
Firefox 158.0.1 and Chromium 156.0.8078.47:

| Browser | Point | Directory in the sandbox | Branch |
|---|---|---|---|
| Firefox | `org.mozilla.firefox.systemconfig` | `/app/etc/firefox` | `stable` (no `version`: the app's) |
| Chromium | `org.chromium.Chromium.Extension` (`subdirectories`, `merge-dirs` `extensions;native-messaging-hosts;policies/managed;policies/recommended`) | `/app/chromium/extensions/<name>`; policies merged into `/app/chromium/extensions/policies/managed/` | `1` (Flathub's `version`) |

Flathub's Chromium also has `.Policy` and `.NativeMessagingHost` points; the
`.Extension` one carries the policy and the CRX together.

**The image ships them as unmanaged Flatpak extensions,** not as refs from a
remote: `/usr/share/mauvely/browser/<point name>/`, bind-mounted at
`/var/lib/flatpak/extension/<point name>/x86_64/<branch>` by two mount units
(os-image `rootfs/usr/lib/systemd/system/var-lib-flatpak-extension-*.mount`).
Flatpak mounts an unmanaged extension from there into every start of the app,
and prefers it to an installed ref (`app-extensions` names it `=local`).

- **Why not refs in the Mauvely remote,** as the brief proposed: the agent
  would have to install them (they are `no-autodownload`), `publish-flatpak.sh`
  would have to learn runtime refs, and the extension could move ahead of or
  behind the host and the broker it talks to. In the image, all three move
  together, and nothing is fetched at all.
- **Why bind mounts, not links:** Flatpak 1.18.4 with GLib 2.88 skips a link
  where it lists a point's subdirectories (the enumerator does not ask for the
  file type, and gets none for a link), so Chromium's would never mount, and
  every Flatpak start prints a page of `GLib-GIO-CRITICAL`. A link left behind
  by an image without the files would point at nothing, and for Firefox's
  point Flatpak then refuses to start Firefox at all. A mount unit whose source
  is missing mounts nothing, and the browser starts as it would without
  Mauvely.

**Chromium:** `policies/managed/com.mauvely.signin.json` is
`ExtensionInstallForcelist: ["<id>;file:///app/chromium/extensions/mauvely/update.xml"]`,
and `update.xml` points at `mauvely-signin.crx` beside it. Chromium checks a
force-installed extension's update manifest on its own schedule (every few
hours), so a new image's version should be taken after the reboot that brings
it; an update was not tried.

**Firefox:** `policies/policies.json` is `ExtensionSettings` with
`force_installed` and `install_url`
`file:///app/etc/firefox/mauvely/mauvely-signin.xpi`. Firefox reads a
`file://` install URL again at every start and installs it when its version is
newer (`PoliciesHelpers.sys.mjs`, `installAddonFromURL`; read in Firefox's
source, not seen). **Release Firefox
installs only an AMO-signed XPI**: the unsigned one is refused with
`ERROR_SIGNEDSTATE_REQUIRED`, and about:policies says "Not fully applied".

Only the Firefox point takes one extension, so an organisation's own Firefox
policies will have to be merged into this `policies.json` (brief 19's admin
policies, later). Chromium's managed directory takes any number of files.

## Packaging

`browser/package.py`, Python's standard library and `openssl`:

```sh
python3 -I browser/package.py stage <out>     # the two trees the image ships
python3 -I browser/package.py build <out>     # unpacked builds and the unsigned XPI, for trying it
python3 -I browser/package.py crx-id key.pem  # the id a key gives
```

`stage` reads its keys from the environment, never from an argument:

| Variable | Used for | Without it |
|---|---|---|
| `CRX_SIGNING_KEY_FILE` | A PEM file holding the Chromium extension's RSA key: the CRX3 is packed and signed here (no Chromium needed) | No Chromium tree |
| `AMO_JWT_ISSUER`, `AMO_JWT_SECRET` | addons.mozilla.org's API, v5: the XPI is uploaded as an **unlisted** add-on, signed, and downloaded. A version is signed once: a later run finds it and downloads it again, and refuses if AMO's file is not this source (bump `version` in both manifests) | No Firefox tree |
| `MAUVELY_UNSIGNED_XPI=1` | Tests only: the Firefox tree with the unsigned XPI | |

Each tree left out says so, and the run succeeds; the image then carries no
extension for that browser, and its mount unit mounts nothing. os-image's
`scripts/build.sh` and `publish-image.yml` run it (os-image's `HANDOFF.md`).

**The AMO half has run only against a fake** on 127.0.0.1
(`browser/test_package.py`): there are no keys yet. It sends the key only to
`https://addons.mozilla.org`, and drops it on a redirect elsewhere.

## Tests

```sh
cargo test -p mauvely-browser-host -p mauvely-session  # host, placement, the origin op
node --test browser/extension/test/*.test.cjs          # the extension, against a fake browser
python3 -I browser/test_package.py                     # CRX3, staging, AMO against a fake
```

The extension's tests run `src/signin.js` against a cookie jar with the
cookies API's domain, host-only and path rules, a scripted native host, and
tabs. Each guard in it, the host and `browserhost` was broken once and a test
failed, except the extension's `!c.hostOnly`, which the domain check (`.` + the
domain) already covers.
