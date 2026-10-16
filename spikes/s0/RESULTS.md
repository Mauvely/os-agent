# Brief 22, S0: spikes for single sign-on (S2 to S4)

Run on 2026-10-16 on the development machine (CachyOS, Flatpak 1.18.4, kernel 7.2.9). Everything here
was reproduced from a clean state by `./run-all.sh` (30 steps, about four minutes); the logs of that
last run are in `evidence/logs/`.

| Spike | Pass line | Result |
|---|---|---|
| 1. Native host inside the sandbox | both Flathub browsers launch a host from their own `~/.var/app` directory, no portal, extension exchanges a message | **PASS**, Firefox 158.0 and Chromium 155.0.8059.39 |
| 2. Socket and caller id | reachable with `xdg-run/mauvely`, refused without, `.flatpak-info` names the caller, host callers are distinguishable | **PASS** |
| 3. Policy refs from another remote | each browser honours its policy extension installed from a non-Flathub remote | **PASS**, both |

Beyond the pass lines, four things were tested because S4 depends on them, and all four worked
(section "Beyond the pass lines"): policy force-install of an extension in Chromium, the native host
shipped inside a ref instead of copied into `~/.var/app`, a policy update by `flatpak update`, and
what a release Firefox does with an unsigned force-installed XPI (it refuses).

## How it was contained

- **Flatpak:** `FLATPAK_USER_DIR=$HOME/.cache/mauvely-flatpak/user` and `flatpak --user` on every call.
  Nothing system-wide, no `sudo`. The two browsers (Flathub `org.mozilla.firefox` `9c1e95bd`, 158.0, and
  `org.chromium.Chromium` `1d1959f8`, 155.0.8059.39, runtime `org.freedesktop.Platform//25.08`) were
  installed there and are still there.
- **Browser data:** every `flatpak` call ran with `HOME=$HOME/.cache/mauvely-s0/home`. Flatpak takes
  `~/.var/app` from `g_get_home_dir()`, which honours `$HOME`, so the browsers' data landed in
  `~/.cache/mauvely-s0/home/.var/app/` and the user's real `~/.var/app/org.mozilla.firefox` and `org.chromium.Chromium` were never touched
  (checked at the end: both directories and their contents kept their 2026-10-06 and 2026-10-14 mtimes;
  the `com.mauvely.*` entries there that moved belong to other sessions). Inside the sandbox `$HOME` is that same path.
- **GUI:** only inside `hsway` (`HSWAY_NAME=s0`, a separate session from the default one), with a
  private D-Bus session bus that has no activation (`lib/gui.sh`), `DISPLAY=:91` on the daemon as a
  tripwire for at-spi, and `--no-a11y-bus`. After the runs
  `org.a11y.Bus GetAddress` still answers `bus_0` (see `evidence/logs/99-cleanup.txt`).
- **Sockets:** the main spike used `$XDG_RUNTIME_DIR/mauvely-s0/`; `spike2-exact-path.sh` repeated spike 2 on
  the real `$XDG_RUNTIME_DIR/mauvely/broker` and `xdg-run/mauvely` (refuses to run if that directory
  exists). Both are removed afterwards.
- **Remote and keys:** a throwaway local remote `mauvely-s0` (`file://` repo), signed with a throwaway
  RSA GPG key made in `~/.cache/mauvely-s0/gpg`. `cleanup.sh` uninstalls everything that came from it
  and removes the remote. Note `flatpak remote-delete --force` alone leaves the installed refs behind
  as orphans; `s0_forget_remote` in `env.sh` uninstalls first.
- **Not mine, left alone:** the user's real `org.freedesktop.portal.Flatpak` service on the real bus,
  and the `default` hsway session that another agent had running.

## Spike 1: native host inside the sandbox. PASS

**Host:** `host/s0host.rs`, std-only Rust, built `-C target-feature=+crt-static` (1.3 MB, static-pie;
`build-host.sh`). It frames native messages, echoes them, and reports what it can see (pid, parent,
argv, `/.flatpak-info`, `$HOME`, `$XDG_RUNTIME_DIR`), then tries the broker socket.

**Interpreters in both runtimes** (`org.freedesktop.Platform//25.08`, identical for both browsers):
`/usr/bin/python3`, `bash`, `sh` and `curl` exist; no `perl`, `socat` or `nc`. A script host would
work, but the static binary needs nothing.

**Placement, exactly as in the brief, no portal, no override:**

| Browser | Manifest | `path` in the manifest |
|---|---|---|
| Firefox | `~/.var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts/com.mauvely.s0.json` | `<HOME>/.var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts/s0host` |
| Chromium | `~/.var/app/org.chromium.Chromium/config/chromium/NativeMessagingHosts/com.mauvely.s0.json` | `<HOME>/.var/app/org.chromium.Chromium/config/chromium/NativeMessagingHosts/s0host` |

- **Firefox** `persistent=.mozilla` maps that directory to `~/.mozilla/native-messaging-hosts/` in the
  sandbox, and the whole `.var/app/<id>` tree is also visible at its own path, so an absolute `.var/app`
  path in `path` works. The mount has no `noexec` (`rw,nosuid,nodev,...`).
- **Chromium** has `filesystems=home`; `$XDG_CONFIG_HOME/chromium` is the default user-data-dir, so it
  reads `NativeMessagingHosts/` from there. Do not pass `--user-data-dir`, it moves that directory.
- **Allow-lists:** Firefox `allowed_extensions: ["s0@mauvely.invalid"]`; Chromium
  `allowed_origins: ["chrome-extension://<id>/"]`, with the id fixed by a `key` in the manifest
  (`build-ext.sh` derives it from a throwaway key).

**Observed** (`evidence/logs/10-s1-firefox.txt`, `11-s1-chromium.txt`), identically in both browsers:
- `runtime.sendNativeMessage` returns the echo, and `runtime.connectNative` keeps one host process (same
  pid) across two messages.
- The host is a **direct child of the browser process inside the sandbox**
  (`ppid` 2, `parent_comm` `firefox-bin` / `chrome`), has `/.flatpak-info` with
  `name=org.mozilla.firefox` / `org.chromium.Chromium`, the real `$HOME`, `$XDG_RUNTIME_DIR=/run/user/1000`,
  and `cwd` the manifest directory. Firefox passes `argv = [path, manifest path, extension id]`;
  Chromium passes `argv = [path, "chrome-extension://<id>/"]`.
- Both extensions were Manifest V3 from one source (`ext/background.js`, a Firefox and a Chromium
  manifest). The Chromium one is a service worker; it launched the host fine.
- No portal was involved: for Firefox the private bus had no services at all. Chromium needs
  `org.freedesktop.portal.Flatpak` on the session bus for zypak (its renderer sandbox), and dies at
  startup without it ("Failed to initialize (is the Flatpak D-Bus portal working?)"); the spike started
  `/usr/lib/flatpak-portal` on the private bus. That is not the native messaging path (the host is a
  direct child of the browser), and a real Plasma session always has it.
- **The S4 cookie dance works in both**, from the extension, with `cookies` plus
  `host_permissions: https://*.mauvely.invalid/*`: set a host-only `mauvely_session`, remove it, then set
  `mauvely_session` with `Domain=.mauvely.invalid; Secure; HttpOnly; SameSite=Lax` and read it back
  (`evidence/logs/10`, `11`, the `cookies` step). Host permissions were granted to the temporary
  add-on, to the unpacked one and to the policy-installed one.

**How the extensions were installed, and what production needs instead:**
- **Firefox:** a temporary add-on over Marionette: `Addon:Install {path: s0.xpi, temporary: true}`
  (`lib/marionette.py`), Firefox started with `--marionette --no-remote --profile ...`. A release Firefox
  accepts nothing unsigned any other way: forcing the same unsigned XPI by policy is refused with
  `Invalid XPI: signature is required but missing` (`evidence/logs/27-x-firefox-forced-xpi.txt`).
  **Production needs the XPI signed through AMO** (unlisted add-on).
- **Chromium:** `--load-extension=<dir>` works in Flathub's unbranded Chromium 155. **Production needs a
  CRX and an update manifest**; both were built and used below. Dev gotcha: once a forcelist policy names
  the same extension id, `--load-extension` of it is blocked ("blocked by the administrator").

**The whole chain** (`BROKER=1`, `evidence/logs/12`, `13`): extension, then host inside the browser's sandbox,
then a unix socket under `xdg-run/mauvely-s0`. The broker stand-in saw `kind=flatpak`,
`app=org.mozilla.firefox` / `org.chromium.Chromium` for the host's connection, with the host binary as the
peer process: the identity is the sandbox, not the binary (see design notes).

## Spike 2: socket and caller id. PASS

`broker/broker_spike.py` listens on `$XDG_RUNTIME_DIR/mauvely-s0/broker` (directory `0700`, socket `0600`)
and identifies each peer; `spike2-socket.sh` and `spike2-exact-path.sh` drive it. Raw results are in
`evidence/logs/08-s2-socket.txt` and `09-s2-exact-path.txt`.

**Reach:**

| Caller | Result |
|---|---|
| host process (`s0client`) | connects; server says `kind=host` |
| `com.mauvely.s0granted`, finish-args `filesystems=xdg-run/mauvely-s0;` | connects |
| `com.mauvely.s0denied`, no grant | `No such file or directory`: the directory is not mounted at all |
| Firefox, Chromium, no grant | `No such file or directory` |
| Firefox, Chromium with `--filesystem=xdg-run/mauvely-s0` | connects |
| the same with `:ro` and with `:create` | connects (connecting to a socket on a read-only bind mount works, so `:ro` is enough) |
| persistent `flatpak override --user --filesystem=xdg-run/mauvely-s0 org.mozilla.firefox` | connects; written to `$FLATPAK_USER_DIR/overrides/org.mozilla.firefox` as `[Context]` `filesystems=xdg-run/mauvely-s0;`; `flatpak override --user --reset` revokes it |
| the exact production path, `$XDG_RUNTIME_DIR/mauvely/broker` with `xdg-run/mauvely`: no grant, grant and `:ro` for the test app and both browsers | same results (`09`) |
| `--filesystem=host`, `host-os`, `home` | **still no socket**: flatpak keeps `/run/user/<uid>` out of those, also via `/run/host/...` |
| `--filesystem=/run/user/<uid>/mauvely-s0` (explicit path) | connects |

So reachability needs `xdg-run/<name>` (or an explicit `/run/user/<uid>/...` path, which an app
cannot hard-code without knowing the uid); broad grants like `host` do not reach it.

**Caller identity, server side, unprivileged (same uid):**
- `SO_PEERCRED` already returns the **host-namespace pid** of a sandboxed peer (flatpak unshares the pid
  namespace; the kernel translates into the reader's). `uid` is 1000 inside and out.
- **`SO_PEERPIDFD` works on this kernel (7.2).** `/proc/self/fdinfo/<pidfd>` gave the same pid before and
  after reading `.flatpak-info`, so the pid cannot have been reused in between. Use it.
- `/proc/<pid>/root/.flatpak-info` is readable by an unprivileged server for a same-uid sandboxed peer. For
  a host peer it is `ENOENT`, which is the host test. A second host signal: the host peer's cgroup is
  outside `app-flatpak-<id>-<instance>.scope`.

**Which fields `.flatpak-info` actually has** (from `flatpak_info_raw` in the server log; flatpak 1.18.4):

| Section | Keys seen |
|---|---|
| `[Application]` | `name`, `runtime` |
| `[Instance]` | `instance-id`, `instance-path` (`<HOME>/.var/app/<id>`), `app-path` (the deploy's `files` directory, e.g. `.../app/<id>/x86_64/stable/<commit>/files`), `app-commit`, `runtime-path`, `runtime-commit`, `runtime-extensions`, `branch`, `arch`, `flatpak-version`, `session-bus-proxy`, `system-bus-proxy`, `extra-args`, and **`app-extensions`** (`<ext id>=<commit>;...`) when any extension is mounted |
| `[Context]` | the **effective** permissions: finish-args merged with overrides and command-line flags, including `filesystems` |
| `[Environment]` | the environment the sandbox sets |

- **It does not name the origin remote and does not name the installation.**
- **The installation is the prefix of `app-path`:** `/var/lib/flatpak/app/...` for the system one,
  `<FLATPAK_USER_DIR>/app/...` here. The spike's apps are user installs and classify `not-system`.
- **The origin is one hop away:** `<app-path>/../deploy` is a GVariant `(ssasta{sv})` whose first string is
  the origin remote, e.g. `flathub` for the browsers, `mauvely-s0` for the test apps. It is a local alias
  chosen when the remote was added, so it is not a trust anchor; the root-owned system path is.
- `app-extensions` shows which extension refs, at which commit, were mounted in this very instance: for the
  browsers, `org.mozilla.firefox.systemconfig=<commit>` and
  `org.chromium.Chromium.Extension.s0=<commit>` (`evidence/logs/17-s3-sandbox-view.txt`).
- The S2 rule "a system install under `/var/lib/flatpak/app/com.mauvely.<key>/`" is directly checkable
  (`mauvely_system_app` in the stand-in does it); it answered false for the test apps, as they are user installs.

## Spike 3: policy refs from another remote. PASS

**Extension points declared by the Flathub manifests** (`flatpak info --show-metadata`, `spike3-metadata.sh`,
`evidence/logs/07-s3-flathub-metadata.txt`):

| App | Extension point | `directory` | other keys |
|---|---|---|---|
| `org.mozilla.firefox` (branch `stable`) | `org.mozilla.firefox.systemconfig` | `etc/firefox` | `no-autodownload=true`; no `version`, so the branch is the app's: `stable`; not `subdirectories`, so exactly one ref |
| | `org.mozilla.firefox.Locale` | `share/runtime/langpack` | `autodelete`, `locale-subset` (irrelevant) |
| `org.chromium.Chromium` (branch `stable`) | `org.chromium.Chromium.Extension` | `chromium/extensions` | `subdirectories=true`, `no-autodownload=true`, `autodelete=true`, **`version=1`**, **`merge-dirs=extensions;native-messaging-hosts;policies/managed;policies/recommended`** |
| | `org.chromium.Chromium.Policy` | `chromium/policies` | `subdirectories=true`, `no-autodownload=true`, `autodelete=true`, `version=1`, `merge-dirs=policies/managed;policies/recommended` |
| | `org.chromium.Chromium.NativeMessagingHost` | `chromium/native-messaging-hosts` | `subdirectories=true`, `no-autodownload=true`, `autodelete=true`, `version=1`, `merge-dirs=native-messaging-hosts` |

So the refs are `runtime/org.mozilla.firefox.systemconfig/x86_64/stable` and
`runtime/org.chromium.Chromium.{Extension,Policy,NativeMessagingHost}.<name>/x86_64/1`. A
`subdirectories` extension named `...Extension.<name>` mounts at `/app/chromium/extensions/<name>`.
**Branch `1` is Flathub's choice**: if they bump `version`, refs on branch `1` silently stop mounting, so
the publish step should assert these values from the installed Flathub metadata.

**Built without the SDK.** `flatpak build-init --type=extension` refuses to run unless the 700 MB
`org.freedesktop.Sdk//25.08` is installed, and flatpak-builder was not needed: a runtime-kind extension is
a `metadata` file (`[Runtime] name=...`, `[ExtensionOf] ref=app/<parent>/x86_64/stable`) and a `files/`
tree, then `flatpak build-export --gpg-sign=...` and `build-update-repo` (`lib/remote.sh`,
`make-remote.sh`). Flathub's own `org.chromium.Chromium.Codecs` has exactly that metadata shape.

**Result, installed from `mauvely-s0` into the same user installation** (`flatpak install mauvely-s0
runtime/<ref>`; the origin shown by `flatpak list` is `mauvely-s0`):

- **Firefox** (`evidence/logs/14` vs `18`): `Services.policies.status` goes **0 to 1** (inactive to active);
  `getActivePolicies()` returns the three policies; `browser.startup.homepage` becomes the policy's URL and
  is locked; `about:policies` lists them (`evidence/firefox-policy-before.png`, `firefox-policy-after.png`).
  The file arrives as `/app/etc/firefox/policies/policies.json`.
- **Chromium** (`evidence/logs/15` vs `19`, `chrome-policy-rows-*`, `chromium-policy-*.png`):
  `chrome://policy` shows all four policies, from both `Extension.s0` (`policies/managed/...`) and
  `Policy.s0`, with Source `Platform`, Applies to `Machine`, Level `Mandatory`, Status `OK`; before the
  install the same four read `Not set.`. Chromium treats them as machine-level managed policy, which is
  what force-installing an extension needs.
- **Update path:** publishing a second commit of the same ref and running `flatpak update -y
  org.mozilla.firefox.systemconfig` replaced `policies.json` (`evidence/logs/26`); the next Firefox start
  saw the new policy.
- **Housekeeping:** `flatpak uninstall --unused` lists the refs as pinned and removes nothing (an explicit
  install of a runtime ref pins it; `evidence/logs/25`), and `flatpak update` offers nothing for them.

## Beyond the pass lines

| What | Result |
|---|---|
| Chromium force-install from a policy: `ExtensionInstallForcelist` with a CRX and `update.xml` served on `127.0.0.1` | **Works** on the Linux Flatpak. Chromium fetched `update.xml` then `s0.crx` (`installsource=notfromwebstore&installedby=policy`), the extension ran and talked to its host (`evidence/logs/24`). The CRX was packed by Chromium itself: `chromium --pack-extension=<dir> --pack-extension-key=<pem>` (`pack-crx.sh`). |
| **One Chromium ref for everything**, `org.chromium.Chromium.Extension.s0all`: policy with `file:///app/chromium/extensions/s0all/update.xml`, the CRX, `update.xml` (`codebase=file:///app/...`), the host manifest and the host binary | **Works**, from a wiped profile, with no web server: forced install from `file://` inside the ref, host launched from `/app/chromium/extensions/s0all/s0host` (`evidence/logs/30`, `chrome-policy-rows-chromium-single-force-policy.txt`). Nothing is copied into `~/.var/app`. |
| Chromium host from `org.chromium.Chromium.NativeMessagingHost.s0` alone | **Works**: manifest merged, host at `/app/chromium/native-messaging-hosts/s0/s0host` (`evidence/logs/22`). |
| Firefox host shipped in `org.mozilla.firefox.systemconfig` at `/app/etc/firefox/mauvely/s0host`, with only the manifest in `~/.var/app` and `path` pointing there | **Works** (`evidence/logs/28`, `argv[0]` is the `/app/etc/...` path). |
| Firefox policy `ExtensionSettings` force-install of an **unsigned** XPI from `file://` | **Refused**: `Invalid XPI: signature is required but missing`; the add-on is absent (`evidence/logs/27`). The `file://` URL itself was read. |

## What it means for the design

Brief 22 stays valid. These are the changes it should take.

**S2, the broker**
1. **Grant `xdg-run/mauvely:ro`, not plain `xdg-run/mauvely`**, in app finish-args and in the agent's
   `flatpak override --system`. `:ro` connects fine (tested on the command line and for both browsers),
   and it stops an app creating or replacing files in the directory. Tested as a persistent override
   without `:ro`; the `:ro` spelling there is the same syntax but was run only on the command line.
2. **Identify the caller by `SO_PEERPIDFD`, then `/proc/<pid>/root/.flatpak-info`.** No privilege needed.
   Use the pidfd so the pid cannot be recycled between the two steps.
3. **The check is the path, not a name.** `.flatpak-info` carries `app-path`, not the installation or the
   origin. Require `app-path` to start with `/var/lib/flatpak/app/<id>/` for the browsers as well as for
   the Mauvely apps: the brief only says it for the apps, but a user-installed lookalike
   `org.mozilla.firefox` under `~/.local/share/flatpak` would otherwise present the same app id.
   Read the origin from `<app-path>/../deploy` only as a second check; the remote name is a local alias.
4. **Optionally** answer `browser` only to a Firefox or Chromium whose `app-extensions` lists the Mauvely
   ref (`org.mozilla.firefox.systemconfig`, `org.chromium.Chromium.Extension.mauvely`): a browser without
   Mauvely's policy has no business asking.
5. **Identity is the sandbox, not the binary.** The native host is a child of the browser and shows up as
   `org.mozilla.firefox`. So `browser` is available to **anything that runs inside the browser's sandbox**.
   `allowed_extensions` and `allowed_origins` limit who may start the host, not who may connect to the
   socket. This is acceptable only because the answer is a browser-scoped session and the sandbox is the
   trust boundary; it should be written into the brief's threat model.
6. Reachability is not the gate. `host`, `host-os` and `home` do not reach `/run/user/<uid>`, but an app
   given `--filesystem=/run/user/<uid>/...` does, so the identity check must stay.

**S4, the extension and the host**
7. **Chromium: one ref, `org.chromium.Chromium.Extension.mauvely`** (branch `1`), carrying the policy
   (`ExtensionInstallForcelist` to a `file:///app/chromium/extensions/mauvely/update.xml`), the CRX, the
   host manifest (`allowed_origins`) and the host. Tested end to end (`s0all`). This drops the planned
   per-login copy into `~/.var/app/org.chromium.Chromium/config/chromium/NativeMessagingHosts/` and the
   need to host a CRX. The brief already names the `Extension` ref; use its `merge-dirs` for the host too.
8. **Firefox: keep the copy of the manifest, drop the copy of the binary.** There is no Firefox extension
   point for host manifests, so `mauvely-session` still writes
   `~/.var/app/org.mozilla.firefox/.mozilla/native-messaging-hosts/<name>.json`. Its `path` can point at the
   host inside the `org.mozilla.firefox.systemconfig` ref (`/app/etc/firefox/mauvely/<host>`), so the binary
   arrives and updates with the ref and nothing user-writable is executed. Tested. The manifest's
   `allowed_extensions` and the extension id come from the AMO signing.
9. **Firefox needs the AMO-signed XPI** (unlisted), delivered by `ExtensionSettings` `force_installed` with an
   `install_url` that can be `https://` or `file:///app/etc/firefox/mauvely/<name>.xpi` inside the same ref
   (the `file://` read worked in the spike; a signed XPI was not available to try).
10. **Policy changes ship as a new commit of the same ref**, applied by `flatpak update`. The agent
    installs the refs explicitly (they are `no-autodownload`); explicit installs are pinned, so
    `--unused` leaves them alone.
11. **CI check for `publish-flatpak.sh`:** read the extension points of the Flathub apps
    (`spike3-metadata.sh` shows how) and assert `directory`, `version` and `merge-dirs` before publishing
    a policy ref. A Flathub change here fails silently on devices.
12. **Chromium and the Flatpak portal:** the helper's tests, and any headless run, need
    `org.freedesktop.portal.Flatpak` on the session bus.
13. **When the agent removes a remote it must uninstall the refs from it first**; `remote-delete --force`
    leaves them behind.
14. MV3 in both browsers works from one source with a manifest per browser; the cookie operations and
    `nativeMessaging` need no more than the permissions listed in S4.

## Not tested

- **A system installation.** All runs used a user installation (no root here). `--system` differs in
  `app-path` (`/var/lib/flatpak/app/...`), the override file (`/var/lib/flatpak/overrides/<id>`), and that
  the browser and its extension refs must live in one installation. None of that is expected to change a
  result, but the first device test should re-run `run-all.sh` against a system install.
- A **signed** XPI: host permissions for a force-installed signed add-on, and `file://` install of it.
- Firefox ESR, Brave, LibreWolf, and a browser that is not on Flathub.
- The browsers' nested sandboxes (renderer, `flatpak-spawn --sandbox`): what `.flatpak-info` says there.
- A real Plasma session: portals, KWallet, `systemd-creds --user`.
- `:ro` as a persistent override (only as a flag).

## Reproduce

```sh
./run-all.sh        # installs the browsers if missing, runs all 30 steps, then cleanup.sh
./cleanup.sh        # on its own: remove the test remote and its refs, runtime-dir leftovers, bus, sway
```

| File | Does |
|---|---|
| `env.sh` | the containment variables and `s0flatpak`, `s0_forget_remote` |
| `install.sh`, `build-host.sh`, `build-ext.sh`, `pack-crx.sh` | browsers, static host and client, the extension per browser, the CRX |
| `make-remote.sh`, `make-remote-extra.sh`, `lib/remote.sh` | the signed throwaway remote and every ref in it |
| `spike2-socket.sh`, `spike2-exact-path.sh`, `broker/broker_spike.py` | spike 2 and its server |
| `spike1-firefox.sh`, `spike1-chromium.sh` | spike 1 and, with `POLICY`, `BROKER`, `FORCE`, `SINGLE`, `HOSTREF`, `NOADDON`, the rest |
| `spike3-metadata.sh`, `spike3-sandbox-view.sh` | spike 3 inventory |
| `lib/gui.sh`, `lib/marionette.py`, `lib/cdp.mjs`, `lib/collector.py` | private bus, Marionette client, CDP helper, report collector |
| `host/s0host.rs`, `host/s0client.rs`, `ext/`, `policies/` | the spike's own code |
| `evidence/` | screenshots and trimmed policy rows; `evidence/logs/NN-name.txt` is each step's output |

Ports used on loopback: 18099 (collector), 18100 (CRX server), 19222 (CDP), 28282 (Marionette).
