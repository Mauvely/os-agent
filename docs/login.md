# Signing in with a Mauvely account

Brief 26, Mauvely OS milestone 2: a person signs in at the computer's login
screen with their Mauvely username, password and code. Two pieces here:

- **`pam_mauvely`** (`crates/pam-mauvely`), the PAM module in every login
  path. It talks to the login service and nothing else.
- **The login service**, `mauvelyd login` (`crates/mauvelyd/src/login/`),
  root, on `/run/mauvely/auth.sock`, from `dist/mauvely-login.service`. It
  owns the rest: the KDF, the online check, the offline cache, the person's
  records and home, and handing their `os` session to `mauvely-session`.

The server side is website-devices' login door (`worker/routes/login.ts`
there) and website-main behind it (`docs/OS-LOGIN.md` there). The image's
side (the PAM stack, `mauvely-home@.service`, SELinux, the patched login
screen) is os-image's.

## The service is a unit of its own

`mauvelyd login` is the same binary as the agent, in its own process and
unit, `Before=display-manager.service`. The agent's unit waits for
`network-online.target`, which on a laptop out of range of its network takes
up to a minute, and the login screen is up long before that: the one person
who most needs the offline sign-in would get "can't retrieve authentication
info" instead. A crash or a restart of either never takes the other down.

They share files, never memory: the agent writes `desired.people` at each
check-in and prunes the cache; the service reads them per request. It loads
the device's key itself at the first online sign-in after enrolment.

## The protocol

Version 1. One connection per authentication, one JSON line each way. The
connection stays open between the password and the code, so nothing names
the attempt. `login/wire.rs` holds it; `pam-mauvely/src/client.rs` is the
other end.

```text
→ {"v":1,"op":"auth","service":"<PAM_SERVICE>","username":"timur","password":"…"}
← {"result":"ok"}
 | {"result":"code","prompt":"Code","info":"Enter the code from your authenticator app."}
 | {"result":"refused","reason":"<code>","message":"<one sentence>"}
→ {"v":1,"op":"code","code":"123456"}              (only after "code")
← {"result":"ok"} | {"result":"refused",…}
→ {"v":1,"op":"account","service":"…","username":"…"}
← {"result":"ok"} | {"result":"refused",…}
```

Unknown fields are ignored. `info` is "Enter the code we emailed you." for an
emailed code. The prompt is "Code", never a phrase with "password" in it: the
patched login screen answers any prompt holding that word with the password.

| Limit | |
|---|---|
| A request line | 8 KiB; a password 4 KiB, a username, service or code 64 bytes, no control characters |
| An answer line | 4 KiB (the module's limit) |
| The first line | 10 s after connecting |
| The code | 5 minutes, and never past its challenge's own expiry |
| Writing an answer | 5 s |
| Connections | 32 at once; 4 from any one uid but root; past either, `busy` |
| Argon2id | 2 derivations at once, 64 MiB each; a third waits up to 20 s |
| The module's wait for an answer | 60 s at `plasmalogin`, 20 s elsewhere; a missing socket fails at once, a full listen queue after 5 s |
| Each call to the server | 10 s for `params`, 15 s for `login`, `code` and the KDF upgrade |
| `mauvely-home@` | 20 s |

## Who may ask

By `SO_PEERCRED`, the connecting process's effective uid at `connect`:

- **uid 0** may ask about anyone: `plasmalogin-helper`, `login`, and the
  setuid `sudo`, `su` and polkit's `polkit-agent-helper-1`.
- **Any other uid** may ask only about the person whose uid it is (our
  userdb record's), which is the lock screen, running as the person. Asking
  about anyone else is `forbidden`.
- **Only uid 0 may ask for `plasmalogin`**, the only service that goes
  online, mints a session and writes records.

SELinux is os-image's policy: the socket is `mauvely_auth_sock_t` in
`mauvely_var_run_t`, and the domains that connect are `xdm_t`
(plasmalogin-helper), `local_login_t` (`login`), `policykit_auth_t` (polkit's
helper), `sshd_session_t`, and unconfined ones (the lock screen, `sudo`,
`su`).

## `auth`

1. **The caller**, as above.
2. **The name.** A name NSS knows (`/etc/passwd`, `/usr/lib/passwd`, userdb)
   that is not one of our records is `not_mauvely`, and the module returns
   `PAM_IGNORE`, so `pam_unix` judges it. os-image's stack already sends
   local and system accounts past the module with two `pam_localuser` lines;
   this catches the rest (a dynamic user, another userdb record). A name that
   is on no list is never ignored: it is a first sign-in, decided here. A name
   no Mauvely person could have (website-devices' rule, mirrored in
   `names.rs`) is `unknown_user`; a Mauvely name a computer cannot use (a
   leading digit, or 32 characters: systemd's strict rule and utmp) is
   `bad_username`.
3. **The device's say**, `desired.people`, before anything is sent: on an
   assigned device, the assigned person and the organisation's device
   admins; on a shared device, any valid username. Others are `not_allowed`,
   and lose their cache entry.
4. **The login screen (`plasmalogin`) goes online:** `params`, then the
   Argon2id `authSecret` (version 1, held to website-main's vectors in
   `tests/vectors/kdf.json`) or the password itself (version 0), `login`, and
   `code` when the server asks. A wrong code ends the attempt.
5. **Every other service** (`kde`, `sudo`, `polkit-1`, `login`, `su`, …)
   checks the password against the cache and nothing else, so unlocking and
   sudo never mint a session. No entry is `not_cached`, "Sign in at the login
   screen first." A wrong password waits 2 s before its answer. The entry's
   age does not matter here: a person who stays signed in for three weeks can
   still unlock.

**Offline is the login screen's only.** When the server cannot be reached
(no connection, a timeout, a 5xx, or a 404 from a server without the door)
at `params` or `login`, the cache is tried: an entry younger than its
`offlineDays`, and than the collection's `offline_days` now when that is
fewer, whose verifier matches, signs the person in without a code. A clock
more than 5 minutes before the entry's sign-in is not believed. Unreachable
at the code is `unreachable`: the person signs in again, and offline that
goes to the cache.

**A refusal is never answered from the cache.** And some make it stale:

| Server's refusal | The cache entry |
|---|---|
| `credentials`, for the password the cache knows | removed: the password changed, or the account went |
| `credentials` for any other password | kept, or anyone typing at the login screen could wipe a person's offline sign-in |
| `not_member`, `inactive`, `sso_required`, `not_allowed` | removed |
| `rate_limited`, `second_factor_setup`, `revoked`, `code`, `expired` | kept |

**Signed in online:**

1. The person the server signed in must be who typed: the same username,
   the handle `<username>.<org slug>`, a uid from 20000 to 59999 and the same
   gid. Anything else is `unavailable`, and nothing is written.
2. **Records**: `/etc/userdb/<username>.user` and `.group`, the
   `<uid>.user` and `<uid>.group` links, `<username>:<username>.membership`
   (nss-systemd(8) asks for the primary group's too) and
   `<username>:wheel.membership` exactly while they are a device admin. All
   `0644`, renamed into place, only when they change, with `"service":
   "com.mauvely.Users"`, which is how a record is known for ours. A uid or name
   another account already has here is never taken over (`internal`). A uid
   that had another of our names is a rename: the old records and cache go,
   the old home stays.
3. **Home**: `systemctl start --no-ask-password mauvely-home@<username>.service`,
   the plain username, waited for. A failure refuses the login (`internal`).
4. **Cache**: the entry, sealed (below). A failure refuses the login.
5. **Hand-off**: `/run/mauvely/login/<uid>` (below). A failure is logged; the
   person is then offered the sign-in window.
6. The answer, then, for a version 0 account, the upgrade: a fresh salt, the
   secret derived from the password, `POST <accounts origin>/api/auth/kdf`
   with the new session as a bearer. Only logged.

## `account`

The same caller, name and device rules, then:

- no cache entry is `not_cached`;
- `login`, a text console, is `text_login` for anyone not in
  `desired.people`'s device admins (brief 28): "Sign in at the login screen.";
- everything else is `ok`.

## Refusals

| Reason | When | Message | `auth` | `account` |
|---|---|---|---|---|
| `credentials` | A wrong password, online or against the cache | Wrong name or password. | `PAM_AUTH_ERR` | |
| `code` | A wrong code | That code isn't right. | `PAM_AUTH_ERR` | |
| `expired` | The challenge is spent, used up or older than its expiry | That code has expired. Sign in again. | `PAM_AUTH_ERR` | |
| `rate_limited` | The server's limits | Too many attempts. Try again in a few minutes. | `PAM_AUTH_ERR` | |
| `unknown_user` | Not a name anyone could sign in with here | Wrong name or password. | `PAM_USER_UNKNOWN` | `PAM_USER_UNKNOWN` |
| `bad_username` | A Mauvely name a computer cannot use | This name can't be used to sign in to a computer. | `PAM_USER_UNKNOWN` | `PAM_USER_UNKNOWN` |
| `not_mauvely` | A local account that is not ours | (none, nothing is said) | `PAM_IGNORE` | `PAM_IGNORE` |
| `not_allowed` | The device's say, or the server's | This computer is assigned to someone else. | `PAM_PERM_DENIED` | `PAM_PERM_DENIED` |
| `forbidden` | The caller may not ask about this person | You can only sign in as yourself here. | `PAM_PERM_DENIED` | `PAM_PERM_DENIED` |
| `inactive` | | Your account is switched off. | `PAM_PERM_DENIED` | |
| `not_member` | | You're no longer a member of this organisation. | `PAM_PERM_DENIED` | |
| `sso_required` | | Your organisation signs you in with single sign-on, which this computer can't do yet. | `PAM_PERM_DENIED` | |
| `second_factor_setup` | | Set up an authenticator app in your Mauvely account, then sign in here. | `PAM_PERM_DENIED` | |
| `revoked` | This computer is revoked | This computer has been removed from your organisation. | `PAM_PERM_DENIED` | |
| `text_login` | A text console, not an admin | Sign in at the login screen. | | `PAM_PERM_DENIED` |
| `not_cached` | No cache entry, away from the login screen | Sign in at the login screen first. | `PAM_AUTHINFO_UNAVAIL` | `PAM_PERM_DENIED` |
| `offline` | Unreachable, and the cache cannot sign them in | Connect to the internet to sign in. | `PAM_AUTHINFO_UNAVAIL` | |
| `unreachable` | Unreachable at the code | Mauvely can't be reached. Sign in again. | `PAM_AUTHINFO_UNAVAIL` | |
| `unavailable` | The server answered something unusable (`unauthorised`, a 400, a body off the contract, someone else signed in) | Mauvely can't sign you in right now. Try again later. | `PAM_AUTHINFO_UNAVAIL` | `PAM_AUTHINFO_UNAVAIL` |
| `not_ready` | No `desired.people` yet, or not enrolled | This computer isn't ready for Mauvely accounts yet. | `PAM_AUTHINFO_UNAVAIL` | `PAM_AUTHINFO_UNAVAIL` |
| `busy` | The limits above | This computer is busy. Try again. | `PAM_AUTHINFO_UNAVAIL` | `PAM_AUTHINFO_UNAVAIL` |
| `internal` | Records, home or cache failed | Something went wrong on this computer. Try again. | `PAM_SYSTEM_ERR` | `PAM_SYSTEM_ERR` |
| `bad_request`, `version` | Not this protocol | The same | `PAM_SYSTEM_ERR` | `PAM_SYSTEM_ERR` |

The daemon missing, silent past the wait, hanging up or garbling its answer is
`PAM_AUTHINFO_UNAVAIL`. A reason the module does not know is `PAM_AUTH_ERR`
(`auth`) or `PAM_PERM_DENIED` (`account`). Every refusal but `not_mauvely` is
said with `pam_error`, unless the caller passed `PAM_SILENT`.

**Against the stack** (`[success=done ignore=ignore default=die]`, after the
two `pam_localuser` lines): success ends the stack; `PAM_IGNORE` goes on to
`pam_unix` with the password already in `PAM_AUTHTOK`; every other code fails
the login there and then, so `pam_unix` never sees a Mauvely name. sudo asks
again after `PAM_AUTH_ERR` and stops after the others.

## The module

- The password comes from `pam_get_authtok`, so an earlier module's is used,
  and it stays in `PAM_AUTHTOK` for the wallet modules after the substack
  (`pam_kwallet5`, `pam_gnome_keyring`); it is libpam's, never wiped by us.
- At `result: code`: `pam_info` with `info`, then `PAM_PROMPT_ECHO_OFF` with
  `prompt`. An empty answer refuses the login without sending anything (the
  patched login screen's cancel); a conversation that fails is
  `PAM_CONV_ERR`.
- No file, no network, no thread. It fails closed: `PAM_AUTHINFO_UNAVAIL`.
- Our copies of the password and code are wiped: the request is written into
  a buffer sized up front so it never moves, the code's malloc'd answer is
  overwritten before `free`.
- Every entry point runs in `catch_unwind`; a panic is `PAM_SYSTEM_ERR`.
- `socket=<path>` moves the socket in a debug build only.
- It builds to `target/release/libpam_mauvely.so`, linked against libpam
  (`pam-devel` in the builder), exporting `pam_sm_authenticate`,
  `pam_sm_acct_mgmt` and `pam_sm_setcred` only. Installed as
  `/usr/lib64/security/pam_mauvely.so`.

## The offline cache

`/var/lib/mauvely/people/<username>.cred`, `0600` in a `0700` directory.

- **Holds** the username, handle, uid, name, deviceAdmin, `offlineDays`, the
  time of the online sign-in, and a verifier of the password.
- **The verifier** is Argon2id with a fresh 16-byte salt, m=64 MiB, t=4, p=1,
  32 bytes, and associated data `mauvely-os offline cache v1`. Never the
  server's `authSecret`, so a stolen entry cannot sign anybody in to Mauvely,
  and compared in constant time.
- **Sealed whole** with `systemd-creds`, as the device key is (TPM2 where
  there is one, else the host key), under the name
  `mauvely-person-<username>`, so an entry renamed to another person does not
  unseal. It costs one `systemd-creds decrypt` per unlock or sudo. Worth it:
  the same password opens the person's Cloud vault (plan 23), and sealed to
  the TPM a copied disk cannot even be guessed against.
- An entry that does not unseal is taken as none.
- **Who loses it:** someone `desired.people` no longer allows (at each
  check-in, and at each request), and the server's refusals above. Their
  records and home stay: removing those is brief 29's reset, or a later
  cleanup.

## The hand-off

`/run/mauvely/login/<uid>`: `0600`, the person's, staged at
`/run/mauvely/.login-<uid>.tmp` (root's alone) and renamed in.

```json
{"v":1,"token":"…","expiresAt":1771200000,"origin":"https://mauvely.com","handle":"timur.suez"}
```

`origin` is the accounts origin for `/etc/mauvely/server` (the same table as
`docs/broker.md`); with none known, nothing is handed over. The directory is
`01733`, so the person can delete their own file and nobody else's.
`mauvely-session` (`broker/login.rs`) takes only a regular file of its own
uid, mode `0600`, opened without following a link; reads it, deletes it, and
seals the session as a linked one, replacing any stored session. A person
signed in this way is never offered the sign-in window. Offline sign-ins hand
nothing over: the session sealed at the last online one carries on.

## The greeter's file

`/var/lib/mauvely-desktop/people.json`, `0644`, written by the agent at each
check-in when it changes:

```json
{"mode":"assigned","assigned":{"username":"timur","name":"Timur Inal"},"org":{"name":"Suez","slug":"suez"}}
```

Never the admins: those stay in `/var/lib/mauvely/people.json` (`0600`).

## Threat model, as built

- **The socket is everyone's to connect to; what they may ask is not.** A
  local user can ask only about themselves, and only the cache: they can
  guess their own password at about one try in two seconds per connection,
  four connections at most. Only root reaches the server or writes anything.
- **The login screen's online path is root's.** A person cannot mint an `os`
  session or write records from their own session by claiming `plasmalogin`.
- **A stolen cache entry** is sealed to this machine (and its TPM), and even
  unsealed is an Argon2id verifier that the server does not take.
- **A wrong server answer** cannot make a local account: the person must be
  who typed, in a uid range no local account uses, on a uid and name nobody
  here has.
- **Logs** never hold a token, a password or a code; a typed name is logged
  only once it is a person here, since people type passwords into the name
  box.
- **What it cannot stop:** root. And on a shared device, a member removed from
  the organisation keeps their cache, so their lock screen and sudo, until
  they try the login screen online: `desired.people` does not list a shared
  device's members.

## Testing it

- `cargo test`: every rule above, without root, a TPM, the network or PAM.
- `tests/login/local.sh <scratch>`: the debug module through this machine's
  libpam (`pam_start_confdir`), against `fake_daemon.py`.
- `tests/login/container.sh <scratch>`: the release module, built in Fedora
  44, in Kinoite 44 as root, under the `mauvely` authselect profile
  (`stack.sh`): the real `/usr/lib/pam.d/plasmalogin`, sudo, `login`, the
  password reaching a module after the substack, and the `pam_localuser`
  guard with the daemon down.
- `tests/login/e2e.sh <scratch>`: the real `mauvelyd login` and the real
  module in Kinoite, against `fake_devices.py`, with the key and the cache
  sealed by the real `systemd-creds`: records seen by `getent` and `id`, the
  home, the hand-off, the KDF vector on the wire, a version 0 upgrade, sudo,
  the lock screen as the person, a text console, offline.

The last two need podman, and the network for `dnf` and crates.io.
