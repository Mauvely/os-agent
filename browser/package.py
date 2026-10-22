#!/usr/bin/env python3
"""Packages the Mauvely OS browser extension for the image (brief 22, S4).

    python3 -I browser/package.py build <out>     unpacked builds and the unsigned XPI
    python3 -I browser/package.py stage <out>     the two Flatpak extension trees the image ships
    python3 -I browser/package.py crx-id <pem>    the Chromium id a private key gives

`stage` writes, under <out>:

    org.chromium.Chromium.Extension.mauvely/      /app/chromium/extensions/mauvely/ in Chromium
        policies/managed/com.mauvely.signin.json  ExtensionInstallForcelist
        update.xml, mauvely-signin.crx
    org.mozilla.firefox.systemconfig/             /app/etc/firefox/ in Firefox
        policies/policies.json                    ExtensionSettings, force_installed
        mauvely/mauvely-signin.xpi

os-image ships them in /usr/share/mauvely/browser/ and bind-mounts each at
/var/lib/flatpak/extension/<name>/x86_64/<branch>, where Flatpak mounts it into
the browser as an unmanaged extension (os-agent docs/browser.md). Each tree needs
a key, read from the environment and never from an argument:

    CRX_SIGNING_KEY_FILE   the Chromium extension's RSA private key, PEM. Its public
                           half must be manifest.chromium.json's `key`, which fixes
                           the extension's id. Unset: no Chromium tree.
    AMO_JWT_ISSUER         an addons.mozilla.org API key and its secret. The XPI is
    AMO_JWT_SECRET         signed as an unlisted add-on, once per version, and the
                           signed file is fetched again on later runs. Unset: no
                           Firefox tree.
    MAUVELY_UNSIGNED_XPI=1 tests only: the Firefox tree with the unsigned XPI, which
                           release Firefox refuses to install.

A tree whose key is missing is left out with a message, and the run succeeds.

Python's standard library and the `openssl` command only.
"""

import base64
import hashlib
import hmac
import io
import json
import os
import secrets
import struct
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
EXTENSION = HERE / "extension"
FILES = ["background.js", "signin.js"]

# The extensions' names, and where each browser mounts it. The branch each is
# mounted under (Chromium's `1`, Flathub's `version` for the point; Firefox's
# `stable`, the app's own) is the image's mount units' business.
CHROMIUM_REF = "org.chromium.Chromium.Extension.mauvely"
CHROMIUM_APP_DIR = "/app/chromium/extensions/mauvely"
FIREFOX_REF = "org.mozilla.firefox.systemconfig"
FIREFOX_APP_DIR = "/app/etc/firefox"
CRX = "mauvely-signin.crx"
XPI = "mauvely-signin.xpi"

AMO = "https://addons.mozilla.org"


def fail(message):
    print(f"package: {message}", file=sys.stderr)
    sys.exit(1)


def manifest(browser):
    return json.loads((EXTENSION / f"manifest.{browser}.json").read_text())


def deterministic_zip(files):
    """A zip of {name: bytes}, the same bytes for the same files."""
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.external_attr = 0o644 << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, files[name])
    return out.getvalue()


def sources(browser):
    files = {name: (EXTENSION / "src" / name).read_bytes() for name in FILES}
    files["manifest.json"] = (EXTENSION / f"manifest.{browser}.json").read_bytes()
    return files


def build(out):
    out = Path(out)
    for browser in ("chromium", "firefox"):
        d = out / browser
        d.mkdir(parents=True, exist_ok=True)
        for name, data in sources(browser).items():
            (d / name).write_bytes(data)
    (out / "mauvely-signin-unsigned.xpi").write_bytes(deterministic_zip(sources("firefox")))
    (out / "mauvely-signin.zip").write_bytes(deterministic_zip(sources("chromium")))
    return out


# ── Chromium: CRX3 ──────────────────────────────────────────────────────────


def openssl(args, data=None):
    r = subprocess.run(["openssl", *args], input=data, capture_output=True)
    if r.returncode != 0:
        fail(f"openssl {args[0]}: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def public_der(key_file):
    return openssl(["pkey", "-in", str(key_file), "-pubout", "-outform", "DER"])


def crx_id(der):
    """Chromium's id: the first 16 bytes of the key's SHA-256, as a to p."""
    return "".join(chr(ord("a") + int(c, 16)) for c in hashlib.sha256(der).hexdigest()[:32])


def varint(n):
    out = bytearray()
    while True:
        byte = n & 0x7F
        n >>= 7
        out.append(byte | (0x80 if n else 0))
        if not n:
            return bytes(out)


def field(number, data):
    """A length-delimited protobuf field."""
    return varint(number << 3 | 2) + varint(len(data)) + data


def pack_crx(zip_bytes, key_file):
    """CRX3: `Cr24`, version 3, a CrxFileHeader, then the zip. The header holds
    one sha256_with_rsa proof (the public key and a signature) and the signed
    data, which is the 16-byte crx id."""
    der = public_der(key_file)
    signed_data = field(1, hashlib.sha256(der).digest()[:16])
    message = b"CRX3 SignedData\x00" + struct.pack("<I", len(signed_data)) + signed_data + zip_bytes
    signature = openssl(["dgst", "-sha256", "-sign", str(key_file)], message)
    header = field(2, field(1, der) + field(2, signature)) + field(10000, signed_data)
    return b"Cr24" + struct.pack("<II", 3, len(header)) + header + zip_bytes


def stage_chromium(out, key_file):
    m = manifest("chromium")
    der = public_der(key_file)
    if base64.b64encode(der).decode() != m["key"]:
        fail(
            "CRX_SIGNING_KEY_FILE's public half is not manifest.chromium.json's `key`, so the "
            "CRX would have another id than the one the policy and mauvely-session name. A new "
            "key changes the id: put its public half in the manifest and follow docs/browser.md."
        )
    ext_id, version = crx_id(der), m["version"]
    tree = out / CHROMIUM_REF
    (tree / "policies/managed").mkdir(parents=True, exist_ok=True)
    (tree / CRX).write_bytes(pack_crx(deterministic_zip(sources("chromium")), key_file))
    (tree / "update.xml").write_text(
        "<?xml version='1.0' encoding='UTF-8'?>\n"
        "<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>\n"
        f"  <app appid='{ext_id}'>\n"
        f"    <updatecheck codebase='file://{CHROMIUM_APP_DIR}/{CRX}' version='{version}' />\n"
        "  </app>\n"
        "</gupdate>\n"
    )
    policy = {"ExtensionInstallForcelist": [f"{ext_id};file://{CHROMIUM_APP_DIR}/update.xml"]}
    (tree / "policies/managed/com.mauvely.signin.json").write_text(json.dumps(policy, indent=2) + "\n")
    print(f"package: Chromium {ext_id} {version}")
    return ext_id


# ── Firefox: AMO ────────────────────────────────────────────────────────────


def amo_base():
    base = os.environ.get("AMO_BASE", AMO)
    parsed = urllib.parse.urlsplit(base)
    # Moved only to a fake on this machine, for the tests.
    if base != AMO and not (parsed.scheme == "http" and parsed.hostname == "127.0.0.1"):
        fail(f"AMO_BASE {base!r} is neither {AMO} nor a loopback fake")
    return base


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=")


def jwt(issuer, secret):
    """AMO's API key: HS256 over {iss, jti, iat, exp}, for at most a minute."""
    now = int(time.time())
    head = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    body = b64url(json.dumps({"iss": issuer, "jti": secrets.token_hex(16), "iat": now, "exp": now + 60}).encode())
    sig = b64url(hmac.new(secret.encode(), head + b"." + body, hashlib.sha256).digest())
    return (head + b"." + body + b"." + sig).decode()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Amo:
    def __init__(self, issuer, secret):
        self.issuer, self.secret, self.base = issuer, secret, amo_base()
        self.opener = urllib.request.build_opener(NoRedirect)

    def call(self, method, path, body=None, content_type="application/json"):
        url = path if path.startswith("http") else self.base + path
        req = urllib.request.Request(url, data=body, method=method)
        # The key goes only to AMO itself, never to wherever it redirects.
        if urllib.parse.urlsplit(url).netloc == urllib.parse.urlsplit(self.base).netloc:
            req.add_header("Authorization", f"JWT {jwt(self.issuer, self.secret)}")
        if body is not None:
            req.add_header("Content-Type", content_type)
        try:
            with self.opener.open(req, timeout=60) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            if e.code in (301, 302, 303, 307, 308) and method == "GET":
                return self.call("GET", e.headers["Location"])
            return e.code, e.read()

    def json(self, method, path, payload=None):
        body = None if payload is None else json.dumps(payload).encode()
        status, data = self.call(method, path, body)
        try:
            return status, json.loads(data or b"null")
        except ValueError:
            return status, None

    def version(self, guid, version):
        """The version's entry, or None when AMO has no such version."""
        path = f"/api/v5/addons/addon/{urllib.parse.quote(guid)}/versions/?filter=all_with_unlisted&page_size=50"
        while path:
            status, page = self.json("GET", path)
            if status == 404:
                return None
            if status != 200 or not isinstance(page, dict):
                fail(f"AMO: listing {guid}'s versions answered {status}")
            for v in page.get("results", []):
                if v.get("version") == version:
                    return v
            path = page.get("next")
        return None

    def upload(self, xpi):
        boundary = uuid.uuid4().hex
        body = (
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"channel\"\r\n\r\nunlisted\r\n"
            f"--{boundary}\r\nContent-Disposition: form-data; name=\"upload\"; filename=\"{XPI}\"\r\n"
            "Content-Type: application/x-xpinstall\r\n\r\n"
        ).encode() + xpi + f"\r\n--{boundary}--\r\n".encode()
        status, data = self.call("POST", "/api/v5/addons/upload/", body, f"multipart/form-data; boundary={boundary}")
        if status not in (200, 201, 202):
            fail(f"AMO: the upload answered {status}: {data[:300]!r}")
        upload = json.loads(data)
        for _ in range(120):
            if upload.get("processed"):
                break
            time.sleep(float(os.environ.get("AMO_POLL", "5")))
            _, upload = self.json("GET", f"/api/v5/addons/upload/{upload['uuid']}/")
        if not upload.get("processed"):
            fail("AMO: the upload was not processed in ten minutes")
        if not upload.get("valid"):
            messages = (upload.get("validation") or {}).get("messages", [])
            fail("AMO: the upload is not valid: " + "; ".join(m.get("message", "?") for m in messages[:5]))
        return upload["uuid"]

    def submit(self, guid, upload_uuid):
        status, _ = self.json("GET", f"/api/v5/addons/addon/{urllib.parse.quote(guid)}/")
        if status == 404:
            # The first version creates the add-on, unlisted, under our guid.
            status, data = self.json("PUT", f"/api/v5/addons/addon/{urllib.parse.quote(guid)}/",
                                     {"version": {"upload": upload_uuid}})
        else:
            status, data = self.json("POST", f"/api/v5/addons/addon/{urllib.parse.quote(guid)}/versions/",
                                     {"upload": upload_uuid})
        if status not in (200, 201, 202):
            fail(f"AMO: submitting answered {status}: {str(data)[:300]}")

    def signed(self, guid, version):
        """Waits for the version's signed file, and downloads it."""
        for _ in range(120):
            v = self.version(guid, version)
            f = (v or {}).get("file") or {}
            if f.get("status") == "public" and f.get("url"):
                status, data = self.call("GET", f["url"])
                if status != 200:
                    fail(f"AMO: downloading the signed file answered {status}")
                return data
            if f.get("status") in ("disabled", "rejected"):
                fail(f"AMO: {guid} {version} is {f['status']}")
            time.sleep(float(os.environ.get("AMO_POLL", "5")))
        fail(f"AMO: {guid} {version} was not signed in ten minutes")


def same_content(signed, unsigned):
    """Whether a signed XPI holds exactly the unsigned one's files; AMO adds
    only META-INF/."""
    with zipfile.ZipFile(io.BytesIO(signed)) as s, zipfile.ZipFile(io.BytesIO(unsigned)) as u:
        theirs = {n: s.read(n) for n in s.namelist() if not n.startswith("META-INF/")}
        ours = {n: u.read(n) for n in u.namelist()}
        return theirs == ours and any(n.startswith("META-INF/") for n in s.namelist())


def sign_xpi(unsigned, issuer, secret):
    m = manifest("firefox")
    guid, version = m["browser_specific_settings"]["gecko"]["id"], m["version"]
    amo = Amo(issuer, secret)
    if amo.version(guid, version) is None:
        print(f"package: AMO: signing {guid} {version}, unlisted")
        amo.submit(guid, amo.upload(unsigned))
    else:
        print(f"package: AMO: {guid} {version} is there already; fetching it")
    signed = amo.signed(guid, version)
    if not same_content(signed, unsigned):
        fail(
            f"AMO's {guid} {version} is not this source. A version is signed once: "
            "bump `version` in both manifests."
        )
    return signed


def stage_firefox(out, xpi):
    m = manifest("firefox")
    guid = m["browser_specific_settings"]["gecko"]["id"]
    tree = out / FIREFOX_REF
    (tree / "policies").mkdir(parents=True, exist_ok=True)
    (tree / "mauvely").mkdir(parents=True, exist_ok=True)
    (tree / "mauvely" / XPI).write_bytes(xpi)
    # Firefox reads a file:// install_url again at each start and installs a
    # newer version from it (PoliciesHelpers.sys.mjs, installAddonFromURL).
    policy = {
        "policies": {
            "ExtensionSettings": {
                guid: {
                    "installation_mode": "force_installed",
                    "install_url": f"file://{FIREFOX_APP_DIR}/mauvely/{XPI}",
                }
            }
        }
    }
    (tree / "policies/policies.json").write_text(json.dumps(policy, indent=2) + "\n")
    print(f"package: Firefox {guid} {m['version']}")


def stage(out):
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    c, f = manifest("chromium"), manifest("firefox")
    if c["version"] != f["version"]:
        fail("the two manifests have different versions")

    key = os.environ.get("CRX_SIGNING_KEY_FILE")
    if key:
        stage_chromium(out, key)
    else:
        print("package: CRX_SIGNING_KEY_FILE is not set: no Chromium extension in this image")

    unsigned = deterministic_zip(sources("firefox"))
    issuer, secret = os.environ.get("AMO_JWT_ISSUER"), os.environ.get("AMO_JWT_SECRET")
    if issuer and secret:
        stage_firefox(out, sign_xpi(unsigned, issuer, secret))
    elif os.environ.get("MAUVELY_UNSIGNED_XPI") == "1":
        print("package: the unsigned XPI, for tests: release Firefox refuses it")
        stage_firefox(out, unsigned)
    else:
        print("package: AMO_JWT_ISSUER and AMO_JWT_SECRET are not set: no Firefox extension in this image")


def main(argv):
    if len(argv) == 3 and argv[1] == "build":
        build(argv[2])
    elif len(argv) == 3 and argv[1] == "stage":
        stage(argv[2])
    elif len(argv) == 3 and argv[1] == "crx-id":
        print(crx_id(public_der(argv[2])))
    else:
        print(__doc__, file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
