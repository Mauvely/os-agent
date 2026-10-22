#!/usr/bin/env python3
"""Tests for package.py: `python3 -I browser/test_package.py`.

The CRX is read back and its signature checked with openssl; the AMO side runs
against a fake on 127.0.0.1 that speaks the part of addons.mozilla.org's v5 API
package.py uses. The real AMO has not been tried (no keys yet).
"""

import base64
import contextlib
import hashlib
import hmac
import http.server
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
import package  # noqa: E402

GUID = "os-signin@mauvely.com"
VERSION = package.manifest("firefox")["version"]


def read_varint(data, i):
    n = shift = 0
    while True:
        b = data[i]
        i += 1
        n |= (b & 0x7F) << shift
        shift += 7
        if not b & 0x80:
            return n, i


def fields(data):
    """A protobuf message's length-delimited fields, as (number, bytes)."""
    i, out = 0, []
    while i < len(data):
        key, i = read_varint(data, i)
        assert key & 7 == 2, "only length-delimited fields"
        n, i = read_varint(data, i)
        out.append((key >> 3, data[i:i + n]))
        i += n
    return out


def new_key(directory):
    key = Path(directory) / "key.pem"
    subprocess.run(["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                    "-out", str(key)], check=True, capture_output=True)
    return key


class Crx(unittest.TestCase):
    def test_a_crx3_that_verifies(self):
        with tempfile.TemporaryDirectory() as d:
            key = new_key(d)
            zip_bytes = package.deterministic_zip(package.sources("chromium"))
            crx = package.pack_crx(zip_bytes, key)
            self.assertEqual(crx[:4], b"Cr24")
            version, header_len = struct.unpack("<II", crx[4:12])
            self.assertEqual(version, 3)
            header = crx[12:12 + header_len]
            self.assertEqual(crx[12 + header_len:], zip_bytes)

            top = fields(header)
            self.assertEqual([n for n, _ in top], [2, 10000])
            proof = dict(fields(top[0][1]))
            der, signature = proof[1], proof[2]
            self.assertEqual(der, package.public_der(key))
            signed_data = top[1][1]
            self.assertEqual(fields(signed_data), [(1, hashlib.sha256(der).digest()[:16])])

            # The signature is over Chromium's prefix, the signed data's length,
            # the signed data and the archive.
            message = b"CRX3 SignedData\x00" + struct.pack("<I", len(signed_data)) + signed_data + zip_bytes
            Path(d, "msg").write_bytes(message)
            Path(d, "sig").write_bytes(signature)
            Path(d, "pub.der").write_bytes(der)
            r = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(Path(d, "pub.der")),
                                "-keyform", "DER", "-signature", str(Path(d, "sig")), str(Path(d, "msg"))],
                               capture_output=True, text=True)
            self.assertIn("Verified OK", r.stdout, r.stderr)

    def test_the_id_is_chromiums(self):
        # Chromium's own example: the id of a known key is its SHA-256, a to p.
        der = b"\x30\x00"
        digest = hashlib.sha256(der).hexdigest()[:32]
        self.assertEqual(package.crx_id(der), "".join("abcdefghijklmnop"[int(c, 16)] for c in digest))
        key = base64.b64decode(package.manifest("chromium")["key"])
        self.assertRegex(package.crx_id(key), r"^[a-p]{32}$")

    def test_a_key_that_is_not_the_manifests_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            key = new_key(d)
            with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
                package.stage_chromium(Path(d, "out"), key)
            self.assertIn("not manifest.chromium.json's `key`", err.getvalue())
            self.assertFalse(Path(d, "out").exists())


class Staging(unittest.TestCase):
    def setUp(self):
        self.env = dict(os.environ)
        for name in ("CRX_SIGNING_KEY_FILE", "AMO_JWT_ISSUER", "AMO_JWT_SECRET", "MAUVELY_UNSIGNED_XPI", "AMO_BASE"):
            os.environ.pop(name, None)

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self.env)

    def test_zips_are_reproducible(self):
        a = package.deterministic_zip(package.sources("firefox"))
        b = package.deterministic_zip(package.sources("firefox"))
        self.assertEqual(a, b)
        with zipfile.ZipFile(io.BytesIO(a)) as z:
            self.assertEqual(z.namelist(), ["background.js", "manifest.json", "signin.js"])
            self.assertEqual(json.loads(z.read("manifest.json"))["browser_specific_settings"]["gecko"]["id"], GUID)

    def test_without_keys_nothing_is_staged(self):
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()) as out:
            package.stage(d)
            self.assertEqual(list(Path(d).iterdir()), [])
        self.assertIn("no Chromium extension", out.getvalue())
        self.assertIn("no Firefox extension", out.getvalue())

    def test_the_firefox_tree(self):
        os.environ["MAUVELY_UNSIGNED_XPI"] = "1"
        with tempfile.TemporaryDirectory() as d, contextlib.redirect_stdout(io.StringIO()):
            package.stage(d)
            tree = Path(d, "org.mozilla.firefox.systemconfig")
            self.assertEqual(
                sorted(str(p.relative_to(tree)) for p in tree.rglob("*") if p.is_file()),
                ["mauvely/mauvely-signin.xpi", "policies/policies.json"],
            )
            self.assertEqual(
                json.loads((tree / "policies/policies.json").read_text()),
                {"policies": {"ExtensionSettings": {GUID: {
                    "installation_mode": "force_installed",
                    "install_url": "file:///app/etc/firefox/mauvely/mauvely-signin.xpi",
                }}}},
            )
            self.assertEqual((tree / "mauvely/mauvely-signin.xpi").read_bytes(),
                             package.deterministic_zip(package.sources("firefox")))


# ── AMO ─────────────────────────────────────────────────────────────────────


class FakeAmo(http.server.BaseHTTPRequestHandler):
    """addons.mozilla.org, as far as package.py uses it."""

    state = None

    def log_message(self, *args):
        pass

    def authorised(self):
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("JWT "):
            return False
        head, body, sig = auth[4:].encode().split(b".")
        good = base64.urlsafe_b64encode(hmac.new(b"the-secret", head + b"." + body, hashlib.sha256).digest()).rstrip(b"=")
        claims = json.loads(base64.urlsafe_b64decode(body + b"=" * (-len(body) % 4)))
        return hmac.compare_digest(sig, good) and claims["iss"] == "user:1:2" and claims["exp"] - claims["iat"] <= 300

    def send(self, status, payload=None, raw=None):
        data = raw if raw is not None else json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        s = self.state
        s["calls"].append(("GET", self.path))
        if not self.authorised():
            return self.send(401, {"detail": "no"})
        prefix = f"/api/v5/addons/addon/{GUID.replace('@', '%40')}/"
        if self.path.startswith(prefix + "versions/"):
            if not s["addon"]:
                return self.send(404, {"detail": "Not found."})
            if s["pending"]:
                s["pending"] -= 1
            results = [{"version": v, "file": {"status": "unreviewed" if s["pending"] else "public",
                                               "url": f"http://127.0.0.1:{s['port']}/files/{v}.xpi"}}
                       for v in s["versions"]]
            return self.send(200, {"results": results, "next": None})
        if self.path == prefix:
            return self.send(200 if s["addon"] else 404, {"guid": GUID} if s["addon"] else {"detail": "Not found."})
        if self.path.startswith("/api/v5/addons/upload/"):
            return self.send(200, {"uuid": "u1", "processed": True, "valid": s["valid"],
                                   "validation": {"messages": [{"message": "bad manifest"}]}})
        if self.path.startswith("/files/"):
            return self.send(200, raw=s["signed"])
        self.send(404, {})

    def do_POST(self):
        s = self.state
        s["calls"].append(("POST", self.path))
        if not self.authorised():
            return self.send(401, {})
        length = int(self.headers["Content-Length"])
        body = self.rfile.read(length)
        if self.path == "/api/v5/addons/upload/":
            assert b'name="channel"\r\n\r\nunlisted' in body
            s["uploaded"] = body
            return self.send(202, {"uuid": "u1", "processed": False})
        if self.path.endswith("/versions/"):
            s["versions"].append(VERSION)
            return self.send(201, {"version": VERSION})
        self.send(404, {})

    def do_PUT(self):
        s = self.state
        s["calls"].append(("PUT", self.path))
        if not self.authorised():
            return self.send(401, {})
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        assert body == {"version": {"upload": "u1"}}
        s["addon"] = True
        s["versions"].append(VERSION)
        self.send(201, {"guid": GUID})


def signed(unsigned, extra=None):
    """What AMO hands back: the files, plus META-INF."""
    out = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(unsigned)) as u, zipfile.ZipFile(out, "w") as z:
        for n in u.namelist():
            z.writestr(n, u.read(n))
        for n, data in (extra or {}).items():
            z.writestr(n, data)
        z.writestr("META-INF/cose.sig", b"sig")
        z.writestr("META-INF/manifest.mf", b"mf")
    return out.getvalue()


class Amo(unittest.TestCase):
    def setUp(self):
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), FakeAmo)
        port = self.server.server_address[1]
        self.unsigned = package.deterministic_zip(package.sources("firefox"))
        FakeAmo.state = {"calls": [], "addon": False, "versions": [], "pending": 2, "valid": True,
                         "port": port, "signed": signed(self.unsigned)}
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.env = dict(os.environ)
        os.environ.update({"AMO_BASE": f"http://127.0.0.1:{port}", "AMO_POLL": "0"})

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        os.environ.clear()
        os.environ.update(self.env)

    def sign(self):
        with contextlib.redirect_stdout(io.StringIO()):
            return package.sign_xpi(self.unsigned, "user:1:2", "the-secret")

    def test_the_first_version_creates_the_unlisted_addon(self):
        self.assertEqual(self.sign(), FakeAmo.state["signed"])
        methods = [m for m, _ in FakeAmo.state["calls"]]
        self.assertIn("PUT", methods)
        self.assertEqual(methods.count("POST"), 1)
        self.assertIn(self.unsigned, FakeAmo.state["uploaded"])

    def test_a_version_signed_before_is_fetched_not_signed_again(self):
        FakeAmo.state.update(addon=True, versions=[VERSION], pending=0)
        self.assertEqual(self.sign(), FakeAmo.state["signed"])
        self.assertNotIn("POST", [m for m, _ in FakeAmo.state["calls"]])

    def test_a_later_version_is_added(self):
        FakeAmo.state.update(addon=True, versions=["0.0.1"], pending=0)
        self.sign()
        self.assertIn(("POST", f"/api/v5/addons/addon/{GUID.replace('@', '%40')}/versions/"), FakeAmo.state["calls"])
        self.assertNotIn("PUT", [m for m, _ in FakeAmo.state["calls"]])

    def test_amo_holding_other_code_under_this_version_is_refused(self):
        FakeAmo.state.update(addon=True, versions=[VERSION], pending=0,
                             signed=signed(self.unsigned, {"extra.js": b"other code"}))
        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
            self.sign()
        self.assertIn("bump `version`", err.getvalue())

    def test_an_unsigned_file_back_is_refused(self):
        FakeAmo.state.update(addon=True, versions=[VERSION], pending=0, signed=self.unsigned)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.sign()

    def test_an_invalid_upload_stops_it(self):
        FakeAmo.state["valid"] = False
        with contextlib.redirect_stderr(io.StringIO()) as err, self.assertRaises(SystemExit):
            self.sign()
        self.assertIn("bad manifest", err.getvalue())

    def test_the_key_goes_to_amo_alone(self):
        for base in ("https://addons.mozilla.org.evil.example", "http://addons.mozilla.org", "http://10.0.0.1:80"):
            os.environ["AMO_BASE"] = base
            with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                package.Amo("user:1:2", "the-secret")


if __name__ == "__main__":
    unittest.main()
