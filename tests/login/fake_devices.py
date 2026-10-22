"""A stand-in for website-devices' login door (on 8798) and website-main's
POST /api/auth/kdf (on 8787), for e2e.sh. Test people, test values:

| Username | Account | Answers |
|---|---|---|
| timur | version 1, salt all zeros | a TOTP code, 123456; uid 21001 |
| ada | version 0 | signed in at once; a device admin, uid 21002; upgraded after |
| anyone else | | credentials |

Every request is appended to <log> as one JSON line: port, path, whether it
was signed, the Authorization header, and the body.

    python3 -I fake_devices.py <log>
"""
import json
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

LOG = sys.argv[1]
# kdf.json's first vector: "correct horse battery staple 1" against 16 zero bytes.
TIMUR_SECRET = "0d0R8jeMwo4LuShcvdP7aW4F1sSlks3OkaoTN5E60AE="
lock = threading.Lock()


def person(username, uid, admin, kdf):
    return {
        "username": username, "handle": f"{username}.suez",
        "name": {"timur": "Timur Inal", "ada": "Ada Lovelace"}[username],
        "uid": uid, "gid": uid, "deviceAdmin": admin, "kdfVersion": kdf,
        "emailIsPlaceholder": False,
    }


def signed_in(username, uid, admin, kdf):
    return 200, {
        "step": "signed_in",
        "session": {"token": f"tok_{username}", "expiresAt": int(time.time()) + 90 * 86400},
        "person": person(username, uid, admin, kdf),
        "offlineDays": 14,
    }


def answer(port, path, headers, body):
    if port == 8798:
        if not headers.get("X-Mauvely-Signature") or headers.get("X-Mauvely-Device") != "dev_e2e":
            return 401, {"error": "unauthorised"}
        if path == "/api/agent/v2/login/params":
            if body["username"] == "ada":
                return 200, {"kdfVersion": 0, "authSalt": None}
            return 200, {"kdfVersion": 1, "authSalt": "AAAAAAAAAAAAAAAAAAAAAA=="}
        if path == "/api/agent/v2/login":
            if body == {"username": "timur", "kdfVersion": 1, "secret": TIMUR_SECRET}:
                return 200, {"step": "code", "challenge": "ch_timur", "factor": "totp",
                             "expiresAt": int(time.time()) + 600}
            if body == {"username": "ada", "kdfVersion": 0, "secret": "ada password 1"}:
                return signed_in("ada", 21002, True, 0)
            return 401, {"error": "credentials"}
        if path == "/api/agent/v2/login/code":
            if body == {"challenge": "ch_timur", "code": "123456"}:
                return signed_in("timur", 21001, False, 1)
            return 401, {"error": "code"}
    if port == 8787 and path == "/api/auth/kdf":
        if headers.get("Authorization") == "Bearer tok_ada" and body.get("password") == "ada password 1":
            return 200, {"ok": True, "authSalt": body["authSalt"]}
        return 400, {"error": "bad_password"}
    return 404, {"error": "not_found"}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        port = self.server.server_address[1]
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)))
        body = json.loads(raw)
        status, out = answer(port, self.path, self.headers, body)
        with lock, open(LOG, "a") as log:
            log.write(json.dumps({
                "port": port, "path": self.path,
                "signed": bool(self.headers.get("X-Mauvely-Signature")),
                "authorization": self.headers.get("Authorization"),
                "body": body, "status": status,
            }) + "\n")
        data = json.dumps(out).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


servers = [ThreadingHTTPServer(("127.0.0.1", port), Handler) for port in (8798, 8787)]
for s in servers[1:]:
    threading.Thread(target=s.serve_forever, daemon=True).start()
print("listening", flush=True)
servers[0].serve_forever()
