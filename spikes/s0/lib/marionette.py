#!/usr/bin/env python3
"""Minimal Marionette client (Firefox remote protocol v3), stdlib only.

  marionette.py PORT install-addon PATH      temporary add-on install (Addon:Install, temporary:true)
  marionette.py PORT chrome-js 'return ...'  run a script in chrome context, print its JSON result
  marionette.py PORT content-js 'return ...' run a script in content context
  marionette.py PORT navigate URL
  marionette.py PORT quit
"""
import json, socket, sys, time


class M:
    def __init__(self, port, timeout=60):
        self.s = socket.create_connection(("127.0.0.1", port), timeout=timeout)
        self.buf = b""
        self.id = 0
        self.greeting = self._read()
        self.cmd("WebDriver:NewSession", {"capabilities": {}})

    def _read(self):
        while b":" not in self.buf:
            self.buf += self._recv()
        n, rest = self.buf.split(b":", 1)
        n = int(n)
        while len(rest) < n:
            rest += self._recv()
        self.buf = rest[n:]
        return json.loads(rest[:n])

    def _recv(self):
        d = self.s.recv(65536)
        if not d:
            raise EOFError("marionette closed")
        return d

    def cmd(self, name, params=None):
        self.id += 1
        msg = json.dumps([0, self.id, name, params or {}]).encode()
        self.s.sendall(str(len(msg)).encode() + b":" + msg)
        while True:
            r = self._read()
            if r[0] == 1 and r[1] == self.id:
                if r[2]:
                    raise RuntimeError(f"{name}: {r[2]}")
                return r[3]


def connect(port, tries=120):
    for _ in range(tries):
        try:
            return M(port)
        except (OSError, EOFError):
            time.sleep(0.5)
    raise SystemExit("marionette did not come up")


if __name__ == "__main__":
    port, op = int(sys.argv[1]), sys.argv[2]
    m = connect(port)
    if op == "install-addon":
        print(json.dumps(m.cmd("Addon:Install", {"path": sys.argv[3], "temporary": True})))
    elif op in ("chrome-js", "content-js"):
        m.cmd("Marionette:SetContext", {"value": "chrome" if op == "chrome-js" else "content"})
        print(json.dumps(m.cmd("WebDriver:ExecuteScript", {"script": sys.argv[3], "args": []}), indent=1))
    elif op == "navigate":
        m.cmd("Marionette:SetContext", {"value": "content"})
        print(json.dumps(m.cmd("WebDriver:Navigate", {"url": sys.argv[3]})))
    elif op == "quit":
        try:
            m.cmd("Marionette:Quit", {"flags": ["eForceQuit"]})
        except Exception as e:  # the connection drops as it quits
            print("quit:", e)
