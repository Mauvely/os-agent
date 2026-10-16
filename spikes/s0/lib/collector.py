#!/usr/bin/env python3
"""Loopback collector: the spike extension POSTs one JSON object per step; we append them to a file."""
import http.server, sys

LOG = sys.argv[1]
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 18099


class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8", "replace")
        with open(LOG, "a") as f:
            f.write(body.replace("\n", " ") + "\n")
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

    do_OPTIONS = do_POST

    def log_message(self, *a):
        pass


http.server.ThreadingHTTPServer(("127.0.0.1", PORT), H).serve_forever()
