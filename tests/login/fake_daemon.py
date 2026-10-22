"""A stand-in for mauvelyd's login socket, for the PAM harness.

    python3 -I fake_daemon.py <socket> <script.json> <log>

The script maps "<op>:<username>" (op "auth" or "account") to the answers to
give on that connection, one per line received: a password, then a code. A
connection whose key is not in the script is refused "unknown_user". Every
line received is appended to <log>, the code and password included: this is a
test, with test values.
"""
import json
import os
import socket
import sys

path, script_path, log_path = sys.argv[1:4]
script = json.load(open(script_path))
try:
    os.unlink(path)
except FileNotFoundError:
    pass
server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
server.bind(path)
os.chmod(path, 0o666)
server.listen(16)
print("listening", flush=True)
while True:
    conn, _ = server.accept()
    with conn, conn.makefile("rwb") as f:
        answers = None
        while True:
            line = f.readline()
            if not line:
                break
            with open(log_path, "a") as log:
                log.write(line.decode())
            request = json.loads(line)
            if answers is None:
                key = f"{request['op']}:{request.get('username')}"
                answers = list(script.get(key, [
                    {"result": "refused", "reason": "unknown_user", "message": "Wrong name or password."}
                ]))
            if not answers:
                break
            answer = answers.pop(0)
            if answer is None:
                break
            f.write((json.dumps(answer) + "\n").encode())
            f.flush()
