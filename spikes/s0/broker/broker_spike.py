#!/usr/bin/env python3
"""Spike S0 broker stand-in.

Listens on a unix socket in a 0700 directory and, for every connection, identifies the peer
the way the real broker will:

    SO_PEERCRED            -> pid, uid, gid  (the pid is translated into *our* pid namespace)
    SO_PEERPIDFD           -> a pidfd for the same process, so the pid cannot be reused under us
    /proc/<pid>/root/.flatpak-info  -> present iff the peer is inside a Flatpak sandbox

It speaks one line of Suite's broker protocol ({"v":1,"op":"token","client":"<key>"}) and answers
one line of JSON that says what it saw. Everything it saw is also appended to --log.
"""
import argparse, configparser, io, json, os, socket, socketserver, struct, sys, time

SO_PEERPIDFD = getattr(socket, "SO_PEERPIDFD", 77)


def pidfd_pid(fd):
    """The pid a pidfd refers to, from /proc/self/fdinfo (None if the process is gone)."""
    try:
        for line in open(f"/proc/self/fdinfo/{fd}"):
            if line.startswith("Pid:"):
                v = int(line.split()[1])
                return v if v > 0 else None
    except OSError:
        return None


def read_flatpak_info(pid):
    """Return (text, error). Reads through /proc/<pid>/root, i.e. the peer's own mount namespace."""
    try:
        with open(f"/proc/{pid}/root/.flatpak-info", "r", encoding="utf-8") as f:
            return f.read(), None
    except FileNotFoundError:
        return None, "ENOENT"
    except PermissionError:
        return None, "EACCES"
    except OSError as e:
        return None, f"{type(e).__name__}: {e}"


def parse_keyfile(text):
    cp = configparser.RawConfigParser(interpolation=None, delimiters=("=",), strict=False)
    cp.optionxform = str  # keyfile keys are case-sensitive
    cp.read_file(io.StringIO(text))
    return {s: dict(cp.items(s)) for s in cp.sections()}


def classify_installation(app_path):
    """.flatpak-info does not name the installation; the path of the deploy does."""
    if not app_path:
        return None
    return "system" if app_path.startswith("/var/lib/flatpak/") else "not-system"


def deploy_origin(app_path):
    """The origin *remote name* from <commit>/deploy, a GVariant (ssasta{sv}): origin, commit, ...
    The name is whatever the remote was called when it was added; it is not a trust anchor."""
    try:
        import gi
        from gi.repository import GLib
        data = open(os.path.join(os.path.dirname(app_path), "deploy"), "rb").read()
        v = GLib.Variant.new_from_bytes(GLib.VariantType("(ssasta{sv})"), GLib.Bytes.new(data), False)
        return v.get_child_value(0).get_string()
    except Exception as e:  # no gi, or an unreadable/odd deploy
        return f"<{e.__class__.__name__}>"


def identify(conn):
    cred = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
    pid, uid, gid = struct.unpack("3i", cred)
    out = {"pid": pid, "uid": uid, "gid": gid}
    try:
        pfd = conn.getsockopt(socket.SOL_SOCKET, SO_PEERPIDFD, struct.calcsize("i"))
        pfd = struct.unpack("i", pfd)[0]
        out["peerpidfd_pid"] = pidfd_pid(pfd)
        # a pidfd survives pid reuse: read what we need, then check the process is still the one
        info, err = read_flatpak_info(pid)
        out["peerpidfd_pid_after"] = pidfd_pid(pfd)
        os.close(pfd)
    except OSError as e:
        out["peerpidfd_error"] = f"{e.__class__.__name__}: {e}"
        info, err = read_flatpak_info(pid)
    for k, p in (("exe", "exe"), ("comm", "comm"), ("cgroup", "cgroup")):
        try:
            out[k] = os.readlink(f"/proc/{pid}/{p}") if k == "exe" else open(f"/proc/{pid}/{p}").read().strip()
        except OSError as e:
            out[k] = f"<{e.__class__.__name__}>"
    if info is None:
        out["kind"] = "host" if err == "ENOENT" else "unknown"
        out["flatpak_info_error"] = err
        return out
    out["kind"] = "flatpak"
    parsed = parse_keyfile(info)
    out["flatpak_info_sections"] = {s: sorted(v) for s, v in parsed.items()}
    app = parsed.get("Application", {})
    inst = parsed.get("Instance", {})
    out["app"] = app.get("name")
    out["runtime"] = app.get("runtime")
    out["app_path"] = inst.get("app-path")
    out["app_commit"] = inst.get("app-commit")
    out["branch"] = inst.get("branch")
    out["arch"] = inst.get("arch")
    out["instance_id"] = inst.get("instance-id")
    out["installation"] = classify_installation(inst.get("app-path"))
    out["origin"] = deploy_origin(inst["app-path"]) if inst.get("app-path") else None
    out["app_extensions"] = inst.get("app-extensions")
    # the S2 rule for a Mauvely app: a system install, under its own id
    out["mauvely_system_app"] = bool(
        out["app"] and out["app"].startswith("com.mauvely.")
        and (inst.get("app-path") or "").startswith(f"/var/lib/flatpak/app/{out['app']}/"))
    out["filesystems"] = parsed.get("Context", {}).get("filesystems")
    out["flatpak_info_raw"] = info
    return out


class H(socketserver.StreamRequestHandler):
    def handle(self):
        who = identify(self.request)
        self.request.settimeout(5)
        try:
            line = self.rfile.readline(4096).decode("utf-8", "replace").strip()
        except OSError:
            line = ""
        who["request"] = line
        who["time"] = time.strftime("%H:%M:%S")
        with open(self.server.logpath, "a") as f:
            f.write(json.dumps(who) + "\n")
        brief = {k: who.get(k) for k in ("kind", "pid", "uid", "app", "app_path", "installation", "origin", "mauvely_system_app", "branch", "instance_id", "flatpak_info_error")}
        self.wfile.write((json.dumps({"v": 1, "ok": True, "you": brief}) + "\n").encode())


class S(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", required=True, help="directory to hold the socket (made 0700)")
    ap.add_argument("--log", required=True)
    a = ap.parse_args()
    os.makedirs(a.dir, mode=0o700, exist_ok=True)
    os.chmod(a.dir, 0o700)
    path = os.path.join(a.dir, "broker")
    if os.path.exists(path):
        os.unlink(path)
    srv = S(path, H)
    srv.logpath = a.log
    os.chmod(path, 0o600)
    print("listening", path, flush=True)
    try:
        srv.serve_forever()
    finally:
        try:
            os.unlink(path)
        except OSError:
            pass
