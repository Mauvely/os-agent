#!/usr/bin/env bash
# Spike 2: a socket under $XDG_RUNTIME_DIR/$S0_SOCKNAME is reachable from a Flatpak granted
# --filesystem=xdg-run/$S0_SOCKNAME and not from one without it; the server identifies each
# caller from SO_PEERCRED -> /proc/<pid>/root/.flatpak-info.
# Needs: ./install.sh, ./build-host.sh, ./make-remote.sh and both test apps installed from it.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/env.sh"
. "$here/lib/gui.sh"
s0_start_bus                       # a private, empty session bus: flatpak never sees the user's
export DBUS_SESSION_BUS_ADDRESS="$S0_DBUS"
mkdir -p "$S0_ROOT/logs"
log="$S0_ROOT/logs/broker.jsonl"; : > "$log"
sock="$S0_SOCKDIR/broker"
client="$S0_ROOT/bin/s0client"

python3 -I "$here/broker/broker_spike.py" --dir "$S0_SOCKDIR" --log "$log" > "$S0_ROOT/logs/broker.out" 2>&1 &
srv=$!
cleanup() { kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null; rm -f "$sock"; rmdir "$S0_SOCKDIR" 2>/dev/null; s0_stop_bus; }
trap cleanup EXIT
for _ in $(seq 50); do [ -S "$sock" ] && break; sleep 0.1; done
[ -S "$sock" ] || { echo "server did not start"; cat "$S0_ROOT/logs/broker.out"; exit 1; }
ls -ld "$S0_SOCKDIR"; ls -l "$sock"

# $XDG_RUNTIME_DIR inside a sandbox is /run/user/<uid>, the same string as outside
insock="/run/user/$(id -u)/$S0_SOCKNAME/broker"
# the binary lives outside the throwaway HOME; expose just that directory, read-only
bin="--filesystem=$S0_ROOT/bin:ro"
run() { echo; echo "### $*"; "$@"; echo "[exit $?]"; }

run "$client" "$sock"                                                                  # host caller
run s0flatpak run com.mauvely.s0granted "$insock"                                       # finish-args grant
run s0flatpak run com.mauvely.s0denied "$insock"                                        # none
for app in org.mozilla.firefox org.chromium.Chromium; do
  run s0flatpak run --no-a11y-bus --no-documents-portal $bin --command="$client" $app "$insock"
  run s0flatpak run --no-a11y-bus --no-documents-portal $bin --filesystem=xdg-run/$S0_SOCKNAME --command="$client" $app "$insock"
  run s0flatpak run --no-a11y-bus --no-documents-portal $bin --filesystem=xdg-run/$S0_SOCKNAME:ro --command="$client" $app "$insock"
  run s0flatpak run --no-a11y-bus --no-documents-portal $bin --filesystem=xdg-run/$S0_SOCKNAME:create --command="$client" $app "$insock"
done
# the grant as the agent will apply it: a persistent override on the installation
echo; echo "### persistent override (flatpak override --user --filesystem=xdg-run/$S0_SOCKNAME org.mozilla.firefox)"
s0flatpak override --filesystem="xdg-run/$S0_SOCKNAME" org.mozilla.firefox
cat "$FLATPAK_USER_DIR/overrides/org.mozilla.firefox"
run s0flatpak run --no-a11y-bus --no-documents-portal $bin --command="$client" org.mozilla.firefox "$insock"
s0flatpak override --reset org.mozilla.firefox
run s0flatpak run --no-a11y-bus --no-documents-portal $bin --command="$client" org.mozilla.firefox "$insock"

# Broader grants do not reach it: flatpak keeps /run/user/<uid> out of host, host-os and home.
# Only xdg-run/<name> or an explicit /run/user/<uid>/... path does, so the identity check at the
# broker, not reachability alone, is what keeps other apps out.
uid="$(id -u)"
for fs in --filesystem=host --filesystem=host-os --filesystem=home --filesystem="/run/user/$uid/$S0_SOCKNAME"; do
  echo; echo "### com.mauvely.s0denied with $fs"
  s0flatpak run --no-a11y-bus --no-documents-portal "$fs" --command=s0client com.mauvely.s0denied "$insock"
  s0flatpak run --no-a11y-bus --no-documents-portal "$fs" --command=s0client com.mauvely.s0denied "/run/host$insock"
done

echo; echo "### server log (one JSON object per accepted connection), flatpak_info_raw trimmed to the first caller"
python3 -I - "$log" <<'PY'
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1])]
for i, r in enumerate(rows):
    raw = r.pop("flatpak_info_raw", None)
    r.pop("flatpak_info_sections", None) if i else None
    print(json.dumps(r, indent=1) if i < 2 else json.dumps(r))
    if raw and i == 1:
        print("---- raw /.flatpak-info of caller #2 ----"); print(raw)
PY
