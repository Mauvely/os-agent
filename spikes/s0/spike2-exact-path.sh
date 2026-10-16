#!/usr/bin/env bash
# Spike 2 again, on the exact production path $XDG_RUNTIME_DIR/mauvely/broker with
# --filesystem=xdg-run/mauvely. Refuses to run if that directory already exists (it is not ours
# then), and removes it afterwards.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
export S0_SOCKNAME=mauvely
. "$here/env.sh"; . "$here/lib/gui.sh"
[ -e "$S0_SOCKDIR" ] && { echo "refusing: $S0_SOCKDIR exists"; exit 1; }
s0_start_bus; export DBUS_SESSION_BUS_ADDRESS="$S0_DBUS"
mkdir -p "$S0_ROOT/logs"; log="$S0_ROOT/logs/broker-exact.jsonl"; : > "$log"
python3 -I "$here/broker/broker_spike.py" --dir "$S0_SOCKDIR" --log "$log" > "$S0_ROOT/logs/broker.out" 2>&1 &
srv=$!
cleanup() { kill "$srv" 2>/dev/null; wait "$srv" 2>/dev/null; rm -f "$S0_SOCKDIR/broker"; rmdir "$S0_SOCKDIR" 2>/dev/null; s0_stop_bus; }
trap cleanup EXIT
for _ in $(seq 50); do [ -S "$S0_SOCKDIR/broker" ] && break; sleep 0.1; done
ls -ld "$S0_SOCKDIR"
client="$S0_ROOT/bin/s0client"; insock="/run/user/$(id -u)/mauvely/broker"; bin="--filesystem=$S0_ROOT/bin:ro"
for app in com.mauvely.s0denied org.mozilla.firefox org.chromium.Chromium; do
  cmd=(--command="$client"); [ $app = com.mauvely.s0denied ] && cmd=(--command=s0client)
  echo "### $app, no grant";           s0flatpak run --no-a11y-bus --no-documents-portal $bin "${cmd[@]}" $app "$insock"
  echo "### $app, xdg-run/mauvely";    s0flatpak run --no-a11y-bus --no-documents-portal $bin --filesystem=xdg-run/mauvely "${cmd[@]}" $app "$insock"
  echo "### $app, xdg-run/mauvely:ro"; s0flatpak run --no-a11y-bus --no-documents-portal $bin --filesystem=xdg-run/mauvely:ro "${cmd[@]}" $app "$insock"
done
echo "### host"; "$client" "$S0_SOCKDIR/broker"
