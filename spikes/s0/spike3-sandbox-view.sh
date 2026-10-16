#!/usr/bin/env bash
# Spike 3: what each browser's sandbox sees once the refs from the other remote are installed
# (the merged directories, and what /.flatpak-info says about the mounted extensions).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/lib/gui.sh"
s0_start_bus; export DBUS_SESSION_BUS_ADDRESS="$S0_DBUS"; trap s0_stop_bus EXIT
run() { s0flatpak run --no-a11y-bus --no-documents-portal --command=sh "$1" -c "$2" 2>&1; }
echo "################ org.mozilla.firefox"
run org.mozilla.firefox 'ls -l /app/etc/firefox /app/etc/firefox/policies; echo "app-extensions:"; sed -n "s/^app-extensions=//p" /.flatpak-info | tr ";" "\n"'
echo; echo "################ org.chromium.Chromium"
run org.chromium.Chromium 'for d in /app/chromium/extensions/policies/managed /app/chromium/policies/policies/managed /app/chromium/extensions /app/chromium/policies; do echo "-- $d"; ls -l $d; done; echo "app-extensions:"; sed -n "s/^app-extensions=//p" /.flatpak-info | tr ";" "\n"'
echo; echo "## installed from the throwaway remote:"; s0flatpak list --columns=ref,origin,installation | grep mauvely-s0
