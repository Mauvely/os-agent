#!/usr/bin/env bash
# Pack the Chromium build of the spike extension into a CRX3 with Chromium's own packer, and
# write the update manifest ExtensionInstallForcelist needs. Output: $S0_ROOT/crx/{s0.crx,update.xml}
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/lib/gui.sh"
id="$(cat "$S0_ROOT/chromium-ext-id")"
pk="$S0_HOME/s0pack"; rm -rf "$pk"; mkdir -p "$pk/src" "$S0_ROOT/crx"
cp "$here/ext/background.js" "$pk/src/"
sed '/"key": "@@KEY@@",/d' "$here/ext/manifest.chromium.json" > "$pk/src/manifest.json"   # the key signs the CRX instead
cp "$S0_ROOT/ext-key.pem" "$pk/key.pem"
PORTAL=1 s0_start_bus
trap 's0_hsway stop >/dev/null 2>&1; s0_stop_bus' EXIT
s0_hsway start 1280x800 >/dev/null
HSWAY_NAME=s0 "$S0_HSWAY" exec env HOME="$S0_HOME" FLATPAK_USER_DIR="$FLATPAK_USER_DIR" DBUS_SESSION_BUS_ADDRESS="$S0_DBUS" \
  flatpak --user run --no-a11y-bus --no-documents-portal org.chromium.Chromium --no-first-run --password-store=basic \
  --ozone-platform=wayland --pack-extension="$pk/src" --pack-extension-key="$pk/key.pem" >/dev/null 2>&1 || true
cp "$pk/src.crx" "$S0_ROOT/crx/s0.crx"
cat > "$S0_ROOT/crx/update.xml" <<XML
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='$id'>
    <updatecheck codebase='http://127.0.0.1:18100/s0.crx' version='0.0.1' />
  </app>
</gupdate>
XML
ls -l "$S0_ROOT/crx"; head -c 4 "$S0_ROOT/crx/s0.crx"; echo
