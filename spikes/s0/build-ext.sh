#!/usr/bin/env bash
# Assemble the spike extension for each browser under $S0_HOME (visible inside both sandboxes
# at the same path), a throwaway signing key for a stable Chromium id, and an unsigned .xpi.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/env.sh"
out="$S0_HOME/s0ext"; rm -rf "$out"; mkdir -p "$out/firefox" "$out/chromium"
[ -f "$S0_ROOT/ext-key.pem" ] || openssl genrsa -out "$S0_ROOT/ext-key.pem" 2048 2>/dev/null
der="$(openssl rsa -in "$S0_ROOT/ext-key.pem" -pubout -outform DER 2>/dev/null | base64 -w0)"
# Chromium extension id: first 16 bytes of sha256(DER public key), hex digits 0-f mapped to a-p
id="$(openssl rsa -in "$S0_ROOT/ext-key.pem" -pubout -outform DER 2>/dev/null | sha256sum | head -c32 | tr '0-9a-f' 'a-p')"
echo "$id" > "$S0_ROOT/chromium-ext-id"
cp "$here/ext/background.js" "$out/firefox/"; cp "$here/ext/background.js" "$out/chromium/"
cp "$here/ext/manifest.firefox.json" "$out/firefox/manifest.json"
sed "s|@@KEY@@|$der|" "$here/ext/manifest.chromium.json" > "$out/chromium/manifest.json"
python3 -I - "$out" <<'PY'
import sys, zipfile, os
out = sys.argv[1]
with zipfile.ZipFile(os.path.join(out, "s0.xpi"), "w", zipfile.ZIP_DEFLATED) as z:
    for n in ("manifest.json", "background.js"):
        z.write(os.path.join(out, "firefox", n), n)
PY
echo "chromium extension id: $id"; ls -l "$out" "$out/firefox" "$out/chromium"
