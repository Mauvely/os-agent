#!/usr/bin/env bash
# Spike 1, Chromium: a native messaging host placed in the browser's own ~/.var/app directory is
# launched by Flathub's org.chromium.Chromium, with no portal, and an extension talks to it.
# The extension is loaded unpacked (--load-extension). Variants as for spike1-firefox.sh:
#   BROKER=1   also run the broker stand-in and grant xdg-run/$S0_SOCKNAME
#   POLICY=1   (spike 3) show chrome://policy; expects the policy extension refs to be installed
#   SINGLE=1   like FORCE=1 but from the one ref org.chromium.Chromium.Extension.s0all: the CRX is
#              fetched from file:///app/... (no web server) and the profile is wiped first
#   FORCE=1    (spike 3, S4's install path) no --load-extension: the extension arrives by
#              ExtensionInstallForcelist from org.chromium.Chromium.Extension.s0force, as a CRX
#              served on 127.0.0.1:18100 (run pack-crx.sh first). Implies POLICY=1
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/lib/gui.sh"
app=org.chromium.Chromium
appdir="$S0_HOME/.var/app/$app"
nmdir="$appdir/config/chromium/NativeMessagingHosts"
CPORT=19222
extid="$(cat "$S0_ROOT/chromium-ext-id")"
shots="$here/evidence"; mkdir -p "$shots"
[ -n "${SINGLE:-}" ] && FORCE=1
[ -n "${FORCE:-}" ] && POLICY=1
tag="chromium${SINGLE:+-single}${FORCE:+-force}${BROKER:+-broker}${POLICY:+-policy}${PHASE:+-$PHASE}"

cleanup() {
  s0flatpak kill $app 2>/dev/null
  s0_hsway stop >/dev/null 2>&1
  s0_stop_collector; s0_stop_bus
  [ -n "${web:-}" ] && kill "$web" 2>/dev/null
  [ -n "${srv:-}" ] && { kill "$srv" 2>/dev/null; rm -f "$S0_SOCKDIR/broker"; rmdir "$S0_SOCKDIR" 2>/dev/null; }
}
trap cleanup EXIT

mkdir -p "$nmdir"
cp "$S0_ROOT/bin/s0host" "$nmdir/s0host"
cat > "$nmdir/com.mauvely.s0.json" <<JSON
{
  "name": "com.mauvely.s0",
  "description": "Mauvely S0 spike host",
  "path": "$nmdir/s0host",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$extid/"]
}
JSON
echo "## host side: $nmdir"; ls -l "$nmdir"; cat "$nmdir/com.mauvely.s0.json"

PORTAL=1 s0_start_bus; s0_start_collector
s0_hsway start 1280x800 >/dev/null
extra=()
if [ -n "${BROKER:-}" ]; then
  python3 -I "$here/broker/broker_spike.py" --dir "$S0_SOCKDIR" --log "$S0_ROOT/logs/broker-$tag.jsonl" > "$S0_ROOT/logs/broker.out" 2>&1 &
  srv=$!; : > "$S0_ROOT/logs/broker-$tag.jsonl"
  for _ in $(seq 50); do [ -S "$S0_SOCKDIR/broker" ] && break; sleep 0.1; done
  extra+=("--filesystem=xdg-run/$S0_SOCKNAME")
fi

if [ -n "${FORCE:-}" ]; then
  if [ -n "${SINGLE:-}" ]; then
    rm -rf "$appdir/config/chromium/Default" "$appdir/config/chromium/Local State"   # nothing cached: install from scratch
  else
    python3 -I -m http.server 18100 --bind 127.0.0.1 --directory "$S0_ROOT/crx" > "$S0_ROOT/logs/crx-server.log" 2>&1 &
    web=$!
  fi
  loadflag=(); echo; echo "## launching Chromium in hsway (extension from ExtensionInstallForcelist)"
else
  loadflag=(--load-extension="$S0_HOME/s0ext/chromium"); echo; echo "## launching Chromium in hsway (unpacked extension $extid)"
fi
s0_gui_run chromium "${extra[@]}" $app --no-first-run --no-default-browser-check --password-store=basic \
  --ozone-platform=wayland --remote-debugging-port=$CPORT "${loadflag[@]}" about:blank
wait_s=90; [ -n "${FORCE:-}" ] && wait_s=150     # a policy install takes longer than a flag
s0_wait_report done chromium "$wait_s" || { echo "!! no 'done' report within $wait_s s"; tail -5 /run/user/1000/hsway/s0/logs/env.log; }
sleep 1

if [ -n "${POLICY:-}" ]; then
  echo; echo "## chrome://policy (via CDP, deep text of the page)"
  tid="$(node "$here/lib/cdp.mjs" $CPORT open chrome://policy)"
  sleep 3
  node "$here/lib/cdp.mjs" $CPORT eval "$tid" '(() => { const out = []; const walk = (n) => { if (n.shadowRoot) walk(n.shadowRoot); for (const c of n.childNodes) { if (c.nodeType === 3) { const t = c.textContent.trim(); if (t) out.push(t); } else if (c.nodeType === 1) walk(c); } }; walk(document.body); return out.join(" | "); })()' \
    > "$S0_ROOT/logs/chrome-policy-text.txt"
  rows="$here/evidence/chrome-policy-rows-$tag.txt"
  grep -oE '(HomepageLocation|ShowHomeButton|PasswordManagerEnabled|BookmarkBarEnabled|ExtensionInstallForcelist)[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*\|[^|]*' "$S0_ROOT/logs/chrome-policy-text.txt" | sed 's/\\"/"/g' | tee "$rows"
  sleep 1
fi
s0_hsway windows
[ -n "${POLICY:-}" ] && s0_hsway shot "$shots/$tag.png"      # a screenshot of a blank tab proves nothing

echo; echo "## collector log (host replies shortened)"
python3 -I - "$S0_COLLECTOR_LOG" <<'PY'
import json, sys
for l in open(sys.argv[1]):
    try: o = json.loads(l)
    except Exception: print("RAW", l); continue
    d = o["data"]
    print(f'[{o["browser"]}] {o["step"]}: {json.dumps(d)[:1800]}')
PY
[ -n "${BROKER:-}" ] && { echo "## broker log"; python3 -I -c '
import sys, json
for l in open(sys.argv[1]):
    o = json.loads(l); o.pop("flatpak_info_raw", None); o.pop("flatpak_info_sections", None); print(json.dumps(o))' "$S0_ROOT/logs/broker-$tag.jsonl"; }
exit 0
