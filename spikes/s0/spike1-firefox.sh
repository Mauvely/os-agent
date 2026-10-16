#!/usr/bin/env bash
# Spike 1, Firefox: a native messaging host placed in the browser's own ~/.var/app directory is
# launched by Flathub's org.mozilla.firefox, with no portal, and an extension talks to it.
#   BROKER=1  also run the broker stand-in and grant xdg-run/$S0_SOCKNAME, so the host can reach it
#   POLICY=1  (spike 3) run with org.mozilla.firefox.systemconfig installed and print the policy state
#   HOSTREF=1 the manifest's "path" points at the host shipped inside the systemconfig ref
#             (/app/etc/firefox/mauvely/s0host), so only the manifest lives in ~/.var/app
#   NOADDON=1 do not install the temporary add-on; used with a policy that force-installs the
#             (unsigned) XPI, to record what a release Firefox does with it. Implies POLICY=1
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/lib/gui.sh"
app=org.mozilla.firefox
appdir="$S0_HOME/.var/app/$app"
nmdir="$appdir/.mozilla/native-messaging-hosts"
profile="$appdir/data/s0profile"
MPORT=28282
shots="$here/evidence"; mkdir -p "$shots"
[ -n "${NOADDON:-}" ] && POLICY=1
tag="firefox${HOSTREF:+-hostref}${NOADDON:+-noaddon}${FORCE:+-force}${BROKER:+-broker}${POLICY:+-policy}${PHASE:+-$PHASE}"

cleanup() {
  python3 -I "$here/lib/marionette.py" $MPORT quit >/dev/null 2>&1
  sleep 1; s0flatpak kill $app 2>/dev/null
  s0_hsway stop >/dev/null 2>&1
  s0_stop_collector; s0_stop_bus
  [ -n "${srv:-}" ] && { kill "$srv" 2>/dev/null; rm -f "$S0_SOCKDIR/broker"; rmdir "$S0_SOCKDIR" 2>/dev/null; }
}
trap cleanup EXIT

# 1. the host and its manifest, in the browser's own persisted directory. Nothing else.
mkdir -p "$nmdir" "$profile"
hostpath="$nmdir/s0host"
if [ -n "${HOSTREF:-}" ]; then hostpath=/app/etc/firefox/mauvely/s0host; else cp "$S0_ROOT/bin/s0host" "$nmdir/s0host"; fi
cat > "$nmdir/com.mauvely.s0.json" <<JSON
{
  "name": "com.mauvely.s0",
  "description": "Mauvely S0 spike host",
  "path": "$hostpath",
  "type": "stdio",
  "allowed_extensions": ["s0@mauvely.invalid"]
}
JSON
cat > "$profile/user.js" <<JS
user_pref("marionette.port", $MPORT);
user_pref("browser.shell.checkDefaultBrowser", false);
user_pref("browser.startup.homepage_override.mstone", "ignore");
user_pref("startup.homepage_welcome_url", "");
user_pref("startup.homepage_welcome_url.additional", "");
user_pref("browser.aboutwelcome.enabled", false);
user_pref("datareporting.policy.dataSubmissionEnabled", false);
user_pref("toolkit.telemetry.reportingpolicy.firstRun", false);
user_pref("browser.tabs.warnOnClose", false);
JS
echo "## host side: $nmdir"; ls -l "$nmdir"; cat "$nmdir/com.mauvely.s0.json"

echo; echo "## what the sandbox sees of that directory (no portal, no override beyond the test extension dir):"
s0flatpak run --no-a11y-bus --no-documents-portal --command=sh $app -c \
  "echo HOME=\$HOME; ls -l ~/.var/app/$app/.mozilla/native-messaging-hosts/ ~/.mozilla/native-messaging-hosts/; mount 2>/dev/null | head -0; grep -c noexec /proc/self/mountinfo; findmnt -no OPTIONS -T ~/.var/app/$app/.mozilla/native-messaging-hosts 2>/dev/null || awk '{print \$5, \$6}' /proc/self/mountinfo | grep -E 'native|\.var|mozilla' | head" 2>&1 | head -30

s0_start_bus; s0_start_collector
s0_hsway start 1280x800 >/dev/null
extra=("--filesystem=$S0_HOME/s0ext:ro")
if [ -n "${BROKER:-}" ]; then
  python3 -I "$here/broker/broker_spike.py" --dir "$S0_SOCKDIR" --log "$S0_ROOT/logs/broker-$tag.jsonl" > "$S0_ROOT/logs/broker.out" 2>&1 &
  srv=$!; : > "$S0_ROOT/logs/broker-$tag.jsonl"
  for _ in $(seq 50); do [ -S "$S0_SOCKDIR/broker" ] && break; sleep 0.1; done
  extra+=("--filesystem=xdg-run/$S0_SOCKNAME")
fi

echo; echo "## launching Firefox in hsway"
s0_gui_run firefox "${extra[@]}" $app --no-remote --marionette -remote-allow-system-access --profile "$profile" about:blank
if [ -z "${NOADDON:-}" ]; then
  echo "## installing the temporary (unsigned) add-on over Marionette"
  python3 -I "$here/lib/marionette.py" $MPORT install-addon "$S0_HOME/s0ext/s0.xpi"
  s0_wait_report done firefox 60 || echo "!! no 'done' report within 60 s"
else
  echo "## no temporary add-on; waiting 25 s for the policy to try the force install"
  python3 -I "$here/lib/marionette.py" $MPORT chrome-js 'return 1' >/dev/null; sleep 25
  python3 -I "$here/lib/marionette.py" $MPORT chrome-js '
    return (async () => {
      const {AddonManager} = ChromeUtils.importESModule("resource://gre/modules/AddonManager.sys.mjs");
      const a = await AddonManager.getAddonByID("s0@mauvely.invalid");
      const msgs = Services.console.getMessageArray().map(m => m.message)
        .filter(m => /s0@mauvely|xpinstall|signature|not verified|corrupt|ExtensionSettings|force/i.test(m)).slice(-8);
      return {addon: a ? {id: a.id, active: a.isActive, signedState: a.signedState} : null, msgs};
    })();'
fi
sleep 1

if [ -n "${POLICY:-}" ]; then
  echo; echo "## policy state (chrome context)"
  python3 -I "$here/lib/marionette.py" $MPORT chrome-js '
    return {status: Services.policies.status,
            active: Services.policies.getActivePolicies(),
            homepagePref: Services.prefs.getStringPref("browser.startup.homepage", null),
            homepageLocked: Services.prefs.prefIsLocked("browser.startup.homepage"),
            telemetryPref: Services.prefs.getBoolPref("datareporting.policy.dataSubmissionEnabled", null)};'
  # about:policies is a privileged page: WebDriver navigation refuses it, a chrome-context tab does not
  python3 -I "$here/lib/marionette.py" $MPORT chrome-js '
    const tab = window.gBrowser.addTab("about:policies", {triggeringPrincipal: Services.scriptSecurityManager.getSystemPrincipal()});
    window.gBrowser.selectedTab = tab; return "opened about:policies";' >/dev/null
  sleep 3
fi
s0_hsway windows
[ -n "${POLICY:-}" ] && s0_hsway shot "$shots/$tag.png"      # a screenshot of a blank tab proves nothing

echo; echo "## collector log"
python3 -I - "$S0_COLLECTOR_LOG" <<'PY'
import json, sys
for l in open(sys.argv[1]):
    try: o = json.loads(l)
    except Exception: print("RAW", l); continue
    print(f'[{o["browser"]}] {o["step"]}: {json.dumps(o["data"], indent=1)}')
PY
[ -n "${BROKER:-}" ] && { echo "## broker log"; cat "$S0_ROOT/logs/broker-$tag.jsonl" | python3 -I -c '
import sys, json
for l in sys.stdin:
    o = json.loads(l); o.pop("flatpak_info_raw", None); o.pop("flatpak_info_sections", None); print(json.dumps(o))'; }
exit 0
