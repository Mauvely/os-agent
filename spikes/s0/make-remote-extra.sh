#!/usr/bin/env bash
# Extra refs, published after make-remote.sh (do not rebuild the base refs):
#   org.chromium.Chromium.NativeMessagingHost.s0  the host + its manifest delivered as a ref
#                                                 instead of copied into ~/.var/app
#   org.chromium.Chromium.Extension.s0force       ExtensionInstallForcelist -> the self-hosted CRX
#   org.mozilla.firefox.systemconfig (a second commit) adds ExtensionSettings force_installed
#                                                 for an unsigned XPI (update path + expected refusal)
#                                                 and the host binary at /app/etc/firefox/mauvely/s0host
#   org.chromium.Chromium.Extension.s0all         ONE ref carrying policy (forcelist with a file://
#                                                 update manifest), CRX, host manifest and host:
#                                                 needs no web server and no per-user copy
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/env.sh"
. "$here/lib/remote.sh"
id="$(cat "$S0_ROOT/chromium-ext-id")"
x="$S0_ROOT/extra"; rm -rf "$x"; mkdir -p "$x"

# the host's manifest, with the path it has inside /app once the ref is mounted
cat > "$x/com.mauvely.s0ext.json" <<JSON
{
  "name": "com.mauvely.s0ext",
  "description": "Mauvely S0 spike host, delivered by a NativeMessagingHost extension ref",
  "path": "/app/chromium/native-messaging-hosts/s0/s0host",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$id/"]
}
JSON
mkext org.chromium.Chromium.NativeMessagingHost.s0 1 app/org.chromium.Chromium/$arch/stable \
      "$x/com.mauvely.s0ext.json:native-messaging-hosts/com.mauvely.s0ext.json" \
      "$S0_ROOT/bin/s0host:s0host"

printf '{ "ExtensionInstallForcelist": ["%s;http://127.0.0.1:18100/update.xml"] }\n' "$id" > "$x/forcelist.json"
mkext org.chromium.Chromium.Extension.s0force 1 app/org.chromium.Chromium/$arch/stable \
      "$x/forcelist.json:policies/managed/s0-forcelist.json"

# Firefox: the same policy ref, one commit later
python3 -I - "$here/policies/firefox-policies.json" "$S0_HOME/s0ext/s0.xpi" "$x/firefox-policies-v2.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
p["policies"]["ExtensionSettings"] = {"s0@mauvely.invalid": {"installation_mode": "force_installed", "install_url": "file://" + sys.argv[2]}}
json.dump(p, open(sys.argv[3], "w"), indent=2)
PY
mkext org.mozilla.firefox.systemconfig stable app/org.mozilla.firefox/$arch/stable \
      "$x/firefox-policies-v2.json:policies/policies.json" \
      "$S0_ROOT/bin/s0host:mauvely/s0host"

# Chromium: everything in one Extension.* ref (its merge-dirs cover policies/managed and
# native-messaging-hosts), mounted at /app/chromium/extensions/s0all
a="$x/s0all"; mkdir -p "$a"; root=/app/chromium/extensions/s0all
printf '{ "ExtensionInstallForcelist": ["%s;file://%s/update.xml"] }\n' "$id" "$root" > "$a/s0-all.json"
cat > "$a/com.mauvely.s0all.json" <<JSON
{
  "name": "com.mauvely.s0all",
  "description": "Mauvely S0 spike host, from the single Extension ref",
  "path": "$root/s0host",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$id/"]
}
JSON
cat > "$a/update.xml" <<XML
<?xml version='1.0' encoding='UTF-8'?>
<gupdate xmlns='http://www.google.com/update2/response' protocol='2.0'>
  <app appid='$id'><updatecheck codebase='file://$root/s0.crx' version='0.0.1' /></app>
</gupdate>
XML
mkext org.chromium.Chromium.Extension.s0all 1 app/org.chromium.Chromium/$arch/stable \
      "$a/s0-all.json:policies/managed/s0-all.json" \
      "$a/com.mauvely.s0all.json:native-messaging-hosts/com.mauvely.s0all.json" \
      "$S0_ROOT/bin/s0host:s0host" "$S0_ROOT/crx/s0.crx:s0.crx" "$a/update.xml:update.xml"
update_repo
ostree refs --repo="$repo"
