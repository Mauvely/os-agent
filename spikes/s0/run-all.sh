#!/usr/bin/env bash
# Every spike, in order, from a clean throwaway state. Logs: evidence/logs/NN-name.txt.
# Needs only the two Flathub browsers (install.sh installs them into the throwaway user
# installation) and the tools in README.md. Takes about ten minutes.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/env.sh"
logs="$here/evidence/logs"; rm -rf "$logs"; mkdir -p "$logs"
n=0
step() {  # <name> <command...>   (env assignments before the call apply to the command)
  local name="$1"; shift; n=$((n + 1)); local f; f="$(printf '%s/%02d-%s.txt' "$logs" "$n" "$name")"
  printf '%02d %-26s ' "$n" "$name"
  "$@" > "$f" 2>&1; local rc=$?
  # progress bars and very long lines make logs unreadable; keep the substance
  sed -i -e '/%\|bytes\/s/d' -e 's/\x1b\[[0-9;]*[A-Za-z]//g' "$f"; cut -c1-1500 "$f" > "$f.tmp" && mv "$f.tmp" "$f"
  echo "exit $rc"
}
envstep() { local name="$1"; shift; step "$name" env "$@"; }

[[ "$S0_HOME" == */mauvely-s0/home ]] || { echo "unexpected S0_HOME $S0_HOME"; exit 1; }
rm -rf "$S0_HOME/.var"                              # fresh browser profiles, throwaway only

step install            "$here/install.sh"
step build-host         "$here/build-host.sh"
step build-ext          "$here/build-ext.sh"
step pack-crx           "$here/pack-crx.sh"
s0_forget_remote >/dev/null 2>&1
step make-remote        "$here/make-remote.sh"
step install-test-apps  bash -c ". '$here/env.sh'; s0flatpak install -y mauvely-s0 com.mauvely.s0granted com.mauvely.s0denied"

step s3-flathub-metadata "$here/spike3-metadata.sh"
# spike 2
step s2-socket          "$here/spike2-socket.sh"
step s2-exact-path      "$here/spike2-exact-path.sh"
# spike 1, no policy refs installed yet
step s1-firefox         "$here/spike1-firefox.sh"
step s1-chromium        "$here/spike1-chromium.sh"
envstep s1-firefox-broker  BROKER=1 "$here/spike1-firefox.sh"
envstep s1-chromium-broker BROKER=1 "$here/spike1-chromium.sh"
# spike 3: before, install the refs from the other remote, after
envstep s3-firefox-before  POLICY=1 PHASE=before "$here/spike1-firefox.sh"
envstep s3-chromium-before POLICY=1 PHASE=before "$here/spike1-chromium.sh"
step install-policy-refs bash -c ". '$here/env.sh'; s0flatpak install -y mauvely-s0 runtime/org.mozilla.firefox.systemconfig/x86_64/stable runtime/org.chromium.Chromium.Extension.s0/x86_64/1 runtime/org.chromium.Chromium.Policy.s0/x86_64/1; s0flatpak list --runtime --columns=application,branch,origin | grep mauvely-s0"
step s3-sandbox-view    "$here/spike3-sandbox-view.sh"
envstep s3-firefox-after   POLICY=1 PHASE=after "$here/spike1-firefox.sh"
envstep s3-chromium-after  POLICY=1 PHASE=after "$here/spike1-chromium.sh"
# beyond the pass lines
step make-remote-extra  "$here/make-remote-extra.sh"
step install-nmhost-ref bash -c ". '$here/env.sh'; s0flatpak install -y mauvely-s0 runtime/org.chromium.Chromium.NativeMessagingHost.s0/x86_64/1"
envstep x-chromium-nmhost-ref PHASE=nmhostref "$here/spike1-chromium.sh"
step install-force-ref  bash -c ". '$here/env.sh'; s0flatpak install -y mauvely-s0 runtime/org.chromium.Chromium.Extension.s0force/x86_64/1"
envstep x-chromium-forcelist FORCE=1 "$here/spike1-chromium.sh"
step unused-and-pins    bash -c ". '$here/env.sh'; echo n | s0flatpak uninstall --unused"
step update-firefox-policy-ref bash -c ". '$here/env.sh'; s0flatpak update -y org.mozilla.firefox.systemconfig; s0flatpak info --show-commit org.mozilla.firefox.systemconfig"
envstep x-firefox-forced-xpi NOADDON=1 PHASE=v2 "$here/spike1-firefox.sh"
envstep x-firefox-host-in-ref HOSTREF=1 PHASE=v2 "$here/spike1-firefox.sh"
# one Chromium ref for everything; the http-served forcelist ref and the separate host ref go first
step swap-to-single-ref bash -c ". '$here/env.sh'; s0flatpak uninstall -y org.chromium.Chromium.Extension.s0force org.chromium.Chromium.NativeMessagingHost.s0; s0flatpak install -y mauvely-s0 runtime/org.chromium.Chromium.Extension.s0all/x86_64/1"
envstep x-chromium-single-ref SINGLE=1 "$here/spike1-chromium.sh"

"$here/cleanup.sh" > "$logs/99-cleanup.txt" 2>&1; echo "cleanup exit $?"
