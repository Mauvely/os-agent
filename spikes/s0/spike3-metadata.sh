#!/usr/bin/env bash
# Spike 3, step 0: the extension points the two Flathub manifests declare, as flatpak shows them.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/env.sh"
for app in org.mozilla.firefox org.chromium.Chromium; do
  echo "################ $app  ($(s0flatpak info "$app" | grep -E '^\s*(Version|Commit|Origin):' | tr -s ' ' | tr '\n' ' '))"
  s0flatpak info --show-metadata "$app" | awk '/^\[/ {keep = ($0 ~ /^\[Extension / || $0 ~ /^\[Application\]/ || $0 ~ /^\[Context\]/)} keep'
done
