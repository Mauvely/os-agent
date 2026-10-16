#!/usr/bin/env bash
# Build a throwaway signed Flatpak remote ("mauvely-s0") holding
#   - two tiny apps, com.mauvely.s0granted (carries --filesystem=xdg-run/$S0_SOCKNAME) and
#     com.mauvely.s0denied (carries nothing), each just the static s0client
#   - the browsers' policy extension refs, at the exact names/branches the Flathub
#     manifests declare (see RESULTS.md, spike 3):
#       org.mozilla.firefox.systemconfig                 branch stable   -> /app/etc/firefox
#       org.chromium.Chromium.Extension.s0               branch 1        -> merge policies/managed
#       org.chromium.Chromium.Policy.s0                  branch 1        -> merge policies/managed
# and add it to the throwaway user installation, signed by a throwaway GPG key. Idempotent.
#
# `flatpak build-init` is not used: it insists on the 700 MB SDK being installed, and these
# build dirs are two text files and a directory each, which is all build-init writes.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/env.sh"
. "$here/lib/remote.sh"

if [ ! -d "$GNUPGHOME" ]; then
  mkdir -m700 "$GNUPGHOME"
  gpg --batch --pinentry-mode loopback --passphrase '' \
      --quick-gen-key 'Mauvely S0 throwaway <s0@mauvely.invalid>' rsa3072 sign never
  gpg --export > "$S0_ROOT/s0.pub.gpg"
fi
[ -f "$repo/config" ] || ostree init --repo="$repo" --mode=archive-z2
rm -rf "$b"; mkdir -p "$b"

mkapp com.mauvely.s0granted "xdg-run/$S0_SOCKNAME"
mkapp com.mauvely.s0denied ""

mkext org.mozilla.firefox.systemconfig stable app/org.mozilla.firefox/$arch/stable \
      "$here/policies/firefox-policies.json:policies/policies.json"
mkext org.chromium.Chromium.Extension.s0 1 app/org.chromium.Chromium/$arch/stable \
      "$here/policies/chromium-extension-ref.json:policies/managed/s0-extension-ref.json"
mkext org.chromium.Chromium.Policy.s0 1 app/org.chromium.Chromium/$arch/stable \
      "$here/policies/chromium-policy-ref.json:policies/managed/s0-policy-ref.json"

update_repo
ostree refs --repo="$repo"

# (re)add the remote with the throwaway key; never trust it without the key
s0_forget_remote
s0flatpak remote-add --if-not-exists --gpg-import="$S0_ROOT/s0.pub.gpg" mauvely-s0 "file://$repo"
s0flatpak remotes --show-details
