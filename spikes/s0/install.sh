#!/usr/bin/env bash
# Install both Flathub browsers into the throwaway user installation.
set -euo pipefail
. "$(dirname "$0")/env.sh"
s0flatpak remotes --show-details
s0flatpak install -y flathub org.mozilla.firefox org.chromium.Chromium || echo "(install returned non-zero; fine if they were already installed)"
s0flatpak list
