#!/usr/bin/env bash
# Remove what the spikes added: the test remote and everything installed from it, leftovers in
# $XDG_RUNTIME_DIR, the private bus and nested sway. The two Flathub browsers and their runtime
# stay in the throwaway installation (re-running is much faster); remove them with
#   flatpak --user uninstall org.mozilla.firefox org.chromium.Chromium     (FLATPAK_USER_DIR set)
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/env.sh"; . "$here/lib/gui.sh"
s0_hsway stop 2>/dev/null; s0_stop_bus; s0_stop_collector
s0_forget_remote 2>&1 | tail -4
for d in mauvely mauvely-s0; do rmdir "$XDG_RUNTIME_DIR/$d" 2>/dev/null; done
# flatpak's own scratch for the four ids the spikes ran (never while one of them runs)
if [ -z "$(s0flatpak ps --columns=application 2>/dev/null)" ]; then
  for a in org.mozilla.firefox org.chromium.Chromium com.mauvely.s0granted com.mauvely.s0denied; do
    rm -f "$XDG_RUNTIME_DIR/app/$a/.flextop-lock"; rmdir "$XDG_RUNTIME_DIR/app/$a" 2>/dev/null
    rm -rf "${XDG_RUNTIME_DIR:?}/.flatpak/$a"
  done
fi
echo "leftovers in \$XDG_RUNTIME_DIR:"; ls -d "$XDG_RUNTIME_DIR"/mauvely* "$XDG_RUNTIME_DIR"/app/* 2>&1 | head
echo "user's a11y bus still answers:"; busctl --user call org.a11y.Bus /org/a11y/bus org.a11y.Bus GetAddress 2>&1 | head -2
s0flatpak list --columns=application,origin
