# Source this file. Everything the S0 spikes do is confined to the variables below.
#
#   FLATPAK_USER_DIR  a throwaway Flatpak *user* installation; never the real one
#   S0_HOME           HOME for every `flatpak` call. Flatpak derives ~/.var/app from
#                     g_get_home_dir(), which honours $HOME, so browser data lands in
#                     $S0_HOME/.var/app and the real ~/.var/app is never touched
#   XDG_RUNTIME_DIR   left alone (the nested sway socket lives there); sockets under it
#                     live in $S0_SOCKDIR only
export S0_ROOT="${S0_ROOT:-$HOME/.cache/mauvely-s0}"
export S0_REALHOME="${S0_REALHOME:-$HOME}"
export S0_HOME="$S0_ROOT/home"
export FLATPAK_USER_DIR="$S0_REALHOME/.cache/mauvely-flatpak/user"
export S0_SOCKNAME="${S0_SOCKNAME:-mauvely-s0}"          # the directory under $XDG_RUNTIME_DIR
export S0_SOCKDIR="${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/$S0_SOCKNAME"
export S0_HSWAY="$S0_REALHOME/.claude/tools/headless-sway/hsway"
mkdir -p "$S0_HOME" "$S0_ROOT"

# flatpak, always --user, always with the throwaway HOME
s0flatpak() { HOME="$S0_HOME" flatpak --user "$@"; }
# flatpak without --user, for the build-* commands (they take no installation option; they
# still find runtimes in $FLATPAK_USER_DIR)
s0flatpak_raw() { HOME="$S0_HOME" flatpak "$@"; }

# Uninstall everything that came from the test remote, then drop the remote. (`remote-delete
# --force` alone leaves the installed refs behind, orphaned: a "before" test would not be clean.)
s0_forget_remote() {
  local refs
  refs="$(s0flatpak list --columns=ref,origin 2>/dev/null | awk -F'\t' '$2=="mauvely-s0" {print $1}')"
  # shellcheck disable=SC2086
  [ -z "$refs" ] || s0flatpak uninstall -y $refs
  s0flatpak remote-delete --force mauvely-s0 2>/dev/null || true
}
