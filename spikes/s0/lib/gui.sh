# Sourced by the GUI spikes. Everything GUI runs inside hsway; the D-Bus session bus is a private,
# activation-free one (no services, so nothing of the user's desktop or at-spi is ever started).
here_lib="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
. "$here_lib/../env.sh"
S0_BUS_SOCK="$S0_ROOT/bus.sock"
S0_COLLECTOR_LOG="$S0_ROOT/logs/reports.jsonl"
mkdir -p "$S0_ROOT/logs"

s0_start_bus() {
  cat > "$S0_ROOT/bus.conf" <<CONF
<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path=$S0_BUS_SOCK</listen>
  <auth>EXTERNAL</auth>
  <policy context="default"><allow send_destination="*" eavesdrop="true"/><allow eavesdrop="true"/><allow own="*"/></policy>
</busconfig>
CONF
  rm -f "$S0_BUS_SOCK"
  # DISPLAY=:91 as a tripwire: if anything ever did start at-spi on this bus it could not touch bus_0
  DISPLAY=:91 setsid dbus-daemon --config-file="$S0_ROOT/bus.conf" --nofork > "$S0_ROOT/logs/bus.log" 2>&1 &
  echo $! > "$S0_ROOT/bus.pid"
  for _ in $(seq 50); do [ -S "$S0_BUS_SOCK" ] && break; sleep 0.1; done
  [ -S "$S0_BUS_SOCK" ] || { echo "private bus did not start"; return 1; }
  export S0_DBUS="unix:path=$S0_BUS_SOCK"
  # Chromium's zypak sandbox spawns its renderers through org.freedesktop.portal.Flatpak and dies
  # at startup without it ("Failed to initialize (is the Flatpak D-Bus portal working?)"). A real
  # session always has it, D-Bus activated; this bus has no activation, so start it by hand.
  if [ -n "${PORTAL:-}" ]; then
    DBUS_SESSION_BUS_ADDRESS="$S0_DBUS" HOME="$S0_HOME" FLATPAK_USER_DIR="$FLATPAK_USER_DIR" \
      setsid /usr/lib/flatpak-portal > "$S0_ROOT/logs/flatpak-portal.log" 2>&1 &
    echo $! > "$S0_ROOT/portal.pid"
    sleep 1
  fi
}
s0_stop_bus() {
  [ -f "$S0_ROOT/portal.pid" ] && { kill "$(cat "$S0_ROOT/portal.pid")" 2>/dev/null; rm -f "$S0_ROOT/portal.pid"; }
  [ -f "$S0_ROOT/bus.pid" ] && kill "$(cat "$S0_ROOT/bus.pid")" 2>/dev/null; rm -f "$S0_BUS_SOCK" "$S0_ROOT/bus.pid"
}

s0_start_collector() {
  : > "$S0_COLLECTOR_LOG"
  python3 -I "$here_lib/collector.py" "$S0_COLLECTOR_LOG" 18099 &
  echo $! > "$S0_ROOT/collector.pid"
  sleep 0.5
}
s0_stop_collector() { [ -f "$S0_ROOT/collector.pid" ] && kill "$(cat "$S0_ROOT/collector.pid")" 2>/dev/null; rm -f "$S0_ROOT/collector.pid"; }

# wait up to $3 seconds for a collector line containing $1 (a step) from browser $2
s0_wait_report() {
  local step="$1" who="$2" secs="${3:-60}"
  timeout "$secs" bash -c "until grep -q '\"browser\":\"$who\",\"step\":\"$step\"' '$S0_COLLECTOR_LOG'; do sleep 0.5; done"
}

# hsway-run a Flatpak with the throwaway HOME/installation and the private bus
s0_gui_run() {  # <logname> <flatpak run args...>
  local name="$1"; shift
  HSWAY_NAME=s0 "$S0_HSWAY" run env HOME="$S0_HOME" FLATPAK_USER_DIR="$FLATPAK_USER_DIR" \
      DBUS_SESSION_BUS_ADDRESS="$S0_DBUS" flatpak --user run --no-a11y-bus --no-documents-portal "$@"
}
s0_hsway() { HSWAY_NAME=s0 "$S0_HSWAY" "$@"; }
