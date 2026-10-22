#!/bin/bash
# A real PAM run on this machine, as yourself: libpam's pam_start_confdir
# reads the stack from a scratch directory, and a debug build's socket=
# argument points the module at a fake daemon.
#   tests/login/local.sh <scratch dir>
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
WORK=$1
mkdir -p "$WORK/conf"
cargo build -p pam-mauvely --manifest-path "$root/Cargo.toml" >/dev/null
cc -Wall -o "$WORK/pam_harness" "$here/pam_harness.c" -lpam
SO="$root/target/debug/libpam_mauvely.so"
# A socket's path must fit in 108 bytes, which a scratch directory may not.
SOCK="${XDG_RUNTIME_DIR:?}/pam-mauvely-harness-$$.sock"
SOCK_ARG="socket=$SOCK"
CONF="$WORK/conf"
RUN="$WORK/pam_harness"
run() { "$WORK/pam_harness" "$1" "$2" "$CONF"; }
RUN=run
set +e
. "$here/cases.sh"
rm -f "$SOCK"
exit $fail
