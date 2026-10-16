#!/usr/bin/env bash
# Build the spike's two static binaries into $S0_ROOT/bin (glibc, crt-static: no interpreter or
# shared library needed inside any runtime).
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
. "$here/env.sh"
mkdir -p "$S0_ROOT/bin"
for b in s0host s0client; do
  rustc --edition 2021 -C opt-level=2 -C target-feature=+crt-static -C strip=symbols \
    -o "$S0_ROOT/bin/$b" "$here/host/$b.rs"
done
ls -l "$S0_ROOT/bin"
file "$S0_ROOT/bin/s0host" 2>/dev/null || true
