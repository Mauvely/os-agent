#!/bin/bash
# The real `mauvelyd login` and the real pam_mauvely, end to end, in Mauvely
# OS's base as root, against a fake website-devices (fake_devices.py).
#   tests/login/e2e.sh <scratch dir>
#
# Builds both in Fedora 44, then in Kinoite 44: the PAM stack (stack.sh), an
# enrolled device's state with its key sealed by the real systemd-creds, and
# the login service under its own name. Only `systemctl start
# mauvely-home@<name>` is faked, since nothing runs systemd in the container.
# Needs podman and the network (dnf, crates.io).
set -eu
here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
WORK=$(cd "$1" && pwd)
mkdir -p "$WORK/out" "$WORK/target" "$WORK/cargo"
FEDORA=${FEDORA:-quay.io/fedora/fedora:44}
KINOITE=${KINOITE:-quay.io/fedora-ostree-desktops/kinoite:44.20261019.0}

podman run --rm --security-opt label=disable \
    -v "$root:/src:ro" -v "$WORK/target:/target" -v "$WORK/cargo:/cargo" -v "$WORK/out:/out" \
    -e CARGO_TARGET_DIR=/target -e CARGO_HOME=/cargo \
    "$FEDORA" sh -euc '
        dnf -y -q install cargo gcc pam-devel >/dev/null
        cd /src && cargo build --release --locked -p mauvelyd -p pam-mauvely
        cp /target/release/libpam_mauvely.so /target/release/mauvelyd /out/
        gcc -Wall -o /out/pam_harness tests/login/pam_harness.c -lpam'

# A volume for /var/lib/systemd: systemd-creds will not make its host key on
# the container's own layer.
podman run --rm --security-opt label=disable -v /var/lib/systemd \
    -v "$here:/harness:ro" -v "$WORK/out:/out" \
    "$KINOITE" bash -euc '. /harness/stack.sh; bash /harness/e2e-inside.sh'
