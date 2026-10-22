#!/bin/bash
# A real PAM run in Mauvely OS's base, as root, with the stack brief 26 drafts.
#   tests/login/container.sh <scratch dir>
#
# 1. Builds the release module and the harness in Fedora 44 (`pam-devel`), as
#    os-image's builder stage would.
# 2. In Kinoite 44: installs the module at /usr/lib64/security/pam_mauvely.so,
#    makes the `mauvely` authselect vendor profile (stack.sh), starts a fake
#    mauvelyd at /run/mauvely/auth.sock, and runs the real
#    /usr/lib/pam.d/plasmalogin, sudo, login and a stack that shows the
#    password reaching the modules after this one.
# Needs podman and the network (dnf, crates.io). Leaves nothing behind but
# <scratch dir>.
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
        cd /src && cargo build --release --locked -p pam-mauvely
        cp /target/release/libpam_mauvely.so /out/
        gcc -Wall -o /out/pam_harness tests/login/pam_harness.c -lpam
        rpm -q pam pam-devel glibc > /out/built-against'

podman run --rm --security-opt label=disable \
    -v "$here:/harness:ro" -v "$WORK/out:/out" \
    "$KINOITE" bash -euc '
        . /harness/stack.sh

        # A local admin with a password, to show the guard.
        useradd -m localadmin
        echo "localadmin:local pass 1" | chpasswd

        # The modules after this one get the password: what the wallets need.
        cat > /usr/libexec/mauvely-save-authtok <<SH
#!/bin/sh
cat > /run/authtok-seen
SH
        chmod 0755 /usr/libexec/mauvely-save-authtok
        cat > /etc/pam.d/mauvely-authtok <<PAM
auth     substack password-auth
auth     optional pam_exec.so expose_authtok quiet /usr/libexec/mauvely-save-authtok
account  include  password-auth
PAM

        mkdir -p /run/mauvely
        cd /run
        export SO=/usr/lib64/security/pam_mauvely.so SOCK=/run/mauvely/auth.sock WORK=/run/harness
        mkdir -p $WORK
        bash /harness/inside.sh
    '
