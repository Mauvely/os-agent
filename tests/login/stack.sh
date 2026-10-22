# Mauvely OS's PAM stack, as brief 26 drafts it, in a Kinoite container:
# sourced by inside.sh and e2e-inside.sh, as root. The module is
# /out/libpam_mauvely.so.
#
# The `mauvely` authselect vendor profile is made from `local` at build time,
# with these lines before pam_unix in system-auth and password-auth, for
# auth and for account, as os-image's build (ec68879) inserts them:
#   [success=2 default=ignore]               pam_localuser.so
#   [success=1 default=ignore]               pam_localuser.so file=/usr/lib/passwd
#   [success=done ignore=ignore default=die] pam_mauvely.so
# so local and system accounts never reach pam_mauvely.
install -m 0755 /out/libpam_mauvely.so /usr/lib64/security/pam_mauvely.so
authselect create-profile mauvely --vendor --base-on local \
    --symlink-nsswitch --symlink-dconf -s postlogin -s fingerprint-auth \
    -s smartcard-auth -s switchable-auth >/dev/null
profile=/usr/share/authselect/vendor/mauvely
sed -i "1s/.*/Mauvely OS/" $profile/README
for f in system-auth password-auth; do
    python3 -I - "$profile/$f" <<"PY"
import re, sys
path = sys.argv[1]
text = open(path).read()
for kind in ("auth", "account"):
    m = re.search(rf"^{kind}\s+\S+\s+pam_unix\.so.*$", text, re.M)
    assert m, f"no {kind} pam_unix line in {path}"
    lines = (f"{kind:<9}[success=2 default=ignore]               pam_localuser.so\n"
             f"{kind:<9}[success=1 default=ignore]               pam_localuser.so file=/usr/lib/passwd\n"
             f"{kind:<9}[success=done ignore=ignore default=die] pam_mauvely.so\n")
    text = text[:m.start()] + lines + text[m.start():]
open(path, "w").write(text)
PY
done
authselect select mauvely with-silent-lastlog with-mdns4 --force >/dev/null
authselect check
echo "--- password-auth, as selected"
grep -E "^(auth|account)" /etc/pam.d/password-auth
