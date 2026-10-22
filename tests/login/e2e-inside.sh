# The cases inside Kinoite, for e2e.sh. Root, real /etc/pam.d, the real
# login service.
set -u
fail=0
check() {
    if grep -qxF -- "$2" <<<"$3"; then echo "ok   $1: $2"
    else echo "FAIL $1: wanted \"$2\" in:"; sed 's/^/       /' <<<"$3"; fail=1; fi
}
absent() {
    if grep -qF -- "$2" <<<"$3"; then echo "FAIL $1: \"$2\" should not be there"; fail=1
    else echo "ok   $1: no \"$2\""; fi
}
H=/out/pam_harness
as() { local uid=$1; shift; setpriv --reuid="$uid" --regid="$uid" --clear-groups "$@"; }

# An enrolled device that has checked in, as the agent leaves it.
systemd-machine-id-setup >/dev/null 2>&1 || true
mkdir -p /etc/mauvely /var/lib/mauvely /var/home
chmod 0700 /var/lib/mauvely
echo http://127.0.0.1:8798 > /etc/mauvely/server
head -c 32 /dev/urandom | systemd-creds encrypt --name=mauvely-device-key --with-key=host - /var/lib/mauvely/key.cred
echo '{"device_id":"dev_e2e","org_slug":"suez"}' > /var/lib/mauvely/device.json
echo '{"mode":"shared","assigned":null,"admins":["ada"],"org":{"name":"Suez","slug":"suez"},"offline_days":14}' \
    > /var/lib/mauvely/people.json
# What mauvely-home@.service would do: no systemd runs here.
mkdir -p /run/fakebin
cat > /run/fakebin/systemctl <<"SH"
#!/bin/sh
[ "$1 $2" = "start --no-ask-password" ] || exit 2
name=${3#mauvely-home@}; name=${name%.service}
install -d -m 0700 -o "$name" -g "$name" "/var/home/$name" && echo "$name" >> /run/homes-made
SH
chmod 0755 /run/fakebin/systemctl

python3 -I /harness/fake_devices.py /run/devices.log > /run/devices.out 2>&1 &
DEVICES=$!
PATH=/run/fakebin:$PATH /out/mauvelyd login > /run/mauvelyd.log 2>&1 &
for _ in $(seq 100); do
    [ -S /run/mauvely/auth.sock ] && grep -q listening /run/devices.out && break
    sleep 0.1
done
check "socket" "666" "$(stat -c %a /run/mauvely/auth.sock)"

echo "--- the login screen, a version 1 account with a code"
out=$(HARNESS_PASSWORD="correct horse battery staple 1" HARNESS_CODE=123456 $H plasmalogin timur)
check "timur" "INFO Enter the code from your authenticator app." "$out"
check "timur" "PROMPT Code" "$out"
check "timur" "AUTH 0 Success" "$out"
check "timur" "ACCOUNT 0 Success" "$out"
check "timur, getent" "timur:x:21001:21001:Timur Inal:/home/timur:/bin/bash" "$(getent passwd timur)"
check "timur, by uid" "timur:x:21001:21001:Timur Inal:/home/timur:/bin/bash" "$(getent passwd 21001)"
check "timur, groups" "uid=21001(timur) gid=21001(timur) groups=21001(timur)" "$(id timur)"
check "timur, home" "700 timur timur" "$(stat -c '%a %U %G' /var/home/timur)"
check "timur, hand-off" "600 timur" "$(stat -c '%a %U' /run/mauvely/login/21001)"
check "timur, hand-off dir" "1733" "$(stat -c '%a' /run/mauvely/login)"
check "timur, hand-off" "tok_timur" "$(python3 -c 'import json; print(json.load(open("/run/mauvely/login/21001"))["token"])')"
check "timur, hand-off" "http://127.0.0.1:8787" "$(python3 -c 'import json; print(json.load(open("/run/mauvely/login/21001"))["origin"])')"
check "timur, cache" "600" "$(stat -c '%a' /var/lib/mauvely/people/timur.cred)"
absent "timur, cache sealed" "correct horse" "$(cat /var/lib/mauvely/people/timur.cred)"
check "timur, the vector's secret was sent" '{"username": "timur", "kdfVersion": 1, "secret": "0d0R8jeMwo4LuShcvdP7aW4F1sSlks3OkaoTN5E60AE="}' \
    "$(python3 -c 'import json,sys; [print(json.dumps(json.loads(l)["body"])) for l in open("/run/devices.log")]')"
absent "timur, no password on the wire" "correct horse battery staple 1" "$(cat /run/devices.log)"

echo "--- the login screen, a version 0 account, a device admin"
out=$(HARNESS_PASSWORD="ada password 1" $H plasmalogin ada)
check "ada" "AUTH 0 Success" "$out"
check "ada, wheel" "uid=21002(ada) gid=21002(ada) groups=21002(ada),10(wheel)" "$(id ada)"
for _ in $(seq 50); do grep -q /api/auth/kdf /run/devices.log && break; sleep 0.1; done
check "ada, upgraded with the new session" "Bearer tok_ada 200" \
    "$(python3 -c 'import json; [print(r["authorization"], r["status"]) for r in map(json.loads, open("/run/devices.log")) if r["path"] == "/api/auth/kdf"]')"

echo "--- refused online"
out=$(HARNESS_PASSWORD="wrong password 1" $H plasmalogin bob)
check "bob" "ERROR Wrong name or password." "$out"
check "bob" "AUTH 7 Authentication failure" "$out"
absent "bob, nothing made" "bob" "$(ls /etc/userdb /var/lib/mauvely/people)"

echo "--- sudo and the lock screen: the cache only"
before=$(wc -l < /run/devices.log)
out=$(HARNESS_PASSWORD="correct horse battery staple 1" $H sudo timur)
check "sudo" "AUTH 0 Success" "$out"
check "sudo" "ACCOUNT 0 Success" "$out"
out=$(HARNESS_PASSWORD="wrong password 1" $H sudo timur)
check "sudo, wrong" "AUTH 7 Authentication failure" "$out"
out=$(as 21001 env HARNESS_PASSWORD="correct horse battery staple 1" $H kde timur)
check "lock screen, as timur" "AUTH 0 Success" "$out"
out=$(as 21001 env HARNESS_PASSWORD="ada password 1" $H kde ada)
check "lock screen, timur asking about ada" "ERROR You can only sign in as yourself here." "$out"
check "lock screen, timur asking about ada" "AUTH 6 Permission denied" "$out"
out=$(as 21001 env HARNESS_PASSWORD="x" HARNESS_CODE=1 $H plasmalogin timur)
check "the login screen, not as root" "AUTH 6 Permission denied" "$out"
check "the server was not asked" "$before" "$(wc -l < /run/devices.log)"

echo "--- a text console"
out=$(HARNESS_PASSWORD="correct horse battery staple 1" $H login timur)
check "login, timur" "ERROR Sign in at the login screen." "$out"
check "login, timur" "ACCOUNT 6 Permission denied" "$out"
out=$(HARNESS_PASSWORD="ada password 1" $H login ada)
check "login, ada the admin" "ACCOUNT 0 Success" "$out"

echo "--- offline"
kill $DEVICES; wait $DEVICES 2>/dev/null
rm /run/mauvely/login/21001
out=$(HARNESS_PASSWORD="correct horse battery staple 1" $H plasmalogin timur)
check "offline, timur" "AUTH 0 Success" "$out"
absent "offline, no code" "PROMPT Code" "$out"
check "offline, no new session" "no" "$([ -e /run/mauvely/login/21001 ] && echo yes || echo no)"
out=$(HARNESS_PASSWORD="wrong password 1" $H plasmalogin timur)
check "offline, wrong" "AUTH 7 Authentication failure" "$out"
out=$(HARNESS_PASSWORD="whatever 1" $H plasmalogin carol)
check "offline, never here" "ERROR Connect to the internet to sign in." "$out"

echo "--- the log"
log=$(cat /run/mauvelyd.log)
absent "log" "tok_" "$log"
absent "log" "correct horse" "$log"
absent "log" "ada password" "$log"
absent "log, the typed name of nobody here" "carol" "$log"
sed 's/^/    /' /run/mauvelyd.log
exit $fail
