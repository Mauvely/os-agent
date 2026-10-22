# The cases inside Kinoite, for container.sh. Root, real /etc/pam.d.
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
cat > $WORK/script.json <<JSON
{
  "auth:timur": [
    {"result": "code", "prompt": "Code", "info": "Enter the code from your authenticator app."},
    {"result": "ok"}
  ],
  "account:timur": [{"result": "ok"}],
  "auth:bob": [{"result": "refused", "reason": "credentials", "message": "Wrong name or password."}],
  "auth:ada": [{"result": "ok"}],
  "account:ada": [{"result": "refused", "reason": "text_login", "message": "Sign in at the login screen."}],
  "auth:polkitd": [{"result": "refused", "reason": "not_mauvely", "message": ""}],
  "auth:erin": [{"result": "ok"}],
  "account:erin": [{"result": "ok"}]
}
JSON
: > $WORK/log
python3 -I /harness/fake_daemon.py $SOCK $WORK/script.json $WORK/log > $WORK/daemon.out 2>&1 &
DAEMON=$!
for _ in $(seq 50); do [ -S $SOCK ] && break; sleep 0.1; done

echo "--- the login screen: /usr/lib/pam.d/plasmalogin"
out=$(HARNESS_PASSWORD="correct horse 1" HARNESS_CODE=123456 $H plasmalogin timur)
check "login screen" "PROMPT Password: " "$out"
check "login screen" "INFO Enter the code from your authenticator app." "$out"
check "login screen" "PROMPT Code" "$out"
check "login screen" "AUTH 0 Success" "$out"
check "login screen" "ACCOUNT 0 Success" "$out"
check "login screen, sent" '{"v":1,"op":"auth","service":"plasmalogin","username":"timur","password":"correct horse 1"}' "$(cat $WORK/log)"

echo "--- sudo"
out=$(HARNESS_PASSWORD="wrong 1" $H sudo bob)
check "sudo, wrong" "ERROR Wrong name or password." "$out"
check "sudo, wrong" "AUTH 7 Authentication failure" "$out"

echo "--- a text console, for somebody who is not an admin"
out=$(HARNESS_PASSWORD="correct horse 1" $H login ada)
check "login" "AUTH 0 Success" "$out"
check "login" "ERROR Sign in at the login screen." "$out"
check "login" "ACCOUNT 6 Permission denied" "$out"

echo "--- a system user from /usr/lib/passwd: pam_unix decides, mauvelyd is not asked"
out=$(HARNESS_PASSWORD="x" $H sudo polkitd)
check "system user" "AUTH 7 Authentication failure" "$out"
absent "system user" "ERROR" "$out"
absent "system user, not asked" "polkitd" "$(cat $WORK/log)"

echo "--- the modules after this one get the password"
out=$(HARNESS_PASSWORD="correct horse 1" $H mauvely-authtok erin)
check "authtok" "AUTH 0 Success" "$out"
seen=$(tr -d "\0" < /run/authtok-seen)
check "authtok, seen by pam_exec" "correct horse 1" "$seen"

echo "--- the guard: a local account with mauvelyd down"
kill $DAEMON; wait $DAEMON 2>/dev/null; rm -f $SOCK
out=$(HARNESS_PASSWORD="local pass 1" $H plasmalogin localadmin)
check "local, daemon down" "AUTH 0 Success" "$out"
check "local, daemon down" "ACCOUNT 0 Success" "$out"
out=$(HARNESS_PASSWORD="local pass 2" $H plasmalogin localadmin)
check "local, wrong password" "AUTH 7 Authentication failure" "$out"
out=$(HARNESS_PASSWORD="x" $H sudo root)
check "root goes to pam_unix" "AUTH 7 Authentication failure" "$out"
echo "--- a Mauvely name with mauvelyd down: closed, never pam_unix"
out=$(HARNESS_PASSWORD="correct horse 1" $H plasmalogin timur)
check "daemon down" "AUTH 9 Authentication service cannot retrieve authentication info" "$out"
out=$(HARNESS_PASSWORD="local pass 1" $H plasmalogin someone-new)
check "daemon down, any name" "AUTH 9 Authentication service cannot retrieve authentication info" "$out"
echo "--- built against"; cat /out/built-against
exit $fail
