# The cases, shared by local.sh and container.sh. Sourced with:
#   $SO      the module
#   $SOCK    the daemon's socket ($SOCK_ARG is what the PAM lines pass)
#   $CONF    a directory for PAM service files, and $RUN, which runs
#            "pam_harness <service> <user>" against it
#   $WORK    a scratch directory
set -u
fail=0
check() { # check <name> <expected line> <output>
    if grep -qxF -- "$2" <<<"$3"; then
        echo "ok   $1: $2"
    else
        echo "FAIL $1: wanted \"$2\" in:"; sed 's/^/       /' <<<"$3"; fail=1
    fi
}
absent() { # absent <name> <line> <output>
    if grep -qF -- "$2" <<<"$3"; then
        echo "FAIL $1: \"$2\" should not be there"; fail=1
    else
        echo "ok   $1: no \"$2\""
    fi
}

cat > "$CONF/plasmalogin" <<PAM
auth     [success=done ignore=ignore default=die] $SO $SOCK_ARG
auth     required pam_permit.so
account  [success=done ignore=ignore default=die] $SO $SOCK_ARG
account  required pam_permit.so
PAM
cp "$CONF/plasmalogin" "$CONF/sudo"

CJK=$(python3 -c 'print("密码很安全的口令" * 25)')
cat > "$WORK/script.json" <<JSON
{
  "auth:timur": [
    {"result": "code", "prompt": "Code", "info": "Enter the code from your authenticator app."},
    {"result": "ok"}
  ],
  "account:timur": [{"result": "ok"}],
  "auth:bob": [{"result": "refused", "reason": "credentials", "message": "Wrong name or password."}],
  "auth:carol": [
    {"result": "code", "prompt": "Code", "info": "Enter the code we emailed you."},
    {"result": "refused", "reason": "code", "message": "That code isn't right."}
  ],
  "auth:dave": [{"result": "ok"}],
  "account:dave": [{"result": "refused", "reason": "text_login", "message": "Sign in at the login screen."}],
  "auth:sysuser": [{"result": "refused", "reason": "not_mauvely", "message": ""}],
  "account:sysuser": [{"result": "refused", "reason": "not_mauvely", "message": ""}],
  "auth:erin": [{"result": "ok"}],
  "account:erin": [{"result": "ok"}],
  "auth:hang": [null]
}
JSON
: > "$WORK/log"
python3 -I "$here/fake_daemon.py" "$SOCK" "$WORK/script.json" "$WORK/log" > "$WORK/daemon.out" 2>&1 &
DAEMON=$!
for _ in $(seq 50); do [ -S "$SOCK" ] && break; sleep 0.1; done

out=$(HARNESS_PASSWORD='correct horse 1' HARNESS_CODE=123456 $RUN plasmalogin timur)
check "password then code" "INFO Enter the code from your authenticator app." "$out"
check "password then code" "PROMPT Code" "$out"
check "password then code" "AUTH 0 Success" "$out"
check "password then code" "ACCOUNT 0 Success" "$out"
check "sent" '{"v":1,"op":"auth","service":"plasmalogin","username":"timur","password":"correct horse 1"}' "$(cat "$WORK/log")"
check "sent" '{"v":1,"op":"code","code":"123456"}' "$(cat "$WORK/log")"
check "sent" '{"v":1,"op":"account","service":"plasmalogin","username":"timur"}' "$(cat "$WORK/log")"

out=$(HARNESS_PASSWORD='wrong 1' $RUN sudo bob)
check "wrong password" "ERROR Wrong name or password." "$out"
check "wrong password" "AUTH 7 Authentication failure" "$out"

out=$(HARNESS_PASSWORD='correct horse 1' HARNESS_CODE=000000 $RUN plasmalogin carol)
check "wrong code" "INFO Enter the code we emailed you." "$out"
check "wrong code" "ERROR That code isn't right." "$out"
check "wrong code" "AUTH 7 Authentication failure" "$out"

out=$(HARNESS_PASSWORD='correct horse 1' $RUN sudo dave)
check "account refused" "ERROR Sign in at the login screen." "$out"
check "account refused" "ACCOUNT 6 Permission denied" "$out"

# Not a Mauvely person: PAM_IGNORE, so the next line decides (pam_permit here,
# pam_unix in the real stack), and nothing is said.
out=$(HARNESS_PASSWORD='x' $RUN sudo sysuser)
check "local account" "AUTH 0 Success" "$out"
check "local account" "ACCOUNT 0 Success" "$out"
absent "local account" "ERROR" "$out"

# A password longer than PAM_MAX_RESP_SIZE, in another script, arrives whole.
out=$(HARNESS_PASSWORD="$CJK" $RUN sudo erin)
check "long password" "AUTH 0 Success" "$out"
check "long password, sent whole" "{\"v\":1,\"op\":\"auth\",\"service\":\"sudo\",\"username\":\"erin\",\"password\":\"$CJK\"}" "$(cat "$WORK/log")"

# The daemon hangs up: closed, at once.
out=$(HARNESS_PASSWORD='x' $RUN sudo hang)
check "daemon hangs up" "AUTH 9 Authentication service cannot retrieve authentication info" "$out"

# No daemon: closed, and fast.
kill $DAEMON; wait $DAEMON 2>/dev/null; rm -f "$SOCK"
start=$(date +%s%N)
out=$(HARNESS_PASSWORD='x' $RUN plasmalogin timur)
took=$(( ($(date +%s%N) - start) / 1000000 ))
check "no daemon" "AUTH 9 Authentication service cannot retrieve authentication info" "$out"
if [ "$took" -lt 1000 ]; then echo "ok   no daemon: ${took} ms"; else echo "FAIL no daemon: ${took} ms"; fail=1; fi
