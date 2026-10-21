#!/bin/sh
# A stand-in for `kdialog` in the dialog tests, which never draw a window. The
# tests make a directory with a symlink to this file named `kdialog`; this
# script keeps its state in the directory it was run from:
#   argv.N, stdin.N, pid.N  what run N was given, and its process id
#   hold                    while it exists, the "window" stays open
#   crash                   when it exists, the process kills itself
#   exit                    the exit status to give, 0 when absent
d="$(dirname "$0")"
n=$(( $(cat "$d/count" 2>/dev/null || echo 0) + 1 ))
echo $n > "$d/count"
echo $$ > "$d/pid.$n"
printf '%s\n' "$@" > "$d/argv.$n"
case "$*" in *--textbox*) cat > "$d/stdin.$n" ;; esac
while [ -e "$d/hold" ]; do sleep 0.02; done
[ -e "$d/crash" ] && kill -KILL $$
exit "$(cat "$d/exit" 2>/dev/null || echo 0)"
