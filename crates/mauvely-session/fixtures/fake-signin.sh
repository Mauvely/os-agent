#!/bin/bash
# A stand-in for `mauvely-signin` in the signin tests, which never draws a
# window. The tests make a directory with a symlink to this file named
# `mauvely-signin`; this script keeps its state in the directory it was run
# from:
#   argv.N, stdin.N, pid.N  what run N was given (its first line), its pid
#   finish.N                what ended its wait: the next line, or EOF
#   close                   the person closes it: `closed` on stdout, once,
#                           and it goes on waiting to be finished
#   quit                    it exits by itself, with the status in `exit`
#   crash                   it kills itself
#   stubborn                it does not exit when told to finish
d="$(dirname "$0")"
n=$(( $(cat "$d/count" 2>/dev/null || echo 0) + 1 ))
echo $n > "$d/count"
echo $$ > "$d/pid.$n"
printf '%s' "$*" > "$d/argv.$n"
IFS= read -r first
printf '%s\n' "$first" > "$d/stdin.$n"
said=
while :; do
  IFS= read -r -t 0.05 rest
  rc=$?
  [ $rc -eq 0 ] && { printf '%s\n' "$rest" > "$d/finish.$n"; break; }
  # 1 is the end of input; above 128, the wait timed out.
  [ $rc -le 128 ] && { echo EOF > "$d/finish.$n"; break; }
  [ -e "$d/crash" ] && kill -KILL $$
  [ -e "$d/quit" ] && exit "$(cat "$d/exit" 2>/dev/null || echo 0)"
  [ -e "$d/close" ] && [ -z "$said" ] && { echo closed; said=1; }
done
[ -e "$d/stubborn" ] && while :; do sleep 0.05; done
exit 0
