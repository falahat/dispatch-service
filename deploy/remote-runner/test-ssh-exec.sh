#!/bin/bash
# ssh-exec.sh round trip without SSH: a stand-in ssh runs the serve side locally with an empty environment, as the
# key's forced command would run. A job's inputs reach the remote folder (an executable stays executable, an empty
# folder stays) over several connections, its GPU grant goes along, its output and result come back and its remote
# folder is deleted; a command's failure comes back in place of its result. A file the remote cache holds, an earlier
# input or output, is read-only there and is not sent again; a pruned cache is refilled; a stopped job's remote command
# receives SIGTERM.
set -euo pipefail
kit=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d); trap 'rm -rf -- "$t"' EXIT
mkdir -p "$t/bin" "$t/remote" "$t/job/inputs/code/sub" "$t/job/inputs/empty" "$t/job/outputs"
cat > "$t/bin/ssh" <<EOF
#!/bin/bash
while [ "\${1#-}" != "\$1" ]; do shift 2; done; shift
echo "\$1" >> "$t/verbs"
exec env -i PATH=/usr/bin:/bin SSH_EXEC_CACHE_MB=\${SSH_EXEC_CACHE_MB:-10240} SSH_ORIGINAL_COMMAND="\$*" \
  bash "$kit/ssh-exec.sh" serve "$t/remote" "$t/command"
EOF
cat > "$t/command" <<EOF
#!/bin/bash
set -eu
python3 -c 'import json, os, sys; assert json.load(sys.stdin)["workdir"] == os.getcwd()'
[ "\$(cat inputs/code/x.txt)" = code ] && [ -x inputs/code/run.sh ] && [ -d inputs/empty ] || exit 3
trap 'echo stopped > $t/mark; exit 143' TERM
echo "remote log line"
if [ "\${PWD##*/}" = j_stop ]; then touch $t/started; while :; do sleep 0.1; done; fi
if [ "\${PWD##*/}" = j_fail ]; then echo '{"error_class": "fatal", "message": "own"}' > invoke-failure.json; exit 0; fi
mkdir -p outputs/out; echo "\${DISPATCH_GPU_MEMORY_MB:-}" > outputs/out/grant.txt
echo '{"outputs": {"out": "outputs/out"}, "metrics": {"exit": 0}}' > invoke-result.json
EOF
chmod 700 "$t/bin/ssh" "$t/command"
echo code > "$t/job/inputs/code/x.txt"
printf '#!/bin/sh\n' > "$t/job/inputs/code/run.sh"; chmod 755 "$t/job/inputs/code/run.sh"
for i in 1 2 3 4 5; do head -c $((i * 1000)) /dev/urandom > "$t/job/inputs/code/sub/f$i"; done
cd "$t/job"
drive() { printf '{"job_id": "%s", "workdir": "%s"}' "$1" "$t/job" | PATH=$t/bin:$PATH bash "$kit/ssh-exec.sh" drive "$t/config" host; }
puts() { grep -c '^put$' "$t/verbs" || true; }
export SSH_EXEC_STREAMS=3; streams=3
spread() { echo $(( $1 < streams ? $1 : streams )); }
fail() { echo "$1" >&2; exit 1; }

log=$(DISPATCH_GPU_MEMORY_MB=3000 drive j_1)
[ "$log" = "remote log line" ] && [ "$(cat outputs/out/grant.txt)" = 3000 ] && [ -f invoke-result.json ] &&
  [ ! -e "$t/remote/j_1" ] || fail "round trip failed: $log"
[ "$(puts)" = "$(spread 7)" ] || fail "7 new files went over $(puts) connections, not $(spread 7)"
[ "$(stat -c %a "$t/remote/.cache/$(sha256sum < outputs/out/grant.txt | cut -d' ' -f1)")" = 444 ] ||
  fail "a kept output is writable in the cache"
rm -r outputs/out invoke-result.json; : > "$t/verbs"
echo 3000 > inputs/code/was-output.txt
SSH_EXEC_CACHE_MB=0 drive j_2 > /dev/null
[ "$(puts)" = 0 ] && [ -f outputs/out/grant.txt ] || fail "held inputs and an earlier output were sent again"
[ -z "$(ls -A "$t/remote/.cache")" ] || fail "a cache over its limit was not pruned"
rm -r outputs/out invoke-result.json; : > "$t/verbs"
drive j_3 > /dev/null
[ "$(puts)" = "$(spread 8)" ] && [ -f outputs/out/grant.txt ] || fail "a pruned cache was not refilled"
rm -r outputs/out invoke-result.json

drive j_fail > /dev/null
[ "$(cat invoke-failure.json)" = '{"error_class": "fatal", "message": "own"}' ] && [ ! -e invoke-result.json ] ||
  fail "a command's failure did not come back"
rm -r outputs invoke-failure.json

printf '{"job_id": "j_stop", "workdir": "%s"}' "$t/job" |
  PATH=$t/bin:$PATH bash "$kit/ssh-exec.sh" drive "$t/config" host > /dev/null &
driver=$!
until [ -e "$t/started" ]; do sleep 0.1; done
kill -TERM "$driver"
rc=0; wait "$driver" || rc=$?
[ "$rc" != 0 ] && [ "$(cat "$t/mark")" = stopped ] && [ ! -e "$t/remote/j_stop" ] && [ ! -e invoke-result.json ] ||
  fail "stop failed: rc $rc"
echo "ssh-exec round trip, cache, failure and stop: ok"
