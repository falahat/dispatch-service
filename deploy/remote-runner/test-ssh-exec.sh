#!/bin/bash
# ssh-exec.sh round trip without SSH: a stand-in ssh runs the serve side locally with an empty environment, as the
# key's forced command would run. A job's inputs reach the remote folder, its GPU grant goes along, its output and
# result come back, its remote folder is deleted, and a stopped job's remote command receives SIGTERM.
set -euo pipefail
kit=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d); trap 'rm -rf -- "$t"' EXIT
mkdir -p "$t/bin" "$t/remote" "$t/job/inputs/code" "$t/job/outputs"
cat > "$t/bin/ssh" <<EOF
#!/bin/bash
shift 3
exec env -i PATH=/usr/bin:/bin SSH_ORIGINAL_COMMAND="\$*" bash "$kit/ssh-exec.sh" serve "$t/remote" "$t/command"
EOF
cat > "$t/command" <<EOF
#!/bin/bash
set -eu
python3 -c 'import json, os, sys; assert json.load(sys.stdin)["workdir"] == os.getcwd()'
[ "\$(cat inputs/code/x.txt)" = code ] || exit 3
trap 'echo stopped > $t/mark; exit 143' TERM
echo "remote log line"
if [ "\${PWD##*/}" = j_2 ]; then touch $t/started; while :; do sleep 0.1; done; fi
mkdir -p outputs/out; echo "\$DISPATCH_GPU_MEMORY_MB" > outputs/out/grant.txt
echo '{"outputs": {"out": "outputs/out"}, "metrics": {"exit": 0}}' > invoke-result.json
EOF
chmod 700 "$t/bin/ssh" "$t/command"
echo code > "$t/job/inputs/code/x.txt"
cd "$t/job"
log=$(printf '{"job_id": "j_1", "workdir": "%s"}' "$t/job" |
  PATH=$t/bin:$PATH DISPATCH_GPU_MEMORY_MB=3000 bash "$kit/ssh-exec.sh" drive "$t/config" host)
[ "$log" = "remote log line" ] && [ "$(cat outputs/out/grant.txt)" = 3000 ] && [ -f invoke-result.json ] &&
  [ ! -e "$t/remote/j_1" ] || { echo "round trip failed: $log" >&2; exit 1; }
rm -r outputs/out invoke-result.json
printf '{"job_id": "j_2", "workdir": "%s"}' "$t/job" | PATH=$t/bin:$PATH bash "$kit/ssh-exec.sh" drive "$t/config" host > /dev/null &
driver=$!
until [ -e "$t/started" ]; do sleep 0.1; done
kill -TERM "$driver"
rc=0; wait "$driver" || rc=$?
[ "$rc" != 0 ] && [ "$(cat "$t/mark")" = stopped ] && [ ! -e "$t/remote/j_2" ] && [ ! -e invoke-result.json ] ||
  { echo "stop failed: rc $rc" >&2; exit 1; }
echo "ssh-exec round trip and stop: ok"
