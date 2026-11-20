#!/bin/bash
# A command runner's installed command that runs each job on another machine over SSH, for a machine that must never
# connect to the plane: the runner drives it, and it only answers.
#
#   The runner's COMMAND, on its own machine:   ssh-exec.sh drive SSH_CONFIG HOST
#   The other machine, as the key's forced command in its authorized_keys:
#     restrict,command="ssh-exec.sh serve WORK COMMAND [ARG...]" ssh-ed25519 ...
#
# drive sends the job's inputs/ to HOST, runs COMMAND there in WORK/JOB with the runner's stdin (its workdir rewritten)
# and GPU grant, streams the command's output into the job log, brings back outputs/ and invoke-result.json when it
# exits 0, and deletes WORK/JOB. On SIGTERM it stops the remote command first and waits for it. serve answers only
# nvidia-smi --query-...=/--format=... (the runner reads HOST's GPUs through a --nvidia-smi wrapper), put, run, stop,
# get and drop of one job folder; it runs no command but its own, and both ends unpack only regular files and folders.
# Progress files are not relayed.
set -euo pipefail
untar='import sys, tarfile
with tarfile.open(fileobj=sys.stdin.buffer, mode="r|") as archive:
    for member in archive:
        if not (member.isreg() or member.isdir()):
            sys.exit("ssh-exec: refusing %s, not a regular file or folder" % member.name)
        archive.extract(member, sys.argv[1], filter="data")'
grant='NVIDIA_VISIBLE_DEVICES|CUDA_VISIBLE_DEVICES|DISPATCH_GPU_INDEX|DISPATCH_GPU_UUID|DISPATCH_GPU_MEMORY_MB|DISPATCH_GPU_MODE|DISPATCH_RUNNER_ID|DISPATCH_RUNNER_NODE'
case ${1:-} in
drive)
  config=$2 host=$3
  request=$(cat)
  id=$(printf '%s' "$request" | python3 -c 'import json, sys; print(json.load(sys.stdin)["job_id"])')
  remote() { ssh -F "$config" "$host" "$@"; }
  vars=()
  for v in ${grant//|/ }; do [ -z "${!v+x}" ] || vars+=("$v=${!v}"); done
  tar -cf - inputs | remote put "$id"
  printf '%s' "$request" | remote run "$id" "${vars[@]}" &
  job=$!
  trap 'until remote stop "$id" || ! kill -0 "$job" 2> /dev/null; do sleep 1; done' TERM INT
  rc=0; wait "$job" || rc=$?
  while kill -0 "$job" 2> /dev/null; do rc=0; wait "$job" || rc=$?; done
  [ "$rc" != 0 ] || remote get "$id" | python3 -c "$untar" .
  remote drop "$id" || true
  exit "$rc" ;;
serve)
  work=$2; shift 2
  read -r -a words <<< "${SSH_ORIGINAL_COMMAND:-}"
  verb=${words[0]:-} id=${words[1]:-}
  if [ "$verb" = nvidia-smi ]; then
    for a in "${words[@]:1}"; do [[ $a =~ ^--(query-gpu|query-compute-apps|format)=[a-z_.,]+$ ]] || exit 2; done
    exec nvidia-smi "${words[@]:1}"
  fi
  [[ $id =~ ^[A-Za-z0-9_-]{1,64}$ ]] || { echo "ssh-exec: bad job id" >&2; exit 2; }
  dir=$work/$id
  case $verb in
  put) mkdir -p "$dir"; exec python3 -c "$untar" "$dir" ;;
  run)
    for kv in "${words[@]:2}"; do [[ $kv =~ ^($grant)=[A-Za-z0-9_.:,-]*$ ]] || exit 2; export "${kv?}"; done
    cd "$dir"; mkdir -p outputs
    python3 -c 'import json, sys; j = json.load(sys.stdin); j["workdir"] = sys.argv[1]; json.dump(j, sys.stdout)' "$dir" > request.json
    export DISPATCH_WORKDIR=$dir DISPATCH_PROGRESS_FILE=$dir/invoke-progress.json
    echo $$ > run.pid
    exec "$@" < request.json ;;
  stop)
    pid=$(cat "$dir/run.pid"); kill -TERM "$pid" 2> /dev/null || true
    while kill -0 "$pid" 2> /dev/null; do sleep 1; done ;;
  get) cd "$dir"; exec tar -cf - outputs invoke-result.json ;;
  drop) exec rm -rf -- "$dir" ;;
  *) echo "ssh-exec: unknown request" >&2; exit 2 ;;
  esac ;;
*) echo "usage: ssh-exec.sh drive SSH_CONFIG HOST | serve WORK COMMAND [ARG...]" >&2; exit 2 ;;
esac
