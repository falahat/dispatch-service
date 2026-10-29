#!/usr/bin/env bash
# tailworker owns private SSH policy; runtime work uses the PEP doors.
set -euo pipefail
set +x
umask 077
resolve() {
    tailworker resolve "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["host"])'
}
remote() {
    local destination=$1; shift
    if [[ $destination == local ]]; then "$@"; return; fi
    local -a transport
    mapfile -d '' -t transport < <(tailworker ssh-argv "$destination" --null)
    (("${#transport[@]}")) && [[ ${transport[0]} == ssh ]] || return 2
    "${transport[@]}" "$(printf '%q ' "$@")"
}
