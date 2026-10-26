#!/usr/bin/env bash
# Job traffic uses ordinary pinned OpenSSH, never forwarding or Tailscale SSH.
set -euo pipefail
set +x
umask 077
remote() {
    local destination=$1; shift
    if [[ $destination == local ]]; then "$@"; return; fi
    [[ $destination =~ ^[A-Za-z0-9_][A-Za-z0-9_.@-]*$ ]] || return 2
    ssh -T -x -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o ForwardAgent=no -o ClearAllForwardings=yes -o PermitLocalCommand=no \
        -o ProxyCommand=none -o ProxyJump=none -o ConnectTimeout=5 \
        -o ConnectionAttempts=1 "$destination" "$(printf '%q ' "$@")"
}
