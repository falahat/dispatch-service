#!/usr/bin/env bash
# Installation uses pinned private OpenSSH; runtime work uses the PEP doors.
set -euo pipefail
set +x
umask 077
resolve() {
    tailworker resolve "$1" | python3 -c 'import json,sys; print(json.load(sys.stdin)["host"])'
}
remote() {
    local destination=$1; shift
    if [[ $destination == local ]]; then "$@"; return; fi
    [[ $destination =~ ^[A-Za-z0-9_][A-Za-z0-9_.@-]*$ ]] || return 2
    local -a transport=(ssh -T -x -o BatchMode=yes -o StrictHostKeyChecking=yes \
        -o ForwardAgent=no -o ClearAllForwardings=yes -o PermitLocalCommand=no \
        -o ProxyCommand=none -o ProxyJump=none -o ConnectTimeout=5 \
        -o ControlPath=none -o CanonicalizeHostname=no -o ConnectionAttempts=1)
    local -a pinned
    mapfile -t pinned < <("${transport[@]}" -G "$destination" | python3 -c '
import ipaddress, socket, sys
config = dict(line.strip().split(" ", 1) for line in sys.stdin if " " in line)
host = config["hostname"]
addresses = list(dict.fromkeys(row[4][0] for row in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)))
def private(value):
    ip = ipaddress.ip_address(value)
    ip = getattr(ip, "ipv4_mapped", None) or ip
    return any(ip in ipaddress.ip_network(net) for net in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "::1/128", "fc00::/7"))
if not addresses or not all(map(private, addresses)):
    raise ValueError("installation destination must resolve only to private addresses")
print(addresses[0]); print(config.get("hostkeyalias", host) if config.get("hostkeyalias") != "none" else host)
')
    ((${#pinned[@]} == 2)) || return 2
    "${transport[@]}" -o "HostName=${pinned[0]}" -o "HostKeyAlias=${pinned[1]}" \
        "$destination" "$(printf '%q ' "$@")"
}
