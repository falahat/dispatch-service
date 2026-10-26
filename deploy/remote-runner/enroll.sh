#!/usr/bin/env bash
# The seed stays on its worker; only the public key and signed biscuit cross SSH.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/common.sh"
worker= signer= lanes= note=
while (($#)); do
    [[ $# -ge 2 ]] || exit 2
    case $1 in --worker) worker=$2;; --signer) signer=$2;; --lanes) lanes=$2;; --note) note=$2;; *) exit 2;; esac
    shift 2
done
[[ -n $worker && -n $signer && -n $lanes && -n $note ]] || {
    echo 'usage: enroll.sh --worker DESTINATION|local --signer COMMAND --lanes LANES --note NOTE' >&2; exit 2;
}
public=$(remote "$worker" bash -c '
set -euo pipefail
unit=$HOME/.config/containers/systemd/plane-runner.container
grep -Fx "Environment=LANES=$1" "$unit" >/dev/null
image=$(sed -n "s/^Image=//p" "$unit")
[[ -n $image && ! -e $HOME/.config/plane-runner/cred/runner.json ]]
podman run --rm --pull=never --network=none --user 1000:1000 \
    --userns=keep-id:uid=1000,gid=1000 --read-only --cap-drop=all \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev \
    -v "$HOME/.config/plane-runner/cred:/run/plane-cred:rw" \
    "$image" keygen --out /run/plane-cred/runner.json
' _ "$lanes")
[[ $public =~ ^[0-9a-f]{64}$ ]] || { echo 'runner returned no valid public key' >&2; exit 1; }
# The application's signer owns rights and lane scope; the kit grants none.
bash -c "$signer \"\$@\"" _ --pubkey "$public" --note "$note" | remote "$worker" bash -c '
set -euo pipefail
image=$(sed -n "s/^Image=//p" "$HOME/.config/containers/systemd/plane-runner.container")
podman run --rm -i --pull=never --network=none --user 1000:1000 \
    --userns=keep-id:uid=1000,gid=1000 --read-only --cap-drop=all \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev \
    -v "$HOME/.config/plane-runner/cred:/run/plane-cred:rw" \
    "$image" seal --cred /run/plane-cred/runner.json --biscuit-file -
if [[ -f $HOME/.config/containers/systemd/plane-smokescreen.container ]]; then
    systemctl --user start plane-smokescreen.service
fi
systemctl --user start plane-runner.service
'
printf 'Runner public key for revocation: %s\n' "$public"
