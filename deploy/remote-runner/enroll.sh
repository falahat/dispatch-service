#!/usr/bin/env bash
# The seed stays on its worker; only the public key and signed biscuit cross SSH.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/common.sh"
machine= name= signer= lanes= note=
while (($#)); do
    [[ $# -ge 2 ]] || exit 2
    case $1 in --machine) machine=$2;; --name) name=$2;; --signer) signer=$2;; --lanes) lanes=$2;; --note) note=$2;; *) exit 2;; esac
    shift 2
done
[[ -n $machine && $name =~ ^[a-z][a-z0-9-]*$ && -n $signer && -n $lanes && -n $note ]] || {
    echo 'usage: enroll.sh --name APP --machine NAME --signer COMMAND --lanes LANES --note NOTE' >&2; exit 2;
}
worker=$(resolve "$machine")
public=$(remote "$worker" bash -c '
set -euo pipefail
name=$1; lanes=$2
unit=$HOME/.config/containers/systemd/$name-runner.container
grep -Fx "Environment=LANES=$lanes" "$unit" >/dev/null
image=$(sed -n "s/^Image=//p" "$unit")
[[ -n $image && ! -e $HOME/.config/plane-runners/$name/cred/runner.json ]]
podman run --rm --pull=never --network=none --user 1000:1000 \
    --userns=keep-id:uid=1000,gid=1000 --read-only --cap-drop=all \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev \
    -v "$HOME/.config/plane-runners/$name/cred:/run/plane-cred:rw" \
    "$image" keygen --out /run/plane-cred/runner.json
' _ "$name" "$lanes")
[[ $public =~ ^[0-9a-f]{64}$ ]] || { echo 'runner returned no valid public key' >&2; exit 1; }
# The application's signer owns rights and lane scope; the kit grants none.
bash -c "$signer \"\$@\"" _ --pubkey "$public" --note "$note" | remote "$worker" bash -c '
set -euo pipefail
name=$1
image=$(sed -n "s/^Image=//p" "$HOME/.config/containers/systemd/$name-runner.container")
podman run --rm -i --pull=never --network=none --user 1000:1000 \
    --userns=keep-id:uid=1000,gid=1000 --read-only --cap-drop=all \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev \
    -v "$HOME/.config/plane-runners/$name/cred:/run/plane-cred:rw" \
    "$image" seal --cred /run/plane-cred/runner.json --biscuit-file -
if [[ -f $HOME/.config/containers/systemd/$name-smokescreen.container ]]; then
    systemctl --user start "$name-smokescreen.service"
fi
systemctl --user start "$name-runner.service"
' _ "$name"
printf 'Runner public key for revocation: %s\n' "$public"
