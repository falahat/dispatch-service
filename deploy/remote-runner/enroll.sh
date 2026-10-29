#!/usr/bin/env bash
# The seed stays on its worker; both executor adapters use this enrollment.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/common.sh"
machine= name= signer= lanes= note=
while (($#)); do
    [[ $# -ge 2 ]] || exit 2
    case $1 in --machine) machine=$2;; --name) name=$2;; --signer) signer=$2;; --lanes) lanes=$2;; --note) note=$2;; *) exit 2;; esac
    shift 2
done
[[ -n $machine && $name =~ ^[a-z][a-z0-9-]*$ && -n $signer && -n $note ]] || {
    echo 'usage: enroll.sh --name APP --machine NAME --signer COMMAND [--lanes LANES] --note NOTE' >&2; exit 2;
}
worker=$(resolve "$machine")
mapfile -t profile < <(remote "$worker" python3 -c 'import json,pathlib,sys; p=json.loads((pathlib.Path.home()/".config/plane-runners"/sys.argv[1]/"profile.json").read_text()); print(p["COUNT"]); print(p["LANES"])' "$name")
[[ ${#profile[@]} == 2 && ${profile[0]} =~ ^[0-9]+$ && ${profile[0]} -ge 1 && ${profile[0]} -le 64 ]]
[[ -z $lanes || $lanes == "${profile[1]}" ]]
invoke='
set -euo pipefail
name=$1 instance=$2 action=$3
base=$HOME/.config/plane-runners/$name
mapfile -t config < <(python3 -c '\''import json,sys; p=json.load(open(sys.argv[1])); print(p["MODE"]); print(p.get("RUNNER_IMAGE",""))'\'' "$base/profile.json")
if [[ ${config[0]} == command ]]; then
    disk=$base/cred/$instance.json; file=$disk; runner=("$base/runner"); unit=$name-runner@$instance.service
else
    [[ ${config[0]} == http && ${config[1]} =~ ^sha256:[0-9a-f]{64}$ ]]
    disk=$base/cred/runner.json; file=/run/plane-cred/runner.json; unit=$name-runner.service
    runner=(podman run --rm -i --pull=never --network=none --user 1000:1000
        --userns=keep-id:uid=1000,gid=1000 --read-only --cap-drop=all
        --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev
        -v "$base/cred:/run/plane-cred:rw" "${config[1]}")
fi
if [[ $action == keygen ]]; then [[ ! -e $disk ]]; exec "${runner[@]}" keygen --out "$file"; fi
[[ $action == seal ]]
"${runner[@]}" seal --cred "$file" --biscuit-file -
if [[ ${config[0]} == command ]]; then systemctl --user enable --now "$unit"
else
    [[ ! -f $HOME/.config/containers/systemd/$name-smokescreen.container ]] || systemctl --user start "$name-smokescreen.service"
    systemctl --user start "$unit"
fi'
for ((i=1; i<=profile[0]; i++)); do
    public=$(remote "$worker" bash -c "$invoke" _ "$name" "$i" keygen)
    [[ $public =~ ^[0-9a-f]{64}$ ]] || { echo 'runner returned no valid public key' >&2; exit 1; }
    # The application's signer owns rights and lane scope; the kit grants none.
    bash -c "$signer \"\$@\"" _ --pubkey "$public" --note "$note/$i" | remote "$worker" bash -c "$invoke" _ "$name" "$i" seal
    printf 'Runner public key for revocation: %s\n' "$public"
done
