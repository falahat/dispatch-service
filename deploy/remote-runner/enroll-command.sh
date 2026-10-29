#!/usr/bin/env bash
# Unique keys are generated on the worker; the application owns signing policy.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/common.sh"
name= machine= signer= note=
while (($#)); do
    [[ $# -ge 2 ]] || exit 2
    case $1 in --name) name=$2;; --machine) machine=$2;; --signer) signer=$2;; --note) note=$2;; *) exit 2;; esac
    shift 2
done
[[ $name =~ ^[a-z][a-z0-9-]*$ && -n $machine && -n $signer && -n $note ]] || exit 2
worker=$(resolve "$machine")
count=$(remote "$worker" python3 -c 'import json,pathlib,sys; print(json.loads((pathlib.Path.home()/".config/plane-runners"/sys.argv[1]/"profile.json").read_text())["COUNT"])' "$name")
[[ $count =~ ^[0-9]+$ && $count -ge 1 && $count -le 64 ]] || exit 2
for ((i=1; i<=count; i++)); do
    public=$(remote "$worker" bash -c '
set -euo pipefail
base=$HOME/.config/plane-runners/$1; file=$base/cred/$2.json
[[ ! -e $file ]]
"$base/runner" keygen --out "$file"
' _ "$name" "$i")
    [[ $public =~ ^[0-9a-f]{64}$ ]] || exit 1
    bash -c "$signer \"\$@\"" _ --pubkey "$public" --note "$note/$i" | remote "$worker" bash -c '
set -euo pipefail
base=$HOME/.config/plane-runners/$1
"$base/runner" seal --cred "$base/cred/$2.json" --biscuit-file -
systemctl --user enable --now "$1-runner@$2.service"
' _ "$name" "$i"
    printf 'Runner public key for revocation: %s\n' "$public"
done
