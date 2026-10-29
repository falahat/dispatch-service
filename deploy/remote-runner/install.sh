#!/usr/bin/env bash
# Render reviewed public application settings; install units without starting jobs.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/common.sh"
environment= machine= binary= secrets=()
while (($#)); do
    [[ $# -ge 2 ]] || exit 2
    case $1 in
        --env) environment=$2; shift 2;;
        --machine) machine=$2; shift 2;;
        --runner) binary=$2; [[ -f $binary ]]; shift 2;;
        --secret) [[ $# -ge 3 ]] || exit 2; secrets+=("$2" "$3"); shift 3;;
        *) exit 2;;
    esac
done
[[ -n $environment && -n $machine ]] || { echo 'usage: install.sh --env FILE --machine NAME [--runner BINARY] [--secret NAME FILE]' >&2; exit 2; }
[[ -z $binary || ${#secrets[@]} == 0 ]] || { echo '--runner does not use provider-secret options' >&2; exit 2; }
worker=$(resolve "$machine")
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
python3 -I "$here/worker_profile.py" "$here" "$environment" "$stage" "$binary"
if [[ -n $binary ]]; then install -m 700 "$binary" "$stage/runner"
else
    while IFS= read -r image; do tailworker image send "$image" --to "$machine"; done <"$stage/images"
fi
tar -C "$stage" -cf - . | remote "$worker" bash -c '
set -euo pipefail
[[ $(id -u) != 0 && $(podman info --format "{{.Host.Security.Rootless}}") == true ]]
stage=$(mktemp -d); trap '\''rm -rf -- "$stage"'\'' EXIT
tar -xf - -C "$stage"
name=$(<"$stage/name"); [[ $name =~ ^[a-z][a-z0-9-]*$ ]]
if systemctl --user is-active --quiet "$name-runner.service" "$name-runner@*.service" "$name-compute.service" "$name-smokescreen.service"; then
    echo "Stop this application runner explicitly before replacing its units." >&2; exit 2
fi
install -d -m 700 "$HOME/.config/containers/systemd" "$HOME/.config/plane-runners/$name/cred"
base=$HOME/.config/plane-runners/$name
install -m 600 "$stage/profile.json" "$base/profile.json"
if [[ -f $stage/runner ]]; then
    install -m 700 "$stage/runner" "$base/runner"
    install -d -m 700 "$HOME/.config/systemd/user"
    sed "s|@BASE@|$base|g" "$stage/runner.service" >"$HOME/.config/systemd/user/$name-runner@.service"
else
if [[ -d $stage/smokescreen ]]; then
    install -d -m 700 "$HOME/.config/plane-runners/$name/smokescreen"
    install -m 600 "$stage"/smokescreen/*.yaml "$HOME/.config/plane-runners/$name/smokescreen/"
fi
for file in "$stage"/*.container "$stage"/*.network "$stage"/*.volume; do
    if [[ $file == *.container ]]; then
        image=$(sed -n "s/^Image=//p" "$file")
        identity=$(podman image inspect --format "{{.Id}}" "$image")
        identity=${identity#sha256:}; [[ $identity =~ ^[0-9a-f]{64}$ ]]
        sed -i "s|^Image=.*|Image=sha256:$identity|" "$file"
    fi
    install -m 600 "$file" "$HOME/.config/containers/systemd/"
done
for suffix in smokescreen.container model.network model-cache.volume; do
    [[ -f $stage/$name-$suffix ]] || rm -f -- "$HOME/.config/containers/systemd/$name-$suffix"
done
python3 -c '\''import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); value=json.loads(p.read_text()); units=pathlib.Path(sys.argv[2]); name=value["NAME"]
for key,role in [("RUNNER_IMAGE","runner"),("COMPUTE_IMAGE","compute"),("SMOKESCREEN_IMAGE","smokescreen")]:
 if key in value: value[key]=next(line[6:] for line in (units/(name+"-"+role+".container")).read_text().splitlines() if line.startswith("Image="))
p.write_text(json.dumps(value))'\'' "$base/profile.json" "$HOME/.config/containers/systemd"
fi
systemctl --user daemon-reload
echo "Remote-runner units installed; no service was started."
'
name=$(<"$stage/name")
for ((i=0; i<${#secrets[@]}; i+=2)); do
    secret=${secrets[i]} file=${secrets[i+1]}
    [[ $secret =~ ^[a-z][a-z0-9_-]*$ ]] || exit 2
    python3 - "$file" <<'PY'
import os, pathlib, stat, sys
info = pathlib.Path(sys.argv[1]).lstat()
if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o077:
    raise ValueError('secret must be an owned mode-0600 regular file')
PY
    cat "$file" | remote "$worker" podman secret create --replace "$name-$secret" - >/dev/null
done
