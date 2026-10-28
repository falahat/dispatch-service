#!/usr/bin/env bash
# Render reviewed public application settings; install units without starting jobs.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/common.sh"
environment= machine= image_source=() secrets=()
while (($#)); do
    [[ $# -ge 2 ]] || exit 2
    case $1 in
        --env) environment=$2; shift 2;;
        --machine) machine=$2; shift 2;;
        --from) [[ $2 == docker ]] || exit 2; image_source=(--from docker); shift 2;;
        --secret) [[ $# -ge 3 ]] || exit 2; secrets+=("$2" "$3"); shift 3;;
        *) exit 2;;
    esac
done
[[ -n $environment && -n $machine ]] || { echo 'usage: install.sh --env FILE --machine NAME [--from docker] [--secret NAME FILE]' >&2; exit 2; }
worker=$(resolve "$machine")
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
python3 - "$here" "$environment" "$stage" <<'PY'
import ipaddress, json, pathlib, re, shlex, shutil, sys
source, environment, stage = map(pathlib.Path, sys.argv[1:])
config = {}
for line in environment.read_text().splitlines():
    words = shlex.split(line, comments=True)
    if not words:
        continue
    if len(words) != 1 or '=' not in words[0]:
        raise ValueError('use one quoted KEY=value assignment per line; no shell code or secrets')
    key, value = words[0].split('=', 1)
    config[key] = value
required = {'NAME', 'RUNNER_IMAGE', 'COMPUTE_IMAGE', 'PLANE_ADDR', 'LANES', 'GPU', 'MODEL_EGRESS'}
optional = {'SMOKESCREEN_IMAGE', 'MODEL_SUBNET', 'COMPUTE_ENV', 'COMPUTE_SECRETS', 'COMPUTE_ARGS', 'RUNNER_NODE'}
if required - config.keys() or config.keys() - required - optional:
    raise ValueError('missing or unknown remote-runner settings')
if any(any(ord(c) < 32 or c == '%' for c in value) for value in config.values()):
    raise ValueError('settings may not contain control characters or systemd specifiers')
if not re.fullmatch(r'[a-z][a-z0-9-]*', config['NAME']):
    raise ValueError('NAME must be a lowercase application identifier')
for name in ('RUNNER_IMAGE', 'COMPUTE_IMAGE', 'SMOKESCREEN_IMAGE'):
    if name in config and not re.fullmatch(r'[A-Za-z0-9_./:@+-]+', config[name]):
        raise ValueError('use a container image reference')
if not re.fullmatch(r'[A-Za-z0-9_.:\[\]-]+', config['PLANE_ADDR']) or not re.fullmatch(r'[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*', config['LANES']):
    raise ValueError('invalid plane address or lane names')
if config['GPU'] not in ('0', '1') or config['MODEL_EGRESS'] not in ('0', '1'):
    raise ValueError('GPU and MODEL_EGRESS must be 0 or 1')
config.setdefault('RUNNER_NODE', config['NAME'] + '-%H')
options = []
if config['GPU'] == '1':
    options += ['AddDevice=nvidia.com/gpu=all', 'Volume=/var/lib/tailworker/locks:/var/lib/tailworker/locks:ro',
                'Environment=GPU_LOCK_DIR=/var/lib/tailworker/locks']
if config['MODEL_EGRESS'] == '1':
    if not config.get('SMOKESCREEN_IMAGE') or not config.get('MODEL_SUBNET'):
        raise ValueError('model egress requires SMOKESCREEN_IMAGE and a distinct MODEL_SUBNET')
    if not ipaddress.ip_network(config['MODEL_SUBNET'], strict=True).is_private:
        raise ValueError('model subnet must be private')
    options += ['Network=' + config['NAME'] + '-model.network',
                'Volume=' + config['NAME'] + '-model-cache.volume:/cache',
                'Environment=HTTP_PROXY=http://' + config['NAME'] + '-smokescreen:4750',
                'Environment=HTTPS_PROXY=http://' + config['NAME'] + '-smokescreen:4750', 'Environment=HF_HOME=/cache']
for value in shlex.split(config.get('COMPUTE_ENV', '')):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.+', value):
        raise ValueError('COMPUTE_ENV contains public KEY=value settings only')
    options.append('Environment=' + json.dumps(value))
for value in shlex.split(config.get('COMPUTE_SECRETS', '')):
    if not re.fullmatch(r'[A-Za-z0-9_.=,/-]+', value):
        raise ValueError('COMPUTE_SECRETS contains Podman secret names and mount options only')
    options.append('Secret=' + value)
if config.get('COMPUTE_ARGS'):
    options.append('Exec=' + ' '.join(json.dumps(value) for value in shlex.split(config['COMPUTE_ARGS'])))
config['COMPUTE_OPTIONS'] = '\n'.join(options)
for path in source.iterdir():
    if path.suffix not in ('.container', '.network', '.volume'):
        continue
    if 'model' in path.name or 'smokescreen' in path.name:
        if config['MODEL_EGRESS'] != '1':
            continue
    text = path.read_text()
    for name, value in config.items():
        text = text.replace('@' + name + '@', value)
    if re.search(r'@[A-Z_]+@', text):
        raise ValueError('unresolved unit placeholder')
    (stage / path.name.replace('plane-', config['NAME'] + '-', 1)).write_text(text)
(stage / 'name').write_text(config['NAME'] + '\n')
(stage / 'images').write_text('\n'.join(config[key] for key in
                                     ('RUNNER_IMAGE', 'COMPUTE_IMAGE', 'SMOKESCREEN_IMAGE') if config.get(key)) + '\n')
if config['MODEL_EGRESS'] == '1':
    shutil.copytree(source.parent / 'smokescreen', stage / 'smokescreen',
                    ignore=shutil.ignore_patterns('*.go', 'go.*', 'Dockerfile'))
PY
while IFS= read -r image; do
    tailworker image send "$image" --to "$machine" "${image_source[@]}"
done <"$stage/images"
tar -C "$stage" -cf - . | remote "$worker" bash -c '
set -euo pipefail
[[ $(id -u) != 0 && $(podman info --format "{{.Host.Security.Rootless}}") == true ]]
stage=$(mktemp -d); trap '\''rm -rf -- "$stage"'\'' EXIT
tar -xf - -C "$stage"
name=$(<"$stage/name"); [[ $name =~ ^[a-z][a-z0-9-]*$ ]]
if systemctl --user is-active --quiet "$name-runner.service" "$name-compute.service" "$name-smokescreen.service"; then
    echo "Stop this application runner explicitly before replacing its units." >&2; exit 2
fi
install -d -m 700 "$HOME/.config/containers/systemd" "$HOME/.config/plane-runners/$name/cred"
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
    remote "$worker" podman secret create --ignore "$name-$secret" - <"$file" >/dev/null
done
