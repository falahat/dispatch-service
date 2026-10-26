#!/usr/bin/env bash
# Render reviewed public application settings; install units without starting jobs.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/common.sh"
environment= worker=
while (($#)); do
    [[ $# -ge 2 ]] || exit 2
    case $1 in --env) environment=$2;; --worker) worker=$2;; *) exit 2;; esac
    shift 2
done
[[ -n $environment && -n $worker ]] || { echo 'usage: install.sh --env FILE --worker DESTINATION|local' >&2; exit 2; }
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
required = {'RUNNER_IMAGE', 'COMPUTE_IMAGE', 'PLANE_ADDR', 'LANES', 'GPU', 'MODEL_EGRESS'}
optional = {'SMOKESCREEN_IMAGE', 'MODEL_SUBNET', 'COMPUTE_ENV', 'COMPUTE_SECRETS', 'RUNNER_NODE'}
if required - config.keys() or config.keys() - required - optional:
    raise ValueError('missing or unknown remote-runner settings')
if any(any(ord(c) < 32 or c == '%' for c in value) for value in config.values()):
    raise ValueError('settings may not contain control characters or systemd specifiers')
for name in ('RUNNER_IMAGE', 'COMPUTE_IMAGE', 'SMOKESCREEN_IMAGE'):
    if name in config and not re.fullmatch(r'[A-Za-z0-9_./:@+-]+', config[name]):
        raise ValueError('use a container image reference')
if not re.fullmatch(r'[A-Za-z0-9_.:\[\]-]+', config['PLANE_ADDR']) or not re.fullmatch(r'[A-Za-z0-9_.-]+(?:,[A-Za-z0-9_.-]+)*', config['LANES']):
    raise ValueError('invalid plane address or lane names')
if config['GPU'] not in ('0', '1') or config['MODEL_EGRESS'] not in ('0', '1'):
    raise ValueError('GPU and MODEL_EGRESS must be 0 or 1')
config.setdefault('RUNNER_NODE', '%H')
options = []
if config['GPU'] == '1':
    options += ['AddDevice=nvidia.com/gpu=all', 'Volume=/var/lib/tailworker/locks:/var/lib/tailworker/locks:ro',
                'Environment=GPU_LOCK_DIR=/var/lib/tailworker/locks']
if config['MODEL_EGRESS'] == '1':
    if not config.get('SMOKESCREEN_IMAGE'):
        raise ValueError('model egress requires SMOKESCREEN_IMAGE')
    config.setdefault('MODEL_SUBNET', '172.30.0.0/24')
    if not ipaddress.ip_network(config['MODEL_SUBNET']).is_private:
        raise ValueError('model subnet must be private')
    options += ['Network=plane-model.network', 'Volume=plane-model-cache.volume:/cache',
                'Environment=HTTP_PROXY=http://plane-smokescreen:4750',
                'Environment=HTTPS_PROXY=http://plane-smokescreen:4750', 'Environment=HF_HOME=/cache']
for value in shlex.split(config.get('COMPUTE_ENV', '')):
    if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*=.+', value):
        raise ValueError('COMPUTE_ENV contains public KEY=value settings only')
    options.append('Environment=' + json.dumps(value))
for value in shlex.split(config.get('COMPUTE_SECRETS', '')):
    if not re.fullmatch(r'[A-Za-z0-9_.=,/-]+', value):
        raise ValueError('COMPUTE_SECRETS contains Podman secret names and mount options only')
    options.append('Secret=' + value)
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
    (stage / path.name).write_text(text)
if config['MODEL_EGRESS'] == '1':
    shutil.copytree(source.parent / 'smokescreen', stage / 'smokescreen',
                    ignore=shutil.ignore_patterns('*.go', 'go.*', 'Dockerfile'))
PY
tar -C "$stage" -cf - . | remote "$worker" bash -c '
set -euo pipefail
[[ $(id -u) != 0 && $(podman info --format "{{.Host.Security.Rootless}}") == true ]]
if systemctl --user is-active --quiet plane-runner.service plane-compute.service plane-smokescreen.service; then
    echo "Stop the existing kit services explicitly before replacing their units." >&2; exit 2
fi
stage=$(mktemp -d); trap '\''rm -rf -- "$stage"'\'' EXIT
tar -xf - -C "$stage"
install -d -m 700 "$HOME/.config/containers/systemd" "$HOME/.config/plane-runner/cred"
if [[ -d $stage/smokescreen ]]; then
    install -d -m 700 "$HOME/.config/plane-runner/smokescreen"
    install -m 600 "$stage"/smokescreen/*.yaml "$HOME/.config/plane-runner/smokescreen/"
fi
for file in "$stage"/*.container "$stage"/*.network "$stage"/*.volume; do
    install -m 600 "$file" "$HOME/.config/containers/systemd/"
done
for name in plane-smokescreen.container plane-model.network plane-model-cache.volume; do
    [[ -f $stage/$name ]] || rm -f -- "$HOME/.config/containers/systemd/$name"
done
systemctl --user daemon-reload
echo "Remote-runner units installed; no service was started."
'
