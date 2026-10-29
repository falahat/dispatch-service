#!/usr/bin/env bash
# Install the existing network runner with an owner-fixed host executor.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
source "$here/common.sh"
environment= machine= binary=
while (($#)); do
    [[ $# -ge 2 ]] || exit 2
    case $1 in --env) environment=$2;; --machine) machine=$2;; --runner) binary=$2;; *) exit 2;; esac
    shift 2
done
[[ -f $environment && -f $binary && -n $machine ]] || {
    echo 'usage: install-command.sh --env FILE --machine NAME --runner FILE' >&2; exit 2;
}
stage=$(mktemp -d); trap 'rm -rf -- "$stage"' EXIT
python3 - "$environment" "$stage" <<'PY'
import json, pathlib, re, shlex, sys
environment, stage = map(pathlib.Path, sys.argv[1:])
config = {}
for line in environment.read_text().splitlines():
    words = shlex.split(line, comments=True)
    if not words:
        continue
    if len(words) != 1 or '=' not in words[0]:
        raise ValueError('use quoted KEY=value assignments, without secrets')
    key, value = words[0].split('=', 1)
    if key in config or any(ord(c) < 32 or c == '%' for c in value):
        raise ValueError('duplicate setting, control character or systemd specifier')
    config[key] = value
required = {'NAME', 'DISPATCHER_ADDR', 'CAS_URL', 'LANES', 'RUNNER_NODE', 'WORK_ROOT', 'COMMAND', 'COUNT'}
if required - config.keys() or config.keys() - required - {'NO_DEADLINE'}:
    raise ValueError('missing or unknown command-runner setting')
if not re.fullmatch(r'[a-z][a-z0-9-]*', config['NAME']) or not 1 <= int(config['COUNT']) <= 64:
    raise ValueError('invalid name or instance count')
if not all(re.fullmatch(r'[a-z0-9-]{1,32}', lane) for lane in config['LANES'].split(',')):
    raise ValueError('invalid lanes')
if not pathlib.Path(config['WORK_ROOT']).is_absolute() or config.get('NO_DEADLINE', '0') not in ('0', '1'):
    raise ValueError('invalid work root or deadline setting')
command = shlex.split(config['COMMAND'])
if not command or not pathlib.Path(command[0]).is_absolute():
    raise ValueError('COMMAND must start with an absolute installed executable')
(stage / 'profile.json').write_text(json.dumps(config))
args = ['run', '--credential', '@BASE@/cred/%i.json', '--dispatcher', config['DISPATCHER_ADDR'],
        '--cas', config['CAS_URL'], '--node', config['RUNNER_NODE'], '--lanes', config['LANES'],
        '--work', config['WORK_ROOT']]
if config.get('NO_DEADLINE') == '1':
    args += ['--no-deadline']
args += ['--', *command]
(stage / 'runner.service').write_text('''[Unit]
Description=Authenticated command worker
After=network-online.target
StartLimitIntervalSec=0
[Service]
ExecStart="@BASE@/runner" ''' + ' '.join(json.dumps(arg) for arg in args) + '''
KillMode=process
TimeoutStopSec=infinity
Restart=on-failure
RestartSec=5s
UMask=0077
[Install]
WantedBy=default.target
''')
PY
install -m 700 "$binary" "$stage/runner"
tar -C "$stage" -cf - . | remote "$(resolve "$machine")" bash -c '
set -euo pipefail
[[ $(id -u) != 0 && $(podman info --format "{{.Host.Security.Rootless}}") == true ]]
stage=$(mktemp -d); trap '\''rm -rf -- "$stage"'\'' EXIT
tar -xf - -C "$stage"
name=$(python3 -c '\''import json,sys; print(json.load(open(sys.argv[1]))["NAME"])'\'' "$stage/profile.json")
base=$HOME/.config/plane-runners/$name
if systemctl --user is-active --quiet "$name-runner@*.service"; then
    echo "Stop this application runner explicitly before replacing it." >&2; exit 2
fi
install -d -m 700 "$base/cred" "$HOME/.config/systemd/user"
install -m 700 "$stage/runner" "$base/runner"
install -m 600 "$stage/profile.json" "$base/profile.json"
sed "s|@BASE@|$base|g" "$stage/runner.service" >"$HOME/.config/systemd/user/$name-runner@.service"
systemctl --user daemon-reload
'
