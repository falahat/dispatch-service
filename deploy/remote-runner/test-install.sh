#!/usr/bin/env bash
# Functional unit rendering only; this fixture starts no services or containers.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
temporary=$(mktemp -d)
trap 'rm -rf -- "$temporary"' EXIT
export HOME=$temporary/home
mkdir -p "$HOME" "$temporary/bin"
export PATH=$temporary/bin:$PATH
# The renderer's host identity is controlled; the surrounding test container may
# use UID 0 inside its rootless user namespace.
cat >"$temporary/bin/id" <<'SH'
#!/bin/sh
test "$1" = -u
printf '1000\n'
SH
cat >"$temporary/bin/podman" <<'SH'
#!/bin/sh
case "$1" in
  info) printf 'true\n';;
  image) printf 'sha256:%064d\n' 1;;
  secret) cat >/dev/null;;
  run)
    case " $* " in
      *' keygen '*) printf '%064d\n' 0;;
      *' seal '*) cat >/dev/null;;
      *) exit 92;;
    esac;;
  *) exit 91;;
esac
SH
cat >"$temporary/bin/systemctl" <<'SH'
#!/bin/sh
case "$2" in
  is-active) exit 3;;
  daemon-reload) exit 0;;
  enable) echo "$4" >>"$HOME/started"; rm -f "$HOME/$4.inactive";;
  start) echo "$3" >>"$HOME/started"; rm -f "$HOME/$3.inactive";;
  show)
    if test -e "$HOME/$3.inactive"; then echo ActiveState=inactive; else echo ActiveState=active; fi
    echo Result=success;;
  *) exit 91;;
esac
SH
cat >"$temporary/bin/tailworker" <<'SH'
#!/bin/sh
case "$1" in
  resolve) printf '{"host":"local"}\n';;
  image) echo "$*" >>"$HOME/images";;
  *) exit 91;;
esac
SH
chmod 700 "$temporary/bin/"*
cat >"$temporary/runner.env" <<'ENV'
NAME=first
RUNNER_IMAGE=runner:reviewed
COMPUTE_IMAGE=compute:reviewed
PLANE_ADDR=app-plane
LANES=embed
GPU=0
MODEL_EGRESS=0
MEMORY=4g
CPUS=2
ENV
bash "$here/install.sh" --env "$temporary/runner.env" --machine owned
units=$HOME/.config/containers/systemd
grep -Fx 'UserNS=keep-id:uid=1000,gid=1000' "$units/first-runner.container"
grep -Fx 'Volume=first-work.volume:/work:U' "$units/first-runner.container"
grep -Fx 'Volume=first-work.volume:/work:U' "$units/first-compute.container"
grep -Fx 'Environment=DISPATCHER_ADDR=app-plane:7443' "$units/first-runner.container"
grep -Fx 'Internal=true' "$units/first-invoke.network"
grep -Fx "Image=sha256:$(printf '%064d' 1)" "$units/first-compute.container"
grep -Fx 'PodmanArgs=--memory=4g --memory-swap=4g --cpus=2 --pids-limit=8192' "$units/first-compute.container"
test ! -e "$units/first-model.network"
test ! -e "$units/first-smokescreen.container"
sed 's/NAME=first/NAME=second/' "$temporary/runner.env" >"$temporary/second.env"
bash "$here/install.sh" --env "$temporary/second.env" --machine owned
cp "$units/second-runner.container" "$temporary/second.saved"
sed -i 's/GPU=0/GPU=1/; s/MODEL_EGRESS=0/MODEL_EGRESS=1/' "$temporary/runner.env"
printf '%s\n' 'SMOKESCREEN_IMAGE=proxy:reviewed' 'MODEL_SUBNET=172.30.0.0/24' \
    'COMPUTE_ENV="PUBLIC_SETTING=value"' 'COMPUTE_ARGS="--public value"' \
    'COMPUTE_SECRETS="first-provider,target=provider"' >>"$temporary/runner.env"
printf 'fixture-only\n' >"$temporary/provider"; chmod 600 "$temporary/provider"
bash "$here/install.sh" --env "$temporary/runner.env" --machine owned --secret provider "$temporary/provider"
grep -Fx 'AddDevice=nvidia.com/gpu=all' "$units/first-compute.container"
grep -Fx 'Volume=/var/lib/tailworker/locks:/var/lib/tailworker/locks:ro' "$units/first-compute.container"
grep -Fx 'Environment=SMOKESCREEN_ROLE_NETS=172.30.0.0/24=model' "$units/first-smokescreen.container"
grep -Fx 'Exec="--public" "value"' "$units/first-compute.container"
grep -Fx 'Internal=true' "$units/first-model.network"
test -f "$HOME/.config/plane-runners/first/smokescreen/allowlist.yaml"
test -f "$HOME/.config/plane-runners/first/smokescreen/config.yaml"
cmp "$temporary/second.saved" "$units/second-runner.container"
bash "$here/enroll.sh" --name first --machine owned --signer 'printf signed-fixture' --lanes embed --note fixture
grep -Fx first-runner.service "$HOME/started"
grep -Fx first-smokescreen.service "$HOME/started"
sed -i 's/GPU=1/GPU=0/; s/MODEL_EGRESS=1/MODEL_EGRESS=0/' "$temporary/runner.env"
bash "$here/install.sh" --env "$temporary/runner.env" --machine owned
test ! -e "$units/first-smokescreen.container"
test ! -e "$units/first-model.network"
cmp "$temporary/second.saved" "$units/second-runner.container"
cat >"$temporary/runner" <<'SH'
#!/bin/sh
case "$1" in
  keygen)
    test ! -e "$3"
    python3 - "$3" <<'PY'
import hashlib, json, pathlib, sys
path = pathlib.Path(sys.argv[1])
public = hashlib.sha256(str(path).encode()).hexdigest()
path.write_text(json.dumps(dict(pubkey_hex=public, seed_b64='fixture-only')))
path.chmod(0o600)
print(public)
PY
    ;;
  seal)
    test -f "$3"; cat >/dev/null
    python3 - "$3" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1]); value = json.loads(path.read_text())
value['biscuit'] = 'signed-fixture'; path.write_text(json.dumps(value))
PY
    ;;
  *) exit 92;;
esac
SH
chmod 700 "$temporary/runner"
cat >"$temporary/command.env" <<'ENV'
NAME=command
DISPATCHER_ADDR=100.64.0.1:7443
CAS_URL=http://100.64.0.1:8443
LANES=build
RUNNER_NODE=worker
WORK_ROOT=/work/jobs
COMMAND='/usr/bin/python3 /work/executor.py'
COUNT=2
NO_DEADLINE=1
ENV
bash "$here/install.sh" --env "$temporary/command.env" --machine owned --runner "$temporary/runner"
unit=$HOME/.config/systemd/user/command-runner@.service
grep -F -- '--no-deadline' "$unit"
grep -F -- '"/usr/bin/python3" "/work/executor.py"' "$unit"
bash "$here/enroll.sh" --name command --machine owned --signer 'printf signed-fixture' --note command
grep -Fx command-runner@1.service "$HOME/started"
grep -Fx command-runner@2.service "$HOME/started"
if bash "$here/enroll.sh" --name command --machine owned --signer 'printf signed-fixture' --note duplicate; then
    echo 'existing credentials were replaced' >&2; exit 1
fi
cat >"$temporary/client.py" <<'PY'
import json, pathlib, sys, time
home = pathlib.Path.home()
operation = sys.argv[1]
with (home / 'operations').open('a') as log:
    log.write(operation + '\n')
rows = []
for path in sorted((home / '.config/plane-runners/command/cred').glob('*.json')):
    identity = json.loads(path.read_text())['pubkey_hex']
    if operation == 'drain' and identity == sys.argv[2]:
        (home / ('command-runner@' + path.stem + '.service.inactive')).touch()
    rows.append(dict(runner_id=identity, online=True, draining=False,
                     quarantined=False, last_seen_ts=time.time_ns() // 1000000))
print(json.dumps(dict(runners=rows) if operation == 'fleet' else {}))
PY
cp "$HOME/.config/plane-runners/command/cred/1.json" "$temporary/credential.saved"
client="python3 $temporary/client.py"
bash "$here/worker.sh" apply --env "$temporary/command.env" --machine owned \
    --runner "$temporary/runner" --client "$client" --signer 'exit 99' --note update >"$temporary/status.json"
cmp "$temporary/credential.saved" "$HOME/.config/plane-runners/command/cred/1.json"
grep -Fx drain "$HOME/operations"
grep -Fx resume "$HOME/operations"
bash "$here/worker.sh" status --name command --machine owned --client "$client" >"$temporary/status.json"
python3 - "$temporary/status.json" <<'PY'
import json, sys
value = json.load(open(sys.argv[1]))
assert value['ready'] and len(value['runners']) == 2
assert 'seed_b64' not in open(sys.argv[1]).read()
PY
sed 's/LANES=build/LANES=other/' "$temporary/command.env" >"$temporary/changed.env"
cp "$HOME/operations" "$temporary/operations.saved"
if bash "$here/worker.sh" apply --env "$temporary/changed.env" --machine owned \
    --runner "$temporary/runner" --client "$client" --signer 'exit 99' --note invalid; then exit 1; fi
test "$(grep -c drain "$HOME/operations")" = "$(grep -c drain "$temporary/operations.saved")"
echo 'remote-runner unit rendering: green'
