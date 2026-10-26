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
test "$1" = info
printf 'true\n'
SH
cat >"$temporary/bin/systemctl" <<'SH'
#!/bin/sh
case "$2" in is-active) exit 3;; daemon-reload) exit 0;; *) exit 91;; esac
SH
chmod 700 "$temporary/bin/"*
cat >"$temporary/runner.env" <<'ENV'
RUNNER_IMAGE=runner:reviewed
COMPUTE_IMAGE=compute:reviewed
PLANE_ADDR=app-plane
LANES=embed
GPU=0
MODEL_EGRESS=0
ENV
bash "$here/install.sh" --env "$temporary/runner.env" --worker local
units=$HOME/.config/containers/systemd
grep -Fx 'UserNS=keep-id:uid=1000,gid=1000' "$units/plane-runner.container"
grep -Fx 'Environment=DISPATCHER_ADDR=app-plane:7443' "$units/plane-runner.container"
grep -Fx 'Internal=true' "$units/plane-invoke.network"
test ! -e "$units/plane-model.network"
test ! -e "$units/plane-smokescreen.container"
sed -i 's/GPU=0/GPU=1/; s/MODEL_EGRESS=0/MODEL_EGRESS=1/' "$temporary/runner.env"
printf '%s\n' 'SMOKESCREEN_IMAGE=proxy:reviewed' 'COMPUTE_ENV="PUBLIC_SETTING=value"' >>"$temporary/runner.env"
bash "$here/install.sh" --env "$temporary/runner.env" --worker local
grep -Fx 'AddDevice=nvidia.com/gpu=all' "$units/plane-compute.container"
grep -Fx 'Volume=/var/lib/tailworker/locks:/var/lib/tailworker/locks:ro' "$units/plane-compute.container"
grep -Fx 'Environment=SMOKESCREEN_ROLE_NETS=172.30.0.0/24=model' "$units/plane-smokescreen.container"
grep -Fx 'Internal=true' "$units/plane-model.network"
test -f "$HOME/.config/plane-runner/smokescreen/allowlist.yaml"
test -f "$HOME/.config/plane-runner/smokescreen/config.yaml"
sed -i 's/GPU=1/GPU=0/; s/MODEL_EGRESS=1/MODEL_EGRESS=0/' "$temporary/runner.env"
bash "$here/install.sh" --env "$temporary/runner.env" --worker local
test ! -e "$units/plane-smokescreen.container"
test ! -e "$units/plane-model.network"
echo 'remote-runner unit rendering: green'
