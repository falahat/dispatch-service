# Local integration deployment

`compose.dev.yml` is a standalone integration stack for the plane. It is not the
easy-podcast production deployment. easy-podcast owns the production topology and runs it
through
[`deploy/easypod`](https://github.com/falahat/easy-podcast/blob/main/deploy/easypod).

## Topology

| Network | Members | Host exposure |
|---|---|---|
| `backplane` | PEP, dispatcher, CAS | none |
| `edge` | PEP and runner | PEP ports `7443` and `8443` |
| `invoke` | runner and echo compute | none |

The echo compute has no credential and no internet route. Application deployments add
their own compute and ingest egress guards on separate internal networks.

## Start

```sh
./deploy/bootstrap.sh embed
docker compose -f compose.dev.yml up --build
```

Bootstrap preserves an existing issuer key and pairing registry, writes the issuer public
key to `.env`, and creates a mode-`0600` runner credential under `deploy/cred/`. The private
holder seed stays in that credential file.

Stop and remove the local containers with:

```sh
docker compose -f compose.dev.yml down
```

The CAS rewrites Bazel Remote Cache paths behind the PEP. The default priced-work cap is
`$0.00`, so this stack cannot admit cloud-priced work.

## Remote runners

The `remote-runner/` kit installs the same rootless Podman Quadlets on an owned
machine or a tailworker SSH destination. Machine provisioning, private networking,
host pins and GPU locks belong to tailworker. Every application keeps its own
plane, signer, credentials and data policy. The kit adds no trust root or queue.
It never creates a machine or changes its network policy. Use ordinary pinned
OpenSSH; Tailscale SSH and forwarding are disabled for automation.

An application's reviewed `deploy/remote-runner.env` contains public settings:

```sh
RUNNER_IMAGE=registry.example/runner:reviewed
COMPUTE_IMAGE=registry.example/compute:reviewed
PLANE_ADDR=app-plane
LANES=embed
GPU=0
MODEL_EGRESS=0
# With model downloads: MODEL_EGRESS=1 and a reviewed SMOKESCREEN_IMAGE.
# MODEL_SUBNET defaults to 172.30.0.0/24 and is the proxy's model role network.
# COMPUTE_ENV='PUBLIC_SETTING=value OTHER_SETTING=value'
# COMPUTE_SECRETS='secret-name,type=mount,target=/run/secrets/model-token'
# RUNNER_NODE=operator-chosen-name  (default: the worker hostname)
```

Assignments use shell quoting but contain no shell code or secret values. Create
Podman secrets separately from protected standard input on their machine. Image
references are copied there with `tailworker image send`; the units never pull.
GPU images must implement tailworker's resident-model lock protocol and receive
its lock directory read-only. Compute is on an internal invoke network; only
model downloads add its internal model network and the constrained egress proxy.
The runner reaches its PEP through a separate network, without exposing ports.

On the control host, install public units without starting any services:

```sh
bash deploy/remote-runner/install.sh --env path/to/remote-runner.env --worker tw-NAME
```

Use `--worker local` when running on that machine itself. Installation refuses
active services of this kit; stop those explicitly before updating. It never
stops unrelated services. After installation, the owner enrolls the runner:

```sh
bash deploy/remote-runner/enroll.sh --worker tw-NAME \
  --signer 'path/to/application sign-runner' --lanes embed --note 'test worker'
```

The signer command accepts `--pubkey HEX --note NOTE`; its application owns
rights and lane scope. `--lanes` must match the installed runner, and grants no
additional authority. Key generation happens in an offline rootless container
on the worker. Its seed stays in the owned mode-0600 credential file. The signed
biscuit goes through standard input into `runner seal`, then the kit starts its
runner and compute (and proxy when configured). Only the public revocation key
is printed. Never enroll production credentials without the owner's approval.

Revoke with that application's existing command and verify denial on the next
request. Stop `plane-runner.service`, `plane-compute.service` and, when present,
`plane-smokescreen.service` through `systemctl --user` to disable the runner.
Do not delete or revoke another application's credentials. The kit's functional
echo check is distinct from the owner's hand-written adversarial auth/egress
tests; those tests remain required and are never generated or weakened here.
