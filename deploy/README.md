# Shared deployment kit

Tailworker owns approved environments, private SSH and machine discovery.
Dispatch-service owns queue/runner credentials and service installation.
Applications supply queue policy, workload configuration and the signer command.
All state lives outside Git in private owned directories.

## Coordinator

Install reviewed binaries at `ROOT/bin/runner`, this kit at `ROOT/dispatch/kit`,
and copy `plane.sh` to `ROOT/bin/plane.sh`. Supply `ROOT/dispatch/plane.json`:

```json
{"address":"100.64.0.1","runner_port":7443,"cas_port":8443,"dispatcher_image":"sha256:REVIEWED","auth_image":"sha256:REVIEWED","cas_image":"registry/IMAGE@sha256:REVIEWED"}
```

Supply the application's `ROOT/dispatch/plane.toml`. Its backend endpoints must
be `runner_listen="127.0.0.1:7700"`, `app_socket="/work/plane/app.sock"`,
`app_listen=""`, and `db_path="/work/plane/queue.db"`. All other queue settings
belong to the application. Run `bash ROOT/bin/plane.sh ROOT init`; only the PEP's
private ports are published. Images are pinned to installed IDs. The issuer
stays in `ROOT/secrets`; `info` reports public enrollment settings and `sign`
provides the shared signer adapter. Compute never receives issuer credentials.

## Workers

The same installer and enrollment lifecycle serve both executor types:

```sh
bash deploy/remote-runner/worker.sh apply --env APP.env --machine MACHINE --signer COMMAND --client COMMAND --note NOTE
bash deploy/remote-runner/worker.sh status --env APP.env --machine MACHINE --client COMMAND
```

Add `--runner REVIEWED_BINARY` for an owner-reviewed command executor;
HTTP compute instead declares its pinned runner/compute images. Public settings
and supported fields are documented in the [README](../README.md#add-a-worker).
No shell code or secret values belong in APP.env. Optional `--secret NAME FILE`
installs an owned mode-0600 provider secret only for HTTP compute.

Installation starts nothing and refuses active application units. Enrollment
creates a unique worker credential, signs only its public key through standard
input, and starts that application's runner; unit dependencies start the rest,
as at boot. The runner starts its compute, and with model egress compute starts
its smokescreen guard first. Each restarts after a failure, and compute after any
exit (INVOKE.md): they only want each
other, since a requirement would leave the rest down for good when one fails at
boot. A compute restart leaves its runner running, taking no lease until compute
is ready again.
Existing credentials are refused;
inspect partial setup before repeating it. Key revocation remains with the
application signer. No cloud API, network-policy change or machine creation is
part of this kit. `test-install.sh` tests both adapters without real credentials
or services; the hand-written auth/egress tests remain unchanged.

`worker.sh` is the shared lifecycle. It validates the public profile before
draining, waits for the runners to exit cleanly, replaces only this profile's
units, preserves credentials with unchanged coordinator/lane scope, then resumes
admission and requires a fresh healthy fleet heartbeat. A runner hears its drain
only through the dispatcher: one the fleet has shown offline for `--reconnect-grace`
(60 s) in a row stops apply, with the drain left in place, and `status` waits as long
for a running worker to be ready, so a runner reconnecting after the coordinator
restarts is not taken for gone. First enrollment still
creates unique credentials. `--client` is the application's fixed private
`dispatchctl` command prefix; the kit appends fleet/drain/resume arguments.
HTTP profiles declare explicit `MEMORY` and `CPUS` limits. Images transfer only
from rootless Podman, are pinned to local image IDs, and status checks both
installed and running identities against the reviewed profile. Provider secret
rotation replaces only the namespaced Podman secret while compute is stopped.
Podman's `:U` option owns only the profile's named work/model volumes for its
container user; host credential and policy mounts stay read-only.
No execution deadline or automatic replay is added.
