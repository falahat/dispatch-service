# dispatch-service

dispatch-service is the reusable GPU work plane used by easy-podcast and
antibody-analysis. It provides a durable queue, authenticated CAS, runner, isolated
compute protocol, and constrained egress. Each application deploys its own plane instance,
trust root, and runtime state; only the code and wire contracts are shared. The system
design lives in easy-podcast's
[dispatch-plane document](https://github.com/falahat/easy-podcast/blob/main/docs/DISPATCH_PLANE.md);
the decisions behind each contract change are in [docs/DISPATCH_PLANE.md](docs/DISPATCH_PLANE.md).

## Components

| Path | Responsibility |
|---|---|
| `contracts/` | Versioned wire, artifact, CAS, invoke, and state-machine contracts |
| `dispatcher/` | Durable queue, leases, fencing, retries, admission, and fleet state |
| `runner/` | Authenticated lease client, CAS transfer, and compute invocation |
| `auth/` | Biscuit/PoP PEPs, nonce and revocation stores, and isolated signer |
| `client/` | Application socket client and operator CLI |
| `deploy/smokescreen/` | Source-network egress roles and destination policy |
| `deploy/remote-runner/` | Install an application's runner/compute pair on an approved tailworker machine |
| `compute/echo/` | Credential-free fixture compute used by integration tests |

The schemas under `contracts/` are normative. Components reject unsupported contract
versions rather than negotiating mixed deployments.

## Installed command execution

The existing network runner can invoke either a paired HTTP compute container
or an owner-installed command. Both use the same PEP, CAS, queue, leases and
completion acknowledgements. Tailworker owns environment setup; the application
owns its workload command and persistence. See [the command contract](contracts/COMMAND.md).
A command that knows why its job failed reports the failure's class, so the job's
policy, not the application, decides whether it runs again.
The executor can publish opaque progress during execution without completing the job.
`job`, `jobs`, `wait` and exact submission `lookup` expose the same job view.
The operator CLI prints these native JSON results; `trace JOB` is an alias for
`job JOB`, including its full attempt timeline.
Install `client/` to get `dispatchctl -addr ADDRESS COMMAND [arguments]`.
It uses the same standard-library client as applications, with no automatic replay.
`dispatchctl run` uploads a command's inputs, runs it on a worker, streams its log and
fetches its outputs in one call ([run a command](client/README.md#run-a-command)). An input
that already lies on a worker's machine is passed in place (`--local`), and the job runs
there ([local artifacts](contracts/ARTIFACTS.md)).
Run it in the application environment that owns access to the private app socket;
the dispatcher image contains only the dispatcher. See [operator usage](client/README.md#operator-commands).

## Coordinator setup

Applications own their topology, queue policy and state. The shared rootless
`deploy/remote-runner/plane.sh ROOT init` installs the dispatcher, authenticated
CAS and signer from reviewed local images. Its public `plane.json` declares
private bind addresses and images; the application's `plane.toml` supplies queue
policy. State and credentials stay in an owned private directory outside Git.
See [deployment](deploy/README.md). No cloud resource is created.

## Add a worker

Use the consuming application's setup command. It supplies its public image/lane
settings and its existing signer to this shared kit:

```sh
bash deploy/remote-runner/worker.sh apply --env APP.env --machine MACHINE --signer COMMAND --client COMMAND --note NOTE
bash deploy/remote-runner/worker.sh status --env APP.env --machine MACHINE --client COMMAND
```

For a trusted host command that launches its own isolated workloads, add
`--runner REVIEWED_BINARY` to the same apply command.
The public profile contains NAME, DISPATCHER_ADDR, CAS_URL, LANES, RUNNER_NODE,
WORK_ROOT, COMMAND (absolute executable plus fixed arguments), COUNT and optional
NO_DEADLINE=1, GPUS (`all` or indexes such as `0,1`), GPU_LOCK (the machine's GPU lock
file, `/var/lib/tailworker/locks/gpu` where tailworker shares the GPU), GPU_QUEUED=1 (the
command waits in the machine's own GPU queue), MPS_PIPE, NVIDIA_SMI and
ROOTS (`NAME=/folder` pairs separated by commas); see [GPUs](contracts/COMMAND.md#gpus) and
[local roots](contracts/COMMAND.md#local-roots). Each instance receives a unique credential on the worker. Runtime
traffic goes through the same authenticated runner and CAS doors; SSH is setup only.

Tailworker resolves the approved machine and transfers images; the kit installs
rootless Quadlet units pinned to their image IDs. The runner starts at boot and
starts its compute; with MODEL_EGRESS=1, compute starts its smokescreen guard
first. Each unit restarts after a failure, and compute after any exit, so one that
fails at boot holds no other down. A compute restart leaves its runner running, and
the runner takes no job while its compute is not ready. A runner stopped at its boot
gate exits cleanly, and one stopped mid-job releases the job as `interrupted`.
`NAME` isolates each application's containers, networks, volumes and credentials,
so applications can share a machine.
The worker creates its own seed. Only its public key and the application's signed
capability cross SSH; compute never mounts the runner credential. Optional
`--secret NAME FILE` copies an owned mode-0600 provider secret into a namespaced
Podman secret. Public settings contain secret references, never their contents.
Compute keeps its root read-only; ephemeral `/run` supplies secret mountpoints.

Apply validates settings, drains admission without cancelling current work, waits
for clean runner exit, installs reviewed units and requires a fresh healthy heartbeat.
A runner hears its drain only through the dispatcher, so apply waits only while the
dispatcher counts it online; one it has not heard from within a lease, such as a
runner held at its boot gate, stops apply with the drain left in place.
An update preserves existing credentials only with unchanged coordinator and lane scope.
HTTP compute declares explicit MEMORY and CPUS limits. Runner admission waits for
model warmup until cancelled, without a startup deadline. Private tailnet access and the app's
authenticated runner/CAS doors must already be configured. No machine is provisioned
and no cloud API is called. `bash deploy/remote-runner/test-install.sh` checks setup,
update and their refusals without starting services or using real credentials.

## Gates

```sh
cargo build --manifest-path auth/Cargo.toml --bins
go test ./...
(cd deploy/smokescreen && go test ./...)
cargo test --manifest-path auth/Cargo.toml
bash deploy/remote-runner/test-install.sh
bash deploy/remote-runner/test-ssh-exec.sh
```

The e2e tests run the `pep` and `signer` in `auth/target/debug` and skip when they are
missing, so build them first: a stale build tests old code.

The Rust PEP is the only credential-verification engine. Backends receive verified
identity and never parse credentials. Model and ingest egress use separate source-network
roles; unknown roles are denied. The priced-work cap defaults to `$0.00`.

The PEP stops on SIGTERM or SIGINT. It stops accepting, closes each keep-alive connection
that is waiting for its next request, lets the requests in flight finish, and exits 0
(`auth/src/shutdown.rs`). It waits at most 5 s; a connection that has not sent its first
request yet holds the exit until then. A runner's lease that is still waiting is dropped
at once: it holds no work yet. The dispatcher ends a long-poll whose connection closes,
and undoes a grant that never left it (D19), so a runner it has seen go is granted
nothing. A surface whose accept fails (out of file descriptors, say) logs it and tries
again 1 s later.

Each accepted connection probes a silent peer with TCP keepalive: idle 10 s, then two
probes 5 s apart. A runner that vanished without a close (its power lost, its network
path gone) loses its connection, and its waiting lease, about 20 s after its last sign of
life. A job granted to it before then is lost with it until its lease expires.

Security-boundary tests under `auth/tests/` are hand-written and must not be weakened or
generated by an agent. HTTP PEP details are in [docs/PEP_HTTP.md](docs/PEP_HTTP.md).
