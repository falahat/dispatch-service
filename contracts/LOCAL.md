# Local command execution

> Role: contract (trusted local executor and existing queue composition)
> Status: current
> Updated when: local command invocation, persistence or cancellation changes

`dispatch-local` composes the existing dispatcher and runner. It adds no second
queue or job state machine. The root must be an owned, private Linux directory;
both app and runner sockets are mode 0600 inside it. The content-addressed byte
store is local, with the same SHA-256 verification as the network CAS client.
Network applications continue to use the existing PEP and HTTP compute contract.

## Setup

Write a positive integer to an owner-controlled capacity file. Write ordinary
plane TOML; for work that must never be retried:

```toml
heartbeat_interval_s = 1
lease_ttl_s = 30
runner_rate_per_min = 0

[default_lane]
single_attempt = true
```

Run the reviewed daemon with the application's fixed executor:

```sh
dispatch-local --root QUEUE_ROOT --config PLANE_TOML --workers-file CAPACITY_FILE \
  --lanes work --no-deadline -- /usr/bin/python3 INSTALLED_EXECUTOR
```

The executable is resolved at startup. Invocation data cannot select it. The
executor is trusted owner code: it is responsible for containing untrusted work.
The daemon provides no container socket or credentials to a workload. SIGHUP
reloads capacity; removed consumers finish their current execution before draining.
SIGTERM shuts down this daemon and cooperatively cancels its owned executors.

## Invocation and results

Use the existing `invocation/v0` object. Place its bytes under
`QUEUE_ROOT/cas/blobs/sha256/HASH`, where HASH is their SHA-256 digest, then enqueue
that address through `DispatchClient("unix:QUEUE_ROOT/app.sock", retry_requests=False)`.
The directory and blob must stay private; publish complete blobs atomically.
Parameters and inputs retain the ordinary artifact contract and validation.

The installed executor receives the existing `InvokeRequest` JSON on stdin,
with its working directory set to `workdir`. `DISPATCH_WORKDIR`,
`DISPATCH_RUNNER_ID` and `DISPATCH_RUNNER_NODE` describe that local consumer.
Stdout/stderr go to `workdir/invoke.log`. Write the existing `InvokeResult` shape
to `workdir/invoke-result.json` and exit successfully only after application
results have been persisted. For example:

```json
{"outputs": {}, "metrics": {"exit": 3}}
```

An application's failed test is an application result; it can be returned as an
exit metric. The application must use that metric when reporting success. An
executor process failure is a queue execution failure. Output paths and metrics
use the existing result and CAS contracts. Local results are acknowledged only
after executor persistence and runner output storage; a restarted daemon drains
any already-persisted completion inbox without invoking its work again.

`--no-deadline` sets the local request's `deadline_ts` to zero and installs no
execution timer. Lease heartbeats detect a lost consumer; they do not limit the
execution's duration. A `single_attempt` lane forces one attempt and makes
infrastructure releases terminal too. Failures remain visible and are not rerun.

## Wait and cancellation

The app surface's `job {job_id}` reads one job. `wait {job_id}` blocks until its
execution ends; each Python wait uses its own connection, so concurrent waits
and cancellation do not take over the completion subscription. Replies include
identity, state, attempt, release count, reason and the stored action result.
Local waits include result acknowledgement.

Cancellation requests SIGTERM for the owned executor and waits for it to exit.
The executor must stop and reap only its own subprocesses or containers before
exiting. No timer or SIGKILL fallback is added. A running cancellation's wait
returns only after the executor's cleanup settles. A daemon crash can leave that
settlement unconfirmed; an unresolved cancellation stays incomplete rather than
claiming that an orphan stopped. Queued cancellation needs no executor cleanup.
