# Installed command executor

> Role: contract (trusted host executor using the existing network runner)
> Status: current
> Updated when: command invocation, logs or cancellation changes

`runner run [network and credential flags] --no-deadline -- EXECUTABLE ARG...`
uses the ordinary authenticated runner, dispatcher and HTTP CAS. Without a command,
the runner uses its paired HTTP compute container. There is one queue and lease protocol.
The executable and arguments are fixed by the owner at installation; invocation
data cannot choose a host command. This trusted executor must contain untrusted work.

The command receives the existing `InvokeRequest` on stdin, in its private `workdir`.
`DISPATCH_WORKDIR`, `DISPATCH_RUNNER_ID` and `DISPATCH_RUNNER_NODE` describe the
consumer. Write an `InvokeResult` to `invoke-result.json` and exit zero after cleanup.
Output files are uploaded to the authenticated CAS and delivered in the ordinary
completion inbox. The application persists its result, then acknowledges it.
Application failure can be an integer exit metric; an executor crash is a queue failure.

Stdout/stderr remain outside workload mounts in `invoke.log`. The runner publishes
CAS-addressed chunks through its heartbeat, with byte offsets acknowledged by the
dispatcher. The app-only `logs` verb reads these chunks independently of completion
subscriptions. Bytes are verified by the existing CAS client, never executed.

The executor may atomically replace `invoke-progress.json` with a JSON object
of at most 16 KiB, outside workload mounts. Heartbeats publish this opaque object;
`job` and `wait` return the latest `progress` for the current attempt. The application
owns its meaning. Progress does not complete a job or change its queue state.

`--no-deadline` supplies `deadline_ts=0` and adds no execution watchdog. A
`single_attempt` lane makes execution, shipping and lease-loss failures terminal.
The command handles SIGTERM by stopping and reaping only its own children and
containers; there is no kill timer. With `wait_for_executor=true`, cancellation keeps
the lease live until this cleanup returns a result and the app acknowledges it.
`wait` includes acknowledgement. A lost worker fails visibly; it does not certify cleanup.

`runner cas --url URL --credential FILE put FILE` and
`runner cas --url URL --credential FILE [--max-bytes N] get ADDRESS FILE`
reuse the worker's PoP authentication and content verification. Downloads publish
atomically after verification and enforce the chosen size limit.

The shared `deploy/remote-runner/install-command.sh` installs this fixed command;
`enroll-command.sh` creates a unique credential for each consumer on the worker.
The application's signer owns rights and lanes. SSH is setup transport only;
runtime work uses the existing PEP runner and CAS doors over the private network.
