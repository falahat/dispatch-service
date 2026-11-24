# Invoke contract v0 — runner ⇄ compute container

Normative. The **entire** obligation of a compute image, in one page, any language. The
runner is PID-less of it: compute is a separate container; they share a private network (or
a UDS on a shared volume) and a workdir volume. Precedents: OpenWhisk action containers,
the AWS Lambda Runtime API.

## The compute container MUST

1. **Serve HTTP/1.1 on `INVOKE_ADDR`** (env; a UDS path like `/sock/invoke.sock`, or
   `host:port` on the pair's private network) with exactly two endpoints:

   **`GET /healthz`** → `200 {"ready": true, "op": "transcribe", "op_version": 2}`
   once models/resources are loaded. Anything else = not ready. This is the container's
   readiness probe AND what the runner polls at boot and before each lease.

   **`POST /invoke`** — request:
   ```jsonc
   {
     "job_id": "j_…",
     "invocation": { …verbatim invocation/v0… },
     "workdir": "/work/j_…",              // both containers see the same volume
     "inputs":  { "audio": "inputs/audio" },        // relative to workdir, laid out by the runner; a local input: its absolute path
     "outputs_dir": "outputs",                       // write results under workdir/outputs/
     "deadline_ts": 1789999999000,
     "roots": { "runs": "/srv/runs" }                // the runner's roots, present when it has any
   }
   ```
   Success → `200 {"outputs": {"transcript": "outputs/transcript.json", "frames": "outputs/frames"}, "metrics": {…}}`
   (paths relative to workdir, each under `outputs/`; a path naming a folder publishes
   that folder's files as one output; `{"root": …, "path": …}` names a local output under
   one of the runner's roots, written where `roots` says that root lies; integer metrics). A
   pair serving local artifacts mounts each runner root at the same path in both containers. Failure →
   `500 {"error_class": "oom" | "timeout" | "bad_input" | "fatal" | "unknown", "message": "…" }`.
   **One invoke in flight**: a second concurrent `POST /invoke` → `409`.

2. **Exit non-zero on fatal.** A wedged context, unrecoverable CUDA state, or a
   self-detected corrupt runtime → exit; the container runtime revives it with a fresh
   process, whatever its exit status (the worker kit's compute unit: `Restart=always`).
   Per-job freshness (if an op wants it) = exit 0 after every response; same contract,
   no second mode.

3. **Honor the deadline** (SHOULD): stop and return `error_class: timeout` by
   `deadline_ts`. The runner enforces it regardless (fails the job and marks the container
   unhealthy at the deadline).

4. **Touch nothing else.** No credentials exist in the container; the network has no route
   except the runner (ingest-lane images additionally get the EgressGuard proxy as their
   only outbound door — never raw egress). Read `workdir/inputs/**` and local inputs, write
   `workdir/outputs/**` and local outputs under `roots`; the runner does all hashing and
   all CAS traffic.

5. **Name only plain files and folders under `outputs/`.** The runner fails the job as
   `fatal` when a named output path leaves `outputs/`, when the output or anything under
   a named folder is a symbolic link, a file with more than one hard link or another
   special file, or when `outputs/` itself was replaced during the invoke.

## The runner's obligations at this boundary

Lay out `workdir/inputs/` (fetched + verified) and create `workdir/outputs/` before
`POST /invoke`; read outputs only through that folder, uploading each named file, or each
file of a named folder and then its manifest; treat connection drop or container exit
mid-invoke as `error_class: fatal`; map the response to `complete`/`fail` on the control
plane; delete the workdir after `complete`/`fail`/`release`;
run the **fixture invocation** (`GET /healthz`, then one `POST /invoke` with the image's
declared fixture) at boot before its first lease — on failure, never join the fleet.
Take no lease while `/healthz` is not ready, asking again each second (D17). An invoke
that never connected, because the compute is down, and one cut short because the runner
itself is stopping, report nothing: the lease expires and the job runs again.

## Conformance

`runner check <image>` validates any compute image against this page locally (healthz,
fixture invoke, 409 behavior, deadline behavior, error mapping) — the same checks the E2E
suite runs in CI. An image that passes `runner check` is a valid compute container, in any
language, with no SDK.
