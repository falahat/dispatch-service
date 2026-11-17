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
   readiness probe AND what the runner polls at boot.

   **`POST /invoke`** — request:
   ```jsonc
   {
     "job_id": "j_…",
     "invocation": { …verbatim invocation/v0… },
     "workdir": "/work/attempt-…/j_…",    // both containers see the same volume
     "inputs":  { "audio": "inputs/audio" },        // paths relative to workdir, laid out by the runner
     "outputs_dir": "outputs",                       // write results under workdir/outputs/
     "deadline_ts": 1789999999000
   }
   ```
   Success → `200 {"outputs": {"transcript": "outputs/transcript.json"}, "metrics": {…}}`
   (paths relative to workdir; integer metrics). Failure →
   `500 {"error_class": "oom" | "timeout" | "bad_input" | "fatal" | "unknown", "message": "…" }`.
   **One invoke in flight**: a second concurrent `POST /invoke` → `409`.

2. **Exit non-zero on fatal.** A wedged context, unrecoverable CUDA state, or a
   self-detected corrupt runtime → exit; the container runtime (`restart: unless-stopped`)
   revives it with a fresh process. Per-job freshness (if an op wants it) = exit 0 after
   every response; same contract, no second mode.

3. **Honor the deadline** (SHOULD): stop and return `error_class: timeout` by
   a positive `deadline_ts`. The runner enforces the same execution deadline.
   An explicitly uncapped invocation sends `deadline_ts: 0`; lease abandonment
   and runner shutdown still cancel the request.

4. **Touch nothing else.** No credentials exist in the container; the network has no route
   except the runner (ingest-lane images additionally get the EgressGuard proxy as their
   only outbound door — never raw egress). Read `workdir/inputs/**`, write
   `workdir/outputs/**`; the runner does all hashing and all CAS traffic.

## The runner's obligations at this boundary

Lay out `workdir/inputs/` (fetched + verified) before `POST /invoke`; treat connection
drop or container exit mid-invoke as `error_class: fatal`; map the response to
`complete`/`fail` on the control plane. Keep separate directories for concurrent or
retried attempts. Delete a directory when no compute invocation occurred, compute
returned a failure, or all outputs have reached CAS and the dispatcher acknowledged
completion. Preserve a directory when termination or publication is uncertain.

Before its first lease, run the **fixture invocation** (`GET /healthz`, then one
`POST /invoke` with the image's declared fixture). On failure, never join the fleet.

## Conformance

`runner check <image>` validates any compute image against this page locally (healthz,
fixture invoke, 409 behavior, deadline behavior, error mapping) — the same checks the E2E
suite runs in CI. An image that passes `runner check` is a valid compute container, in any
language, with no SDK.
