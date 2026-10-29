# dispatch-client

Pure-stdlib Python client for the dispatch-service **app surface** (wire contract
v0.1). No third-party runtime dependencies — just `socket`, `struct`, `json`,
`threading`.

## Install

```
pip install -e .           # from client/
```

## Usage

```python
from dispatch_client import DispatchClient

client = DispatchClient("unix:/run/dispatch.sock")   # or "127.0.0.1:7701"

# Idempotent on a live job_key: a repeat returns the same job_id, created=False.
results = client.enqueue([{
    "job_key": "ep-42",
    "lane": "embed",
    "invocation_address": "sha256:" + "0" * 64,
}])

view = client.jobs(filter={"state": "PERSISTING"})     # read view
client.approve(job_id, author="me", reason="ok")        # priced-job gate
client.cancel(job_id, reason="stale")
snap = client.fleet(); bud = client.budget(); sw = client.sweep()
drain = client.stats()                                  # drain health: states, windowed
                                                        # complete/fail, failure reasons

# A caller that must never hang on a wedged dispatcher (health pollers):
poller = DispatchClient("unix:/run/dispatch.sock", timeout=5.0)

# An uncertain connection must not replay a CI submission.
ci = DispatchClient("unix:/run/dispatch.sock", retry_requests=False)
view = ci.job(job_id)
finished = ci.wait(job_id)  # dedicated blocking connection; no automatic replay

# Consume completions (blocking generator). Ack each to drain PERSISTING.
for completion in client.completions():
    process(completion)                                 # resolve outputs from CAS
    client.ack(completion["job_id"], "persisted")       # or "rejected"
    if done:
        client.close()                                  # stops the generator
        break
```

## Address format

`"unix:/path/to/sock"` for an AF_UNIX socket, or `"host:port"` for loopback TCP
(e.g. `"127.0.0.1:7701"`). Connections open lazily on first use.

## completions() semantics

`job()` and `wait()` are independent of the completion subscription. Each wait
owns a connection so other calls, including cancellation, can proceed on the same
client. Network-plane waits return at PERSISTING for explicit application ack;
local command queues wait through their automatic persistence ack and cancellation
cleanup. Neither operation installs a job execution deadline.

`completions()` owns a dedicated subscription connection. On connect the server
delivers every `PERSISTING` job oldest-first, then live events. There is **no
cursor**: the PERSISTING set *is* the inbox, and `ack` empties it. On a
`takeover` frame (a newer subscriber won) or a dropped connection the generator
**reconnects and resubscribes automatically**; the server **redelivers** the
un-acked PERSISTING set, so redelivery is free and you never track a position.
Only one subscription is active server-wide at a time.

**Acks go on a separate connection.** The subscription connection is
write-only from the server; `ack` (and every other verb) travels the client's
request/reply connection, so it is safe to call `client.ack(...)` from another
thread while iterating `completions()`. The single `DispatchClient` is
thread-safe for this pattern.

## Operator commands

The installed SDK provides `dispatchctl`; `python -m dispatch_client.cli` is the
same entry point. Run it in the application's Python environment with access
to its private app socket, including the application container when deployed:

```sh
dispatchctl -addr unix:/run/dispatch/app.sock jobs --state RUNNING
dispatchctl -addr unix:/run/dispatch/app.sock job JOB_ID
dispatchctl -addr unix:/run/dispatch/app.sock wait JOB_ID
dispatchctl -addr unix:/run/dispatch/app.sock lookup SUBMISSION_KEY
```

`COMMAND --help` lists arguments. The existing jobs, job, trace, wait, lookup,
fleet, stats, budget, cancel, approve, reject, ack, sweep and enqueue commands
all print native JSON. `trace JOB_ID` uses the same complete view as `job`.
Commands use the SDK's connection and framing with no implicit request replay
or deadline. The dispatcher image contains only the Go server; it requires no
Python runtime. The application environment owns the operator client.
