# dispatch-client

Pure-stdlib Python client for the dispatch-service **app surface** (wire contract
v0.8). No third-party runtime dependencies — just `socket`, `struct`, `json`,
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
client.hold("laptop", reason="owner needs it")          # machine takes no new work;
client.unhold("laptop")                                 # returns once its work has ended

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

## Folders in the CAS

`CasClient.put_folder(path)` stores a folder's regular files and a `manifest/v0`
naming them, and returns the manifest's address for a `manifest` input; it refuses
links and special files. `CasClient.get_folder(address, dest)` fetches a manifest,
such as a folder output (`kind: "manifest"`), and every file it names into the new
folder `dest`. Each file is verified, and an entry path that could leave `dest`
fails the fetch before anything appears at `dest`.

## Run a command

`dispatchctl run` uploads the inputs, queues the job, streams its log to stderr, saves its
outputs and acknowledges the job, then prints a JSON summary: job, state, output paths,
local outputs, metrics, seconds (upload, queued, run, fetch, total) and bytes (uploaded,
already stored, downloaded).

```sh
export DISPATCH_ADDR=unix:/run/dispatch/app.sock DISPATCH_CAS_URL=http://127.0.0.1:8443 \
       DISPATCH_CREDENTIAL=app-cas.json
dispatchctl run --lane pose --input code=./pose --input video=clip.mp4 --output report \
    --gpu-mb 8192 -- python /pose/scripts/fit.py /in/video /out/report
```

A file input arrives as `inputs/NAME`, a folder as `inputs/NAME/...`. The invocation
carries ARGV in `params.argv`, the output names in `params.outputs` and each
`--param KEY=VALUE` as a string; the worker's installed command runs it
([command contract](../contracts/COMMAND.md)). Outputs land in `--dest` (default
`dispatch-out/JOB_ID`), and nothing already there is replaced. A file of 1 MiB or more that
the CAS already holds is not sent again, and folder files move 8 at a time. Submitting the
same run while it is queued or running joins that job. Ctrl-C stops watching, not the job;
`dispatchctl follow JOB_ID` picks it up again. `--no-ack` leaves the job in the completion
inbox for another consumer. The exit status is 0 only when the job succeeded and its `exit`
metric, if any, is 0. `run_step` and `follow` in `dispatch_client.run` are the Python forms;
`run_step` also takes the rest of a job's `policy` (`max_attempts`, `backoff_class`, ...) and a
`cost_estimate_usd`, which parks the job until it is approved against the plane's budget.

`--local NAME=NODE:ROOT/PATH` passes an input that already lies on NODE, at PATH under the
root its runner was installed with as ROOT: nothing is uploaded, the job runs on NODE, and
the command reads the input where it lies ([local artifacts](../contracts/ARTIFACTS.md)).
`--node NODE` pins a job without local inputs. `--keep NAME=ROOT/PATH` names an output the
command writes where it is to stay, at PATH under ROOT on the job's node, in `params.keep` as
`{root, path}`; the command finds each root's folder in its request's `roots`. A local output
is listed under `local` in the summary as `NODE:ROOT/PATH`, and nothing of it is uploaded or
fetched.

```sh
dispatchctl run --lane pose --local run=bigboi:runs/K -- python /pose/scripts/fit.py /in/run
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

`COMMAND --help` lists arguments; `-addr` defaults to `$DISPATCH_ADDR`. The jobs, job,
trace, wait, lookup, fleet, drain, resume, hold, unhold, stats, budget, cancel, approve, reject,
ack, sweep and enqueue commands print native JSON; run and follow are described above.
`trace JOB_ID` uses the same complete view as `job`.
Commands use the SDK's connection and framing with no implicit request replay
or deadline. The dispatcher image contains only the Go server; it requires no
Python runtime. The application environment owns the operator client.

`drain RUNNER_ID` closes admission and blocks until its current job settles;
it never cancels that job. The runner exits cleanly after finishing. `resume
RUNNER_ID` reopens admission before the shared installer starts it again. Fleet
`online` uses the coordinator's lease TTL and clock, not a client-side guess.

`hold NODE [--reason TEXT]` stops every runner of that machine (the `--node` it runs with)
taking new work and blocks until the machine's running jobs have ended; it never cancels
them. The runners stay connected, so `unhold NODE` gives the machine work again at once,
and a runner that connects while its machine is held waits too. Fleet rows show `held`, and
the fleet's `holds` lists each held machine with its reason. Interrupting `hold` leaves the
machine held.
