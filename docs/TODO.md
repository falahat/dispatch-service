# TODO

> Role: backlog (requests from consuming applications that the plane does not serve yet)
> Status: open
> Updated when: a request is built, dropped or added

## Long multi-step GPU pipelines (pose-estimation)

pose-estimation turns phone videos into a textured body mesh through a chain of GPU
steps: surface prep, body fit, head fit, texture bake. It runs on three GPU machines (an
L4 cloud VM, bigboi, a laptop) with a shell scheduler per machine and no queue.

The plane already covers these parts:
- script steps as installed commands with `--no-deadline`, logs and progress
  (`contracts/COMMAND.md`);
- folder inputs and outputs as `manifest/v0`;
- one command that uploads inputs, runs a step, streams its log and fetches its outputs
  (`dispatchctl run`, `client/README.md`);
- placement by declared GPU memory, exclusive and MPS modes, and a starvation guard
  (`contracts/WIRE.md`, GPU placement; `contracts/COMMAND.md`, GPUs);
- the CAS rate of 64 GiB/min per identity (`PEP_MAX_BYTES_PER_MIN`) and blobs up to
  8 GiB (`PEP_MAX_BLOB_BYTES`);
- worker setup through `deploy/remote-runner/`.

Each contract change below bumps the contract version and cites its rows in
[DISPATCH_PLANE.md](DISPATCH_PLANE.md).

### Resume from a checkpoint
- Now: a failed or expired lease requeues the job as `attempt+1`, which starts again
  from its inputs (`contracts/states.json`). Progress belongs to the current attempt
  (`contracts/COMMAND.md`).
- Need: a fit runs about an hour. Google advises Cloud Run GPU tasks of an hour or less
  (the limit is 12 h), and a spot VM can stop at any time. A command can already `runner cas put` a checkpoint and name it
  in `invoke-progress.json`. Give the next attempt the previous attempt's last progress
  object, so it fetches that checkpoint and continues.

### Cloud GPU workers on demand
- Now: workers are machines installed ahead of time. The kit creates no machine and
  calls no cloud API (`deploy/README.md`). Priced jobs wait for approval and reserve
  against a cap that defaults to `$0.00`.
- Need: approved, priced GPU work runs on a Cloud Run job task with an L4, or a VM.
  - The owner, 2026-11-19: "Under no cicrcumstance can bigboi be open to the internet.
    Why would your design need bigboi to be addressible/accessible FROM the worker
    jobs?" So a cloud task never connects to the plane or the tailnet. A runner at home
    drives it outbound: it uploads the job's inputs to a private bucket, starts the task
    through Google's API, downloads the outputs and deletes the bucket copy. The task
    holds no plane credential and touches only its bucket.
  - Cloud stays off without explicit per-task permission.
