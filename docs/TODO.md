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
- folder inputs as `manifest/v0`;
- the CAS rate of 64 GiB/min per identity (`PEP_MAX_BYTES_PER_MIN`) and blobs up to
  8 GiB (`PEP_MAX_BLOB_BYTES`);
- worker setup through `deploy/remote-runner/`.

Each contract change below is its own PR citing a DISPATCH_PLANE decision row.

### Folder outputs
- Now: a job returns at most 64 outputs, each a single file (`contracts/ARTIFACTS.md`).
  The runner uploads each one with `PutFile` (`runner/loop.go`).
- Need: surface prep writes two files per video frame, 900 per phone for a 15 s clip.
  That is about 25 GB, which pose-estimation is cutting first. An output may name a
  folder; the runner uploads its files and returns a `manifest/v0`, the shape inputs
  already take.

### Placement by GPU memory
- Now: a runner advertises a slot count (`capacity`). Heartbeats carry `vram_free_mb`,
  which is stored and shown but never used to place work (`dispatcher/heartbeat.go`,
  `dispatcher/views.go`). The worker profile's `MEMORY` and `CPUS` are container
  limits. Nothing declares GPU memory.
- Need: a job declares the GPU memory it needs, and a GPU starts jobs while their
  declared needs fit its free memory. Read free memory on the machine when a lease is
  taken, because heartbeat numbers go stale. Also:
  - an exclusive flag for timing runs: the job waits for an idle GPU and runs alone;
  - a starvation guard: once a job has waited past a limit (20 min today), later jobs
    stop starting ahead of it;
  - CUDA MPS for shared jobs, without counting the MPS server as a job. Measured on an
    L4: two fits side by side took 209 s against 296 s one after the other, with scores
    equal within 0.001 px.

### Resume from a checkpoint
- Now: a failed or expired lease requeues the job as `attempt+1`, which starts again
  from its inputs (`contracts/states.json`). Progress belongs to the current attempt
  (`contracts/COMMAND.md`).
- Need: a fit runs about an hour. A Cloud Run GPU task stops at one hour, and a spot VM
  can stop at any time. A command can already `runner cas put` a checkpoint and name it
  in `invoke-progress.json`. Give the next attempt the previous attempt's last progress
  object, so it fetches that checkpoint and continues.

### Cloud GPU workers on demand
- Now: workers are machines installed ahead of time. The kit creates no machine and
  calls no cloud API (`deploy/README.md`). Priced jobs wait for approval and reserve
  against a cap that defaults to `$0.00`.
- Need: approved, priced GPU work starts a worker for one job: a Cloud Run job task with
  an L4, or a VM, in any region that has capacity. The worker takes the job and exits.
  - Open, and both are the owner's security decisions: how the worker reaches the
    runner and CAS doors (tailnet inside the task, or a public door), and how a one-shot
    worker gets a credential without SSH enrollment.
  - Cloud stays off without explicit per-task permission.
