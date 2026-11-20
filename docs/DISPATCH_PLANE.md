# Dispatch plane decisions

> Role: decision record (why each contract change is shaped the way it is)
> Status: current
> Updated when: a contract change adds or replaces a decision

The system design lives in easy-podcast's
[dispatch-plane document](https://github.com/falahat/easy-podcast/blob/main/docs/DISPATCH_PLANE.md).
This file records the decisions behind this repo's contract changes; each contract change
adds its rows and cites them. A replaced decision is deleted, not struck through.

## Decisions

| ID | Contract | Decision | Why |
|---|---|---|---|
| D1 | 0.2 | An output may name a folder under `outputs/`. The runner uploads the folder's files and returns a `manifest/v0` of them, marked `kind: "manifest"` on the output. | A pose surface-prep step writes two files per video frame, about 900 for one clip. A manifest is the shape folder inputs already take, so the next step takes a folder output by address, with no copy and no new format. |
| D2 | 0.2 | `kind` on an output is optional; absent means one blob. | Action results stored before 0.2 stay valid without a migration. |
| D3 | 0.2 | The runner reads outputs only through the `outputs/` folder it created, opened as an `os.Root`. A named path outside it, a symbolic link, a file with more than one hard link, any other special file, or a replaced `outputs/` folder fails the job as `fatal`. | Outputs are untrusted compute data. Before 0.2 the runner uploaded whatever path the compute named, so a path or link could publish a file outside the workdir, such as the runner's credential, into the CAS. Retrying the same computation breaks the rule again, so the failure is fatal. |
| D4 | 0.3 | A job declares the most GPU memory it will use (`policy.gpu.memory_mb`) and a mode, `shared` (default), `mps` or `exclusive`. A job without the block never receives a GPU, and a runner offers GPUs only when started with `--gpus`. | Pose stages need 0.6 to 7.4 GB each on a 23 GB L4 or an 8 GB card. Placing them by declared memory lets small stages share a GPU and keeps a 7.4 GB stage off a card it cannot fit. Opt-in at both ends leaves the planes that declare nothing unchanged. |
| D5 | 0.3 | The runner sends a fresh reading of its GPUs (index, UUID, total and free memory, compute processes without the MPS server) with each `lease`; a lease carrying one waits at most 5 s. A shared job fits when the declared memory of the plane's RUNNING jobs on that GPU plus its own stays within the total less `gpu_reserve_mb` (default 1024), and its own figure is at most the GPU's free memory. | The rule of the machines' `gpu-slot.sh`. The declared sum covers jobs that have started but not yet allocated; the live free figure covers programs outside the plane. A reading older than a few seconds is not trusted, so the long-poll is shortened. |
| D6 | 0.3 | An `exclusive` job needs a GPU with no RUNNING job of the plane's and no compute process; a GPU holding one takes nothing else. | Timing runs must have the card alone, as `gpu-slot.sh --alone` gives them. |
| D7 | 0.3 | A GPU job runnable for `gpu_starve_after_s` (default 1200) starts first wherever it fits, and until then the GPUs where a runner asking for work in its lane could place it, once they drain, take no other new GPU job. | Without it a stream of small jobs keeps a large or exclusive job waiting forever. Holding back only those GPUs leaves cards it could never use, and jobs without a GPU, running. |
| D8 | 0.4 | A runner credential (one whose authority grants `right("lease")`) reads only the blobs of jobs it holds a live lease on, the invocation, its inputs and each file of a manifest input, and looks up or stores blobs only while it holds one. The PEP keeps the book of leases from the grants it relays, ends a lease at complete, fail or release, and lets one that heartbeats stop renewing expire after its TTL. | Before 0.4 any worker credential could read every blob whose address it knew, another job's video or outputs included, and store at will. A leaked worker key now reaches only the jobs that worker is running. The PEP already sees every grant on the runner surface, so the dispatcher learns nothing about blobs and runners change nothing; minting a token per lease would have changed both. |
