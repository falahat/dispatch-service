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
Each named output is a file or a folder under `outputs/`, as in `INVOKE.md`; a folder
arrives as a `manifest/v0` of its files. Outputs are uploaded to the authenticated CAS and
delivered in the ordinary completion inbox. The application persists its result, then
acknowledges it.
Application failure can be an integer exit metric; an executor crash is a queue failure.

## Local roots

`--root NAME=DIR` (repeatable; `ROOTS` in the worker profile) installs a root: an absolute
folder on this machine whose files jobs read in place and keep their outputs in, fixed at
installation like the command.
A local input under it arrives in `InvokeRequest.inputs` as its absolute path where it
lies, not under `inputs/`. `InvokeRequest.roots` maps each root's name to its folder, so
the command can write an output where it is to stay and name it as `{"root": NAME, "path":
P}` in place of a path under `outputs/`; the runner checks that P exists under that root
and reports it without reading it ([ARTIFACTS.md](ARTIFACTS.md), D10). Several jobs at
once on one machine are several runner instances (`COUNT` in the worker profile), each
with its own credential; the plane packs their GPU jobs by declared memory.

Stdout/stderr remain outside workload mounts in `invoke.log`. The runner publishes
CAS-addressed chunks through its heartbeat, with byte offsets acknowledged by the
dispatcher. The app-only `logs` verb reads these chunks independently of completion
subscriptions. Bytes are verified by the existing CAS client, never executed.

The executor may atomically replace `invoke-progress.json` with a JSON object
of at most 16 KiB, outside workload mounts. Heartbeats publish this opaque object;
`job`, `jobs` and `wait` return the latest `progress` for the current attempt. The application
owns its meaning. Progress does not complete a job or change its queue state.

## GPUs

`--gpus all` or `--gpus 0,1` makes a command runner offer those host GPUs with each
request for work (`WIRE.md`, GPU placement), read with `nvidia-smi` at that moment; a
failed reading offers none. Such a runner rewrites the GPU part of each command's
environment: it drops any inherited `NVIDIA_VISIBLE_DEVICES`, `CUDA_VISIBLE_DEVICES`,
`CUDA_MPS_*` and `DISPATCH_GPU_*`. A job granted a GPU gets `NVIDIA_VISIBLE_DEVICES=<host
index>` (for `docker --gpus device=` or a CDI device), `CUDA_VISIBLE_DEVICES=<GPU UUID>`,
`DISPATCH_GPU_INDEX`, `DISPATCH_GPU_UUID`, `DISPATCH_GPU_MEMORY_MB` (the job's declared
most) and `DISPATCH_GPU_MODE` (`shared`, `mps` or `exclusive`). An `mps` job also gets
`CUDA_MPS_PIPE_DIRECTORY` from `--mps-pipe DIR` when that machine's MPS daemon answers.
A job without a GPU gets `CUDA_VISIBLE_DEVICES=` and no `NVIDIA_VISIBLE_DEVICES`.
An executor that measures its job's peak GPU memory reports it as the integer metric
`peak_vram_mb`, so its application can declare what its jobs really use. A
runner without `--gpus` leaves the environment as it found it. `--nvidia-smi PROGRAM`
reads the GPUs through PROGRAM, called with nvidia-smi's arguments, in place of the local
`nvidia-smi`: a runner whose command drives another machine offers that machine's GPUs.

`--gpu-lock FILE` (Linux, macOS) joins the machine's GPU contract shared with other
schedulers: before a GPU job's command starts, the runner takes `FILE.want`, then `FILE`
(exclusive `flock`), lets go of `FILE.want`, and holds `FILE` until the command ends.
Holding the lock gives a job the whole GPU, so such a runner offers each GPU with all its
memory free and no processes.

`--gpu-queued` (`GPU_QUEUED=1` in the worker profile) says the command itself waits in the
machine's own GPU queue, the one jobs started by hand wait in, before it uses its GPU. Such
a runner also offers each GPU with all its memory free and no processes: the plane packs
its jobs by what they declare, and the machine's queue orders them among the rest. A whole
offer does not change, so a runner with either flag reads its GPUs once, not for each
request for work.

`--no-deadline` supplies `deadline_ts=0` and adds no execution watchdog. A
`single_attempt` lane makes execution, shipping and lease-loss failures terminal.
The command handles SIGTERM by stopping and reaping only its own children and
containers; there is no kill timer. With `wait_for_executor=true`, cancellation keeps
the lease live until this cleanup returns a result and the app acknowledges it.
`wait` includes acknowledgement. A lost worker fails visibly; it does not certify cleanup.

`runner cas --url URL --credential FILE put FILE` and
`runner cas --url URL --credential FILE [--max-bytes N] get ADDRESS FILE`
reuse the PoP authentication and content verification. Downloads publish
atomically after verification and enforce the chosen size limit. A worker
credential reads only its live leases' blobs and writes only while it holds a lease
([CAS contract](CAS.md#auth-enforced-by-the-pep-per-request)), so use an application
credential for transfers outside a job.

The shared `deploy/remote-runner/install.sh --runner REVIEWED_BINARY` installs this fixed command;
`enroll.sh` creates a unique credential for each consumer on the worker.
The application's signer owns rights and lanes. SSH is setup transport only;
runtime work uses the existing PEP runner and CAS doors over the private network.
