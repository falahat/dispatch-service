# Cutover guide — moving the live apps onto the dispatch plane

The plane (`dispatcher`, `runner`, `pep`, `client`, `dispatchctl`, `compose`) is
built and verified (unit + cross-language auth E2E + SIGKILL crash-injection).
This is the **grounded, reviewable checklist** for retiring each app's bespoke
worker/coordinator machinery onto it. It is deliberately incremental: run the new
plane **alongside** the old path, verify on real work on the real hardware, then
delete — never a blind rip-out of a pipeline holding irreplaceable data.

The order is fixed by safety, not convenience:
**integrate (flagged, additive) → verify on the desktop/GPU → delete → deploy → retire.**

---

## easy-podcast

The app was designed for this. `jobs/spec.py` already carries the **Invocation
seam** — `prepare(ctx, episode) -> Invocation`, `parse(raw) -> persist input`,
`remote_runnable`, `placement`, per-op VRAM/image routing — and `jobs/invocation.py`
defines a serializable `Invocation{op, episode_id, audio_sha256, params}`. That maps
almost 1:1 onto the plane's `invocation/v0`.

### EP1 — app integration (additive; behind a `use_dispatch_plane` flag)

A new adapter module (e.g. `sync/dispatch_adapter.py`) that uses `client/` (the
Python app client):

1. **Enqueue.** For a `remote_runnable` op, `prepare(ctx, episode) -> Invocation`,
   then project it to `invocation/v0`:
   - `op = spec.op`, `op_version` from the spec (add an `op_version: int` field to
     `JobSpec`), `params = Invocation.params` (integers-only rule: `diarize` bool ok,
     `model` string ok; any float becomes a decimal-string),
   - `inputs = {"audio": {"address": "sha256:"+audio_sha256, "kind": "blob"}}` — the
     audio bytes must already be in the CAS (see the audio-ingest note below),
   - `cas.put(canonical_json(invocation))` → `invocation_address`,
   - `client.enqueue([{job_key: f"{episode_id}:{op}", lane: op, invocation_address}])`.
   The `job_key` gives free idempotency; re-enqueue of a live op is a no-op.
2. **Consume.** A background thread runs `for c in client.completions():` — for each
   completion, fetch `c.action_result.outputs[...]` from the CAS (verify-on-read),
   `raw = json.load(...)`, `prepared = spec.parse(raw)`, then **under the store lock**
   `spec.persist(ctx, PipelineRequest(...), prepared)`, then `client.ack(c.job_id,
   "persisted")` (or `"rejected"` if `parse` says the output is garbage).
3. **Reconciler staleness** (`on_drift`, app-side per WIRE.md): before persisting,
   compare the completion's `invocation_address` to what the reconciler would build
   now; per-op policy — `impossible` (persist regardless; transcribe never drifts
   meaningfully), `debounce` (persist, it's cheap to redo), `cancel` (only for ops
   where a stale result is wrong). Do **not** cancel-on-any-drift for corpus ops.
4. **PipelineRequest projection.** Keep the existing `PipelineRequest` as the app's
   own record; the plane's `job_id`/attempt/metrics become fields on it (a thin
   projection), so the phone UX and the CLI views are unchanged.

**Audio into the CAS.** Today the worker pulls sealed `/audio` by `episode_id`
(`Invocation.audio_url`/`audio_sha256`). Under the plane, the coordinator `cas.put`s
the audio bytes once (addressed by `audio_sha256`, which the app already computes) so
the runner fetches them through the PEP. This *replaces* `/audio` and `inputsource.py`.
**The biometric `ExampleAudio_11s.m4a` is never enqueued** (it is not a corpus episode).

### EP2–EP7 — compute images (one per remote op)

Each wraps the **existing** pipeline code behind the invoke protocol (`INVOKE.md`);
`runner check <image>` is the gate. None of them touches the store.

| op | image | notes |
|---|---|---|
| `transcribe` | whisperx (GPU, persistent, model preloaded at `/healthz`) | wraps `pipelines/transcribe.py`; `params={model, diarize}`; input `audio`; output `transcript.json` = the normalized dict `parse` already expects (identity parse). VRAM per `min_vram_gb`. |
| `embed` | GPU | wraps the embed pipeline; input `audio`/transcript; output `embeddings.bin` (a CAS blob) referenced by a manifest if large. |
| enrichment ops (`segment`, `chapters`, `long_pauses`, `chapter_guess`, `speaker_guess`) | CPU | these are `PLACEMENT_LOCAL` today and read the store; to move them off-box they need `prepare`/`parse` (serialize their store inputs). Until then they stay coordinator-local — **do not force them remote.** |
| `connections` | CPU, **manifest input** | scans the whole library — its input is a corpus **manifest** (one small address pinning every episode's embeddings); staleness policy = `debounce`, never cancel-on-drift (a corpus op must not livelock). |
| `feed`, `download` | ingest lane, **egress-jailed** | the only images with outbound network — on the `worker` network with `HTTP(S)_PROXY=smokescreen`; the allowlist (`deploy/smokescreen/allowlist.yaml`) is the real feed/CDN hosts. Throttle downloads (ethics rule). |

### EP8 — THE DELETION (only after EP1–7 verify on real episodes)

Delete the **worker-dispatch** machinery. **Surgical**: `sync/` also holds the
**phone-sync replica**, which MUST stay. Verify each file's role before deleting.

- **Delete (worker dispatch):** `sync/coordinator_loop.py`, `sync/coordinator.py`,
  `sync/workrpc.py`, `sync/workerservice.py`, `sync/remoteworker.py`,
  `sync/worker_pool.py`, `sync/inputsource.py`, `sync/reconcile_gate.py`,
  `sync/stager.py`, `sync/imageproxy.py`, `sync/protocol.py` (worker protocol),
  `sync/provisioner.py` (cloud provisioning → the plane's Provisioner/cost gate);
  `Store.claim` + the queue mechanics in `store/store.py`; the sealed `/audio`
  route in `web/app.py`; the `dispatch_kit` dependency (`jobs/spec.py`'s
  `ToolRequirements` → the dispatcher's admission).
- **KEEP (phone sync / shared trust — do NOT delete):** `sync/syncservice.py`,
  `sync/server.py`, `sync/scoring.py`, `sync/adminservice.py`, `sync/phoneauth.py`,
  `sync/smoke.py`. **Reconcile with the PEP (do not blind-delete):**
  `sync/workerauth.py`, `sync/authz.py`, `sync/signer.py`, `sync/registry.py`,
  `sync/revocation.py` — worker auth/authz moves to the Rust PEP; the phone side of
  signer/registry/revocation stays. (The trust-plane split already published
  trust-core + isolated the signer — align the worker half to the PEP here.)
- After deletion: `check` (ruff/black/pytest) green, phone sync still works.

### EP9 — desktop deploy (your hardware)

`deploy/bootstrap.sh` (issuer key **preserved** → no device re-pairing) then
`docker compose up`; enroll the desktop GPU runner on the `transcribe`/`embed` lanes;
run real episodes end to end; confirm the phone UX is unchanged via the projection.
This step runs on the desktop coordinator + GPU — not reachable from a laptop session.

---

## antibody-analysis

Symmetric, smaller. The seam is `adapters/executors.py`
(`TailnetWorkerExecutor` / `HttpsWorkerTransport`) + `adapters/worker_auth.py` + the
worker ASGI + `DbJobStore`.

- **AB1 — integrate:** a Dagster op/IOManager that `client.enqueue`s an
  `invocation/v0` (its tools as ops/lanes) and an IOManager that consumes
  `client.completions()` → parses → materializes the asset → `ack`.
- **AB2 — compute images:** one per tool, wrapping the existing tool code behind
  `INVOKE.md`.
- **AB3 — delete:** `TailnetWorkerExecutor`, `HttpsWorkerTransport`, the worker ASGI,
  `adapters/worker_auth.py`, `DbJobStore` (push path). Dagster keeps orchestration;
  the plane owns dispatch.
- **AB4 — Cloud Run Jobs on the GCS lane:** the cloud runner fetches via GCS signed
  URLs (same address space); the cost gate goes live (raise `cap_usd` from `$0`).
  **No real GCP change without explicit per-task permission** (cloud OFF default).

---

## Wave 5 — completion (nothing left behind)

- `dispatchctl`/`fleet` views unified across both apps.
- Retire the PyPI `dispatch-kit` + `trust-core` packages once no consumer remains
  (archive with a pointer README).
- Update in place: `SECURITY.md`, `ARCHITECTURE.md`, `WORKER_DISTRIBUTION.md`,
  `TRUST_PLANE.md`, `DISPATCH_PLANE.md` statuses.
- Final sweep: every row here done or a recorded non-goal.
