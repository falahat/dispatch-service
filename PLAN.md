# Implementation plan — parallel tracks to a complete migration

Rules that make parallelism safe: **contracts are frozen** (every task builds against
`contracts/` and the wave-0 stubs, never against another track's code); **tracks share no
files**; a task is **done** when its listed tests pass in CI — and for migration tasks, when
the code it replaces is **deleted**. 🔒 = security-critical: hand-written adversarial tests +
human review required; agents may implement but not author or modify the attack suites.

**Critical path:** `T0.1 → C1 → I1 → I3 → EP9`. Widest unblock: `A1` (three dispatcher tasks
fan out from it). Everything else floats.

## Wave 0 — foundations (small; unblocks all tracks)

| ID | Task | Done when |
|---|---|---|
| T0.1 | Repo scaffolding: Go workspace (`dispatcher/`, `runner/`, `dispatchctl/`, `internal/wire/`), cargo workspace (`auth/` = PEP+PDP+signer crate), `client-py/`, `compose.dev.yml` skeleton, path-filtered CI (lint + test per component) | CI green on empty components |
| T0.2 | `internal/wire` (Go): length-prefix JSON codec, typed structs for every message, strict decode (unknown fields rejected) | round-trips + rejects per `schemas/wire.schema.json` in tests |
| T0.3 | **Contract stubs** (test doubles): in-memory stub-dispatcher (full verb surface), stub-CAS (map-backed, verify-on-write) as Go test utilities + a small Python stub server for the client | stubs validate against the schemas; this is what lets B/D/E proceed without A |
| T0.4 | Echo-compute image (Python stdlib HTTP: `/healthz` + `/invoke` echoing inputs→outputs) + a fixture invocation | passes the checks `runner check` will codify |

T0.2–T0.4 run in parallel after T0.1.

## Wave 1 — five tracks, fully parallel (zero file overlap)

**Track A — dispatcher (Go).** A1 first; A2/A3/A4 in parallel after it.

| ID | Task | Tests to done |
|---|---|---|
| A1 | SQLite schema; state machine driven by `states.json`; `enqueue` idempotency on live `job_key`; `sweep` skeleton | unit: every legal transition passes, **every illegal transition asserted impossible**; crash-sim around the enqueue txn |
| A2 🔒 | Leases: **claim = flip-state + stamp-lease in ONE txn** (an orphan is unrepresentable); long-poll; `lease_id` fencing on complete/fail/release; heartbeat + directives; release-cap → `FAILED(unstartable)`; poison cap; per-class backoff | unit + kill-during-claim crash test; fencing: stale/foreign lease_id rejected with no state change |
| A3 | Subscription: push on `complete`, single-active-sub newest-wins takeover, `ack` (persisted/rejected), `PERSISTING` inbox redelivery on reconnect, backpressure watermark pauses leasing per lane | integration vs stub client: kill/reconnect redelivers exactly the un-acked set |
| A4 | Admission + fleet: cost gate (reserve-on-enqueue, approve/reject, **$0 fail-closed default**), two-witness quarantine, per-runner rate caps, `jobs/fleet/budget` views, server-stamped times | unit: cap never exceeded under concurrent enqueue; quarantine impossible with a single runner |

**Track B — runner (Go).** B1 ∥ B2, then B3. Tests run against stubs + echo-compute — no dependency on Track A.

| ID | Task | Tests to done |
|---|---|---|
| B1 | CAS client: streaming get/put, verify-on-read, manifest expansion, workdir layout with traversal re-check | unit: corrupted stream rejected; traversal path rejected; manifest incremental fetch |
| B2 | Invoke client + `runner check <image>`: healthz gate, fixture invoke, 409 single-flight, deadline enforcement, error-class mapping | `runner check` passes echo-compute, fails a broken image |
| B3 | The loop: lease→fetch→invoke→put→complete; release-vs-fail phase mapping; heartbeat thread (renewal + directives); `loop`/`drain` modes; boot smoke | integration vs stubs: each failure injected at each step produces exactly the contract's verb |

**Track C — auth crate (Rust) 🔒 all of it.** C1 first; C2/C3 parallel; C4 last.

| ID | Task | Tests to done |
|---|---|---|
| C1 🔒 | Core: PoP canonical string + Ed25519 verify, **durable** single-use nonce store, Biscuit authorize with policy tables as config data (`biscuit-auth`) | unit incl. replay-across-restart rejected; malformed token never panics (no unwrap on untrusted input) |
| C2 🔒 | Streaming proxy: verify → forward pre-authed over loopback (dispatcher + CAS); per-blob size caps, per-identity quotas; denial logging | 100 MB streamed without buffering; quota/oversize rejected mid-stream |
| C3 🔒 | Signer: mint worker/app credentials over UDS; **loads the EXISTING `secrets.json` issuer-key format** — pairings preserved | mint round-trip verified by C1; existing-key fixture loads byte-identically |
| C4 🔒 | Per-lease attenuation minted from the grant: GET scoped to the invocation closure, PUT tagged to the job | attempt to fetch another job's address is denied |

**Track D — Python app client.** `enqueue` / blocking `completions()` iterator (reconnect + redelivery in the client) / `ack` / views over UDS. Tested against the stub dispatcher.

**Track E — dispatchctl (Go).** Admin verbs + `trace <job>` timeline. Against the stub, then real.

**Track F — deployment config.** Full `compose.dev.yml` + desktop overlay: bazel-remote, smokescreen + the egress-jail network topology (compute networks `internal: true`; ingest lane's only extra neighbor is smokescreen), PEP wiring, volumes, healthchecks.

## Wave 2 — integration gates (the sync points; in order)

| ID | Gate | Proves |
|---|---|---|
| I1 | PEP fronting dispatcher + CAS in compose | real auth end-to-end; backends see only pre-authed loopback; attenuation live |
| I2 | Full happy path: enqueue → lease → invoke(echo) → CAS → complete → push → persist(fake app) → ack | the whole plane, real wire |
| I3 | **Crash-injection E2E**: kill each component at each step | no lost job, no double-lease, no double-persist, exactly-once effect, TTL recovery, backpressure, `PERSISTING` survives app restarts |
| I4 | Adversarial suites green (authored by humans throughout wave 1) | every boundary fails closed — see `tests/README.md` for the attack list |
| I5 | Perf sanity | 100 MB through the PEP ≥ floor; invoke overhead budget on the echo image |

**I3 + I4 green = the plane is done as infrastructure.**

## Wave 3 — easy-podcast cutover (its repo; starts after I2, mostly parallel)

| ID | Task |
|---|---|
| EP1 | App integration: build + `cas.put` invocation at enqueue; `completions()` consumer → parse → persist → ack; `PipelineRequest` projection; staleness policy in the reconciler (`impossible`/`cancel`/`debounce` per op) |
| EP2–EP7 | **One compute image per op, embarrassingly parallel**: transcribe (whisperx, persistent, GPU), embed, enrichment ops, `connections` (manifest input), feed + download (ingest jail via smokescreen). Each: fixture + `runner check` + an E2E run |
| EP8 | **THE DELETION**: `CoordinatorLoop` + LOCAL lane, `workrpc`/`workerservice`, `/audio`, `workerauth.py` + `authz.py`, `Store.claim` queue mechanics, the three `InputSource`s, the `dispatch-kit` dependency. Full easy-podcast suite green after |
| EP9 | Desktop deploy (issuer key preserved → no re-pairing); real episodes end-to-end; phone UX unchanged via the projection |

## Wave 4 — antibody cutover (parallel with wave 3 after I3)

AB1 Dagster enqueue + IOManager consume/ack · AB2 compute images for its tools · AB3 **deletion**: push path (`TailnetWorkerExecutor`, `HttpsWorkerTransport`, worker ASGI), `worker_auth.py`, `DbJobStore` · AB4 Cloud Run Jobs on the GCS lane, cost gate live.

## Wave 5 — completion (the "nothing left behind" audit)

Z1 one-fleet views in both UIs · Z2 retire the PyPI `dispatch-kit` + `trust-core` packages (archive repos with a pointer README) · Z3 docs updated in place (`SECURITY.md`, `ARCHITECTURE.md`, `WORKER_DISTRIBUTION.md`, `TRUST_PLANE.md`, `DISPATCH_PLANE.md` statuses) · Z4 final sweep against this plan: every row done or an explicitly recorded non-goal — **no deferred items exist**.

## Assignment rules

One task = one implementer (human or agent) = its own directory; cross-track edits are a
review reject. Contract changes are separate human-approved PRs that update every component
at once. 🔒 tasks additionally require human review of the diff and human-authored
adversarial tests before merge.
