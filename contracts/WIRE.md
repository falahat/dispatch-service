# Wire contract v0 — dispatcher ⇄ runner ⇄ app

Normative. Schemas: [`schemas/wire.schema.json`](schemas/wire.schema.json) bind; this prose
explains. States: [`states.json`](states.json). Artifacts (invocation, manifest, action
result): [`ARTIFACTS.md`](ARTIFACTS.md). MUST/SHOULD per RFC 2119.

## Framing, versioning, strictness

- Transport: length-prefixed JSON frames (`trust_core.wire`), UTF-8, one JSON object per
  frame: `{"v": "0.1", "type": "<message>", "id": "<request-id>", "body": {...}}`.
  Responses echo `id`. `id` is a client-chosen unique string per in-flight request.
- **Connection preamble:** first frame MUST be `hello`; the server replies `hello_ok`, or
  `error{version_mismatch}` and closes. All components are co-deployed, so a version
  mismatch is a **hard error** (a misconfiguration), not a negotiated mixed-version state.
  After `hello`, frames with an unknown `type` or schema-invalid `body` → `error{invalid}`
  (fail-closed; unknown fields are rejected).
- **Surfaces.** *Runner surface*: tailnet TCP, **terminated by the in-path Rust PEP/PDP**
  (the single verify engine — it also fronts the CAS); the PEP forwards pre-authenticated
  frames to the dispatcher over loopback. The dispatcher parses **no credential** and holds
  no auth crypto — it trusts the PEP-attached verified identity and applies only live-state
  authz (lease fencing). *App/admin surface*: Unix domain socket (filesystem permissions are
  the access control; loopback TCP fallback where AF_UNIX is absent); no PoP, no PEP.
- **Auth binding (PEP, runner + CAS surfaces).** Each request rides Biscuit + PoP: the
  canonical request string is `dispatch/v0 <type> <sha256(body-bytes)> <nonce> <ts>`, signed
  by the runner keypair; the Biscuit MUST carry `right("<type>")` and, where the verb names
  a lane, `lane("<lane>")`. The PEP verifies signature + PoP + freshness + revocation +
  static right/lane policy, and owns the **durable** single-use nonce store. Denials are
  logged as first-class outcomes. There is exactly one verify implementation (Rust), in one
  place; the dispatcher never re-verifies.

## Identifiers and scalars

| Name | Form | Notes |
|---|---|---|
| `job_id` | `j_` + ULID (26 Crockford-base32 chars) | server-assigned, time-sortable |
| `lease_id` | `l_` + ULID | **fencing token** — see Leases |
| `job_key` | app string ≤ 256 bytes | idempotency key; unique among **live** jobs |
| `address` | `sha256:` + 64 lowercase hex | see ARTIFACTS.md |
| `lane` | `[a-z0-9-]{1,32}` | routing key |
| `attempt` | int ≥ 1 | server-truth |
| timestamps | int, ms since epoch, **server clock only** | field suffix `_ts` |
| `error_class` | `oom · timeout · rate_limit · network · bad_input · integrity · fatal · unknown` | closed enum |

## Job states

`AWAITING_APPROVAL · REJECTED · QUEUED · RUNNING · PERSISTING · SUCCEEDED · FAILED ·
CANCELLED`. The transition table in [`states.json`](states.json) is exhaustive: **any
transition not listed is illegal, and the dispatcher's tests assert it cannot occur.**
Terminal: `SUCCEEDED, FAILED, REJECTED, CANCELLED`. (No DAG states — `depends_on` is a
non-goal; the app's reconciler decides what jobs exist.)

## Leases (fencing)

A grant creates a lease: `{lease_id, ttl_s, deadline_ts}`. `complete`/`fail`/`release` MUST
present the `lease_id`; a mismatch (superseded, expired, or foreign) → `error{not_leaseholder}`
and **no state change** — stale leaseholders are fenced by token, not by identity guesswork.
`heartbeat` carrying the `lease_id` renews it. Sweep: an expired lease re-queues the job with
`attempt+1` (a silent death is presumed a crash — this is what catches crash-loops via the
poison cap) unless `attempt ≥ policy.max_attempts` → `FAILED(fatal)`.

## Runner surface

| Verb | Body → Reply | Semantics |
|---|---|---|
| `hello` | `{contract:"0.1", runner:{id, version, node, lanes[], capacity}}` → `hello_ok {server_ts, heartbeat_interval_s, min_wait_s, max_wait_s}` | introduces the runner (fleet row upsert); `runner.id` = its public-key fingerprint. |
| `lease` | `{lanes[], wait_s}` → `grant {job, lease}` \| `empty {reason?: backpressure\|drained, retry_after_s?}` | **long-poll**: blocks up to `wait_s` (clamped to server bounds) until a job is runnable. Atomic claim: oldest runnable job in a requested lane (`next_attempt_at ≤ now`), selecting the lane by round-robin over the runner's open lanes so one lane's backlog can't starve another, lane concurrency cap ok, runner not quarantined, per-runner rate cap ok, lane not in inbox backpressure. `job = {job_id, job_key, lane, invocation_address, attempt, expected_wall_s?, hints{batch_scale?, ...}}`. |
| `heartbeat` | `{status:{node, lanes[], capacity, gpu?, vram_free_mb?, current_job_id?}, lease_id?}` → `beat_ok {directives[]}` | renews the named lease; the reply is the **only steering channel**: directives are `abandon {job_id}` (stop work now; job was cancelled or you are quarantined), `drain` (finish, take no more leases, exit), `throttle {lease_after_ts}`. |
| `complete` | `{lease_id, job_id, attempt, action_result}` → `ok` | compute + `cas.put` done → `PERSISTING`; pushes to the app subscription. Idempotent per `(job_id, attempt)`: exact replay → `ok`; divergent replay → `error{conflict}`. |
| `fail` | `{lease_id, job_id, attempt, error_class, message ≤ 4 KiB}` → `ok` | compute failed. Attempt burned; the job's declared policy maps `error_class` → retriable (backoff) or terminal. Idempotent per `(job_id, attempt)`. |
| `release` | `{lease_id, job_id, reason: cas_unreachable \| cas_miss \| integrity \| wrong_hardware \| shipping}` → `ok` | "could not start / could not ship" — back to `QUEUED`, **attempt unchanged**, `release_count+1`; the cap depends on the reason's class: `cas_unreachable`/`shipping` are INFRASTRUCTURE (bounded generously, so a self-clearing outage cannot dead-letter healthy work), while `integrity`/`wrong_hardware`/`cas_miss` use `policy.release_cap`. At the cap → `FAILED`, carrying the reason: `input_evicted` for `cas_miss` (the app re-stages the blob and re-enqueues), else `unstartable:<reason>`. `integrity` additionally raises a loud telemetry event. Rate-limited and quarantine-scored. |

## App surface (UDS)

| Verb | Body → Reply | Semantics |
|---|---|---|
| `enqueue` | `{jobs[1..256]: {job_key, lane, invocation_address, policy?, cost_estimate_usd?}}` → `{results[]: {job_key, job_id, created}}` | **Idempotent on live `job_key`**: an existing live job → its `job_id`, `created=false`, all other fields ignored. Priced jobs (`cost_estimate_usd > 0`) reserve against the budget and park in `AWAITING_APPROVAL`; reserve failure → per-job `error{budget}`. Terminal jobs do not block re-use of their `job_key`. |
| `subscribe` | `{}` → stream of `completion {job_id, job_key, lane, attempt, action_result, completed_ts}` | the push subscription. On connect: every `PERSISTING` job is delivered oldest-first, then live events. **One active subscription**: a new `subscribe` wins; the old connection receives `takeover {}` and is closed. No cursor exists — `PERSISTING` is the inbox, `ack` empties it. |
| `job` / `wait` | `{job_id}` → `job_result {job_id, job_key, state, invocation_address, runner_id, attempt, release_count, reason, action_result?}` | app-only direct lookup / independent blocking wait. Network waits return at PERSISTING or a terminal state; local command waits include persistence ack and confirmed cancellation cleanup. No polling or completion-subscription takeover. |
| `ack` | `{job_id, disposition: persisted \| rejected, reason?}` → `ok` | `persisted` → `SUCCEEDED` (unpins the job's CAS blobs for GC); `rejected` (parse says the output is garbage) → `FAILED(bad_output)`, dead-lettered. Idempotent; only valid from `PERSISTING`. |
| `approve` / `reject` | `{job_id, author, reason}` → `ok` | the priced-job gate; append-only approval facts; `reject` → `REJECTED` and releases the reservation. |
| `cancel` | `{job_id, reason}` → `ok` | any non-terminal → `CANCELLED`. `RUNNING` → the runner learns via an `abandon` directive; `PERSISTING` → removed from the inbox; CAS pins released. |
| `jobs` | `{filter?: {state?, lane?, job_key_prefix?}, page?}` → `{jobs[], next_page?}` | read view. `job` rows include the full attempt/release timeline (the dead-letter view is `jobs{state: FAILED}`). |
| `fleet` / `budget` | `{}` → snapshots | fleet: per-runner health, lanes, quarantine state, recent RTF. budget: cap, reserved, spent, per-job ledger. |
| `stats` | `{window_s?}` → `{server_ts, window_s, jobs[]: {lane, state, count}, attempts[]: {lane, outcome, count}, recent_failures[]: {lane, error_class?, reason?, count}, oldest_queued_age_s}` | the drain-health snapshot (read-only). `attempts` counts settled events (`ended_ts` set) within the trailing window (default 900s, capped 7d) — in-flight `claimed` rows are excluded; `recent_failures` groups `fail` rows by (lane, class, reason), worst first, top 10. Activity ≠ progress: these counts are what the 2026-07 drain-collapse hid. |
| `sweep` | `{}` → `{recovered, expired, gc_candidates, pruned}` | runs the timer pass on demand (tests / `dispatchctl`); `pruned` counts terminal jobs deleted by the retention window (0 when no TTL is set). |

## Server rules (cross-cutting)

- **Time**: all `*_ts` values are stamped by the dispatcher's clock. Client-supplied times
  are never stored as truth.
- **Backpressure**: per lane, `count(PERSISTING) > watermark` → `lease` returns
  `empty{backpressure}` for that lane until drained.
- **Quarantine**: `should_quarantine` (dispatch-kit rule) requires failing evidence from the
  runner **plus** ≥ 1 of those jobs succeeding on a *different* runner (≥ 2 witnesses — a
  single-runner lane can never starve itself). Quarantined runners still heartbeat; their
  `lease` gets `empty`.
- **Hints**: on retry after `fail{oom}`, the grant SHOULD carry `hints.batch_scale` halved
  from the failed attempt (floor per lane policy) — the error-class → sizing feedback loop.
- **Errors**: `error {code, message, retryable}` with closed codes: `unauthenticated ·
  forbidden · version_mismatch · invalid · not_leaseholder · gone · conflict · budget ·
  backpressure · rate_limited · internal`.

## Policy block (dispatcher-enforced only)

```
policy: {
  max_attempts:  1..10   (default 3),
  backoff_class: quick | standard | long   (default standard),
  error_class_overrides?: { <error_class>: terminal | retriable },
  expected_wall_s?: int,        # per-job wall budget: the runner bounds a job's runtime at a
                                # generous multiple of this (a tighter backstop than the flat
                                # MaxJobDuration); rides the grant to the runner
  priority?: 0..9 (default 5),  # lower first within a lane
  release_cap?: 1..20 (default 5)
}
```
Staleness (`on_drift`) is **deliberately absent** — it is reconciler (app) policy, enforced
app-side by digest comparison + `cancel`; the dispatcher never evaluates domain freshness.
