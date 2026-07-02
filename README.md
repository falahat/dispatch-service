# dispatch-service

The shared **dispatch plane**: one durable, co-located work service (the **dispatcher**) and
its paired **runner** image, spoken to over frozen, language-neutral contracts. The design
reference is easy-podcast's [`docs/DISPATCH_PLANE.md`](../transcription/easy-podcast/docs/DISPATCH_PLANE.md);
this repo is its implementation home. Auth is [trust-core](../trust-core) (Biscuit + PoP);
pure policy math is [dispatch-kit](../dispatch-kit).

## Layout

| Path | What | Language |
|---|---|---|
| `contracts/` | **The frozen v0 contracts** — normative specs + JSON Schemas + the state machine as data. Everything below implements these; nothing implements prose. | data |
| `dispatcher/` | the work service: durable queue (SQLite WAL), leases, retries, cost admission, fleet; the pure decision rules as an internal package | **Go** (born) |
| `runner/` | the shared worker client image; drives compute containers over the invoke protocol | **Go** (born) |
| `pep/` | the auth enforcement proxy + PDP — the **single verify engine**, in-path on both the CAS and the dispatcher's runner surface (backends get pre-authed requests over loopback) + the **signer** (mint), one crate | **Rust** (born) |
| `client/` | the app-side UDS client (enqueue · completions subscription · ack · views) | Python (for the Python apps) |
| `dispatchctl/` | the human console over the admin surface | **Go** (with the dispatcher) |
| `tests/` | unit (per package) · integration (compose) · E2E (full job flow + crash injection) · adversarial (hand-written attacks per boundary) | protected |

Every component is **born in its end-state language** — no interim Python, no port phase.
The existing Python `dispatch-kit` / `trust-core` / easy-podcast coordinator are the
behavioural *reference* (what the Go/Rust code must do), retired once the migration deletes
their last consumer.

## Rules for implementers (human or agent)

1. Implement against `contracts/schemas/*.json` and `contracts/states.json` — never against
   prose alone; the prose explains, the schemas bind.
2. `tests/**` is the acceptance gate. Implementation PRs **add** tests and make them pass;
   they do not weaken or delete existing tests. The **adversarial** suites are hand-written,
   never agent-generated, and no implementation PR may modify them.
3. Contract changes are their own human-approved PRs.
4. Every PR cites the DISPATCH_PLANE decision rows it implements.
5. All times are **server-stamped** ms-epoch; runner-reported timings are hints, never truth.
6. **Completion means deletion** — a migration PR is not done until the old code it replaces
   is gone.
