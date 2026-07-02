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
| `dispatcher/` | the work service: durable queue (SQLite WAL), leases, retries, cost admission, fleet | Python → Go |
| `runner/` | the shared worker client image; drives compute containers over the invoke protocol | Python → Go |
| `pep/` | the auth enforcement proxy + PDP — the **single verify engine**, in-path on both the CAS and the dispatcher's runner surface (backends get pre-authed requests over loopback) | **Rust (born)** |
| `client/` | the app-side UDS client (enqueue · completions subscription · ack · views) | Python |
| `dispatchctl/` | the human console over the admin surface | Go (with the dispatcher) |
| `tests/conformance/` | golden wire transcripts + crash-injection property tests — **defines** conformant | **protected path** |
| `tests/adversarial/` | attack suites for every boundary — **hand-written, never agent-written** | **protected path** |

## Rules for implementers (human or agent)

1. Implement against `contracts/schemas/*.json` and `contracts/states.json` — never against
   prose alone; the prose explains, the schemas bind.
2. `tests/conformance/**` and `tests/adversarial/**` are **protected paths**: implementation
   PRs must not modify them. You make red files green; you do not move the bar.
3. Contract changes are their own PRs, human-approved, additive-only within a major version.
4. Every PR cites the DISPATCH_PLANE decision rows it implements.
5. All times are **server-stamped** ms-epoch; runner-reported timings are hints, never truth.
