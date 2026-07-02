# Contracts v0 — the frozen surface everything implements

These files **are** the specification. Prose (`*.md`) explains; schemas (`schemas/*.json`)
and `states.json` bind; the suites under `../tests/` enforce. Nothing is implemented against
prose alone. All four contracts share one design spine — **content addressing for identity,
capability tokens for authority, idempotency + fencing for safety, integers + RFC 8785 for
cross-language determinism** — so an agent that has internalized one reads the others fast.

| Contract | Boundary | Reply-bearing peer | Auth |
|---|---|---|---|
| [WIRE.md](WIRE.md) + [`schemas/wire.schema.json`](schemas/wire.schema.json) | dispatcher ⇄ runner (tailnet), dispatcher ⇄ app (UDS) | dispatcher | Biscuit+PoP (runner); socket perms (app) |
| [ARTIFACTS.md](ARTIFACTS.md) + [`schemas/artifacts.schema.json`](schemas/artifacts.schema.json) | what rides in the CAS (invocation · manifest · action result) + the digest rule | — | content-addressed integrity |
| [INVOKE.md](INVOKE.md) | runner ⇄ compute container (local HTTP) | compute container | none (compute is jailed, credential-less) |
| [CAS.md](CAS.md) | runner/app ⇄ CAS, via the PEP (HTTP) | PEP | Biscuit+PoP |
| [states.json](states.json) | the job state machine (shared by dispatcher + conformance) | — | — |

## The seven design invariants (cite these in PRs)

1. **Content addressing is identity.** Two identities, never conflated: `job_key` (intent,
   enqueue-time, idempotency) vs `invocation_digest` (computation, build-time, provenance/memo).
2. **Idempotency everywhere.** enqueue on live `job_key`; complete/fail on `(job_id, attempt)`;
   ack on `PERSISTING`; CAS put on address. Replays are safe by construction.
3. **Fencing, not guessing.** `lease_id` gates every terminal runner verb; stale holders are
   rejected by token.
4. **One failure verb per phase.** `release` (couldn't start, no attempt) · `fail` (compute
   broke, attempt burned) · `ack(rejected)` (output garbage, terminal).
5. **Delivery is the dispatcher's job.** Long-poll leases, pushed completions; nothing polls.
6. **Server-stamped time.** One clock; runner timings are hints.
7. **Cross-language determinism is mechanical.** RFC 8785 canonicalization; **integers only**
   among numbers (decimals as strings); strict schemas (unknown fields rejected).

## Versioning

`v0.x` — additive minors within major 0; a new optional field or enum value bumps the minor.
Any removal, rename, or semantic change to an existing field is a **major** bump and a
human-approved contract PR. Implementations negotiate exact-major / highest-common-minor in
`hello`.
