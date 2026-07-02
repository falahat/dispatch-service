# tests/conformance — PROTECTED PATH

Golden wire transcripts + crash-injection property tests. **This directory defines what
"conformant" means**; every dispatcher, runner, PEP, or client implementation — in any
language, as its shipped container — must pass it unchanged.

Implementation PRs MUST NOT modify anything here. Changes to this directory are contract
changes: their own PRs, human-approved, versioned with the contract.

Core properties (derived from `contracts/states.json` + `contracts/WIRE.md`):
no lost job · no double-lease · exactly-once effect (at-least-once delivery + idempotent
persist) · correct release-vs-fail phase mapping · fencing (stale `lease_id` never mutates)
· subscription redelivery of `PERSISTING` on reconnect · newest-subscriber takeover ·
backpressure at the watermark · legal transitions only.
