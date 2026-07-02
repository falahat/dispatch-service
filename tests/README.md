# tests/ — the acceptance gate

Ordinary, thorough testing — no bespoke cross-language equivalence apparatus. A component is
correct when it passes these; a migration step is done when the old code is deleted and these
still pass. Implementation PRs **add** tests and make them green; they never weaken or delete
existing ones.

## unit/ — per package, per component

Fast, isolated tests for the pure logic and each component's internals: the decision rules
(backoff by class, quarantine on two-witness evidence, the claim predicate), address
parse/verify/traversal-guard, the state-machine transitions derived from
`../contracts/states.json` (every illegal transition asserted impossible), schema validation
of every frame.

## integration/ — components over the real wire (compose)

Two real components at a time against the frozen contracts: dispatcher ⇄ runner (lease →
complete/fail/release, fencing, idempotency), PEP ⇄ dispatcher and PEP ⇄ CAS (auth accepted
/ denied, per-lease attenuation), app-client ⇄ dispatcher (enqueue idempotency, pushed
completions, ack, subscription takeover), runner ⇄ compute (the invoke protocol, `runner
check`).

## e2e/ — the whole plane, real flow + crashes

`compose.dev.yml` brings up dispatcher + CAS + PEP + a fake app + the echo-compute image and
drives full job flows: enqueue → lease → invoke → CAS → complete → persist → ack. Plus the
resilience claims, by **injecting crashes/kills** at each step and asserting the invariants:
no lost job, no double-lease, no double-persist, exactly-once effect, correct
release-vs-fail, backpressure pauses leasing, app-outage delays but never loses. A few
fixture episodes are checked against known-good outputs as a sanity assertion.

## adversarial/ — attacks, hand-written (never agent-generated)

Per the standing rule, one file per boundary, each asserting the fail-closed outcome so "the
attack is still defended" stays a green test forever: replay, stale/fenced complete, forged
lane, enqueue-dedup abuse, budget-cap bypass, quarantine dodge, release-gaming (unstartable
loop), lease-takeover, subscription-takeover; CAS: mismatched-hash put, junk-flood vs quota,
oversize stream, cross-job fetch probe, partial-upload visibility, manifest traversal path;
auth: PoP replay across a restart, forged/attenuated-beyond-grant token, expired credential.
