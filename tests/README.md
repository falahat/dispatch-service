# tests/ — the acceptance gate (protected paths)

`conformance/` and `adversarial/` **define** what "correct" means for every component. They
are authored by maintainers, not by implementation PRs. CI enforces two rules: (1) an
implementation PR that modifies either tree fails; (2) every component image must pass the
suites for its surface before merge.

## conformance/ — behaviour, as data

- `vectors/` — **language-neutral test-vector files** (JSON). Each case: inputs + required
  outcome. Loaded identically by every implementation in every language (the Wycheproof /
  JSON-Schema-test-suite pattern). Subtrees:
  - `wire/` — golden request→response transcripts per verb + the `states.json`-derived
    legal-transition matrix (every illegal transition asserted impossible).
  - `artifacts/` — canonicalization + digest vectors (same invocation → same
    `invocation_digest` across languages; the integer-only and RFC-8785 rules exercised).
  - `auth/` — the trust-core verdict vectors (accept / deny-with-reason). **Python
    trust-core and the Rust PEP MUST both pass this file** — the born-Rust PEP is what makes
    language-neutrality real in Phase 1, not Phase 5.
- `crash/` — crash-injection property tests: kill any component at any step; assert no lost
  job, no double-lease, no double-persist, exactly-once effect, correct release-vs-fail.

## adversarial/ — attacks, hand-written

Per the standing rule, **hand-written, never agent-generated**, one file per boundary:
replay, stale/fenced complete, forged lane, enqueue-dedup abuse, budget-cap bypass,
quarantine dodge, release-gaming (unstartable loop), lease-takeover, subscription-takeover;
CAS: mismatched-hash put, junk-flood vs quota, oversize stream, cross-job fetch probe,
partial-upload visibility, traversal path in a manifest.

Each attack states its expected fail-closed outcome as a vector, so "the attack is still
defended" is a green test forever.
