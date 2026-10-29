# dispatch-service — agent instructions

The shared GPU **dispatch plane** (Go dispatcher/runner, Rust PEP/PDP + signer, adopted
bazel-remote CAS, embedded smokescreen egress guards). Read `README.md` first (layout,
the frozen `contracts/`, the implementer rules) and `docs/PEP_HTTP.md` for the HTTP
surface. The design rationale lives in easy-podcast's `docs/DISPATCH_PLANE.md`.

This repo is one checkout in a single system whose other repos live under `Code/`
(easy-podcast the product + its `transcription/` workspace, trust-core, antibody-analysis).
Same owner, same bar as `transcription/CLAUDE.md` — that file does
NOT auto-load here, so the load-bearing rules are restated below.

## The bar

Sole user, self-hosted. Downtime is free — never optimize for it or pause for it. The
bar is clean, elegant, readable code + utmost security and privacy.

- One concern per file; names say what the thing IS. Small functions, no clever tricks.
  Comments state invariants and WHY, never what the next line does.
- No duplicate code. Components share **no code, only the contracts** — keep it that way
  (it's what keeps the monorepo splittable).
- Delete retired code completely — completion means deletion, no compat shims, no
  flag-gated corpses, no reconstructing killed designs from git history.
- Rank design options by security, maintainability, elegance, reusability, portability.
  Never sell "small blast radius" / "least churn" / "easier" as a virtue — recommend the
  architecturally-sound option and defend it on quality.

## Security (non-negotiable)

- Be maximally paranoid; never skip a hardening because it churns tests — update the
  tests and do the full pass. Stricter beats broader; fail closed on every reject path.
- Every auth/egress boundary gets adversarial tests — forge, escalate-by-attenuation,
  replay, look-alike hosts, spoofed trust headers, fail-closed assertions. These are
  **hand-written, never agent-generated**, and no implementation change may weaken or
  delete them (`README.md` rule 2).
- The egress guards (`deploy/smokescreen/`) are the plane's SSRF/exfil control. NEVER
  float `@latest` on smokescreen — the old tag ships reachable vulns (GO-2025-3503, an
  HTTP-proxy bypass). Pin a scanned master commit; `deny_ranges` blocks
  metadata/CGNAT/loopback/link-local on the resolved IP at CONNECT, every redirect hop.
  Bump deliberately: bump → `govulncheck` → rebuild (govulncheck also runs as a CI gate).
- Supply chain is gated automatically (`.github/workflows/`, fail-closed on push/PR + weekly):
  `osv-scanner` checks every committed lockfile (`Cargo.lock`, both `go.sum`,
  `client-web/package-lock.json`, `client/uv.lock`) against OSV; `cargo-deny` vets the auth
  crate — advisories/bans/licenses/sources per `auth/deny.toml` (two ignores, both documented
  and justified by unreachability); `govulncheck` covers both Go modules by reachability. Base
  images are digest-pinned; Dependabot opens the upgrade PRs these gates re-check. Lockfiles
  are committed — installs are deterministic (`--locked` / `npm ci` / `uv sync --frozen`).
- Secrets never enter git, logs, or command output. If a secret lands in a transcript,
  disclose it immediately and offer rotation.
- Never assert Tailscale/GCP console state (ACLs, key properties, quotas) from a code
  read — say "verify in your console." Cloud is OFF without explicit per-task permission.

## Contracts & implementation

- Implement against `contracts/schemas/*.json` + `contracts/states.json`, never prose
  alone. A contract change is its own PR and cites the DISPATCH_PLANE decision rows.
- Every component is born in its end-state language — no interim ports.
- All times are server-stamped ms-epoch; runner-reported timings are hints, never truth.

## Gates & mechanics

- **Go** (`dispatcher/`, `runner/`, `internal/`, `deploy/smokescreen/`):
  `gofmt`/`go vet`/`go build`/`go test` all clean. Builds for the plane happen in Docker
  on bigboi; the local Go SDK is at `C:\Users\aryan\go-sdk\go\bin` (no gcc, so no `-race`
  locally — the CI/Docker path covers it).
- **Rust** (`auth/`): `cargo fmt` + `cargo clippy` (deny warnings) + `cargo test` clean.
- **Python** (`client/`): black + ruff + mypy strict, no inline suppressions.

## Process

- Commit incrementally and proactively — one conventional commit per green logical unit,
  straight to main, without being asked. No Co-Authored-By/attribution lines, ever. The
  chain is commit → push → deploy.
- Update docs (README, contracts, PEP_HTTP) IN THE SAME change. Lean, present-tense:
  what IS, pointing at code.
- No parallel/background subagents — read, search, and edit the code yourself.
- Multiple agents work these repos concurrently: re-read state fresh before acting,
  expect the tree to move mid-session, stage only your own paths when committing.

## Deploy — bigboi is production

Everything runs on the desktop `bigboi` (`rosebud@192.168.1.126`; `sudo docker` is
NOPASSWD). The plane deploys as part of easy-podcast's stack via that repo's
`docs/RUNBOOK.md` (`git pull` → `deploy/build.sh` SHA-stamps image tags →
`docker compose -f docker-compose.deploy.yml --env-file deploy/.env up -d`). Recreate
containers freely. Go builds run in Docker on the host, not from the local SDK.
