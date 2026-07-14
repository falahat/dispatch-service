# PEP HTTP mode — fronting an app's HTTP surface

The PEP has three in-path surfaces. Two are fixed (the dispatcher's framed runner
surface and the CAS). The third is **generic HTTP**: it fronts one app's loopback
HTTP backend (its Flask/FastAPI server) and enforces Biscuit + a per-request **DPoP
proof** per a static **route table** before streaming each request through. The
backend binds loopback only, holds no auth crypto, and sees only pre-authenticated
traffic — identical to the CAS surface, but the capability for each `(method, path)`
is named by the route table rather than a fixed CAS convention.

Enabling it is opt-in: set **both** `PEP_HTTP_ROUTES` (a route-table file) and
`PEP_HTTP_LISTEN` (the surface's listen address). Absent, the PEP serves only the
runner + CAS surfaces, exactly as before.

The runner + CAS surfaces keep their bespoke canonical-string PoP (`cas/v0`,
`dispatch/v0`); only this browser-facing HTTP surface uses DPoP.

## DPoP proof (what the client signs)

The per-request proof is an **RFC 9449 DPoP proof JWT** — a short-lived JWS the holder
signs with the Ed25519 key its Biscuit binds. The client uses a maintained JOSE library
(browser `jose`, Python PyJWT); the PEP verifies with `jsonwebtoken` (EdDSA) and owns
only the DPoP-specific claim checks. There is no hand-rolled canonical string.

- **header:** `typ = dpop+jwt`, `alg = EdDSA`, `jwk` = the holder's PUBLIC Ed25519 key
  (OKP). The `alg` allowlist (EdDSA only) is the alg-confusion defense. The raw key from
  the `jwk` is what the PEP binds against the Biscuit's `pubkey(<hex>)` fact — same key
  material, hex vs base64url, so no thumbprint and no Biscuit change. Trusting the
  in-proof `jwk` is not circular: the root-signed Biscuit is what authorizes that key.
- **claims:**
  - `htm` — the request method; `htu` — the request URI **without query/fragment**.
    The PEP rebuilds `htu` from its **configured public origin + the request path**,
    never from a client `Host`/`X-Forwarded-*` header (TLS terminates at the Serve edge).
  - `ath = base64url(sha256(biscuit))` — binds the proof to *this* Biscuit.
  - `content-digest = base64url(sha256(body))` — binds the full body (the empty-body
    digest for a bodyless GET). The PEP buffers the body under a hard cap, hashes it, and
    checks this against the *delivered* bytes, so post-signing tampering fails closed. We
    do **not** trust the transport to protect the body. (Plain base64url of the hash — NOT
    the RFC 9530 structured-field `Content-Digest` header.)
  - `iat` (freshness) + `jti` (single-use replay id).

**Carriers.** Header-auth rides `Authorization: DPoP <biscuit>` + `DPoP: <proof-jwt>`.
Query-auth (signed URLs, where a browser `<audio>`/`<img>` can't set headers) rides the
`biscuit` + `dpop` query params; the proof's `htu` is the path only, so the query — which
carries the auth — is not signed.

## Replay discipline: single-use vs freshness-only

- **`header` auth is SINGLE-USE.** The proof `jti` is consumed on the first verify, so an
  exact replay of a mutating call is rejected (durably, across a PEP restart).
- **`query` auth is FRESHNESS-ONLY.** The `iat` must be within the freshness window (so a
  signed URL still **expires**), but the `jti` is **not** stored. A browser reusing one
  signed URL across range requests / retries (e.g. an `<audio>` element seeking) is
  therefore not replay-rejected. Because a freshness-only credential is reusable within
  its window, `query` auth is restricted to **idempotent GET/HEAD** routes — a mutating
  query route is rejected at boot.

The freshness window is the plane-wide `PEP_FRESHNESS_MS` (default 5 min).

## Verified identity handed to the backend

On an **authed** route (`header` or `query`), the PEP forwards the verified caller
identity to the loopback backend as **`x-dispatch-identity: <pubkey-hex>`** — the same
Ed25519 pubkey the credential is bound to (the runner/device fingerprint). The backend
attributes the request to that identity **without holding any auth crypto**.

Credentials are consumed at the boundary. Header auth never forwards `Authorization` or
`DPoP`; query auth removes `biscuit` and `dpop` while preserving application parameters.

This header is un-spoofable: the PEP strips **every** client `x-dispatch-*` header (and the
consumed `Authorization` / `DPoP` headers) before injecting its own, so a client that sends
`x-dispatch-identity: someone-else` has it dropped and replaced with the PEP-verified value.
On a **passthrough** route there is no verified identity, so **no** `x-dispatch-identity` is
injected (and any client-sent one is still stripped).

## Route-table format

TOML (or JSON — anything serde reads). **Phases 3 & 5 must author files in exactly
this shape.**

```toml
# The PEP's public origin (scheme + host, no path). REQUIRED: the DPoP `htu` a proof
# must match is rebuilt from this + the request path, so it is a trusted config value,
# never a client header. A missing origin fails at boot.
origin = "https://easypod.tail46021f.ts.net"

# The one loopback backend this surface fronts.
backend = "http://127.0.0.1:5000"

# Optional per-request body cap in bytes (default 64 MiB). Enforced by counting
# bytes WHILE buffering — a lying or absent Content-Length cannot smuggle an
# oversize body past it; the request is rejected 413 the moment the cap is hit.
max_body_bytes = 67108864

# An authed API call: `Authorization: DPoP <biscuit>` + a `DPoP:` proof header.
[[routes]]
methods = ["POST"]
path    = "/upsert"        # exact path
auth    = "header"
right   = "sync_write"     # required capability

# A signed-URL GET: the biscuit + dpop proof ride in the query string.
# Query auth is GET/HEAD only (freshness-only reusable reads).
[[routes]]
methods = ["GET"]
prefix  = "/audio"         # matches /audio and /audio/... (segment boundary)
auth    = "query"
right   = "audio_get"

# Unauthenticated passthrough: the app shell, the enrollment redeem endpoint.
[[routes]]
methods = ["GET"]
path    = "/pair/redeem"
auth    = "passthrough"    # no `right`
```

### Fields

| field | where | meaning |
|---|---|---|
| `origin` | top level | the PEP's public origin (scheme + host, no path), e.g. `https://host.ts.net`. **Required**: the DPoP `htu` is rebuilt from this + the request path. A bare host (no scheme) or a missing value is a boot failure. |
| `backend` | top level | loopback base URL, e.g. `http://127.0.0.1:5000`. |
| `max_body_bytes` | top level, optional | per-request body cap in bytes, enforced while buffering (default 64 MiB). |
| `routes` | top level | the array of route entries below. |
| `methods` | route | HTTP methods this route serves, e.g. `["GET"]`, `["POST","PUT"]`. Non-empty. |
| `path` | route | exact-path matcher. Exactly one of `path` / `prefix`. Must start with `/`. |
| `prefix` | route | path-prefix matcher on a **segment boundary**: `/audio` matches `/audio` and `/audio/x`, never `/audioX`. Exactly one of `path` / `prefix`. `prefix = "/"` is **rejected at boot** — a catch-all is inexpressible; publish the root with `path = "/"` and name each path. |
| `auth` | route | `header` (single-use, any method), `query` (freshness-only, GET/HEAD only), or `passthrough`. |
| `right` | route | the required capability for `header` / `query`. Omitted (and rejected) for `passthrough`. |

### Matching

Routing is resolved **once**, from `(method, path)` only, **before any auth**, by
**longest, most-specific match** (an exact `path` beats a `prefix`; a longer prefix
beats a shorter one). Route order in the file is irrelevant. Because the decision is
made before auth and depends only on the request line, a **passthrough route can
never be used to reach an authed route** — a request is authenticated iff the route
it matched says so.

- No matching path → `404`.
- Matching path but no matching method → `405`.
- Body over the cap → `413` (caught while buffering).
- Matched an authed route, auth fails → `401` (malformed / stale / replay / bad DPoP
  proof — signature, `htm`/`htu`/`ath`/`content-digest` mismatch, tampered body — or bad
  biscuit) or `403` (valid identity, missing right) — the same status policy the CAS
  surface uses.
- Per-identity rate exceeded → `429`.
- Matched a route, auth passes (or passthrough) → forwarded to `backend` with application
  parameters preserved, the true buffered length set, and auth + hop-by-hop fields removed.
  The response body streams straight back.

A malformed route table (a missing/scheme-less `origin`, both `path` and `prefix`,
neither, a `prefix = "/"` catch-all, an authed route with no `right`, a passthrough with
a `right`, an unknown `auth`, a bad method, or a `query` route on a non-GET/HEAD method)
is a **boot failure** — never a request-time surprise.

## Credential revocation (deny-list)

Revocation is a **plane-wide** control shared by all three surfaces (runner, CAS,
HTTP), independent of the route table. A credential is revoked by putting one of its
Biscuit **revocation identifiers** on a **live-reloaded deny-list file**. `verify()`
computes the presented credential's revocation identifiers and denies (**403** /
`forbidden`) if **any** is on the list — checked *after* the signature parse and
*before* the capability check, so a revoked credential is denied regardless of the
right it would otherwise satisfy.

- **Revoke the authority-block id and every attenuation dies too.** A token's
  revocation identifiers always include its authority-block id, which every
  attenuated child inherits — so one deny-list entry kills the base credential and
  all leases derived from it.
- **Live reload, no restart.** The file is re-read when its mtime/size changes, so
  writing it denies the *very next* request. A **missing** file means nothing is
  revoked (not an error); a present-but-malformed file keeps the last-known-good set
  (a revocation is never *lost* to a bad write) and is logged.

Deny-list file format:

```json
{
  "revoked": [
    { "id": "<lowercase-hex revocation id>", "note": "why", "revoked_at": 0 }
  ]
}
```

`id` is a lowercase-hex Biscuit revocation identifier. The **signer** records each
credential's authority-block revocation id at enrollment and the `signer revoke
--pubkey <hex>` subcommand appends it to this file (see the signer CLI).

## PEP env for the HTTP surface

| env | default | meaning |
|---|---|---|
| `PEP_HTTP_ROUTES` | — | route-table file path. Set with `PEP_HTTP_LISTEN` to enable. |
| `PEP_HTTP_LISTEN` | — | listen address, e.g. `0.0.0.0:9443`. |
| `PEP_HTTP_MAX_REQ_PER_MIN` | `6000` | per-identity request-rate cap (429 over). |
| `PEP_HTTP_MAX_BYTES_PER_MIN` | `4 GiB` | per-identity byte-rate cap (429 over). |
| `PEP_REVOCATION_DB` | `pep-revocations.json` | live-reloaded credential deny-list (shared across all three surfaces). |
