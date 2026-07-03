# PEP HTTP mode — fronting an app's HTTP surface

The PEP has three in-path surfaces. Two are fixed (the dispatcher's framed runner
surface and the CAS). The third is **generic HTTP**: it fronts one app's loopback
HTTP backend (its Flask/FastAPI server) and enforces Biscuit + PoP per a static
**route table** before streaming each request through. The backend binds loopback
only, holds no auth crypto, and sees only pre-authenticated traffic — identical to
the CAS surface, but the capability for each `(method, path)` is named by the route
table rather than a fixed CAS convention.

Enabling it is opt-in: set **both** `PEP_HTTP_ROUTES` (a route-table file) and
`PEP_HTTP_LISTEN` (the surface's listen address). Absent, the PEP serves only the
runner + CAS surfaces, exactly as before.

## Canonical string (what the PoP signs)

```
http/v0 <METHOD> <path> <sha256hex(body)> <nonce> <ts>
```

The PoP binds **method + path + the full request body**. `<path>` is the request
path **without** the query string; `<sha256hex(body)>` is the lowercase hex SHA-256
of the raw request body (`sha256hex(b"")` for an empty GET/HEAD body).

- **Body-binding (why).** The PEP buffers the body under a hard cap, hashes it, and
  rebuilds this string from the *delivered* bytes — so tampering with the body after
  signing breaks the PoP. We do **not** trust the transport to protect the body
  ("the tunnel protects it" is the trust-the-tunnel assumption the plane rejects).
  This matches the Python `trust_core` engine the apps use today.
- **The query is NOT signed.** A signed URL carries its auth fields in the query, and
  those fields cannot sign themselves. So a PoP binds the exact method + path (any
  path tamper breaks it) while a benign query reordering is tolerated.

Header names for header-auth are the plane-wide `x-dispatch-*` set:
`x-dispatch-biscuit`, `x-dispatch-pubkey`, `x-dispatch-nonce`, `x-dispatch-ts`,
`x-dispatch-pop`. Query-auth uses the same five names as query keys, minus the
prefix: `biscuit`, `pubkey`, `nonce`, `ts`, `pop`.

## Nonce discipline: single-use vs freshness-only

- **`header` auth is SINGLE-USE.** The nonce is consumed on the first verify, so an
  exact replay of a mutating call is rejected (durably, across a PEP restart).
- **`query` auth is FRESHNESS-ONLY.** The `ts` must be within the freshness window
  (so a signed URL still **expires**), but the nonce is **not** stored. A browser
  reusing one signed URL across range requests / retries (e.g. an `<audio>` element
  seeking) is therefore not replay-rejected. Because a freshness-only credential is
  reusable within its window, `query` auth is restricted to **idempotent GET/HEAD**
  routes — a mutating query route is rejected at boot.

The freshness window is the plane-wide `PEP_FRESHNESS_MS` (default 5 min).

## Verified identity handed to the backend

On an **authed** route (`header` or `query`), the PEP forwards the verified caller
identity to the loopback backend as **`x-dispatch-identity: <pubkey-hex>`** — the same
Ed25519 pubkey the credential is bound to (the runner/device fingerprint). The backend
attributes the request to that identity **without holding any auth crypto**.

This header is un-spoofable: the PEP strips **every** client `x-dispatch-*` header before
injecting its own, so a client that sends `x-dispatch-identity: someone-else` has it
dropped and replaced with the PEP-verified value. On a **passthrough** route there is no
verified identity, so **no** `x-dispatch-identity` is injected (and any client-sent one is
still stripped).

## Route-table format

TOML (or JSON — anything serde reads). **Phases 3 & 5 must author files in exactly
this shape.**

```toml
# The one loopback backend this surface fronts.
backend = "http://127.0.0.1:5000"

# Optional per-request body cap in bytes (default 64 MiB). Enforced by counting
# bytes WHILE buffering — a lying or absent Content-Length cannot smuggle an
# oversize body past it; the request is rejected 413 the moment the cap is hit.
max_body_bytes = 67108864

# An authed API call: the five PoP fields ride in x-dispatch-* headers.
[[routes]]
methods = ["POST"]
path    = "/upsert"        # exact path
auth    = "header"
right   = "sync_write"     # required capability

# A signed-URL GET: the five PoP fields ride in the query string.
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
| `backend` | top level | loopback base URL, e.g. `http://127.0.0.1:5000`. |
| `max_body_bytes` | top level, optional | per-request body cap in bytes, enforced while buffering (default 64 MiB). |
| `routes` | top level | the array of route entries below. |
| `methods` | route | HTTP methods this route serves, e.g. `["GET"]`, `["POST","PUT"]`. Non-empty. |
| `path` | route | exact-path matcher. Exactly one of `path` / `prefix`. Must start with `/`. |
| `prefix` | route | path-prefix matcher on a **segment boundary**: `/audio` matches `/audio` and `/audio/x`, never `/audioX`. Exactly one of `path` / `prefix`. |
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
- Matched an authed route, auth fails → `401` (malformed / stale / replay / bad PoP /
  bad biscuit / tampered body) or `403` (valid identity, missing right) — the same
  status policy the CAS surface uses.
- Per-identity rate exceeded → `429`.
- Matched a route, auth passes (or passthrough) → forwarded to `backend` with the full
  path + query preserved, the true buffered length set, and the `x-dispatch-*` /
  hop-by-hop headers stripped. The response body streams straight back.

A malformed route table (both `path` and `prefix`, neither, an authed route with no
`right`, a passthrough with a `right`, an unknown `auth`, a bad method, or a `query`
route on a non-GET/HEAD method) is a **boot failure** — never a request-time
surprise.

## PEP env for the HTTP surface

| env | default | meaning |
|---|---|---|
| `PEP_HTTP_ROUTES` | — | route-table file path. Set with `PEP_HTTP_LISTEN` to enable. |
| `PEP_HTTP_LISTEN` | — | listen address, e.g. `0.0.0.0:9443`. |
| `PEP_HTTP_MAX_REQ_PER_MIN` | `6000` | per-identity request-rate cap (429 over). |
| `PEP_HTTP_MAX_BYTES_PER_MIN` | `4 GiB` | per-identity byte-rate cap (429 over). |
