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
http/v0 <METHOD> <path> <nonce> <ts>
```

`<path>` is the request path **without** the query string. The query is *not*
signed — a signed URL carries its auth fields in the query, and those fields cannot
sign themselves. So a PoP binds the exact method + path (any path tamper breaks it)
while a benign query reordering is tolerated. The body is not signed either; body
integrity, where an app needs it, is the app's concern (the CAS binds content via
its address instead).

Header names for header-auth are the plane-wide `x-dispatch-*` set:
`x-dispatch-biscuit`, `x-dispatch-pubkey`, `x-dispatch-nonce`, `x-dispatch-ts`,
`x-dispatch-pop`. Query-auth uses the same five names as query keys, minus the
prefix: `biscuit`, `pubkey`, `nonce`, `ts`, `pop`.

## Route-table format

TOML (or JSON — anything serde reads). **Phases 3 & 5 must author files in exactly
this shape.**

```toml
# The one loopback backend this surface fronts.
backend = "http://127.0.0.1:5000"

# Optional per-request body cap in bytes (default 64 MiB). A declared
# Content-Length above this is rejected 413 before the body streams.
max_body_bytes = 67108864

# An authed API call: the five PoP fields ride in x-dispatch-* headers.
[[routes]]
methods = ["POST"]
path    = "/upsert"        # exact path
auth    = "header"
right   = "sync_write"     # required capability

# A signed-URL GET: the five PoP fields ride in the query string.
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
| `max_body_bytes` | top level, optional | per-request declared-body cap in bytes (default 64 MiB). |
| `routes` | top level | the array of route entries below. |
| `methods` | route | HTTP methods this route serves, e.g. `["GET"]`, `["POST","PUT"]`. Non-empty. |
| `path` | route | exact-path matcher. Exactly one of `path` / `prefix`. Must start with `/`. |
| `prefix` | route | path-prefix matcher on a **segment boundary**: `/audio` matches `/audio` and `/audio/x`, never `/audioX`. Exactly one of `path` / `prefix`. |
| `auth` | route | `header`, `query`, or `passthrough`. |
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
- Matched an authed route, auth fails → `401` (malformed / stale / replay / bad PoP /
  bad biscuit) or `403` (valid identity, missing right) — the same status policy the
  CAS surface uses.
- Matched a route, auth passes (or passthrough) → streamed to `backend` with the full
  path + query preserved and the `x-dispatch-*` / hop-by-hop headers stripped.

A malformed route table (both `path` and `prefix`, neither, an authed route with no
`right`, a passthrough with a `right`, an unknown `auth`, a bad method) is a **boot
failure** — never a request-time surprise.

## PEP env for the HTTP surface

| env | default | meaning |
|---|---|---|
| `PEP_HTTP_ROUTES` | — | route-table file path. Set with `PEP_HTTP_LISTEN` to enable. |
| `PEP_HTTP_LISTEN` | — | listen address, e.g. `0.0.0.0:9443`. |
| `PEP_HTTP_MAX_REQ_PER_MIN` | `6000` | per-identity request-rate cap (429 over). |
| `PEP_HTTP_MAX_BYTES_PER_MIN` | `4 GiB` | per-identity byte-rate cap (429 over). |
