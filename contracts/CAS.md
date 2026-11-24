# CAS contract v0 — the byte plane, as seen through the PEP

Normative. The store is **bazel-remote** (adopted; it hash-verifies CAS puts natively, so the
PEP inherits integrity). This page specifies the surface the **PEP** (Rust) exposes to
runners and apps — the only way bytes move. (A swap to MinIO would only require the PEP to
stream-verify PUTs itself; blobs are content-addressed, so no migration.)

## HTTP surface

| Method + path | Semantics |
|---|---|
| `GET /blobs/sha256/<hex>` | stream the blob or `404`. Consumers MUST verify-on-read regardless (trust lives in the address, not the store). |
| `HEAD /blobs/sha256/<hex>` | existence + `Content-Length`; used by manifest-aware fetch planning. |
| `PUT /blobs/sha256/<hex>` | body = the bytes. `Content-Length` REQUIRED. Streamed to a temp object, hashed en route; hash ≠ claimed address → `400 hash_mismatch`, temp discarded (a partial or failed upload is never readable). Existing address → `200` (idempotent no-op). New → `201`. |
| *(no LIST, no DELETE on this surface)* | enumeration and deletion are admin/GC-only. A GET requires knowing the exact 256-bit name. |

Errors: `401 unauthenticated · 403 forbidden · 404 not_found · 400 hash_mismatch ·
409 busy · 413 too_large · 429 quota_exceeded · 507 store_full`.

A client bounds how long a response may take to begin, counted from when the request, body
included, is sent (the runner: 30 s), so a hung store fails a transfer instead of stalling
it. The body may then take as long as it needs.

## Auth (enforced by the PEP, per request)

- Biscuit + PoP; canonical string `cas/v0 <METHOD> /blobs/sha256/<hex> <nonce> <ts>` —
  note the address in the path IS the content commitment for PUT, so the signature binds
  the bytes without hashing twice.
- Rights: `right("cas_get")` for GET/HEAD, `right("cas_put")` for PUT. Per-identity
  policy: `max_blob_bytes` (per lane class), rolling byte + request quotas. Denials are
  logged as first-class outcomes.
- **Per-lease narrowing (contract 0.4):** a credential whose authority grants
  `right("lease")` (a runner's) may GET only the blobs of a job it holds a live lease on: the
  invocation, each input, and each file of a `manifest` input. It may HEAD or PUT only while
  it holds a live lease. Anything else is `403 not_in_lease`. The PEP records each grant it
  relays on the runner surface before the runner sees it, reading the job's invocation and
  manifests from the store for at most 5 s; past that the lease covers only the invocation,
  and the runner, refused the rest, releases the job. The lease ends at the runner's
  `complete`, `fail` or `release`, and one that heartbeats do not renew expires after its
  `ttl_s` (a heartbeat reply that tells the runner to abandon the job stops renewal). The
  book is held in memory: after a PEP restart a running job is refused until it is granted
  again, so its runner releases it (`cas_unreachable` or `shipping`) and it runs again on the
  same attempt. An
  application credential (`cas_get`/`cas_put` without `lease`) is not narrowed. A PEP that
  serves the CAS surface without the runner surface gives runner credentials no CAS access.
  This bounds a leaked worker credential to the jobs that worker is running and closes the
  digest-as-capability membership oracle for runners.
- The PEP holds **no private keys** (verifier only) and streams — it MUST NOT buffer whole
  blobs.

## Retention (the GC contract)

- **Pinned**: any blob referenced by a non-terminal job — its `invocation_address`, every
  address reachable through that invocation (manifest closure), and every address in a
  `PERSISTING` action result. Ack-gated: pins release at `SUCCEEDED / FAILED / REJECTED /
  CANCELLED`.
- **Mortal**: unpinned blobs are deleted after the orphan TTL (default 24 h). The adopted
  store's own LRU is a backstop only; **the GC owns deletion** and runs against the
  dispatcher's pin view.
- Volume sizing: ≥ (staging window per `plan_stage`) + (inbox watermark × max output size).
  `507 store_full` is an operational alarm, never a silent eviction.

## Cloud lane

The GCS staging bucket is the **same address space** over a different backend: objects
keyed `sha256/<hex>`, fetched by signed URL, verified identically on read. `get(address)`
resolution order is deployment config (co-located store first; GCS for cloud-lane runners).
