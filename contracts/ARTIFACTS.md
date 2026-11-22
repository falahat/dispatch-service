# Artifacts contract v0 — addresses, invocation, manifest, action result

Normative. Schemas: [`schemas/artifacts.schema.json`](schemas/artifacts.schema.json) bind.

## Addresses

`sha256:<64 lowercase hex>` — a blob named by the SHA-256 of its bytes. Rules every
component MUST enforce:

1. **Validate shape before any use** (regex `^sha256:[0-9a-f]{64}$`); an address is data,
   never a path fragment — no filesystem or URL interpolation of unvalidated input.
2. **Verify on read**: after fetching, re-hash and compare to the requested address; a
   mismatch is an integrity failure (runner → `release{integrity}` + telemetry; app →
   refuse to persist).
3. **Verify on write**: a store/PEP MUST reject a put whose bytes do not hash to the claimed
   address. Existing address → success without rewrite (idempotent; same hash ⇒ same bytes).

## Invocation (`kind: "invocation/v0"`)

The app-authored description of one computation, stored in the CAS; its address rides in the
grant. The compute container receives it verbatim.

```jsonc
{
  "kind": "invocation/v0",
  "op": "transcribe",            // [a-z0-9_]{1,64}
  "op_version": 2,               // integer; bump on any semantic change to the op
  "params": { ... },             // arbitrary JSON object, canonicalization rules below
  "inputs": {                    // name -> input; names [a-z0-9_]{1,64}, ≤ 64 entries
    "audio":  { "address": "sha256:…", "kind": "blob" },
    "corpus": { "address": "sha256:…", "kind": "manifest" }
  }
}
```

- `kind: "blob"` → the runner fetches one blob to `inputs/<name>`.
- `kind: "manifest"` → the runner fetches the manifest, then every listed entry into
  `inputs/<name>/<entry.path>`, verifying each. Incremental by construction: entries the
  runner already holds (same address) need no transfer.
- `kind: "local"` → `{"kind": "local", "node": "bigboi", "root": "runs", "path": "K/fit"}`,
  with no address: a file or folder where it lies on `node`, at `path` (a manifest entry's
  path shape with no `.` segment) under the root its runner was installed with as `root`
  (`--root NAME=DIR`, [COMMAND.md](COMMAND.md#local-roots)). The runner on that node checks
  the place through an `os.Root` opened on the root, so no `..`, absolute path or link
  leads out of it, and hands the compute the place's path where it lies; nothing is
  fetched, hashed or copied. The job is pinned to that node (`policy.node`,
  [WIRE.md](WIRE.md#policy-block-dispatcher-enforced-only)); a runner on another node
  gives it back (`release{wrong_hardware}`), and a root that runner lacks or a missing
  path fails it as `bad_input` (D10, D11).

## Computation identity — the invocation's own address (no separate digest)

**The invocation's CAS address IS its computation identity.** Because
`invocation_address = sha256(invocation bytes)` and the invocation is exactly
`{op, op_version, params, input addresses}`, that one address already names the precise
computation — Bazel's *action key*, realized as content rather than recomputed. It is the
provenance key (fetch it back to see exactly what ran) and the future action-cache key. The
two identities stay distinct: **`job_key`** (intent, enqueue-time, idempotency) vs
**`invocation_address`** (computation, build-time, provenance/memo).

There is **no separate `invocation_digest`, and therefore no cross-language canonicalizer** —
every component but the authoring app compares addresses as opaque strings.

- **Canonicalization is an app-side SHOULD, not a wire MUST.** The app SHOULD emit stable
  bytes (sorted keys) so re-building the same computation yields the same address and the
  action cache hits. It is never correctness-critical: a formatting drift costs at most a
  memo miss (a recompute), never a wrong result.
- A local input is named by its place, not its bytes, so an invocation that has one does
  not pin what was read: reusing its result takes the app's own knowledge that the place
  is unchanged.
- **`params` numbers MUST still be integers** (decimals as strings, `"temperature": "0.7"`;
  the schema rejects fractional/exponent forms) — retained not for digest determinism but
  because `params` are read by **compute containers in arbitrary languages**, where float
  parsing is ambiguous.

## Manifest (`kind: "manifest/v0"`)

```jsonc
{
  "kind": "manifest/v0",
  "entries": [                    // ≤ 65536 entries
    { "path": "ep-0042/embeddings.bin", "address": "sha256:…", "size": 1048576 }
  ]
}
```
`path` MUST be a relative path with no `..` segment, no leading `/`, no backslash, and no
NUL (the traversal guard is schema-level *and* MUST be re-checked by the consumer).
Manifests are themselves CAS blobs, so a corpus snapshot is one small address and the
Merkle composition pins every byte transitively. Manifests the runner and client write
list their entries sorted by `path`.

## Action result (`kind: "action_result/v0"`)

The runner's `complete` payload — **addresses and numbers only, never domain bytes**:

```jsonc
{
  "kind": "action_result/v0",
  "invocation_address": "sha256:…",   // echoed from the grant — the computation that ran
  "outputs": {                         // ≤ 64, names as inputs
    "transcript": { "address": "sha256:…", "size": 482133, "kind": "blob" },
    "frames":     { "address": "sha256:…", "size": 9120, "kind": "manifest" }
  },
  "metrics": { "wall_s": 512, "work_units": 3600, "peak_vram_mb": 9800 },  // integers only
  "runner":  { "node": "desktop-ai", "version": "runner/0.1.0" }
}
```

An output is one file (`kind: "blob"`, or no `kind`) or one folder (`kind: "manifest"`).
A folder output's address names a `manifest/v0` of the folder's files, paths relative to
that folder, and its `size` counts the manifest's own bytes. A folder output is already a
valid `manifest` input, so a later invocation takes it by address with no copy.

An output may instead be local, `{"kind": "local", "node", "root", "path", "size"}`: a place
the compute named under one of its runner's roots, reported where it lies and never read or
uploaded. `size` is a file's size, and 0 for a folder. It is a valid local input for a later
job on that node (D10).

The runner **echoes** `invocation_address` from its grant (it cannot lie — it fetched exactly
that address, whose bytes are hash-bound). The app resolves `outputs` from the CAS
(verify-on-read), parses fail-closed, persists into its own store, then `ack`s. A re-persist after redelivery MUST be a no-op (content-addressed
domain ids make this natural).
