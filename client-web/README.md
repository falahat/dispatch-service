# @dispatch/client-web

The browser signer for the dispatch plane's PEP. One pure, framework-agnostic
crypto module shared by every web peer — the easy-podcast PWA and the antibody
frontend both authenticate with this. It produces the plane's proof-of-possession
(libsodium Ed25519) over the frozen HTTP request contract and the BLAKE2b pairing
MAC. Storage (IndexedDB, etc.) is the app's job: pass the identity and biscuit in,
get signed headers / query params out.

The Rust source of truth for every byte is `dispatch-service/auth/src/`
(`canonical.rs`, `cred.rs`, `http_proxy.rs`). A cross-implementation test in the
`auth` crate verifies a fixed vector emitted by this module.

## The contract this implements

```
canonical: http/v0 <METHOD> <path> <sha256hex(body)> <nonce> <ts>
```

Single ASCII spaces; `METHOD` uppercased; `<path>` is the URL path only (no
query); `<sha256hex(body)>` is lowercase-hex SHA-256 of the raw body
(`sha256hex("")` for an empty body); `<ts>` is the decimal integer epoch-ms.

| field | encoding |
|---|---|
| `pop` | **STANDARD base64, WITH padding** (libsodium `base64_variants.ORIGINAL`) — the Rust PEP decodes it with the STANDARD engine, NOT url-safe |
| `pubkey` | lowercase hex of the 32-byte Ed25519 public key |
| `ts` | decimal string of the integer epoch-millisecond timestamp |
| `nonce` | a fresh random base64 string, used identically in the canonical and on the wire |
| `biscuit` | opaque; stored from pairing and forwarded verbatim (never re-encoded) |

Header-auth attaches five headers: `x-dispatch-{biscuit,pubkey,nonce,ts,pop}`.
Query-auth (signed URLs, empty body) uses the same five as query keys:
`biscuit,pubkey,nonce,ts,pop`.

## API

```ts
import {
  generateIdentity, identityFromSeed,
  signRequest, signQueryParams,
  pairingMac, sodiumReady,
} from '@dispatch/client-web';

// An Ed25519 identity. Persist identity.secretKey in the app's storage.
const identity = await generateIdentity();

// Header-auth (mutating call). Returns the five x-dispatch-* headers.
const headers = await signRequest(identity, biscuit, {
  method: 'POST', path: '/upsert', body: new TextEncoder().encode(json),
});
await fetch('/upsert', { method: 'POST', headers, body: json });

// Query-auth (signed URL, GET/HEAD, empty body). Returns the five raw fields;
// the caller URL-encodes them (e.g. URLSearchParams).
const q = await signQueryParams(identity, biscuit, { method: 'GET', path: '/audio' });
const url = `/audio?${new URLSearchParams({ ...q, id: 'ep42' })}`;

// Pairing redeem MAC (BLAKE2b-256, keyed by the one-time QR token). Hex.
const mac = await pairingMac(tokenBytes, identity.publicKeyHex, timestamp);
```

`sodiumReady()` resolves the initialised libsodium once; the signing functions
await it internally, so calling it yourself is optional (useful to pre-warm WASM).

### Reproducible signatures

`signRequest` / `signQueryParams` take an optional `{ nonce, ts }` override.
Default nonce is fresh 32-byte random (standard-base64); default `ts` is
`Date.now()`. Overrides exist to reproduce fixed vectors — production calls MUST
use the fresh default nonce (header-auth is single-use at the PEP).

## Build & test

```
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest
npm run lint        # eslint
npm run build       # tsc -> dist/ (ESM + .d.ts)
```
