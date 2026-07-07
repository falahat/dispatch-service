# @dispatch/client-web

The browser signer for the dispatch plane's PEP. One pure, framework-agnostic
crypto module shared by every web peer — the easy-podcast PWA and the antibody
frontend both authenticate with this. It produces the plane's per-request proof —
an RFC 9449 **DPoP proof JWT** (via [`jose`](https://github.com/panva/jose), over the
peer's Ed25519 key) — and the BLAKE2b pairing MAC (libsodium). Storage (IndexedDB,
etc.) is the app's job: pass the identity + biscuit in, get the DPoP headers / query
params out.

The Rust source of truth is `dispatch-service/auth/src/dpop.rs` (the PEP's
`jsonwebtoken` verifier). Because the wire format is a standard JWS/JWT, agreement is
library-guaranteed, not byte-kept: a cross-implementation test in the `auth` crate
verifies a PyJWT-signed proof, and this signer's `jose` output uses the identical JWS.

## The contract this implements

Per request the peer signs a **DPoP proof JWT**:

- **header** — `typ = dpop+jwt`, `alg = EdDSA`, `jwk` = the peer's PUBLIC Ed25519 key
  (OKP). The PEP verifies the signature against that key and binds it (hex of the raw
  key) to the Biscuit's `pubkey(<hex>)` fact.
- **claims** — `htm` (method), `htu` (scheme+host+path, **no query**),
  `ath = base64url(sha256(biscuit))`, `content-digest = base64url(sha256(body))` (empty
  digest for a bodyless GET), `iat` (freshness), `jti` (single-use replay).

`alg` is `EdDSA` — the value the Rust PEP (`jsonwebtoken`) and the Python signer (PyJWT)
all speak. Carriers: header-auth sends `Authorization: DPoP <biscuit>` + `DPoP: <proof>`;
query-auth (signed URLs, empty body) sends the `biscuit` + `dpop` query params.

## API

```ts
import {
  generateIdentity, identityFromSeed,
  dpopHeaders, dpopQuery,
  pairingMac, sodiumReady,
} from '@dispatch/client-web';

// An Ed25519 identity. Persist identity.secretKey in the app's storage.
const identity = await generateIdentity();

// Header-auth (mutating call). `htu` is the request URI, no query.
// Returns { authorization: 'DPoP <biscuit>', dpop: '<proof-jwt>' }.
const headers = await dpopHeaders(identity, {
  method: 'POST', htu: `${location.origin}/upsert`, biscuit,
  body: new TextEncoder().encode(json),
});
await fetch('/upsert', { method: 'POST', headers, body: json });

// Query-auth (signed URL, GET/HEAD, empty body). Returns { biscuit, dpop } — the
// caller URL-encodes them (e.g. URLSearchParams) alongside any app params.
const q = await dpopQuery(identity, { method: 'GET', htu: `${location.origin}/audio`, biscuit });
const url = `/audio?${new URLSearchParams({ ...q, id: 'ep42' })}`;

// Pairing redeem MAC (BLAKE2b-256, keyed by the one-time QR token). Hex.
const mac = await pairingMac(tokenBytes, identity.publicKeyHex, timestamp);
```

`sodiumReady()` resolves the initialised libsodium once (used by the pairing MAC + key
handling); the functions await it internally, so calling it yourself is optional. The
DPoP proof uses WebCrypto Ed25519 via `jose` — available in every target browser and
Node 18+. Each proof carries a fresh `iat` + `jti`, so header-auth is single-use at the
PEP; do not cache a proof across requests.

## Build & test

```
npm install
npm run typecheck   # tsc --noEmit
npm test            # vitest
npm run lint        # eslint
npm run build       # tsc -> dist/ (ESM + .d.ts)
```
