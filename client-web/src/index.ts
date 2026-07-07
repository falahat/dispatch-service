// @dispatch/client-web — the browser signer for the dispatch plane's PEP.
//
// A pure, framework-agnostic crypto module shared by every web peer (the
// easy-podcast PWA, the antibody frontend). It produces the plane's per-request
// proof — an RFC 9449 DPoP proof JWT (via `jose`, over the phone's Ed25519 key) —
// and the BLAKE2b pairing MAC. Storage (IndexedDB, etc.) is the app's job: pass the
// identity + the biscuit in; get the DPoP headers / query params out.
//
// The plane contract this implements (see dispatch-service `auth/src/dpop.rs`):
//   Authorization: DPoP <biscuit>        the capability (a plane Biscuit)
//   DPoP: <proof-jwt>                     the proof: typ=dpop+jwt, alg=EdDSA, jwk=<pubkey>
//   proof claims: htm, htu, iat, jti, ath=sha256(biscuit), content-digest=sha256(body)
//   signed-URL reads carry `biscuit` + `dpop` as query params instead (freshness-only)

export { sodiumReady } from './sodium.js';
export type { Sodium } from './sodium.js';

export { generateIdentity, identityFromSeed, SEED_BYTES } from './identity.js';
export type { Identity } from './identity.js';

export { buildDpopProof, dpopHeaders, dpopQuery } from './dpop.js';
export type { DpopHeaders, DpopQuery, DpopRequest } from './dpop.js';

export { pairingMac } from './pairing.js';
