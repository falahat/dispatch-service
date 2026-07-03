// @dispatch/client-web — the browser signer for the dispatch plane's PEP.
//
// A pure, framework-agnostic crypto module shared by every web peer (the
// easy-podcast PWA, the antibody frontend). It produces the plane's canonical
// proof-of-possession (libsodium Ed25519) over the frozen HTTP request contract
// and the BLAKE2b pairing MAC. Storage (IndexedDB, etc.) is the app's job: pass
// the identity and the biscuit in; get signed headers / query params out.
//
// The plane contract this implements (see dispatch-service `auth/src/`):
//   canonical: `http/v0 <METHOD> <path> <sha256hex(body)> <nonce> <ts>`
//   pop    = STANDARD base64 (padded) Ed25519 signature over the canonical
//   pubkey = lowercase hex of the 32-byte Ed25519 public key
//   ts     = decimal string of integer epoch-ms
//   nonce  = a fresh random base64 string, identical in canonical + header/query
//   header keys: x-dispatch-{biscuit,pubkey,nonce,ts,pop}
//   query  keys: biscuit,pubkey,nonce,ts,pop

export { sodiumReady } from './sodium.js';
export type { Sodium } from './sodium.js';

export { EMPTY_BODY_SHA256_HEX, httpCanonical, sha256Hex } from './canonical.js';

export { generateIdentity, identityFromSeed, SEED_BYTES } from './identity.js';
export type { Identity } from './identity.js';

export { signRequest, signQueryParams, signAuthFields } from './sign.js';
export type {
  AuthFields,
  QueryRequestToSign,
  RequestToSign,
  SignOverrides,
  SignedHeaders,
} from './sign.js';

export { pairingMac } from './pairing.js';
