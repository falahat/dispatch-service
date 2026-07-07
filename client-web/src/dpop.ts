// The phone's per-request proof of possession: an RFC 9449 DPoP proof JWT.
//
// This is the browser side of the contract the plane's Rust PEP (`auth/src/dpop.rs`)
// verifies and the Python client (`easy_podcast.sync.planeauth`) also signs. The proof
// is a short-lived JWT produced by `jose` (panva) over the phone's Ed25519 key — its
// PUBLIC half embedded as an OKP `jwk` header, so the PEP verifies the signature
// against it AND binds that key to the Biscuit's `pubkey` fact. The claims bind:
//   htm             = the request method (uppercase)
//   htu             = the target URI, scheme+host+path, NO query
//   ath             = base64url(sha256(biscuit))     — the presented capability
//   content-digest  = base64url(sha256(body))        — the exact body (empty for a GET)
//   iat, jti        = freshness + single-use replay
//
// There is NO hand-rolled canonical string: the JWS framing + Ed25519 signature are the
// library's, and the claim set agrees with Rust + Python by NAME (a standard JWT), not
// by a fragile byte layout. `alg` is `EdDSA` — the value every runtime here speaks.

import { SignJWT, importJWK } from 'jose';
import type { Identity } from './identity.js';

/** The JOSE header `typ` a DPoP proof MUST carry (RFC 9449 §4.2). */
const DPOP_TYP = 'dpop+jwt';

/** The interoperable JWS alg for Ed25519 — what the Rust PEP + Python signer both speak. */
const DPOP_ALG = 'EdDSA';

/** URL-safe base64 without padding — the JOSE encoding for a jwk's `x` and the digest claims. */
function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** SHA-256 of `data` via WebCrypto, as raw bytes. */
async function sha256(data: Uint8Array): Promise<Uint8Array> {
  // Hash a fresh ArrayBuffer-backed copy: WebCrypto's BufferSource type rejects a
  // Uint8Array that TS believes might be SharedArrayBuffer-backed (TS 5.7 typed-array
  // generics). The inputs here are small (a biscuit string, an app-JSON body).
  const buffer = new ArrayBuffer(data.byteLength);
  new Uint8Array(buffer).set(data);
  return new Uint8Array(await crypto.subtle.digest('SHA-256', buffer));
}

/** A fresh single-use proof id (`jti`): 16 random bytes, base64url. */
function freshJti(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return base64url(bytes);
}

/** The public OKP jwk advertised in the proof header (the key the PEP binds + verifies against). */
function publicJwk(identity: Identity): { kty: 'OKP'; crv: 'Ed25519'; x: string } {
  return { kty: 'OKP', crv: 'Ed25519', x: base64url(identity.publicKey) };
}

/** Import the phone's Ed25519 key into WebCrypto for signing, via its OKP jwk. */
async function signingKey(identity: Identity): Promise<CryptoKey> {
  // libsodium's 64-byte secret key is seed(32) ++ public(32); the OKP `d` is the 32-byte seed.
  const seed = identity.secretKey.slice(0, 32);
  const jwk = { ...publicJwk(identity), d: base64url(seed) };
  return (await importJWK(jwk, DPOP_ALG)) as CryptoKey;
}

/** A request to prove. `htu` is the target URI (scheme+host+path, NO query). */
export interface DpopRequest {
  /** HTTP method; uppercased into the `htm` claim. */
  readonly method: string;
  /** The target URI, scheme+host+path, without query or fragment. */
  readonly htu: string;
  /** The presented Biscuit (base64) — bound via the `ath` claim. */
  readonly biscuit: string;
  /** The exact request body; omit or pass empty for a bodyless request. */
  readonly body?: Uint8Array | undefined;
}

/**
 * Build the RFC 9449 DPoP proof JWT for `req`, signed by `identity`. `iat` is the
 * current time (seconds) and `jti` is fresh, so each call is single-use at the PEP.
 */
export async function buildDpopProof(identity: Identity, req: DpopRequest): Promise<string> {
  const key = await signingKey(identity);
  const body = req.body ?? new Uint8Array(0);
  const ath = base64url(await sha256(new TextEncoder().encode(req.biscuit)));
  const contentDigest = base64url(await sha256(body));
  return new SignJWT({
    htm: req.method.toUpperCase(),
    htu: req.htu,
    ath,
    'content-digest': contentDigest,
  })
    .setProtectedHeader({ typ: DPOP_TYP, alg: DPOP_ALG, jwk: publicJwk(identity) })
    .setIssuedAt()
    .setJti(freshJti())
    .sign(key);
}

/** The header-auth carriers: `Authorization: DPoP <biscuit>` + `DPoP: <proof>`. */
export interface DpopHeaders {
  readonly authorization: string;
  readonly dpop: string;
}

/**
 * Sign a (possibly body-bearing) request for HEADER auth. The Biscuit rides in the
 * `Authorization: DPoP` header and the fresh single-use proof in `DPoP`.
 */
export async function dpopHeaders(identity: Identity, req: DpopRequest): Promise<DpopHeaders> {
  const proof = await buildDpopProof(identity, req);
  return { authorization: `DPoP ${req.biscuit}`, dpop: proof };
}

/** The signed-URL query carriers: `biscuit` + `dpop` (a browser `<audio>`/`<img>` can't set headers). */
export interface DpopQuery {
  readonly biscuit: string;
  readonly dpop: string;
}

/**
 * Sign a bodyless GET/HEAD request for QUERY auth (a signed URL). The body is always
 * empty; `htu` is the path only, so the query — which carries these params — is not
 * part of what the proof signs. Returns the raw values; the caller URL-encodes them.
 */
export async function dpopQuery(identity: Identity, req: DpopRequest): Promise<DpopQuery> {
  const proof = await buildDpopProof(identity, { ...req, body: new Uint8Array(0) });
  return { biscuit: req.biscuit, dpop: proof };
}
