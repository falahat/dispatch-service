// Sign a request for the plane's PEP: build the canonical string, produce the
// Ed25519 proof-of-possession, and emit either the five `x-dispatch-*` headers
// (header-auth: mutating calls, single-use nonce) or the five query parameters
// (query-auth: signed-URL GET/HEAD reads, freshness-only).

import type { Identity } from './identity.js';
import type { Sodium } from './sodium.js';
import { sodiumReady, toStandardBase64, utf8 } from './sodium.js';
import { EMPTY_BODY_SHA256_HEX, httpCanonical, sha256Hex } from './canonical.js';

/** How many random bytes back a request nonce (base64-encoded on the wire). */
const NONCE_BYTES = 32;

/** A request to sign. `path` MUST be the URL path only, without the query string. */
export interface RequestToSign {
  /** HTTP method; uppercased into the canonical string. */
  readonly method: string;
  /** URL path only (no query, no fragment), e.g. `/upsert`. */
  readonly path: string;
  /** Raw request body. Omit or pass empty for a bodyless request (GET/HEAD/POST). */
  readonly body?: Uint8Array | undefined;
}

/** A request whose body is always empty (GET/HEAD signed URLs). */
export interface QueryRequestToSign {
  readonly method: string;
  readonly path: string;
}

/** The five plane-wide auth fields, before they are placed in headers or a query. */
export interface AuthFields {
  readonly biscuit: string;
  readonly pubkey: string;
  readonly nonce: string;
  readonly ts: string;
  readonly pop: string;
}

/** The `x-dispatch-*` header set for a header-auth request. */
export interface SignedHeaders {
  readonly 'x-dispatch-biscuit': string;
  readonly 'x-dispatch-pubkey': string;
  readonly 'x-dispatch-nonce': string;
  readonly 'x-dispatch-ts': string;
  readonly 'x-dispatch-pop': string;
}

/** Optional overrides for the volatile fields — used only to reproduce fixed vectors. */
export interface SignOverrides {
  /** Force the nonce (default: a fresh 32-byte random, standard-base64). */
  readonly nonce?: string | undefined;
  /** Force the timestamp in epoch-ms (default: `Date.now()`). */
  readonly ts?: number | undefined;
}

function freshNonce(sodium: Sodium): string {
  return toStandardBase64(sodium, sodium.randombytes_buf(NONCE_BYTES));
}

/**
 * Sign `req` and return the five auth fields. The nonce is fresh random
 * (standard-base64) unless overridden; the timestamp is `Date.now()` unless
 * overridden. The PoP is the Ed25519 signature over the canonical string,
 * encoded as STANDARD (padded) base64 — the variant the Rust PEP decodes.
 */
export async function signAuthFields(
  identity: Identity,
  biscuit: string,
  req: RequestToSign,
  bodySha256Hex: string,
  overrides: SignOverrides = {},
): Promise<AuthFields> {
  const sodium = await sodiumReady();
  const nonce = overrides.nonce ?? freshNonce(sodium);
  const ts = overrides.ts ?? Date.now();
  const canonical = httpCanonical(req.method, req.path, bodySha256Hex, nonce, ts);
  const sig = sodium.crypto_sign_detached(utf8(canonical), identity.secretKey);
  return {
    biscuit,
    pubkey: identity.publicKeyHex,
    nonce,
    ts: String(ts),
    pop: toStandardBase64(sodium, sig),
  };
}

/**
 * Sign a (possibly body-bearing) request for HEADER auth. Returns the five
 * `x-dispatch-*` headers to attach to the outbound request. Header-auth is
 * single-use at the PEP, so each call MUST use a fresh nonce (the default).
 */
export async function signRequest(
  identity: Identity,
  biscuit: string,
  req: RequestToSign,
  overrides: SignOverrides = {},
): Promise<SignedHeaders> {
  const sodium = await sodiumReady();
  const body = req.body ?? new Uint8Array(0);
  const bodyHash = body.length === 0 ? EMPTY_BODY_SHA256_HEX : sha256Hex(sodium, body);
  const f = await signAuthFields(identity, biscuit, req, bodyHash, overrides);
  return {
    'x-dispatch-biscuit': f.biscuit,
    'x-dispatch-pubkey': f.pubkey,
    'x-dispatch-nonce': f.nonce,
    'x-dispatch-ts': f.ts,
    'x-dispatch-pop': f.pop,
  };
}

/**
 * Sign a GET/HEAD request for QUERY auth (a signed URL). The body is always
 * empty, so the canonical binds `sha256hex("")`. Returns the five query
 * parameters (`biscuit`, `pubkey`, `nonce`, `ts`, `pop`) to append to the URL.
 * The returned values are RAW — the caller URL-encodes them when building the
 * query (e.g. via `URLSearchParams`).
 */
export async function signQueryParams(
  identity: Identity,
  biscuit: string,
  req: QueryRequestToSign,
  overrides: SignOverrides = {},
): Promise<AuthFields> {
  return signAuthFields(
    identity,
    biscuit,
    { method: req.method, path: req.path },
    EMPTY_BODY_SHA256_HEX,
    overrides,
  );
}
