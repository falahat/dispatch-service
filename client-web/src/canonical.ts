// The canonical request string the proof-of-possession signs — byte-for-byte the
// plane's `auth/src/canonical.rs` `Op::Http` form:
//
//   http/v0 <METHOD> <path> <sha256hex(body)> <nonce> <ts>
//
// Single ASCII spaces; METHOD uppercase; `<path>` is the URL path only (NO query
// — the query carries signed-URL auth fields that must not sign themselves);
// `<sha256hex(body)>` is the lowercase-hex SHA-256 of the raw request body;
// `<ts>` is the decimal string of an integer epoch-millisecond timestamp.

import type { Sodium } from './sodium.js';
import { toHex } from './sodium.js';

/**
 * `sha256hex("")` — the body hash for every empty-body request (GET/HEAD, and any
 * bodyless POST). Pinned as a constant so a caller can assert the empty case
 * without hashing, and so this value is checked against Rust in the vitest suite.
 */
export const EMPTY_BODY_SHA256_HEX =
  'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

/** Lowercase-hex SHA-256 of `body`. Empty input yields {@link EMPTY_BODY_SHA256_HEX}. */
export function sha256Hex(sodium: Sodium, body: Uint8Array): string {
  return toHex(sodium, sodium.crypto_hash_sha256(body));
}

/**
 * Build the exact canonical string the PoP covers. `method` is uppercased,
 * `path` is used verbatim (the caller must pass the URL path without its query),
 * `ts` is the decimal integer epoch-ms.
 */
export function httpCanonical(
  method: string,
  path: string,
  bodySha256Hex: string,
  nonce: string,
  ts: number,
): string {
  return `http/v0 ${method.toUpperCase()} ${path} ${bodySha256Hex} ${nonce} ${ts}`;
}
