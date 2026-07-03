// libsodium bootstrap + the exact encodings the plane's Rust verifier expects.
//
// The plane's `auth/src/cred.rs` decodes each field with a FIXED encoding, so the
// browser must emit the matching one byte-for-byte:
//   - pop  : STANDARD base64 WITH padding  (base64::engine::general_purpose::STANDARD)
//   - pubkey: lowercase hex of the 32-byte Ed25519 public key
//   - nonce: an opaque base64 string, used identically in the canonical and the
//            header/query (the verifier treats it as a string, not decoded bytes)
//
// We centralise those choices here so no call site can pick the wrong variant.

import _sodium from 'libsodium-wrappers-sumo';

/** The concrete libsodium module type, once ready. */
export type Sodium = typeof _sodium;

let readyPromise: Promise<Sodium> | undefined;

/**
 * Resolve the initialised libsodium module. Safe to call repeatedly and
 * concurrently: initialisation happens exactly once and every caller awaits the
 * same promise.
 */
export function sodiumReady(): Promise<Sodium> {
  if (readyPromise === undefined) {
    readyPromise = _sodium.ready.then(() => _sodium);
  }
  return readyPromise;
}

/** Lowercase hex of `bytes` (matches Rust `hex::encode`, which is lowercase). */
export function toHex(sodium: Sodium, bytes: Uint8Array): string {
  // libsodium's to_hex is lowercase, matching Rust's `hex` crate.
  return sodium.to_hex(bytes);
}

/** Decode lowercase/uppercase hex to bytes. Throws on malformed input. */
export function fromHex(sodium: Sodium, hex: string): Uint8Array {
  return sodium.from_hex(hex);
}

/**
 * STANDARD base64 WITH padding — the variant the Rust PEP decodes the PoP with
 * (`STANDARD.decode`). NOT the url-safe default. Every PoP signature and biscuit
 * on the wire uses this variant.
 */
export function toStandardBase64(sodium: Sodium, bytes: Uint8Array): string {
  return sodium.to_base64(bytes, sodium.base64_variants.ORIGINAL);
}

/** Decode STANDARD (padded) base64 to bytes. */
export function fromStandardBase64(sodium: Sodium, b64: string): Uint8Array {
  return sodium.from_base64(b64, sodium.base64_variants.ORIGINAL);
}

/** UTF-8 encode a string to bytes. */
export function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}
