// The peer's Ed25519 identity: the keypair whose private half every per-request
// proof-of-possession signs with, and whose public half (hex) the plane's Biscuit
// binds. The private key is meant to live in the app's storage (IndexedDB in the
// PWA); this module is pure crypto and never touches storage.

import type { Sodium } from './sodium.js';
import { sodiumReady, toHex } from './sodium.js';

/**
 * An Ed25519 identity. `publicKey` is 32 bytes; `secretKey` is libsodium's
 * 64-byte Ed25519 secret key (seed ++ public key) as consumed by
 * `crypto_sign_detached`. `publicKeyHex` is the lowercase-hex the wire + Biscuit
 * use (`x-dispatch-pubkey`).
 */
export interface Identity {
  readonly publicKey: Uint8Array;
  readonly secretKey: Uint8Array;
  readonly publicKeyHex: string;
}

/** The Ed25519 seed length libsodium requires for a deterministic keypair. */
export const SEED_BYTES = 32;

function identityFromKeypair(
  sodium: Sodium,
  keypair: { publicKey: Uint8Array; privateKey: Uint8Array },
): Identity {
  return {
    publicKey: keypair.publicKey,
    secretKey: keypair.privateKey,
    publicKeyHex: toHex(sodium, keypair.publicKey),
  };
}

/** Generate a fresh random Ed25519 identity. */
export async function generateIdentity(): Promise<Identity> {
  const sodium = await sodiumReady();
  return identityFromKeypair(sodium, sodium.crypto_sign_keypair());
}

/**
 * Derive a DETERMINISTIC Ed25519 identity from a 32-byte seed
 * (`crypto_sign_seed_keypair`). Same seed ⇒ same keypair as the Rust
 * `SigningKey::from_bytes(seed)` — the basis of the cross-implementation vector.
 * Throws if the seed is not exactly {@link SEED_BYTES} bytes.
 */
export async function identityFromSeed(seed: Uint8Array): Promise<Identity> {
  if (seed.length !== SEED_BYTES) {
    throw new RangeError(`seed must be ${SEED_BYTES} bytes, got ${seed.length}`);
  }
  const sodium = await sodiumReady();
  return identityFromKeypair(sodium, sodium.crypto_sign_seed_keypair(seed));
}
