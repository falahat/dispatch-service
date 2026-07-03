// The pairing redeem MAC — the browser's half of easy-podcast's QR pairing flow.
//
// Byte-identical to easy-podcast's `sync/phoneauth.py::pairing_mac`:
//   mac = keyed-BLAKE2b-256(key = one-time token bytes,
//                           message = utf8(pubkeyHex + timestamp))
// returned as lowercase hex (the server compares against `mac` in the redeem body
// via `bytes.fromhex`). libsodium's `crypto_generichash` IS BLAKE2b, so a 32-byte
// digest under a keyed hash reproduces PyNaCl's `blake2b(msg, digest_size=32,
// key=token)` exactly. This is why the signer uses libsodium and not WebCrypto —
// WebCrypto has no BLAKE2b.

import { sodiumReady, toHex, utf8 } from './sodium.js';

/**
 * Compute the pairing redeem MAC. `token` is the raw bytes of the one-time QR
 * token (the keyed-hash key), `pubkeyHex` is the peer's lowercase-hex Ed25519
 * public key, and `timestamp` is the redeem timestamp string, concatenated to the
 * pubkey verbatim (the server passes the identical string through to its MAC, so
 * the two sides must format it the same way). Returns lowercase hex.
 */
export async function pairingMac(
  token: Uint8Array,
  pubkeyHex: string,
  timestamp: string,
): Promise<string> {
  const sodium = await sodiumReady();
  const message = utf8(pubkeyHex + timestamp);
  const mac = sodium.crypto_generichash(32, message, token);
  return toHex(sodium, mac);
}
