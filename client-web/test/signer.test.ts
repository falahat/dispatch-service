// Unit tests for the browser signer. These prove the signer is self-consistent
// and, crucially, that its ENCODINGS match the plane's Rust verifier byte-for-
// byte: the exact canonical string, the empty-body hash constant, the STANDARD
// (padded) base64 variant for the PoP, and the pairing MAC (asserted against a
// value produced by easy-podcast's PyNaCl `pairing_mac`).

import { beforeAll, describe, expect, it } from 'vitest';
import {
  EMPTY_BODY_SHA256_HEX,
  generateIdentity,
  httpCanonical,
  identityFromSeed,
  pairingMac,
  sha256Hex,
  signQueryParams,
  signRequest,
  sodiumReady,
  type Identity,
} from '../src/index.js';
import type { Sodium } from '../src/sodium.js';
import { fromStandardBase64, utf8 } from '../src/sodium.js';

let sodium: Sodium;

beforeAll(async () => {
  sodium = await sodiumReady();
});

/** A fixed 32-byte seed → a deterministic identity, for reproducible assertions. */
const SEED = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));

describe('canonical string', () => {
  it('is the exact plane form, single-spaced and http/v0-tagged', () => {
    const s = httpCanonical('post', '/upsert', 'ff'.repeat(32), 'N0nce+/', 1700000000000);
    expect(s).toBe(`http/v0 POST /upsert ${'ff'.repeat(32)} N0nce+/ 1700000000000`);
  });

  it('uppercases the method and never touches the path', () => {
    const s = httpCanonical('get', '/audio/ep 42', EMPTY_BODY_SHA256_HEX, 'x', 1);
    expect(s).toBe(`http/v0 GET /audio/ep 42 ${EMPTY_BODY_SHA256_HEX} x 1`);
  });
});

describe('empty-body hash', () => {
  it('matches the pinned sha256hex("") constant', () => {
    expect(sha256Hex(sodium, new Uint8Array(0))).toBe(EMPTY_BODY_SHA256_HEX);
    expect(EMPTY_BODY_SHA256_HEX).toBe(
      'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    );
  });

  it('hashes a non-empty body to lowercase hex', () => {
    // Known SHA-256 of "abc".
    expect(sha256Hex(sodium, utf8('abc'))).toBe(
      'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad',
    );
  });
});

describe('identity', () => {
  it('derives a deterministic keypair from a seed', async () => {
    const a = await identityFromSeed(SEED);
    const b = await identityFromSeed(SEED);
    expect(a.publicKeyHex).toBe(b.publicKeyHex);
    expect(a.publicKey.length).toBe(32);
    expect(a.secretKey.length).toBe(64); // libsodium Ed25519 sk = seed ++ pk
    expect(a.publicKeyHex).toMatch(/^[0-9a-f]{64}$/);
  });

  it('rejects a wrong-length seed', async () => {
    await expect(identityFromSeed(new Uint8Array(31))).rejects.toThrow(RangeError);
  });

  it('generates distinct random identities', async () => {
    const a = await generateIdentity();
    const b = await generateIdentity();
    expect(a.publicKeyHex).not.toBe(b.publicKeyHex);
  });
});

/** Verify a PoP against a canonical string using libsodium directly (the same
 * primitive the Rust `verify_pop` uses under the hood). */
function popVerifies(id: Identity, canonical: string, popB64: string): boolean {
  const sig = fromStandardBase64(sodium, popB64);
  return sodium.crypto_sign_verify_detached(sig, utf8(canonical), id.publicKey);
}

describe('signRequest (header auth)', () => {
  it('round-trips: the PoP verifies over the rebuilt canonical', async () => {
    const id = await identityFromSeed(SEED);
    const body = utf8('{"k":"v"}');
    const h = await signRequest(id, 'BISCUIT', { method: 'POST', path: '/upsert', body });
    expect(h['x-dispatch-biscuit']).toBe('BISCUIT');
    expect(h['x-dispatch-pubkey']).toBe(id.publicKeyHex);
    const canonical = httpCanonical(
      'POST',
      '/upsert',
      sha256Hex(sodium, body),
      h['x-dispatch-nonce'],
      Number(h['x-dispatch-ts']),
    );
    expect(popVerifies(id, canonical, h['x-dispatch-pop'])).toBe(true);
  });

  it('binds the body: a PoP for one body fails over another', async () => {
    const id = await identityFromSeed(SEED);
    const h = await signRequest(id, 'B', { method: 'POST', path: '/upsert', body: utf8('A') });
    const wrong = httpCanonical(
      'POST',
      '/upsert',
      sha256Hex(sodium, utf8('B')), // hash of a DIFFERENT body
      h['x-dispatch-nonce'],
      Number(h['x-dispatch-ts']),
    );
    expect(popVerifies(id, wrong, h['x-dispatch-pop'])).toBe(false);
  });

  it('uses the empty-body hash for a bodyless request', async () => {
    const id = await identityFromSeed(SEED);
    const h = await signRequest(id, 'B', { method: 'POST', path: '/ping' });
    const canonical = httpCanonical(
      'POST',
      '/ping',
      EMPTY_BODY_SHA256_HEX,
      h['x-dispatch-nonce'],
      Number(h['x-dispatch-ts']),
    );
    expect(popVerifies(id, canonical, h['x-dispatch-pop'])).toBe(true);
  });

  it('emits a fresh nonce on each call', async () => {
    const id = await identityFromSeed(SEED);
    const a = await signRequest(id, 'B', { method: 'POST', path: '/x' });
    const b = await signRequest(id, 'B', { method: 'POST', path: '/x' });
    expect(a['x-dispatch-nonce']).not.toBe(b['x-dispatch-nonce']);
  });

  it('honours overrides for a reproducible signature (Ed25519 is deterministic)', async () => {
    const id = await identityFromSeed(SEED);
    const o = { nonce: 'fixed-nonce', ts: 1700000000000 };
    const a = await signRequest(id, 'B', { method: 'POST', path: '/x' }, o);
    const b = await signRequest(id, 'B', { method: 'POST', path: '/x' }, o);
    expect(a['x-dispatch-pop']).toBe(b['x-dispatch-pop']);
  });
});

describe('signQueryParams (query auth)', () => {
  it('round-trips over the empty-body canonical', async () => {
    const id = await identityFromSeed(SEED);
    const p = await signQueryParams(id, 'BISCUIT', { method: 'GET', path: '/audio' });
    expect(p.biscuit).toBe('BISCUIT');
    expect(p.pubkey).toBe(id.publicKeyHex);
    const canonical = httpCanonical('GET', '/audio', EMPTY_BODY_SHA256_HEX, p.nonce, Number(p.ts));
    expect(popVerifies(id, canonical, p.pop)).toBe(true);
  });
});

describe('base64 variant (pop encoding)', () => {
  it('emits STANDARD (padded) base64, decodable as ORIGINAL', async () => {
    const id = await identityFromSeed(SEED);
    const h = await signRequest(id, 'B', { method: 'POST', path: '/x' });
    const pop = h['x-dispatch-pop'];
    // A 64-byte Ed25519 signature → 88 standard-base64 chars incl. padding.
    expect(pop.length).toBe(88);
    expect(pop.endsWith('=')).toBe(true);
    // Decodes under the ORIGINAL (standard) variant to exactly 64 bytes.
    expect(fromStandardBase64(sodium, pop).length).toBe(64);
    // It must NOT be the url-safe variant: url-safe alphabet never contains
    // '+' or '/', but if this pop happens to have neither we skip that check —
    // padding + length above already pins the STANDARD variant.
  });

  it('produces a pop that fails to decode as strict URLSAFE when it contains + or /', async () => {
    // Find a signature that actually exercises the standard-only alphabet so the
    // variant distinction is observable, then prove url-safe strict decode rejects it.
    let popWithSpecial: string | undefined;
    for (let i = 0; i < 50 && popWithSpecial === undefined; i++) {
      const id = await generateIdentity();
      const h = await signRequest(id, 'B', { method: 'POST', path: '/x' });
      if (h['x-dispatch-pop'].includes('+') || h['x-dispatch-pop'].includes('/')) {
        popWithSpecial = h['x-dispatch-pop'];
      }
    }
    expect(popWithSpecial, 'expected a standard-base64 pop with + or /').toBeDefined();
    expect(() =>
      sodium.from_base64(popWithSpecial as string, sodium.base64_variants.URLSAFE),
    ).toThrow();
  });
});

describe('pairingMac', () => {
  it('matches easy-podcast PyNaCl pairing_mac for a fixed vector', async () => {
    // Vector produced by easy-podcast's `sync/phoneauth.py::pairing_mac`
    // (PyNaCl keyed BLAKE2b-256 over pubkey_hex || timestamp).
    const token = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));
    const pubkeyHex = 'aa'.repeat(32);
    const timestamp = '1700000000.5';
    const mac = await pairingMac(token, pubkeyHex, timestamp);
    expect(mac).toBe('71176746685443deb11ae7a9b0c91c31ec5e95bd2f17c755c3d90e4f0f78cde7');
  });

  it('is keyed: a different token yields a different MAC', async () => {
    const a = await pairingMac(new Uint8Array(32), 'aa'.repeat(32), '1');
    const b = await pairingMac(new Uint8Array(32).fill(1), 'aa'.repeat(32), '1');
    expect(a).not.toBe(b);
  });
});
