// Unit tests for the browser signer. They prove the DPoP proof the phone signs is a
// well-formed RFC 9449 proof JWT whose signature verifies against its embedded jwk, and
// whose claims bind the method / URI / biscuit / body exactly as the plane's Rust PEP
// (`auth/src/dpop.rs`) checks. Cross-language agreement with the PEP is proven separately
// (a `jose`-signed proof and a PyJWT-signed proof both verify under `jsonwebtoken`); here
// we pin the browser signer's own shape + bindings. The pairing MAC is asserted against a
// value produced by easy-podcast's PyNaCl `pairing_mac`.

import { beforeAll, describe, expect, it } from 'vitest';
import { EmbeddedJWK, jwtVerify, type JWTVerifyResult } from 'jose';
import {
  buildDpopProof,
  dpopHeaders,
  dpopQuery,
  generateIdentity,
  identityFromSeed,
  pairingMac,
  sodiumReady,
} from '../src/index.js';

beforeAll(async () => {
  await sodiumReady();
});

/** A fixed 32-byte seed → a deterministic identity, for reproducible assertions. */
const SEED = new Uint8Array(Array.from({ length: 32 }, (_, i) => i));

const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

function base64url(bytes: Uint8Array): string {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** base64url(sha256(data)) — the value the `ath` + `content-digest` claims carry. */
async function sha256Base64Url(data: Uint8Array): Promise<string> {
  const buffer = new ArrayBuffer(data.byteLength);
  new Uint8Array(buffer).set(data);
  return base64url(new Uint8Array(await crypto.subtle.digest('SHA-256', buffer)));
}

/** Verify a proof the way the PEP does: against the key embedded in its own header. */
function verifyProof(proof: string): Promise<JWTVerifyResult> {
  return jwtVerify(proof, EmbeddedJWK, { algorithms: ['EdDSA'] });
}

describe('DPoP proof', () => {
  it('is a dpop+jwt whose signature verifies against its embedded Ed25519 jwk', async () => {
    const id = await identityFromSeed(SEED);
    const proof = await buildDpopProof(id, {
      method: 'POST',
      htu: 'https://h.test/upsert',
      biscuit: 'BISC',
      body: utf8('{"k":"v"}'),
    });
    const { payload, protectedHeader } = await verifyProof(proof);
    expect(protectedHeader.typ).toBe('dpop+jwt');
    expect(protectedHeader.alg).toBe('EdDSA');
    const jwk = protectedHeader.jwk as { kty: string; crv: string; x: string };
    expect(jwk.kty).toBe('OKP');
    expect(jwk.crv).toBe('Ed25519');
    expect(jwk.x).toBe(base64url(id.publicKey)); // advertises the phone's public key
    expect(payload.htm).toBe('POST');
    expect(payload.htu).toBe('https://h.test/upsert');
    expect(typeof payload.iat).toBe('number');
    expect(typeof payload.jti).toBe('string');
  });

  it('binds the biscuit via ath and the body via content-digest', async () => {
    const id = await identityFromSeed(SEED);
    const body = utf8('the-body');
    const { payload } = await verifyProof(
      await buildDpopProof(id, { method: 'POST', htu: 'https://h/x', biscuit: 'BISCUIT', body }),
    );
    expect(payload.ath).toBe(await sha256Base64Url(utf8('BISCUIT')));
    expect(payload['content-digest']).toBe(await sha256Base64Url(body));
  });

  it('uppercases the method into htm', async () => {
    const id = await identityFromSeed(SEED);
    const { payload } = await verifyProof(
      await buildDpopProof(id, { method: 'get', htu: 'https://h/a', biscuit: 'B' }),
    );
    expect(payload.htm).toBe('GET');
  });

  it('uses the empty-body digest for a bodyless request', async () => {
    const id = await identityFromSeed(SEED);
    const { payload } = await verifyProof(
      await buildDpopProof(id, { method: 'POST', htu: 'https://h/ping', biscuit: 'B' }),
    );
    expect(payload['content-digest']).toBe(await sha256Base64Url(new Uint8Array(0)));
  });

  it('emits a fresh jti on each call', async () => {
    const id = await identityFromSeed(SEED);
    const a = await verifyProof(
      await buildDpopProof(id, { method: 'POST', htu: 'https://h/x', biscuit: 'B' }),
    );
    const b = await verifyProof(
      await buildDpopProof(id, { method: 'POST', htu: 'https://h/x', biscuit: 'B' }),
    );
    expect(a.payload.jti).not.toBe(b.payload.jti);
  });

  it('rejects a tampered proof (the signature no longer verifies)', async () => {
    const id = await identityFromSeed(SEED);
    const proof = await buildDpopProof(id, {
      method: 'POST',
      htu: 'https://h/x',
      biscuit: 'B',
      body: utf8('a'),
    });
    // Flip the first char of the payload segment; the signature must fail.
    const parts = proof.split('.');
    const payloadSeg = parts[1] ?? '';
    parts[1] = (payloadSeg.startsWith('A') ? 'B' : 'A') + payloadSeg.slice(1);
    await expect(verifyProof(parts.join('.'))).rejects.toThrow();
  });
});

describe('dpopHeaders (header auth)', () => {
  it('carries the biscuit in Authorization and a bound proof in DPoP', async () => {
    const id = await identityFromSeed(SEED);
    const { authorization, dpop } = await dpopHeaders(id, {
      method: 'POST',
      htu: 'https://h/upsert',
      biscuit: 'BISCUIT',
      body: utf8('x'),
    });
    expect(authorization).toBe('DPoP BISCUIT');
    const { payload } = await verifyProof(dpop);
    expect(payload.ath).toBe(await sha256Base64Url(utf8('BISCUIT')));
    expect(payload['content-digest']).toBe(await sha256Base64Url(utf8('x')));
  });
});

describe('dpopQuery (query auth)', () => {
  it('carries the biscuit + a bodyless proof for a signed URL', async () => {
    const id = await identityFromSeed(SEED);
    const { biscuit, dpop } = await dpopQuery(id, {
      method: 'GET',
      htu: 'https://h/audio',
      biscuit: 'BISCUIT',
    });
    expect(biscuit).toBe('BISCUIT');
    const { payload } = await verifyProof(dpop);
    expect(payload.htm).toBe('GET');
    expect(payload.htu).toBe('https://h/audio');
    expect(payload['content-digest']).toBe(await sha256Base64Url(new Uint8Array(0)));
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
