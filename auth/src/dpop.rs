//! RFC 9449 DPoP proof verification for the browser-facing HTTP surface.
//!
//! The per-request proof is a **DPoP proof JWT** (RFC 9449): a short-lived JWS the
//! holder signs with the Ed25519 private key its Biscuit binds. Unlike the runner
//! surfaces' bespoke canonical string (`crate::canonical`), the wire format here is
//! a standard JWT — produced by maintained JOSE libraries on the clients (browser
//! `jose`, Python `joserfc`) and parsed/verified by a maintained JWT crate here
//! (`jsonwebtoken`, EdDSA, pure Rust). Only the DPoP-specific binding checks below
//! are ours; the JWS framing and signature are the library's.
//!
//! What the proof carries and what we check:
//! - header `typ = dpop+jwt`, `alg = EdDSA`, `jwk` = the holder's PUBLIC Ed25519 key.
//!   The `alg` allowlist (EdDSA only) is what defeats alg-confusion (`none`, or
//!   HS256 using the public key as an HMAC secret). The raw key from the `jwk` is
//!   the pubkey we bind against the Biscuit's `pubkey(<hex>)` fact — same key
//!   material as the runner PoP, hex vs base64url, so NO thumbprint and no Biscuit
//!   change. Trusting the in-proof `jwk` is NOT circular: the signature only proves
//!   "signed by whoever this key is"; the ROOT-SIGNED Biscuit is what says that key
//!   is authorized (the authorizer's `presented_pubkey` check, in `cred.rs`).
//! - `htm`/`htu` — the request method + URI (no query). A captured proof can't be
//!   replayed on another route. `htu` is rebuilt by the PEP from its CONFIGURED
//!   public origin + the request path, never from a client Host header.
//! - `ath = base64url(sha256(biscuit))` — binds the proof to THIS Biscuit, so a
//!   valid proof can't be paired with a different (also-valid) credential.
//! - `content-digest = base64url(sha256(body))` — end-to-end body integrity, the
//!   one thing TLS can't give us (TLS terminates at the Serve edge; the body then
//!   crosses internal plaintext hops). Its value is the plain base64url of the body
//!   hash — NOT the RFC 9530 structured-field `Content-Digest` header.
//! - `iat` + `jti` — freshness and single-use replay, handled downstream by the
//!   shared nonce store (`cred::verify_http_dpop`), exactly like the runner PoP's
//!   `ts` + `nonce`.

use crate::cred::ProvenIdentity;
use crate::error::{AuthError, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use jsonwebtoken::jwk::{AlgorithmParameters, EllipticCurve};
use jsonwebtoken::{decode, decode_header, Algorithm, DecodingKey, Validation};
use sha2::{Digest, Sha256};

/// The JOSE header `typ` a DPoP proof MUST carry (RFC 9449 §4.2).
const DPOP_TYP: &str = "dpop+jwt";

/// The DPoP proof claim set we require. Every field is mandatory: a missing claim
/// fails deserialization, so `decode` rejects the proof before we read anything.
#[derive(serde::Deserialize)]
struct ProofClaims {
    /// HTTP method (uppercase), bound to the request's method.
    htm: String,
    /// HTTP target URI without query/fragment, bound to the PEP-rebuilt origin+path.
    htu: String,
    /// Issued-at, epoch SECONDS (JWT NumericDate). Freshness is the server window.
    iat: i64,
    /// Unique proof id — the single-use replay key.
    jti: String,
    /// `base64url(sha256(biscuit))` — binds the proof to the presented Biscuit.
    ath: String,
    /// `base64url(sha256(body))` — binds the proof to the exact request body.
    #[serde(rename = "content-digest")]
    content_digest: String,
}

fn reject(msg: impl Into<String>) -> AuthError {
    AuthError::DpopFailed(msg.into())
}

/// Verify a DPoP proof JWT against the request it claims to authorize, returning the
/// proven identity (the holder's pubkey) plus the replay id and timestamp the shared
/// authorization path (`cred::verify_http_dpop`) feeds to the nonce store.
///
/// `htu_expected` is the PEP-rebuilt `<public-origin><path>` (no query); `body_sha256`
/// is the raw 32-byte SHA-256 of the buffered request body (the empty-body digest for
/// a bodyless GET/HEAD). This does NOT check freshness or replay — that is the nonce
/// store's job, shared with the runner PoP path so the window lives in one place.
pub fn verify_proof(
    proof_jwt: &str,
    method: &str,
    htu_expected: &str,
    biscuit_b64: &str,
    body_sha256: &[u8],
) -> Result<ProvenIdentity> {
    // 1. Header: require typ=dpop+jwt and pull the embedded PUBLIC Ed25519 key.
    let header = decode_header(proof_jwt).map_err(|e| reject(format!("bad jwt header: {e}")))?;
    if header.typ.as_deref() != Some(DPOP_TYP) {
        return Err(reject("typ is not dpop+jwt"));
    }
    let jwk = header.jwk.ok_or_else(|| reject("proof carries no jwk"))?;
    let AlgorithmParameters::OctetKeyPair(okp) = &jwk.algorithm else {
        return Err(reject("jwk is not an OKP key"));
    };
    if okp.curve != EllipticCurve::Ed25519 {
        return Err(reject("jwk curve is not Ed25519"));
    }
    let pubkey_raw = URL_SAFE_NO_PAD
        .decode(&okp.x)
        .map_err(|_| reject("jwk x is not base64url"))?;
    if pubkey_raw.len() != 32 {
        return Err(reject("jwk x is not a 32-byte Ed25519 key"));
    }
    let pubkey_hex = hex::encode(&pubkey_raw);

    // 2. Verify the JWS signature against that key, EdDSA ONLY. The algorithm
    //    allowlist is the alg-confusion defense: a `none` or HS256 proof is rejected
    //    here, before any claim is trusted. DPoP proofs carry no exp/aud, and
    //    freshness is the server's `iat` window (nonce store), so those library
    //    checks are off.
    let key = DecodingKey::from_jwk(&jwk).map_err(|e| reject(format!("jwk key: {e}")))?;
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.validate_exp = false;
    validation.validate_aud = false;
    validation.required_spec_claims = std::collections::HashSet::new();
    let claims = decode::<ProofClaims>(proof_jwt, &key, &validation)
        .map_err(|e| reject(format!("signature: {e}")))?
        .claims;

    // 3. Bind the proof to THIS request. Each is a fail-closed equality.
    if claims.htm != method {
        return Err(reject("htm does not match the request method"));
    }
    if claims.htu != htu_expected {
        return Err(reject("htu does not match the request uri"));
    }
    let ath_expected = URL_SAFE_NO_PAD.encode(Sha256::digest(biscuit_b64.as_bytes()));
    if claims.ath != ath_expected {
        return Err(reject("ath does not match the presented biscuit"));
    }
    let cdig_expected = URL_SAFE_NO_PAD.encode(body_sha256);
    if claims.content_digest != cdig_expected {
        return Err(reject("content-digest does not match the request body"));
    }
    if claims.jti.is_empty() {
        return Err(reject("jti is empty"));
    }

    Ok(ProvenIdentity {
        pubkey_hex,
        replay_id: claims.jti,
        // JWT `iat` is epoch SECONDS; the nonce store's freshness window works in ms.
        ts_ms: claims.iat.saturating_mul(1000),
    })
}
