//! The dispatcher runner-surface proxy: it terminates the runner's authenticated
//! framed connection, verifies Biscuit + PoP on every frame, and forwards the
//! inner (clean) wire frame to the dispatcher over loopback. The dispatcher
//! parses no credential and trusts the PEP-attached identity.
//!
//! Auth frame (length-prefixed JSON), runner -> PEP:
//!   { "b": <biscuit b64>, "k": <pop pubkey hex>, "n": <nonce b64>,
//!     "t": <ts ms>, "s": <pop sig b64>, "m": <inner wire frame bytes, b64> }
//! The PoP signs `dispatch/v0 <verb> <sha256hex(inner frame bytes)> <nonce> <ts>`.
//! Replies are plain wire frames streamed straight back.

use crate::cred::{verify, AuthedRequest};
use crate::nonce::NonceStore;
use crate::revocation::RevocationStore;
use crate::Op;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use biscuit_auth::PublicKey;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_FRAME: u32 = 4 << 20;

#[derive(Clone)]
pub struct FrameProxy {
    root_pub: PublicKey,
    nonces: NonceStore,
    revocations: RevocationStore,
    dispatcher_addr: String, // loopback address of the dispatcher runner surface
    now: Arc<dyn Fn() -> i64 + Send + Sync>,
}

#[derive(Deserialize)]
struct AuthFrame {
    b: String, // biscuit
    k: String, // pop pubkey hex
    n: String, // nonce b64
    t: i64,    // ts ms
    s: String, // pop sig b64
    m: String, // inner frame bytes, b64
}

impl FrameProxy {
    pub fn new(
        root_pub: PublicKey,
        nonces: NonceStore,
        revocations: RevocationStore,
        dispatcher_addr: String,
        now: Arc<dyn Fn() -> i64 + Send + Sync>,
    ) -> Self {
        Self {
            root_pub,
            nonces,
            revocations,
            dispatcher_addr,
            now,
        }
    }

    pub async fn serve(self, listener: TcpListener) {
        loop {
            let (stream, peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    log::warn!("frame: accept: {e}");
                    continue;
                }
            };
            let proxy = self.clone();
            tokio::spawn(async move {
                if let Err(e) = proxy.handle_conn(stream).await {
                    log::debug!("frame: conn {peer}: {e}");
                }
            });
        }
    }

    async fn handle_conn(&self, mut runner: TcpStream) -> std::io::Result<()> {
        // One loopback connection to the dispatcher per runner connection (1:1),
        // so the dispatcher sees a stable identity for the connection.
        let mut backend = TcpStream::connect(&self.dispatcher_addr).await?;

        loop {
            let outer = match read_frame(&mut runner).await {
                Ok(Some(f)) => f,
                Ok(None) => return Ok(()), // clean close
                Err(e) => return Err(e),
            };
            let af: AuthFrame = match serde_json::from_slice(&outer) {
                Ok(a) => a,
                Err(_) => {
                    write_error(&mut runner, "", "invalid", "malformed auth frame").await?;
                    continue;
                }
            };
            let inner = match STANDARD.decode(&af.m) {
                Ok(b) => b,
                Err(_) => {
                    write_error(&mut runner, "", "invalid", "bad inner b64").await?;
                    continue;
                }
            };
            // Parse the inner frame minimally to learn the verb, id, and lanes.
            let (verb, id, lanes) = match parse_inner(&inner) {
                Some(v) => v,
                None => {
                    write_error(&mut runner, "", "invalid", "malformed inner frame").await?;
                    continue;
                }
            };

            let frame_hash = hex::encode(Sha256::digest(&inner));
            let sig = match STANDARD.decode(&af.s) {
                Ok(s) => s,
                Err(_) => {
                    write_error(&mut runner, &id, "unauthenticated", "bad sig b64").await?;
                    continue;
                }
            };
            let areq = AuthedRequest {
                op: Op::Dispatch {
                    verb: verb.clone(),
                    frame_sha256_hex: frame_hash,
                },
                biscuit_b64: af.b.clone(),
                pubkey_hex: af.k.clone(),
                nonce_b64: af.n.clone(),
                ts_ms: af.t,
                pop_sig_b64: STANDARD.encode(&sig),
                required_lanes: lanes,
                address_hex: None,
            };
            let now = (self.now)();
            // The runner frame is single-use: every frame consumes its nonce.
            let identity = match verify(
                &self.root_pub,
                &self.nonces,
                &self.revocations,
                now,
                &areq,
                true,
            ) {
                Ok(id) => id,
                Err(e) => {
                    let code = match e {
                        crate::AuthError::Denied(_) | crate::AuthError::Revoked => "forbidden",
                        _ => "unauthenticated",
                    };
                    log::warn!("frame: {} denied: {}", verb, e);
                    write_error(&mut runner, &id, code, &format!("{e}")).await?;
                    continue;
                }
            };

            // Bind the fleet identity: a hello must declare the verified key.
            if verb == "hello" && !hello_id_matches(&inner, &identity.id) {
                write_error(
                    &mut runner,
                    &id,
                    "forbidden",
                    "hello identity does not match credential",
                )
                .await?;
                continue;
            }

            // Forward the clean inner frame to the dispatcher and pipe the reply.
            write_frame(&mut backend, &inner).await?;
            match read_frame(&mut backend).await? {
                Some(reply) => write_frame(&mut runner, &reply).await?,
                None => return Ok(()), // dispatcher closed
            }
        }
    }
}

/// Parse an inner wire frame's type, id, and (for lease) lanes.
fn parse_inner(inner: &[u8]) -> Option<(String, String, Vec<String>)> {
    let v: serde_json::Value = serde_json::from_slice(inner).ok()?;
    let typ = v.get("type")?.as_str()?.to_string();
    let id = v.get("id")?.as_str()?.to_string();
    let mut lanes = Vec::new();
    if typ == "lease" {
        if let Some(arr) = v
            .get("body")
            .and_then(|b| b.get("lanes"))
            .and_then(|l| l.as_array())
        {
            for item in arr {
                if let Some(s) = item.as_str() {
                    lanes.push(s.to_string());
                }
            }
        }
    }
    Some((typ, id, lanes))
}

fn hello_id_matches(inner: &[u8], identity: &str) -> bool {
    let v: serde_json::Value = match serde_json::from_slice(inner) {
        Ok(v) => v,
        Err(_) => return false,
    };
    v.get("body")
        .and_then(|b| b.get("runner"))
        .and_then(|r| r.get("id"))
        .and_then(|i| i.as_str())
        .map(|s| s == identity)
        .unwrap_or(false)
}

async fn read_frame(s: &mut TcpStream) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match s.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let n = u32::from_be_bytes(len);
    if n == 0 || n > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "bad frame length",
        ));
    }
    let mut buf = vec![0u8; n as usize];
    s.read_exact(&mut buf).await?;
    Ok(Some(buf))
}

async fn write_frame(s: &mut TcpStream, payload: &[u8]) -> std::io::Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    s.write_all(&len).await?;
    s.write_all(payload).await?;
    s.flush().await
}

async fn write_error(s: &mut TcpStream, id: &str, code: &str, msg: &str) -> std::io::Result<()> {
    let frame = serde_json::json!({
        "v": "0.1",
        "type": "error",
        "id": if id.is_empty() { "0" } else { id },
        "body": { "code": code, "message": msg, "retryable": false }
    });
    let bytes = serde_json::to_vec(&frame).unwrap();
    write_frame(s, &bytes).await
}
