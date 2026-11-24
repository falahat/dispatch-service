//! What the lease book lets a runner read once it records a grant (D8).
//!
//! The book narrows a runner credential to the blobs of the jobs it holds, so what it records
//! is part of the auth boundary: a job's blobs when the CAS backend names them, and no more
//! than its invocation when the backend does not answer. Each test stands up a real loopback
//! backend; they are hand-written.

use dispatch_auth::cas_proxy::{BackendStyle, CasConfig};
use dispatch_auth::lease_book::LeaseBook;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

const NOW: i64 = 1_700_000_000_000;
const RUNNER: &str = "runner-1";
/// The address of the granted job's one input.
const INPUT: &str = "abc123abc123abc123abc123abc123abc123abc123abc123abc123abc123abcd";

/// A loopback CAS backend serving `blobs` by their hex address.
async fn serving(blobs: HashMap<String, Vec<u8>>) -> String {
    let blobs = Arc::new(blobs);
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((stream, _)) = ln.accept().await {
            let blobs = blobs.clone();
            let serve = service_fn(move |req: Request<Incoming>| {
                let blob = req
                    .uri()
                    .path()
                    .strip_prefix("/blobs/sha256/")
                    .and_then(|hex| blobs.get(hex))
                    .cloned();
                async move {
                    let response = match blob {
                        Some(bytes) => Response::new(Full::new(Bytes::from(bytes))),
                        None => Response::builder()
                            .status(StatusCode::NOT_FOUND)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    };
                    Ok::<_, Infallible>(response)
                }
            });
            tokio::spawn(async move {
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(TokioIo::new(stream), serve)
                    .await;
            });
        }
    });
    format!("http://{addr}")
}

/// A loopback CAS backend that takes every connection and never answers on it.
async fn silent() -> String {
    let ln = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = ln.local_addr().unwrap();
    tokio::spawn(async move {
        let mut held = Vec::new();
        while let Ok((stream, _)) = ln.accept().await {
            held.push(stream);
        }
    });
    format!("http://{addr}")
}

fn book(backend: String) -> LeaseBook {
    LeaseBook::new(CasConfig {
        backend,
        max_blob_bytes: 1 << 20,
        style: BackendStyle::Passthrough,
    })
}

/// The invocation of a job reading [`INPUT`], and its hex address.
fn invocation() -> (Vec<u8>, String) {
    let doc = serde_json::json!({
        "inputs": { "audio": { "kind": "blob", "address": format!("sha256:{INPUT}") } }
    });
    let bytes = serde_json::to_vec(&doc).unwrap();
    let hex = hex::encode(Sha256::digest(&bytes));
    (bytes, hex)
}

/// A runner's lease frame and the dispatcher's grant of the job whose invocation is `hex`.
fn grant(hex: &str) -> (Vec<u8>, Vec<u8>) {
    let lease = serde_json::json!({
        "v": "0.8", "type": "lease", "id": "r1",
        "body": { "lanes": ["embed"], "wait_s": 30 }
    });
    let granted = serde_json::json!({
        "v": "0.8", "type": "grant", "id": "r1",
        "body": {
            "lease": { "lease_id": "l1", "ttl_s": 300 },
            "job": { "job_id": "j1", "invocation_address": format!("sha256:{hex}") }
        }
    });
    (
        serde_json::to_vec(&lease).unwrap(),
        serde_json::to_vec(&granted).unwrap(),
    )
}

#[tokio::test]
async fn a_granted_job_may_read_its_invocation_and_its_inputs() {
    let (doc, hex) = invocation();
    let book = book(serving(HashMap::from([(hex.clone(), doc)])).await);
    let (lease, granted) = grant(&hex);

    book.observe(RUNNER, "lease", &lease, &granted, NOW).await;

    assert!(book.may_read(RUNNER, &hex, NOW));
    assert!(book.may_read(RUNNER, INPUT, NOW));
    assert!(!book.may_read("another-runner", INPUT, NOW));
}

/// The runner sees a grant only once the book has recorded it, and it stops waiting 15 s
/// after its long-poll ends. A backend that never answered used to hold the grant until the
/// runner gave up, and the job sat leased to nobody until its lease expired.
#[tokio::test]
async fn a_backend_that_never_answers_holds_a_grant_briefly_and_opens_none_of_its_inputs() {
    let (_doc, hex) = invocation();
    let book = book(silent().await);
    let (lease, granted) = grant(&hex);

    let started = Instant::now();
    tokio::time::timeout(
        Duration::from_secs(60),
        book.observe(RUNNER, "lease", &lease, &granted, NOW),
    )
    .await
    .expect("recording the grant waited on a backend that never answers");

    assert!(
        started.elapsed() < Duration::from_secs(15),
        "the runner stops waiting for its grant 15 s after its long-poll"
    );
    assert!(book.holds_lease(RUNNER, NOW));
    assert!(book.may_read(RUNNER, &hex, NOW));
    assert!(
        !book.may_read(RUNNER, INPUT, NOW),
        "an input the book could not look up stays closed"
    );
}
