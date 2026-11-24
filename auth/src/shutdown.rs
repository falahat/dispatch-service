//! Graceful stop for the PEP's surfaces. Once a stop is requested, each surface stops
//! accepting and lets the requests in flight finish. The process waits for them up to its
//! drain deadline (`bin/pep.rs`), then exits.

use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use hyper::service::HttpService;
use hyper_util::rt::TokioIo;
use std::future::Future;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Tells a surface when to stop. The default one never stops.
#[derive(Clone, Default)]
pub struct Stop(Option<watch::Receiver<bool>>);

/// The sender that requests a stop (`send_replace(true)`), and a [`Stop`] that sees it.
pub fn channel() -> (watch::Sender<bool>, Stop) {
    let (stopper, stop) = watch::channel(false);
    (stopper, Stop(Some(stop)))
}

impl Stop {
    /// Resolves once a stop has been requested, at once if it already has. A dropped
    /// sender counts as a stop: nothing is left to keep the surface open for.
    pub async fn requested(&mut self) {
        match &mut self.0 {
            Some(stop) => {
                let _ = stop.wait_for(|stopping| *stopping).await;
            }
            None => std::future::pending().await,
        }
    }
}

/// Accepts connections until a stop is requested, serving each with `serve`. Then it
/// closes the listener, so nothing more is accepted, and returns once the connections
/// still open have finished.
pub async fn accept_until<F, Fut>(listener: TcpListener, mut stop: Stop, surface: &str, serve: F)
where
    F: Fn(TcpStream, SocketAddr, Stop) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let mut open = JoinSet::new();
    loop {
        tokio::select! {
            biased;
            () = stop.requested() => break,
            Some(_) = open.join_next(), if !open.is_empty() => {}
            accepted = listener.accept() => match accepted {
                Ok((stream, peer)) => {
                    open.spawn(serve(stream, peer, stop.clone()));
                }
                Err(e) => log::warn!("{surface}: accept: {e}"),
            },
        }
    }
    drop(listener);
    while open.join_next().await.is_some() {}
}

/// Serves one HTTP/1 connection. After a stop it finishes the request in flight and
/// closes; a keep-alive connection waiting for its next request closes at once.
pub async fn serve_http1<S>(stream: TcpStream, service: S, mut stop: Stop) -> hyper::Result<()>
where
    S: HttpService<Incoming>,
    S::Error: Into<BoxError>,
    S::ResBody: 'static,
    <S::ResBody as Body>::Error: Into<BoxError>,
{
    let conn = http1::Builder::new().serve_connection(TokioIo::new(stream), service);
    tokio::pin!(conn);
    tokio::select! {
        biased;
        done = conn.as_mut() => return done,
        () = stop.requested() => conn.as_mut().graceful_shutdown(),
    }
    conn.await
}
