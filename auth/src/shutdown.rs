//! How the PEP's surfaces accept and stop. Each accepted connection probes a silent peer.
//! Once a stop is requested, each surface stops accepting and lets the requests in flight
//! finish. The process waits for them up to its drain deadline (`bin/pep.rs`), then exits.

use hyper::body::{Body, Incoming};
use hyper::server::conn::http1;
use hyper::service::HttpService;
use hyper_util::rt::TokioIo;
use socket2::{SockRef, TcpKeepalive};
use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinSet;

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// How long a surface waits to accept again after an accept fails. Out of file
/// descriptors, every accept fails at once until a connection closes, so trying again at
/// once would spin and log a warning per try.
const ACCEPT_RETRY: Duration = Duration::from_secs(1);

/// TCP keepalive on each accepted connection: idle 10 s, then two probes 5 s apart, so a
/// peer that vanished without a close (its power lost, its network path gone) fails its
/// connection about 20 s after its last sign of life. The peer is whatever holds the other
/// end of the connection: behind a relay such as Tailscale Serve, that is the relay, which
/// answers the probes for a runner that has gone. The dispatcher's heartbeat check (D20)
/// is what notices such a runner.
const KEEPALIVE_IDLE: Duration = Duration::from_secs(10);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(target_os = "linux")]
const KEEPALIVE_PROBES: u32 = 2;

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
                    if let Err(e) = keep_alive(&stream) {
                        log::warn!("{surface}: keepalive for {peer}: {e}");
                    }
                    open.spawn(serve(stream, peer, stop.clone()));
                }
                Err(e) => {
                    log::warn!("{surface}: accept: {e}");
                    tokio::time::sleep(ACCEPT_RETRY).await;
                }
            },
        }
    }
    drop(listener);
    while open.join_next().await.is_some() {}
}

fn keep_alive(stream: &TcpStream) -> std::io::Result<()> {
    let probes = TcpKeepalive::new()
        .with_time(KEEPALIVE_IDLE)
        .with_interval(KEEPALIVE_INTERVAL);
    #[cfg(target_os = "linux")]
    let probes = probes.with_retries(KEEPALIVE_PROBES);
    SockRef::from(stream).set_tcp_keepalive(&probes)
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    /// Every surface probes its peers: a connection it accepts carries the keepalive
    /// timing, so a peer that vanished without a close is noticed.
    #[tokio::test]
    async fn an_accepted_connection_probes_a_silent_peer() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (seen_tx, mut seen) = tokio::sync::mpsc::channel(1);
        let (stopper, stop) = channel();
        let surface = tokio::spawn(accept_until(listener, stop, "test", move |stream, _, _| {
            let seen_tx = seen_tx.clone();
            async move {
                let socket = SockRef::from(&stream);
                let timing = (
                    socket.keepalive().unwrap(),
                    socket.tcp_keepalive_time().unwrap(),
                    socket.tcp_keepalive_interval().unwrap(),
                    socket.tcp_keepalive_retries().unwrap(),
                );
                seen_tx.send(timing).await.unwrap();
            }
        }));
        let _client = TcpStream::connect(addr).await.unwrap();
        assert_eq!(
            seen.recv().await.unwrap(),
            (true, KEEPALIVE_IDLE, KEEPALIVE_INTERVAL, KEEPALIVE_PROBES)
        );
        stopper.send_replace(true);
        surface.await.unwrap();
    }
}
