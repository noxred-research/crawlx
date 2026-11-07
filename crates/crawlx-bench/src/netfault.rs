//! `netfault`: an in-process TCP fault proxy (a "toxiproxy" stand-in).
//!
//! The proxy sits between a client (the worker's `sqlx` pool, the API) and an upstream
//! (PostgreSQL) and injects the faults the chaos table needs without a sidecar process:
//!
//! * **latency** — every forwarded chunk waits [`Proxy::set_latency`] before it is written;
//! * **blackhole** — bytes are read and discarded, nothing reaches the other side
//!   ([`Proxy::set_blackhole`]; a partition the client only notices through timeouts);
//! * **refuse** — new connections are accepted and reset at once ([`Proxy::set_refuse`]);
//! * **reset** — every live proxied connection is closed with `SO_LINGER = 0`, so both ends
//!   see an `ECONNRESET` instead of an orderly `FIN` ([`Proxy::reset_all`]).
//!
//! Faults are flipped at run time from the test or the soak scheduler; the proxy never reads
//! a clock of its own beyond the latency sleep. [`rewrite_url`] points a `postgres://` URL at
//! the proxy so the system under test needs no code change (lease and journal
//! semantics are then exercised across real socket failures).

use crate::error::BenchError;
use parking_lot::Mutex;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

/// Forwarding buffer per direction.
const CHUNK: usize = 16 * 1024;

/// Counters of one proxy, cumulative since start.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Serialize)]
#[non_exhaustive]
pub struct ProxyStats {
    /// Connections accepted (including refused ones).
    pub accepted: u64,
    /// Connections refused by [`Proxy::set_refuse`].
    pub refused: u64,
    /// Connections currently forwarding.
    pub live: u64,
    /// Connections killed by [`Proxy::reset_all`].
    pub resets: u64,
    /// Bytes forwarded client → upstream.
    pub bytes_up: u64,
    /// Bytes forwarded upstream → client.
    pub bytes_down: u64,
}

#[derive(Default)]
struct Shared {
    latency_ns: AtomicU64,
    blackhole: AtomicBool,
    refuse: AtomicBool,
    accepted: AtomicU64,
    refused: AtomicU64,
    resets: AtomicU64,
    bytes_up: AtomicU64,
    bytes_down: AtomicU64,
    /// Live connections by id; each token cancels one connection's forwarding tasks.
    live: Mutex<BTreeMap<u64, CancellationToken>>,
}

impl Shared {
    fn latency(&self) -> Duration {
        Duration::from_nanos(self.latency_ns.load(Ordering::Relaxed))
    }
}

/// A running fault proxy; dropping it stops the listener (live connections end with it).
pub struct Proxy {
    addr: SocketAddr,
    upstream: SocketAddr,
    shared: Arc<Shared>,
    stop: CancellationToken,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl Proxy {
    /// Listen on an ephemeral loopback port and forward to `upstream`.
    ///
    /// # Errors
    /// [`BenchError::Bind`] when the loopback listener cannot be bound,
    /// [`BenchError::LocalAddr`] when its address cannot be read.
    pub async fn start(upstream: SocketAddr) -> Result<Self, BenchError> {
        let bind: SocketAddr = ([127, 0, 0, 1], 0).into();
        let listener = TcpListener::bind(bind)
            .await
            .map_err(|source| BenchError::Bind { addr: bind, source })?;
        let addr = listener.local_addr().map_err(BenchError::LocalAddr)?;
        let shared = Arc::new(Shared::default());
        let stop = CancellationToken::new();
        let task = tokio::spawn(accept_loop(listener, upstream, shared.clone(), stop.clone()));
        Ok(Self {
            addr,
            upstream,
            shared,
            stop,
            task: Some(task),
        })
    }

    /// Address clients connect to.
    #[must_use]
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Address the proxy forwards to.
    #[must_use]
    pub fn upstream(&self) -> SocketAddr {
        self.upstream
    }

    /// Delay applied to every forwarded chunk in both directions (`0` = none).
    pub fn set_latency(&self, latency: Duration) {
        self.shared.latency_ns.store(
            u64::try_from(latency.as_nanos()).unwrap_or(u64::MAX),
            Ordering::Relaxed,
        );
    }

    /// Swallow all bytes (both directions) while `on`; connections stay open.
    pub fn set_blackhole(&self, on: bool) {
        self.shared.blackhole.store(on, Ordering::Relaxed);
    }

    /// Reset every new connection immediately while `on`; live connections are untouched.
    pub fn set_refuse(&self, on: bool) {
        self.shared.refuse.store(on, Ordering::Relaxed);
    }

    /// Kill every live proxied connection with an RST; returns how many were killed.
    #[allow(clippy::must_use_candidate)] // the side effect is the point; the count is informational
    pub fn reset_all(&self) -> u64 {
        let tokens: Vec<CancellationToken> = {
            let live = self.shared.live.lock();
            live.values().cloned().collect()
        };
        let n = u64::try_from(tokens.len()).unwrap_or(u64::MAX);
        for t in tokens {
            t.cancel();
        }
        self.shared.resets.fetch_add(n, Ordering::Relaxed);
        n
    }

    /// Cumulative counters.
    #[must_use]
    pub fn stats(&self) -> ProxyStats {
        let s = &self.shared;
        ProxyStats {
            accepted: s.accepted.load(Ordering::Relaxed),
            refused: s.refused.load(Ordering::Relaxed),
            live: u64::try_from(s.live.lock().len()).unwrap_or(u64::MAX),
            resets: s.resets.load(Ordering::Relaxed),
            bytes_up: s.bytes_up.load(Ordering::Relaxed),
            bytes_down: s.bytes_down.load(Ordering::Relaxed),
        }
    }

    /// Stop accepting, kill live connections and wait for the accept loop.
    pub async fn shutdown(mut self) {
        self.stop.cancel();
        self.reset_all();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        self.stop.cancel();
        for t in self.shared.live.lock().values() {
            t.cancel();
        }
    }
}

async fn accept_loop(
    listener: TcpListener,
    upstream: SocketAddr,
    shared: Arc<Shared>,
    stop: CancellationToken,
) {
    let mut conns = JoinSet::new();
    let mut next_id = 0u64;
    loop {
        let accepted = tokio::select! {
            () = stop.cancelled() => break,
            r = listener.accept() => r,
        };
        let Ok((client, _)) = accepted else { continue };
        shared.accepted.fetch_add(1, Ordering::Relaxed);
        if shared.refuse.load(Ordering::Relaxed) {
            shared.refused.fetch_add(1, Ordering::Relaxed);
            abort(&client);
            continue;
        }
        let id = next_id;
        next_id += 1;
        let token = stop.child_token();
        shared.live.lock().insert(id, token.clone());
        conns.spawn(forward(id, client, upstream, shared.clone(), token));
        // reap finished connection tasks without blocking the accept loop
        while let Some(res) = conns.try_join_next() {
            if let Err(e) = res {
                tracing::warn!(error = %e, "netfault: connection task failed");
            }
        }
    }
    conns.abort_all();
    while conns.join_next().await.is_some() {}
}

/// Close with `SO_LINGER = 0` so the peer receives an RST rather than a FIN.
///
/// tokio deprecates `set_linger` because a non-zero linger blocks the thread on drop; a zero
/// linger never blocks (the kernel discards the send queue and resets at once), which is
/// exactly the fault being injected.
#[allow(deprecated)]
fn abort(stream: &TcpStream) {
    if let Err(e) = stream.set_linger(Some(Duration::ZERO)) {
        tracing::debug!(error = %e, "netfault: set_linger");
    }
}

async fn forward(
    id: u64,
    client: TcpStream,
    upstream: SocketAddr,
    shared: Arc<Shared>,
    token: CancellationToken,
) {
    let connected = tokio::select! {
        () = token.cancelled() => None,
        r = TcpStream::connect(upstream) => r.ok(),
    };
    let Some(server) = connected else {
        abort(&client);
        shared.live.lock().remove(&id);
        return;
    };
    let _ = client.set_nodelay(true);
    let _ = server.set_nodelay(true);
    let (mut cr, mut cw) = client.into_split();
    let (mut sr, mut sw) = server.into_split();
    let up = pump(&mut cr, &mut sw, &shared, &shared.bytes_up, &token);
    let down = pump(&mut sr, &mut cw, &shared, &shared.bytes_down, &token);
    let cancelled = tokio::select! {
        () = token.cancelled() => true,
        _ = up => false,
        _ = down => false,
    };
    let client = cr.reunite(cw);
    let server = sr.reunite(sw);
    if cancelled {
        if let Ok(c) = &client {
            abort(c);
        }
        if let Ok(s) = &server {
            abort(s);
        }
    }
    drop(client);
    drop(server);
    shared.live.lock().remove(&id);
}

/// Copy `from` to `to` until EOF or an error, applying the active faults per chunk.
async fn pump<R, W>(from: &mut R, to: &mut W, shared: &Shared, counter: &AtomicU64, token: &CancellationToken)
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = match from.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => n,
        };
        let latency = shared.latency();
        if !latency.is_zero() {
            tokio::select! {
                () = token.cancelled() => break,
                () = tokio::time::sleep(latency) => {}
            }
        }
        if shared.blackhole.load(Ordering::Relaxed) {
            continue;
        }
        if to.write_all(&buf[..n]).await.is_err() {
            break;
        }
        counter.fetch_add(u64::try_from(n).unwrap_or(u64::MAX), Ordering::Relaxed);
    }
    let _ = to.shutdown().await;
}

/// `host:port` of a `postgres://` URL resolved to one socket address (default port 5432).
///
/// # Errors
/// [`BenchError::Url`] when the URL does not parse, [`BenchError::Ablation`] when it has no
/// host or the host does not resolve.
pub async fn upstream_of(database_url: &str) -> Result<SocketAddr, BenchError> {
    let url = url::Url::parse(database_url)?;
    let host = url
        .host_str()
        .ok_or_else(|| BenchError::Ablation("database url has no host".to_owned()))?
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    let port = url.port().unwrap_or(5432);
    let mut addrs = tokio::net::lookup_host((host.as_str(), port))
        .await
        .map_err(|e| BenchError::Ablation(format!("resolve {host}:{port}: {e}")))?;
    addrs
        .next()
        .ok_or_else(|| BenchError::Ablation(format!("{host}:{port} resolves to nothing")))
}

/// `database_url` with its authority pointed at `proxy` (user, password, path and query kept).
///
/// # Errors
/// [`BenchError::Url`] when the URL does not parse or refuses the new host.
pub fn rewrite_url(database_url: &str, proxy: SocketAddr) -> Result<String, BenchError> {
    let mut url = url::Url::parse(database_url)?;
    url.set_ip_host(proxy.ip())
        .map_err(|()| url::ParseError::SetHostOnCannotBeABaseUrl)?;
    url.set_port(Some(proxy.port()))
        .map_err(|()| url::ParseError::InvalidPort)?;
    Ok(url.into())
}
