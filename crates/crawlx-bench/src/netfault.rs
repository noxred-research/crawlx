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
//!
//! A [`FaultSchedule`] (`latency=50ms@0s..10s,blackhole@12s..15s,reset@20s,refuse@25s..27s`, or
//! generated from a seed) turns those switches into a timeline that [`Proxy::run_schedule`]
//! drives; the `netfault` binary and `load --fault` use it as a standard tool.

use crate::error::BenchError;
use crawlx_core::seed::CrawlSeed;
use parking_lot::Mutex;
use rand::RngExt as _;
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
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
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
        Self::start_on(([127, 0, 0, 1], 0).into(), upstream).await
    }

    /// Listen on `bind` and forward to `upstream`.
    ///
    /// # Errors
    /// [`BenchError::Bind`] when `bind` cannot be bound, [`BenchError::LocalAddr`] when the
    /// bound address cannot be read.
    pub async fn start_on(bind: SocketAddr, upstream: SocketAddr) -> Result<Self, BenchError> {
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

/// A fault the schedule switches on.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Fault {
    /// Every forwarded chunk waits this long (both directions).
    Latency(Duration),
    /// Bytes are swallowed; stuck connections are reset when the window ends.
    Blackhole,
    /// New connections are reset at once.
    Refuse,
    /// Every live connection is reset at one instant.
    Reset,
}

impl Fault {
    /// Name used in the text spec.
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::Latency(_) => "latency",
            Self::Blackhole => "blackhole",
            Self::Refuse => "refuse",
            Self::Reset => "reset",
        }
    }

    /// Does the fault break connections (everything except added latency)?
    #[must_use]
    pub const fn kills_connections(&self) -> bool {
        !matches!(self, Self::Latency(_))
    }

    /// Position in the order of equal start times and in the overlap check.
    const fn rank(&self) -> u8 {
        match self {
            Self::Latency(_) => 0,
            Self::Blackhole => 1,
            Self::Refuse => 2,
            Self::Reset => 3,
        }
    }
}

/// One scheduled fault: active from `start` to `end`, or an instant when `end` is empty
/// (only [`Fault::Reset`]). Offsets are measured from the start of the schedule.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct FaultEvent {
    /// What is injected.
    pub fault: Fault,
    /// When it starts.
    pub start: Duration,
    /// When it ends; `None` for an instantaneous fault.
    pub end: Option<Duration>,
}

/// An ordered timeline of faults for [`Proxy::run_schedule`].
///
/// Text spec: comma-separated items `fault[=ARG]@START[..END]`. `latency=50ms@0s..10s` adds
/// 50 ms per chunk for ten seconds; `blackhole@12s..15s` and `refuse@25s..27s` are windows;
/// `reset@20s` kills every live connection once. Spans are `<n>ms`, `<n>s`, `<n>m`, `<n>h` or
/// a concatenation such as `1m30s`. Windows of one kind must not overlap; different kinds may.
#[derive(Clone, PartialEq, Eq, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct FaultSchedule {
    events: Vec<FaultEvent>,
}

/// Milliseconds of `d`, saturating.
fn millis(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// Parse `50ms`, `3s`, `2m`, `1h`, `1m30s` (every number needs a unit).
fn parse_span(text: &str) -> Result<Duration, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("empty duration".to_owned());
    }
    let mut rest = text;
    let mut total: u64 = 0;
    while !rest.is_empty() {
        let digits = rest.chars().take_while(char::is_ascii_digit).count();
        if digits == 0 {
            return Err(format!("duration `{text}`: expected a number at `{rest}`"));
        }
        let n: u64 = rest[..digits]
            .parse()
            .map_err(|e| format!("duration `{text}`: {e}"))?;
        rest = &rest[digits..];
        let (unit_ms, len) = if rest.starts_with("ms") {
            (1u64, 2)
        } else if rest.starts_with('s') {
            (1_000, 1)
        } else if rest.starts_with('m') {
            (60_000, 1)
        } else if rest.starts_with('h') {
            (3_600_000, 1)
        } else {
            return Err(format!("duration `{text}`: `{n}` needs a unit (ms, s, m or h)"));
        };
        rest = &rest[len..];
        total = n
            .checked_mul(unit_ms)
            .and_then(|ms| total.checked_add(ms))
            .ok_or_else(|| format!("duration `{text}` overflows"))?;
    }
    Ok(Duration::from_millis(total))
}

fn parse_item(item: &str) -> Result<FaultEvent, String> {
    let (head, window) = item
        .split_once('@')
        .ok_or_else(|| format!("fault `{item}` needs `@START[..END]`"))?;
    let (name, arg) = match head.split_once('=') {
        Some((name, arg)) => (name.trim(), Some(arg.trim())),
        None => (head.trim(), None),
    };
    let (start, end) = match window.split_once("..") {
        Some((start, end)) => (parse_span(start)?, Some(parse_span(end)?)),
        None => (parse_span(window)?, None),
    };
    let fault = match (name, arg) {
        ("latency", Some(arg)) => {
            let latency = parse_span(arg)?;
            if latency.is_zero() {
                return Err(format!("fault `{item}`: latency must be above zero"));
            }
            Fault::Latency(latency)
        }
        ("latency", None) => return Err(format!("fault `{item}`: latency needs `=DURATION`")),
        ("blackhole", None) => Fault::Blackhole,
        ("refuse", None) => Fault::Refuse,
        ("reset", None) => Fault::Reset,
        ("blackhole" | "refuse" | "reset", Some(_)) => {
            return Err(format!("fault `{item}`: {name} takes no argument"))
        }
        (other, _) => {
            return Err(format!(
                "unknown fault `{other}` (latency, blackhole, refuse, reset)"
            ))
        }
    };
    match (fault, end) {
        (Fault::Reset, Some(_)) => Err(format!(
            "fault `{item}`: reset is instantaneous, write `reset@START`"
        )),
        (Fault::Reset, None) => Ok(FaultEvent {
            fault,
            start,
            end: None,
        }),
        (_, None) => Err(format!("fault `{item}`: {name} needs a window `@START..END`")),
        (_, Some(end)) if end <= start => Err(format!("fault `{item}`: the window ends before it starts")),
        (_, Some(end)) => Ok(FaultEvent {
            fault,
            start,
            end: Some(end),
        }),
    }
}

impl FaultSchedule {
    /// Build a schedule from events: sorted by start, and refused when two windows of one
    /// kind overlap.
    ///
    /// # Errors
    /// A `String` naming the overlapping windows.
    pub fn new(mut events: Vec<FaultEvent>) -> Result<Self, String> {
        events.sort_by_key(|e| (e.start, e.fault.rank(), e.end));
        for (i, a) in events.iter().enumerate() {
            let Some(a_end) = a.end else { continue };
            for b in events.iter().skip(i + 1) {
                if b.fault.rank() == a.fault.rank() && b.start < a_end {
                    return Err(format!(
                        "two {} windows overlap at {}ms",
                        a.fault.name(),
                        millis(b.start)
                    ));
                }
            }
        }
        Ok(Self { events })
    }

    /// Parse the text spec (see the type docs). The empty string is the empty schedule.
    ///
    /// # Errors
    /// A `String` naming the malformed item.
    pub fn parse(spec: &str) -> Result<Self, String> {
        let events = spec
            .split(',')
            .map(str::trim)
            .filter(|item| !item.is_empty())
            .map(parse_item)
            .collect::<Result<Vec<_>, _>>()?;
        Self::new(events)
    }

    /// `count` faults spread over `horizon`, one per equal slot and never overlapping, drawn
    /// from `seed` alone: the same arguments always yield the same schedule.
    ///
    /// # Errors
    /// A `String` when `count` is zero or `horizon` is shorter than `count` milliseconds.
    pub fn generate(seed: u64, horizon: Duration, count: usize) -> Result<Self, String> {
        let count_u64 = u64::try_from(count).map_err(|e| format!("fault count: {e}"))?;
        let slot = millis(horizon)
            .checked_div(count_u64)
            .filter(|slot| *slot > 0)
            .ok_or_else(|| "a generated schedule needs at least one fault and 1 ms per fault".to_owned())?;
        let mut rng = CrawlSeed(seed).rng("netfault", &[]);
        let mut events = Vec::with_capacity(count);
        for i in 0..count_u64 {
            let base = i.saturating_mul(slot);
            // inside its slot: starts in the first 30 %, lasts 10-40 %, so slots never overlap
            let lead = rng.random_range(0..=slot.saturating_mul(3) / 10);
            let len = (slot / 10).max(1) + rng.random_range(0..=slot.saturating_mul(3) / 10);
            let start = Duration::from_millis(base.saturating_add(lead));
            let end = Duration::from_millis(base.saturating_add(lead).saturating_add(len));
            let event = match rng.random_range(0..4u8) {
                0 => FaultEvent {
                    fault: Fault::Latency(Duration::from_millis(rng.random_range(25..=250u64))),
                    start,
                    end: Some(end),
                },
                1 => FaultEvent {
                    fault: Fault::Blackhole,
                    start,
                    end: Some(end),
                },
                2 => FaultEvent {
                    fault: Fault::Refuse,
                    start,
                    end: Some(end),
                },
                _ => FaultEvent {
                    fault: Fault::Reset,
                    start,
                    end: None,
                },
            };
            events.push(event);
        }
        Self::new(events)
    }

    /// The events, ordered by start.
    #[must_use]
    pub fn events(&self) -> &[FaultEvent] {
        &self.events
    }

    /// No fault at all?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Only added latency: nothing in the schedule breaks a connection.
    #[must_use]
    pub fn latency_only(&self) -> bool {
        !self.events.is_empty() && self.events.iter().all(|e| !e.fault.kills_connections())
    }

    /// When the last fault ends (or fires).
    #[must_use]
    pub fn horizon(&self) -> Duration {
        self.events
            .iter()
            .map(|e| e.end.unwrap_or(e.start))
            .max()
            .unwrap_or(Duration::ZERO)
    }

    /// Windows `[start, end + tail]` of the faults that satisfy `keep`; an instant fault gets
    /// `[start, start + tail]`. The tail covers requests that were in flight when the fault
    /// ended and still fail afterwards.
    #[must_use]
    pub fn windows(&self, tail: Duration, keep: impl Fn(&Fault) -> bool) -> Vec<(Duration, Duration)> {
        self.events
            .iter()
            .filter(|e| keep(&e.fault))
            .map(|e| (e.start, e.end.unwrap_or(e.start).saturating_add(tail)))
            .collect()
    }
}

impl std::fmt::Display for FaultSchedule {
    /// The canonical spec, in milliseconds; [`FaultSchedule::parse`] reads it back unchanged.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for (i, e) in self.events.iter().enumerate() {
            if i > 0 {
                f.write_str(",")?;
            }
            f.write_str(e.fault.name())?;
            if let Fault::Latency(d) = e.fault {
                write!(f, "={}ms", millis(d))?;
            }
            write!(f, "@{}ms", millis(e.start))?;
            if let Some(end) = e.end {
                write!(f, "..{}ms", millis(end))?;
            }
        }
        Ok(())
    }
}

/// A fault [`Proxy::run_schedule`] applied.
#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub struct AppliedFault {
    /// What was injected.
    pub fault: Fault,
    /// Milliseconds after the schedule started when it was switched on.
    pub start_ms: u64,
    /// Milliseconds after the schedule started when it was switched off; `None` for an
    /// instantaneous fault or a window cut short by cancellation.
    pub end_ms: Option<u64>,
    /// Connections reset by the fault: the kill of a reset, the heal of a blackhole.
    pub resets: u64,
}

impl Proxy {
    /// Drive `schedule` against this proxy: switch every fault on and off at its offset from
    /// the moment of the call, until the last fault is done or `cancel` fires. A blackhole
    /// ends with a reset of the connections it stranded, so a client waits out the window and
    /// not its own timeout. Cancellation switches every fault off. Time is only slept, never
    /// read, so the sequence depends on the schedule alone.
    ///
    /// Returns the faults that were applied.
    pub async fn run_schedule(
        &self,
        schedule: &FaultSchedule,
        cancel: CancellationToken,
    ) -> Vec<AppliedFault> {
        // (offset, 0 = end before 1 = start at the same offset, event index)
        let mut steps: Vec<(Duration, u8, usize)> = Vec::with_capacity(schedule.events.len() * 2);
        for (i, e) in schedule.events.iter().enumerate() {
            steps.push((e.start, 1, i));
            if let Some(end) = e.end {
                steps.push((end, 0, i));
            }
        }
        steps.sort_unstable();
        let origin = tokio::time::Instant::now();
        let mut applied: Vec<AppliedFault> = Vec::new();
        let mut slot_of: BTreeMap<usize, usize> = BTreeMap::new();
        for (at, order, i) in steps {
            tokio::select! {
                () = cancel.cancelled() => {
                    self.clear_faults();
                    return applied;
                }
                () = tokio::time::sleep_until(origin + at) => {}
            }
            let event = schedule.events[i];
            let now_ms = millis(origin.elapsed());
            if order == 1 {
                let mut resets = 0;
                match event.fault {
                    Fault::Latency(d) => self.set_latency(d),
                    Fault::Blackhole => self.set_blackhole(true),
                    Fault::Refuse => self.set_refuse(true),
                    Fault::Reset => resets = self.reset_all(),
                }
                slot_of.insert(i, applied.len());
                applied.push(AppliedFault {
                    fault: event.fault,
                    start_ms: now_ms,
                    end_ms: None,
                    resets,
                });
            } else {
                let mut resets = 0;
                match event.fault {
                    Fault::Latency(_) => self.set_latency(Duration::ZERO),
                    Fault::Blackhole => {
                        self.set_blackhole(false);
                        resets = self.reset_all();
                    }
                    Fault::Refuse => self.set_refuse(false),
                    Fault::Reset => {}
                }
                if let Some(done) = slot_of.get(&i).and_then(|s| applied.get_mut(*s)) {
                    done.end_ms = Some(now_ms);
                    done.resets += resets;
                }
            }
        }
        applied
    }

    fn clear_faults(&self) {
        self.set_latency(Duration::ZERO);
        self.set_blackhole(false);
        self.set_refuse(false);
    }
}
