//! Signed webhook delivery driven by `crawl_events`.
//!
//! [`WebhookSender::tick`] does two things: it copies new matching `crawl_events` of every
//! webhook run into the delivery outbox ([`ApiStore::webhook_enqueue`]), then claims due
//! deliveries and attempts them through a [`WebhookTransport`].
//!
//! Request: `POST <url>`, body = the SSE `data` envelope, headers `Crawlx-Event`,
//! `Crawlx-Delivery-Id`, `Crawlx-Timestamp` and
//! `Crawlx-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "{t}.{body}")>`.
//! Retries after 10 s, 30 s, 2 min, 10 min, 1 h, 6 h, 24 h with ±20 % seeded jitter
//! (8 attempts), then `dead`; `410` stops at once; every attempt re-checks the
//! destination against the [`EgressPolicy`].
//!
//! Every attempt is counted in `crawlx.webhook.deliveries{event,outcome}`; after each tick
//! `crawlx.webhook.pending{event}` and `crawlx.webhook.oldest_pending_age{event}` (seconds
//! the oldest pending delivery has been due, by the sender's [`Clock`]) describe the outbox.
//!
//! Zero-data-retention runs: a `page` event whose `pageId` is in the
//! [`DeliveryBuffer`] carries `data.content.{markdown,html,...}` in the request body, and a
//! `2xx` acknowledges the page out of the buffer.
//!
//! Runs with a scrape job (the Firecrawl crawl and batch scrape facade) deliver the
//! Firecrawl payload instead: `POST <url>` with the body
//! `{success, type: "crawl.page" | "crawl.started" | "crawl.completed" | "crawl.failed" |
//! "batch_scrape.*", id, webhookId, data: [document...], metadata, error?}` and the header
//! `X-Firecrawl-Signature: sha256=<hex HMAC-SHA256(secret, body)>` (`secret` is
//! `ApiConfig::webhook_secret`), plus the job's `webhook.headers`. `webhook.events` selects
//! `started`, `page`, `completed`, `failed` (with or without the product prefix); the retry
//! schedule is the one above.

use crate::intel::webhook::firecrawl_signature;
use crate::routes::events::delivery_envelope;
use crate::scrape_service::{firecrawl_document, record_run_usage};
use crate::state::AppState;
use crate::store::{ApiStore, DeliveryResult, DeliveryStatus, WebhookDelivery};
use async_trait::async_trait;
use chrono::Duration as ChronoDuration;
use crawlx_core::config::RetentionMode;
use crawlx_core::repo::{CrawlRun, EventRepo, PageRecord, RunEvent, RunRepo};
use crawlx_core::scrape::ScrapeJob;
use crawlx_core::{Clock, CrawlRunId, StoreError, Timestamp};
use crawlx_policy::EgressPolicy;
use crawlx_storage::{BufferedPage, DeliveryBuffer};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use hmac::{Hmac, Mac};
use parking_lot::Mutex;
use rand::Rng as _;
use serde_json::json;
use sha2::Sha256;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

/// Delay after failed attempt `n` (1-based), seconds. Eight attempts in total.
pub const RETRY_SCHEDULE_SECS: [u64; 7] = [10, 30, 120, 600, 3_600, 21_600, 86_400];
/// Attempts before a delivery is `dead`.
pub const MAX_ATTEMPTS: u16 = 8;
/// A delivery attempt succeeds only within this window.
pub const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(10);
/// Events copied into the outbox per run per tick.
const ENQUEUE_BATCH: u32 = 200;
/// Claimed rows are deferred this long so concurrent senders do not double-deliver.
const CLAIM_LEASE_SECS: u32 = 60;
const CLAIM_BATCH: u32 = 50;
/// Events delivered when `output.webhook.events` is empty.
const DEFAULT_EVENTS: [&str; 2] = ["completed", "failed"];

/// One outgoing request.
#[derive(Clone)]
pub struct WebhookRequest {
    /// Destination, already admitted by the egress policy at registration.
    pub url: url::Url,
    /// Header name/value pairs (`Crawlx-*` signature headers plus user headers).
    pub headers: Vec<(String, String)>,
    /// Exact bytes that were signed.
    pub body: Vec<u8>,
    /// Egress policy the transport must enforce after DNS resolution.
    pub egress: EgressPolicy,
}

/// Header values may carry credentials (`webhook.headers`): only the names are printed.
impl std::fmt::Debug for WebhookRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WebhookRequest")
            .field("url", &self.url)
            .field(
                "headers",
                &self.headers.iter().map(|(k, _)| k.as_str()).collect::<Vec<_>>(),
            )
            .field("body_len", &self.body.len())
            .field("egress", &self.egress)
            .finish()
    }
}

/// Transport failure.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The destination (or a resolved address) is forbidden: permanent.
    #[error("destination denied: {0}")]
    Egress(String),
    /// DNS, connect, TLS or timeout failure: retryable.
    #[error("{0}")]
    Network(String),
}

/// HTTP transport; tests inject a recording implementation.
#[async_trait]
pub trait WebhookTransport: Send + Sync {
    /// POST `req` and return the HTTP status.
    async fn post(&self, req: WebhookRequest) -> Result<u16, TransportError>;
}

/// `reqwest` transport: DNS resolved here, every address checked, the connection pinned to a
/// checked address, redirects not followed, 10 s timeout.
#[derive(Clone, Debug, Default)]
pub struct ReqwestTransport;

#[async_trait]
impl WebhookTransport for ReqwestTransport {
    async fn post(&self, req: WebhookRequest) -> Result<u16, TransportError> {
        let host = req
            .url
            .host_str()
            .ok_or_else(|| TransportError::Egress("missing host".to_owned()))?
            .to_owned();
        let port = req
            .url
            .port_or_known_default()
            .ok_or_else(|| TransportError::Egress("missing port".to_owned()))?;
        let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host.as_str(), port))
            .await
            .map_err(|e| TransportError::Network(format!("dns: {e}")))?
            .collect();
        let ips: Vec<std::net::IpAddr> = addrs.iter().map(std::net::SocketAddr::ip).collect();
        req.egress
            .check_all(&host, &ips)
            .map_err(|e| TransportError::Egress(e.to_string()))?;
        let pinned = addrs
            .first()
            .copied()
            .ok_or_else(|| TransportError::Network("no addresses".to_owned()))?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(ATTEMPT_TIMEOUT)
            .resolve(&host, pinned)
            .build()
            .map_err(|e| TransportError::Network(e.to_string()))?;
        let mut rb = client.post(req.url.clone()).body(req.body);
        for (k, v) in &req.headers {
            rb = rb.header(k, v);
        }
        let resp = rb
            .send()
            .await
            .map_err(|e| TransportError::Network(e.to_string()))?;
        Ok(resp.status().as_u16())
    }
}

/// Lowercase hex `HMAC-SHA256(secret, "{timestamp}.{body}")`.
#[must_use]
pub fn signature(secret: &str, timestamp: i64, body: &[u8]) -> String {
    // HMAC accepts keys of any length, so construction cannot fail.
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(secret.as_bytes()) else {
        return String::new();
    };
    mac.update(timestamp.to_string().as_bytes());
    mac.update(b".");
    mac.update(body);
    hex::encode(mac.finalize().into_bytes())
}

/// `Crawlx-Signature` header value.
#[must_use]
pub fn signature_header(secret: &str, timestamp: i64, body: &[u8]) -> String {
    format!("t={timestamp},v1={}", signature(secret, timestamp, body))
}

/// Delay before the next attempt after failed attempt `attempt` (1-based), with ±20 % jitter
/// seeded from the run seed, delivery id and attempt number.
#[must_use]
pub fn retry_delay(run: &CrawlRun, delivery: Uuid, attempt: u16) -> Option<Duration> {
    let base = *RETRY_SCHEDULE_SECS.get(usize::from(attempt).checked_sub(1)?)?;
    let mut rng = run
        .seed
        .rng("webhook-jitter", &[delivery.as_bytes(), &attempt.to_le_bytes()]);
    let factor: f64 = 0.8 + 0.4 * rng.gen::<f64>();
    Some(Duration::from_secs(base).mul_f64(factor))
}

/// Counts from one [`WebhookSender::tick`].
#[derive(Clone, Copy, PartialEq, Eq, Default, Debug)]
pub struct TickReport {
    /// Events copied from `crawl_events` into the delivery outbox.
    pub enqueued: u64,
    /// Deliveries the receiver acknowledged with a 2xx status.
    pub delivered: u64,
    /// Deliveries that failed and were rescheduled.
    pub retried: u64,
    /// Deliveries that are permanently `dead` (attempts exhausted or `410`).
    pub dead: u64,
}

/// The page rows of scrape runs read during one tick.
type PageCache = HashMap<CrawlRunId, Vec<PageRecord>>;

/// A delivery ready to be posted.
struct Prepared {
    headers: Vec<(String, String)>,
    body: Vec<u8>,
    /// The zero-data-retention page this delivery carries; acknowledged on `2xx`.
    buffered: Option<BufferedPage>,
}

/// Outcome of preparing a Firecrawl delivery.
enum Prep {
    Ready(Prepared),
    /// The delivery cannot be built and is dead (the reason is recorded on the outbox row).
    Dead(String),
}

/// The Firecrawl event name (`started`, `page`, `completed`, `failed`) of a run event of a scrape
/// run; `None` for run events Firecrawl has no webhook for. A `completed` event of a failed run
/// is `failed`; a cancelled run ends `completed`; a failed page is a `page`.
fn firecrawl_event(ev: &RunEvent) -> Option<&'static str> {
    match ev.kind.as_str() {
        "started" => Some("started"),
        "page" | "page.failed" => Some("page"),
        "failed" => Some("failed"),
        "completed" => Some(
            if ev.payload.get("status").and_then(serde_json::Value::as_str) == Some("failed") {
                "failed"
            } else {
                "completed"
            },
        ),
        _ => None,
    }
}

/// `name` without the `crawl.` / `batch_scrape.` product prefix.
fn bare_event(name: &str) -> &str {
    name.strip_prefix("crawl.")
        .or_else(|| name.strip_prefix("batch_scrape."))
        .unwrap_or(name)
}

/// Does the webhook's `events` filter select Firecrawl event `name` (empty means every event;
/// the `crawl.` / `batch_scrape.` prefix is optional)?
fn firecrawl_wants(events: &[String], name: &str) -> bool {
    events.is_empty() || events.iter().any(|e| bare_event(e) == name)
}

/// Headers a caller's `webhook.headers` may not set: they would break the signed request.
fn reserved_header(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    n.starts_with("crawlx-")
        || matches!(
            n.as_str(),
            "content-type"
                | "content-length"
                | "host"
                | "transfer-encoding"
                | "connection"
                | "x-firecrawl-signature"
        )
}

/// Record that `run` started: the `started` event of a scrape run with a webhook. The run is
/// accepted and queued; Firecrawl's `crawl.started` / `batch_scrape.started` tell the receiver
/// the job exists and its id.
///
/// # Errors
/// `500`/`503` when the event cannot be stored.
pub(crate) async fn announce_started(
    state: &AppState,
    run: &CrawlRun,
) -> Result<(), crate::errors::HttpError> {
    if run.config.scrape.is_some() && run.config.output.webhook.is_some() {
        state
            .repos
            .events
            .append(run.id, "started", json!({ "url": run.config.seed_url }))
            .await?;
    }
    Ok(())
}

/// Outbox driver.
pub struct WebhookSender {
    api: Arc<dyn ApiStore>,
    runs: Arc<dyn RunRepo>,
    events: Arc<dyn EventRepo>,
    transport: Arc<dyn WebhookTransport>,
    secret: String,
    clock: Arc<dyn Clock>,
    /// Page content of zero-data-retention runs: attached to `page` events on
    /// the way out and acknowledged on `2xx`.
    zdr: Option<Arc<DeliveryBuffer>>,
    /// Renders the documents of scrape runs' `page` events.
    documents: Option<AppState>,
    cursors: Mutex<HashMap<CrawlRunId, u64>>,
    /// Event types whose pending gauges were set by an earlier tick (reset to 0 once drained).
    gauged_events: Mutex<BTreeSet<String>>,
}

impl WebhookSender {
    /// A sender over the outbox in `api`, signing with `secret` and delivering via `transport`.
    #[must_use]
    pub fn new(
        api: Arc<dyn ApiStore>,
        runs: Arc<dyn RunRepo>,
        events: Arc<dyn EventRepo>,
        transport: Arc<dyn WebhookTransport>,
        secret: String,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            api,
            runs,
            events,
            transport,
            secret,
            clock,
            zdr: None,
            documents: None,
            cursors: Mutex::new(HashMap::new()),
            gauged_events: Mutex::new(BTreeSet::new()),
        }
    }

    /// Deliver page content of zero-data-retention runs from `buffer`: a `page` event whose
    /// `pageId` is buffered goes out with `data.content.{markdown,html,...}` attached, and a
    /// `2xx` acknowledges the page out of the buffer.
    #[must_use]
    pub fn with_zdr_buffer(mut self, buffer: Arc<DeliveryBuffer>) -> Self {
        self.zdr = Some(buffer);
        self
    }

    /// Render the documents of the `page` events of scrape runs (crawl and batch scrape
    /// webhooks carry the Firecrawl document of the page) with `state`. Without it a delivery
    /// for a scrape run is `dead` with an explanatory error.
    #[must_use]
    pub fn with_documents(mut self, state: AppState) -> Self {
        self.documents = Some(state);
        self
    }

    /// The buffered page a `page` event of a ZDR run refers to, if any.
    async fn zdr_page(&self, run: &CrawlRun, event: &RunEvent) -> Result<Option<BufferedPage>, StoreError> {
        if run.config.retention.mode != RetentionMode::Zdr || event.kind != "page" {
            return Ok(None);
        }
        let Some(page) = event.payload.get("pageId").and_then(serde_json::Value::as_i64) else {
            return Ok(None);
        };
        match &self.zdr {
            Some(buffer) => buffer.get(run.tenant, run.id, page).await,
            None => Ok(None),
        }
    }

    /// Enqueue new events, attempt every due delivery, then publish the pending gauges.
    ///
    /// # Errors
    /// Storage failures.
    pub async fn tick(&self) -> Result<TickReport, StoreError> {
        // Sweep even without webhook destinations, including pages left by crashed workers.
        if let Some(buffer) = self.zdr.as_ref().filter(|buffer| buffer.is_enabled()) {
            let _ = buffer.sweep(self.clock.now()).await?;
        }
        let mut report = TickReport {
            enqueued: self.enqueue_new().await?,
            ..TickReport::default()
        };
        let now = self.clock.now();
        let deliveries = Metrics::global().counter(names::WEBHOOK_DELIVERIES);
        // page rows of scrape runs, read once per run and tick
        let mut pages = PageCache::new();
        for d in self
            .api
            .webhook_claim_due(now, CLAIM_BATCH, CLAIM_LEASE_SECS)
            .await?
        {
            let outcome = match self.attempt(&d, &mut pages).await? {
                DeliveryResult::Delivered { .. } => {
                    report.delivered += 1;
                    "delivered"
                }
                DeliveryResult::Retry { .. } => {
                    report.retried += 1;
                    "retry"
                }
                DeliveryResult::Dead { .. } => {
                    report.dead += 1;
                    "exhausted"
                }
            };
            deliveries.inc_by(1, &[("event", &d.event_type), ("outcome", outcome)]);
        }
        self.publish_pending_gauges().await?;
        Ok(report)
    }

    /// Set `crawlx.webhook.pending{event}` and `crawlx.webhook.oldest_pending_age{event}` from
    /// the outbox; event types gauged earlier but drained now are reset to 0.
    // Counts and millisecond ages are far below 2^53; the gauge stores `f64` anyway.
    #[allow(clippy::cast_precision_loss)]
    async fn publish_pending_gauges(&self) -> Result<(), StoreError> {
        let mut pending: BTreeMap<String, (u64, Timestamp)> = BTreeMap::new();
        for run_id in self.api.webhook_runs().await? {
            for d in self.api.webhook_list(run_id).await? {
                if d.status != DeliveryStatus::Pending {
                    continue;
                }
                let entry = pending.entry(d.event_type).or_insert((0, d.next_attempt_at));
                entry.0 = entry.0.saturating_add(1);
                entry.1 = entry.1.min(d.next_attempt_at);
            }
        }
        let now = self.clock.now();
        let metrics = Metrics::global();
        let count = metrics.gauge(names::WEBHOOK_PENDING);
        let age = metrics.gauge(names::WEBHOOK_OLDEST_PENDING_AGE);
        let previous = std::mem::take(&mut *self.gauged_events.lock());
        for event in previous.iter().filter(|e| !pending.contains_key(*e)) {
            count.set(0.0, &[("event", event)]);
            age.set(0.0, &[("event", event)]);
        }
        for (event, (n, oldest_due)) in &pending {
            count.set(*n as f64, &[("event", event)]);
            let due_for_ms = (now - *oldest_due).num_milliseconds().max(0);
            age.set(due_for_ms as f64 / 1_000.0, &[("event", event)]);
        }
        *self.gauged_events.lock() = pending.into_keys().collect();
        Ok(())
    }

    async fn enqueue_new(&self) -> Result<u64, StoreError> {
        let mut enqueued = 0;
        for run_id in self.api.webhook_runs().await? {
            let run = match self.runs.get(run_id).await {
                Ok(r) => r,
                Err(StoreError::NotFound { .. }) => continue,
                Err(error @ StoreError::RetentionDenied(_)) => {
                    if self.runs.get_metadata(run_id).await?.retention.mode == RetentionMode::Zdr {
                        continue;
                    }
                    return Err(error);
                }
                Err(e) => return Err(e),
            };
            let Some(hook) = run.config.output.webhook.clone() else {
                continue;
            };
            let scrape = run.config.scrape.is_some();
            let wanted: Vec<&str> = if hook.events.is_empty() {
                DEFAULT_EVENTS.to_vec()
            } else {
                hook.events.iter().map(String::as_str).collect()
            };
            let cached = self.cursors.lock().get(&run_id).copied();
            let mut cursor = match cached {
                Some(c) => c,
                None => self.api.webhook_cursor(run_id).await?,
            };
            loop {
                let batch = self.events.list_after(run_id, cursor, ENQUEUE_BATCH).await?;
                if batch.is_empty() {
                    break;
                }
                for ev in &batch {
                    cursor = ev.seq;
                    // scrape runs deliver Firecrawl events: a `completed` event of a failed run
                    // is `failed`, a `page.failed` is a `page`
                    let deliver = if scrape {
                        firecrawl_event(ev).is_some_and(|name| firecrawl_wants(&hook.events, name))
                    } else {
                        wanted.contains(&ev.kind.as_str())
                    };
                    if !deliver {
                        continue;
                    }
                    let delivery = WebhookDelivery {
                        id: Uuid::now_v7(),
                        run: run_id,
                        event_seq: ev.seq,
                        event_type: ev.kind.clone(),
                        url: hook.url.to_string(),
                        status: DeliveryStatus::Pending,
                        attempts: 0,
                        next_attempt_at: self.clock.now(),
                        delivered_at: None,
                        last_status: None,
                        last_error: None,
                    };
                    if self.api.webhook_enqueue(&delivery).await? {
                        enqueued += 1;
                    }
                }
            }
            self.cursors.lock().insert(run_id, cursor);
        }
        Ok(enqueued)
    }

    async fn event_for(&self, d: &WebhookDelivery) -> Result<Option<RunEvent>, StoreError> {
        let batch = self
            .events
            .list_after(d.run, d.event_seq.saturating_sub(1), 1)
            .await?;
        Ok(batch.into_iter().find(|e| e.seq == d.event_seq))
    }

    /// Attempt one claimed delivery and record the outcome.
    async fn attempt(
        &self,
        d: &WebhookDelivery,
        pages: &mut PageCache,
    ) -> Result<DeliveryResult, StoreError> {
        let attempt_no = d.attempts + 1;
        let result = self.deliver(d, attempt_no, pages).await?;
        self.api.webhook_record(d.id, &result).await?;
        Ok(result)
    }

    async fn deliver(
        &self,
        d: &WebhookDelivery,
        attempt_no: u16,
        pages: &mut PageCache,
    ) -> Result<DeliveryResult, StoreError> {
        let dead = |status: Option<u16>, error: String| DeliveryResult::Dead { status, error };
        let run = match self.runs.get(d.run).await {
            Ok(r) => r,
            Err(StoreError::NotFound { .. }) => return Ok(dead(None, "run no longer exists".to_owned())),
            Err(error @ StoreError::RetentionDenied(_)) => {
                if self.runs.get_metadata(d.run).await?.retention.mode == RetentionMode::Zdr {
                    return Ok(dead(None, "zdr delivery window expired".to_owned()));
                }
                return Err(error);
            }
            Err(e) => return Err(e),
        };
        let Some(event) = self.event_for(d).await? else {
            return Ok(dead(None, "event no longer exists".to_owned()));
        };
        let url = match url::Url::parse(&d.url) {
            Ok(u) => u,
            Err(e) => return Ok(dead(None, format!("invalid destination: {e}"))),
        };
        let egress = EgressPolicy::new(run.config.safety.allow_private_networks);
        if let Err(e) = egress.check_url(&url) {
            return Ok(dead(None, format!("egress_denied: {e}")));
        }
        let now = self.clock.now();
        let prepared = match run.config.scrape.as_ref() {
            Some(job) => match self.firecrawl_request(&run, job, d, &event, pages).await? {
                Prep::Ready(p) => p,
                Prep::Dead(reason) => return Ok(dead(None, reason)),
            },
            None => self.native_request(&run, d, &event, now).await?,
        };
        let Prepared {
            headers,
            body,
            buffered,
        } = prepared;
        let outcome = self
            .transport
            .post(WebhookRequest {
                url,
                headers,
                body,
                egress,
            })
            .await;
        let failure = match outcome {
            Ok(s) if (200..300).contains(&s) => {
                if let (Some(page), Some(buffer)) = (&buffered, &self.zdr) {
                    if buffer.ack(run.tenant, run.id, page.page).await? {
                        tracing::debug!(run = %run.id, page = page.page, "zdr page acknowledged");
                    }
                }
                return Ok(DeliveryResult::Delivered { status: s, at: now });
            }
            Ok(410) => return Ok(dead(Some(410), "destination returned 410 Gone".to_owned())),
            Ok(s) => (Some(s), format!("destination returned {s}")),
            Err(TransportError::Egress(m)) => return Ok(dead(None, format!("egress_denied: {m}"))),
            Err(TransportError::Network(m)) => (None, m),
        };
        match retry_delay(&run, d.id, attempt_no).filter(|_| attempt_no < MAX_ATTEMPTS) {
            Some(delay) => Ok(DeliveryResult::Retry {
                status: failure.0,
                error: failure.1,
                next_attempt_at: now
                    + ChronoDuration::milliseconds(i64::try_from(delay.as_millis()).unwrap_or(i64::MAX)),
            }),
            None => Ok(dead(failure.0, failure.1)),
        }
    }

    /// The native delivery: the SSE envelope signed as `Crawlx-Signature: t=<unix>,v1=<hmac>`.
    async fn native_request(
        &self,
        run: &CrawlRun,
        d: &WebhookDelivery,
        event: &RunEvent,
        now: Timestamp,
    ) -> Result<Prepared, StoreError> {
        let (payload, buffered) = delivery_envelope(
            run.tenant,
            run.id,
            run.config.retention.mode == RetentionMode::Zdr,
            event,
            self.zdr.as_deref(),
        )
        .await?;
        let body = payload.to_string().into_bytes();
        let t = now.timestamp();
        let headers = vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Crawlx-Event".to_owned(), d.event_type.clone()),
            ("Crawlx-Delivery-Id".to_owned(), d.id.to_string()),
            ("Crawlx-Timestamp".to_owned(), t.to_string()),
            (
                "Crawlx-Signature".to_owned(),
                signature_header(&self.secret, t, &body),
            ),
        ];
        Ok(Prepared {
            headers,
            body,
            buffered,
        })
    }

    /// The page `page_id` of `run`. `pages` keeps the rows read earlier in this tick; a page the
    /// cached rows miss is looked up afresh (the worker stores a page before it journals it).
    async fn page_for(
        &self,
        state: &AppState,
        pages: &mut PageCache,
        run: &CrawlRun,
        page_id: i64,
    ) -> Result<Option<PageRecord>, StoreError> {
        let find = |rows: &[PageRecord]| rows.iter().find(|p| p.frontier_id == page_id).cloned();
        if let Some(hit) = pages.get(&run.id).and_then(|rows| find(rows)) {
            return Ok(Some(hit));
        }
        let fresh = state.repos.pages.list(run.id).await?;
        let hit = find(&fresh);
        pages.insert(run.id, fresh);
        Ok(hit)
    }

    /// The Firecrawl delivery of a run event of a scrape run: `{success, type, id, webhookId,
    /// data, metadata, error?}` signed as `X-Firecrawl-Signature: sha256=<hmac of the body>`,
    /// with the job's `webhook.headers` added (they never override the signature, content type
    /// or host headers and are never logged).
    async fn firecrawl_request(
        &self,
        run: &CrawlRun,
        job: &ScrapeJob,
        d: &WebhookDelivery,
        event: &RunEvent,
        pages: &mut PageCache,
    ) -> Result<Prep, StoreError> {
        let Some(name) = firecrawl_event(event) else {
            return Ok(Prep::Dead(
                "the run event has no Firecrawl counterpart".to_owned(),
            ));
        };
        let Some(state) = &self.documents else {
            return Ok(Prep::Dead(
                "this sender has no document renderer for scrape runs".to_owned(),
            ));
        };
        let mut data = Vec::new();
        let mut error: Option<String> = None;
        match event.kind.as_str() {
            "page" => {
                let Some(id) = event.payload.get("pageId").and_then(serde_json::Value::as_i64) else {
                    return Ok(Prep::Dead("a page event without a pageId".to_owned()));
                };
                let Some(page) = self.page_for(state, pages, run, id).await? else {
                    return Ok(Prep::Dead(format!("page {id} no longer exists")));
                };
                data.push(firecrawl_document(state, run, &page, "").await);
            }
            "page.failed" => {
                let text = |k: &str| event.payload.get(k).and_then(serde_json::Value::as_str);
                let why = text("message")
                    .or_else(|| text("reason"))
                    .unwrap_or("page failed");
                error = Some(match text("url") {
                    Some(url) => format!("{url}: {why}"),
                    None => why.to_owned(),
                });
            }
            _ if name == "failed" => {
                let reason = event
                    .payload
                    .get("terminalReason")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("failed");
                error = Some(format!("{} failed: {reason}", job.kind.event_prefix()));
            }
            _ => {}
        }
        if matches!(name, "completed" | "failed") {
            // the run is terminal: book its credits in the usage ledger (once)
            record_run_usage(state, run).await;
        }
        let event_type = format!("{}.{name}", job.kind.event_prefix());
        let metadata = if job.webhook_metadata.is_null() {
            json!({})
        } else {
            job.webhook_metadata.clone()
        };
        let mut payload = json!({
            "success": error.is_none(),
            "type": event_type,
            "id": run.id,
            "webhookId": d.id,
            "data": data,
            "metadata": metadata,
        });
        if let Some(e) = &error {
            payload["error"] = json!(e);
        }
        let body = payload.to_string().into_bytes();
        let mut headers = vec![
            ("Content-Type".to_owned(), "application/json".to_owned()),
            ("Crawlx-Event".to_owned(), event_type),
            ("Crawlx-Delivery-Id".to_owned(), d.id.to_string()),
            (
                "X-Firecrawl-Signature".to_owned(),
                firecrawl_signature(&self.secret, &body),
            ),
        ];
        headers.extend(
            job.webhook_headers
                .iter()
                .filter(|(k, _)| !reserved_header(k))
                .map(|(k, v)| (k.clone(), v.clone())),
        );
        Ok(Prep::Ready(Prepared {
            headers,
            body,
            buffered: self.zdr_page(run, event).await?,
        }))
    }

    /// Run [`Self::tick`] every `interval` until `shutdown` is cancelled. A tick in flight
    /// finishes first, so a claimed delivery is never abandoned mid-attempt.
    pub async fn run_forever(self: Arc<Self>, interval: Duration, shutdown: CancellationToken) {
        while !shutdown.is_cancelled() {
            if let Err(e) = self.tick().await {
                tracing::warn!(error = %e, "webhook tick failed");
            }
            tokio::select! {
                () = shutdown.cancelled() => break,
                () = tokio::time::sleep(interval) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn signature_matches_known_hmac_sha256() {
        // RFC 4231 test case 2 style check: HMAC-SHA256("Jefe", "what do ya want for nothing?")
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(b"Jefe").unwrap();
        mac.update(b"what do ya want for nothing?");
        assert_eq!(
            hex::encode(mac.finalize().into_bytes()),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
        let a = signature("s", 1_760_607_001, b"{}");
        assert_eq!(a.len(), 64);
        assert_eq!(a, signature("s", 1_760_607_001, b"{}"));
        assert_ne!(a, signature("s", 1_760_607_002, b"{}"));
        assert!(signature_header("s", 7, b"x").starts_with("t=7,v1="));
    }

    fn run_event(kind: &str, payload: serde_json::Value) -> RunEvent {
        RunEvent {
            seq: 1,
            kind: kind.to_owned(),
            at: chrono::Utc::now(),
            payload,
        }
    }

    #[test]
    fn run_events_map_to_firecrawl_event_names() {
        let name = |kind: &str, payload: serde_json::Value| firecrawl_event(&run_event(kind, payload));
        assert_eq!(name("started", json!({})), Some("started"));
        assert_eq!(name("page", json!({"pageId": 1})), Some("page"));
        assert_eq!(name("page.failed", json!({})), Some("page"));
        assert_eq!(
            name("completed", json!({"status": "completed"})),
            Some("completed")
        );
        assert_eq!(
            name("completed", json!({"status": "cancelled"})),
            Some("completed")
        );
        assert_eq!(name("completed", json!({"status": "failed"})), Some("failed"));
        assert_eq!(name("failed", json!({})), Some("failed"));
        for other in ["state", "action", "paused", "status", "session"] {
            assert_eq!(name(other, json!({})), None, "{other}");
        }
    }

    #[test]
    fn firecrawl_event_filters_accept_prefixed_names() {
        let events = |l: &[&str]| l.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>();
        assert!(firecrawl_wants(&[], "failed"), "no filter means every event");
        assert!(firecrawl_wants(&events(&["crawl.page"]), "page"));
        assert!(firecrawl_wants(&events(&["batch_scrape.completed"]), "completed"));
        assert!(firecrawl_wants(&events(&["started", "page"]), "started"));
        assert!(!firecrawl_wants(&events(&["started", "page"]), "completed"));
    }

    #[test]
    fn webhook_headers_cannot_override_the_signature() {
        for reserved in [
            "Content-Type",
            "x-firecrawl-signature",
            "X-FIRECRAWL-SIGNATURE",
            "Crawlx-Event",
            "Host",
            "Content-Length",
        ] {
            assert!(reserved_header(reserved), "{reserved}");
        }
        assert!(!reserved_header("Authorization"));
        assert!(!reserved_header("X-My-Header"));
    }

    #[test]
    fn requests_never_debug_print_header_values() {
        let req = WebhookRequest {
            url: url::Url::parse("https://h.example.test/").unwrap(),
            headers: vec![("Authorization".to_owned(), "Bearer top-secret".to_owned())],
            body: b"{}".to_vec(),
            egress: EgressPolicy::new(false),
        };
        let shown = format!("{req:?}");
        assert!(
            shown.contains("Authorization") && !shown.contains("top-secret"),
            "{shown}"
        );
    }
}
