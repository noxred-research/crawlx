//! The run's capture backend: the browser-context decorator that feeds a
//! [`TrafficSource`] with the session's epoch windows, and the shared [`ProxyCapture`]
//! behind `capture.backend = "proxy"`.
//!
//! Every session's context is wrapped by the pool (also on recovery and replay
//! acquisitions). The decorator opens an epoch window when `navigate`/`perform` return an
//! epoch and closes it after `settle`:
//!
//! * **CDP** (default): `drain_traffic` passes the browser's own events through a
//!   per-session [`CdpTraffic`], which applies the contract's `late` rule (started after
//!   the epoch settled).
//! * **Proxy**: `drain_traffic` retains raw proxy events alongside explicitly identified
//!   CDP supplements for HTTPS, streams, service workers and retained body artifacts.
//!   CDP stays the attribution authority. Only derived operation views deduplicate.

use async_trait::async_trait;
use crawlx_core::action::BrowserAction;
use crawlx_core::browser::ResponseBodySink;
use crawlx_core::captcha::CaptchaSecrets;
use crawlx_core::config::RetentionMode;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::observation::{
    ActionReceipt, DomSelector, NavigationResult, ObservationBundle, ObservationSpec, QuiescencePolicy,
    Revalidation, RuntimeLocator, SettleReport,
};
use crawlx_core::repo::{ArtifactStore, Sensitivity};
use crawlx_core::request_controls::RequestControls;
use crawlx_core::secret::ArtifactSink;
use crawlx_core::traffic::{Protocol, TrafficEvent};
use crawlx_core::{
    ArtifactRef, BrowserContext, BrowserError, CanonicalUrl, Clock, CrawlRunId, NetworkEpochId, SessionId,
    StoreError,
};
use crawlx_observe::{CdpTraffic, ProxyCaptureStats, ProxyTraffic, TrafficSource as _};
use parking_lot::Mutex;
use std::sync::Arc;

/// Capacity of the flow channel between the proxy / fetch plane and the source. The
/// proxy never blocks on it: a full channel drops the flow and counts it.
pub const FLOW_CHANNEL: usize = 4096;

/// Reject scoped secrets without allocating a lossy UTF-8 copy of an opaque capture.
pub(crate) fn check_run_secrets(
    bytes: &[u8],
    controls: &RequestControls,
    captcha: Option<&CaptchaSecrets>,
) -> Result<(), StoreError> {
    if crawlx_core::secret::contains_secret_bytes(bytes, |part| {
        controls.secret_values().any(|secret| {
            part.windows(secret.len())
                .any(|window| window == secret.as_bytes())
        })
    }) || captcha
        .map_or(Ok(false), |registry| registry.contains_bytes(bytes))
        .map_err(|_| StoreError::RetentionDenied("artifact secret registry unavailable".into()))?
    {
        return Err(StoreError::RetentionDenied(
            "artifact contains run secrets".into(),
        ));
    }
    Ok(())
}

/// Policy boundary for retained response bodies before bytes enter artifact storage.
pub(crate) struct RetainedBodySink {
    run: CrawlRunId,
    artifacts: Arc<dyn ArtifactStore>,
    controls: RequestControls,
    retention: RetentionMode,
    key: [u8; 32],
    captcha_secrets: CaptchaSecrets,
    body_limit: usize,
}

impl std::fmt::Debug for RetainedBodySink {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetainedBodySink")
            .field("run", &self.run)
            .field("retention", &self.retention)
            .finish_non_exhaustive()
    }
}

impl RetainedBodySink {
    /// Create a run-scoped sink; ZDR, binary and secret-bearing bodies are refused.
    pub(crate) fn new(
        run: CrawlRunId,
        artifacts: Arc<dyn ArtifactStore>,
        controls: RequestControls,
        retention: RetentionMode,
        key: [u8; 32],
        captcha_secrets: CaptchaSecrets,
    ) -> Self {
        Self {
            run,
            artifacts,
            controls,
            retention,
            key,
            captcha_secrets,
            body_limit: 1024 * 1024,
        }
    }

    /// Use the static fetcher's existing bounded read limit instead of the browser cap.
    #[must_use]
    pub(crate) const fn with_body_limit(mut self, limit: usize) -> Self {
        self.body_limit = limit;
        self
    }

    fn permits(&self, content_type: &str, bytes: &[u8], truncated: bool) -> bool {
        let limit = if truncated { 64 * 1024 } else { self.body_limit };
        if self.retention == RetentionMode::Zdr || bytes.len() > limit {
            return false;
        }
        let Ok(body) = std::str::from_utf8(bytes) else {
            return false;
        };
        if check_run_secrets(bytes, &self.controls, Some(&self.captcha_secrets)).is_err() {
            return false;
        }
        if body
            .chars()
            .any(|ch| ch.is_control() && !matches!(ch, '\n' | '\r' | '\t'))
            || !crawlx_extract::secrets::detect(&self.key, &[], body).is_empty()
        {
            return false;
        }
        let content_type = content_type.trim();
        let mime = content_type.split(';').next().unwrap_or("").trim();
        if truncated
            && !(mime.eq_ignore_ascii_case("text/html")
                || mime.eq_ignore_ascii_case("application/json")
                || mime
                    .rsplit_once('+')
                    .is_some_and(|(_, suffix)| suffix.eq_ignore_ascii_case("json")))
        {
            return false;
        }
        let json = contains_ascii_case(content_type, "json")
            || body.trim_start().starts_with('{')
            || body.trim_start().starts_with('[');
        if json {
            match serde_json::from_str::<serde_json::Value>(body) {
                Ok(value) if sensitive_json_fields(&value) => return false,
                Ok(_) if !truncated => return true,
                Ok(_) => {}
                // A bounded prefix may end inside a key or value. Without a complete
                // parse, escapes can conceal sensitive names or scoped literal secrets.
                Err(_) if !truncated || body.contains('\\') => return false,
                Err(_) => {}
            }
        }
        // A bounded prefix may end inside a JSON string or object. Validate its
        // text and sensitive markers rather than requiring a complete document.
        if !(json
            || content_type
                .as_bytes()
                .get(..5)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case(b"text/"))
            || contains_ascii_case(content_type, "javascript")
            || contains_ascii_case(content_type, "xml"))
        {
            return false;
        }
        // Form fields and assignment-shaped credentials may not match a provider's
        // token pattern. Refuse rather than retain uncertain secret-bearing text.
        !body
            .split(|ch: char| !ch.is_ascii_alphanumeric() && !matches!(ch, '_' | '-'))
            .any(sensitive_field)
    }
}

/// Whether an artifact media type permits text redaction, including generated HTTP exchange text.
pub(crate) fn is_text_artifact(content_type: &str) -> bool {
    let mime = content_type.split(';').next().unwrap_or("").trim();
    mime.get(..5)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("text/"))
        || [
            "application/json",
            "application/xml",
            "application/javascript",
            "application/graphql",
            "application/x-www-form-urlencoded",
            "message/http",
        ]
        .iter()
        .any(|text| mime.eq_ignore_ascii_case(text))
        || mime.rsplit_once('+').is_some_and(|(_, suffix)| {
            suffix.eq_ignore_ascii_case("json") || suffix.eq_ignore_ascii_case("xml")
        })
}

fn contains_ascii_case(value: &str, needle: &str) -> bool {
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

pub(crate) fn sensitive_field(field: &str) -> bool {
    [
        "token",
        "secret",
        "password",
        "passwd",
        "login",
        "authorization",
        "authentication",
        "oauth",
        "auth_",
        "auth-",
        "cookie",
        "session",
        "access_key",
        "access-key",
        "credential",
        "csrf",
    ]
    .iter()
    .any(|sensitive| contains_ascii_case(field, sensitive))
        || field.eq_ignore_ascii_case("auth")
}

pub(crate) fn sensitive_json_fields(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::Object(fields) => fields
            .iter()
            .any(|(key, value)| sensitive_field(key) || sensitive_json_fields(value)),
        serde_json::Value::Array(values) => values.iter().any(sensitive_json_fields),
        _ => false,
    }
}

#[async_trait]
impl ResponseBodySink for RetainedBodySink {
    async fn store(
        &self,
        content_type: &str,
        bytes: &[u8],
        truncated: bool,
    ) -> Result<Option<ArtifactRef>, StoreError> {
        if !self.permits(content_type, bytes, truncated) {
            return Ok(None);
        }
        let scrubbed = crawlx_telemetry::Redactor::new().scrub_bytes(bytes, std::iter::empty::<&str>());
        let limit = if truncated { 64 * 1024 } else { self.body_limit };
        let mut end = scrubbed.len().min(limit);
        if let Ok(text) = std::str::from_utf8(&scrubbed) {
            while !text.is_char_boundary(end) {
                end = end.saturating_sub(1);
            }
        }
        let approved = crawlx_core::secret::Redactor::new().redact_artifact(&scrubbed[..end])?;
        // Redaction can create a scoped literal that was absent from the source bytes.
        // Check the exact approved rendition against the live registry before dispatch.
        if check_run_secrets(approved.as_ref(), &self.controls, Some(&self.captcha_secrets)).is_err() {
            return Ok(None);
        }
        ArtifactSink::over(self.artifacts.as_ref())
            .put(self.run, Sensitivity::Content, content_type, &approved)
            .await
            .map(Some)
    }
}

/// The run's proxy traffic source, shared by its session contexts.
pub struct ProxyCapture {
    source: Mutex<ProxyTraffic>,
}

impl std::fmt::Debug for ProxyCapture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyCapture")
            .field("stats", &self.stats())
            .finish_non_exhaustive()
    }
}

impl ProxyCapture {
    /// Wrap a source.
    #[must_use]
    pub fn new(source: ProxyTraffic) -> Arc<Self> {
        Arc::new(Self {
            source: Mutex::new(source),
        })
    }

    /// Counters so far (flows waiting on the channel are pulled first).
    #[must_use]
    pub fn stats(&self) -> ProxyCaptureStats {
        let mut s = self.source.lock();
        s.pump();
        s.stats()
    }

    /// Protocols the backend disabled in the browser.
    #[must_use]
    pub fn protocols_disabled(&self) -> Vec<Protocol> {
        self.source.lock().protocols_disabled().to_vec()
    }

    /// Events attributed to nobody yet still waiting (flows that arrived after the last
    /// drain of the run); reported in the run's `capture.proxy.summary` event.
    #[must_use]
    pub fn pending(&self) -> usize {
        let mut s = self.source.lock();
        s.pump();
        s.pending()
    }
}

/// Where a decorated context's traffic comes from.
enum Backend {
    Cdp(CdpTraffic),
    Proxy(Arc<ProxyCapture>),
}

/// Decorate `ctx` for `session` with the CDP backend (window `late` rule only).
#[must_use]
pub fn wrap_cdp(
    session: SessionId,
    clock: Arc<dyn Clock>,
    ctx: Box<dyn BrowserContext>,
    captcha_secrets: CaptchaSecrets,
) -> Box<dyn BrowserContext> {
    Box::new(CaptureContext {
        inner: ctx,
        session,
        backend: Backend::Cdp(CdpTraffic::new()),
        clock,
        current: None,
        seq: 0,
        captcha_secrets,
    })
}

/// Decorate `ctx` for `session` with the proxy backend.
#[must_use]
pub fn wrap_proxy(
    capture: &Arc<ProxyCapture>,
    session: SessionId,
    clock: Arc<dyn Clock>,
    ctx: Box<dyn BrowserContext>,
    captcha_secrets: CaptchaSecrets,
) -> Box<dyn BrowserContext> {
    Box::new(CaptureContext {
        inner: ctx,
        session,
        backend: Backend::Proxy(Arc::clone(capture)),
        clock,
        current: None,
        seq: 0,
        captcha_secrets,
    })
}

/// A browser context whose traffic goes through a capture backend (see the module docs).
pub struct CaptureContext {
    inner: Box<dyn BrowserContext>,
    session: SessionId,
    backend: Backend,
    clock: Arc<dyn Clock>,
    current: Option<NetworkEpochId>,
    seq: u64,
    captcha_secrets: CaptchaSecrets,
}

impl CaptureContext {
    fn open(&mut self, epoch: NetworkEpochId, at: crawlx_core::Timestamp) {
        match &mut self.backend {
            Backend::Cdp(cdp) => cdp.open_epoch(epoch),
            Backend::Proxy(p) => p.source.lock().open_epoch(epoch, self.session, at),
        }
        self.current = Some(epoch);
    }

    fn close(&mut self, at: crawlx_core::Timestamp) {
        let Some(epoch) = self.current else { return };
        match &mut self.backend {
            Backend::Cdp(cdp) => cdp.close_epoch(epoch, at),
            Backend::Proxy(p) => p.source.lock().close_epoch(epoch, at),
        }
    }
}

#[async_trait]
impl BrowserContext for CaptureContext {
    async fn navigate(&mut self, url: &CanonicalUrl) -> Result<NavigationResult, BrowserError> {
        let r = self.inner.navigate(url).await?;
        self.open(r.network_epoch, self.clock.now());
        Ok(r)
    }
    async fn observe(&mut self, spec: ObservationSpec) -> Result<ObservationBundle, BrowserError> {
        self.inner.observe(spec).await
    }
    async fn revalidate(
        &mut self,
        locator: &RuntimeLocator,
        expected: ObservationEpoch,
    ) -> Result<Revalidation, BrowserError> {
        self.inner.revalidate(locator, expected).await
    }
    async fn resolve_selector(
        &mut self,
        selector: &DomSelector,
    ) -> Result<Option<RuntimeLocator>, BrowserError> {
        self.inner.resolve_selector(selector).await
    }
    async fn perform(&mut self, action: BrowserAction) -> Result<ActionReceipt, BrowserError> {
        let r = self.inner.perform(action).await?;
        self.open(r.network_epoch, r.started_at);
        Ok(r)
    }
    async fn settle(&mut self, policy: QuiescencePolicy) -> Result<SettleReport, BrowserError> {
        let r = self.inner.settle(policy).await?;
        self.close(self.clock.now());
        Ok(r)
    }
    async fn captcha_pending(&mut self) -> Result<bool, BrowserError> {
        self.inner.captcha_pending().await
    }
    fn current_epoch(&self) -> ObservationEpoch {
        self.inner.current_epoch()
    }
    fn drain_traffic(&mut self) -> Vec<TrafficEvent> {
        let cdp = self.inner.drain_traffic();
        let mut events = match &mut self.backend {
            Backend::Cdp(source) => {
                source.push_drained(cdp);
                source.drain()
            }
            Backend::Proxy(p) => {
                let mut source = p.source.lock();
                source.push_cdp(self.session, cdp);
                source.pump();
                source.take_for(self.session)
            }
        };
        for event in &mut events {
            mask_captcha_event(event, &self.captcha_secrets);
            self.seq = self.seq.saturating_add(1);
            event.seq = self.seq;
        }
        events
    }
    async fn export_storage(&mut self) -> Result<Vec<u8>, BrowserError> {
        self.inner.export_storage().await
    }
    async fn import_storage(&mut self, blob: &[u8]) -> Result<(), BrowserError> {
        self.inner.import_storage(blob).await
    }
    async fn close(self: Box<Self>) -> Result<(), BrowserError> {
        self.inner.close().await
    }
    async fn page_op(
        &mut self,
        op: crawlx_core::page_op::PageOp,
    ) -> Result<crawlx_core::page_op::PageOpResult, BrowserError> {
        self.inner.page_op(op).await
    }
    async fn lazy_scroll(
        &mut self,
        spec: crawlx_core::dom_ops::LazyScrollSpec,
    ) -> Result<crawlx_core::dom_ops::LazyScrollReport, BrowserError> {
        self.inner.lazy_scroll(spec).await
    }
    async fn css_filter(
        &mut self,
        filter: &crawlx_core::dom_ops::CssFilter,
        targets: &[RuntimeLocator],
    ) -> Result<Vec<bool>, BrowserError> {
        self.inner.css_filter(filter, targets).await
    }
    fn drain_xhr(&mut self) -> Vec<crawlx_core::dom_ops::XhrRecord> {
        self.inner.drain_xhr()
    }
    fn drain_blocked_navigations(&mut self) -> Vec<crawlx_core::BlockedNavigation> {
        self.inner.drain_blocked_navigations()
    }
}

fn mask_captcha_event(event: &mut TrafficEvent, secrets: &CaptchaSecrets) {
    if matches!(secrets.has_values(), Ok(false)) {
        return;
    }
    // The synchronous BrowserContext drain cannot return errors. A poisoned
    // registry must conceal data rather than leak tokens or drop raw events.
    let mask = |text: &str| {
        secrets
            .redact(text)
            .unwrap_or_else(|_| crawlx_core::traffic::REDACTED_PLACEHOLDER.to_owned())
    };
    event.url = mask(&event.url);
    for (name, value) in event
        .request_headers
        .iter_mut()
        .chain(&mut event.response_headers)
    {
        if name == "x-crawlx-capture-source" {
            continue;
        }
        *name = mask(name);
        *value = mask(value);
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_browser::fake::{FakePage, FakeScript};
    use crawlx_browser::FakeBackend;
    use crawlx_core::traffic::{ProxyFlow, ProxyFlowSource, TrafficOrigin, UnattributedReason};
    use crawlx_core::{BrowserBackend, ContextConfig, SystemClock};
    use crawlx_observe::Redactor;
    use crawlx_storage::artifacts::{ArtifactBlobs, FsBlobs, ObjectArtifactStore};
    use crawlx_url::{CanonicalizeOptions, Canonicalizer};

    #[test]
    fn http_exchange_media_type_uses_text_redaction_without_reclassifying_opaque_bodies() {
        assert!(is_text_artifact("message/http"));
        assert!(is_text_artifact("Message/HTTP; msgtype=response"));
        assert!(!is_text_artifact("application/octet-stream"));
        assert!(!is_text_artifact("application/pdf"));
    }

    #[tokio::test]
    async fn scoped_run_checks_reject_escaped_four_and_five_byte_request_secrets() {
        let mut fetch = crawlx_core::config::Fetch::default();
        fetch.extra_headers.insert("x-short-four", "Q7z9");
        fetch.extra_headers.insert("x-short-five", "W8y2p");
        let controls = RequestControls::resolve(&fetch, "example.test", None)
            .await
            .unwrap();
        for bytes in [
            br#"{"data":"\u00517z9"}"#.as_slice(),
            br#"{"data":"\u00578y2p"}"#,
            br#"{"\u00517z9":"safe"}"#,
            br#"{"nested":[{"data":"\u00578y2p"}]}"#,
            br#"{"data":"\u00517z9","data":"safe"}"#,
        ] {
            assert!(check_run_secrets(bytes, &controls, None).is_err());
        }
    }

    #[test]
    fn scoped_run_checks_reject_duplicate_json_members_containing_captcha_secrets() {
        let captcha = CaptchaSecrets::default();
        captcha
            .register(crawlx_core::secret::SecretOr::secret(
                "duplicate-capture-canary-q7m2".into(),
            ))
            .unwrap();
        let bytes = br#"{"data":"duplicate-capture-\u0063anary-q7m2","data":"safe"}"#;
        assert!(check_run_secrets(bytes, &RequestControls::default(), Some(&captcha)).is_err());
    }

    fn flow(url: &str, at: crawlx_core::Timestamp) -> ProxyFlow {
        ProxyFlow {
            source: ProxyFlowSource::Browser,
            method: "GET".to_owned(),
            url: url.to_owned(),
            status: Some(200),
            protocol: Protocol::Http11,
            request_headers: Vec::new(),
            response_headers: Vec::new(),
            request_body: None,
            response_body: None,
            tunnel: None,
            peer: None,
            started_at: at,
            finished_at: at,
        }
    }

    fn seed() -> CanonicalUrl {
        Canonicalizer::canonicalize_url(
            &url::Url::parse("https://example.test/").unwrap(),
            &CanonicalizeOptions::default(),
        )
        .unwrap()
    }

    #[tokio::test]
    async fn proxy_decorator_attributes_flows_to_the_performed_epoch_and_keeps_unmatched() {
        let clock = Arc::new(crawlx_core::time::ManualClock::new(
            "2026-11-01T00:00:00Z".parse().unwrap(),
        ));
        let backend = FakeBackend::builder()
            .script(FakeScript::new().page(FakePage::new("https://example.test/")))
            .clock(clock.clone())
            .build();
        let session = SessionId::new();
        let raw = backend.new_context(ContextConfig::new(session)).await.unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let capture = ProxyCapture::new(ProxyTraffic::new(rx, Redactor::new([1u8; 32])));
        let mut ctx = wrap_proxy(&capture, session, clock.clone(), raw, CaptchaSecrets::default());
        // a flow before any epoch
        tx.try_send(flow("https://example.test/early", clock.now()))
            .unwrap();
        clock.advance_ms(1);
        let nav = ctx.navigate(&seed()).await.unwrap();
        clock.advance_ms(1);
        tx.try_send(flow("https://example.test/doc", clock.now()))
            .unwrap();
        clock.advance_ms(1);
        ctx.settle(QuiescencePolicy::default()).await.unwrap();
        let events = ctx.drain_traffic();
        assert_eq!(events.len(), 3, "{events:?}");
        // Attribution belongs to the identified raw event, not its position among
        // the chronologically merged proxy flows and CDP supplements.
        let early = events
            .iter()
            .find(|event| event.url == "https://example.test/early")
            .unwrap();
        assert_eq!(early.epoch_id, None);
        assert_eq!(
            early.unattributed_reason,
            Some(UnattributedReason::UnmatchedProxyFlow)
        );
        assert_eq!(early.origin, TrafficOrigin::Page);
        assert!(!early.late);
        let proxy = events
            .iter()
            .find(|event| event.url == "https://example.test/doc")
            .unwrap();
        assert_eq!(proxy.epoch_id, Some(nav.network_epoch));
        assert_eq!(proxy.unattributed_reason, None);
        assert_eq!(proxy.origin, TrafficOrigin::Page);
        assert!(!proxy.late);
        let supplement = events
            .iter()
            .find(|event| event.url == "https://example.test/")
            .unwrap();
        assert_eq!(supplement.epoch_id, Some(nav.network_epoch));
        assert_eq!(supplement.unattributed_reason, None);
        assert!(supplement
            .response_headers
            .iter()
            .any(|(name, value)| name == "x-crawlx-capture-source" && value == "cdp_supplement"));
        assert!(events
            .windows(2)
            .all(|pair| pair[0].started_at <= pair[1].started_at));
        assert_eq!(capture.stats().unmatched, 1);
        assert_eq!(capture.stats().unattributed, 1);
        assert_eq!(
            events.iter().map(|event| event.seq).collect::<Vec<_>>(),
            [1, 2, 3]
        );
        assert_eq!(capture.protocols_disabled(), vec![Protocol::H3]);
        // after settle, a flow is still the epoch's but late
        clock.advance_ms(1);
        tx.try_send(flow("https://example.test/late", clock.now()))
            .unwrap();
        let late = ctx.drain_traffic();
        assert_eq!(late.len(), 1);
        assert_eq!(late[0].epoch_id, Some(nav.network_epoch));
        assert_eq!(late[0].unattributed_reason, None);
        assert!(late[0].late);
        assert_eq!(late[0].seq, 4);
        assert_eq!(capture.stats().late, 1);
        assert_eq!(capture.pending(), 0);
    }

    #[tokio::test]
    async fn cdp_decorator_passes_the_browser_events_through_the_window_rule() {
        let backend = FakeBackend::new(FakeScript::new().page(FakePage::new("https://example.test/")));
        let session = SessionId::new();
        let raw = backend.new_context(ContextConfig::new(session)).await.unwrap();
        let clock: Arc<dyn Clock> = Arc::new(SystemClock);
        let mut ctx = wrap_cdp(session, clock, raw, CaptchaSecrets::default());
        let nav = ctx.navigate(&seed()).await.unwrap();
        ctx.settle(QuiescencePolicy::default()).await.unwrap();
        let events = ctx.drain_traffic();
        assert!(!events.is_empty(), "the fake records the navigation");
        assert!(events.iter().all(|e| e.epoch_id == Some(nav.network_epoch)));
        assert!(events.iter().all(|e| !e.late), "{events:?}");
    }

    #[derive(Default)]
    struct CapturedArtifacts {
        bodies: Mutex<Vec<Vec<u8>>>,
    }

    #[async_trait]
    impl ArtifactStore for CapturedArtifacts {
        async fn put(
            &self,
            _run: CrawlRunId,
            class: Sensitivity,
            content_type: &str,
            bytes: &[u8],
        ) -> Result<ArtifactRef, StoreError> {
            assert_eq!(class, Sensitivity::Content);
            assert!(!content_type.is_empty());
            self.bodies.lock().push(bytes.to_vec());
            Ok(ArtifactRef {
                id: crawlx_core::ArtifactId::new(),
                digest: crawlx_core::hash::Digest::of("capture-test", bytes),
            })
        }

        async fn get(&self, artifact: &ArtifactRef) -> Result<Vec<u8>, StoreError> {
            self.bodies
                .lock()
                .iter()
                .find(|body| crawlx_core::hash::Digest::of("capture-test", body) == artifact.digest)
                .cloned()
                .ok_or_else(|| StoreError::NotFound {
                    entity: "artifact",
                    id: artifact.id.to_string(),
                })
        }
    }

    struct PausedFsBlobs {
        inner: FsBlobs,
        entered: tokio::sync::Semaphore,
        release: tokio::sync::Semaphore,
        received: Mutex<Option<Vec<u8>>>,
    }

    #[async_trait]
    impl ArtifactBlobs for PausedFsBlobs {
        fn bucket(&self) -> &str {
            self.inner.bucket()
        }

        async fn put(&self, key: &str, bytes: &[u8]) -> Result<(), StoreError> {
            self.put_shared(key, bytes::Bytes::copy_from_slice(bytes)).await
        }

        async fn put_shared(&self, key: &str, bytes: bytes::Bytes) -> Result<(), StoreError> {
            if key.starts_with("encrypted/") {
                *self.received.lock() = Some(bytes.to_vec());
                self.entered.add_permits(1);
                self.release.acquire().await.unwrap().forget();
            }
            self.inner.put(key, &bytes).await
        }

        async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, StoreError> {
            self.inner.get(key).await
        }

        async fn exists(&self, key: &str) -> Result<bool, StoreError> {
            self.inner.exists(key).await
        }

        async fn delete(&self, key: &str) -> Result<(), StoreError> {
            self.inner.delete(key).await
        }

        async fn list(&self, prefix: &str) -> Result<Vec<crawlx_storage::artifacts::BlobEntry>, StoreError> {
            self.inner.list(prefix).await
        }
    }

    fn retained_sink(
        store: &Arc<CapturedArtifacts>,
        retention: RetentionMode,
        controls: RequestControls,
    ) -> RetainedBodySink {
        RetainedBodySink::new(
            CrawlRunId::new(),
            Arc::clone(store) as Arc<dyn ArtifactStore>,
            controls,
            retention,
            [7; 32],
            CaptchaSecrets::default(),
        )
    }

    #[tokio::test]
    async fn full_body_sink_stores_real_text_and_json_artifact_refs() {
        let store = Arc::new(CapturedArtifacts::default());
        let sink = retained_sink(&store, RetentionMode::Standard, RequestControls::default());
        for (content_type, body) in [
            ("text/plain", "ordinary page content"),
            (
                "text/html",
                "<article><h1>Example</h1><p>Ordinary content.</p></article>",
            ),
            (
                "Application/JSON",
                r#"{"items":[{"title":"example","count":2,"author":"Ada"}]}"#,
            ),
        ] {
            let artifact = sink
                .store(content_type, body.as_bytes(), false)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(store.get(&artifact).await.unwrap(), body.as_bytes());
        }
        assert_eq!(store.bodies.lock().len(), 3);
    }

    #[tokio::test]
    async fn full_body_sink_refuses_zdr_binary_oversize_and_secret_shapes_before_storage() {
        let store = Arc::new(CapturedArtifacts::default());
        let sink = retained_sink(&store, RetentionMode::Standard, RequestControls::default());
        for (content_type, body) in [
            (
                "application/json",
                br#"{"nested":[{"access_token":"opaque-value"}]}"#.as_slice(),
            ),
            (
                "application/json",
                br#"{"session":{"id":"opaque-value"}}"#.as_slice(),
            ),
            ("application/json", br#"{"Password":"opaque-value"}"#.as_slice()),
            (
                "application/json",
                br#"{"auth":{"value":"opaque-value"}}"#.as_slice(),
            ),
            ("application/json", br#"{"items":broken}"#.as_slice()),
            (
                "application/json",
                br#"{"password":"canary-password-947",broken}"#.as_slice(),
            ),
            ("text/plain", b"access_token=canary-access-947".as_slice()),
            ("text/plain", b"CREDENTIAL=canary-credential-947".as_slice()),
            ("text/plain", b"session_id: canary-session-947".as_slice()),
            ("text/plain", b"{malformed csrf=canary-csrf-947".as_slice()),
            (
                "text/html",
                br#"<input name="password" value="opaque-value">"#.as_slice(),
            ),
            (
                "text/html",
                br#"<form><input type="hidden" NAME="csrf" value="canary-csrf-947"></form>"#.as_slice(),
            ),
            (
                "text/html",
                br#"<script>window.access_token = "canary-access-947";</script>"#.as_slice(),
            ),
            (
                "text/html",
                br#"<input name="credential" value="canary-credential-947">"#.as_slice(),
            ),
            ("text/plain", b"Authorization: Bearer opaque-value".as_slice()),
            (
                "text/plain",
                // Synthetic detector canary, assembled from parts.
                concat!("api_key=sk_", "live_abcdefghijklmnopqrstuvwx").as_bytes(),
            ),
            ("text/plain", &[0xff, 0xfe]),
            ("application/octet-stream", b"looks printable".as_slice()),
        ] {
            assert!(sink.store(content_type, body, false).await.unwrap().is_none());
        }
        let oversized = vec![b'x'; 1024 * 1024 + 1];
        assert!(sink
            .store("text/plain", &oversized, false)
            .await
            .unwrap()
            .is_none());
        let zdr = retained_sink(&store, RetentionMode::Zdr, RequestControls::default());
        assert!(zdr
            .store("text/plain", b"ordinary content", false)
            .await
            .unwrap()
            .is_none());
        assert!(store.bodies.lock().is_empty());
    }

    #[tokio::test]
    async fn full_body_sink_refuses_request_control_secret_echoes() {
        let store = Arc::new(CapturedArtifacts::default());
        let mut fetch = crawlx_core::config::Fetch::default();
        fetch.extra_headers.insert("x-api-key", "opaque-credential-947");
        let controls = RequestControls::resolve(&fetch, "example.test", None)
            .await
            .unwrap();
        let sink = retained_sink(&store, RetentionMode::Extended, controls);
        assert!(sink
            .store("text/plain", b"echo opaque-credential-947", false)
            .await
            .unwrap()
            .is_none());
        assert!(sink
            .store("application/json", br#"{"value":"opaque-credential-947"}"#, false)
            .await
            .unwrap()
            .is_none());
        assert!(store.bodies.lock().is_empty());
    }

    #[tokio::test]
    async fn text_capped_sink_refuses_incomplete_json_with_escaped_sensitive_fields() {
        let store = Arc::new(CapturedArtifacts::default());
        let sink = retained_sink(&store, RetentionMode::Standard, RequestControls::default());
        let result = sink
            .store(
                "application/json",
                br#"{"pass\u0077ord":"partial-unknown-canary"#,
                true,
            )
            .await
            .unwrap();
        assert!(result.is_none());
        assert!(store.bodies.lock().is_empty());
    }

    #[tokio::test]
    async fn retained_body_sink_refuses_json_escaped_request_control_secrets() {
        let store = Arc::new(CapturedArtifacts::default());
        let mut fetch = crawlx_core::config::Fetch::default();
        fetch.extra_headers.insert("x-short-control", "Q7z9");
        let controls = RequestControls::resolve(&fetch, "example.test", None)
            .await
            .unwrap();
        let sink = retained_sink(&store, RetentionMode::Standard, controls);
        for truncated in [false, true] {
            let result = sink
                .store("application/json", br#"{"data":"\u00517z9"}"#, truncated)
                .await
                .unwrap();
            assert!(result.is_none());
            assert!(store.bodies.lock().is_empty());
        }
    }

    #[tokio::test]
    async fn retained_body_sink_refuses_json_escaped_scoped_captcha_secrets() {
        let store = Arc::new(CapturedArtifacts::default());
        let secrets = CaptchaSecrets::default();
        let sink = RetainedBodySink::new(
            CrawlRunId::new(),
            Arc::clone(&store) as Arc<dyn ArtifactStore>,
            RequestControls::default(),
            RetentionMode::Standard,
            [7; 32],
            secrets.clone(),
        );
        secrets
            .register(crawlx_core::secret::SecretOr::secret(
                "scoped-capture-canary-q7m2".to_owned(),
            ))
            .unwrap();
        for truncated in [false, true] {
            let result = sink
                .store(
                    "application/json",
                    br#"{"data":"scoped-\u0063apture-canary-q7m2"}"#,
                    truncated,
                )
                .await
                .unwrap();
            assert!(result.is_none());
            assert!(store.bodies.lock().is_empty());
        }
    }

    #[tokio::test]
    async fn retained_body_sink_never_publishes_duplicate_json_members() {
        let store = Arc::new(CapturedArtifacts::default());
        let sink = retained_sink(&store, RetentionMode::Standard, RequestControls::default());
        for truncated in [false, true] {
            let result = sink
                .store(
                    "application/json",
                    br#"{"data":"hidden","d\u0061ta":"public"}"#,
                    truncated,
                )
                .await;
            assert!(matches!(result, Ok(None) | Err(StoreError::RetentionDenied(_))));
            assert!(store.bodies.lock().is_empty());
        }
    }

    #[tokio::test]
    async fn proxy_capture_masks_registered_tokens_in_url_and_headers() {
        let backend = FakeBackend::new(FakeScript::new().page(FakePage::new("https://example.test/")));
        let session = SessionId::new();
        let raw = backend.new_context(ContextConfig::new(session)).await.unwrap();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        let capture = ProxyCapture::new(ProxyTraffic::new(rx, Redactor::new([1; 32])));
        let secrets = CaptchaSecrets::default();
        secrets
            .register(crawlx_core::secret::SecretOr::secret(
                "solver-value-947".to_owned(),
            ))
            .unwrap();
        let clock: Arc<dyn Clock> = Arc::new(crawlx_core::time::ManualClock::new(
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        ));
        let mut ctx = wrap_proxy(&capture, session, Arc::clone(&clock), raw, secrets);
        ctx.navigate(&seed()).await.unwrap();
        let mut raw_flow = flow("https://example.test/solver-value-947", clock.now());
        raw_flow
            .response_headers
            .push(("x-result".to_owned(), "solver-value-947".to_owned()));
        tx.try_send(raw_flow).unwrap();
        let events = ctx.drain_traffic();
        let proxy = events
            .iter()
            .find(|event| {
                event
                    .response_headers
                    .iter()
                    .any(|(name, value)| name == "x-crawlx-capture-source" && value == "proxy")
            })
            .unwrap();
        assert!(!proxy.url.contains("solver-value-947"));
        assert!(!proxy
            .response_headers
            .iter()
            .any(|(_, value)| value.contains("solver-value-947")));
        assert_eq!(events.iter().map(|event| event.seq).collect::<Vec<_>>(), [1, 2]);
    }

    #[tokio::test]
    async fn shared_proxy_source_keeps_each_context_sequence_contiguous_across_drains() {
        let backend = FakeBackend::new(FakeScript::new().page(FakePage::new("https://example.test/")));
        let (_tx, rx) = tokio::sync::mpsc::channel(8);
        let capture = ProxyCapture::new(ProxyTraffic::new(rx, Redactor::new([1; 32])));
        let clock: Arc<dyn Clock> = Arc::new(crawlx_core::time::ManualClock::new(
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        ));
        let mut contexts = Vec::new();
        for _ in 0..2 {
            let session = SessionId::new();
            let raw = backend.new_context(ContextConfig::new(session)).await.unwrap();
            contexts.push(wrap_proxy(
                &capture,
                session,
                Arc::clone(&clock),
                raw,
                CaptchaSecrets::default(),
            ));
        }
        for context in &mut contexts {
            context.navigate(&seed()).await.unwrap();
            let events = context.drain_traffic();
            assert_eq!(events.iter().map(|event| event.seq).collect::<Vec<_>>(), [1]);
        }
        contexts[0].navigate(&seed()).await.unwrap();
        let events = contexts[0].drain_traffic();
        assert_eq!(events.iter().map(|event| event.seq).collect::<Vec<_>>(), [2]);
    }

    #[tokio::test]
    async fn text_capped_sink_accepts_incomplete_public_json_but_never_exceeds_64k() {
        let store = Arc::new(CapturedArtifacts::default());
        let sink = retained_sink(&store, RetentionMode::Standard, RequestControls::default());
        let mut prefix = br#"{"value":""#.to_vec();
        prefix.resize(64 * 1024, b'x');
        let artifact = sink
            .store("application/json", &prefix, true)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(store.get(&artifact).await.unwrap(), prefix);
        let too_large = vec![b'x'; 64 * 1024 + 1];
        assert!(sink.store("text/html", &too_large, true).await.unwrap().is_none());
        assert_eq!(store.bodies.lock().len(), 1);
    }

    #[tokio::test]
    async fn text_capped_sink_refuses_sensitive_prefixes_binary_and_zdr() {
        let store = Arc::new(CapturedArtifacts::default());
        let sink = retained_sink(&store, RetentionMode::Standard, RequestControls::default());
        for (content_type, body) in [
            (
                "application/json",
                br#"{"password":"canary-password-947"#.as_slice(),
            ),
            ("text/html", b"access_token=canary-access-947".as_slice()),
            (
                "text/html",
                br#"<input name="csrf" value="canary-csrf-947"#.as_slice(),
            ),
            ("text/html", &[0xff, 0xfe]),
            ("text/plain", b"ordinary public text".as_slice()),
        ] {
            assert!(sink.store(content_type, body, true).await.unwrap().is_none());
        }
        let zdr = retained_sink(&store, RetentionMode::Zdr, RequestControls::default());
        assert!(zdr
            .store("text/html", b"public content", true)
            .await
            .unwrap()
            .is_none());
        assert!(store.bodies.lock().is_empty());
    }

    #[tokio::test]
    async fn retained_body_sink_refuses_secret_registered_during_backend_upload() {
        const BODY: &[u8] = b"lateScopedCommitCanary528";
        let clock: Arc<dyn Clock> = Arc::new(crawlx_core::time::ManualClock::new(
            chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
        ));
        let runs = Arc::new(crawlx_storage::MemoryStore::with_clock(clock.clone()));
        let run = crawlx_storage::testkit::crawl_run(
            crawlx_core::TenantId::new(),
            crawlx_storage::testkit::create_crawl("https://example.test/", &[], 1),
        );
        crawlx_core::repo::RunRepo::create(runs.as_ref(), &run, None)
            .await
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let custody: Arc<dyn crawlx_storage::ArtifactCustody> =
            Arc::new(crawlx_storage::LocalArtifactCustody::new());
        let keys: Arc<dyn crawlx_storage::artifact_key_crypto::ArtifactKeys> =
            Arc::new(crawlx_storage::artifact_key_crypto::MemoryArtifactKeys::new().unwrap());
        let artifacts = Arc::new(
            ObjectArtifactStore::new(
                PausedFsBlobs {
                    inner: FsBlobs::open(dir.path()).await.unwrap(),
                    entered: tokio::sync::Semaphore::new(0),
                    release: tokio::sync::Semaphore::new(0),
                    received: Mutex::new(None),
                },
                runs,
                clock,
            )
            .with_custody(
                Arc::clone(&custody),
                keys,
                crawlx_storage::CustodyWrites::Required,
            ),
        );
        let store: Arc<dyn ArtifactStore> = artifacts.clone();
        let secrets = CaptchaSecrets::default();
        let sink = RetainedBodySink::new(
            run.id,
            store,
            RequestControls::default(),
            RetentionMode::Standard,
            [7; 32],
            secrets.clone(),
        );
        let lease = crawlx_core::custody::CustodyLease::new(
            run.tenant,
            run.id,
            SessionId::new(),
            crawlx_core::WorkerId::new(),
            1,
        );
        // The same registrar a worker installs on the session's browser context.
        let registrar = crawlx_storage::LeasedSecretRegistrar::new(custody, lease.clone(), secrets.clone());
        let pending =
            crawlx_core::custody::with_producer(lease, async { sink.store("text/plain", BODY, false).await });
        tokio::pin!(pending);
        tokio::select! {
            result = &mut pending => panic!("capture completed before the backend barrier: {result:?}"),
            entered = artifacts.blobs().entered.acquire() => entered.unwrap().forget(),
        }
        assert!(!secrets.has_values().unwrap());
        // The backend only ever receives ciphertext: the plaintext object is never written.
        let staged = artifacts.blobs().received.lock().clone().unwrap();
        assert_ne!(staged.as_slice(), BODY);
        assert!(
            !staged.windows(BODY.len()).any(|window| window == BODY),
            "the staged object must not contain the plaintext"
        );
        assert!(artifacts.blobs().inner.list("").await.unwrap().is_empty());
        crawlx_core::custody::SecretRegistrar::register(
            &registrar,
            &crawlx_core::secret::SecretOr::secret(std::str::from_utf8(BODY).unwrap().to_owned()),
        )
        .await
        .unwrap();
        assert!(
            secrets.has_values().unwrap(),
            "the local mirror follows the registration"
        );
        artifacts.blobs().release.add_permits(1);
        let result = pending.await;
        assert!(
            matches!(result, Ok(None) | Err(StoreError::RetentionDenied(_))),
            "publication must refuse bytes that became secret during the upload: {result:?}"
        );
        let durable = artifacts.blobs().inner.list("").await.unwrap();
        assert!(
            durable.is_empty(),
            "a rejected capture must leave no durable objects or catalog rows"
        );
    }

    #[tokio::test]
    async fn retained_body_sink_refuses_scoped_secrets_introduced_by_redaction() {
        assert!(crawlx_core::secret::register_secret("origCanary962"));
        let store = Arc::new(CapturedArtifacts::default());
        let secrets = CaptchaSecrets::default();
        secrets
            .register(crawlx_core::secret::SecretOr::secret("AA[REDACTED]BB".to_owned()))
            .unwrap();
        let sink = RetainedBodySink::new(
            CrawlRunId::new(),
            Arc::clone(&store) as Arc<dyn ArtifactStore>,
            RequestControls::default(),
            RetentionMode::Standard,
            [7; 32],
            secrets,
        );
        let result = sink
            .store("text/plain", b"AAorigCanary962BB", false)
            .await
            .unwrap();
        assert!(result.is_none());
        assert!(store.bodies.lock().is_empty());
    }

    #[tokio::test]
    async fn retained_body_sink_reads_dynamic_captcha_registry_before_storage() {
        let store = Arc::new(CapturedArtifacts::default());
        let secrets = CaptchaSecrets::default();
        let sink = RetainedBodySink::new(
            CrawlRunId::new(),
            Arc::clone(&store) as Arc<dyn ArtifactStore>,
            RequestControls::default(),
            RetentionMode::Standard,
            [7; 32],
            secrets.clone(),
        );
        secrets
            .register(crawlx_core::secret::SecretOr::secret(
                "opaque-solver-947".to_owned(),
            ))
            .unwrap();
        assert!(sink
            .store("text/html", b"echo opaque-solver-947", true)
            .await
            .unwrap()
            .is_none());
        assert!(store.bodies.lock().is_empty());
    }

    #[tokio::test]
    async fn static_full_capture_uses_existing_fetch_limit_instead_of_browser_limit() {
        let store = Arc::new(CapturedArtifacts::default());
        let sink = retained_sink(&store, RetentionMode::Standard, RequestControls::default())
            .with_body_limit(2 * 1024 * 1024);
        let body = vec![b'x'; 1024 * 1024 + 1];
        let artifact = sink.store("text/plain", &body, false).await.unwrap().unwrap();
        assert_eq!(store.get(&artifact).await.unwrap(), body);
    }
}
