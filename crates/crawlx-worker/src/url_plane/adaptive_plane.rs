//! Adaptive crawl behavior of the URL plane: render prediction with a paid, recorded probe, the
//! query-driven stop policy, and typed hops with queue cost.
//!
//! None of it grants anything. A probe only asks the browser plane to look at a page the plane
//! already fetched; a hop kind only describes how a URL was reached and bounds how long a chain
//! of hops may grow; a queue cost only orders the queue. Every discovered URL, whatever its
//! kind, still passes scope, robots, authorization, the budget and the origin governor.
//!
//! Every decision is deterministic under the run seed and is written to the run's event log, so a
//! replay of the run recomputes and verifies it instead of drawing again.

use super::*;
use crawlx_core::adaptive::AdaptiveStopReason;
use crawlx_core::request::hops::{HopDenialV1, HopKindV1, HopPathV1};
use crawlx_core::request::RequestEnvelopeV1;
use crawlx_strategies::adaptive_render::{
    PredictorRecordV1, ProbeCharge, ProbeDenial, ProbeLedger, RenderPredictor, RenderVerdict,
};
use crawlx_strategies::adaptive_stop::{AdaptiveStop, Observation};

/// Event kind of one recorded render-predictor decision.
const PREDICTOR_EVENT: &str = "dynamic.predictor";
/// Event kind of one evaluated page of the adaptive stop policy.
const OBSERVED_EVENT: &str = "adaptive.observed";
/// Event kind of a full export of the adaptive stop state.
const EXPORT_EVENT: &str = "adaptive.export";
/// Event kind written when the adaptive stop policy ends the crawl.
const STOPPED_EVENT: &str = "adaptive.stopped";
/// Pages between two exports of the adaptive stop state (it is also exported at every stop).
const EXPORT_EVERY_PAGES: u32 = 16;

/// Where a hop starts from: the page that named the target.
pub(super) struct HopContext<'a> {
    /// Row of the page, when it has one.
    pub(super) from: Option<i64>,
    /// Depth the target is queued at.
    pub(super) depth: u16,
    /// The hops that led to the page.
    pub(super) parent_path: &'a HopPathV1,
}

/// The embeds and prerequisites one page names.
#[derive(Default)]
pub(super) struct PageHops {
    /// The ones `scope.hops` follows, in document order and without repeats.
    pub(super) followed: Vec<(Url, HopKindV1)>,
    /// Every embed and prerequisite the document names, followed or not, by URL.
    kinds: BTreeMap<String, HopKindV1>,
}

impl PageHops {
    /// The kind of hop an endpoint found at `url` through `source` is: the kind the document's own
    /// tree gives that URL, else the kind of the construct that named it. Endpoint discovery finds
    /// the same iframes, scripts, stylesheets and images as the typed hops; it must not follow as a
    /// link what the hop policy declines as an embed or a prerequisite.
    pub(super) fn kind_of(&self, url: &Url, source: crawlx_extract::endpoints::EndpointSource) -> HopKindV1 {
        self.kinds
            .get(url.as_str())
            .copied()
            .unwrap_or_else(|| endpoint_hop_kind(source))
    }
}

/// The hop kind of a construct that names an endpoint. A `link` element could be a stylesheet or
/// a plain relation; the document's tree decides that case ([`PageHops::kind_of`]), so it is a
/// link here.
fn endpoint_hop_kind(source: crawlx_extract::endpoints::EndpointSource) -> HopKindV1 {
    match (source.tag, source.attribute) {
        ("script", "src") | ("svg", "script-href") => HopKindV1::Prerequisite,
        (
            "iframe" | "frame" | "embed" | "input-image" | "img" | "audio" | "video" | "source" | "track"
            | "object" | "applet" | "body" | "table" | "svg",
            attribute,
        ) if attribute != "srcdoc" => HopKindV1::Embed,
        _ => HopKindV1::Link,
    }
}

/// State of the adaptive policies of one plane.
#[derive(Default)]
pub(super) struct AdaptivePlane {
    predictor: Option<RenderPredictor>,
    /// Probes paid for, by row.
    probes: Mutex<ProbeLedger>,
    /// Recorded decisions by row, loaded at start and appended as they are made.
    decisions: Mutex<BTreeMap<i64, PredictorRecordV1>>,
    /// Outcome of paying for the probe of the attempt in flight, by row.
    charges: Mutex<BTreeMap<i64, ProbeCharge>>,
    stop: Mutex<Option<AdaptiveStop>>,
    /// Pages kept per host, for the queue cost success rule.
    hosts: Mutex<BTreeMap<String, u32>>,
}

impl AdaptivePlane {
    /// The adaptive state `crawl` asks for; nothing when it asks for none.
    ///
    /// # Errors
    /// An invalid stop policy.
    pub(super) fn new(crawl: &CreateCrawl) -> Result<Self, WorkerError> {
        let adaptive = crawl.dynamic.adaptive.clone();
        let max_probes = adaptive.as_ref().map_or(0, |config| config.max_probes);
        let predictor = adaptive.map(|config| RenderPredictor::new(crawl.effective_seed(), config));
        let stop = crawl
            .adaptive
            .clone()
            .map(AdaptiveStop::new)
            .transpose()
            .map_err(|error| WorkerError::Config(error.to_string()))?;
        Ok(Self {
            predictor,
            probes: Mutex::new(ProbeLedger::new(max_probes)),
            stop: Mutex::new(stop),
            ..Self::default()
        })
    }

    /// Whether any page text must be kept for the stop policy.
    pub(super) fn observes(&self) -> bool {
        self.stop.lock().is_some()
    }

    /// Drop the probe a refunded attempt had paid for.
    pub(super) fn release_probe(&self, row: i64) {
        self.probes.lock().refund(row);
        self.charges.lock().remove(&row);
    }

    /// Count a kept page against its host.
    pub(super) fn record_success(&self, host: &str) {
        let mut hosts = self.hosts.lock();
        let count = hosts.entry(host.to_owned()).or_insert(0);
        *count = count.saturating_add(1);
    }

    fn host_successes(&self, host: &str) -> u32 {
        self.hosts.lock().get(host).copied().unwrap_or(0)
    }

    /// Most rows one lease may take without overshooting the stop policy's page limit.
    pub(super) fn lease_cap(&self) -> u32 {
        self.stop
            .lock()
            .as_ref()
            .map_or(u32::MAX, |stop| stop.pages_left().max(1))
    }

    /// The reason the stop policy has ended the crawl, if it has.
    pub(super) fn stopped(&self) -> Option<(AdaptiveStopReason, u32, u16)> {
        let guard = self.stop.lock();
        let stop = guard.as_ref()?;
        stop.stopped()
            .map(|reason| (reason, stop.pages(), stop.confidence_permille()))
    }
}

impl UrlPlaneRunner {
    // ---- render prediction (probe) --------------------------------------------------------

    /// Effects to add to this attempt's reservation so that a selected probe is paid for before
    /// the page is fetched; `0` when the page is not probed, the probe is already paid for, or
    /// the run's probe allowance is spent. Records the outcome the plane reads after
    /// classification.
    pub(super) fn plan_probe(&self, entry: &FrontierEntry, applicable: bool) -> u32 {
        let (Some(predictor), true) = (&self.adaptive.predictor, applicable) else {
            return 0;
        };
        if !predictor.draw(&entry.url.key.0).selected {
            return 0;
        }
        let probes = self.adaptive.probes.lock();
        if probes.paid(entry.id) {
            // a retried row keeps the probe it already paid for
            self.adaptive
                .charges
                .lock()
                .insert(entry.id, ProbeCharge::Charged);
            return 0;
        }
        if !probes.has_room(entry.id) {
            self.adaptive
                .charges
                .lock()
                .insert(entry.id, ProbeCharge::Denied(ProbeDenial::ProbeAllowance));
            return 0;
        }
        predictor.config().probe_effects
    }

    /// Whether a page of `entry` is classified by the native static path, so a probe's browser
    /// look is meaningful: hybrid mode, a native fetch (not a scrape job, a protocol route or a
    /// cache replay) of a page rather than a discovery-only or `HEAD` row.
    pub(super) fn probe_applicable(
        &self,
        entry: &FrontierEntry,
        method_head: bool,
        discovery_only: bool,
    ) -> bool {
        self.adaptive.predictor.is_some()
            && !method_head
            && !discovery_only
            && self.scrape.is_none()
            && !self.crawl.cache_only()
            && self.crawl.mode == CrawlMode::Hybrid
            && crate::protocol::select_route(&self.protocol_routes, &entry.url.url).is_none()
    }

    /// Record whether the effect reservation that included a probe went through.
    pub(super) fn settle_probe(&self, row: i64, paid: bool) {
        if paid {
            self.adaptive.probes.lock().charge(row);
            self.adaptive.charges.lock().insert(row, ProbeCharge::Charged);
        } else {
            self.adaptive
                .charges
                .lock()
                .insert(row, ProbeCharge::Denied(ProbeDenial::EffectBudget));
        }
    }

    /// Decide what the browser plane sees of a fetched page, record the decision, and return the
    /// dynamic signal to store with the page: the heuristic's own for a page it flagged, the
    /// probe's for a static page the seeded draw selected and the effect budget paid for.
    ///
    /// # Errors
    /// A recorded draw this seed cannot reproduce, or an event log that refuses the record.
    pub(super) async fn decide_render(
        &self,
        entry: &FrontierEntry,
        heuristic: Option<DynamicSignal>,
    ) -> Result<(Option<DynamicSignal>, Option<PredictorRecordV1>), WorkerError> {
        let Some(predictor) = &self.adaptive.predictor else {
            return Ok((heuristic, None));
        };
        let recorded = self.adaptive.decisions.lock().get(&entry.id).cloned();
        let draw = match &recorded {
            Some(record) => predictor
                .replay(record, &entry.url.key.0)
                .map_err(|error| WorkerError::Config(error.to_string()))?,
            None => predictor.draw(&entry.url.key.0),
        };
        let paid = self.adaptive.charges.lock().remove(&entry.id);
        // a replayed decision that paid keeps its payment
        let charge = paid.or_else(|| {
            recorded
                .as_ref()
                .filter(|r| r.charged)
                .map(|_| ProbeCharge::Charged)
        });
        let signal = heuristic.map(DynamicSignal::as_str);
        let verdict = predictor.verdict(&draw, signal, charge);
        let record = RenderPredictor::record(&draw, signal, charge, verdict);
        if recorded.as_ref() != Some(&record) {
            self.deps
                .events
                .append(
                    self.run,
                    PREDICTOR_EVENT,
                    serde_json::json!({ "frontierId": entry.id, "predictor": record }),
                )
                .await?;
            self.adaptive.decisions.lock().insert(entry.id, record.clone());
        }
        let stored = match verdict {
            RenderVerdict::Escalate { .. } => heuristic,
            RenderVerdict::Probe => Some(DynamicSignal::PredictorProbe),
            _ => None,
        };
        Ok((stored, Some(record)))
    }

    // ---- recorded state -------------------------------------------------------------------

    /// Rebuild what an earlier worker of this run recorded: render-predictor decisions (and the
    /// probes they paid for) and the latest export of the adaptive stop state.
    ///
    /// # Errors
    /// A record that cannot be read, or stop state that is not this crawl's.
    pub(super) async fn load_adaptive_state(&self) -> Result<(), WorkerError> {
        if self.adaptive.predictor.is_none() && !self.adaptive.observes() {
            return Ok(());
        }
        let mut cursor = 0;
        let mut latest_export = None;
        loop {
            let page = self.deps.events.list_after(self.run, cursor, 256).await?;
            if page.is_empty() {
                break;
            }
            for event in page {
                cursor = event.seq;
                match event.kind.as_str() {
                    PREDICTOR_EVENT if self.adaptive.predictor.is_some() => {
                        let row = event
                            .payload
                            .get("frontierId")
                            .and_then(serde_json::Value::as_i64);
                        let record = event
                            .payload
                            .get("predictor")
                            .cloned()
                            .map(serde_json::from_value::<PredictorRecordV1>)
                            .transpose()
                            .map_err(|error| StoreError::Serialization(error.to_string()))?;
                        if let (Some(row), Some(record)) = (row, record) {
                            if record.charged {
                                self.adaptive.probes.lock().charge(row);
                            }
                            self.adaptive.decisions.lock().insert(row, record);
                        }
                    }
                    EXPORT_EVENT => latest_export = Some(event.payload),
                    _ => {}
                }
            }
        }
        if let Some(payload) = latest_export {
            let state = serde_json::from_value(payload)
                .map_err(|error| StoreError::Serialization(error.to_string()))?;
            if let Some(stop) = self.adaptive.stop.lock().as_mut() {
                stop.import(&state)
                    .map_err(|error| WorkerError::Config(error.to_string()))?;
            }
        }
        Ok(())
    }

    // ---- query-driven stop ----------------------------------------------------------------

    /// Evaluate the text of a kept page and record the observation. The state is exported every
    /// few pages and whenever the policy stops, so a restart resumes from it.
    ///
    /// # Errors
    /// An event log that refuses the record.
    pub(super) async fn observe_adaptive(
        &self,
        entry: &FrontierEntry,
        text: &str,
    ) -> Result<(), WorkerError> {
        let (observation, export) = {
            let mut guard = self.adaptive.stop.lock();
            let Some(stop) = guard.as_mut() else {
                return Ok(());
            };
            let observation: Observation = stop.observe(text);
            let export = (observation.stop.is_some() || observation.pages.is_multiple_of(EXPORT_EVERY_PAGES))
                .then(|| stop.export());
            (observation, export)
        };
        self.deps
            .events
            .append(
                self.run,
                OBSERVED_EVENT,
                serde_json::json!({
                    "frontierId": entry.id,
                    "relevancePermille": observation.relevance_permille,
                    "noveltyPermille": observation.novelty_permille,
                    "gainPermille": observation.gain_permille,
                    "confidencePermille": observation.confidence_permille,
                    "pages": observation.pages,
                    "stop": observation.stop,
                }),
            )
            .await?;
        if let Some(export) = export {
            self.deps
                .events
                .append(
                    self.run,
                    EXPORT_EVENT,
                    serde_json::to_value(export)
                        .map_err(|error| StoreError::Serialization(error.to_string()))?,
                )
                .await?;
        }
        Ok(())
    }

    /// Export the stop policy's state when this plane stops, so a later run of the same query
    /// can continue from it.
    ///
    /// # Errors
    /// An event log that refuses the record.
    pub(super) async fn export_adaptive_state(&self) -> Result<(), WorkerError> {
        let export = self.adaptive.stop.lock().as_ref().map(AdaptiveStop::export);
        if let Some(export) = export {
            self.deps
                .events
                .append(
                    self.run,
                    EXPORT_EVENT,
                    serde_json::to_value(export)
                        .map_err(|error| StoreError::Serialization(error.to_string()))?,
                )
                .await?;
        }
        Ok(())
    }

    /// The terminal reason when the stop policy has ended the crawl, with a recorded stop event.
    /// The record states that the confidence is an estimate over the fetched pages: no stop
    /// claims that the site was covered exhaustively.
    pub(super) async fn adaptive_stop_check(&self) -> Option<TerminalReason> {
        let (reason, pages, confidence) = self.adaptive.stopped()?;
        self.event(
            STOPPED_EVENT,
            serde_json::json!({
                "reason": reason.as_str(),
                "pages": pages,
                "confidencePermille": confidence,
                "exhaustive": false,
            }),
        )
        .await;
        Some(match reason {
            AdaptiveStopReason::PageLimit => TerminalReason::LimitReached,
            _ => TerminalReason::PolicyStopped,
        })
    }

    // ---- typed hops and queue cost ---------------------------------------------------------

    /// The hop path of the page `entry`, empty for a seed. Read only when a hop or queue cost
    /// policy is configured.
    pub(super) async fn parent_hop_path(&self, entry: &FrontierEntry) -> Result<HopPathV1, WorkerError> {
        if self.crawl.scope.hops.is_none() && self.crawl.scope.queue_cost.is_none() {
            return Ok(HopPathV1::default());
        }
        Ok(self
            .deps
            .frontier
            .get_request(self.run, entry.id)
            .await?
            .envelope
            .hop_path())
    }

    /// Discover `url` as a `kind` hop from `ctx`: the request carries its hop path and, under a
    /// queue cost policy, the explicit priority that orders it. The hop and cost policies decide
    /// nothing else: scope, robots, the budget and dedupe apply exactly as for any link. With no
    /// hop or cost policy this is [`UrlPlaneRunner::discover`].
    pub(super) async fn discover_hop(
        &self,
        ctx: &HopContext<'_>,
        url: CanonicalUrl,
        kind: HopKindV1,
        action_bearing: bool,
        source: RequestSource,
    ) -> Result<DiscoveryOutcome, StoreError> {
        if self.crawl.scope.hops.is_none() && self.crawl.scope.queue_cost.is_none() {
            return self
                .discover(url, ctx.depth, ctx.from, action_bearing, Some(source))
                .await;
        }
        let path = ctx
            .parent_path
            .pushed(kind)
            .unwrap_or_else(|| ctx.parent_path.clone());
        let mut request = RequestEnvelopeV1::get(url.clone(), ctx.depth, ctx.from);
        request.set_hop_path(&path);
        if let Some(policy) = &self.crawl.scope.queue_cost {
            let host = url.url.host_str().unwrap_or("").to_ascii_lowercase();
            let cost = policy.cost(&url.url, &path, self.adaptive.host_successes(&host));
            request.priority = policy.priority(0, cost);
        }
        self.discover_with(
            url,
            ctx.depth,
            ctx.from,
            action_bearing,
            Some(source),
            Some(request),
        )
        .await
    }

    /// The embeds and prerequisites of a page, with the ones `scope.hops` follows in document
    /// order and without repeats. Ordinary links come from the document's own link set; a form
    /// action is only ever a proposal and is never followed.
    pub(super) fn typed_hops(&self, hops: &[crawlx_extract::source_policy::SourceHop]) -> PageHops {
        use crawlx_extract::source_policy::HopKind;
        let policy = self.crawl.scope.hops.as_ref();
        let mut page = PageHops::default();
        let mut seen = BTreeSet::new();
        for hop in hops {
            let kind = match hop.kind {
                HopKind::Embed => HopKindV1::Embed,
                HopKind::Prerequisite => HopKindV1::Prerequisite,
                _ => continue,
            };
            page.kinds.entry(hop.url.as_str().to_owned()).or_insert(kind);
            let followed = policy.is_some_and(|policy| match kind {
                HopKindV1::Embed => policy.follow_embeds,
                _ => policy.follow_prerequisites,
            });
            if followed && seen.insert(hop.url.as_str().to_owned()) {
                page.followed.push((hop.url.clone(), kind));
            }
        }
        page
    }

    /// What `pages.metadata.request.hop` records for a request: its hop path, the kind of its
    /// last hop and its queue priority. `None` when no hop or cost policy is configured.
    pub(super) fn hop_metadata(&self, request: &RequestEnvelopeV1) -> Option<serde_json::Value> {
        if self.crawl.scope.hops.is_none() && self.crawl.scope.queue_cost.is_none() {
            return None;
        }
        let path = request.hop_path();
        let kind = path
            .as_str()
            .chars()
            .next_back()
            .and_then(HopKindV1::from_symbol)
            .map(HopKindV1::as_str);
        Some(serde_json::json!({
            "path": path.as_str(),
            "kind": kind,
            "priority": request.priority,
        }))
    }

    /// Discover a URL a listing names (a sitemap, `robots.txt` or recorded source) at depth 1,
    /// as a link hop from the seed, so it is costed like any other link.
    pub(super) async fn discover_listed(
        &self,
        url: CanonicalUrl,
        action_bearing: bool,
        source: RequestSource,
    ) -> Result<DiscoveryOutcome, StoreError> {
        let seed_path = HopPathV1::default();
        let ctx = HopContext {
            from: None,
            depth: 1,
            parent_path: &seed_path,
        };
        self.discover_hop(&ctx, url, HopKindV1::Link, action_bearing, source)
            .await
    }

    /// The limit a proposed hop breaks, judged from the hop path the proposal carries.
    pub(super) fn hop_denial(&self, proposal: &RequestEnvelopeV1, url: &Url) -> Option<HopDenialV1> {
        let policy = self.crawl.scope.hops.as_ref()?;
        let path = proposal.hop_path();
        let text = path.as_str();
        let (parent, last) = text.split_at(text.len().checked_sub(1)?);
        let kind = last.chars().next().and_then(HopKindV1::from_symbol)?;
        let parent = HopPathV1::try_from(parent.to_owned()).ok()?;
        policy.admit(&parent, kind, url).err()
    }
}
