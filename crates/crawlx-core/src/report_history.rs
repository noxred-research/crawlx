//! Bounded, privacy-safe measured facts and page-scoped report calculations.
//!
//! Facts contain opaque keys and finite enums, never raw URLs, headers or content.
//! Repositories filter before applying the bounded keyset page, and must validate
//! current custody authority on every append. Old missing facts remain unknown.

use crate::custody::{CustodyLease, CustodySource};
use crate::hash::Digest;
use crate::{CrawlRunId, StoreError, TenantId, Timestamp};
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeMap;

/// Maximum facts returned by one history query or percentile sample.
pub const REPORT_PAGE_LIMIT: u32 = 64;

/// Longest error-snapshot code, matching the request disposition code bound.
pub const ERROR_CODE_MAX_BYTES: usize = 128;

/// Longest redacted error-snapshot detail text.
pub const ERROR_DETAIL_MAX_BYTES: usize = 256;

/// A finite, versioned class of report evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ReportKindV1 {
    /// Checked DNS observation.
    Dns,
    /// Measured processor stage.
    Stage,
    /// Independently measured transport counters.
    Wire,
    /// Allowlisted diagnostic.
    Alert,
    /// Counted diagnostic loss.
    Loss,
    /// Durable processing progression.
    Pipeline,
}

impl ReportKindV1 {
    /// Stable database discriminator, matching the serialized payload tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::Stage => "stage",
            Self::Wire => "wire",
            Self::Alert => "alert",
            Self::Loss => "loss",
            Self::Pipeline => "pipeline",
        }
    }
}

/// Checked DNS outcome; missing observations are not successes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DnsOutcomeV1 {
    /// At least one resolver answer was observed; egress admission is separate.
    Resolved,
    /// Resolver reported no answer.
    NotFound,
    /// Resolver deadline expired.
    Timeout,
    /// Resolver refused the query.
    Refused,
    /// Other measured resolver failure.
    Failed,
}

/// Native processing boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProcessorStageV1 {
    /// Request admission.
    Admission,
    /// Representation acquisition.
    Fetch,
    /// Representation parsing.
    Parse,
    /// Item extraction.
    Extract,
    /// Index publication.
    Index,
    /// Durable delivery.
    Delivery,
}

impl ProcessorStageV1 {
    /// Stable label, matching the serialized payload value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Fetch => "fetch",
            Self::Parse => "parse",
            Self::Extract => "extract",
            Self::Index => "index",
            Self::Delivery => "delivery",
        }
    }
}

/// Observed terminal result of one processor attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum StageOutcomeV1 {
    /// Processor completed successfully.
    Succeeded,
    /// Processor failed.
    Failed,
    /// Cancellation interrupted processing.
    Cancelled,
    /// Processing was deliberately skipped.
    Skipped,
}

impl StageOutcomeV1 {
    /// Stable label, matching the serialized payload value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::Skipped => "skipped",
        }
    }
}

/// Finite native processor identity; no arbitrary plugin labels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProcessorIdentityV1 {
    /// Native HTTP transport.
    NativeHttp,
    /// Browser acquisition.
    Browser,
    /// Native representation parser.
    Parser,
    /// Native extraction pipeline.
    Extractor,
    /// Durable item pipeline.
    ItemPipeline,
    /// Durable delivery processor.
    Delivery,
}

/// Allowlisted alert severity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AlertSeverityV1 {
    /// Informational evidence.
    Info,
    /// Degraded operation.
    Warning,
    /// Failed operation.
    Error,
    /// Critical operation failure.
    Critical,
}

impl AlertSeverityV1 {
    /// Stable label, matching the serialized payload value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }
}

/// Privacy-safe alert code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AlertCodeV1 {
    /// DNS resolution failed.
    DnsFailure,
    /// Processing failed.
    ProcessorFailure,
    /// A finite budget was exhausted.
    BudgetExhausted,
    /// Explicit cancellation.
    Cancelled,
    /// Delivery failed.
    DeliveryFailure,
    /// Diagnostics were dropped at a bound.
    ObservationLoss,
}

/// Alert subsystem, never untrusted free text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum AlertContextV1 {
    /// Acquisition boundary.
    Acquisition,
    /// Processing boundary.
    Processing,
    /// Delivery boundary.
    Delivery,
    /// Scheduling boundary.
    Scheduling,
}

/// Durable pipeline checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PipelineStageV1 {
    /// Fetch checkpoint.
    Fetch,
    /// Parse checkpoint.
    Parse,
    /// Index checkpoint.
    Index,
    /// Final delivery/completion checkpoint.
    Completion,
}

impl PipelineStageV1 {
    /// Stable label, matching the serialized payload value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Fetch => "fetch",
            Self::Parse => "parse",
            Self::Index => "index",
            Self::Completion => "completion",
        }
    }
}

/// State of a durable pipeline checkpoint.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum PipelineStateV1 {
    /// No terminal checkpoint yet.
    #[default]
    Pending,
    /// Checkpoint committed successfully.
    Succeeded,
    /// Checkpoint failed.
    Failed,
    /// Checkpoint deliberately skipped.
    Skipped,
}

impl PipelineStateV1 {
    /// Stable label, matching the serialized payload value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

/// Finite payload; all durations are measured monotonic microseconds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ReportDataV1 {
    /// Measured DNS query.
    Dns {
        /// Actual resolver result.
        outcome: DnsOutcomeV1,
        /// Monotonic query duration.
        duration_us: u64,
        /// Checked next lookup time, if known.
        recheck_at: Option<Timestamp>,
    },
    /// Measured processor attempt.
    Stage {
        /// Processing boundary.
        stage: ProcessorStageV1,
        /// Terminal attempt outcome.
        outcome: StageOutcomeV1,
        /// Monotonic elapsed time.
        duration_us: u64,
        /// Actual native processor.
        processor: ProcessorIdentityV1,
        /// Processor schema revision.
        processor_version: u32,
    },
    /// Actual measured wire evidence, not decoded body length.
    Wire {
        /// Observed received bytes, otherwise unknown.
        received_bytes: Option<u64>,
        /// Observed sent bytes, otherwise unknown.
        sent_bytes: Option<u64>,
        /// Observed monotonic transport duration, otherwise unknown.
        duration_us: Option<u64>,
    },
    /// Content-free typed diagnostic.
    Alert {
        /// Severity.
        severity: AlertSeverityV1,
        /// Stable reason.
        code: AlertCodeV1,
        /// Subsystem.
        context: AlertContextV1,
    },
    /// Diagnostics lost due to bounded producer pressure.
    Loss {
        /// Exact counted loss, bounded by signed storage range.
        dropped: u64,
    },
    /// Durable checkpoint; never equivalent to merely enqueued work.
    Pipeline {
        /// Checkpoint.
        stage: PipelineStageV1,
        /// Committed outcome.
        state: PipelineStateV1,
    },
}

impl ReportDataV1 {
    /// Return the payload discriminator without serialization.
    #[must_use]
    pub const fn kind(&self) -> ReportKindV1 {
        match self {
            Self::Dns { .. } => ReportKindV1::Dns,
            Self::Stage { .. } => ReportKindV1::Stage,
            Self::Wire { .. } => ReportKindV1::Wire,
            Self::Alert { .. } => ReportKindV1::Alert,
            Self::Loss { .. } => ReportKindV1::Loss,
            Self::Pipeline { .. } => ReportKindV1::Pipeline,
        }
    }

    /// Return measured duration, preserving unknown observations.
    #[must_use]
    pub const fn duration_us(&self) -> Option<u64> {
        match self {
            Self::Dns { duration_us, .. } | Self::Stage { duration_us, .. } => Some(*duration_us),
            Self::Wire { duration_us, .. } => *duration_us,
            _ => None,
        }
    }

    /// Return measured response wire bytes, never sent or decoded body bytes.
    #[must_use]
    pub const fn wire_bytes(&self) -> Option<u64> {
        match self {
            Self::Wire { received_bytes, .. } => *received_bytes,
            _ => None,
        }
    }

    /// Finite outcome label of a terminal or checkpoint fact, `kind:stage:state`. Facts that do
    /// not state an outcome (DNS, wire, loss) have none. Report counters group by this label.
    #[must_use]
    pub fn outcome_label(&self) -> Option<String> {
        match self {
            Self::Pipeline { stage, state } => {
                Some(format!("pipeline:{}:{}", stage.as_str(), state.as_str()))
            }
            Self::Stage { stage, outcome, .. } => {
                Some(format!("stage:{}:{}", stage.as_str(), outcome.as_str()))
            }
            Self::Alert { severity, .. } => Some(format!("alert:{}", severity.as_str())),
            Self::Dns { .. } | Self::Wire { .. } | Self::Loss { .. } => None,
        }
    }
}

/// Opaque privacy-safe identity of a host as facts and reports show it: the digest every
/// producer stores in `hostKey` and every report row and `hostKey` filter uses, so one value
/// joins them. A trailing root dot does not change it; callers pass the URL's already
/// lowercased host.
#[must_use]
pub fn report_host_key(host: &str) -> Digest {
    Digest::of("crawlx:report:dns-host:v1", host.trim_end_matches('.').as_bytes())
}

/// Opaque privacy-safe identity of a request route (the route label a request carries), as
/// facts and counters show it. The label itself never leaves the frontier row.
#[must_use]
pub fn report_route_key(route: &str) -> Digest {
    Digest::of("crawlx:report:route:v1", route.as_bytes())
}

/// Retention-bounded, redacted description of one failed attempt.
///
/// It lives inside the alert fact it explains, so it shares that fact's deadline (the owning
/// run's retention) and disappears with it. The code is a bounded identifier; the optional
/// detail is free text that has been redacted, stripped of URLs and control characters and
/// cut to [`ERROR_DETAIL_MAX_BYTES`]. No constructor or repository keeps unredacted text.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ErrorSnapshotV1 {
    /// Processing boundary that failed, when it is known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stage: Option<ProcessorStageV1>,
    /// Bounded reason code: ASCII letters, digits, `_`, `-` and `:`.
    pub code: String,
    /// Final HTTP status when the attempt reached the network.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    /// Redacted diagnostic text, never a URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ErrorSnapshotV1 {
    /// Build a snapshot, redacting `detail`.
    ///
    /// # Errors
    /// Returns [`StoreError::Serialization`] for an empty, oversized or non-identifier code or
    /// an HTTP status outside 100..=599.
    pub fn new(
        stage: Option<ProcessorStageV1>,
        code: &str,
        http_status: Option<u16>,
        detail: Option<&str>,
    ) -> Result<Self, StoreError> {
        let snapshot = Self {
            stage,
            code: code.to_owned(),
            http_status,
            detail: detail.map(sanitize_detail).filter(|text| !text.is_empty()),
        };
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Check code, status and detail bounds.
    ///
    /// # Errors
    /// Returns [`StoreError::Serialization`] for malformed evidence.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.code.is_empty()
            || self.code.len() > ERROR_CODE_MAX_BYTES
            || !self
                .code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':'))
        {
            return Err(invalid(
                "error snapshot code is empty, oversized or not an identifier",
            ));
        }
        if !crate::secret::Redactor::default().is_clean_text(&self.code) {
            return Err(invalid("error snapshot code looks like a credential"));
        }
        if self
            .http_status
            .is_some_and(|status| !(100..=599).contains(&status))
        {
            return Err(invalid("error snapshot status outside 100..=599"));
        }
        if self
            .detail
            .as_deref()
            .is_some_and(|text| text.len() > ERROR_DETAIL_MAX_BYTES || text.chars().any(char::is_control))
        {
            return Err(invalid(
                "error snapshot detail is oversized or has control characters",
            ));
        }
        Ok(())
    }

    /// The snapshot with its code and detail passed through the redactor again, or the same
    /// value when nothing changes. Repositories apply this before they persist or serve a fact.
    /// A code that looks like a credential is replaced by `redacted`.
    #[must_use]
    pub fn redacted(&self) -> Cow<'_, Self> {
        let code_clean = crate::secret::Redactor::default().is_clean_text(&self.code);
        let detail = self.detail.as_deref().map(sanitize_detail);
        if code_clean && detail == self.detail {
            return Cow::Borrowed(self);
        }
        Cow::Owned(Self {
            code: if code_clean {
                self.code.clone()
            } else {
                "redacted".to_owned()
            },
            detail: detail.filter(|text| !text.is_empty()),
            ..self.clone()
        })
    }
}

/// Redact, strip URLs and control characters and bound free diagnostic text.
fn sanitize_detail(text: &str) -> String {
    let redacted = crate::secret::Redactor::default().redact_text(text).into_inner();
    let mut clean = String::with_capacity(redacted.len().min(ERROR_DETAIL_MAX_BYTES));
    for word in redacted.split_whitespace() {
        if !clean.is_empty() {
            clean.push(' ');
        }
        // A URL carries host, path and query values no pattern can all recognise.
        clean.push_str(if word.contains("://") { "[url]" } else { word });
    }
    clean.retain(|c| !c.is_control());
    while clean.len() > ERROR_DETAIL_MAX_BYTES {
        clean.pop();
    }
    clean
}

/// Committed outcome counters of one route within one run, read from retained facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RouteCountersV1 {
    /// Opaque route identity, see [`report_route_key`].
    pub route_key: Digest,
    /// Number of retained facts per [`ReportDataV1::outcome_label`].
    pub outcomes: BTreeMap<String, u64>,
}

impl RouteCountersV1 {
    /// Empty counters of one route.
    #[must_use]
    pub const fn new(route_key: Digest) -> Self {
        Self {
            route_key,
            outcomes: BTreeMap::new(),
        }
    }

    /// Count of one outcome label; zero when none was recorded.
    #[must_use]
    pub fn count(&self, label: &str) -> u64 {
        self.outcomes.get(label).copied().unwrap_or(0)
    }

    /// Terminal results committed on this route: one fetch checkpoint per committed attempt.
    #[must_use]
    pub fn committed(&self) -> u64 {
        self.outcomes
            .iter()
            .filter(|(label, _)| label.starts_with("pipeline:fetch:"))
            .map(|(_, count)| *count)
            .fold(0, u64::saturating_add)
    }
}

/// Fenced fact; scope always comes from an authenticated producer lease.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ReportFactV1 {
    /// Schema revision, exactly one.
    pub version: u16,
    /// Stable idempotency identity.
    pub id: Digest,
    /// Owning tenant.
    pub tenant: TenantId,
    /// Owning run.
    pub run: CrawlRunId,
    /// Actual existing ownership row.
    pub source: CustodySource,
    /// Positive producer fence.
    pub fence: i64,
    /// Injected nonnegative UTC observation time.
    pub at: Timestamp,
    /// Existing positive frontier identifier, when available.
    pub request_id: Option<i64>,
    /// Opaque privacy-safe URL identity.
    pub url_key: Option<Digest>,
    /// Opaque privacy-safe host identity.
    pub host_key: Option<Digest>,
    /// Opaque privacy-safe route identity of the request, see [`report_route_key`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub route_key: Option<Digest>,
    /// Redacted failure snapshot; allowed on alert facts only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ErrorSnapshotV1>,
    /// One-based attempt ordinal.
    pub attempt: u16,
    /// Bounded measured evidence.
    pub data: ReportDataV1,
}

impl ReportFactV1 {
    /// Construct first-attempt evidence under the producer's exact scope.
    #[must_use]
    pub fn new(lease: &CustodyLease, id: Digest, at: Timestamp, data: ReportDataV1) -> Self {
        Self {
            version: 1,
            id,
            tenant: lease.tenant,
            run: lease.run,
            source: lease.source,
            fence: lease.fence,
            at,
            request_id: None,
            url_key: None,
            host_key: None,
            route_key: None,
            error: None,
            attempt: 1,
            data,
        }
    }

    /// Check schema, numeric storage bounds and timestamp ordering.
    ///
    /// # Errors
    /// Returns [`StoreError::Serialization`] for malformed finite evidence.
    pub fn validate(&self) -> Result<(), StoreError> {
        if self.version != 1 || self.fence <= 0 || self.attempt == 0 {
            return Err(invalid("invalid report version, fence or attempt"));
        }
        valid_time(self.at)?;
        if self.request_id.is_some_and(|id| id <= 0)
            || matches!(self.source, CustodySource::Url(id) if id <= 0)
        {
            return Err(invalid("report request identifier must be positive"));
        }
        match &self.data {
            ReportDataV1::Dns {
                duration_us,
                recheck_at,
                ..
            } => {
                signed(*duration_us)?;
                if let Some(recheck) = recheck_at {
                    valid_time(*recheck)?;
                    if *recheck < self.at {
                        return Err(invalid("dns recheck precedes observation"));
                    }
                }
            }
            ReportDataV1::Stage {
                duration_us,
                processor_version,
                ..
            } => {
                signed(*duration_us)?;
                if *processor_version == 0 {
                    return Err(invalid("processor version must be positive"));
                }
            }
            ReportDataV1::Wire {
                received_bytes,
                sent_bytes,
                duration_us,
            } => {
                for value in [received_bytes, sent_bytes, duration_us].into_iter().flatten() {
                    signed(*value)?;
                }
            }
            ReportDataV1::Loss { dropped } => signed(*dropped)?,
            ReportDataV1::Alert { .. } | ReportDataV1::Pipeline { .. } => {}
        }
        if let Some(error) = &self.error {
            if !matches!(self.data, ReportDataV1::Alert { .. }) {
                return Err(invalid("error snapshot requires an alert fact"));
            }
            error.validate()?;
        }
        Ok(())
    }

    /// Check descriptor binding only; storage must still validate live authority.
    ///
    /// # Errors
    /// Returns [`StoreError::LeaseLost`] for mismatched or locally cancelled scope.
    pub fn validate_lease(&self, lease: &CustodyLease) -> Result<(), StoreError> {
        lease.check_local_cancellation()?;
        if self.tenant != lease.tenant
            || self.run != lease.run
            || self.source != lease.source
            || self.fence != lease.fence
        {
            return Err(StoreError::LeaseLost);
        }
        Ok(())
    }

    /// The fact with its failure snapshot redacted again, or the same fact when nothing
    /// changes. Repositories apply this before they persist or serve a fact, so a producer
    /// that skipped redaction still cannot store unredacted text.
    #[must_use]
    pub fn redacted(&self) -> Cow<'_, Self> {
        match self.error.as_ref().map(ErrorSnapshotV1::redacted) {
            Some(Cow::Owned(error)) => Cow::Owned(Self {
                error: Some(error),
                ..self.clone()
            }),
            _ => Cow::Borrowed(self),
        }
    }
}

/// Bounded filter applied before repository keyset pagination.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
#[non_exhaustive]
pub struct ReportQueryV1 {
    /// Exclusive sequence cursor; zero starts history.
    pub after: u64,
    /// Page size in 1..=64.
    pub limit: u32,
    /// Optional fact class.
    pub kind: Option<ReportKindV1>,
    /// Optional exact opaque URL key.
    pub url_key: Option<Digest>,
    /// Optional exact opaque host key.
    pub host_key: Option<Digest>,
    /// Optional exact opaque route key.
    pub route_key: Option<Digest>,
    /// Inclusive observation lower bound.
    pub since: Option<Timestamp>,
    /// Inclusive observation upper bound.
    pub until: Option<Timestamp>,
    /// Inclusive measured duration lower bound.
    pub min_duration_us: Option<u64>,
    /// Inclusive measured duration upper bound.
    pub max_duration_us: Option<u64>,
    /// Inclusive observed wire byte lower bound.
    pub min_wire_bytes: Option<u64>,
    /// Inclusive observed wire byte upper bound.
    pub max_wire_bytes: Option<u64>,
}

impl Default for ReportQueryV1 {
    fn default() -> Self {
        Self {
            after: 0,
            limit: REPORT_PAGE_LIMIT,
            kind: None,
            url_key: None,
            host_key: None,
            route_key: None,
            since: None,
            until: None,
            min_duration_us: None,
            max_duration_us: None,
            min_wire_bytes: None,
            max_wire_bytes: None,
        }
    }
}

impl ReportQueryV1 {
    /// Check finite keyset bounds and inclusive range ordering.
    ///
    /// # Errors
    /// Returns [`StoreError::Serialization`] for invalid ranges or storage overflow.
    pub fn validate(&self) -> Result<(), StoreError> {
        if !(1..=REPORT_PAGE_LIMIT).contains(&self.limit) {
            return Err(invalid("report limit must be in 1..=64"));
        }
        signed(self.after)?;
        for at in [self.since, self.until].into_iter().flatten() {
            valid_time(at)?;
        }
        for value in [
            self.min_duration_us,
            self.max_duration_us,
            self.min_wire_bytes,
            self.max_wire_bytes,
        ]
        .into_iter()
        .flatten()
        {
            signed(value)?;
        }
        if reversed(self.since, self.until)
            || reversed(self.min_duration_us, self.max_duration_us)
            || reversed(self.min_wire_bytes, self.max_wire_bytes)
        {
            return Err(invalid("report range is reversed"));
        }
        Ok(())
    }

    /// Test evidence filters, independent of sequence cursor and page size.
    ///
    /// Repositories must test this before taking `limit` matching rows.
    #[must_use]
    pub fn matches(&self, fact: &ReportFactV1) -> bool {
        self.kind.is_none_or(|kind| kind == fact.data.kind())
            && self.url_key.is_none_or(|key| fact.url_key == Some(key))
            && self.host_key.is_none_or(|key| fact.host_key == Some(key))
            && self.route_key.is_none_or(|key| fact.route_key == Some(key))
            && in_range(Some(fact.at), self.since, self.until)
            && in_range(
                fact.data.duration_us(),
                self.min_duration_us,
                self.max_duration_us,
            )
            && in_range(fact.data.wire_bytes(), self.min_wire_bytes, self.max_wire_bytes)
    }
}

/// One repository sequence and its immutable fact.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ReportEntryV1 {
    /// Positive repository-wide sequence.
    pub sequence: u64,
    /// Scoped evidence.
    pub fact: ReportFactV1,
}

impl ReportEntryV1 {
    /// Pair a committed sequence with its fact.
    #[must_use]
    pub const fn new(sequence: u64, fact: ReportFactV1) -> Self {
        Self { sequence, fact }
    }
}

/// Filtered keyset page; aggregates over this page never describe the whole run.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ReportPageV1 {
    /// At most 64 matching facts, in ascending sequence order.
    pub entries: Vec<ReportEntryV1>,
    /// Last returned sequence only when another matching fact exists.
    pub next: Option<u64>,
}

impl ReportPageV1 {
    /// Construct a repository page after filtering and lookahead.
    #[must_use]
    pub const fn new(entries: Vec<ReportEntryV1>, next: Option<u64>) -> Self {
        Self { entries, next }
    }
}

/// Fenced report history with retention-aware durable or volatile storage.
#[async_trait]
pub trait ReportHistoryRepo: Send + Sync {
    /// Append idempotently under current live custody authority.
    ///
    /// Same ID with different evidence must conflict, not overwrite history.
    /// # Errors
    /// Returns validation, retention, lost-lease or backend errors.
    async fn append_fact(&self, lease: &CustodyLease, fact: &ReportFactV1) -> Result<u64, StoreError>;

    /// Read authorized tenant history; absent run requests a tenant-only timeline.
    ///
    /// Apply all filters before bounded keyset pagination. Expired volatile facts
    /// are unavailable, not recreated as durable or successful evidence.
    /// # Errors
    /// Returns validation, authorization or backend errors.
    async fn query_facts(
        &self,
        tenant: TenantId,
        run: Option<CrawlRunId>,
        query: &ReportQueryV1,
    ) -> Result<ReportPageV1, StoreError>;

    /// Committed outcome counters per route of one retained run, ordered by route key.
    ///
    /// Only facts that carry a route key count. Expired facts are unavailable, a volatile
    /// (ZDR) run is withheld, and the counters are derived from committed rows alone, so a
    /// restarted reader sees the same numbers.
    /// # Errors
    /// Returns authorization, retention or backend errors.
    async fn route_counters(
        &self,
        tenant: TenantId,
        run: CrawlRunId,
    ) -> Result<Vec<RouteCountersV1>, StoreError>;
}

/// Exact nearest-rank percentile of at most one page of durations.
///
/// Mutates the caller-owned sample by sorting it. The result describes only this
/// bounded sample, never the entire run. Empty samples return `None`.
/// # Errors
/// Returns a serialization error for percentile outside 1..=100, more than 64
/// samples, signed-storage overflow or checked rank arithmetic failure.
pub fn page_duration_percentile(durations_us: &mut [u64], percentile: u8) -> Result<Option<u64>, StoreError> {
    if !(1..=100).contains(&percentile) || durations_us.len() > 64 {
        return Err(invalid("invalid page percentile bound"));
    }
    for duration in durations_us.iter() {
        signed(*duration)?;
    }
    if durations_us.is_empty() {
        return Ok(None);
    }
    let rank = durations_us
        .len()
        .checked_mul(usize::from(percentile))
        .and_then(|product| product.checked_add(99))
        .map(|product| product / 100)
        .and_then(|rank| rank.checked_sub(1))
        .ok_or_else(|| invalid("percentile rank overflow"))?;
    durations_us.sort_unstable();
    Ok(durations_us.get(rank).copied())
}

/// Per-request progression replayed in committed sequence order.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct PipelineProgressV1 {
    states: [PipelineStateV1; 4],
    delivery_failed: bool,
    #[serde(default)]
    delivery_acknowledged: bool,
}

impl PipelineProgressV1 {
    /// Return the current committed state of a checkpoint.
    #[must_use]
    pub fn state(&self, stage: PipelineStageV1) -> PipelineStateV1 {
        self.states[stage_index(stage)]
    }

    /// Whether completion is successful without a recorded delivery failure.
    #[must_use]
    pub fn delivered(&self) -> bool {
        !self.delivery_failed
            && self.state(PipelineStageV1::Fetch) == PipelineStateV1::Succeeded
            && self.state(PipelineStageV1::Parse) == PipelineStateV1::Succeeded
            && self.state(PipelineStageV1::Index) == PipelineStateV1::Succeeded
            && self.state(PipelineStageV1::Completion) == PipelineStateV1::Succeeded
    }

    /// Arm recovery after the repository verifies the durable outbox ACK.
    ///
    /// Only the existing all-outboxes acknowledgement authority may call this
    /// method, in the same transaction that appends actual successful index and
    /// completion facts. Ordinary observations cannot authorize recovery. Prior
    /// failure facts remain immutable history. This never recovers fetch/parse.
    ///
    /// # Errors
    /// Returns a conflict unless both fetch and parse already succeeded.
    pub fn acknowledge_delivery(&mut self) -> Result<(), StoreError> {
        if self.state(PipelineStageV1::Fetch) != PipelineStateV1::Succeeded
            || self.state(PipelineStageV1::Parse) != PipelineStateV1::Succeeded
        {
            return Err(StoreError::Conflict(
                "delivery acknowledgement lacks fetch or parse success".into(),
            ));
        }
        self.delivery_acknowledged = true;
        self.delivery_failed = false;
        Ok(())
    }

    /// Apply one committed payload without allowing skipped dependency success.
    ///
    /// A delivery failure invalidates delivered status until an independently
    /// verified durable outbox acknowledgement authorizes index/completion recovery.
    /// # Errors
    /// Returns a conflict for missing successful prerequisites, regression to
    /// pending, recovery from failure within one attempt, or concealed delivery failure.
    pub fn apply(&mut self, data: &ReportDataV1) -> Result<(), StoreError> {
        if matches!(
            data,
            ReportDataV1::Stage {
                stage: ProcessorStageV1::Delivery,
                outcome: StageOutcomeV1::Failed | StageOutcomeV1::Cancelled,
                ..
            }
        ) {
            self.delivery_failed = true;
            self.delivery_acknowledged = false;
        }
        let ReportDataV1::Pipeline { stage, state } = data else {
            return Ok(());
        };
        let current = self.state(*stage);
        if *state == PipelineStateV1::Failed
            && matches!(stage, PipelineStageV1::Index | PipelineStageV1::Completion)
        {
            self.delivery_acknowledged = false;
        }
        let acknowledged_recovery = self.delivery_acknowledged
            && matches!(stage, PipelineStageV1::Index | PipelineStageV1::Completion)
            && *state == PipelineStateV1::Succeeded;
        if (current != PipelineStateV1::Pending && *state == PipelineStateV1::Pending)
            || (current == PipelineStateV1::Failed
                && *state != PipelineStateV1::Failed
                && !acknowledged_recovery)
        {
            return Err(StoreError::Conflict(
                "pipeline attempt cannot reset terminal state".into(),
            ));
        }
        if *state == PipelineStateV1::Succeeded {
            let allowed = match stage {
                PipelineStageV1::Index => self.state(PipelineStageV1::Parse) == PipelineStateV1::Succeeded,
                PipelineStageV1::Completion => {
                    self.state(PipelineStageV1::Parse) == PipelineStateV1::Succeeded
                        && self.state(PipelineStageV1::Index) == PipelineStateV1::Succeeded
                        && !self.delivery_failed
                }
                PipelineStageV1::Parse => self.state(PipelineStageV1::Fetch) == PipelineStateV1::Succeeded,
                PipelineStageV1::Fetch => true,
            };
            if !allowed {
                return Err(StoreError::Conflict(
                    "pipeline success lacks committed prerequisite".into(),
                ));
            }
        }
        self.states[stage_index(*stage)] = *state;
        if *stage == PipelineStageV1::Completion && *state == PipelineStateV1::Succeeded {
            self.delivery_acknowledged = false;
        }
        Ok(())
    }
}

const fn stage_index(stage: PipelineStageV1) -> usize {
    match stage {
        PipelineStageV1::Fetch => 0,
        PipelineStageV1::Parse => 1,
        PipelineStageV1::Index => 2,
        PipelineStageV1::Completion => 3,
    }
}

fn invalid(message: &'static str) -> StoreError {
    StoreError::Serialization(message.into())
}

fn signed(value: u64) -> Result<(), StoreError> {
    i64::try_from(value)
        .map(|_| ())
        .map_err(|_| invalid("report integer exceeds signed storage range"))
}

fn valid_time(at: Timestamp) -> Result<(), StoreError> {
    if at.timestamp() < 0 {
        return Err(invalid("report timestamp precedes unix epoch"));
    }
    Ok(())
}

fn reversed<T: PartialOrd>(min: Option<T>, max: Option<T>) -> bool {
    matches!((min, max), (Some(min), Some(max)) if min > max)
}

fn in_range<T: PartialOrd>(value: Option<T>, min: Option<T>, max: Option<T>) -> bool {
    if min.is_none() && max.is_none() {
        return true;
    }
    value.is_some_and(|value| min.is_none_or(|min| value >= min) && max.is_none_or(|max| value <= max))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn fact(data: ReportDataV1) -> ReportFactV1 {
        let lease = CustodyLease::for_url(
            TenantId(uuid::Uuid::from_u128(1)),
            CrawlRunId(uuid::Uuid::from_u128(2)),
            1,
            crate::WorkerId(uuid::Uuid::from_u128(3)),
            2,
        );
        ReportFactV1::new(
            &lease,
            Digest([1; 32]),
            Timestamp::from_timestamp(10, 0).unwrap(),
            data,
        )
    }

    #[test]
    fn finite_schema_roundtrips_without_content() {
        let value = fact(ReportDataV1::Dns {
            outcome: DnsOutcomeV1::Timeout,
            duration_us: 4,
            recheck_at: None,
        });
        let json = serde_json::to_string(&value).unwrap();
        assert_eq!(serde_json::from_str::<ReportFactV1>(&json).unwrap(), value);
        assert!(!json.contains("http"));
    }

    #[test]
    fn validates_signed_bounds_and_time_ordering() {
        let mut value = fact(ReportDataV1::Dns {
            outcome: DnsOutcomeV1::Resolved,
            duration_us: 10,
            recheck_at: Timestamp::from_timestamp(9, 0),
        });
        assert!(value.validate().is_err());
        value.data = ReportDataV1::Loss { dropped: u64::MAX };
        assert!(value.validate().is_err());
        value.data = ReportDataV1::Loss { dropped: 1 };
        value.attempt = 0;
        assert!(value.validate().is_err());
        value.attempt = 1;
        value.at = Timestamp::from_timestamp(-1, 999_999_999).unwrap();
        assert!(value.validate().is_err());
        value.at = Timestamp::from_timestamp(0, 0).unwrap();
        assert!(value.validate().is_ok());
        value.request_id = Some(0);
        assert!(value.validate().is_err());
    }

    #[test]
    fn unknown_wire_is_not_body_length_or_zero() {
        let unknown = fact(ReportDataV1::Wire {
            received_bytes: None,
            sent_bytes: None,
            duration_us: None,
        });
        let mut query = ReportQueryV1 {
            min_wire_bytes: Some(0),
            ..ReportQueryV1::default()
        };
        assert!(!query.matches(&unknown));
        let measured = fact(ReportDataV1::Wire {
            received_bytes: Some(0),
            sent_bytes: None,
            duration_us: None,
        });
        assert!(query.matches(&measured));
        query.min_duration_us = Some(0);
        assert!(!query.matches(&measured));
    }

    #[test]
    fn query_rejects_reversed_and_unbounded_ranges() {
        let mut query = ReportQueryV1::default();
        assert!(query.validate().is_ok());
        query.limit = 65;
        assert!(query.validate().is_err());
        query.limit = 0;
        assert!(query.validate().is_err());
        query.limit = 64;
        query.min_duration_us = Some(3);
        query.max_duration_us = Some(2);
        assert!(query.validate().is_err());
        query.max_duration_us = Some(u64::MAX);
        assert!(query.validate().is_err());
    }

    #[test]
    fn nearest_rank_is_exact_for_page_scope() {
        let mut sample = [40, 10, 30, 20];
        assert_eq!(page_duration_percentile(&mut sample, 50).unwrap(), Some(20));
        assert_eq!(page_duration_percentile(&mut sample, 95).unwrap(), Some(40));
        assert_eq!(page_duration_percentile(&mut [], 50).unwrap(), None);
        assert!(page_duration_percentile(&mut [0; 65], 50).is_err());
        assert!(page_duration_percentile(&mut sample, 0).is_err());
        assert!(page_duration_percentile(&mut [u64::MAX], 99).is_err());
    }

    #[test]
    fn pipeline_requires_parse_and_index_before_completion() {
        let mut progress = PipelineProgressV1::default();
        let success = |stage| ReportDataV1::Pipeline {
            stage,
            state: PipelineStateV1::Succeeded,
        };
        assert!(progress.apply(&success(PipelineStageV1::Index)).is_err());
        assert!(progress.apply(&success(PipelineStageV1::Completion)).is_err());
        assert!(progress.apply(&success(PipelineStageV1::Parse)).is_err());
        progress.apply(&success(PipelineStageV1::Fetch)).unwrap();
        progress.apply(&success(PipelineStageV1::Parse)).unwrap();
        progress.apply(&success(PipelineStageV1::Index)).unwrap();
        progress.apply(&success(PipelineStageV1::Completion)).unwrap();
        assert!(progress.delivered());
        progress
            .apply(&ReportDataV1::Pipeline {
                stage: PipelineStageV1::Index,
                state: PipelineStateV1::Failed,
            })
            .unwrap();
        assert!(!progress.delivered());
        assert!(progress.apply(&success(PipelineStageV1::Index)).is_err());
        progress
            .apply(&ReportDataV1::Stage {
                stage: ProcessorStageV1::Delivery,
                outcome: StageOutcomeV1::Failed,
                duration_us: 1,
                processor: ProcessorIdentityV1::Delivery,
                processor_version: 1,
            })
            .unwrap();
        assert!(!progress.delivered());
        assert!(progress.apply(&success(PipelineStageV1::Completion)).is_err());
    }

    #[test]
    fn actual_delivery_ack_recovers_index_and_completion_without_rewriting_history() {
        let mut progress = PipelineProgressV1::default();
        let state = |stage, state| ReportDataV1::Pipeline { stage, state };
        assert!(progress.acknowledge_delivery().is_err());
        progress
            .apply(&state(PipelineStageV1::Fetch, PipelineStateV1::Succeeded))
            .unwrap();
        assert!(progress.acknowledge_delivery().is_err());
        progress
            .apply(&state(PipelineStageV1::Parse, PipelineStateV1::Succeeded))
            .unwrap();
        progress
            .apply(&state(PipelineStageV1::Index, PipelineStateV1::Failed))
            .unwrap();
        progress
            .apply(&state(PipelineStageV1::Completion, PipelineStateV1::Failed))
            .unwrap();
        progress
            .apply(&ReportDataV1::Stage {
                stage: ProcessorStageV1::Delivery,
                outcome: StageOutcomeV1::Failed,
                duration_us: 1,
                processor: ProcessorIdentityV1::Delivery,
                processor_version: 1,
            })
            .unwrap();
        assert!(!progress.delivered());
        assert!(progress
            .apply(&state(PipelineStageV1::Index, PipelineStateV1::Succeeded))
            .is_err());

        progress.acknowledge_delivery().unwrap();
        assert!(!progress.delivered());
        let encoded = serde_json::to_string(&progress).unwrap();
        let mut recovered: PipelineProgressV1 = serde_json::from_str(&encoded).unwrap();
        recovered
            .apply(&state(PipelineStageV1::Index, PipelineStateV1::Succeeded))
            .unwrap();
        recovered
            .apply(&state(PipelineStageV1::Completion, PipelineStateV1::Succeeded))
            .unwrap();
        assert!(recovered.delivered());
        recovered
            .apply(&state(PipelineStageV1::Index, PipelineStateV1::Failed))
            .unwrap();
        assert!(recovered
            .apply(&state(PipelineStageV1::Index, PipelineStateV1::Succeeded))
            .is_err());
        assert!(recovered
            .apply(&state(PipelineStageV1::Index, PipelineStateV1::Pending))
            .is_err());
        recovered
            .apply(&state(PipelineStageV1::Parse, PipelineStateV1::Failed))
            .unwrap();
        assert!(!recovered.delivered());
        assert!(recovered
            .apply(&state(PipelineStageV1::Parse, PipelineStateV1::Succeeded))
            .is_err());
        assert!(recovered.acknowledge_delivery().is_err());
    }

    const CANARY: &str = "canary-secret-7f3a91";

    #[test]
    fn error_snapshot_never_keeps_credentials_urls_or_control_text() {
        crate::secret::register_secret(CANARY);
        let detail = format!(
            "GET https://user:pw@internal.example/path?sig=abc&token={CANARY} failed\n\
             authorization: Bearer {CANARY}; password={CANARY} saw {CANARY}"
        );
        let snapshot = ErrorSnapshotV1::new(
            Some(ProcessorStageV1::Fetch),
            "fetch_failed",
            Some(502),
            Some(&detail),
        )
        .unwrap();
        let text = serde_json::to_string(&snapshot).unwrap();
        for leaked in [CANARY, "internal.example", "user:pw", "sig=abc", "Bearer"] {
            assert!(!text.contains(leaked), "{leaked} leaked into {text}");
        }
        assert!(snapshot.detail.as_deref().unwrap().contains("[url]"));
        assert!(!text.contains('\n'));
        // an unredacted snapshot built by hand is cleaned by the repository-side pass
        let mut raw = snapshot.clone();
        raw.detail = Some(format!("token={CANARY}"));
        let cleaned = raw.redacted();
        assert!(!cleaned.detail.as_deref().unwrap().contains(CANARY));
        assert!(matches!(snapshot.redacted(), Cow::Borrowed(_)));
    }

    #[test]
    fn error_snapshot_is_bounded_and_alert_only() {
        assert!(ErrorSnapshotV1::new(None, "", None, None).is_err());
        assert!(ErrorSnapshotV1::new(None, "has space", None, None).is_err());
        assert!(ErrorSnapshotV1::new(None, &"a".repeat(ERROR_CODE_MAX_BYTES + 1), None, None).is_err());
        assert!(ErrorSnapshotV1::new(None, "ok", Some(99), None).is_err());
        let long = "word ".repeat(200);
        let snapshot = ErrorSnapshotV1::new(None, "ok", None, Some(&long)).unwrap();
        assert!(snapshot.detail.as_deref().unwrap().len() <= ERROR_DETAIL_MAX_BYTES);

        let mut alert = fact(ReportDataV1::Alert {
            severity: AlertSeverityV1::Error,
            code: AlertCodeV1::ProcessorFailure,
            context: AlertContextV1::Processing,
        });
        alert.error = Some(snapshot.clone());
        alert.validate().unwrap();
        let mut wire = fact(ReportDataV1::Loss { dropped: 1 });
        wire.error = Some(snapshot);
        assert!(wire.validate().is_err());
    }

    #[test]
    fn route_dimension_filters_and_old_facts_keep_their_bytes() {
        let plain = fact(ReportDataV1::Loss { dropped: 1 });
        let json = serde_json::to_string(&plain).unwrap();
        assert!(!json.contains("routeKey") && !json.contains("error"), "{json}");
        assert_eq!(serde_json::from_str::<ReportFactV1>(&json).unwrap(), plain);
        let mut routed = plain.clone();
        routed.route_key = Some(report_route_key("listing"));
        let query = ReportQueryV1 {
            route_key: Some(report_route_key("listing")),
            ..ReportQueryV1::default()
        };
        assert!(query.matches(&routed));
        assert!(!query.matches(&plain));
        let other = ReportQueryV1 {
            route_key: Some(report_route_key("detail")),
            ..ReportQueryV1::default()
        };
        assert!(!other.matches(&routed));
        assert_ne!(report_route_key("listing"), report_route_key("detail"));
    }

    #[test]
    fn outcome_labels_name_checkpoints_stages_and_alerts_only() {
        let pipeline = ReportDataV1::Pipeline {
            stage: PipelineStageV1::Fetch,
            state: PipelineStateV1::Failed,
        };
        assert_eq!(pipeline.outcome_label().as_deref(), Some("pipeline:fetch:failed"));
        assert_eq!(ReportDataV1::Loss { dropped: 1 }.outcome_label(), None);
        let mut counters = RouteCountersV1::new(report_route_key("a"));
        counters.outcomes.insert("pipeline:fetch:failed".into(), 2);
        counters.outcomes.insert("pipeline:fetch:succeeded".into(), 3);
        counters.outcomes.insert("pipeline:index:pending".into(), 9);
        assert_eq!(counters.committed(), 5);
        assert_eq!(counters.count("pipeline:index:pending"), 9);
        assert_eq!(counters.count("absent"), 0);
    }
}
