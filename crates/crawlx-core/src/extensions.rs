//! Reviewed, bounded native extensions; never a source-language or plugin ABI.
//!
//! All values are proposals. This module grants no browser, network, storage or
//! policy authority. Item values remain content-sensitive until artifact admission.

use crate::{extraction::DocumentEnvelopeV1, hash::Digest, request::RequestEnvelopeV1};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Hard descriptor count per immutable execution specification.
pub const MAX_EXTENSIONS: usize = 32;
/// Hard serialized configuration and item limit.
pub const MAX_EXTENSION_BYTES: usize = 1_048_576;

/// Safe response facts. No arbitrary headers, URLs, cookies or bodies are representable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct HeaderFactsV1 {
    /// HTTP response status.
    pub status: u16,
    /// Lowercase MIME essence without parameters.
    pub content_type: Option<String>,
    /// Declared wire body length, not measured downloaded bytes.
    pub content_length: Option<u64>,
}
impl HeaderFactsV1 {
    /// Project bounded non-secret facts from an admitted response.
    ///
    /// # Errors
    /// Rejects invalid status or malformed/oversized MIME essence.
    pub fn new(
        status: u16,
        content_type: Option<&str>,
        content_length: Option<u64>,
    ) -> Result<Self, ExtensionError> {
        let essence = content_type.map(|value| value.split(';').next().unwrap_or("").trim());
        if !(100..=599).contains(&status) || essence.is_some_and(|value| !valid_mime(value)) {
            return Err(ExtensionError::Rejected);
        }
        Ok(Self {
            status,
            content_type: essence.map(str::to_ascii_lowercase),
            content_length,
        })
    }
    /// Check facts received through deserialization before dispatch.
    ///
    /// # Errors
    /// Rejects facts which are not the canonical privacy-safe projection.
    pub fn validate(&self) -> Result<(), ExtensionError> {
        let projected = Self::new(self.status, self.content_type.as_deref(), self.content_length)?;
        if &projected != self {
            return Err(ExtensionError::Rejected);
        }
        Ok(())
    }
}
fn valid_mime(value: &str) -> bool {
    value.len() <= 127
        && value
            .split_once('/')
            .is_some_and(|(left, right)| !left.is_empty() && !right.is_empty() && !right.contains('/'))
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$&^_.+-/".contains(&byte))
}

/// Compiled header gate. Every configured condition narrows admission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct HeaderPolicyV1 {
    /// Minimum allowed status, inclusive.
    pub min_status: u16,
    /// Maximum allowed status, inclusive.
    pub max_status: u16,
    /// Allowed lowercase MIME essences; empty means unrestricted.
    pub content_types: BTreeSet<String>,
    /// Maximum declared body length. Unknown length is refused when set.
    pub max_content_length: Option<u64>,
}
impl Default for HeaderPolicyV1 {
    fn default() -> Self {
        Self {
            min_status: 100,
            max_status: 599,
            content_types: BTreeSet::new(),
            max_content_length: None,
        }
    }
}
impl HeaderPolicyV1 {
    /// Validate immutable gate bounds.
    ///
    /// # Errors
    /// Rejects invalid ranges, excessive selectors or noncanonical MIME essences.
    pub fn validate(&self) -> Result<(), ExtensionError> {
        if !(100..=599).contains(&self.min_status)
            || !(self.min_status..=599).contains(&self.max_status)
            || self.content_types.len() > 32
            || self
                .content_types
                .iter()
                .any(|value| !valid_mime(value) || value.bytes().any(|byte| byte.is_ascii_uppercase()))
        {
            return Err(ExtensionError::InvalidSpec);
        }
        Ok(())
    }
    /// Decide before reading response bytes.
    ///
    /// # Errors
    /// Returns malformed policy/facts or a typed header-stage rejection.
    pub fn check(&self, facts: &HeaderFactsV1) -> Result<(), ExtensionError> {
        self.validate()?;
        facts.validate()?;
        if !(self.min_status..=self.max_status).contains(&facts.status)
            || (!self.content_types.is_empty()
                && facts
                    .content_type
                    .as_ref()
                    .is_none_or(|value| !self.content_types.contains(value)))
            || self
                .max_content_length
                .is_some_and(|limit| facts.content_length.is_none_or(|length| length > limit))
        {
            return Err(ExtensionError::Rejected);
        }
        Ok(())
    }
}

/// Closed, content-free error/skip reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtensionReasonV1 {
    /// Native policy refusal.
    PolicyDenied,
    /// Caller cancellation.
    Cancelled,
    /// Compiled callback failure.
    HandlerFailed,
    /// Compiled rejection or header abort.
    Rejected,
    /// Finite retry allowance exhausted.
    RetryExhausted,
    /// Bounded dispatcher capacity exhausted.
    Capacity,
    /// Caller processing failure without raw error data.
    Processing,
}
/// One immutable terminal outcome per request attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "reason",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum ExtensionTerminalV1 {
    /// Request completed.
    Completed,
    /// Request was skipped, never fabricated as success.
    Skipped(ExtensionReasonV1),
    /// Request failed.
    Failed(ExtensionReasonV1),
}
/// Closed metadata-only lifecycle input. Public extensibility does not admit unknown JSON variants.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "facts",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum ExtensionEventV1 {
    /// Immutable pipeline configured.
    Configure,
    /// Validated proposal, without request bytes.
    RequestProposed {
        /// Whether the method is GET or HEAD; method text is not retained.
        read_only: bool,
    },
    /// Replacement proposal boundary.
    BeforeAcquisition,
    /// Header gate, before body access.
    HeadersReceived(HeaderFactsV1),
    /// Response acquired.
    Response,
    /// HTML parsed.
    Html,
    /// XML parsed.
    Xml,
    /// Shared parse boundary.
    Parse,
    /// Item candidate boundary.
    Item,
    /// Feed processing boundary.
    Feed,
    /// Content-free failure.
    Error(ExtensionReasonV1),
    /// Exactly one skip decision for this attempt.
    Skipped(ExtensionReasonV1),
    /// Failed attempt notification.
    Failed(ExtensionReasonV1),
    /// Single terminal outcome.
    Terminal(ExtensionTerminalV1),
    /// Fenced persistence boundary, not persistence authority.
    Checkpoint,
    /// Owned-state cleanup boundary.
    Close,
    /// Before admitted browser launch.
    BrowserPreLaunch,
    /// After admitted browser launch.
    BrowserPostLaunch,
    /// Page creation boundary.
    BrowserPageCreate,
    /// Page close boundary.
    BrowserPageClose,
    /// Before admitted navigation.
    BrowserPreNavigation,
    /// After admitted navigation.
    BrowserPostNavigation,
    /// Browser owner cleanup; never recursively closes a shared pool.
    BrowserClose,
}
impl ExtensionEventV1 {
    /// Exact compiled selector for this input.
    #[must_use]
    pub const fn stage(&self) -> ExtensionStageV1 {
        match self {
            Self::Configure => ExtensionStageV1::Configure,
            Self::RequestProposed { .. } => ExtensionStageV1::RequestProposed,
            Self::BeforeAcquisition => ExtensionStageV1::BeforeAcquisition,
            Self::HeadersReceived(_) => ExtensionStageV1::HeadersReceived,
            Self::Response => ExtensionStageV1::Response,
            Self::Html => ExtensionStageV1::Html,
            Self::Xml => ExtensionStageV1::Xml,
            Self::Parse => ExtensionStageV1::Parse,
            Self::Item => ExtensionStageV1::Item,
            Self::Feed => ExtensionStageV1::Feed,
            Self::Error(_) => ExtensionStageV1::Error,
            Self::Skipped(_) => ExtensionStageV1::Skipped,
            Self::Failed(_) => ExtensionStageV1::Failed,
            Self::Terminal(_) => ExtensionStageV1::Terminal,
            Self::Checkpoint => ExtensionStageV1::Checkpoint,
            Self::Close => ExtensionStageV1::Close,
            Self::BrowserPreLaunch => ExtensionStageV1::BrowserPreLaunch,
            Self::BrowserPostLaunch => ExtensionStageV1::BrowserPostLaunch,
            Self::BrowserPageCreate => ExtensionStageV1::BrowserPageCreate,
            Self::BrowserPageClose => ExtensionStageV1::BrowserPageClose,
            Self::BrowserPreNavigation => ExtensionStageV1::BrowserPreNavigation,
            Self::BrowserPostNavigation => ExtensionStageV1::BrowserPostNavigation,
            Self::BrowserClose => ExtensionStageV1::BrowserClose,
        }
    }
}
/// Closed output of a compiled lifecycle callback.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
#[non_exhaustive]
pub enum ExtensionResultV1 {
    /// Continue without granting authority.
    Continue,
    /// Bounded non-sensitive annotation identifier.
    Annotation(String),
    /// Skip this attempt.
    Skip(ExtensionReasonV1),
    /// Fail this attempt.
    Fail(ExtensionReasonV1),
}
/// Stable callback receipt, identified by immutable registration position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtensionCallbackReceiptV1 {
    /// Zero-based descriptor registration index.
    pub registration: usize,
    /// Compiled registry version; one denotes implementation 1.0.0.
    pub version: u16,
    /// Immutable selected configuration digest, computed once during compilation.
    pub config_digest: Digest,
    /// Typed callback output.
    pub result: ExtensionResultV1,
}
/// Transferable replay record. No raw input, URL, body, headers or host handle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtensionReceiptV1 {
    /// Contiguous one-based logical sequence; draining never resets it.
    pub sequence: u64,
    /// Closed event input.
    pub event: ExtensionEventV1,
    /// Actual executed callback outputs in execution order.
    pub callbacks: Vec<ExtensionCallbackReceiptV1>,
    /// Sticky dispatcher result.
    pub result: ExtensionResultV1,
}
impl ExtensionReceiptV1 {
    /// Construct a callback-executed record.
    #[must_use]
    pub fn new(
        sequence: u64,
        event: ExtensionEventV1,
        callbacks: Vec<ExtensionCallbackReceiptV1>,
        result: ExtensionResultV1,
    ) -> Self {
        Self {
            sequence,
            event,
            callbacks,
            result,
        }
    }
}
impl ExtensionCallbackReceiptV1 {
    /// Construct a registered compiled callback receipt.
    #[must_use]
    pub fn new(registration: usize, config_digest: Digest, result: ExtensionResultV1) -> Self {
        Self {
            registration,
            version: 1,
            config_digest,
            result,
        }
    }
}
/// Hard bounded per-attempt trail accounting, including drained receipts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtensionEventLimitsV1 {
    /// Total event allowance, including reserved finalization callbacks.
    pub events: usize,
    /// Total serialized receipt bytes.
    pub bytes: usize,
}
impl Default for ExtensionEventLimitsV1 {
    fn default() -> Self {
        Self {
            events: 256,
            bytes: MAX_EXTENSION_BYTES,
        }
    }
}
impl ExtensionEventLimitsV1 {
    /// Construct bounded accounting with room for cancellation cleanup.
    ///
    /// # Errors
    /// Rejects limits outside 8..=4096 events or 65536..=1048576 bytes.
    pub fn new(events: usize, bytes: usize) -> Result<Self, ExtensionError> {
        if !(8..=4096).contains(&events) || !(65_536..=MAX_EXTENSION_BYTES).contains(&bytes) {
            return Err(ExtensionError::Limit);
        }
        Ok(Self { events, bytes })
    }
}

/// Fixed lifecycle boundaries, separate from discovery's RouteLearner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtensionStageV1 {
    /// Validate immutable configuration before work.
    Configure,
    /// Validate a newly proposed request.
    RequestProposed,
    /// Produce a replacement proposal, never an admitted effect.
    BeforeAcquisition,
    /// Inspect bounded header facts, never cookies.
    HeadersReceived,
    /// Inspect response facts after admitted headers.
    Response,
    /// Observe an HTML document without receiving its bytes.
    Html,
    /// Observe an XML document without receiving its bytes.
    Xml,
    /// Observe a feed item batch.
    Feed,
    /// Observe a typed processing error.
    Error,
    /// Observe a skipped decision.
    Skipped,
    /// Observe a failed attempt.
    Failed,
    /// Before launching an admitted browser.
    BrowserPreLaunch,
    /// After launching an admitted browser.
    BrowserPostLaunch,
    /// Before creating a browser page.
    BrowserPageCreate,
    /// After closing a browser page.
    BrowserPageClose,
    /// Before admitted navigation.
    BrowserPreNavigation,
    /// After admitted navigation.
    BrowserPostNavigation,
    /// Before closing an owned browser.
    BrowserClose,
    /// Project shared parsed document metadata.
    Parse,
    /// Run the explicit label handler.
    Route,
    /// Transform an ephemeral item candidate.
    Item,
    /// Preserve failure and policy denial.
    Terminal,
    /// Propose versioned state for the fenced commit.
    Checkpoint,
    /// Release owned ephemeral state exactly once.
    Close,
}
/// Capabilities selected from reviewed registry entries, never self-granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtensionCapabilityV1 {
    /// Read request proposals without credentials.
    RequestRead,
    /// Propose a new request requiring native admission.
    RequestProposal,
    /// Read retention-approved document metadata.
    DocumentRead,
    /// Create or transform an ephemeral item.
    ItemTransform,
    /// Read closed lifecycle facts and return bounded annotations.
    LifecycleRead,
}
/// Explicit failure behavior. Neither choice can erase a policy denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtensionFailurePolicyV1 {
    /// Fail this request.
    Fail,
    /// Reject this candidate without fabricating success.
    Reject,
}
/// Bounded work; one request executes one job at a time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtensionLimitsV1 {
    /// Maximum serialized input bytes.
    pub input_bytes: usize,
    /// Maximum serialized output bytes.
    pub output_bytes: usize,
    /// Maximum replacement requests, at most one.
    pub proposals: usize,
    /// Maximum candidate items, at most one.
    pub items: usize,
    /// Browser action proposals are unavailable in these built-ins; must be zero.
    pub actions: usize,
    /// Cooperative per-stage deadline, at most 30 seconds.
    pub deadline_ms: u32,
    /// Outstanding jobs per request, exactly one.
    pub outstanding: usize,
}
impl Default for ExtensionLimitsV1 {
    fn default() -> Self {
        Self {
            input_bytes: MAX_EXTENSION_BYTES,
            output_bytes: MAX_EXTENSION_BYTES,
            proposals: 1,
            items: 1,
            actions: 0,
            deadline_ms: 1000,
            outstanding: 1,
        }
    }
}
/// Typed configuration for the fixed compiled registry.
/// Empty struct variants deliberately reject unreviewed fields on internally tagged JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ExtensionConfigV1 {
    /// Refuse any method except GET/HEAD; does not authorize either method.
    ReadOnly {},
    /// Return a replacement proposal. The worker must append after fresh admission.
    ReplaceRequest {
        /// Complete bounded proposal, never patched transport state.
        request: Box<RequestEnvelopeV1>,
    },
    /// Reject a document unless its independent extraction gates accepted it.
    RequireQuality {},
    /// Trim the title candidate's Unicode whitespace.
    TrimTitle {},
    /// Reject a candidate without a nonempty title.
    RequireTitle {},
    /// Inspect only admitted, non-secret response header facts.
    HeaderPolicy {
        /// Immutable narrowing policy.
        policy: HeaderPolicyV1,
    },
    /// Execute a compiled annotation callback at one lifecycle boundary.
    Annotate {
        /// Selected boundary.
        stage: ExtensionStageV1,
        /// Bounded identifier, never arbitrary text or content.
        code: String,
    },
    /// Execute a compiled failure callback at one lifecycle boundary.
    FailStage {
        /// Selected boundary.
        stage: ExtensionStageV1,
    },
    /// Execute a compiled candidate rejection callback at one boundary.
    RejectStage {
        /// Selected boundary.
        stage: ExtensionStageV1,
    },
}
impl ExtensionConfigV1 {
    /// Exact compiled implementation identifier.
    #[must_use]
    pub const fn id(&self) -> &'static str {
        match self {
            Self::ReadOnly {} => "native.read_only",
            Self::ReplaceRequest { .. } => "native.replace_request",
            Self::RequireQuality {} => "native.require_quality",
            Self::TrimTitle {} => "native.trim_title",
            Self::RequireTitle {} => "native.require_title",
            Self::HeaderPolicy { .. } => "native.header_policy",
            Self::Annotate { .. } => "native.annotate",
            Self::FailStage { .. } => "native.fail_stage",
            Self::RejectStage { .. } => "native.reject_stage",
        }
    }
    /// Single stage accepted by this reviewed implementation.
    #[must_use]
    pub const fn stage(&self) -> ExtensionStageV1 {
        match self {
            Self::ReadOnly {} => ExtensionStageV1::RequestProposed,
            Self::ReplaceRequest { .. } => ExtensionStageV1::BeforeAcquisition,
            Self::RequireQuality {} => ExtensionStageV1::Parse,
            Self::TrimTitle {} | Self::RequireTitle {} => ExtensionStageV1::Item,
            Self::HeaderPolicy { .. } => ExtensionStageV1::HeadersReceived,
            Self::Annotate { stage, .. } | Self::FailStage { stage } | Self::RejectStage { stage } => *stage,
        }
    }
    /// Exact capabilities required by this implementation.
    #[must_use]
    pub fn capabilities(&self) -> BTreeSet<ExtensionCapabilityV1> {
        [match self {
            Self::ReadOnly {} => ExtensionCapabilityV1::RequestRead,
            Self::ReplaceRequest { .. } => ExtensionCapabilityV1::RequestProposal,
            Self::RequireQuality {} => ExtensionCapabilityV1::DocumentRead,
            Self::TrimTitle {} | Self::RequireTitle {} => ExtensionCapabilityV1::ItemTransform,
            Self::HeaderPolicy { .. }
            | Self::Annotate { .. }
            | Self::FailStage { .. }
            | Self::RejectStage { .. } => ExtensionCapabilityV1::LifecycleRead,
        }]
        .into()
    }
}
/// Fixed, versioned descriptor. Selection never loads code.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtensionSpecV1 {
    /// Reviewed implementation ID.
    pub id: String,
    /// Exact implementation version, currently 1.0.0.
    pub implementation_version: String,
    /// Input schema, exactly one.
    pub input_schema_version: u16,
    /// Output schema, exactly one.
    pub output_schema_version: u16,
    /// Fixed implementation stage.
    pub stage: ExtensionStageV1,
    /// Stable ascending request/item order; reverse response order when configured.
    pub order: i32,
    /// Required capabilities, exactly the reviewed implementation set.
    pub capabilities: BTreeSet<ExtensionCapabilityV1>,
    /// Pure declarative built-in settings.
    pub config: ExtensionConfigV1,
    /// Bounded execution.
    pub limits: ExtensionLimitsV1,
    /// Typed candidate failure behavior.
    pub failure_policy: ExtensionFailurePolicyV1,
}
impl ExtensionSpecV1 {
    /// Construct a reviewed version-one descriptor.
    #[must_use]
    pub fn new(config: ExtensionConfigV1, order: i32) -> Self {
        Self {
            id: config.id().into(),
            implementation_version: "1.0.0".into(),
            input_schema_version: 1,
            output_schema_version: 1,
            stage: config.stage(),
            order,
            capabilities: config.capabilities(),
            config,
            limits: ExtensionLimitsV1::default(),
            failure_policy: ExtensionFailurePolicyV1::Fail,
        }
    }
    /// Validate registry identity, configuration, versions and work bounds.
    ///
    /// # Errors
    /// Returns a typed refusal for unknown implementations, self-granted powers or excess limits.
    pub fn validate(&self) -> Result<(), ExtensionError> {
        let l = &self.limits;
        if self.id != self.config.id()
            || self.implementation_version != "1.0.0"
            || self.input_schema_version != 1
            || self.output_schema_version != 1
            || self.stage != self.config.stage()
            || self.capabilities != self.config.capabilities()
            || !(1..=MAX_EXTENSION_BYTES).contains(&l.input_bytes)
            || !(1..=MAX_EXTENSION_BYTES).contains(&l.output_bytes)
            || l.proposals > 1
            || l.items > 1
            || !(1..=30_000).contains(&l.deadline_ms)
            || l.outstanding != 1
            || l.actions != 0
        {
            return Err(ExtensionError::InvalidSpec);
        }
        if let ExtensionConfigV1::ReplaceRequest { request } = &self.config {
            request.validate().map_err(|_| ExtensionError::InvalidSpec)?;
            if l.proposals == 0 {
                return Err(ExtensionError::Limit);
            }
        }
        match &self.config {
            ExtensionConfigV1::HeaderPolicy { policy } => policy.validate()?,
            ExtensionConfigV1::Annotate { code, .. } if code.len() > 64 || !crate::request::safe_id(code) => {
                return Err(ExtensionError::InvalidSpec);
            }
            _ => {}
        }
        if json_size(&self.config)? > l.input_bytes {
            return Err(ExtensionError::Limit);
        }
        Ok(())
    }
    /// Digest only for trusted config publication; not raw configuration values.
    ///
    /// # Errors
    /// Returns serialization failure; callers must still apply retention policy to the digest.
    pub fn config_digest(&self) -> Result<Digest, ExtensionError> {
        Ok(Digest::of_value("crawlx/extension-config/v1", &self.config)?)
    }
}
/// Compiled route, not a callback, page handle or learned URL template.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum HandlerV1 {
    /// Project approved DocumentEnvelopeV1 metadata into one candidate item.
    DocumentItem,
    /// Explicitly skip parsing without inventing a response or item.
    Skip,
}
/// Immutable native route and lifecycle configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtensionPipelineV1 {
    /// Schema version, exactly one.
    pub version: u16,
    /// Selected reviewed implementations, at most 32.
    pub extensions: Vec<ExtensionSpecV1>,
    /// Explicit labels, not discovery route templates.
    pub routes: BTreeMap<String, HandlerV1>,
    /// Optional handler for unknown labels; omission means typed failure.
    pub default_handler: Option<HandlerV1>,
    /// Reverse response, item and finalization order (python-spider dialect).
    pub reverse_response: bool,
    /// Explicit declared dataset receiving accepted candidates; none means no dataset append.
    pub dataset: Option<String>,
}
impl Default for ExtensionPipelineV1 {
    fn default() -> Self {
        Self {
            version: 1,
            extensions: Vec::new(),
            routes: [("default".into(), HandlerV1::DocumentItem)].into(),
            default_handler: None,
            reverse_response: false,
            dataset: None,
        }
    }
}
impl ExtensionPipelineV1 {
    /// Extract immutable core header policies without depending on worker or fetch.
    pub fn header_policies(&self) -> impl Iterator<Item = &HeaderPolicyV1> {
        self.extensions.iter().filter_map(|entry| match &entry.config {
            ExtensionConfigV1::HeaderPolicy { policy } => Some(policy),
            _ => None,
        })
    }
    /// Whether configuration opts into behavior beyond the legacy default label.
    #[must_use]
    pub fn configured(&self) -> bool {
        !self.extensions.is_empty()
            || self.reverse_response
            || self.default_handler.is_some()
            || self.dataset.is_some()
            || self.routes.len() != 1
            || self.routes.get("default") != Some(&HandlerV1::DocumentItem)
    }
    /// Whether selected parse/item transforms require an explicit article envelope.
    #[must_use]
    pub fn requires_document(&self) -> bool {
        self.dataset.is_some()
            || self
                .extensions
                .iter()
                .any(|entry| matches!(entry.stage, ExtensionStageV1::Parse | ExtensionStageV1::Item))
            || (self.configured()
                && self
                    .routes
                    .iter()
                    .any(|(label, handler)| label != "default" && *handler == HandlerV1::DocumentItem))
            || self.default_handler == Some(HandlerV1::DocumentItem)
    }
    /// Validate all bounds and registry references before work.
    ///
    /// # Errors
    /// Rejects unsupported versions, mutable duplicate selectors and oversized config.
    pub fn validate(&self) -> Result<(), ExtensionError> {
        if self.version != 1
            || self.extensions.len() > MAX_EXTENSIONS
            || self.routes.len() > 64
            || self.routes.keys().any(|k| !crate::request::safe_id(k))
            || self
                .dataset
                .as_ref()
                .is_some_and(|name| crate::dataset::validate_identifier(name).is_err())
        {
            return Err(ExtensionError::InvalidSpec);
        }
        let mut seen = BTreeMap::new();
        for entry in &self.extensions {
            entry.validate()?;
            let key = (&entry.id, entry.stage, &entry.implementation_version);
            if seen
                .insert(key, &entry.config)
                .is_some_and(|old| old != &entry.config)
            {
                return Err(ExtensionError::InvalidSpec);
            }
        }
        if json_size(self)? > MAX_EXTENSION_BYTES {
            return Err(ExtensionError::Limit);
        }
        Ok(())
    }
    /// Resolve an explicit label, with no implicit default recovery.
    ///
    /// # Errors
    /// Returns `UnknownRoute` when neither label nor explicit default exists.
    pub fn route(&self, label: &str) -> Result<HandlerV1, ExtensionError> {
        self.routes
            .get(label)
            .copied()
            .or(self.default_handler)
            .ok_or(ExtensionError::UnknownRoute)
    }
    /// Stable forward order. Reverse execution reverses this exact sequence.
    #[must_use]
    pub fn ordered(&self) -> Vec<&ExtensionSpecV1> {
        let mut entries: Vec<_> = self.extensions.iter().collect();
        // Stable sort preserves registration order for equal stage/order selectors.
        entries.sort_by_key(|entry| (entry.stage, entry.order));
        entries
    }
    /// Safe selected capabilities, versions and digests, never config values.
    ///
    /// # Errors
    /// Returns serialization failure or invalid configuration.
    pub fn publication(&self) -> Result<serde_json::Value, ExtensionError> {
        self.validate()?;
        let selected = self
            .ordered()
            .into_iter()
            .map(|e| {
                Ok(serde_json::json!({
                    "id": e.id, "implementationVersion": e.implementation_version,
                    "stage": e.stage, "capabilities": e.capabilities, "configDigest": e.config_digest()?,
                    "limits": e.limits,
                }))
            })
            .collect::<Result<Vec<_>, ExtensionError>>()?;
        Ok(
            serde_json::json!({"schemaVersion":1,"sdkAbiCompatible":false,"selected":selected,
            "routes":self.routes,"defaultHandler":self.default_handler,"reverseResponse":self.reverse_response,
            "dataset":self.dataset}),
        )
    }
}
/// Project bounded shared metadata, not the document body or browser state.
///
/// # Errors
/// Rejects unsupported envelopes or oversized metadata before creating a candidate.
pub fn document_item(
    document: &DocumentEnvelopeV1,
    limit: usize,
) -> Result<serde_json::Value, ExtensionError> {
    if document.version != 1
        || document
            .metadata
            .title
            .value
            .as_ref()
            .is_some_and(|s| s.len() > limit)
        || document
            .metadata
            .authors
            .value
            .as_ref()
            .is_some_and(|a| a.len() > 64 || a.iter().any(|s| s.len() > 4096))
    {
        return Err(ExtensionError::Limit);
    }
    let value = serde_json::json!({"title":document.metadata.title.value,
        "authors":document.metadata.authors.value,"language":document.metadata.language.value,
        "extractor":document.extractor,"quality":document.quality.status});
    if json_size(&value)? > limit.min(MAX_EXTENSION_BYTES) {
        return Err(ExtensionError::Limit);
    }
    Ok(value)
}

/// Validate complete content-free attempt receipts before a fenced commit.
/// Empty receipts represent an attempt without configured extensions.
///
/// # Errors
/// Rejects gaps, unbounded data, duplicate terminals and invalid cleanup order.
pub fn validate_extension_receipts(receipts: &[ExtensionReceiptV1]) -> Result<(), ExtensionError> {
    if receipts.is_empty() {
        return Ok(());
    }
    if receipts.len() > 4096 || json_size(&receipts)? > MAX_EXTENSION_BYTES {
        return Err(ExtensionError::Limit);
    }
    let mut expected = 1_u64;
    let mut phase = 0_u8;
    let mut previous_result = ExtensionResultV1::Continue;
    for receipt in receipts {
        if receipt.sequence != expected || receipt.callbacks.len() > MAX_EXTENSIONS {
            return Err(ExtensionError::Rejected);
        }
        expected = expected.checked_add(1).ok_or(ExtensionError::Limit)?;
        let mut seen = BTreeSet::new();
        for callback in &receipt.callbacks {
            if callback.registration >= MAX_EXTENSIONS
                || callback.version != 1
                || !seen.insert(callback.registration)
            {
                return Err(ExtensionError::Rejected);
            }
            if let ExtensionResultV1::Annotation(code) = &callback.result {
                if code.len() > 64 || !crate::request::safe_id(code) {
                    return Err(ExtensionError::Rejected);
                }
            }
        }
        if let ExtensionEventV1::HeadersReceived(facts) = &receipt.event {
            facts.validate()?;
        }
        if matches!(receipt.result, ExtensionResultV1::Annotation(_)) {
            return Err(ExtensionError::Rejected);
        }
        match (&receipt.event, phase) {
            (ExtensionEventV1::Configure, 0) => phase = 1,
            (ExtensionEventV1::Error(_), 1) => phase = 2,
            (ExtensionEventV1::Skipped(_) | ExtensionEventV1::Failed(_), 2) => phase = 3,
            (ExtensionEventV1::Terminal(outcome), 1 | 3) => {
                let expected = match previous_result {
                    ExtensionResultV1::Skip(reason) => ExtensionTerminalV1::Skipped(reason),
                    ExtensionResultV1::Fail(reason) => ExtensionTerminalV1::Failed(reason),
                    _ => ExtensionTerminalV1::Completed,
                };
                if *outcome != expected {
                    return Err(ExtensionError::Rejected);
                }
                phase = 4;
            }
            (ExtensionEventV1::Checkpoint, 4) => phase = 5,
            (ExtensionEventV1::Close, 5) => phase = 6,
            (
                ExtensionEventV1::Configure
                | ExtensionEventV1::Error(_)
                | ExtensionEventV1::Skipped(_)
                | ExtensionEventV1::Failed(_)
                | ExtensionEventV1::Terminal(_)
                | ExtensionEventV1::Checkpoint
                | ExtensionEventV1::Close,
                _,
            ) => return Err(ExtensionError::Rejected),
            (_, 1) => {}
            _ => return Err(ExtensionError::Rejected),
        }
        previous_result = receipt.result.clone();
    }
    if phase != 6 {
        return Err(ExtensionError::Rejected);
    }
    Ok(())
}

/// Count serialized JSON without allocating or cloning a content buffer.
///
/// # Errors
/// Returns serialization failure or an overflow error for an unrepresentable length.
pub fn json_size(value: &impl Serialize) -> Result<usize, ExtensionError> {
    struct Counter(usize);
    impl std::io::Write for Counter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0 = self
                .0
                .checked_add(bytes.len())
                .ok_or_else(|| std::io::Error::other("extension JSON length overflow"))?;
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let mut counter = Counter(0);
    serde_json::to_writer(&mut counter, value)?;
    Ok(counter.0)
}
/// Public compiled registry facts. No worker health or source SDK parity is implied.
#[must_use]
pub fn registry_publication() -> serde_json::Value {
    let configs = [
        ExtensionConfigV1::ReadOnly {},
        ExtensionConfigV1::RequireQuality {},
        ExtensionConfigV1::TrimTitle {},
        ExtensionConfigV1::RequireTitle {},
        ExtensionConfigV1::HeaderPolicy {
            policy: HeaderPolicyV1::default(),
        },
        ExtensionConfigV1::Annotate {
            stage: ExtensionStageV1::Configure,
            code: "annotation".into(),
        },
        ExtensionConfigV1::FailStage {
            stage: ExtensionStageV1::Response,
        },
        ExtensionConfigV1::RejectStage {
            stage: ExtensionStageV1::Item,
        },
    ];
    let mut entries: Vec<_> = configs
        .iter()
        .map(|c| {
            serde_json::json!({"id":c.id(),
        "implementationVersion":"1.0.0","stage":c.stage(),"capabilities":c.capabilities(),
        "inputSchemaVersion":1,"outputSchemaVersion":1})
        })
        .collect();
    entries.push(serde_json::json!({"id":"native.replace_request","implementationVersion":"1.0.0",
        "stage":"before_acquisition","capabilities":["request_proposal"],"inputSchemaVersion":1,"outputSchemaVersion":1}));
    serde_json::json!({"schemaVersion":1,"sdkAbiCompatible":false,"arbitraryCode":false,
        "maxExtensions":MAX_EXTENSIONS,"maxBytes":MAX_EXTENSION_BYTES,"registry":entries})
}
/// Extension refusal without sensitive input values.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExtensionError {
    /// Descriptor not recognized or outside the reviewed capability contract.
    #[error("invalid extension descriptor")]
    InvalidSpec,
    /// Label not configured and no explicit default exists.
    #[error("unknown extension route")]
    UnknownRoute,
    /// Bounded input, output or proposal budget exceeded.
    #[error("extension resource limit exceeded")]
    Limit,
    /// Run or request cancellation observed.
    #[error("extension cancelled")]
    Cancelled,
    /// Cooperative execution deadline expired.
    #[error("extension deadline exceeded")]
    Deadline,
    /// A compiled transform rejected this candidate.
    #[error("extension candidate rejected")]
    Rejected,
    /// A configured fail policy stopped request processing.
    #[error("extension processing failed")]
    Failed,
    /// Native policy denial always wins over later extension results.
    #[error("extension policy denied")]
    PolicyDenied,
    /// Already sealed lifecycle cannot produce more work.
    #[error("extension lifecycle closed")]
    Closed,
    /// CPU task failed without exposing input data.
    #[error("extension task failed")]
    Task,
    /// Canonical serialization failed.
    #[error("extension serialization failed")]
    Serialize(#[from] serde_json::Error),
    /// Canonical configuration digest could not be encoded.
    #[error("extension digest serialization failed")]
    Digest(#[from] ciborium::ser::Error<std::io::Error>),
}
impl crate::Classify for ExtensionError {
    fn class(&self) -> crate::ErrorClass {
        match self {
            Self::PolicyDenied => crate::ErrorClass::PolicyDenied,
            Self::Cancelled | Self::Deadline | Self::Task => crate::ErrorClass::Retryable,
            _ => crate::ErrorClass::Terminal,
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn registry_refuses_unknown_versions_self_grants_and_action_capabilities() {
        let mut spec = ExtensionSpecV1::new(ExtensionConfigV1::TrimTitle {}, 0);
        spec.implementation_version = "2.0.0".into();
        assert!(spec.validate().is_err());
        spec.implementation_version = "1.0.0".into();
        spec.capabilities.insert(ExtensionCapabilityV1::RequestProposal);
        assert!(spec.validate().is_err());
        spec.capabilities = spec.config.capabilities();
        spec.limits.actions = 1;
        assert!(spec.validate().is_err());
    }

    #[test]
    fn registry_preserves_registration_ties_and_immutable_duplicates() {
        let mut pipeline = ExtensionPipelineV1 {
            extensions: vec![
                ExtensionSpecV1::new(ExtensionConfigV1::TrimTitle {}, 0),
                ExtensionSpecV1::new(ExtensionConfigV1::RequireTitle {}, 0),
                ExtensionSpecV1::new(ExtensionConfigV1::ReadOnly {}, 99),
            ],
            ..ExtensionPipelineV1::default()
        };
        pipeline.validate().unwrap();
        assert_eq!(
            pipeline
                .ordered()
                .iter()
                .map(|e| e.id.as_str())
                .collect::<Vec<_>>(),
            ["native.read_only", "native.trim_title", "native.require_title"]
        );
        pipeline
            .extensions
            .push(ExtensionSpecV1::new(ExtensionConfigV1::TrimTitle {}, 1));
        pipeline.validate().unwrap();
    }

    #[test]
    fn declarative_config_rejects_unreviewed_fields() {
        assert!(
            serde_json::from_str::<ExtensionConfigV1>(r#"{"kind":"trim_title","python":"import os"}"#)
                .is_err()
        );
        assert!(serde_json::from_str::<ExtensionPipelineV1>(
            r#"{"version":1,"modulePath":"untrusted.Plugin"}"#
        )
        .is_err());
    }
}
