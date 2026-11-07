//! Request model of the Firecrawl v2 `agent` product: the parsed and thread-resolved settings of
//! one run ([`AgentSpec`]) and the persisted conversation state of a thread ([`ThreadState`]).
//!
//! [`RawRequest::parse`] reads the `POST /agent` body strictly (every violation is reported with a
//! JSON-pointer path); [`RawRequest::resolve`] applies the thread inheritance of the docs
//! (`urls`, `schema`, `effort`, `mode`, `location` and `exchange` carry over from the previous
//! turn when omitted; `maxCredits` and `strictConstrainToURLs` do not) and the cross-field rules.

use crate::errors::{Detail, HttpError};
use crate::intel::request::{is_http_url, Body};
use crate::intel::webhook::JobWebhook;
use crate::resources::Warning;
use axum::http::StatusCode;
use jsonschema::Validator;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

/// Longest `prompt` (characters).
pub const MAX_PROMPT_CHARS: usize = 10_000;
/// `maxCredits` when the request sets none.
pub const DEFAULT_MAX_CREDITS: u64 = 2_500;
/// Most `urls` accepted.
pub const MAX_URLS: usize = 100;
/// The only model every run executes on.
pub const MODEL: &str = "spark-2";
/// Deprecated model names that route to [`MODEL`].
pub const DEPRECATED_MODELS: [&str; 2] = ["spark-1-mini", "spark-1-pro"];
/// Event names of `webhook.events`.
pub const WEBHOOK_EVENTS: [&str; 5] = ["started", "action", "completed", "failed", "cancelled"];
/// `exchange.maxCalls` when the request sets none.
pub const DEFAULT_MAX_CALLS: u32 = 16;
/// Largest `exchange.maxCalls`.
pub const MAX_CALLS: u32 = 30;
/// Most pinned `exchange.toolkits`.
pub const MAX_TOOLKITS: usize = 5;
/// Tenant setting (`IntelRepo::setting_get`) that gates zero-data-retention agent runs.
pub const ZDR_SETTING: &str = "zero-data-retention";
/// Most turns a thread keeps (the oldest are dropped).
pub const MAX_THREAD_TURNS: usize = 20;
/// Most gathered pages a thread carries into its next turn.
pub const MAX_THREAD_PAGES: usize = 10;
/// Characters of each gathered page a thread carries.
pub const MAX_THREAD_PAGE_CHARS: usize = 12_000;

const KNOWN: [&str; 17] = [
    "urls",
    "prompt",
    "schema",
    "maxCredits",
    "strictConstrainToURLs",
    "model",
    "effort",
    "webhook",
    "auditMetadata",
    "threatProtection",
    "threadId",
    "mode",
    "zeroDataRetention",
    "location",
    "exchange",
    "integration",
    "origin",
];

/// Reasoning budget (`effort`): bounds the number of steps of a run.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Effort {
    /// 4 steps.
    Low,
    /// 8 steps.
    Medium,
    /// 16 steps.
    High,
}

impl Effort {
    /// Wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }

    /// Steps (LLM decisions) a run may take: low 4, medium 8, high 16.
    #[must_use]
    pub const fn steps(self) -> u32 {
        match self {
            Self::Low => 4,
            Self::Medium => 8,
            Self::High => 16,
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "low" => Some(Self::Low),
            "medium" => Some(Self::Medium),
            "high" => Some(Self::High),
            _ => None,
        }
    }
}

/// Steps of a run that sets no `effort`.
pub const DEFAULT_STEPS: u32 = Effort::Medium.steps();

/// Thread mode.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// Every turn returns the complete structured result in `data`.
    Extract,
    /// A follow-up that needs no new data is answered in `message`.
    Chat,
}

impl Mode {
    /// Wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Extract => "extract",
            Self::Chat => "chat",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "extract" => Some(Self::Extract),
            "chat" => Some(Self::Chat),
            _ => None,
        }
    }
}

/// `exchange.onTermsRequired`.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TermsMode {
    /// Answer with the accepted providers only.
    Skip,
    /// As skip, and end the turn with a `terms` approval.
    Ask,
}

impl TermsMode {
    /// Wire label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Skip => "skip",
            Self::Ask => "ask",
        }
    }
}

/// Resolved `exchange` settings of a turn.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExchangeSpec {
    /// Whether the agent may call providers.
    pub enabled: bool,
    /// Pinned toolkit slugs; empty means every toolkit the tenant can use.
    pub toolkits: Vec<String>,
    /// Most provider calls this turn.
    pub max_calls: u32,
    /// Hold paid calls for approval.
    pub require_approval: bool,
    /// What to do about toolkits whose terms are not accepted.
    pub on_terms_required: TermsMode,
}

impl ExchangeSpec {
    /// Web only.
    #[must_use]
    pub const fn off() -> Self {
        Self {
            enabled: false,
            toolkits: Vec::new(),
            max_calls: DEFAULT_MAX_CALLS,
            require_approval: false,
            on_terms_required: TermsMode::Skip,
        }
    }
}

/// The answer of a turn to the previous turn's `pendingApproval`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Answer {
    /// `exchange.approve`.
    Approve {
        /// The approval answered.
        approval_id: Uuid,
        /// Only these calls; `None` approves all.
        call_ids: Option<Vec<String>>,
        /// Stop asking for the rest of the thread.
        always: bool,
    },
    /// `exchange.decline`.
    Decline {
        /// The approval answered.
        approval_id: Uuid,
    },
}

impl Answer {
    /// The approval this answers.
    #[must_use]
    pub const fn approval_id(&self) -> Uuid {
        match self {
            Self::Approve { approval_id, .. } | Self::Decline { approval_id } => *approval_id,
        }
    }
}

/// One turn of a thread.
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct TurnRecord {
    /// 1-based turn number.
    pub turn: u32,
    /// Job of the turn.
    pub job: Uuid,
    /// The turn's prompt.
    pub prompt: String,
    /// `processing`, `completed`, `failed` or `cancelled`.
    pub status: String,
    /// Result of a completed turn.
    pub data: Option<Value>,
    /// Best-effort result of a failed turn.
    pub partial: Option<Value>,
    /// The agent's note.
    pub message: Option<String>,
    /// Stop reason of a failed turn.
    pub stop_reason: Option<String>,
    /// Failure text.
    pub error: Option<String>,
}

/// A gathered page a thread carries between turns.
#[derive(Clone, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
pub struct PageNote {
    /// Page URL.
    pub url: String,
    /// Page markdown (cut to [`MAX_THREAD_PAGE_CHARS`]).
    pub markdown: String,
}

/// Persisted state of a thread (`IntelRepo::thread_put`).
#[derive(Clone, PartialEq, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ThreadState {
    /// Turns so far, oldest first.
    pub turns: Vec<TurnRecord>,
    /// `urls` of the latest turn.
    pub urls: Vec<String>,
    /// `schema` of the latest turn.
    pub schema: Option<Value>,
    /// `effort` of the latest turn.
    pub effort: Option<Effort>,
    /// `mode` of the latest turn.
    pub mode: Option<Mode>,
    /// `location.country` of the latest turn.
    pub location: Option<String>,
    /// `exchange` settings of the latest turn.
    pub exchange: Option<ExchangeSpec>,
    /// `exchange.approve.always` was answered.
    pub always_approve: bool,
    /// Toolkits whose terms offer was declined (never offered again).
    pub declined_terms: Vec<String>,
    /// The approval the latest turn ended on, until answered.
    pub pending_approval: Option<Value>,
    /// Answers of earlier approvals by approval id.
    pub resolutions: BTreeMap<String, Value>,
    /// Pages gathered so far (bounded).
    pub pages: Vec<PageNote>,
}

/// The settings of one run after thread inheritance.
#[derive(Clone, PartialEq, Debug)]
pub struct AgentSpec {
    /// `urls`.
    pub urls: Vec<String>,
    /// `prompt`.
    pub prompt: String,
    /// `schema`.
    pub schema: Option<Value>,
    /// `maxCredits`.
    pub max_credits: u64,
    /// `strictConstrainToURLs`.
    pub strict: bool,
    /// `effort` as set (inherited or sent).
    pub effort: Option<Effort>,
    /// Effective mode.
    pub mode: Mode,
    /// Upper-case ISO country of `location`.
    pub location: Option<String>,
    /// Effective exchange settings.
    pub exchange: ExchangeSpec,
    /// Answer to the previous turn's approval.
    pub answer: Option<Answer>,
    /// Zero data retention.
    pub zdr: bool,
    /// `webhook`.
    pub webhook: Option<JobWebhook>,
    /// Thread the run belongs to (`None` for ZDR runs).
    pub thread_id: Option<Uuid>,
    /// 1-based turn in the thread.
    pub thread_turn: u32,
    /// Warnings of the request.
    pub warnings: Vec<Warning>,
}

impl AgentSpec {
    /// Steps the run may take.
    #[must_use]
    pub const fn steps(&self) -> u32 {
        match self.effort {
            Some(e) => e.steps(),
            None => DEFAULT_STEPS,
        }
    }

    /// The job's stored `request` body. A ZDR run keeps no prompt, URLs, schema or webhook:
    /// only the billing and status metadata.
    #[must_use]
    pub fn stored_request(&self) -> Value {
        if self.zdr {
            return json!({
                "zeroDataRetention": true,
                "model": MODEL,
                "effort": self.effort.map(Effort::as_str),
                "mode": self.mode.as_str(),
                "maxCredits": self.max_credits,
            });
        }
        json!({
            "urls": self.urls,
            "prompt": self.prompt,
            "schema": self.schema,
            "maxCredits": self.max_credits,
            "strictConstrainToURLs": self.strict,
            "model": MODEL,
            "effort": self.effort.map(Effort::as_str),
            "mode": self.mode.as_str(),
            "location": self.location.as_ref().map(|c| json!({ "country": c })),
            "exchange": self.exchange,
            "webhook": self.webhook.as_ref().map(JobWebhook::to_value),
            "zeroDataRetention": false,
            "threadId": self.thread_id,
            "threadTurn": self.thread_turn,
            "warnings": self.warnings,
        })
    }
}

/// Fields of `exchange` as sent.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
struct RawExchange {
    enabled: Option<bool>,
    toolkits: Option<Vec<String>>,
    max_calls: Option<u32>,
    require_approval: Option<bool>,
    on_terms_required: Option<TermsMode>,
    approve: Option<Answer>,
    decline: Option<Answer>,
}

/// A request body as sent, before thread inheritance.
#[derive(Clone, Debug)]
pub struct RawRequest {
    prompt: String,
    urls: Option<Vec<String>>,
    schema: Option<Value>,
    max_credits: u64,
    strict: Option<bool>,
    effort: Option<Effort>,
    webhook: Option<JobWebhook>,
    thread_id: Option<Uuid>,
    mode: Option<Mode>,
    zdr: Option<bool>,
    location: Option<String>,
    exchange: Option<RawExchange>,
    warnings: Vec<Warning>,
}

fn parse_uuid(b: &mut Body<'_>, key: &str, text: &str) -> Option<Uuid> {
    match Uuid::parse_str(text) {
        Ok(u) => Some(u),
        Err(_) => {
            b.fail(key, "invalid", "expected a UUID");
            None
        }
    }
}

fn parse_location(b: &mut Body<'_>, v: &Value) -> Option<String> {
    let Some(obj) = v.as_object() else {
        b.fail("location", "invalid_type", "expected an object");
        return None;
    };
    for k in obj.keys().filter(|k| k.as_str() != "country") {
        b.fail(
            &format!("location/{k}"),
            "unsupported",
            "location only accepts `country`",
        );
    }
    let Some(country) = obj.get("country").and_then(Value::as_str) else {
        b.fail("location/country", "required", "country is required");
        return None;
    };
    if country.len() == 2 && country.chars().all(|c| c.is_ascii_alphabetic()) {
        Some(country.to_ascii_uppercase())
    } else {
        b.fail(
            "location/country",
            "invalid",
            "country must be an ISO 3166-1 alpha-2 code (special values such as us-generic are rejected)",
        );
        None
    }
}

fn parse_answer(b: &mut Body<'_>, key: &str, v: &Value, approve: bool) -> Option<Answer> {
    let Some(obj) = v.as_object() else {
        b.fail(&format!("exchange/{key}"), "invalid_type", "expected an object");
        return None;
    };
    let path = format!("exchange/{key}/approvalId");
    let id = match obj.get("approvalId").and_then(Value::as_str) {
        Some(s) => match Uuid::parse_str(s) {
            Ok(u) => u,
            Err(_) => {
                b.fail(&path, "invalid", "approvalId must be a UUID");
                return None;
            }
        },
        None => {
            b.fail(&path, "required", "approvalId is required");
            return None;
        }
    };
    if !approve {
        return Some(Answer::Decline { approval_id: id });
    }
    let call_ids = match obj.get("callIds").filter(|c| !c.is_null()) {
        None => None,
        Some(c) => {
            let list: Option<Vec<String>> = c.as_array().and_then(|a| {
                a.iter()
                    .map(|x| x.as_str().map(str::to_owned))
                    .collect::<Option<Vec<_>>>()
            });
            match list {
                Some(l) if l.len() <= 64 => Some(l),
                _ => {
                    b.fail(
                        "exchange/approve/callIds",
                        "invalid",
                        "expected an array of at most 64 strings",
                    );
                    None
                }
            }
        }
    };
    let always = obj.get("always").and_then(Value::as_bool).unwrap_or(false);
    Some(Answer::Approve {
        approval_id: id,
        call_ids,
        always,
    })
}

fn parse_exchange(b: &mut Body<'_>, v: &Value) -> Option<RawExchange> {
    let Some(obj) = v.as_object() else {
        b.fail("exchange", "invalid_type", "expected an object");
        return None;
    };
    let mut out = RawExchange::default();
    if let Some(e) = obj.get("enabled").filter(|e| !e.is_null()) {
        out.enabled = e.as_bool().or_else(|| {
            b.fail("exchange/enabled", "invalid_type", "expected a boolean");
            None
        });
    }
    if let Some(t) = obj.get("toolkits").filter(|t| !t.is_null()) {
        let list: Option<Vec<String>> = t.as_array().and_then(|a| {
            a.iter()
                .map(|x| {
                    x.as_str()
                        .filter(|s| !s.is_empty() && s.len() <= 64)
                        .map(str::to_owned)
                })
                .collect::<Option<Vec<_>>>()
        });
        match list {
            Some(l) if l.len() <= MAX_TOOLKITS => out.toolkits = Some(l),
            Some(_) => b.fail(
                "exchange/toolkits",
                "out_of_range",
                format!("at most {MAX_TOOLKITS} toolkits"),
            ),
            None => b.fail(
                "exchange/toolkits",
                "invalid_type",
                "expected an array of provider slugs",
            ),
        }
    }
    if let Some(m) = obj.get("maxCalls").filter(|m| !m.is_null()) {
        match m
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| (1..=MAX_CALLS).contains(n))
        {
            Some(n) => out.max_calls = Some(n),
            None => b.fail(
                "exchange/maxCalls",
                "out_of_range",
                format!("expected 1 to {MAX_CALLS}"),
            ),
        }
    }
    if let Some(r) = obj.get("requireApproval").filter(|r| !r.is_null()) {
        out.require_approval = r.as_bool().or_else(|| {
            b.fail("exchange/requireApproval", "invalid_type", "expected a boolean");
            None
        });
    }
    if let Some(t) = obj.get("onTermsRequired").filter(|t| !t.is_null()) {
        match t.as_str() {
            Some("skip") => out.on_terms_required = Some(TermsMode::Skip),
            Some("ask") => out.on_terms_required = Some(TermsMode::Ask),
            _ => b.fail("exchange/onTermsRequired", "invalid", "expected `skip` or `ask`"),
        }
    }
    if let Some(a) = obj.get("approve").filter(|a| !a.is_null()) {
        out.approve = parse_answer(b, "approve", a, true);
    }
    if let Some(d) = obj.get("decline").filter(|d| !d.is_null()) {
        out.decline = parse_answer(b, "decline", d, false);
    }
    Some(out)
}

fn warn(code: &str, path: &str, message: &str) -> Warning {
    Warning::new(code, path, message)
}

/// A fractional `maxCredits` (Firecrawl types it `number`) rounded down; `None` outside
/// `1..=1e12`.
#[allow(
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    reason = "the value is finite and within 1..=1e12 before the cast"
)]
fn credits_from_float(f: f64) -> Option<u64> {
    (f.is_finite() && (1.0..=1.0e12).contains(&f)).then(|| f.floor() as u64)
}

impl RawRequest {
    /// Read the `POST /agent` body.
    ///
    /// # Errors
    /// `422 validation_failed` listing every malformed field; the `webhook` member is checked
    /// first and reported alone.
    pub fn parse(body: &Value) -> Result<Self, HttpError> {
        let mut b = Body::new(body)?;
        let mut warnings = Vec::new();
        let webhook = JobWebhook::parse(b.raw("webhook"), "/webhook", &WEBHOOK_EVENTS)?;
        let prompt = b.required_string("prompt", MAX_PROMPT_CHARS);
        let mut urls = b.strings("urls", MAX_URLS, 2_048);
        if let Some(list) = &urls {
            for (i, u) in list.iter().enumerate() {
                if !is_http_url(u) {
                    b.fail(
                        &format!("urls/{i}"),
                        "invalid",
                        "expected an absolute http(s) URL",
                    );
                }
            }
            if list.is_empty() {
                urls = None;
            }
        }
        let schema = b.object("schema").cloned();
        let max_credits = match b.raw("maxCredits") {
            None => DEFAULT_MAX_CREDITS,
            Some(v) => v
                .as_u64()
                .or_else(|| v.as_f64().and_then(credits_from_float))
                .filter(|n| *n >= 1)
                .unwrap_or_else(|| {
                    b.fail("maxCredits", "out_of_range", "expected a number of at least 1");
                    DEFAULT_MAX_CREDITS
                }),
        };
        let strict = b.boolean("strictConstrainToURLs");
        match b.string("model", 32).as_deref() {
            None | Some(MODEL) => {}
            Some(m) if DEPRECATED_MODELS.contains(&m) => warnings.push(warn(
                "model_deprecated",
                "/model",
                &format!("model `{m}` is deprecated and was routed to `{MODEL}`"),
            )),
            Some(_) => b.fail(
                "model",
                "invalid",
                "expected `spark-2`, `spark-1-mini` or `spark-1-pro`",
            ),
        }
        let effort = b.string("effort", 16).and_then(|s| {
            Effort::parse(&s).or_else(|| {
                b.fail("effort", "invalid", "expected `low`, `medium` or `high`");
                None
            })
        });
        let thread_id = b
            .string("threadId", 64)
            .and_then(|s| parse_uuid(&mut b, "threadId", &s));
        let mode = b.string("mode", 16).and_then(|s| {
            Mode::parse(&s).or_else(|| {
                b.fail("mode", "invalid", "expected `extract` or `chat`");
                None
            })
        });
        let zdr = b.boolean("zeroDataRetention");
        let location = b.raw("location").and_then(|v| parse_location(&mut b, v));
        let exchange = b.raw("exchange").and_then(|v| parse_exchange(&mut b, v));
        if let Some(a) = b.raw("auditMetadata") {
            match a.get("username").and_then(Value::as_str) {
                Some(u) if u.len() <= 1_024 => warnings.push(warn(
                    "audit_metadata_ignored",
                    "/auditMetadata",
                    "auditMetadata is accepted and ignored: crawlx has no SIEM log sink",
                )),
                _ => b.fail(
                    "auditMetadata/username",
                    "required",
                    "username is required (at most 1024 characters)",
                ),
            }
        }
        if b.raw("threatProtection").is_some() {
            warnings.push(warn(
                "unsupported_option",
                "/threatProtection",
                "threatProtection is not supported and was ignored",
            ));
        }
        for k in b.unknown_keys(&KNOWN) {
            warnings.push(warn(
                "unsupported_option",
                &format!("/{k}"),
                &format!("option `{k}` is not supported and was ignored"),
            ));
        }
        b.finish()?;
        Ok(Self {
            prompt: prompt.unwrap_or_default(),
            urls,
            schema,
            max_credits,
            strict,
            effort,
            webhook,
            thread_id,
            mode,
            zdr,
            location,
            exchange,
            warnings,
        })
    }

    /// The `threadId` the request continues.
    #[must_use]
    pub const fn thread_id(&self) -> Option<Uuid> {
        self.thread_id
    }

    /// Whether the request asks for zero data retention.
    #[must_use]
    pub fn wants_zdr(&self) -> bool {
        self.zdr == Some(true)
    }

    /// Apply thread inheritance and the cross-field rules.
    ///
    /// `thread` is the stored state of `threadId` (`None` for a new thread), `zdr_forced` says
    /// the tenant has zero data retention forced on, `thread_id` is the thread the run belongs
    /// to (`None` for ZDR runs).
    ///
    /// # Errors
    /// `422 validation_failed` for a schema that does not compile, `strictConstrainToURLs`
    /// without URLs, `exchange.requireApproval` without `mode: "chat"`, and `exchange.approve` /
    /// `decline` that are both sent or have no thread.
    pub fn resolve(
        self,
        thread: Option<&ThreadState>,
        zdr_forced: bool,
        thread_id: Option<Uuid>,
    ) -> Result<(AgentSpec, Option<Arc<Validator>>), HttpError> {
        let mut details: Vec<Detail> = Vec::new();
        let zdr = zdr_forced || self.wants_zdr();
        let urls = self
            .urls
            .clone()
            .or_else(|| thread.map(|t| t.urls.clone()))
            .unwrap_or_default();
        let schema = self
            .schema
            .clone()
            .or_else(|| thread.and_then(|t| t.schema.clone()));
        let effort = self.effort.or_else(|| thread.and_then(|t| t.effort));
        let mode = self
            .mode
            .or_else(|| thread.and_then(|t| t.mode))
            .unwrap_or(Mode::Extract);
        let location = self
            .location
            .clone()
            .or_else(|| thread.and_then(|t| t.location.clone()));
        let strict = self.strict.unwrap_or(false);
        if strict && urls.is_empty() {
            details.push(Detail::new(
                "/strictConstrainToURLs",
                "invalid",
                "strictConstrainToURLs needs a non-empty urls list",
            ));
        }
        let inherited = thread.and_then(|t| t.exchange.clone());
        let (exchange, answer) = match &self.exchange {
            None => (inherited.unwrap_or_else(ExchangeSpec::off), None),
            Some(raw) => {
                let spec = ExchangeSpec {
                    enabled: raw.enabled.unwrap_or(true),
                    toolkits: raw
                        .toolkits
                        .clone()
                        .or_else(|| inherited.as_ref().map(|i| i.toolkits.clone()))
                        .unwrap_or_default(),
                    max_calls: raw.max_calls.unwrap_or(DEFAULT_MAX_CALLS),
                    require_approval: raw.require_approval.unwrap_or(false),
                    on_terms_required: raw
                        .on_terms_required
                        .or_else(|| inherited.as_ref().map(|i| i.on_terms_required))
                        .unwrap_or(TermsMode::Skip),
                };
                if raw.approve.is_some() && raw.decline.is_some() {
                    details.push(Detail::new(
                        "/exchange/decline",
                        "conflict",
                        "send either exchange.approve or exchange.decline, not both",
                    ));
                }
                if (raw.approve.is_some() || raw.decline.is_some()) && self.thread_id.is_none() {
                    details.push(Detail::new(
                        "/exchange/approve",
                        "required",
                        "answering an approval needs threadId",
                    ));
                }
                (spec, raw.approve.clone().or_else(|| raw.decline.clone()))
            }
        };
        if exchange.require_approval && self.mode != Some(Mode::Chat) {
            details.push(Detail::new(
                "/exchange/requireApproval",
                "invalid",
                "exchange.requireApproval needs mode \"chat\" on the same request",
            ));
        }
        let validator = match &schema {
            Some(s) => match jsonschema::validator_for(s) {
                Ok(v) => Some(Arc::new(v)),
                Err(e) => {
                    details.push(Detail::new(
                        "/schema",
                        "invalid_schema",
                        format!("Invalid JSON schema: {e}"),
                    ));
                    None
                }
            },
            None => None,
        };
        if !details.is_empty() {
            return Err(HttpError::validation(details));
        }
        let thread_turn = thread.map_or(1, |t| t.turns.last().map_or(0, |x| x.turn).saturating_add(1));
        Ok((
            AgentSpec {
                urls,
                prompt: self.prompt,
                schema,
                max_credits: self.max_credits,
                strict,
                effort,
                mode,
                location,
                exchange,
                answer,
                zdr,
                webhook: self.webhook,
                thread_id: if zdr { None } else { thread_id },
                thread_turn: if zdr { 1 } else { thread_turn },
                warnings: self.warnings,
            },
            validator,
        ))
    }
}

/// `400 zdr_threads_unsupported`.
#[must_use]
pub fn zdr_threads_unsupported() -> HttpError {
    HttpError::compat(
        StatusCode::BAD_REQUEST,
        "zdr_threads_unsupported",
        "Agent threads are not supported with zero data retention.",
    )
}

/// `400 zdr_not_enabled`.
#[must_use]
pub fn zdr_not_enabled() -> HttpError {
    HttpError::compat(
        StatusCode::BAD_REQUEST,
        "zdr_not_enabled",
        "Zero Data Retention (ZDR) for agent runs requires both scrape ZDR and search ZDR to be enabled for your team.",
    )
}

/// `410 zdr_expired`.
#[must_use]
pub fn zdr_expired() -> HttpError {
    HttpError::compat(
        StatusCode::GONE,
        "zdr_expired",
        "The result of this zero-data-retention run was deleted after the 24-hour retrieval window.",
    )
}

/// A tenant's ZDR switches, from the `zero-data-retention` setting
/// (`{"scrape": bool, "search": bool, "forced": bool}`); every switch defaults to the
/// self-host behaviour: scrape and search ZDR on, not forced.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ZdrPolicy {
    /// Scrape ZDR is enabled.
    pub scrape: bool,
    /// Search ZDR is enabled.
    pub search: bool,
    /// Every run uses ZDR.
    pub forced: bool,
}

impl ZdrPolicy {
    /// Read the setting value (`None` for an unset setting).
    #[must_use]
    pub fn from_setting(value: Option<&Value>) -> Self {
        let flag = |k: &str, default: bool| {
            value
                .and_then(|v| v.get(k))
                .and_then(Value::as_bool)
                .unwrap_or(default)
        };
        Self {
            scrape: flag("scrape", true),
            search: flag("search", true),
            forced: flag("forced", false),
        }
    }

    /// Whether ZDR runs are available.
    #[must_use]
    pub const fn available(self) -> bool {
        self.scrape && self.search
    }
}
