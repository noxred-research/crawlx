//! Operator-approved proposals: compiled crawl specs and agent plans.
//!
//! A model may *propose*; only an operator holding `approvals:decide` can approve, and the
//! approval is a single-use token bound to the exact digest of the proposal body. Proposals
//! are data in the tenant settings store (no schema of their own); an expired proposal is
//! inert whatever its stored status says, and the token is stored only as a keyed digest.
//! By default the key that created a proposal cannot approve it.

use crate::auth::Principal;
use crate::errors::HttpError;
use crate::state::AppState;
use axum::http::StatusCode;
use crawlx_core::hash::Digest;
use crawlx_core::TenantId;
use rand::rand_core::UnwrapErr;
use rand::rngs::SysRng;
use rand::Rng as _;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use uuid::Uuid;

/// Proposals kept per tenant and kind; the oldest are blanked when a new one is stored.
const KEEP: usize = 64;
/// Largest stored proposal body.
const MAX_BODY_BYTES: usize = 256 * 1024;
/// Prefix of approval tokens.
const TOKEN_PREFIX: &str = "cxap_";
/// Most deviations kept on a plan record.
const MAX_DEVIATIONS: usize = 100;

/// What a proposal is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A compiled crawl specification.
    Spec,
    /// An agent plan.
    Plan,
}

impl Kind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Spec => "spec",
            Self::Plan => "plan",
        }
    }

    const fn label(self) -> &'static str {
        match self {
            Self::Spec => "crawl spec",
            Self::Plan => "agent plan",
        }
    }
}

/// Lifecycle of a proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Waiting for an operator.
    AwaitingApproval,
    /// Approved; the token is unspent.
    Approved,
    /// The token was spent: the spec created its crawl or the plan started its job.
    Consumed,
    /// Withdrawn.
    Cancelled,
}

/// The stored approval. The token itself is never stored.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    token_digest: String,
    /// Key id of the approving operator.
    pub approved_by: String,
    /// Approval time, epoch milliseconds.
    pub approved_at_ms: i64,
    /// Last moment the token may be spent, epoch milliseconds.
    pub expires_at_ms: i64,
}

/// One proposal as stored.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Record {
    /// Identifier.
    pub id: Uuid,
    /// `spec` or `plan`.
    pub kind: String,
    /// Key id of the proposing principal.
    pub created_by: String,
    /// Creation time, epoch milliseconds.
    pub created_at_ms: i64,
    /// Expiry of the proposal, epoch milliseconds.
    pub expires_at_ms: i64,
    /// Digest of [`Self::body`]; the approval binds to it.
    pub digest: String,
    /// Lifecycle state.
    pub status: Status,
    /// The approval, once given.
    pub approval: Option<Approval>,
    /// The proposal itself (compiled spec or plan).
    pub body: Value,
    /// Deviations recorded while executing (out-of-plan calls the run refused).
    #[serde(default)]
    pub deviations: Vec<Value>,
    /// What executing the proposal produced (run id or job id).
    #[serde(default)]
    pub execution: Option<Value>,
}

/// Recursively key-sorted JSON text, the input of every proposal digest.
#[must_use]
pub fn canonical(value: &Value) -> String {
    fn sort(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                let mut out = Map::new();
                for key in keys {
                    if let Some(child) = map.get(key) {
                        out.insert(key.clone(), sort(child));
                    }
                }
                Value::Object(out)
            }
            Value::Array(items) => Value::Array(items.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    sort(value).to_string()
}

/// Digest of a proposal body.
#[must_use]
pub fn body_digest(kind: Kind, body: &Value) -> String {
    Digest::of(
        &format!("crawlx.proposal.{}.v1", kind.as_str()),
        canonical(body).as_bytes(),
    )
    .to_hex()
}

fn key(kind: Kind, id: Uuid) -> String {
    format!("proposal:{}:{id}", kind.as_str())
}

fn index_key(kind: Kind) -> String {
    format!("proposal-index:{}", kind.as_str())
}

fn token_digest(token: &str, proposal_digest: &str) -> String {
    Digest::of(
        "crawlx.proposal.token.v1",
        format!("{token}\n{proposal_digest}").as_bytes(),
    )
    .to_hex()
}

fn new_token() -> String {
    let mut bytes = [0u8; 20];
    UnwrapErr(SysRng).fill_bytes(&mut bytes);
    format!("{TOKEN_PREFIX}{}", hex::encode(bytes))
}

fn now_ms(state: &AppState) -> i64 {
    state.clock.now().timestamp_millis()
}

/// Store a new proposal.
///
/// # Errors
/// `413` for a body over the stored-size ceiling, storage failures.
pub async fn create(
    state: &AppState,
    principal: &Principal,
    kind: Kind,
    body: Value,
) -> Result<Record, HttpError> {
    let encoded = canonical(&body);
    if encoded.len() > MAX_BODY_BYTES {
        return Err(HttpError::payload_too_large(MAX_BODY_BYTES));
    }
    let now = now_ms(state);
    let ttl_ms = i64::try_from(state.ai.proposal_ttl_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    let id = Uuid::now_v7();
    let record = Record {
        id,
        kind: kind.as_str().to_owned(),
        created_by: principal.key_id.to_string(),
        created_at_ms: now,
        expires_at_ms: now.saturating_add(ttl_ms),
        digest: body_digest(kind, &body),
        status: Status::AwaitingApproval,
        approval: None,
        body,
        deviations: Vec::new(),
        execution: None,
    };
    save(state, principal.tenant, kind, &record).await?;
    let intel = &state.repos.intel;
    let mut ids: Vec<String> = intel
        .setting_get(principal.tenant, &index_key(kind))
        .await?
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default();
    ids.push(id.to_string());
    while ids.len() > KEEP {
        let old = ids.remove(0);
        if let Ok(old_id) = old.parse::<Uuid>() {
            intel
                .setting_put(
                    principal.tenant,
                    &key(kind, old_id),
                    Value::Null,
                    state.clock.now(),
                )
                .await?;
        }
    }
    intel
        .setting_put(principal.tenant, &index_key(kind), json!(ids), state.clock.now())
        .await?;
    Ok(record)
}

async fn save(state: &AppState, tenant: TenantId, kind: Kind, record: &Record) -> Result<(), HttpError> {
    let value = serde_json::to_value(record).map_err(|_| HttpError::internal())?;
    state
        .repos
        .intel
        .setting_put(tenant, &key(kind, record.id), value, state.clock.now())
        .await?;
    Ok(())
}

/// Persist a changed record.
///
/// # Errors
/// Storage failures.
pub async fn update(
    state: &AppState,
    tenant: TenantId,
    kind: Kind,
    record: &Record,
) -> Result<(), HttpError> {
    save(state, tenant, kind, record).await
}

/// Load a proposal of the caller's tenant.
///
/// # Errors
/// `404` for a malformed id, an unknown or blanked proposal or another tenant's.
pub async fn load(state: &AppState, tenant: TenantId, kind: Kind, id: &str) -> Result<Record, HttpError> {
    let missing = || HttpError::not_found(kind.label());
    let id: Uuid = id.parse().map_err(|_| missing())?;
    let value = state
        .repos
        .intel
        .setting_get(tenant, &key(kind, id))
        .await?
        .filter(|v| !v.is_null())
        .ok_or_else(missing)?;
    serde_json::from_value(value).map_err(|_| HttpError::internal())
}

/// Whether `record` is past its expiry.
#[must_use]
pub fn is_expired(state: &AppState, record: &Record) -> bool {
    now_ms(state) >= record.expires_at_ms
}

/// The effective state shown to callers: `expired` overrides an unspent status.
#[must_use]
pub fn effective_status(state: &AppState, record: &Record) -> &'static str {
    match record.status {
        Status::Consumed => "consumed",
        Status::Cancelled => "cancelled",
        Status::AwaitingApproval if is_expired(state, record) => "expired",
        Status::Approved
            if record
                .approval
                .as_ref()
                .is_none_or(|a| now_ms(state) >= a.expires_at_ms) =>
        {
            "expired"
        }
        Status::AwaitingApproval => "awaiting_approval",
        Status::Approved => "approved",
    }
}

/// Approve `record` for the operator behind `principal` and return the one-time token.
///
/// # Errors
/// `409` unless the proposal awaits approval, `410` when it expired, `403` when the proposing
/// key approves its own proposal and the policy forbids it.
pub async fn approve(
    state: &AppState,
    principal: &Principal,
    kind: Kind,
    mut record: Record,
) -> Result<(Record, String), HttpError> {
    if record.status != Status::AwaitingApproval {
        return Err(HttpError::invalid_state(format!(
            "the {} is {}, not awaiting approval",
            kind.label(),
            effective_status(state, &record)
        )));
    }
    if is_expired(state, &record) {
        return Err(HttpError::expired(format!(
            "the {} expired before approval",
            kind.label()
        )));
    }
    if record.digest != body_digest(kind, &record.body) {
        tracing::error!(proposal = %record.id, "stored proposal no longer matches its digest");
        return Err(HttpError::internal());
    }
    let approver = principal.key_id.to_string();
    if approver == record.created_by && !state.ai.allow_self_approval {
        return Err(HttpError::compat(
            StatusCode::FORBIDDEN,
            "self_approval_refused",
            "a proposal needs approval from a different API key than the one that created it",
        ));
    }
    let token = new_token();
    let now = now_ms(state);
    let ttl_ms = i64::try_from(state.ai.proposal_ttl_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    record.approval = Some(Approval {
        token_digest: token_digest(&token, &record.digest),
        approved_by: approver,
        approved_at_ms: now,
        expires_at_ms: now.saturating_add(ttl_ms),
    });
    record.status = Status::Approved;
    save(state, principal.tenant, kind, &record).await?;
    Ok((record, token))
}

/// Spend the approval token of `record`: the token must match the digest, the approval must
/// be unspent and unexpired.
///
/// # Errors
/// `409` unless approved, `410` when expired, `403 approval_token_invalid` for a wrong token
/// or a body that no longer matches its digest.
pub async fn consume(
    state: &AppState,
    principal: &Principal,
    kind: Kind,
    mut record: Record,
    token: &str,
) -> Result<Record, HttpError> {
    let invalid = || {
        HttpError::compat(
            StatusCode::FORBIDDEN,
            "approval_token_invalid",
            "the approval token does not match this approved proposal",
        )
    };
    if record.status != Status::Approved {
        return Err(HttpError::invalid_state(format!(
            "the {} is {}, not approved",
            kind.label(),
            effective_status(state, &record)
        )));
    }
    let Some(approval) = record.approval.clone() else {
        return Err(HttpError::invalid_state("the approval is missing"));
    };
    if now_ms(state) >= approval.expires_at_ms {
        return Err(HttpError::expired("the approval expired"));
    }
    if record.digest != body_digest(kind, &record.body)
        || approval.token_digest != token_digest(token, &record.digest)
    {
        return Err(invalid());
    }
    record.status = Status::Consumed;
    save(state, principal.tenant, kind, &record).await?;
    Ok(record)
}

/// The proposal as shown to callers (no token material).
#[must_use]
pub fn view(state: &AppState, record: &Record) -> Value {
    json!({
        "id": record.id,
        "kind": record.kind,
        "status": effective_status(state, record),
        "digest": record.digest,
        "createdAtMs": record.created_at_ms,
        "expiresAtMs": record.expires_at_ms,
        "approval": record.approval.as_ref().map(|a| json!({
            "approvedBy": a.approved_by,
            "approvedAtMs": a.approved_at_ms,
            "expiresAtMs": a.expires_at_ms,
        })),
        "deviations": record.deviations,
        "execution": record.execution,
    })
}

/// Record how an executed plan ended: the job it started and the calls the run refused.
/// Best effort; a storage failure is logged because the job result carries the same facts.
pub async fn note_execution(
    state: &AppState,
    tenant: TenantId,
    plan: Uuid,
    job: Uuid,
    status: &str,
    deviations: &[Value],
) {
    let id = plan.to_string();
    let mut record = match load(state, tenant, Kind::Plan, &id).await {
        Ok(record) => record,
        Err(error) => {
            tracing::warn!(%plan, code = ?error, "plan record unavailable after execution");
            return;
        }
    };
    record.deviations = deviations.iter().take(MAX_DEVIATIONS).cloned().collect();
    record.execution = Some(json!({"jobId": job, "status": status}));
    if let Err(error) = save(state, tenant, Kind::Plan, &record).await {
        tracing::warn!(%plan, code = ?error, "plan record could not be updated after execution");
    }
}
