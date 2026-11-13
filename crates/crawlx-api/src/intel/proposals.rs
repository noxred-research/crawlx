//! Operator-approved proposals: compiled crawl specs and agent plans.
//!
//! A model may *propose*; only an operator holding `approvals:decide` can approve, and the
//! approval is a single-use token bound to the exact digest of the proposal body. Proposals
//! are data in the tenant settings store (no schema of their own); an expired proposal is
//! inert whatever its stored status says, and the token is stored only as a keyed digest.
//! By default the key that created a proposal cannot approve it.
//!
//! Every state change that must happen once (approve, spend, cancel) first takes an atomic claim
//! row (`setting_put_if_absent`), so concurrent callers, and a spend racing a cancel, produce
//! exactly one winner; the record is only written by the winner.

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

fn prefix(kind: Kind) -> String {
    format!("proposal:{}:", kind.as_str())
}

fn claim_key(kind: Kind, what: &str, id: Uuid) -> String {
    format!("proposal-{what}:{}:{id}", kind.as_str())
}

fn secret_key(kind: Kind, id: Uuid) -> String {
    format!("proposal-secret:{}:{id}", kind.as_str())
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

/// Live (awaiting or approved, unexpired) proposals one API key may hold per kind.
pub const MAX_LIVE_PER_KEY: usize = 32;
/// Finished proposals (expired, consumed or cancelled) kept per tenant and kind.
const KEEP_FINISHED: usize = 64;
/// Records read when counting live proposals and choosing what to evict.
const LIST_LIMIT: u32 = 1000;

/// Store a new proposal. At most [`MAX_LIVE_PER_KEY`] live proposals of a kind may exist per API
/// key; finished ones beyond [`KEEP_FINISHED`] are evicted oldest first, never live ones.
///
/// # Errors
/// `413` for a body over the stored-size ceiling, `429 proposal_quota` above the live cap,
/// storage failures.
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
    let creator = principal.key_id.to_string();
    let existing = list_records(state, principal.tenant, kind).await?;
    let live = existing
        .iter()
        .filter(|r| r.created_by == creator && is_live(state, r))
        .count();
    if live >= MAX_LIVE_PER_KEY {
        return Err(HttpError::compat(
            StatusCode::TOO_MANY_REQUESTS,
            "proposal_quota",
            format!(
                "this API key already holds {MAX_LIVE_PER_KEY} live {}s; cancel or wait for them to expire",
                kind.label()
            ),
        ));
    }
    let ttl_ms = i64::try_from(state.ai.proposal_ttl_secs.saturating_mul(1000)).unwrap_or(i64::MAX);
    let id = Uuid::now_v7();
    let record = Record {
        id,
        kind: kind.as_str().to_owned(),
        created_by: creator,
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
    let finished: Vec<&Record> = existing.iter().filter(|r| !is_live(state, r)).collect();
    if finished.len() > KEEP_FINISHED {
        for old in finished.iter().take(finished.len() - KEEP_FINISHED) {
            remove(state, principal.tenant, kind, old.id).await?;
        }
    }
    Ok(record)
}

/// Every stored proposal of `kind` of the tenant, oldest first (ids are time-ordered).
async fn list_records(state: &AppState, tenant: TenantId, kind: Kind) -> Result<Vec<Record>, HttpError> {
    let rows = state
        .repos
        .intel
        .setting_list_prefix(tenant, &prefix(kind), LIST_LIMIT)
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|(_, v)| serde_json::from_value::<Record>(v).ok())
        .collect())
}

/// Whether the proposal can still be approved or spent.
fn is_live(state: &AppState, record: &Record) -> bool {
    matches!(effective_status(state, record), "awaiting_approval" | "approved")
}

async fn remove(state: &AppState, tenant: TenantId, kind: Kind, id: Uuid) -> Result<(), HttpError> {
    let intel = &state.repos.intel;
    for key in [
        key(kind, id),
        claim_key(kind, "approve", id),
        claim_key(kind, "claim", id),
        secret_key(kind, id),
    ] {
        intel.setting_delete(tenant, &key).await?;
    }
    Ok(())
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

/// Persist a changed record. Only the caller that won the claim for the transition may call it.
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

/// Keep a server-side secret companion of a proposal (for example the unredacted configuration
/// of a spec). It is never returned, digested or listed, and is deleted with the proposal.
///
/// # Errors
/// Storage failures.
pub async fn put_secret(
    state: &AppState,
    tenant: TenantId,
    kind: Kind,
    id: Uuid,
    value: Value,
) -> Result<(), HttpError> {
    state
        .repos
        .intel
        .setting_put(tenant, &secret_key(kind, id), value, state.clock.now())
        .await?;
    Ok(())
}

/// The secret companion stored by [`put_secret`].
///
/// # Errors
/// `404` when it is gone (the proposal was evicted), storage failures.
pub async fn get_secret(
    state: &AppState,
    tenant: TenantId,
    kind: Kind,
    id: Uuid,
) -> Result<Value, HttpError> {
    state
        .repos
        .intel
        .setting_get(tenant, &secret_key(kind, id))
        .await?
        .ok_or_else(|| HttpError::not_found(kind.label()))
}

/// Load a proposal of the caller's tenant, with the winner of any terminal claim applied.
///
/// # Errors
/// `404` for a malformed id, an unknown proposal or another tenant's.
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
    let mut record: Record = serde_json::from_value(value).map_err(|_| HttpError::internal())?;
    if let Some(claim) = state
        .repos
        .intel
        .setting_get(tenant, &claim_key(kind, "claim", id))
        .await?
    {
        match claim.get("by").and_then(Value::as_str) {
            Some("consumed") => record.status = Status::Consumed,
            Some("cancelled") => record.status = Status::Cancelled,
            _ => {}
        }
    }
    Ok(record)
}

async fn claim(
    state: &AppState,
    tenant: TenantId,
    kind: Kind,
    what: &str,
    id: Uuid,
    by: &str,
) -> Result<bool, HttpError> {
    Ok(state
        .repos
        .intel
        .setting_put_if_absent(
            tenant,
            &claim_key(kind, what, id),
            json!({"by": by, "atMs": now_ms(state)}),
            state.clock.now(),
        )
        .await?)
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
    // one approver wins; a concurrent approval would otherwise silently replace the token the
    // first operator was handed
    if !claim(
        state,
        principal.tenant,
        kind,
        "approve",
        record.id,
        &principal.key_id.to_string(),
    )
    .await?
    {
        return Err(HttpError::invalid_state(format!(
            "the {} was approved by another request",
            kind.label()
        )));
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
    // The single-use spend: exactly one concurrent caller (and no cancel) takes the claim.
    if !claim(state, principal.tenant, kind, "claim", record.id, "consumed").await? {
        return Err(HttpError::invalid_state(format!(
            "the {} was already spent or cancelled",
            kind.label()
        )));
    }
    record.status = Status::Consumed;
    save(state, principal.tenant, kind, &record).await?;
    Ok(record)
}

/// Give a spent approval back after the action it authorized did not start. Only the caller
/// that holds the spend (it just got `Ok` from [`consume`]) may call this.
///
/// # Errors
/// Storage failures.
pub async fn release(
    state: &AppState,
    tenant: TenantId,
    kind: Kind,
    mut record: Record,
) -> Result<(), HttpError> {
    state
        .repos
        .intel
        .setting_delete(tenant, &claim_key(kind, "claim", record.id))
        .await?;
    record.status = Status::Approved;
    save(state, tenant, kind, &record).await
}

/// Cancel an unspent proposal. Races with [`consume`] on the same claim: whichever takes it
/// first wins and the other gets `409`.
///
/// # Errors
/// `409` once the proposal was spent (or by a concurrent spend).
pub async fn cancel(
    state: &AppState,
    tenant: TenantId,
    kind: Kind,
    mut record: Record,
) -> Result<Record, HttpError> {
    if record.status == Status::Cancelled {
        return Ok(record);
    }
    if record.status == Status::Consumed
        || !claim(state, tenant, kind, "claim", record.id, "cancelled").await?
    {
        return Err(HttpError::invalid_state(format!(
            "the {} was already executed",
            kind.label()
        )));
    }
    record.status = Status::Cancelled;
    save(state, tenant, kind, &record).await?;
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
