//! Response bodies of the `agent` endpoints: the job status, the list entry, the canonical trace
//! events and the snapshot envelope.
//!
//! The engine stores one row per step in the trace (kinds `plan`, `search`, `map`, `scrape`,
//! `extract`, `exchange`, `answer`, `error`); [`trace_events`] expands them into the compat API
//! `AgentTraceEvent` shapes (`reasoning.summary`, `tool_call.started`, `tool_call.finished`,
//! `artifact.updated`, `error.occurred`, bracketed by `run.started` and `run.finished`). Every
//! expanded event also carries `seq` (the stored sequence number, the `after` cursor of the trace
//! endpoint) and `kind` (the stored kind).

use crate::intel::agent_spec::MODEL;
use crate::util::{ts, ts_opt};
use crawlx_core::Timestamp;
use crawlx_storage::{JobRecord, JobStatus, Snapshot, TraceEvent};
use serde_json::{json, Map, Value};
use uuid::Uuid;

/// Prefix of the tool names in trace events and `agent.action` webhooks (`mcp__tools__scrape`).
pub const TOOL_PREFIX: &str = "mcp__tools__";

/// Canonical events one stored event expands to, at most.
const EXPANSION: u64 = 4;

/// `producerSequence` of `run.finished`: past every expanded event (the largest integer a JSON
/// consumer reads exactly).
const FINISHED_SEQUENCE: u64 = 9_007_199_254_740_991;

/// A UUID derived from `job` and two counters: stable across reads and processes.
#[must_use]
pub fn derived_uuid(domain: &str, job: Uuid, a: u64, b: u64) -> Uuid {
    let mut h = blake3::Hasher::new_derive_key(domain);
    h.update(job.as_bytes());
    h.update(&a.to_be_bytes());
    h.update(&b.to_be_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&h.finalize().as_bytes()[..16]);
    uuid::Builder::from_random_bytes(bytes).into_uuid()
}

fn put(obj: &mut Map<String, Value>, key: &str, value: Option<&Value>) {
    if let Some(v) = value.filter(|v| !v.is_null()) {
        obj.insert(key.to_owned(), v.clone());
    }
}

/// The body of `GET /agent/{jobId}`.
///
/// `envelope` is the stored result (the job's `result`, or the vault entry of a ZDR run),
/// `resolution` the answer a later turn gave to the pending approval, `expires_at` the end of
/// the retrieval window.
#[must_use]
pub fn status_body(
    job: &JobRecord,
    envelope: Option<&Value>,
    resolution: Option<&Value>,
    expires_at: Timestamp,
) -> Value {
    let req = &job.request;
    let mut body = Map::new();
    body.insert("success".to_owned(), json!(true));
    body.insert("status".to_owned(), json!(job.status.as_str()));
    let e = |k: &str| envelope.and_then(|v| v.get(k));
    put(&mut body, "data", e("data"));
    put(&mut body, "partial", e("partial"));
    put(&mut body, "partialSchemaValid", e("partialSchemaValid"));
    let stop_reason = e("stopReason")
        .cloned()
        .or_else(|| job.stop_reason.as_ref().map(|s| json!(s)));
    put(&mut body, "stopReason", stop_reason.as_ref());
    put(&mut body, "message", e("message"));
    body.insert("model".to_owned(), json!(MODEL));
    put(&mut body, "effort", req.get("effort"));
    let error = if job.status == JobStatus::Failed {
        e("error")
            .cloned()
            .or_else(|| job.error.as_ref().map(|s| json!(s)))
    } else {
        None
    };
    put(&mut body, "error", error.as_ref());
    body.insert("expiresAt".to_owned(), json!(ts(expires_at)));
    body.insert("creditsUsed".to_owned(), json!(job.credits_used));
    body.insert("tokensUsed".to_owned(), json!(job.tokens_used));
    put(&mut body, "threadId", req.get("threadId"));
    put(&mut body, "threadTurn", req.get("threadTurn"));
    put(&mut body, "mode", req.get("mode"));
    put(&mut body, "suggestions", e("suggestions"));
    if let Some(p) = e("pendingApproval") {
        let mut p = p.clone();
        if let (Some(obj), Some(r)) = (p.as_object_mut(), resolution) {
            obj.insert("resolution".to_owned(), r.clone());
        }
        body.insert("pendingApproval".to_owned(), p);
    }
    put(&mut body, "exchange", e("exchange"));
    // present only on runs started from an approved plan (`POST /v1/agent-plans/{id}/execute`)
    put(&mut body, "plan", e("plan"));
    if let Some(w) = req
        .get("warnings")
        .filter(|w| w.as_array().is_some_and(|a| !a.is_empty()))
    {
        body.insert("warnings".to_owned(), w.clone());
    }
    Value::Object(body)
}

/// One entry of `GET /agent` (`agents[]`).
#[must_use]
pub fn list_entry(job: &JobRecord) -> Value {
    let req = &job.request;
    let zdr = req.get("zeroDataRetention").and_then(Value::as_bool) == Some(true);
    let mut options = Map::new();
    if !zdr {
        put(
            &mut options,
            "urls",
            req.get("urls")
                .filter(|u| u.as_array().is_some_and(|a| !a.is_empty())),
        );
        put(&mut options, "prompt", req.get("prompt"));
        put(&mut options, "schema", req.get("schema"));
    }
    options.insert("model".to_owned(), json!(MODEL));
    put(&mut options, "effort", req.get("effort"));
    let hint = if zdr {
        None
    } else {
        req.get("urls")
            .and_then(|u| u.get(0))
            .and_then(Value::as_str)
            .or_else(|| req.get("prompt").and_then(Value::as_str))
            .map(|s| s.chars().take(120).collect::<String>())
    };
    let mut entry = Map::new();
    entry.insert("id".to_owned(), json!(job.id));
    entry.insert("createdAt".to_owned(), json!(ts(job.created_at)));
    if let Some(h) = hint {
        entry.insert("targetHint".to_owned(), json!(h));
    }
    entry.insert("origin".to_owned(), json!("api"));
    entry.insert("settings".to_owned(), json!({}));
    entry.insert("status".to_owned(), json!(job.status.as_str()));
    entry.insert("options".to_owned(), Value::Object(options));
    Value::Object(entry)
}

fn event(job: &JobRecord, e: &TraceEvent, idx: u64, ty: &str, agent_role: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("schemaVersion".to_owned(), json!(1));
    m.insert(
        "eventId".to_owned(),
        json!(derived_uuid("crawlx/agent/event/v1", job.id, e.seq, idx)),
    );
    m.insert("runId".to_owned(), json!(job.id));
    m.insert("occurredAt".to_owned(), json!(ts(e.at)));
    m.insert(
        "producerSequence".to_owned(),
        json!(e
            .seq
            .saturating_mul(EXPANSION)
            .saturating_add(idx)
            .saturating_add(1)),
    );
    m.insert(
        "agent".to_owned(),
        json!({ "id": job.id, "role": agent_role, "name": "agent" }),
    );
    m.insert("type".to_owned(), json!(ty));
    m.insert("seq".to_owned(), json!(e.seq));
    m.insert("kind".to_owned(), json!(e.kind));
    m
}

fn artifact(d: &Value, call: Option<&str>) -> Option<Value> {
    let snapshot = d.get("snapshotId").and_then(Value::as_str)?;
    let mut a = json!({
        "kind": d.get("snapshotKind").and_then(Value::as_str).unwrap_or("json"),
        "artifactId": snapshot,
        "path": d.get("snapshotPath").and_then(Value::as_str).unwrap_or("/workspace/data.json"),
        "snapshotId": snapshot,
        "change": "init",
    });
    if let (Some(obj), Some(c)) = (a.as_object_mut(), call) {
        obj.insert("sourceToolCallId".to_owned(), json!(c));
    }
    Some(a)
}

/// Expand stored events into canonical events. `first_page` adds `run.started`, `last_page` adds
/// `run.finished` for a terminal job.
#[must_use]
pub fn trace_events(job: &JobRecord, stored: &[TraceEvent], first_page: bool, last_page: bool) -> Vec<Value> {
    let mut out = Vec::new();
    if first_page {
        let mut m = Map::new();
        m.insert("schemaVersion".to_owned(), json!(1));
        m.insert(
            "eventId".to_owned(),
            json!(derived_uuid("crawlx/agent/event/v1", job.id, 0, 0)),
        );
        m.insert("runId".to_owned(), json!(job.id));
        m.insert("occurredAt".to_owned(), json!(ts(job.created_at)));
        m.insert("producerSequence".to_owned(), json!(0));
        m.insert(
            "agent".to_owned(),
            json!({ "id": job.id, "role": "system", "name": "run" }),
        );
        m.insert("type".to_owned(), json!("run.started"));
        out.push(Value::Object(m));
    }
    for e in stored {
        let d = &e.data;
        match e.kind.as_str() {
            "plan" => {
                let text = d.get("reasoning").and_then(Value::as_str).map_or_else(
                    || format!("Step {}: {}", d["step"], d["action"].as_str().unwrap_or("?")),
                    str::to_owned,
                );
                let mut m = event(job, e, 0, "reasoning.summary", "orchestrator");
                m.insert("text".to_owned(), json!(text));
                out.push(Value::Object(m));
            }
            "answer" => {
                let mut m = event(job, e, 0, "artifact.updated", "orchestrator");
                if let Some(a) = artifact(d, None) {
                    m.insert("artifact".to_owned(), a);
                }
                out.push(Value::Object(m));
                if let Some(msg) = d.get("message").and_then(Value::as_str) {
                    let mut p = event(job, e, 1, "progress.reported", "orchestrator");
                    p.insert("phase".to_owned(), json!("finalizing"));
                    p.insert("message".to_owned(), json!(msg));
                    out.push(Value::Object(p));
                }
            }
            "error" => {
                let mut m = event(job, e, 0, "error.occurred", "orchestrator");
                m.insert("error".to_owned(), d.clone());
                out.push(Value::Object(m));
            }
            _ => {
                let call = d.get("toolCallId").and_then(Value::as_str).unwrap_or_default();
                let name = format!(
                    "{TOOL_PREFIX}{}",
                    d.get("tool").and_then(Value::as_str).unwrap_or(&e.kind)
                );
                let mut s = event(job, e, 0, "tool_call.started", "orchestrator");
                s.insert("toolCallId".to_owned(), json!(call));
                s.insert("toolName".to_owned(), json!(name));
                s.insert(
                    "parameters".to_owned(),
                    d.get("parameters").cloned().unwrap_or(Value::Null),
                );
                out.push(Value::Object(s));
                let mut f = event(job, e, 1, "tool_call.finished", "orchestrator");
                f.insert("toolCallId".to_owned(), json!(call));
                f.insert("toolName".to_owned(), json!(name));
                f.insert(
                    "result".to_owned(),
                    d.get("result").cloned().unwrap_or(Value::Null),
                );
                put(&mut f, "status", d.get("status"));
                put(&mut f, "creditsUsed", d.get("creditsUsed"));
                out.push(Value::Object(f));
                if let Some(a) = artifact(d, Some(call)) {
                    let mut m = event(job, e, 2, "artifact.updated", "orchestrator");
                    m.insert("artifact".to_owned(), a);
                    out.push(Value::Object(m));
                }
            }
        }
    }
    if last_page && job.status.is_terminal() {
        let (outcome, error) = match job.status {
            JobStatus::Completed => ("succeeded", Value::Null),
            JobStatus::Cancelled => (
                "cancelled",
                json!({ "code": "cancelled", "source": "system", "retryable": false, "message": "The run was cancelled." }),
            ),
            _ if job.stop_reason.as_deref() == Some("credit_limit_reached") => (
                "credit_limit_reached",
                json!({
                    "code": "credit_limit_reached", "source": "billing", "retryable": false,
                    "message": job.error.clone().unwrap_or_default(),
                }),
            ),
            _ => (
                "failed",
                json!({
                    "code": "internal", "source": "agent", "retryable": false,
                    "message": job.error.clone().unwrap_or_default(),
                }),
            ),
        };
        out.push(json!({
            "schemaVersion": 1,
            "eventId": derived_uuid("crawlx/agent/event/v1", job.id, u64::MAX, 0),
            "runId": job.id,
            "occurredAt": ts_opt(job.finished_at.or(Some(job.updated_at))),
            "producerSequence": FINISHED_SEQUENCE,
            "agent": { "id": job.id, "role": "system", "name": "run" },
            "type": "run.finished",
            "outcome": outcome,
            "error": error,
        }));
    }
    out
}

/// The body of `GET /agent/{jobId}/snapshots/{snapshotId}`.
#[must_use]
pub fn snapshot_body(job: Uuid, snap: &Snapshot) -> Value {
    let content = snap.data.get("content").cloned().unwrap_or(Value::Null);
    let text = match (snap.data.get("kind").and_then(Value::as_str), &content) {
        (Some("markdown" | "text" | "html"), Value::String(s)) => s.clone(),
        _ => content.to_string(),
    };
    json!({ "success": true, "id": job, "snapshotId": snap.id, "snapshot": text })
}
