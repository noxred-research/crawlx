//! OpenAPI 3.1 description served at `GET /v1/openapi.json`: operation ids, scopes and security
//! are listed here, the request and response schemas of the facade operations are generated from
//! Rust types in [`crate::openapi_schemas`].

use crate::openapi_schemas::{self, Schemas};
use serde_json::{json, Map, Value};

/// One operation: `(method, path, operationId, summary, scope, success status)`.
pub type Operation = (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
);

/// Every operation of the document: the native and facade-crawl rows below, then the rows each
/// compat route module exports as its own `OPERATIONS`.
fn all_operations() -> impl Iterator<Item = &'static Operation> {
    use crate::routes::{
        compat_agent, compat_crawl, compat_extract, compat_map, compat_monitor, compat_parse, compat_scrape,
        compat_search, compat_team, compat_ws,
    };
    OPERATIONS
        .iter()
        .chain(compat_crawl::OPERATIONS)
        .chain(compat_map::OPERATIONS)
        .chain(compat_scrape::OPERATIONS)
        .chain(compat_search::OPERATIONS)
        .chain(compat_extract::OPERATIONS)
        .chain(compat_agent::OPERATIONS)
        .chain(compat_parse::OPERATIONS)
        .chain(compat_monitor::OPERATIONS)
        .chain(compat_team::OPERATIONS)
        .chain(compat_ws::OPERATIONS)
}

const OPERATIONS: &[Operation] = &[
    (
        "post",
        "/v1/crawls/{id}/login-flows",
        "uploadLoginFlow",
        "Upload exact Recorder or explicit flow JSON on an existing source run; requires crawls:write AND crawls:read. Rejects literal credentials, secrets, ZDR and expired sources before object creation. Returns a readable Content reference and source-run loginPlan descriptor; the descriptor grants no authority and does not mutate target configuration",
        "crawls:write",
        "201",
    ),
    (
        "get",
        "/v1/capabilities/acquisition",
        "getAcquisitionCapabilities",
        "Fresh worker-reported acquisition capabilities; heartbeat is not a future health guarantee",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/capabilities/extensions",
        "getExtensionCapabilities",
        "Reviewed compiled extension registry, schemas and capability ceilings",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/extensions",
        "getRunExtensions",
        "Effective reviewed extension pipeline and configuration digests",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/interactive-profiles/ui",
        "getInteractiveProfileUi",
        "Data-free loopback-only profile control shell; controls require authentication and the exact shared local worker registry",
        "",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/interactive-profiles/{session}/start",
        "startInteractiveProfile",
        "Start explicitly consented local profile control under exact generation and leaseFence; Origin and X-CrawlX-Interactive required",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/interactive-profiles/{session}/status",
        "getInteractiveProfileStatus",
        "Read local control status after live ownership and Origin checks; no browser or secret contents",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/interactive-profiles/{session}/input",
        "inputInteractiveProfile",
        "Propose bounded typed input through fresh target, safety, approval and journal admission; never raw control protocol",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/interactive-profiles/{session}/finish",
        "finishInteractiveProfile",
        "Commit encrypted structured storage and confirm owned browser cleanup before reporting success",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/interactive-profiles/{session}/cancel",
        "cancelInteractiveProfile",
        "Cancel exact local session scope without retaining profile bytes",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/sessions/{session}/screencast",
        "subscribeInteractiveSuppression",
        "Explicit capture/privacy consent returns bounded ephemeral SSE suppression statuses; unproven pixel privacy prevents capture",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/datasets",
        "listDatasets",
        "Declared run-local datasets",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/datasets/{name}/items",
        "listDatasetItems",
        "Committed accepted items, using ordinal keyset pagination",
        "crawls:read",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/datasets/import",
        "importDataset",
        "Import bounded safe JSON under an existing live request fence",
        "crawls:write",
        "200",
    ),
    (
        "delete",
        "/v1/crawls/{id}/source-memo",
        "resetSourceMemo",
        "Reset scoped source memo and category cache without purging frontier work",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/reports",
        "listOperationalReports",
        "List finite operational reports, source facts and withheld fields",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/reports/{report}",
        "searchOperationalReport",
        "Search one bounded retained report source page using structured filters",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/kv/{store}",
        "listKvKeys",
        "Bounded run-local KV metadata, using keyset pagination",
        "crawls:read",
        "200",
    ),
    (
        "delete",
        "/v1/crawls/{id}/kv/{store}",
        "dropKvStore",
        "Permanently drop the run-local KV namespace; stale versions cannot recreate it",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/kv/{store}/{key}",
        "getKvValue",
        "Read a retained typed value reference and exact version ETag",
        "crawls:read",
        "200",
    ),
    (
        "put",
        "/v1/crawls/{id}/kv/{store}/{key}",
        "putKvValue",
        "Compare-and-set a privacy-approved content reference; If-Match required",
        "crawls:write",
        "200",
    ),
    (
        "delete",
        "/v1/crawls/{id}/kv/{store}/{key}",
        "deleteKvValue",
        "Write a versioned tombstone; If-Match required",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/requests",
        "listRequests",
        "Content-free request metadata and producer activity, using bounded keysets",
        "crawls:read",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/requests",
        "appendRequests",
        "Append bounded admitted GET or HEAD proposals under an Idempotency-Key",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/requests/seal",
        "sealRequests",
        "Seal producer input under its expected epoch",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/requests/import",
        "importRequests",
        "Import a bounded, pinned declarative source queue under an Idempotency-Key",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/archives",
        "listArchives",
        "List retained archive finalization progress",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/archives/{export_id}",
        "getArchive",
        "Read retained archive progress or published manifest",
        "crawls:read",
        "200",
    ),
    (
        "delete",
        "/v1/crawls/{id}/archives/{export_id}",
        "eraseArchive",
        "Tombstone the archive and its transitive dependents",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/archives/{export_id}/records",
        "listArchiveRecords",
        "Read bounded committed archive record metadata",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/archives/{export_id}/export",
        "downloadArchive",
        "Stream the published retained archive",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/adaptive-selectors/{selector_id}",
        "getAdaptiveSelector",
        "Read a retained structural descriptor in the authenticated scope",
        "crawls:read",
        "200",
    ),
    (
        "put",
        "/v1/crawls/{id}/adaptive-selectors/{selector_id}",
        "captureAdaptiveSelector",
        "Capture a sanitized descriptor from retained authorized HTML",
        "crawls:write",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/adaptive-selectors/{selector_id}/relocate",
        "relocateAdaptiveSelector",
        "Relocate against retained HTML; ambiguous matches abstain and no requests are sent",
        "crawls:read",
        "200",
    ),
    (
        "post",
        "/v1/crawls",
        "createCrawl",
        "Create a crawl run (Idempotency-Key honored)",
        "crawls:write",
        "202",
    ),
    (
        "get",
        "/v1/crawls/{id}",
        "getCrawl",
        "Status, counters, terminal reason and coverage summary",
        "crawls:read",
        "200",
    ),
    (
        "delete",
        "/v1/crawls/{id}",
        "eraseCrawl",
        "Erase a terminal run and everything it owns",
        "crawls:write",
        "202",
    ),
    (
        "post",
        "/v1/crawls/{id}:pause",
        "pauseCrawl",
        "Pause a running crawl (idempotent by state)",
        "crawls:write",
        "202",
    ),
    (
        "post",
        "/v1/crawls/{id}:resume",
        "resumeCrawl",
        "Resume a paused crawl",
        "crawls:write",
        "202",
    ),
    (
        "post",
        "/v1/crawls/{id}:cancel",
        "cancelCrawl",
        "Cancel a crawl (idempotent by state)",
        "crawls:write",
        "202",
    ),
    (
        "get",
        "/v1/crawls/{id}/pages",
        "listPages",
        "compatibility-API page documents, cursor pagination; ?field= lists field values, ?format=jsonl streams records",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/export",
        "exportCrawl",
        "Line- or JSONL-oriented output of every page: text lines (field or template) or JSONL records",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/events",
        "streamEvents",
        "Server-sent events from crawl_events; Last-Event-ID resumes",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/errors",
        "listErrors",
        "URL-plane and interaction errors",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/states",
        "listStates",
        "Observed states with signatures and clusters",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/transitions",
        "listTransitions",
        "Recorded action transitions",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/coverage",
        "getCoverage",
        "Per-role action-context coverage (lane trusted_ui by default)",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/traffic",
        "listTraffic",
        "Captured traffic (lane trusted_ui by default; all|diagnostic)",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/artifacts/{artifactId}",
        "getArtifact",
        "Artifact bytes or ?view=metadata",
        "crawls:read",
        "200",
    ),
    (
        "get",
        "/v1/crawls/{id}/approvals",
        "listApprovals",
        "Approvals, ?decision= filter",
        "crawls:read",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/approvals/{approvalId}:approve",
        "approveAction",
        "Approve a held action (Idempotency-Key honored)",
        "approvals:decide",
        "200",
    ),
    (
        "post",
        "/v1/crawls/{id}/approvals/{approvalId}:deny",
        "denyAction",
        "Deny a held action (Idempotency-Key honored)",
        "approvals:decide",
        "200",
    ),
    (
        "post",
        "/v1/replays",
        "createReplay",
        "Create a replay run from recorded transitions; 422 validation_failed with details[].code build_mismatch when the source sessions ran on another Chromium build than this deployment, unless allowBuildMismatch is true",
        "replays:write",
        "202",
    ),
    (
        "post",
        "/v1/authorizations",
        "createAuthorization",
        "Create an authorization record. The body is an AuthorizationRecord: `tenant` may be omitted, `id` and `ownership` (dns_txt, well_known_file or operator_signature) are required, `verifiedAt`, `revokedAt` and `revokedReason` are refused. The ownership proof is verified before the record is stored; 201 with {record, bodyDigest, status, verification}, 200 for the identical record again, 409 authorization_exists for the same id with another body (records are immutable), 422 invalid_request or ownership_unverified (details[] names each host or origin)",
        "authorizations:write",
        "201",
    ),
    (
        "post",
        "/v1/authorizations/evidence",
        "uploadAuthorizationEvidence",
        "Store a UTF-8 scope document: {runId, document}. Requires an existing tenant-owned non-ZDR run. Returns {artifactId, digest} for the record's evidence; create and verify resolve the artifact and hash its bytes in tenant scope",
        "authorizations:write",
        "201",
    ),
    (
        "get",
        "/v1/authorizations/{id}",
        "getAuthorization",
        "An authorization record with its status (active, not_yet_valid, expired, revoked), body digest and verification evidence",
        "authorizations:read",
        "200",
    ),
    (
        "post",
        "/v1/authorizations/{id}/revoke",
        "revokeAuthorization",
        "Revoke an authorization record now (optional body {reason}); idempotent: a second call answers with the first revocation. Runs under the record stop at their next re-check",
        "authorizations:write",
        "200",
    ),
    (
        "post",
        "/v1/authorizations/{id}/verify",
        "verifyAuthorization",
        "Run the ownership check of a stored authorization record again; 422 ownership_unverified when the proof no longer holds, 409 invalid_state for a revoked record",
        "authorizations:write",
        "200",
    ),
    (
        "get",
        "/v1/openapi.json",
        "getOpenApi",
        "This document (no authentication)",
        "",
        "200",
    ),
    (
        "get",
        "/metrics",
        "getMetrics",
        "Prometheus text exposition (text/plain; version=0.0.4) of the process metrics",
        "metrics:read",
        "200",
    ),
    (
        "post",
        "/compat/v2/crawl",
        "compatCreateCrawl",
        "compat v2 crawl facade: start a crawl",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/v2/crawl/{id}",
        "compatGetCrawl",
        "compat v2 crawl facade: status and data",
        "crawls:read",
        "200",
    ),
    (
        "delete",
        "/compat/v2/crawl/{id}",
        "compatCancelCrawl",
        "compat v2 crawl facade: cancel",
        "crawls:write",
        "200",
    ),
    (
        "get",
        "/compat/v2/crawl/{id}/errors",
        "compatCrawlErrors",
        "compat v2 crawl facade: errors, robotsBlocked, policyBlocked",
        "crawls:read",
        "200",
    ),
];

fn operation(id: &str, summary: &str, scope: &str, success: &str, path: &str) -> Value {
    let mut params: Vec<Value> = Vec::new();
    for name in [
        "id",
        "approvalId",
        "artifactId",
        "jobId",
        "monitorId",
        "checkId",
        "session",
    ] {
        if path.contains(&format!("{{{name}}}")) {
            params.push(json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string", "format": "uuid" } }));
        }
    }
    for name in [
        "snapshotId",
        "paperId",
        "name",
        "store",
        "key",
        "selector_id",
        "export_id",
    ] {
        if path.contains(&format!("{{{name}}}")) {
            params.push(
                json!({ "name": name, "in": "path", "required": true, "schema": { "type": "string" } }),
            );
        }
    }
    let mut responses = Map::new();
    responses.insert(success.to_owned(), json!({ "description": "Success" }));
    for (code, text) in [
        ("400", "malformed_request"),
        ("401", "unauthenticated"),
        ("403", "scope_missing"),
        ("404", "not_found"),
        (
            "409",
            "invalid_state, approval_not_pending, idempotency_in_progress, authorization_exists",
        ),
        ("410", "expired, artifact_unavailable"),
        ("413", "payload_too_large"),
        (
            "422",
            "validation_failed, idempotency_key_reuse, url_denied, authorization_required, invalid_request, ownership_unverified",
        ),
        ("429", "rate_limited, quota_exceeded, too_many_streams"),
        ("500", "internal"),
        ("503", "unavailable"),
    ] {
        responses.insert(
            code.to_owned(),
            json!({ "description": text, "content": { "application/json": { "schema": { "$ref": "#/components/schemas/ErrorEnvelope" } } } }),
        );
    }
    let mut op = json!({
        "operationId": id,
        "summary": summary,
        "parameters": params,
        "responses": responses,
    });
    if let Some(o) = op.as_object_mut() {
        if scope.is_empty() {
            o.insert("security".to_owned(), json!([]));
        } else {
            o.insert("security".to_owned(), json!([{ "bearerAuth": [scope] }]));
        }
    }
    op
}

/// The OpenAPI document: the operations of [`all_operations`], and in `components.schemas` the
/// shared error envelopes plus every request and response schema the facade operations
/// reference ([`crate::openapi_schemas`]).
#[must_use]
pub fn document() -> Value {
    let mut schemas = Schemas::new();
    let mut paths: Map<String, Value> = Map::new();
    for (method, path, id, summary, scope, success) in all_operations() {
        let mut op = operation(id, summary, scope, success, path);
        if let Some(spec) = openapi_schemas::spec(id) {
            spec.apply(&mut schemas, &mut op);
        }
        openapi_schemas::apply_native(&mut schemas, &mut op, id);
        if *id == "uploadLoginFlow" {
            op["security"] = json!([{"bearerAuth":["crawls:write", "crawls:read"]}]);
            op["requestBody"] = json!({
                "required": true,
                "content": {"application/json": {"schema": {
                    "type": "object", "additionalProperties": false, "required": ["flow"],
                    "properties": {"flow": {
                        "type": "string",
                        "description": "Exact Recorder or explicit recorded-flow JSON text. UTF-8 bytes must not exceed 1048576; the configured HTTP request-body cap also applies. Duplicate members, unsupported steps and literal credentials are rejected, never rewritten."
                    }}
                }}}
            });
            op["responses"]["201"]["content"] = json!({"application/json": {"schema": {
                "type":"object", "additionalProperties":false,
                "required":["artifact","loginPlan","expiresAt"],
                "properties":{
                    "artifact":{"type":"object","additionalProperties":false,"required":["id","digest"],
                        "properties":{"id":{"type":"string","format":"uuid"},"digest":{"type":"string"}}},
                    "loginPlan":{"type":"string","description":"recorded:artifact:// followed by strict JSON {tenant,run,sensitivity:\"content\",artifact:{id,digest}}. run identifies this source, not the new target. Descriptor strings grant no authority."},
                    "expiresAt":{"type":"string","format":"date-time","description":"No later than source creation plus its original retention days; upload never renews retention."}
                }
            }}});
        }
        let entry = paths.entry((*path).to_owned()).or_insert_with(|| json!({}));
        if let Some(obj) = entry.as_object_mut() {
            obj.insert((*method).to_owned(), op);
        }
    }
    let mut components: Map<String, Value> = Map::new();
    components.insert(
        "ErrorEnvelope".to_owned(),
        json!({
            "type": "object",
            "required": ["error"],
            "properties": { "error": {
                "type": "object",
                "required": ["code", "message", "requestId", "retryable", "details"],
                "properties": {
                    "code": { "type": "string" },
                    "message": { "type": "string" },
                    "requestId": { "type": "string" },
                    "retryable": { "type": "boolean" },
                    "details": { "type": "array", "items": {
                        "type": "object",
                        "properties": { "path": { "type": "string" }, "code": { "type": "string" }, "message": { "type": "string" } }
                    } }
                }
            } }
        }),
    );
    components.extend(schemas.finish());
    json!({
        "openapi": "3.1.0",
        "info": {
            "title": "crawlx API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Interaction-aware crawler. Colon verbs (`/v1/crawls/{id}:pause`) are routed as `/v1/crawls/{id}` and split on the last colon. The /compat/v2 operations carry request and response schemas generated from Rust types; their errors are `{success: false, error, code, details[], requestId}` (schema FacadeError).",
        },
        "servers": [{ "url": "/" }],
        "security": [{ "bearerAuth": [] }],
        "paths": paths,
        "components": {
            "securitySchemes": {
                "bearerAuth": { "type": "http", "scheme": "bearer", "description": "cx_live_ followed by 26 characters from a-z and 2-7. An fc- key (16 to 64 ASCII letters or digits) authenticates only on /compat/ routes and only when the server enables compatibility keys." }
            },
            "schemas": components,
        }
    })
}

/// Every `(method, path)` the document lists (tests compare it with the router).
#[must_use]
pub fn operations() -> Vec<(&'static str, &'static str)> {
    all_operations().map(|(m, p, ..)| (*m, *p)).collect()
}
