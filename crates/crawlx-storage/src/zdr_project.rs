//! Rust-side ZDR confidentiality projection.
//!
//! PostgreSQL rewrites rows of zero-data-retention runs in `BEFORE INSERT OR UPDATE` triggers.
//! MariaDB and SQLite cannot (or, for SQLite, cannot assign to `NEW`), so for them the write
//! path itself projects content away before it binds, and the database only carries
//! validator triggers that reject a row still holding content. Every repository that writes a
//! table of [`ZDR_TABLES`] (or the run configuration) calls the functions of this module on
//! the values it is about to bind, on every engine: PostgreSQL's trigger stays as defence in
//! depth and accepts the projected values unchanged (a 64-digit hexadecimal text is a
//! digest, a JSON object holding only a `digest` member is a digest).
//!
//! The projections are pure and deterministic. They never read the clock.
//!
//! | Table | Column | Projection |
//! |---|---|---|
//! | `safety_decisions` | `evidence` | [`safety_evidence`] |
//! | `approvals` | `summary`, `reason` | [`json_digest`], [`approval_reason`] |
//! | `webhook_deliveries` | `url`, `last_error` | domain hash, [`webhook_error`] |
//! | `model_decisions`, `action_contexts`, `crawl_events` | labels, payloads | [`label`], [`json_digest`] |
//! | `pages`, `states`, `url_frontier`, `traffic_events`, `actions`, `enablement_edges` | content columns | `NULL`, `[]` or `{}` by their writer |

use crawlx_core::hash::Digest;
use crawlx_core::StoreError;
use std::borrow::Cow;

/// The tables whose rows the PostgreSQL trigger `enforce_zdr_confidentiality` rewrites for
/// zero-data-retention runs.
pub const ZDR_TABLES: &[&str] = &[
    "action_contexts",
    "actions",
    "approvals",
    "crawl_events",
    "elements",
    "enablement_edges",
    "model_decisions",
    "pages",
    "safety_decisions",
    "states",
    "traffic_events",
    "url_frontier",
    "webhook_deliveries",
    "workflow_runs",
];

/// Dataset tables guarded by `enforce_dataset_zdr`.
pub const ZDR_DATASET_TABLES: &[&str] = &["dataset_delivery_outbox", "dataset_items", "dataset_kv"];

/// The run configuration table, guarded by `enforce_zdr_run_config`.
pub const ZDR_RUN_TABLE: &str = "crawl_runs";

/// Columns no Rust write path projected before this module grew [`safety_evidence`],
/// [`approval_reason`] and [`webhook_error`]; the PostgreSQL trigger alone protected them.
/// Empty once every writer calls the projection; kept so the list of what moved stays visible.
pub const TRIGGER_ONLY_COLUMNS: &[(&str, &str)] = &[];

/// The error text a delivery window leaves when it expires before the delivery is acknowledged.
pub const EXPIRED_DELIVERY_ERROR: &str = "zdr delivery window expired";

/// Domain of the hash that replaces a free-text approval reason.
const APPROVAL_REASON_DOMAIN: &str = "crawlx/zdr-approval-reason/v1";

/// Domain of the hash that replaces a webhook delivery error.
const WEBHOOK_ERROR_DOMAIN: &str = "crawlx/zdr-webhook-error/v1";

/// Domain of the digest that replaces a JSON document.
const JSON_DIGEST_DOMAIN: &str = "crawlx/zdr-metadata/v1";

/// Whether `rows` of `table` need the ZDR projection on engines without the trigger.
#[must_use]
pub fn is_projected_table(table: &str) -> bool {
    table == ZDR_RUN_TABLE || ZDR_TABLES.contains(&table) || ZDR_DATASET_TABLES.contains(&table)
}

/// Whether `text` is a 64-digit lower-case hexadecimal digest, which the PostgreSQL trigger
/// leaves alone.
#[must_use]
pub fn is_digest(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// The label stored for `value`: itself, or for a zero-data-retention run its domain-separated
/// digest (an existing digest is kept).
#[must_use]
pub fn label<'a>(value: &'a str, domain: &'static str, zdr: bool) -> Cow<'a, str> {
    if zdr && !is_digest(value) {
        Cow::Owned(Digest::of(domain, value.as_bytes()).to_hex())
    } else {
        Cow::Borrowed(value)
    }
}

/// `{"digest": <hex>}`: the only form a zero-data-retention run keeps of a JSON document. A
/// document that already is such an object passes unchanged.
///
/// # Errors
/// Returns [`StoreError::Serialization`] if `value` cannot be rendered.
pub fn json_digest(value: &serde_json::Value) -> Result<serde_json::Value, StoreError> {
    if let Some(digest) = value
        .as_object()
        .filter(|map| map.len() == 1)
        .and_then(|map| map.get("digest"))
    {
        if digest.as_str().is_some_and(is_digest) {
            return Ok(value.clone());
        }
    }
    let bytes = serde_json::to_vec(value).map_err(|error| StoreError::Serialization(error.to_string()))?;
    Ok(serde_json::json!({
        "digest": Digest::of(JSON_DIGEST_DOMAIN, &bytes).to_hex(),
    }))
}

/// `safety_decisions.evidence`: the document itself, or its digest for a zero-data-retention
/// run.
///
/// # Errors
/// See [`json_digest`].
pub fn safety_evidence(evidence: &serde_json::Value, zdr: bool) -> Result<serde_json::Value, StoreError> {
    if zdr {
        json_digest(evidence)
    } else {
        Ok(evidence.clone())
    }
}

/// `approvals.summary`: the document itself, or its digest for a zero-data-retention run.
///
/// # Errors
/// See [`json_digest`].
pub fn approval_summary(summary: &serde_json::Value, zdr: bool) -> Result<serde_json::Value, StoreError> {
    safety_evidence(summary, zdr)
}

/// `approvals.reason`: the operator's free text, or its digest for a zero-data-retention run.
#[must_use]
pub fn approval_reason(reason: &str, zdr: bool) -> Cow<'_, str> {
    label(reason, APPROVAL_REASON_DOMAIN, zdr)
}

/// `webhook_deliveries.last_error`: the failure text, or its digest for a zero-data-retention
/// run. Pass [`EXPIRED_DELIVERY_ERROR`] when the delivery window expired.
#[must_use]
pub fn webhook_error(error: &str, zdr: bool) -> Cow<'_, str> {
    label(error, WEBHOOK_ERROR_DOMAIN, zdr)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::tenant_tables;

    #[test]
    fn every_projected_table_is_registered() {
        for table in ZDR_TABLES.iter().chain(ZDR_DATASET_TABLES) {
            assert!(tenant_tables::lookup(table).is_some(), "{table}");
        }
        assert!(tenant_tables::lookup(ZDR_RUN_TABLE).is_some());
    }

    #[test]
    fn lists_are_sorted_and_no_column_is_left_to_the_trigger() {
        assert!(ZDR_TABLES.windows(2).all(|w| w[0] < w[1]));
        assert!(TRIGGER_ONLY_COLUMNS.is_empty());
        assert!(is_projected_table("approvals"));
        assert!(!is_projected_table("workers"));
    }

    #[test]
    fn labels_are_digested_once_and_only_for_zdr_runs() {
        let plain = label("secret", "crawlx/test/v1", false);
        assert_eq!(plain, "secret");
        let hidden = label("secret", "crawlx/test/v1", true).into_owned();
        assert!(is_digest(&hidden));
        assert_ne!(hidden, label("secret", "crawlx/other/v1", true));
        // a digest is kept, so a PostgreSQL trigger pass and a second projection are no-ops
        assert_eq!(label(&hidden, "crawlx/test/v1", true), hidden);
    }

    #[test]
    fn json_documents_collapse_to_a_digest_object() {
        let evidence = serde_json::json!({ "summary": "clicked the delete button", "approval": null });
        assert_eq!(safety_evidence(&evidence, false).unwrap(), evidence);
        let hidden = safety_evidence(&evidence, true).unwrap();
        let object = hidden.as_object().unwrap();
        assert_eq!(object.len(), 1);
        assert!(is_digest(object["digest"].as_str().unwrap()));
        assert!(!hidden.to_string().contains("delete"));
        assert_eq!(json_digest(&hidden).unwrap(), hidden);
    }

    #[test]
    fn free_text_columns_never_survive_for_zdr_runs() {
        assert_eq!(approval_reason("customer asked", false), "customer asked");
        let reason = approval_reason("customer asked", true);
        assert!(is_digest(&reason));
        let error = webhook_error(EXPIRED_DELIVERY_ERROR, true);
        assert!(is_digest(&error));
        assert_eq!(
            webhook_error("502 from https://example.test/hook", false),
            "502 from https://example.test/hook"
        );
        assert_ne!(webhook_error("a", true), webhook_error("b", true));
    }
}
