//! Persist fixture authorization through the real PostgreSQL lifecycle APIs.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use crawlx_policy::AuthorizationRecord;
use crawlx_storage::{AuthorizationRow, Pg, PgApiRepo};

/// Register an explicit fixture record and retain its verified lifecycle state.
pub async fn register_verified_record(pg: &Pg, record: &AuthorizationRecord) {
    let body = serde_json::to_value(record).unwrap();
    let digest = record.body_digest().unwrap();
    pg.ensure_authorization_record(&AuthorizationRow {
        tenant: record.tenant,
        record: record.id,
        version: i32::try_from(record.version).unwrap(),
        body: &body,
        body_digest: &digest.0,
        valid_from: record.valid_from,
        valid_to: record.valid_to,
    })
    .await
    .unwrap();
    let at = record.verified_at.expect("fixture record must be verified");
    let verification = serde_json::json!({"kind": "fixture", "checkedAt": at, "origins": record.origins});
    assert!(PgApiRepo::new(pg.clone())
        .authorization_mark_verified(record.tenant, record.id, &verification, at)
        .await
        .unwrap()
        .is_some());
}
