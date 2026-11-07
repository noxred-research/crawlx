//! `ModelDecisionRepo` over `model_decisions`.

use crate::codec::{conv, digest, get, label, parse_label};
use crate::error::db;
use crate::pg::Pg;
use async_trait::async_trait;
use crawlx_core::repo::{ModelDecisionRecord, ModelDecisionRepo};
use crawlx_core::{CrawlRunId, ModelDecisionId, SessionId, StoreError};

#[async_trait]
impl ModelDecisionRepo for Pg {
    async fn record(&self, d: &ModelDecisionRecord) -> Result<(), StoreError> {
        let _timer = self.query_timer("model.record");
        let (tenant, zdr) = self.privacy_scope(d.run).await?;
        let output_metadata = if zdr {
            Some(super::event::metadata_digest(&d.output)?)
        } else {
            None
        };
        let mut tx = self.pool.begin().await.map_err(db)?;
        let inserted = sqlx::query(
            "INSERT INTO model_decisions (decision_id, run_id, session_id, kind, mode, provider, model, \
             model_version, calibration_version, confidence, output, prompt_digest, latency_ms, breaker_state, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
             ON CONFLICT (decision_id) DO NOTHING",
        )
        .bind(d.id.0)
        .bind(d.run.0)
        .bind(d.session.map(|s| s.0))
        .bind(d.kind.as_str())
        .bind(label(&d.mode)?)
        .bind(super::event::metadata_label(&d.provider, "crawlx/zdr-model-field/v1", zdr))
        .bind(super::event::metadata_label(&d.model, "crawlx/zdr-model-field/v1", zdr))
        .bind(super::event::metadata_label(&d.model_version, "crawlx/zdr-model-field/v1", zdr))
        .bind(d.calibration_version.as_deref().map(|value| super::event::metadata_label(value, "crawlx/zdr-model-field/v1", zdr)))
        .bind(d.confidence)
        .bind(output_metadata.as_ref().unwrap_or(&d.output))
        .bind(d.prompt_digest.0.as_slice())
        .bind(d.latency_ms.map(|ms| conv::<u32, i32>(ms, "latency_ms")).transpose()?)
        .bind(d.breaker_state.as_deref().map(|value| super::event::metadata_label(value, "crawlx/zdr-model-field/v1", zdr)))
        .bind(d.created_at)
        .execute(&mut *tx)
        .await
        .map_err(db)?;
        if inserted.rows_affected() == 0 {
            return Ok(());
        }
        if zdr {
            self.ephemeral_put(tenant, d.run, i64::MIN + 1, &format!("_model:{}", d.id), d)
                .await?;
        }
        tx.commit().await.map_err(db)?;
        Ok(())
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<ModelDecisionRecord>, StoreError> {
        let _timer = self.query_timer("model.list");
        let rows = sqlx::query(
            "SELECT decision_id, run_id, session_id, kind, mode, provider, model, model_version, \
             calibration_version, confidence, output, prompt_digest, latency_ms, breaker_state, created_at \
             FROM model_decisions WHERE run_id = $1 ORDER BY created_at, decision_id",
        )
        .bind(run.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        let mut decisions = Vec::with_capacity(rows.len());
        for r in &rows {
            if zdr {
                let id = ModelDecisionId(get(r, "decision_id")?);
                decisions.push(
                    self.ephemeral_get(tenant, run, i64::MIN + 1, &format!("_model:{id}"))
                        .await?,
                );
                continue;
            }
            decisions.push(ModelDecisionRecord {
                id: ModelDecisionId(get(r, "decision_id")?),
                run: CrawlRunId(get(r, "run_id")?),
                session: get::<Option<uuid::Uuid>>(r, "session_id")?.map(SessionId),
                kind: parse_label(&get::<String>(r, "kind")?)?,
                mode: parse_label(&get::<String>(r, "mode")?)?,
                provider: get(r, "provider")?,
                model: get(r, "model")?,
                model_version: get(r, "model_version")?,
                calibration_version: get(r, "calibration_version")?,
                confidence: get(r, "confidence")?,
                output: get(r, "output")?,
                prompt_digest: digest(&get::<Vec<u8>>(r, "prompt_digest")?)?,
                latency_ms: get::<Option<i32>>(r, "latency_ms")?
                    .map(|ms| conv::<i32, u32>(ms, "latency_ms"))
                    .transpose()?,
                breaker_state: get(r, "breaker_state")?,
                created_at: get(r, "created_at")?,
            });
        }
        Ok(decisions)
    }
}
