//! `ModelDecisionRepo` over `model_decisions`.

use crate::backend::Dialect;
use crate::codec::{conv, digest, label, parse_label};
use crate::sql::{insert_once, stmt, Sql, SqlRow};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::repo::{ModelDecisionRecord, ModelDecisionRepo};
use crawlx_core::{CrawlRunId, ModelDecisionId, SessionId, StoreError};

const FIELD_DOMAIN: &str = "crawlx/zdr-model-field/v1";

#[async_trait]
impl<B: Sql> ModelDecisionRepo for Store<B> {
    async fn record(&self, d: &ModelDecisionRecord) -> Result<(), StoreError> {
        let _timer = self.query_timer("model.record");
        let (tenant, zdr) = self.privacy_scope(d.run).await?;
        let output_metadata = if zdr {
            Some(super::event::metadata_digest(&d.output)?)
        } else {
            None
        };
        let mode = label(&d.mode)?;
        let provider = super::event::metadata_label(&d.provider, FIELD_DOMAIN, zdr);
        let model = super::event::metadata_label(&d.model, FIELD_DOMAIN, zdr);
        let model_version = super::event::metadata_label(&d.model_version, FIELD_DOMAIN, zdr);
        let calibration = d
            .calibration_version
            .as_deref()
            .map(|value| super::event::metadata_label(value, FIELD_DOMAIN, zdr));
        let breaker = d
            .breaker_state
            .as_deref()
            .map(|value| super::event::metadata_label(value, FIELD_DOMAIN, zdr));
        let latency = d
            .latency_ms
            .map(|ms| conv::<u32, i32>(ms, "latency_ms"))
            .transpose()?;
        let conflict = <B::Dialect as Dialect>::upsert_do_nothing(&["decision_id"]);
        let mut tx = self.begin_write().await?;
        let inserted = insert_once::<B>(
            tx.conn(),
            stmt!(B, "SELECT decision_id FROM model_decisions WHERE decision_id = $1").uuid(d.id.0),
            stmt!(
                B,
                format!(
                    "INSERT INTO model_decisions (decision_id, run_id, session_id, kind, mode, provider, model, \
                     model_version, calibration_version, confidence, output, prompt_digest, latency_ms, breaker_state, created_at) \
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15) \
                     {conflict}"
                )
            )
            .uuid(d.id.0)
            .uuid(d.run.0)
            .opt_uuid(d.session.map(|s| s.0))
            .text(d.kind.as_str())
            .text(&mode)
            .text(&provider)
            .text(&model)
            .text(&model_version)
            .opt_text(calibration.as_deref())
            .opt_f32(d.confidence)
            .json(output_metadata.as_ref().unwrap_or(&d.output))
            .bytes(&d.prompt_digest.0)
            .opt_i32(latency)
            .opt_text(breaker.as_deref())
            .ts(d.created_at),
        )
        .await?;
        if !inserted {
            return Ok(());
        }
        if zdr {
            self.ephemeral_put(tenant, d.run, i64::MIN + 1, &format!("_model:{}", d.id), d)
                .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<ModelDecisionRecord>, StoreError> {
        let _timer = self.query_timer("model.list");
        let rows = stmt!(
            B,
            "SELECT decision_id, run_id, session_id, kind, mode, provider, model, model_version, \
             calibration_version, confidence, output, prompt_digest, latency_ms, breaker_state, created_at \
             FROM model_decisions WHERE run_id = $1 ORDER BY created_at, decision_id"
        )
        .uuid(run.0)
        .fetch_all_pool(&self.pool)
        .await?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        let mut decisions = Vec::with_capacity(rows.len());
        for r in &rows {
            if zdr {
                let id = ModelDecisionId(r.uuid("decision_id")?);
                decisions.push(
                    self.ephemeral_get(tenant, run, i64::MIN + 1, &format!("_model:{id}"))
                        .await?,
                );
                continue;
            }
            decisions.push(ModelDecisionRecord {
                id: ModelDecisionId(r.uuid("decision_id")?),
                run: CrawlRunId(r.uuid("run_id")?),
                session: r.opt_uuid("session_id")?.map(SessionId),
                kind: parse_label(&r.text("kind")?)?,
                mode: parse_label(&r.text("mode")?)?,
                provider: r.text("provider")?,
                model: r.text("model")?,
                model_version: r.text("model_version")?,
                calibration_version: r.opt_text("calibration_version")?,
                confidence: r.opt_f32("confidence")?,
                output: r.json("output")?,
                prompt_digest: digest(&r.bytes("prompt_digest")?)?,
                latency_ms: r
                    .opt_i32("latency_ms")?
                    .map(|ms| conv::<i32, u32>(ms, "latency_ms"))
                    .transpose()?,
                breaker_state: r.opt_text("breaker_state")?,
                created_at: r.ts("created_at")?,
            });
        }
        Ok(decisions)
    }
}
