//! `FrontierRepo` over `url_frontier`.

use crate::codec::{canonical_to_json, conv, from_json, get, parse_label};
use crate::error::{db, not_found};
use crate::leases::secs;
use crate::pg::Pg;
use async_trait::async_trait;
use crawlx_core::repo::{
    DiscoveryOutcome, FrontierEntry, FrontierRepo, FrontierStateCounts, FrontierStatus, DEDUPE_REASON_PREFIX,
};
use crawlx_core::url::CanonicalUrl;
use crawlx_core::{CrawlRunId, StoreError, WorkerId};
use sqlx::postgres::PgRow;

#[path = "requests.rs"]
mod requests;

const ENTRY_COLS: &str = "frontier_id, run_id, query_schema, depth, status, COALESCE(denial_reason, error_code) AS denial_reason, attempts, parent_id, priority";

fn operational_page(frontier: i64) -> Result<i64, StoreError> {
    frontier
        .checked_neg()
        .filter(|key| *key < 0 && *key > -(1_i64 << 56))
        .ok_or_else(|| {
            StoreError::RetentionDenied("frontier ephemeral identifier is out of range".to_owned())
        })
}

async fn entry_from_row(pg: &Pg, r: &PgRow) -> Result<FrontierEntry, StoreError> {
    let run = CrawlRunId(get(r, "run_id")?);
    let (tenant, zdr) = pg.privacy_scope(run).await?;
    let url = if zdr {
        pg.ephemeral_get(
            tenant,
            run,
            operational_page(get(r, "frontier_id")?)?,
            "frontier_record",
        )
        .await?
    } else {
        from_json::<CanonicalUrl>(get::<serde_json::Value>(r, "query_schema")?)?
    };
    Ok(FrontierEntry {
        id: get(r, "frontier_id")?,
        run,
        url,
        depth: conv(get::<i16>(r, "depth")?, "depth")?,
        status: parse_label(&get::<String>(r, "status")?)?,
        denial_reason: get(r, "denial_reason")?,
        attempts: conv(get::<i16>(r, "attempts")?, "attempts")?,
        discovered_from: get(r, "parent_id")?,
    })
}

impl Pg {
    /// Backfill only pre-cutover open rows, through their existing retention boundary.
    async fn backfill_strategy_scores(&self, run: CrawlRunId) -> Result<(), StoreError> {
        loop {
            let ids = sqlx::query_scalar::<_, i64>(
                "SELECT frontier_id FROM url_frontier WHERE run_id=$1 \
                 AND status IN ('pending','leased') AND strategy_score IS NULL \
                 ORDER BY frontier_id LIMIT 256",
            )
            .bind(run.0)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
            if ids.is_empty() {
                return Ok(());
            }
            for id in ids {
                let request = self.request_get(run, id).await?;
                let score = crawlx_core::priority::priority_depth(
                    &request.envelope.url.url,
                    u32::from(request.envelope.depth),
                    request.envelope.method == "GET",
                );
                sqlx::query(
                    "UPDATE url_frontier SET strategy_score=$2 \
                     WHERE frontier_id=$1 AND strategy_score IS NULL",
                )
                .bind(id)
                .bind(conv::<u32, i32>(score, "strategy score")?)
                .execute(&self.pool)
                .await
                .map_err(db)?;
            }
        }
    }

    /// Finish a leased row; with a `token`, only the holder of that lease can.
    async fn complete_inner(
        &self,
        id: i64,
        token: Option<i64>,
        status: FrontierStatus,
        reason: Option<String>,
    ) -> Result<(), StoreError> {
        let _timer = self.query_timer("frontier.complete");
        let blocked = matches!(
            status,
            FrontierStatus::PolicyBlocked | FrontierStatus::RobotsBlocked
        );
        if matches!(status, FrontierStatus::Pending | FrontierStatus::Leased) {
            return Err(StoreError::IllegalTransition {
                from: "leased".to_owned(),
                to: status.as_str().to_owned(),
            });
        }
        let updated = sqlx::query(
            "UPDATE url_frontier SET status = $2, \
               denial_reason = CASE WHEN $4 THEN $3 ELSE denial_reason END, \
               error_code = CASE WHEN $4 THEN error_code ELSE COALESCE($3, error_code) END, \
               finished_at = now(), lease_owner = NULL, lease_expires_at = NULL \
             WHERE frontier_id = $1 AND status = 'leased' AND lease_expires_at > now() AND ($5::bigint IS NULL OR fencing_token = $5) RETURNING frontier_id",
        )
        .bind(id)
        .bind(status.as_str())
        .bind(reason)
        .bind(blocked)
        .bind(token)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        if updated.is_some() {
            return Ok(());
        }
        let current: Option<String> =
            sqlx::query_scalar("SELECT status FROM url_frontier WHERE frontier_id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
        match current {
            None => Err(not_found("frontier row", id)),
            // a fenced holder that finds its row elsewhere (returned by the reaper, re-leased,
            // or finished by someone else) has lost the lease
            Some(_) if token.is_some() => Err(StoreError::LeaseLost),
            Some(from) => Err(StoreError::IllegalTransition {
                from,
                to: status.as_str().to_owned(),
            }),
        }
    }
}

#[async_trait]
impl FrontierRepo for Pg {
    async fn append_batch(
        &self,
        batch: crawlx_core::orchestration::RequestBatchV1,
    ) -> Result<crawlx_core::orchestration::RequestBatchReceiptV1, StoreError> {
        self.request_append(batch).await
    }
    async fn page(&self, run: CrawlRunId, after: i64, limit: u32) -> Result<Vec<FrontierEntry>, StoreError> {
        self.request_page(run, after, limit).await
    }
    async fn metadata_page(
        &self,
        run: CrawlRunId,
        after: i64,
        limit: u32,
    ) -> Result<Vec<crawlx_core::orchestration::RequestMetadataV1>, StoreError> {
        self.request_metadata_page(run, after, limit).await
    }
    async fn retry_fenced(
        &self,
        id: i64,
        fence: i64,
        not_before: crawlx_core::Timestamp,
    ) -> Result<bool, StoreError> {
        self.request_retry(id, fence, not_before).await
    }
    async fn reserve_effects_fenced(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        effects: u32,
    ) -> Result<(), StoreError> {
        self.request_reserve(run, id, fence, effects).await
    }
    async fn settle_effects_fenced(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        reserved: u32,
        actual: u32,
    ) -> Result<(), StoreError> {
        self.request_settle_effects(run, id, fence, reserved, actual)
            .await
    }
    async fn reserve_acquisition_fenced(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
    ) -> Result<crawlx_core::acquisition::AcquisitionAllowanceV1, StoreError> {
        self.acquisition_reserve(run, id, fence).await
    }
    async fn settle_acquisition_fenced(
        &self,
        run: CrawlRunId,
        id: i64,
        fence: i64,
        usage: &crawlx_core::acquisition::AcquisitionUsageV1,
    ) -> Result<(), StoreError> {
        self.acquisition_settle(run, id, fence, usage).await
    }
    async fn get_request(
        &self,
        run: CrawlRunId,
        id: i64,
    ) -> Result<crawlx_core::orchestration::QueuedRequestV1, StoreError> {
        self.request_get(run, id).await
    }
    async fn seal(&self, run: CrawlRunId, expected_epoch: u64) -> Result<(), StoreError> {
        self.request_seal(run, expected_epoch).await
    }
    async fn activity(
        &self,
        run: CrawlRunId,
    ) -> Result<crawlx_core::orchestration::FrontierActivityV1, StoreError> {
        self.request_activity(run).await
    }
    async fn loader_cursor(
        &self,
        run: CrawlRunId,
        source: &str,
    ) -> Result<Option<crawlx_core::orchestration::LoaderCursorV1>, StoreError> {
        self.request_cursor(run, source).await
    }
    async fn discover(
        &self,
        run: CrawlRunId,
        url: &CanonicalUrl,
        depth: u16,
        from: Option<i64>,
        denial: Option<(FrontierStatus, String)>,
    ) -> Result<(DiscoveryOutcome, Option<i64>), StoreError> {
        let _timer = self.query_timer("frontier.discover");
        let (status, reason, outcome) = match denial {
            None => (FrontierStatus::Pending, None, DiscoveryOutcome::Admitted),
            Some((FrontierStatus::PolicyBlocked, why)) => (
                FrontierStatus::PolicyBlocked,
                Some(why),
                DiscoveryOutcome::PolicyBlocked,
            ),
            Some((FrontierStatus::RobotsBlocked, why)) => (
                FrontierStatus::RobotsBlocked,
                Some(why),
                DiscoveryOutcome::RobotsBlocked,
            ),
            Some((other, _)) => {
                return Err(StoreError::Conflict(format!(
                    "a discovery denial must be policy_blocked or robots_blocked, got {}",
                    other.as_str()
                )))
            }
        };
        let via = if from.is_none() && depth == 0 {
            "seed"
        } else {
            "link"
        };
        let blocked = reason.is_some();
        let (tenant, zdr) = self.privacy_scope(run).await?;
        let canonical = if zdr { None } else { Some(url.url.as_str()) };
        let origin_hash = zdr
            .then(|| crawlx_core::hash::Digest::of("crawlx/zdr-origin/v1", url.origin.as_bytes()).to_hex());
        let origin = origin_hash.as_deref().unwrap_or(&url.origin);
        let schema = if zdr {
            serde_json::json!({})
        } else {
            canonical_to_json(url)?
        };
        let cfg = <Self as crawlx_core::repo::RunRepo>::get(self, run)
            .await?
            .config
            .orchestration
            .unwrap_or_default();
        cfg.validate()?;
        let envelope = crawlx_core::request::RequestEnvelopeV1::get(url.clone(), depth, from);
        let envelope_bytes = i64::try_from(serde_json::to_vec(&envelope)?.len())
            .map_err(|_| StoreError::Conflict("request size overflow".into()))?;
        let mut tx = self.pool.begin().await.map_err(db)?;
        requests::lock_run(self, &mut tx, run).await?;
        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND canonical_key=$2 AND revisit_generation=0)"
        ).bind(run.0).bind(url.key.0.as_slice()).fetch_one(&mut *tx).await.map_err(db)?;
        if exists {
            return Ok((DiscoveryOutcome::Duplicate, None));
        }
        if status == FrontierStatus::Pending {
            let counts = sqlx::query(
                "SELECT count(*) AS entries,COALESCE(sum(envelope_bytes),0)::bigint AS bytes \
                 FROM url_frontier WHERE run_id=$1 AND status IN ('pending','leased')",
            )
            .bind(run.0)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
            if u64::try_from(get::<i64>(&counts, "entries")?).unwrap_or(u64::MAX)
                >= cfg.queue.max_pending_entries
                || u64::try_from(get::<i64>(&counts, "bytes")?.saturating_add(envelope_bytes))
                    .unwrap_or(u64::MAX)
                    > cfg.queue.max_pending_envelope_bytes
            {
                return Err(StoreError::Conflict("frontier quota exhausted".into()));
            }
        }
        let row = sqlx::query(
            "INSERT INTO url_frontier (run_id, canonical_key, canonical_url, origin, query_schema, depth, via, parent_id, status, denial_reason, finished_at, request_envelope, envelope_bytes, strategy_score) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CASE WHEN $11 THEN now() END, $12, $13, $14) \
             ON CONFLICT (run_id, canonical_key, revisit_generation) DO NOTHING RETURNING frontier_id",
        )
        .bind(run.0)
        .bind(url.key.0.to_vec())
        .bind(canonical)
        .bind(origin)
        .bind(schema)
        .bind(conv::<u16, i16>(depth, "depth")?)
        .bind(via)
        .bind(from)
        .bind(status.as_str())
        .bind(reason)
        .bind(blocked)
        .bind(if zdr { None } else { Some(serde_json::to_value(&envelope)?) })
        .bind(envelope_bytes)
        .bind(conv::<u32, i32>(
            crawlx_core::priority::priority_depth(&url.url, u32::from(depth), true),
            "strategy score",
        )?)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?;
        let result = match row {
            Some(r) => {
                let id = get(&r, "frontier_id")?;
                if zdr {
                    self.ephemeral_put(tenant, run, operational_page(id)?, "frontier_record", url)
                        .await?;
                    self.ephemeral_put(tenant, run, operational_page(id)?, "request_envelope", &envelope)
                        .await?;
                }
                (outcome, Some(id))
            }
            None => (DiscoveryOutcome::Duplicate, None),
        };
        tx.commit().await.map_err(db)?;
        Ok(result)
    }

    async fn lease_batch_fenced(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        limit: u32,
    ) -> Result<Vec<(FrontierEntry, i64)>, StoreError> {
        let _timer = self.query_timer("frontier.lease_batch");
        let admitted = <Self as crawlx_core::repo::RunRepo>::get(self, run).await?;
        let data = crawlx_core::data_capabilities::WorkerDataRequirementsV1::from_config(&admitted.config)?;
        let strategy = admitted.config.scope.strategy;
        let data_required = !data.destinations.is_empty() || data.language_bundle.is_some();
        let required = if let Some(policy) = admitted.config.acquisition {
            policy
                .validate()
                .map_err(|error| StoreError::Conflict(error.to_string()))?;
            policy.backend_ids
        } else {
            Vec::new()
        };
        let limit = limit.min(admitted.config.orchestration.unwrap_or_default().queue.batch_size);
        if limit == 0 {
            return Ok(Vec::new());
        }
        let strategy_name = match strategy {
            crawlx_core::config::CrawlStrategy::BreadthFirst => "breadth_first",
            crawlx_core::config::CrawlStrategy::DepthFirst => "depth_first",
            crawlx_core::config::CrawlStrategy::Priority => {
                self.backfill_strategy_scores(run).await?;
                "priority"
            }
        };
        let sql = "WITH picked AS ( \
               SELECT frontier_id FROM url_frontier WHERE run_id = $1 AND status = 'pending' AND next_attempt_at <= now() \
               AND (cardinality($5::text[])=0 AND NOT $6::boolean OR EXISTS (SELECT 1 FROM workers w \
                 WHERE w.worker_id=$2 AND NOT w.draining AND w.last_heartbeat_at<=clock_timestamp() \
                   AND w.last_heartbeat_at>=clock_timestamp()-interval '90 seconds' \
                   AND (w.capacity->'acceptsQueued'='true'::jsonb OR w.capacity->>'localRun'=$1::text) \
                   AND NOT EXISTS(SELECT 1 FROM unnest($5::text[]) required(backend_id) \
                     WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(w.capacity->'acquisition','[]'::jsonb)) fact \
                       WHERE fact->>'backendId'=required.backend_id AND fact->'available'='true'::jsonb)))) \
               AND crawlx_worker_data_eligible($2,(SELECT data_requirements FROM crawl_runs WHERE run_id=$1)) \
               ORDER BY priority DESC, \
                 CASE $7::text WHEN 'depth_first' THEN -depth::integer WHEN 'priority' THEN strategy_score ELSE depth::integer END, \
                 CASE WHEN $7='priority' THEN depth::integer ELSE 0 END, \
                 CASE WHEN $7='depth_first' THEN ~frontier_id ELSE frontier_id END \
               LIMIT $3 FOR UPDATE SKIP LOCKED) \
             UPDATE url_frontier f SET status = 'leased', lease_owner = $2, lease_expires_at = now() + make_interval(secs => $4), \
               fencing_token = nextval('lease_fence_seq'), attempts = attempts + 1 \
             FROM picked WHERE f.frontier_id = picked.frontier_id \
             RETURNING f.frontier_id, f.run_id, f.query_schema, f.depth, f.status, COALESCE(f.denial_reason, f.error_code) AS denial_reason, \
               f.attempts, f.parent_id, f.priority, COALESCE(f.strategy_score,0) AS strategy_score, f.fencing_token";
        let rows = sqlx::query(sql)
            .bind(run.0)
            .bind(worker.0)
            .bind(i64::from(limit))
            .bind(secs(self.cfg.url_batch_ttl))
            .bind(required)
            .bind(data_required)
            .bind(strategy_name)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push((
                entry_from_row(self, row).await?,
                get::<f32>(row, "priority")?,
                conv::<i32, u32>(get(row, "strategy_score")?, "strategy score")?,
                get::<i64>(row, "fencing_token")?,
            ));
        }
        out.sort_by(|a, b| {
            b.1.total_cmp(&a.1).then_with(|| {
                crawlx_core::priority::strategy_order(strategy, a.0.depth, a.2, a.0.id).cmp(
                    &crawlx_core::priority::strategy_order(strategy, b.0.depth, b.2, b.0.id),
                )
            })
        });
        Ok(out.into_iter().map(|(e, _, _, t)| (e, t)).collect())
    }

    async fn complete(
        &self,
        id: i64,
        status: FrontierStatus,
        reason: Option<String>,
    ) -> Result<(), StoreError> {
        self.complete_inner(id, None, status, reason).await
    }

    async fn complete_fenced(
        &self,
        id: i64,
        fence: i64,
        status: FrontierStatus,
        reason: Option<String>,
    ) -> Result<(), StoreError> {
        self.complete_inner(id, Some(fence), status, reason).await
    }

    async fn give_back(&self, id: i64, fence: i64) -> Result<(), StoreError> {
        let _timer = self.query_timer("frontier.give_back");
        let released = sqlx::query(
            "UPDATE url_frontier SET status = 'pending', lease_owner = NULL, lease_expires_at = NULL, \
               attempts = GREATEST(attempts - 1, 0) \
             WHERE frontier_id = $1 AND status = 'leased' AND fencing_token = $2 AND lease_expires_at > now() RETURNING frontier_id",
        )
        .bind(id)
        .bind(fence)
        .fetch_optional(&self.pool)
        .await
        .map_err(db)?;
        if released.is_some() {
            return Ok(());
        }
        let exists: Option<i64> =
            sqlx::query_scalar("SELECT frontier_id FROM url_frontier WHERE frontier_id = $1")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
        match exists {
            None => Err(not_found("frontier row", id)),
            Some(_) => Err(StoreError::LeaseLost),
        }
    }

    async fn defer_fenced(
        &self,
        id: i64,
        fence: i64,
        not_before: crawlx_core::Timestamp,
    ) -> Result<(), StoreError> {
        let result = sqlx::query(
            "UPDATE url_frontier SET status='pending',lease_owner=NULL,lease_expires_at=NULL, \
             next_attempt_at=GREATEST(next_attempt_at,$3),attempts=GREATEST(attempts-1,0) \
             WHERE frontier_id=$1 AND status='leased' AND fencing_token=$2 AND lease_expires_at>now()",
        )
        .bind(id)
        .bind(fence)
        .bind(not_before)
        .execute(&self.pool)
        .await
        .map_err(db)?;
        if result.rows_affected() != 1 {
            return Err(StoreError::LeaseLost);
        }
        Ok(())
    }

    async fn pending_count(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        let _timer = self.query_timer("frontier.pending_count");
        let n: i64 =
            sqlx::query_scalar("SELECT count(*) FROM url_frontier WHERE run_id = $1 AND status = 'pending'")
                .bind(run.0)
                .fetch_one(&self.pool)
                .await
                .map_err(db)?;
        conv(n, "count")
    }

    async fn open_count(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        let _timer = self.query_timer("frontier.open_count");
        let n: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM url_frontier WHERE run_id = $1 AND status IN ('pending', 'leased')",
        )
        .bind(run.0)
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        conv(n, "count")
    }

    async fn state_counts(&self, run: CrawlRunId) -> Result<FrontierStateCounts, StoreError> {
        let _timer = self.query_timer("frontier.state_counts");
        let row = sqlx::query(
            "SELECT \
               count(*) FILTER (WHERE status = 'pending') AS pending, \
               count(*) FILTER (WHERE status = 'leased') AS leased, \
               count(*) FILTER (WHERE status = 'succeeded') AS succeeded, \
               count(*) FILTER (WHERE status = 'failed') AS failed, \
               count(*) FILTER (WHERE status = 'unreachable') AS unreachable, \
               count(*) FILTER (WHERE status = 'abandoned') AS abandoned, \
               count(*) FILTER (WHERE status = 'policy_blocked') AS policy_blocked, \
               count(*) FILTER (WHERE status = 'robots_blocked') AS robots_blocked, \
               count(*) FILTER (WHERE status = 'succeeded' \
                 AND starts_with(COALESCE(denial_reason, error_code), $2)) AS succeeded_duplicate, \
               count(*) FILTER (WHERE status = 'policy_blocked' \
                 AND starts_with(COALESCE(denial_reason, error_code), $2)) AS policy_blocked_duplicate \
             FROM url_frontier WHERE run_id = $1",
        )
        .bind(run.0)
        .bind(DEDUPE_REASON_PREFIX)
        .fetch_one(&self.pool)
        .await
        .map_err(db)?;
        let n = |column: &str| -> Result<u64, StoreError> { conv(get::<i64>(&row, column)?, "count") };
        Ok(FrontierStateCounts {
            pending: n("pending")?,
            leased: n("leased")?,
            succeeded: n("succeeded")?,
            failed: n("failed")?,
            unreachable: n("unreachable")?,
            abandoned: n("abandoned")?,
            policy_blocked: n("policy_blocked")?,
            robots_blocked: n("robots_blocked")?,
            succeeded_duplicate: n("succeeded_duplicate")?,
            policy_blocked_duplicate: n("policy_blocked_duplicate")?,
        })
    }

    async fn list(&self, run: CrawlRunId) -> Result<Vec<FrontierEntry>, StoreError> {
        let _timer = self.query_timer("frontier.list");
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {ENTRY_COLS} FROM url_frontier WHERE run_id = $1 ORDER BY frontier_id"
        )))
        .bind(run.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let mut entries = Vec::with_capacity(rows.len());
        for row in &rows {
            entries.push(entry_from_row(self, row).await?);
        }
        Ok(entries)
    }
}
