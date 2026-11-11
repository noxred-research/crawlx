//! `FrontierRepo` over `url_frontier`, generic over the engine.

use crate::backend::strategy::{FenceSeq, FrontierClaim};
use crate::backend::{BackendKind, Dialect, RowLock};
use crate::codec::{canonical_to_json, conv, from_json, parse_label};
use crate::error::not_found;
use crate::leases::secs;
use crate::sql::{returning, stmt, Sql, SqlRow, Stmt};
use crate::store::Store;
use crate::worker_eligibility::{claim_eligible, WorkerFacts};
use async_trait::async_trait;
use crawlx_core::repo::{
    DiscoveryOutcome, FrontierEntry, FrontierRepo, FrontierStateCounts, FrontierStatus, RunRepo,
    DEDUPE_REASON_PREFIX,
};
use crawlx_core::url::CanonicalUrl;
use crawlx_core::{CrawlRunId, StoreError, WorkerId};

#[path = "requests.rs"]
mod requests;
#[path = "requests_commit.rs"]
mod requests_commit;

const ENTRY_COLS: &str = "frontier_id, run_id, query_schema, depth, status, COALESCE(denial_reason, error_code) AS denial_reason, attempts, parent_id, priority";

/// The column and value a frontier insert adds where the engine does not assign `tenant_id`
/// itself: PostgreSQL does it in a trigger, the others take it from the owning run (the
/// composite foreign key then rejects a mismatch). Both fragments use the insert's `$1` run.
pub(crate) fn tenant_insert<B: Sql>() -> (&'static str, &'static str) {
    if B::KIND.capabilities().database_enforced_tenancy {
        ("", "")
    } else {
        (
            ", tenant_id",
            ", (SELECT tenant_id FROM crawl_runs WHERE run_id = $1)",
        )
    }
}

fn operational_page(frontier: i64) -> Result<i64, StoreError> {
    frontier
        .checked_neg()
        .filter(|key| *key < 0 && *key > -(1_i64 << 56))
        .ok_or_else(|| {
            StoreError::RetentionDenied("frontier ephemeral identifier is out of range".to_owned())
        })
}

async fn entry_from_row<B: Sql, R: SqlRow>(store: &Store<B>, r: &R) -> Result<FrontierEntry, StoreError> {
    let run = CrawlRunId(r.uuid("run_id")?);
    let (tenant, zdr) = store.privacy_scope(run).await?;
    let url = if zdr {
        store
            .ephemeral_get(
                tenant,
                run,
                operational_page(r.i64("frontier_id")?)?,
                "frontier_record",
            )
            .await?
    } else {
        from_json::<CanonicalUrl>(r.json("query_schema")?)?
    };
    Ok(FrontierEntry {
        id: r.i64("frontier_id")?,
        run,
        url,
        depth: conv(r.i16("depth")?, "depth")?,
        status: parse_label(&r.text("status")?)?,
        denial_reason: r.opt_text("denial_reason")?,
        attempts: conv(r.i16("attempts")?, "attempts")?,
        discovered_from: r.opt_i64("parent_id")?,
    })
}

/// The acquisition backends and data capabilities a worker must offer to take URL leases of
/// a run, from its admitted configuration.
struct LeaseNeeds {
    required: Vec<String>,
    data_required: bool,
}

fn lease_needs(config: &crawlx_core::config::CreateCrawl) -> Result<LeaseNeeds, StoreError> {
    let data = crawlx_core::data_capabilities::WorkerDataRequirementsV1::from_config(config)?;
    let data_required = !data.destinations.is_empty() || data.language_bundle.is_some();
    let required = if let Some(policy) = &config.acquisition {
        policy
            .validate()
            .map_err(|error| StoreError::Conflict(error.to_string()))?;
        policy.backend_ids.clone()
    } else {
        Vec::new()
    };
    Ok(LeaseNeeds {
        required,
        data_required,
    })
}

impl<B: Sql> Store<B> {
    /// Backfill only pre-cutover open rows, through their existing retention boundary.
    async fn backfill_strategy_scores(&self, run: CrawlRunId) -> Result<(), StoreError> {
        loop {
            let rows = stmt!(
                B,
                "SELECT frontier_id FROM url_frontier WHERE run_id=$1 \
                 AND status IN ('pending','leased') AND strategy_score IS NULL \
                 ORDER BY frontier_id LIMIT 256"
            )
            .uuid(run.0)
            .fetch_all_pool(&self.pool)
            .await?;
            if rows.is_empty() {
                return Ok(());
            }
            for row in &rows {
                let id = row.i64("frontier_id")?;
                let request = self.request_get(run, id).await?;
                let score = crawlx_core::priority::priority_depth(
                    &request.envelope.url.url,
                    u32::from(request.envelope.depth),
                    request.envelope.method == "GET",
                );
                stmt!(
                    B,
                    "UPDATE url_frontier SET strategy_score=$2 \
                     WHERE frontier_id=$1 AND strategy_score IS NULL"
                )
                .i64(id)
                .i32(conv::<u32, i32>(score, "strategy score")?)
                .execute_write(&self.pool)
                .await?;
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
        let updated = stmt!(
            B,
            format!(
                "UPDATE url_frontier SET status = $2, \
                   denial_reason = CASE WHEN $4 THEN $3 ELSE denial_reason END, \
                   error_code = CASE WHEN $4 THEN error_code ELSE COALESCE($3, error_code) END, \
                   finished_at = {now}, lease_owner = NULL, lease_expires_at = NULL \
                 WHERE frontier_id = $1 AND status = 'leased' AND lease_expires_at > {now} AND ($5::bigint IS NULL OR fencing_token = $5){ret}",
                now = <B::Dialect as Dialect>::now(),
                ret = returning::<B>("frontier_id"),
            )
        )
        .i64(id)
        .text(status.as_str())
        .opt_text(reason.as_deref())
        .bool(blocked)
        .opt_i64(token)
        .matched_write(&self.pool)
        .await?;
        if updated {
            return Ok(());
        }
        let current = stmt!(B, "SELECT status FROM url_frontier WHERE frontier_id = $1")
            .i64(id)
            .fetch_optional_pool(&self.pool)
            .await?
            .map(|row| row.text("status"))
            .transpose()?;
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

    /// Lease one named pending row where the engine cannot do the eligibility check and the
    /// lease in one statement: everything is decided inside one write transaction.
    async fn lease_one_portable(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        id: i64,
        tenant: crawlx_core::TenantId,
        duration_secs: f64,
        needs: &LeaseNeeds,
    ) -> Result<Option<(FrontierEntry, i64)>, StoreError> {
        let now_sql = <B::Dialect as Dialect>::now();
        let mut tx = self.begin_write().await?;
        let now = B::db_now(&self.pool).await?;
        let share = <B::Dialect as Dialect>::row_lock(RowLock::Share);
        let ceiling = <B::Dialect as Dialect>::add_seconds("COALESCE(r.started_at, r.created_at)", "$3");
        let Some(run_row) = Stmt::<B>::dynamic(&format!(
            "SELECT r.mode, r.data_requirements FROM crawl_runs r WHERE r.run_id = $1 AND r.tenant_id = $2 \
               AND r.status IN ('queued','running') AND r.cancel_requested_at IS NULL AND r.purge_requested_at IS NULL \
               AND COALESCE(r.deadline_at, {ceiling}) > {now_sql}{share}"
        ))
        .uuid(run.0)
        .uuid(tenant.0)
        .f64(duration_secs)
        .fetch_optional(tx.conn())
        .await?
        else {
            return Ok(None);
        };
        if run_row.text("mode")? == "dynamic" {
            return Ok(None);
        }
        let worker_row = stmt!(
            B,
            "SELECT capacity, draining, last_heartbeat_at FROM workers WHERE worker_id = $1"
        )
        .uuid(worker.0)
        .fetch_optional(tx.conn())
        .await?;
        let facts = worker_row
            .map(|row| {
                Ok::<_, StoreError>(WorkerFacts {
                    capacity: row.json("capacity")?,
                    draining: row.bool("draining")?,
                    last_heartbeat_at: row.ts("last_heartbeat_at")?,
                })
            })
            .transpose()?;
        if !claim_eligible(
            facts.as_ref(),
            run.0,
            now,
            &needs.required,
            needs.data_required,
            &run_row.json("data_requirements")?,
        ) {
            return Ok(None);
        }
        let lock = <B::Dialect as Dialect>::row_lock(RowLock::Update);
        let pending = Stmt::<B>::dynamic(&format!(
            "SELECT f.frontier_id FROM url_frontier f WHERE f.run_id = $1 AND f.frontier_id = $2 \
               AND f.via <> 'interaction' AND f.status = 'pending' AND f.next_attempt_at <= {now_sql} \
               AND f.attempts < 32767{lock}"
        ))
        .uuid(run.0)
        .i64(id)
        .fetch_optional(tx.conn())
        .await?;
        if pending.is_none() {
            return Ok(None);
        }
        let fence = B::next_fence(tx.conn(), FenceSeq::Lease).await?;
        let expires = <B::Dialect as Dialect>::add_seconds(now_sql, "$3");
        Stmt::<B>::dynamic(&format!(
            "UPDATE url_frontier SET status = 'leased', lease_owner = $2, lease_expires_at = {expires}, \
               fencing_token = $4, attempts = attempts + 1 WHERE frontier_id = $1"
        ))
        .i64(id)
        .uuid(worker.0)
        .f64(secs(self.cfg.url_batch_ttl))
        .i64(fence)
        .execute(tx.conn())
        .await?;
        let row = stmt!(
            B,
            "SELECT frontier_id, run_id, query_schema, depth, status, COALESCE(denial_reason, error_code) AS denial_reason, \
               attempts, parent_id, priority, fencing_token FROM url_frontier WHERE frontier_id = $1"
        )
        .i64(id)
        .fetch_one(tx.conn())
        .await?;
        tx.commit().await?;
        Ok(Some((
            entry_from_row(self, &row).await?,
            row.i64("fencing_token")?,
        )))
    }
}

#[async_trait]
impl<B: Sql> FrontierRepo for Store<B> {
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
    async fn request_methods(
        &self,
        run: CrawlRunId,
        ids: &[i64],
    ) -> Result<std::collections::BTreeMap<i64, String>, StoreError> {
        self.request_methods_bulk(run, ids).await
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
        let cfg = RunRepo::get(self, run)
            .await?
            .config
            .orchestration
            .unwrap_or_default();
        cfg.validate()?;
        let envelope = crawlx_core::request::RequestEnvelopeV1::get(url.clone(), depth, from);
        let envelope_bytes = i64::try_from(serde_json::to_vec(&envelope)?.len())
            .map_err(|_| StoreError::Conflict("request size overflow".into()))?;
        let mut tx = self.begin_write().await?;
        requests::lock_run::<B>(tx.conn(), run).await?;
        let exists = stmt!(
            B,
            "SELECT EXISTS(SELECT 1 FROM url_frontier WHERE run_id=$1 AND canonical_key=$2 AND revisit_generation=0) AS present"
        )
        .uuid(run.0)
        .bytes(url.key.0.as_slice())
        .fetch_one(tx.conn())
        .await?
        .flag("present")?;
        if exists {
            return Ok((DiscoveryOutcome::Duplicate, None));
        }
        if status == FrontierStatus::Pending {
            let counts = stmt!(
                B,
                format!(
                    "SELECT count(*) AS entries,{bytes} AS bytes \
                     FROM url_frontier WHERE run_id=$1 AND status IN ('pending','leased')",
                    bytes = <B::Dialect as Dialect>::cast_i64("COALESCE(sum(envelope_bytes),0)"),
                )
            )
            .uuid(run.0)
            .fetch_one(tx.conn())
            .await?;
            if u64::try_from(counts.i64("entries")?).unwrap_or(u64::MAX) >= cfg.queue.max_pending_entries
                || u64::try_from(counts.i64("bytes")?.saturating_add(envelope_bytes)).unwrap_or(u64::MAX)
                    > cfg.queue.max_pending_envelope_bytes
            {
                return Err(StoreError::Conflict("frontier quota exhausted".into()));
            }
        }
        // The request key was just checked under the run lock, which every frontier insert
        // takes, so the conflict clause only matters where it is free (MariaDB would answer
        // an ignored duplicate with the existing row).
        let conflict = if B::KIND == BackendKind::MariaDb {
            String::new()
        } else {
            format!(
                " {}",
                <B::Dialect as Dialect>::upsert_do_nothing(&[
                    "run_id",
                    "canonical_key",
                    "revisit_generation"
                ])
            )
        };
        let envelope_json = if zdr {
            None
        } else {
            Some(serde_json::to_value(&envelope)?)
        };
        let row = stmt!(
            B,
            format!(
                "INSERT INTO url_frontier (run_id, canonical_key, canonical_url, origin, query_schema, depth, via, parent_id, status, denial_reason, finished_at, request_envelope, envelope_bytes, strategy_score{tenant_column}) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, CASE WHEN $11 THEN {now} END, $12, $13, $14{tenant_value}){conflict} RETURNING frontier_id",
                now = <B::Dialect as Dialect>::now(),
                tenant_column = tenant_insert::<B>().0,
                tenant_value = tenant_insert::<B>().1,
            )
        )
        .uuid(run.0)
        .bytes(url.key.0.as_slice())
        .opt_text(canonical)
        .text(origin)
        .json(&schema)
        .i16(conv::<u16, i16>(depth, "depth")?)
        .text(via)
        .opt_i64(from)
        .text(status.as_str())
        .opt_text(reason.as_deref())
        .bool(blocked)
        .opt_json(envelope_json.as_ref())
        .i64(envelope_bytes)
        .i32(conv::<u32, i32>(
            crawlx_core::priority::priority_depth(&url.url, u32::from(depth), true),
            "strategy score",
        )?)
        .fetch_optional(tx.conn())
        .await?;
        let result = match row {
            Some(r) => {
                let id = r.i64("frontier_id")?;
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
        tx.commit().await?;
        Ok(result)
    }

    async fn lease_batch_fenced(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        limit: u32,
    ) -> Result<Vec<(FrontierEntry, i64)>, StoreError> {
        let _timer = self.query_timer("frontier.lease_batch");
        let admitted = RunRepo::get(self, run).await?;
        if admitted.config.mode == crawlx_core::CrawlMode::Dynamic {
            return Ok(Vec::new());
        }
        let needs = lease_needs(&admitted.config)?;
        let strategy = admitted.config.scope.strategy;
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
        let rows = B::claim_frontier_batch(
            &self.pool,
            FrontierClaim {
                run: run.0,
                worker: worker.0,
                limit: i64::from(limit),
                ttl_secs: secs(self.cfg.url_batch_ttl),
                required_backends: &needs.required,
                data_required: needs.data_required,
                strategy: strategy_name,
            },
        )
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in &rows {
            out.push((
                entry_from_row(self, row).await?,
                row.f32("priority")?,
                conv::<i32, u32>(row.i32("strategy_score")?, "strategy score")?,
                row.i64("fencing_token")?,
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

    async fn lease_one_fenced(
        &self,
        run: CrawlRunId,
        worker: WorkerId,
        id: i64,
    ) -> Result<Option<(FrontierEntry, i64)>, StoreError> {
        let _timer = self.query_timer("frontier.lease_one");
        let admitted = RunRepo::get(self, run).await?;
        if admitted.config.mode == crawlx_core::CrawlMode::Dynamic {
            return Ok(None);
        }
        if admitted
            .config
            .orchestration
            .as_ref()
            .is_some_and(|cfg| cfg.queue.batch_size == 0)
        {
            return Ok(None);
        }
        let needs = lease_needs(&admitted.config)?;
        let duration = f64::from(admitted.config.limits.duration_seconds);
        if B::KIND != BackendKind::Postgres {
            return self
                .lease_one_portable(run, worker, id, admitted.tenant, duration, &needs)
                .await;
        }
        // PostgreSQL UPDATE rechecks a contended row; FOR SHARE holds the run lifecycle stable.
        let row = stmt!(
            B,
            "UPDATE url_frontier f SET status='leased',lease_owner=$2, \
               lease_expires_at=now()+make_interval(secs=>$4), \
               fencing_token=nextval('lease_fence_seq'),attempts=attempts+1 \
             WHERE f.run_id=$1 AND f.frontier_id=$3 AND f.via<>'interaction' AND f.status='pending' \
               AND (SELECT mode FROM crawl_runs WHERE run_id=$1)<>'dynamic' \
               AND f.next_attempt_at<=now() AND f.attempts<32767 \
               AND EXISTS(SELECT 1 FROM crawl_runs r WHERE r.run_id=$1 AND r.tenant_id=$7 \
                 AND r.status IN ('queued','running') \
                 AND r.cancel_requested_at IS NULL AND r.purge_requested_at IS NULL \
                 AND COALESCE(r.deadline_at,COALESCE(r.started_at,r.created_at)+make_interval(secs=>$8))>now() \
                 FOR SHARE) \
               AND (cardinality($5::text[])=0 AND NOT $6::boolean OR EXISTS(SELECT 1 FROM workers w \
                 WHERE w.worker_id=$2 AND NOT w.draining AND w.last_heartbeat_at<=clock_timestamp() \
                   AND w.last_heartbeat_at>=clock_timestamp()-interval '90 seconds' \
                   AND (w.capacity->'acceptsQueued'='true'::jsonb OR w.capacity->>'localRun'=$1::text) \
                   AND NOT EXISTS(SELECT 1 FROM unnest($5::text[]) required(backend_id) \
                     WHERE NOT EXISTS(SELECT 1 FROM jsonb_array_elements(COALESCE(w.capacity->'acquisition','[]'::jsonb)) fact \
                       WHERE fact->>'backendId'=required.backend_id AND fact->'available'='true'::jsonb)))) \
               AND crawlx_worker_data_eligible($2,(SELECT data_requirements FROM crawl_runs WHERE run_id=$1)) \
             RETURNING f.frontier_id,f.run_id,f.query_schema,f.depth,f.status, \
               COALESCE(f.denial_reason,f.error_code) AS denial_reason, \
               f.attempts,f.parent_id,f.priority,f.fencing_token"
        )
        .uuid(run.0)
        .uuid(worker.0)
        .i64(id)
        .f64(secs(self.cfg.url_batch_ttl))
        .text_list(&needs.required)
        .bool(needs.data_required)
        .uuid(admitted.tenant.0)
        .f64(duration)
        .fetch_optional_write(&self.pool)
        .await?;
        match row {
            Some(row) => Ok(Some((
                entry_from_row(self, &row).await?,
                row.i64("fencing_token")?,
            ))),
            None => Ok(None),
        }
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
        let released = stmt!(
            B,
            format!(
                "UPDATE url_frontier SET status = 'pending', lease_owner = NULL, lease_expires_at = NULL, \
                   attempts = {floor} \
                 WHERE frontier_id = $1 AND status = 'leased' AND fencing_token = $2 AND lease_expires_at > {now}{ret}",
                floor = <B::Dialect as Dialect>::greatest_ignoring_null(&["attempts - 1", "0"]),
                now = <B::Dialect as Dialect>::now(),
                ret = returning::<B>("frontier_id"),
            )
        )
        .i64(id)
        .i64(fence)
        .matched_write(&self.pool)
        .await?;
        if released {
            return Ok(());
        }
        let exists = stmt!(B, "SELECT frontier_id FROM url_frontier WHERE frontier_id = $1")
            .i64(id)
            .fetch_optional_pool(&self.pool)
            .await?;
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
        let result = stmt!(
            B,
            format!(
                "UPDATE url_frontier SET status='pending',lease_owner=NULL,lease_expires_at=NULL, \
                 next_attempt_at={later},attempts={floor} \
                 WHERE frontier_id=$1 AND status='leased' AND fencing_token=$2 AND lease_expires_at>{now}",
                later = <B::Dialect as Dialect>::greatest_ignoring_null(&["next_attempt_at", "$3"]),
                floor = <B::Dialect as Dialect>::greatest_ignoring_null(&["attempts-1", "0"]),
                now = <B::Dialect as Dialect>::now(),
            )
        )
        .i64(id)
        .i64(fence)
        .ts(not_before)
        .execute_write(&self.pool)
        .await?;
        if result != 1 {
            return Err(StoreError::LeaseLost);
        }
        Ok(())
    }

    async fn pending_count(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        let _timer = self.query_timer("frontier.pending_count");
        let row = stmt!(
            B,
            "SELECT count(*) AS n FROM url_frontier WHERE run_id = $1 AND via <> 'interaction' AND status = 'pending' AND (SELECT mode FROM crawl_runs WHERE run_id=$1)<>'dynamic'"
        )
        .uuid(run.0)
        .fetch_one_pool(&self.pool)
        .await?;
        conv(row.i64("n")?, "count")
    }

    async fn open_count(&self, run: CrawlRunId) -> Result<u64, StoreError> {
        let _timer = self.query_timer("frontier.open_count");
        let row = stmt!(
            B,
            "SELECT count(*) AS n FROM url_frontier WHERE run_id = $1 AND via <> 'interaction' AND status IN ('pending', 'leased') AND (SELECT mode FROM crawl_runs WHERE run_id=$1)<>'dynamic'"
        )
        .uuid(run.0)
        .fetch_one_pool(&self.pool)
        .await?;
        conv(row.i64("n")?, "count")
    }

    async fn state_counts(&self, run: CrawlRunId) -> Result<FrontierStateCounts, StoreError> {
        let _timer = self.query_timer("frontier.state_counts");
        let row = stmt!(B, state_counts_sql::<B>())
            .uuid(run.0)
            .text(DEDUPE_REASON_PREFIX)
            .fetch_one_pool(&self.pool)
            .await?;
        let n = |column: &str| -> Result<u64, StoreError> { conv(row.i64(column)?, "count") };
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
        let rows = stmt!(
            B,
            format!("SELECT {ENTRY_COLS} FROM url_frontier WHERE run_id = $1 ORDER BY frontier_id")
        )
        .uuid(run.0)
        .fetch_all_pool(&self.pool)
        .await?;
        let mut entries = Vec::with_capacity(rows.len());
        for row in &rows {
            entries.push(entry_from_row(self, row).await?);
        }
        Ok(entries)
    }
}

/// The per-state tally of one run's frontier (`$2` is the duplicate-reason prefix).
fn state_counts_sql<B: Sql>() -> String {
    let count = |status: &str| <B::Dialect as Dialect>::count_where(&format!("status = '{status}'"));
    let duplicate = |status: &str| {
        <B::Dialect as Dialect>::count_where(&format!(
            "status = '{status}' \
                 AND {}",
            <B::Dialect as Dialect>::starts_with("COALESCE(denial_reason, error_code)", "$2")
        ))
    };
    format!(
        "SELECT \
           {} AS pending, \
           {} AS leased, \
           {} AS succeeded, \
           {} AS failed, \
           {} AS unreachable, \
           {} AS abandoned, \
           {} AS policy_blocked, \
           {} AS robots_blocked, \
           {} AS succeeded_duplicate, \
           {} AS policy_blocked_duplicate \
         FROM url_frontier WHERE run_id = $1 AND via <> 'interaction' AND (SELECT mode FROM crawl_runs WHERE run_id=$1)<>'dynamic'",
        count("pending"),
        count("leased"),
        count("succeeded"),
        count("failed"),
        count("unreachable"),
        count("abandoned"),
        count("policy_blocked"),
        count("robots_blocked"),
        duplicate("succeeded"),
        duplicate("policy_blocked"),
    )
}
