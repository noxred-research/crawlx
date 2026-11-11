//! `RequestCommitRepo`: observed-request leases, request commits, feed finalization hooks and
//! extension attempts over the authoritative URL frontier.
use super::requests::*;
use crate::backend::strategy::{Conn, FenceSeq};
use crate::backend::{BackendKind, Dialect, RowLock};
use crate::codec::conv;
use crate::leases::secs;
use crate::sql::{stmt, Sql, SqlRow};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::extensions::ExtensionReceiptV1;
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::*;
use crawlx_core::repo::{FrontierEntry, FrontierStatus, RunRepo};
use crawlx_core::{CrawlRunId, StoreError, TenantId};
use std::future::Future;
use std::pin::Pin;

#[async_trait]
impl<B: Sql> RequestCommitRepo for Store<B> {
    async fn append_observed_fenced(
        &self,
        request: ObservedRequestV1,
    ) -> Result<ObservedAppendV1, StoreError> {
        self.append_observation(request).await
    }
    async fn lease_observed_fenced(
        &self,
        lease: &crawlx_core::custody::CustodyLease,
        epoch: crawlx_core::ObservationEpoch,
        request_id: i64,
    ) -> Result<Option<(FrontierEntry, i64)>, StoreError> {
        lease.check_local_cancellation()?;
        let queued = self.request_get(lease.run, request_id).await?;
        let mut tx = self.begin_write().await?;
        let (tenant, _) = lock_run::<B>(tx.conn(), lease.run).await?;
        if tenant != lease.tenant {
            return Err(StoreError::LeaseLost);
        }
        let principal = observed_session_tx::<B>(tx.conn(), lease).await?;
        let proposal = ObservedRequestV1::from_staged(lease.clone(), epoch, queued.envelope.clone())?;
        let batch = proposal.batch_id(&principal)?;
        let receipt = batch_receipt::<B>(tx.conn(), lease.run, batch.0.as_slice()).await?;
        if queued.principal != principal
            || queued.envelope.metadata.get("observed_epoch") != Some(&serde_json::to_value(batch)?)
            || receipt.as_ref().and_then(|receipt| receipt.get("inserted"))
                != Some(&serde_json::json!([request_id]))
        {
            return Err(StoreError::LeaseLost);
        }
        // This exact immutable observation already happened. No worker admission or
        // drain gate may turn its receipt into a fresh target dispatch.
        let leased = lease_interaction::<B>(
            self,
            tx.conn(),
            lease,
            request_id,
            &principal,
            queued.identity.key.0.as_slice(),
        )
        .await?;
        observed_session_tx::<B>(tx.conn(), lease).await?;
        tx.commit().await?;
        leased
            .map(|(attempts, fence)| {
                let mut entry = queued.entry;
                entry.status = FrontierStatus::Leased;
                entry.attempts = conv(attempts, "attempts")?;
                Ok((entry, fence))
            })
            .transpose()
    }
    async fn commit_observed_fenced(
        &self,
        mut commit: RequestCommitV1,
        lease: crawlx_core::custody::CustodyLease,
        epoch: crawlx_core::ObservationEpoch,
    ) -> Result<ObservedCommitV1, StoreError> {
        commit.observation = Some((lease, epoch));
        self.commit_fenced(commit).await?;
        Ok(ObservedCommitV1::Committed)
    }
    async fn begin_feed_finalization(
        &self,
        run: CrawlRunId,
        reason: Option<crawlx_core::counters::TerminalReason>,
    ) -> Result<Option<crawlx_core::counters::TerminalReason>, StoreError> {
        self.begin_feed_finalization_owned(run, reason).await
    }
    async fn stage_feed_batches(
        &self,
        run: CrawlRunId,
        batches: &[crawlx_core::dataset::DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        self.stage_feed_batches_owned(run, batches).await
    }
    async fn staged_feed_batch(
        &self,
        run: CrawlRunId,
        feed: &str,
        idempotency_key: &str,
    ) -> Result<Option<crawlx_core::dataset::DeliveryBatchV1>, StoreError> {
        self.staged_feed_batch_owned(run, feed, idempotency_key).await
    }
    async fn finalize_run_feeds(
        &self,
        run: CrawlRunId,
        status: crawlx_core::counters::RunStatus,
        reason: crawlx_core::counters::TerminalReason,
        batches: &[crawlx_core::dataset::DeliveryBatchV1],
    ) -> Result<(), StoreError> {
        self.finalize_run_feeds_owned(run, status, reason, batches).await
    }
    async fn claim_feed_finalizer(
        &self,
        run: CrawlRunId,
        worker: crawlx_core::WorkerId,
        ttl: std::time::Duration,
    ) -> Result<crawlx_core::custody::CustodyLease, StoreError> {
        self.claim_feed_finalizer_owned(run, worker, ttl).await
    }
    async fn renew_feed_finalizer(
        &self,
        lease: &crawlx_core::custody::CustodyLease,
        ttl: std::time::Duration,
    ) -> Result<(), StoreError> {
        self.renew_feed_finalizer_owned(lease, ttl).await
    }
    async fn release_feed_finalizer(
        &self,
        lease: &crawlx_core::custody::CustodyLease,
    ) -> Result<(), StoreError> {
        self.release_feed_finalizer_owned(lease).await
    }
    async fn commit_fenced(&self, commit: RequestCommitV1) -> Result<(), StoreError> {
        if commit.head_response.is_none() {
            return self.commit_request_boxed(commit).await;
        }
        let store = self.clone();
        let tenant = crate::tenant::current();
        // Dropping this JoinHandle detaches the owner instead of dropping its SQL
        // transaction while the delivery backend may still run spawn_blocking work.
        // The run/fence checks remain inside the owner, before any volatile write.
        tokio::spawn(async move {
            match tenant {
                Some(tenant) => crate::tenant::scope(tenant, store.commit_request_owned(commit)).await,
                None => store.commit_request_owned(commit).await,
            }
        })
        .await
        .map_err(|error| StoreError::Backend(format!("HEAD response commit task failed: {error}")))?
    }
    async fn record_extension_attempt(
        &self,
        run: CrawlRunId,
        request_id: i64,
        fence: i64,
        attempt: u32,
        receipts: &[ExtensionReceiptV1],
    ) -> Result<(), StoreError> {
        validate_extension_trail(receipts)?;
        let mut tx = self.begin_write().await?;
        // Same order as the terminal result: run row first, then the request row.
        let (tenant, _) = lock_run::<B>(tx.conn(), run).await?;
        if crate::tenant::current().is_some_and(|current| current != tenant) {
            return Err(StoreError::AccessDenied(
                "extension attempt tenant mismatch".into(),
            ));
        }
        let row = stmt!(
            B,
            format!(
                "SELECT attempts,status::text AS status,fencing_token,lease_expires_at>{clock} AS live_lease FROM url_frontier WHERE frontier_id=$1 AND run_id=$2 AND tenant_id=$3{lock}",
                clock = <B::Dialect as Dialect>::clock_timestamp(),
                lock = <B::Dialect as Dialect>::row_lock(RowLock::Update)
            )
        )
        .i64(request_id)
        .uuid(run.0)
        .uuid(tenant.0)
        .fetch_optional(tx.conn())
        .await?
        .ok_or(StoreError::LeaseLost)?;
        if row.text("status")? != "leased"
            || row.opt_i64("fencing_token")? != Some(fence)
            || row.opt_flag("live_lease")? != Some(true)
            || u32::try_from(row.i16("attempts")?).ok() != Some(attempt)
        {
            return Err(StoreError::LeaseLost);
        }
        let key = ExtensionAttemptKey {
            tenant,
            run,
            request_id,
            fence,
            attempt,
        };
        persist_extension_attempt::<B>(self, tx.conn(), key, receipts).await?;
        tx.commit().await?;
        Ok(())
    }
}

impl<B: Sql> Store<B> {
    /// The request-commit owner as a heap future built in its own short frame, so a caller that
    /// awaits it does not reserve the future's full size in its own, deeply nested frame.
    #[inline(never)]
    fn commit_request_boxed(
        &self,
        commit: RequestCommitV1,
    ) -> Pin<Box<dyn Future<Output = Result<(), StoreError>> + Send + '_>> {
        Box::pin(self.commit_request_owned(commit))
    }

    async fn commit_request_owned(&self, mut commit: RequestCommitV1) -> Result<(), StoreError> {
        commit.validate_processing_evidence()?;
        if matches!(commit.status, FrontierStatus::Pending | FrontierStatus::Leased)
            || commit.reason.as_deref().is_some_and(|reason| {
                reason.len() > 128
                    || !reason
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b':'))
            })
        {
            return Err(StoreError::Conflict("invalid request disposition".into()));
        }
        // Retained replay uses the durable digest; ZDR replay also requires live custody.
        let head_receipt = commit.head_response_receipt()?;
        if head_receipt.is_some() {
            let mut conn = self.begin_read().await?;
            let prior = stmt!(
                B,
                "SELECT r.tenant_id,r.retention_mode='zdr' AS zdr,f.head_response_receipt FROM url_frontier f JOIN crawl_runs r ON r.run_id=f.run_id AND r.tenant_id=f.tenant_id WHERE f.run_id=$1 AND f.frontier_id=$2"
            )
            .uuid(commit.run.0)
            .i64(commit.request_id)
            .fetch_optional(conn.conn())
            .await?
            .ok_or(StoreError::LeaseLost)?;
            let tenant = TenantId(prior.uuid("tenant_id")?);
            let acquisition_tenant = <TenantId as serde::Deserialize>::deserialize(
                &commit.head_response.as_ref().ok_or(StoreError::LeaseLost)?["acquisition"]["tenant"],
            )?;
            if acquisition_tenant != tenant {
                return Err(StoreError::AccessDenied("HEAD response tenant mismatch".into()));
            }
            if crate::tenant::current().is_some_and(|current| current != tenant) {
                return Err(StoreError::AccessDenied("request result tenant mismatch".into()));
            }
            if let Some(stored) = prior.opt_bytes("head_response_receipt")? {
                return check_head_response_receipt::<B>(
                    self,
                    conn.conn(),
                    &commit,
                    tenant,
                    prior.flag("zdr")?,
                    &stored,
                    head_receipt,
                )
                .await;
            }
        }
        let run = self.get(commit.run).await?;
        if crate::tenant::current().is_some_and(|tenant| tenant != run.tenant) {
            return Err(StoreError::AccessDenied("request result tenant mismatch".into()));
        }
        let cfg = run.config.orchestration.clone().unwrap_or_default();
        // Observed rows must never be completed through the generic path, including body-free failures.
        // Fetching the immutable envelope also proves volatile custody before result publication.
        let current = Some(self.request_get(commit.run, commit.request_id).await?);
        if head_receipt.is_some()
            && current
                .as_ref()
                .is_none_or(|request| request.envelope.method != "HEAD")
        {
            return Err(StoreError::Conflict(
                "HEAD response queued method mismatch".into(),
            ));
        }
        if let Some(payload) = &commit.head_response {
            let queued = current.as_ref().ok_or(StoreError::LeaseLost)?;
            let acquisition = &payload["acquisition"];
            // URL evidence may redact path/query secrets; exact authority comes from the queue key.
            let requested_url = <url::Url as serde::Deserialize>::deserialize(&acquisition["requestedUrl"])?;
            if !matches!(requested_url.scheme(), "http" | "https")
                || requested_url.origin() != queued.envelope.url.url.origin()
                || <Digest as serde::Deserialize>::deserialize(&acquisition["requestDigest"])?
                    != queued.identity.key
            {
                return Err(StoreError::Conflict(
                    "HEAD response request identity mismatch".into(),
                ));
            }
        }
        let mut tx = self.begin_write().await?;
        let (tenant, zdr) = lock_run::<B>(tx.conn(), commit.run).await?;
        if crate::tenant::current().is_some_and(|current| current != tenant) {
            return Err(StoreError::AccessDenied("request result tenant mismatch".into()));
        }
        if let Some(payload) = &commit.head_response {
            if <TenantId as serde::Deserialize>::deserialize(&payload["acquisition"]["tenant"])? != tenant {
                return Err(StoreError::AccessDenied("HEAD response tenant mismatch".into()));
            }
        }
        let result = stmt!(
            B,
            format!(
                "SELECT attempts,state_version,head_response_receipt,route_id,principal,lease_owner,via,status::text AS status,fencing_token,lease_expires_at>{clock} AS live_lease FROM url_frontier WHERE frontier_id=$1 AND run_id=$2{lock}",
                clock = <B::Dialect as Dialect>::clock_timestamp(),
                lock = <B::Dialect as Dialect>::row_lock(RowLock::Update)
            )
        )
        .i64(commit.request_id)
        .uuid(commit.run.0)
        .fetch_optional(tx.conn())
        .await?
        .ok_or(StoreError::LeaseLost)?;
        if let Some(stored) = result.opt_bytes("head_response_receipt")? {
            // Replay never republishes the event or renews the original volatile page.
            return check_head_response_receipt::<B>(
                self,
                tx.conn(),
                &commit,
                tenant,
                zdr,
                &stored,
                head_receipt,
            )
            .await;
        }
        if result.text("status")? != "leased"
            || result.opt_i64("fencing_token")? != Some(commit.fence)
            || result.opt_flag("live_lease")? != Some(true)
        {
            return Err(StoreError::LeaseLost);
        }
        let live = result.i64("state_version")?;
        if u64::try_from(live).ok() != Some(commit.expected_state_version) {
            return Err(StoreError::Conflict("request state version changed".into()));
        }
        let observed_principal = if let Some((lease, epoch)) = &commit.observation {
            let principal = observed_session_tx::<B>(tx.conn(), lease).await?;
            let queued = current.as_ref().ok_or(StoreError::LeaseLost)?;
            let proposal = ObservedRequestV1::from_staged(lease.clone(), *epoch, queued.envelope.clone())?;
            let batch = proposal.batch_id(&principal)?;
            let receipt = batch_receipt::<B>(tx.conn(), commit.run, batch.0.as_slice()).await?;
            if lease.run != commit.run
                || lease.tenant != tenant
                || result.text("via")? != "interaction"
                || result.text("principal")? != principal
                || result.opt_uuid("lease_owner")? != Some(lease.worker.0)
                || queued.envelope.metadata.get("observed_epoch") != Some(&serde_json::to_value(batch)?)
                || receipt.as_ref().and_then(|receipt| receipt.get("inserted"))
                    != Some(&serde_json::json!([commit.request_id]))
                || commit.head_response.is_some()
            {
                return Err(StoreError::LeaseLost);
            }
            Some(principal)
        } else {
            if result.text("via")? == "interaction"
                || current
                    .as_ref()
                    .is_some_and(|queued| queued.envelope.metadata.contains_key("observed_epoch"))
            {
                return Err(StoreError::LeaseLost);
            }
            None
        };
        if head_receipt.is_some() {
            let (alias, column) = if B::KIND == BackendKind::Postgres {
                ("", "?column?")
            } else {
                (" AS active", "active")
            };
            let active = stmt!(
                B,
                format!("SELECT status NOT IN ('completed','failed','cancelled'){alias} FROM crawl_runs WHERE run_id=$1")
            )
            .uuid(commit.run.0)
            .fetch_one(tx.conn())
            .await?
            .flag(column)?;
            if !active {
                return Err(StoreError::AccessDenied("HEAD response run is terminal".into()));
            }
            let (allowed, now) = authorization_live::<B>(
                tx.conn(),
                commit.run,
                false,
                run.config.safety.authorization_record_ref.is_none(),
            )
            .await?;
            if !allowed {
                return Err(StoreError::AccessDenied(
                    "HEAD response authorization is not live".into(),
                ));
            }
            if run.config.retention.mode != crawlx_core::config::RetentionMode::Zdr
                && run.config.retention.days != 0
                && run.created_at + chrono::Duration::days(i64::from(run.config.retention.days)) <= now
            {
                return Err(StoreError::RetentionDenied(
                    "committed HEAD source expired".into(),
                ));
            }
        }
        if let Some(page) = &commit.page {
            if page.run != commit.run
                || page.frontier_id != commit.request_id
                || commit.status != FrontierStatus::Succeeded
            {
                return Err(StoreError::Conflict("result page authority mismatch".into()));
            }
            if current
                .as_ref()
                .is_none_or(|request| request.envelope.url.key != page.url.key)
            {
                return Err(StoreError::Conflict("result page url mismatch".into()));
            }
        }
        if commit.content_dedupe.is_some() {
            crate::digest_registry::check_source(&run, chrono::Utc::now())?;
        }
        crate::digest_registry::validate_commit(&commit, tenant)?;
        let digest_outcome = if let Some(claim) = &commit.content_dedupe {
            let outcome = crate::digest_registry::claim::<B>(tx.conn(), claim, commit.request_id).await?;
            crate::digest_registry::apply_outcome(&mut commit, &outcome);
            Some(outcome)
        } else {
            None
        };
        let mut children = commit.children.take();
        if let Some(batch) = &children {
            if batch.run != commit.run
                || batch.parent_fence != Some((commit.request_id, commit.fence))
                || batch
                    .requests
                    .iter()
                    .any(|request| request.revisit_generation != 0)
            {
                return Err(StoreError::Conflict("result child authority mismatch".into()));
            }
        }
        if let (Some(policy), Some(current)) = (
            &cfg.recrawl,
            current.filter(|_| {
                matches!(commit.status, FrontierStatus::Succeeded | FrontierStatus::Failed)
                    && observed_principal.is_none()
            }),
        ) {
            let (allowed, now) = authorization_live::<B>(
                tx.conn(),
                commit.run,
                true,
                run.config.safety.authorization_record_ref.is_none(),
            )
            .await?;
            let deadline = run.started_at.unwrap_or(run.created_at)
                + chrono::Duration::seconds(i64::from(run.config.limits.duration_seconds));
            if allowed {
                if let Some(decision) =
                    policy.next_visit_after_commit(&current.envelope, &commit, now, deadline, None)?
                {
                    let next = decision.request;
                    let principal = stmt!(B, "SELECT principal FROM url_frontier WHERE frontier_id=$1")
                        .i64(commit.request_id)
                        .fetch_one(tx.conn())
                        .await?
                        .text("principal")?;
                    let batch = children.get_or_insert_with(|| {
                        let mut batch = RequestBatchV1::new(
                            run.tenant,
                            run.id,
                            principal,
                            Digest::of("crawlx/recrawl-batch/v1", &commit.request_id.to_be_bytes()),
                            Vec::new(),
                        );
                        batch.parent_fence = Some((commit.request_id, commit.fence));
                        batch
                    });
                    batch.requests.push(next);
                }
            }
        }
        if let Some(batch) = &children {
            append::<B>(
                self,
                tx.conn(),
                batch,
                &cfg,
                true,
                None,
                run.config.limits.duration_seconds,
            )
            .await?;
        }
        crate::dataset::apply::<B>(
            self,
            tx.conn(),
            commit.run,
            commit.request_id,
            &commit.accepted,
            &commit.state_deltas,
            &commit.outbox,
        )
        .await?;
        if !commit.extensions.is_empty() {
            let attempt = u32::try_from(result.i16("attempts")?)
                .map_err(|_| StoreError::Conflict("invalid extension attempt".into()))?;
            let key = ExtensionAttemptKey {
                tenant,
                run: commit.run,
                request_id: commit.request_id,
                fence: commit.fence,
                attempt,
            };
            persist_extension_attempt::<B>(self, tx.conn(), key, &commit.extensions).await?;
        }
        // Facts share the fenced result transaction and run before any commit field is moved.
        crate::report_history::append_commit_facts::<B>(tx.conn(), &commit, tenant).await?;
        if let Some(page) = commit.page {
            // Duplicate results retain their own immutable capture, never replace another page.
            if !digest_outcome
                .as_ref()
                .is_some_and(|outcome| outcome.is_duplicate())
                || observed_principal.is_some()
            {
                self.put_page_projection_tx(
                    &page,
                    tx.conn(),
                    observed_principal.as_deref().unwrap_or("anonymous"),
                    observed_principal.is_some(),
                )
                .await?;
            }
            if run.config.retention.mode != crawlx_core::config::RetentionMode::Zdr {
                let payload = serde_json::to_value(page)
                    .map_err(|error| StoreError::Serialization(error.to_string()))?;
                // A PostgreSQL trigger copies the source run expiry into the capture; the
                // SQLite and MariaDB triggers only validate, so the statement writes it there.
                stmt!(
                    B,
                    if B::KIND == BackendKind::Postgres {
                        "INSERT INTO page_captures (tenant_id,run_id,frontier_id,fence,state_version,payload) \
                         VALUES ($1,$2,$3,$4,$5,$6)"
                    } else {
                        "INSERT INTO page_captures \
                         (tenant_id,run_id,frontier_id,fence,state_version,payload,expires_at) \
                         SELECT $1,$2,$3,$4,$5,$6,expires_at FROM crawl_runs WHERE run_id=$2"
                    }
                )
                .uuid(run.tenant.0)
                .uuid(commit.run.0)
                .i64(commit.request_id)
                .i64(commit.fence)
                .i64(live)
                .json(&payload)
                .execute(tx.conn())
                .await?;
            }
        }
        if let Some(payload) = commit.head_response {
            #[cfg(all(test, target_os = "linux"))]
            tests::before_head_publish::<B>(tx.conn(), commit.run).await;
            crate::repos::event::append_head_response::<B>(
                self,
                tx.conn(),
                commit.run,
                head_receipt.ok_or_else(|| StoreError::Conflict("missing HEAD response receipt".into()))?,
                payload,
            )
            .await?;
        }
        if let Some(receipt) = head_receipt {
            stmt!(
                B,
                "UPDATE url_frontier SET head_response_receipt=$2 WHERE frontier_id=$1"
            )
            .i64(commit.request_id)
            .bytes(if zdr {
                ZDR_HEAD_RECEIPT_MARKER.as_slice()
            } else {
                receipt.0.as_slice()
            })
            .execute(tx.conn())
            .await?;
        }
        if let Some(outcome) = &digest_outcome {
            let outcome = serde_json::to_value(outcome)?;
            stmt!(
                B,
                "UPDATE url_frontier SET content_dedupe_outcome=$3 WHERE run_id=$1 AND frontier_id=$2"
            )
            .uuid(commit.run.0)
            .i64(commit.request_id)
            .json(&outcome)
            .execute(tx.conn())
            .await?;
        }
        let acquisition_ref = commit
            .acquisition_ref
            .filter(|_| !zdr || head_receipt.is_none())
            .map(|digest| digest.0);
        let document_ref = commit.document_ref.map(|digest| digest.0);
        let completed = stmt!(
            B,
            format!(
                "UPDATE url_frontier SET status=$2,error_code=$3,finished_at={now},lease_owner=NULL,lease_expires_at=NULL,state_version=state_version+1,acquisition_ref=$4,document_ref=$5 WHERE frontier_id=$1 AND status='leased' AND fencing_token=$6 AND lease_expires_at>{clock}",
                now = <B::Dialect as Dialect>::now(),
                clock = <B::Dialect as Dialect>::clock_timestamp()
            )
        )
        .i64(commit.request_id)
        .text(commit.status.as_str())
        .opt_text(commit.reason.as_deref())
        .opt_bytes(acquisition_ref.as_ref().map(<[u8; 32]>::as_slice))
        .opt_bytes(document_ref.as_ref().map(<[u8; 32]>::as_slice))
        .i64(commit.fence)
        .execute(tx.conn())
        .await?;
        if completed != 1 {
            return Err(StoreError::LeaseLost);
        }
        if let Some((lease, _)) = &commit.observation {
            observed_session_tx::<B>(tx.conn(), lease).await?;
        }
        crate::chaos::pause("request.before_result_commit").await;
        tx.commit().await?;
        crate::chaos::pause("request.after_result_commit").await;
        Ok(())
    }
}

/// The receipt the frontier stored for `batch`, if any.
async fn batch_receipt<B: Sql>(
    conn: &mut Conn<B>,
    run: CrawlRunId,
    batch: &[u8],
) -> Result<Option<serde_json::Value>, StoreError> {
    Ok(stmt!(
        B,
        "SELECT receipt FROM frontier_batch_receipts WHERE run_id=$1 AND batch_id=$2"
    )
    .uuid(run.0)
    .bytes(batch)
    .fetch_optional(conn)
    .await?
    .map(|row| row.opt_json("receipt"))
    .transpose()?
    .flatten())
}

/// Whether the run's authorization record is live now, and the instant that was judged.
///
/// `unbound_allowed` answers a run without a record row. The record row is read under a share
/// lock; `with_record_id` only selects the column list of the two historic statements.
async fn authorization_live<B: Sql>(
    conn: &mut Conn<B>,
    run: CrawlRunId,
    with_record_id: bool,
    unbound_allowed: bool,
) -> Result<(bool, crawlx_core::Timestamp), StoreError> {
    // PostgreSQL locks the record row only; the other engines have no `OF` clause.
    let share = if B::KIND == BackendKind::Postgres {
        " FOR SHARE OF a"
    } else {
        <B::Dialect as Dialect>::row_lock(RowLock::Share)
    };
    let authority = if with_record_id {
        stmt!(
            B,
            format!("SELECT a.record_id,a.revoked_at,a.valid_from,a.valid_to,a.body_digest,r.authorization_body_digest FROM crawl_runs r JOIN authorization_records a ON a.record_id=r.authorization_record_id AND a.tenant_id=r.tenant_id WHERE r.run_id=$1{share}")
        )
    } else {
        stmt!(
            B,
            format!("SELECT a.revoked_at,a.valid_from,a.valid_to,a.body_digest,r.authorization_body_digest FROM crawl_runs r JOIN authorization_records a ON a.record_id=r.authorization_record_id AND a.tenant_id=r.tenant_id WHERE r.run_id=$1{share}")
        )
    }
    .uuid(run.0)
    .fetch_optional(conn)
    .await?;
    let now = chrono::Utc::now();
    let allowed = match authority {
        Some(row) => {
            row.opt_ts("revoked_at")?.is_none()
                && row.ts("valid_from")? <= now
                && row.ts("valid_to")? > now
                && row
                    .opt_bytes("authorization_body_digest")?
                    .is_none_or(|bound| row.bytes("body_digest").is_ok_and(|digest| bound == digest))
        }
        None => unbound_allowed,
    };
    Ok((allowed, now))
}

/// Lease the pending interaction row of an observation that already happened.
///
/// PostgreSQL does it in one `UPDATE .. RETURNING`. MariaDB has no `UPDATE .. RETURNING` and
/// SQLite no row locks, so there the caller's write transaction locks the candidate row, takes
/// the next fence, updates by id and reads `attempts` and `fencing_token` back.
async fn lease_interaction<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    lease: &crawlx_core::custody::CustodyLease,
    request_id: i64,
    principal: &str,
    key: &[u8],
) -> Result<Option<(i16, i64)>, StoreError> {
    let ttl = secs(store.cfg.url_batch_ttl);
    if B::KIND == BackendKind::Postgres {
        let row = stmt!(
            B,
            "UPDATE url_frontier SET status='leased',lease_owner=$3, \
             lease_expires_at=clock_timestamp()+make_interval(secs=>$4), \
             fencing_token=nextval('lease_fence_seq'),attempts=attempts+1 \
             WHERE run_id=$1 AND frontier_id=$2 AND principal=$5 AND canonical_key=$6 \
             AND via='interaction' AND status='pending' AND next_attempt_at<=clock_timestamp() AND attempts<32767 \
             RETURNING attempts,fencing_token"
        )
        .uuid(lease.run.0)
        .i64(request_id)
        .uuid(lease.worker.0)
        .f64(ttl)
        .text(principal)
        .bytes(key)
        .fetch_optional(conn)
        .await?;
        return row
            .map(|row| Ok((row.i16("attempts")?, row.i64("fencing_token")?)))
            .transpose();
    }
    let candidate = stmt!(
        B,
        format!(
            "SELECT frontier_id FROM url_frontier \
             WHERE run_id=$1 AND frontier_id=$2 AND principal=$3 AND canonical_key=$4 \
             AND via='interaction' AND status='pending' AND next_attempt_at<={clock} AND attempts<32767{lock}",
            clock = <B::Dialect as Dialect>::clock_timestamp(),
            lock = <B::Dialect as Dialect>::row_lock(RowLock::Update)
        )
    )
    .uuid(lease.run.0)
    .i64(request_id)
    .text(principal)
    .bytes(key)
    .fetch_optional(&mut *conn)
    .await?;
    if candidate.is_none() {
        return Ok(None);
    }
    let fence = B::next_fence(&mut *conn, FenceSeq::Lease).await?;
    let leased = stmt!(
        B,
        format!(
            "UPDATE url_frontier SET status='leased',lease_owner=$2,lease_expires_at={expires},fencing_token=$4,attempts=attempts+1 \
             WHERE frontier_id=$1 AND status='pending'",
            expires = <B::Dialect as Dialect>::add_seconds(<B::Dialect as Dialect>::clock_timestamp(), "$3")
        )
    )
    .i64(request_id)
    .uuid(lease.worker.0)
    .f64(ttl)
    .i64(fence)
    .execute(&mut *conn)
    .await?;
    if leased == 0 {
        return Ok(None);
    }
    let row = stmt!(
        B,
        "SELECT attempts,fencing_token FROM url_frontier WHERE frontier_id=$1"
    )
    .i64(request_id)
    .fetch_one(conn)
    .await?;
    Ok(Some((row.i16("attempts")?, row.i64("fencing_token")?)))
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::artifacts::FsArtifactStore;
    use crate::retention::RetentionSweeper;
    use crate::testkit::{canonical_url, crawl_run, create_crawl};
    use crate::{DeliveryBuffer, Pg, StoreConfig};
    use crawlx_core::repo::FrontierRepo;
    use crawlx_core::request::RequestEnvelopeV1;
    use crawlx_core::{SystemClock, WorkerId};
    use std::collections::BTreeMap;
    use std::os::unix::fs::MetadataExt;
    use std::sync::{Arc, LazyLock};
    use tokio::sync::oneshot;

    struct HeadPause {
        ready: oneshot::Sender<i32>,
        release: oneshot::Receiver<()>,
    }

    static HEAD_PAUSES: LazyLock<parking_lot::Mutex<BTreeMap<CrawlRunId, HeadPause>>> =
        LazyLock::new(|| parking_lot::Mutex::new(BTreeMap::new()));

    pub(super) async fn before_head_publish<B: Sql>(conn: &mut Conn<B>, run: CrawlRunId) {
        let pause = HEAD_PAUSES.lock().remove(&run);
        if let Some(pause) = pause {
            let pid = stmt!(B, "SELECT pg_backend_pid() AS pid")
                .fetch_one(conn)
                .await
                .unwrap()
                .i32("pid")
                .unwrap();
            pause.ready.send(pid).unwrap();
            pause.release.await.unwrap();
        }
    }

    async fn wait_for_erasure_blocker(pg: &Pg, owner: i32) {
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let blocked: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity a \
                     WHERE a.datname=current_database() AND $1=ANY(pg_blocking_pids(a.pid)))",
                )
                .bind(owner)
                .fetch_one(&pg.pool)
                .await
                .unwrap();
                if blocked {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("erasure must wait for the owned HEAD transaction");
    }

    async fn wait_for_filesystem_writer(inode: u64) {
        let inode = format!(":{inode}");
        let pid = std::process::id().to_string();
        tokio::time::timeout(std::time::Duration::from_secs(30), async {
            loop {
                let locks = tokio::fs::read_to_string("/proc/locks").await.unwrap();
                if locks.lines().any(|line| {
                    line.contains("->")
                        && line.split_whitespace().any(|part| part == "FLOCK")
                        && line.split_whitespace().any(|part| part == pid)
                        && line.split_whitespace().any(|part| part.ends_with(&inode))
                }) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the actual filesystem writer must block on the held OS lock");
    }

    #[tokio::test]
    async fn cancelled_head_commit_keeps_transaction_until_filesystem_publication_before_erasure() {
        let Ok(url) = std::env::var("CRAWLX_TEST_DATABASE_URL") else {
            return;
        };
        let root = tempfile::tempdir().unwrap();
        let clock = Arc::new(SystemClock);
        let buffer = Arc::new(
            DeliveryBuffer::open_fs(root.path(), clock.clone(), Default::default())
                .await
                .unwrap(),
        );
        let pg = Pg::connect(
            &url,
            StoreConfig {
                max_connections: 4,
                schema: Some(format!("head_cancel_{}", CrawlRunId::new().0.simple())),
                ..StoreConfig::default()
            },
        )
        .await
        .unwrap()
        .with_delivery_buffer(buffer.clone());
        pg.migrate().await.unwrap();
        let tenant = TenantId::new();
        pg.ensure_tenant(tenant, "head-cancellation").await.unwrap();
        let mut config = create_crawl("https://example.test/", &[], 1);
        config.retention.mode = crawlx_core::config::RetentionMode::Zdr;
        config.retention.days = 0;
        config.orchestration = Some(OrchestrationConfigV1::default());
        let run = crawl_run(tenant, config);
        pg.create(&run, None).await.unwrap();
        let mut envelope = RequestEnvelopeV1::get(canonical_url("https://example.test/head"), 0, None);
        envelope.method = "HEAD".into();
        let ids = pg
            .append_batch(RequestBatchV1::new(
                tenant,
                run.id,
                "anonymous".into(),
                Digest::of("test/head-cancellation", b"batch"),
                vec![envelope],
            ))
            .await
            .unwrap()
            .inserted;
        let leased = pg.lease_batch_fenced(run.id, WorkerId::new(), 1).await.unwrap();
        let queued = pg.get_request(run.id, ids[0]).await.unwrap();
        let mut acquisition = crawlx_core::acquisition::AcquisitionResultV1::new(
            run.id,
            tenant,
            queued.envelope.url.url.clone(),
            queued.identity.key,
            crawlx_core::acquisition::BackendCapabilitiesV1::native_http("crawlx-fetch", "test"),
        );
        acquisition.target_status = Some(200);
        acquisition.transport_succeeded = true;
        let mut commit =
            RequestCommitV1::terminal(run.id, ids[0], leased[0].1, 1, FrontierStatus::Succeeded, None);
        commit.head_response = Some(serde_json::json!({
            "requestId": ids[0],
            "method": "HEAD",
            "status": 200,
            "bodyBytes": 0,
            "response_headers": {"content-type": "text/html"},
            "acquisition": acquisition
        }));
        let (ready, staged) = oneshot::channel();
        let (release, proceed) = oneshot::channel();
        HEAD_PAUSES.lock().insert(
            run.id,
            HeadPause {
                ready,
                release: proceed,
            },
        );
        let caller = {
            let pg = pg.clone();
            let commit = commit.clone();
            tokio::spawn(async move { pg.commit_fenced(commit).await })
        };
        let owner = tokio::time::timeout(std::time::Duration::from_secs(30), staged)
            .await
            .unwrap()
            .unwrap();
        let lock = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(root.path().join("zdr/.lock"))
            .unwrap();
        let inode = lock.metadata().unwrap().ino();
        lock.lock().unwrap();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        let store = Arc::new(
            FsArtifactStore::open(root.path().join("objects"), Arc::new(pg.clone()), clock)
                .await
                .unwrap()
                .with_zdr_buffer(buffer.clone()),
        );
        let erasing = {
            let sweeper = RetentionSweeper::new(pg.clone()).with_artifacts(store);
            tokio::spawn(async move { sweeper.purge_run_objects(run.id).await })
        };
        wait_for_erasure_blocker(&pg, owner).await;
        release.send(()).unwrap();
        wait_for_filesystem_writer(inode).await;
        wait_for_erasure_blocker(&pg, owner).await;
        assert!(!erasing.is_finished());
        lock.unlock().unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(30), erasing)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(buffer.is_empty().await.unwrap());
        let events: i64 =
            sqlx::query_scalar("SELECT count(*) FROM crawl_events WHERE run_id=$1 AND type='head_response'")
                .bind(run.id.0)
                .fetch_one(&pg.pool)
                .await
                .unwrap();
        assert_eq!(
            events, 1,
            "the detached owner must finish its real publication before erasure"
        );
        assert!(matches!(
            pg.commit_fenced(commit).await,
            Err(StoreError::RetentionDenied(_))
        ));
        assert!(buffer.is_empty().await.unwrap());
        pg.drop_schema().await.unwrap();
    }
}
