//! Terminal archive custody: sealing archive output under a frozen secret epoch.
//!
//! A terminal run has permanently closed secret registration, so no live registry
//! snapshot exists to rescan against and none may be recreated. An archive export that
//! packages such a run is sealed under a [`FrozenArchiveGrant`] instead: a durable,
//! secret-free binding of the exact claimed export fence, the run's closed secret epoch
//! and incarnation, the aggregate retained class and deadline, and every source artifact
//! (identity, fixity, class, deadline). Issuing and publishing register no secret and read
//! no raw registry value, so both keep working after the volatile registry expired.
//!
//! The sealed-authority triggers forbid every new catalog row once a run is sealed. The one
//! exception is an exact output row that was validated against a live grant of the claimed
//! export; it can neither reopen the seal nor update key custody or retention.

use super::{
    database_now, denied, frag, insert_artifact, run_lock, scope, ArtifactKeyEnvelope, CiphertextIdentity,
    SecretAuthority, PUBLISH_STALE,
};
use crate::artifact_custody::ArtifactCustody;
use crate::artifacts::ArtifactRow;
use crate::backend::strategy::Conn;
use crate::sql::{stmt, Sql, SqlRow, Stmt};
use crawlx_core::archive_catalog::{ArchiveCustodyV1, ArchiveExportV1};
use crawlx_core::custody::{
    with_frozen_archive, CustodyLease, CustodySource, FrozenArchiveGrant, FrozenArchiveSource, SecretEpoch,
};
use crawlx_core::repo::Sensitivity;
use crawlx_core::{StoreError, TenantId, Timestamp, WorkerId};
use std::collections::BTreeMap;
use std::future::Future;
use uuid::Uuid;

fn class_name(custody: &ArchiveCustodyV1) -> Result<&'static str, StoreError> {
    match custody.sensitivity {
        Sensitivity::Content => Ok("content"),
        Sensitivity::Sensitive => Ok("sensitive"),
        _ => Err(StoreError::RetentionDenied(
            "frozen archive custody is invalid".into(),
        )),
    }
}

fn export_of(lease: &CustodyLease) -> Result<Uuid, StoreError> {
    match lease.source {
        CustodySource::ArchiveExport(export) => Ok(export),
        _ => Err(StoreError::AccessDenied(
            "frozen archive grant requires an archive export producer".into(),
        )),
    }
}

/// Validate the claimed export, the terminal run and its closed authority, returning the
/// exact epoch outputs are sealed under. Holds shared locks until the transaction ends.
async fn frozen_epoch<B: Sql>(
    conn: &mut Conn<B>,
    tenant: TenantId,
    run: crawlx_core::CrawlRunId,
    export: Uuid,
    fence: i64,
) -> Result<SecretEpoch, StoreError> {
    if fence <= 0 {
        return Err(StoreError::LeaseLost);
    }
    let now = frag::clock::<B>();
    let lease_until = stmt!(
        B,
        format!(
            "SELECT lease_until FROM archive_exports WHERE tenant_id=$1 AND run_id=$2 AND export_id=$3 \
         AND fence=$4 AND state='recording' AND (expires_at IS NULL OR expires_at>{now}){}",
            frag::share::<B>()
        )
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .uuid(export)
    .i64(fence)
    .fetch_optional(conn)
    .await?;
    let lease_until = lease_until.ok_or(StoreError::LeaseLost)?.opt_ts("lease_until")?;
    let lease_until = lease_until.ok_or(StoreError::LeaseLost)?;
    if lease_until <= database_now::<B>(conn).await? {
        return Err(StoreError::LeaseLost);
    }
    let state = stmt!(
        B,
        format!(
            "SELECT status::text AS status, retention_mode::text AS retention FROM crawl_runs WHERE tenant_id=$1 AND run_id=$2 \
         AND purge_requested_at IS NULL AND (expires_at IS NULL OR expires_at>{now}){}",
            frag::share::<B>()
        )
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .fetch_optional(conn)
    .await?;
    let state = state.ok_or_else(|| denied("frozen archive run unavailable"))?;
    let (status, retention) = (state.text("status")?, state.text("retention")?);
    if retention == "zdr" {
        return Err(StoreError::RetentionDenied(
            "zdr cannot publish retained artifact custody".into(),
        ));
    }
    if !matches!(status.as_str(), "completed" | "failed" | "cancelled") {
        return Err(denied("frozen archive requires a terminal run"));
    }
    let row = stmt!(
        B,
        format!(
            "SELECT incarnation,epoch,pending_operation,pending_renewal_operation FROM run_secret_authority \
         WHERE tenant_id=$1 AND run_id=$2{}",
            frag::share::<B>()
        )
    )
    .uuid(tenant.0)
    .uuid(run.0)
    .fetch_optional(conn)
    .await?
    .ok_or_else(|| denied("frozen archive secret authority missing"))?;
    let pending = row.opt_uuid("pending_operation")?;
    let renewing = row.opt_uuid("pending_renewal_operation")?;
    let epoch: i64 = row.i64("epoch")?;
    if pending.is_some() || renewing.is_some() || epoch < 1 {
        return Err(denied("frozen archive secret epoch not closed"));
    }
    Ok(SecretEpoch::new(tenant, run, row.uuid("incarnation")?, epoch))
}

/// The proofs of a frozen grant bound against the live catalog: identity, fixity, class and
/// deadline of each artifact, and whether it is still bound to the exported run or to a live
/// export it depends on.
type LiveSources = BTreeMap<Uuid, (Vec<u8>, String, Option<Timestamp>, bool)>;

/// Read the live catalog rows of `ids` for the export.
async fn live_sources<B: Sql>(
    conn: &mut Conn<B>,
    lease: &CustodyLease,
    export: Uuid,
    ids: &[Uuid],
) -> Result<LiveSources, StoreError> {
    // A source must belong to the exported run, or be a committed record of this export or of a
    // live (not erased) export it depends on. A caller-supplied list alone never widens that.
    let rows = if frag::is_pg::<B>() {
        stmt!(
            B,
            "SELECT a.artifact_id,a.content_digest,a.sensitivity::text AS class,a.expires_at,\
         (a.run_id=$3 OR EXISTS(SELECT 1 FROM archive_records r JOIN archive_exports e \
            ON e.tenant_id=r.tenant_id AND e.export_id=r.export_id \
            WHERE r.tenant_id=a.tenant_id AND r.artifact_id=a.artifact_id AND e.state<>'deleted' \
            AND (e.export_id=$4 OR e.export_id IN (SELECT d.source_export FROM archive_dependencies d \
                WHERE d.tenant_id=a.tenant_id AND d.export_id=$4)))) AS bound \
         FROM artifacts a WHERE a.tenant_id=$1 AND a.artifact_id=ANY($2) AND a.deleted_at IS NULL"
        )
        .uuid(lease.tenant.0)
        .uuid_list(ids)
        .uuid(lease.run.0)
        .uuid(export)
        .fetch_all(conn)
        .await?
    } else {
        // engines without array parameters: the ids follow the three fixed parameters
        let list = (0..ids.len())
            .map(|at| format!("${}", at + 4))
            .collect::<Vec<_>>()
            .join(",");
        let template = format!(
            "SELECT a.artifact_id,a.content_digest,a.sensitivity AS class,a.expires_at,\
         (a.run_id=$2 OR EXISTS(SELECT 1 FROM archive_records r JOIN archive_exports e \
            ON e.tenant_id=r.tenant_id AND e.export_id=r.export_id \
            WHERE r.tenant_id=a.tenant_id AND r.artifact_id=a.artifact_id AND e.state<>'deleted' \
            AND (e.export_id=$3 OR e.export_id IN (SELECT d.source_export FROM archive_dependencies d \
                WHERE d.tenant_id=a.tenant_id AND d.export_id=$3)))) AS bound \
         FROM artifacts a WHERE a.tenant_id=$1 AND a.artifact_id IN ({list}) AND a.deleted_at IS NULL"
        );
        Stmt::<B>::dynamic(&template)
            .uuid(lease.tenant.0)
            .uuid(lease.run.0)
            .uuid(export)
            .uuid_list(ids)
            .fetch_all(conn)
            .await?
    };
    let mut live = LiveSources::new();
    for row in &rows {
        live.insert(
            row.uuid("artifact_id")?,
            (
                row.bytes("content_digest")?,
                row.text("class")?,
                row.opt_ts("expires_at")?,
                row.bool("bound")?,
            ),
        );
    }
    Ok(live)
}

/// Check every proof against its live catalog row: identity, fixity, class and deadline.
async fn verify_sources<B: Sql>(
    conn: &mut Conn<B>,
    lease: &CustodyLease,
    export: Uuid,
    sources: &[FrozenArchiveSource],
    now: Timestamp,
) -> Result<(), StoreError> {
    let ids: Vec<Uuid> = sources.iter().map(|source| source.artifact.id.0).collect();
    let live = live_sources::<B>(conn, lease, export, &ids).await?;
    for source in sources {
        let (digest, class, expires_at, bound) = live
            .get(&source.artifact.id.0)
            .ok_or_else(|| StoreError::RetentionDenied("frozen archive source unavailable".into()))?;
        let bounded = match (source.custody.expires_at, *expires_at) {
            (None, None) => true,
            (Some(claimed), Some(actual)) => claimed <= actual,
            (Some(_), None) => true,
            (None, Some(_)) => false,
        };
        if !*bound
            || digest.as_slice() != source.artifact.digest.0.as_slice()
            || class.as_str() != class_name(&source.custody)?
            || !bounded
            || expires_at.is_some_and(|expiry| expiry <= now)
            || source.custody.expires_at.is_some_and(|expiry| expiry <= now)
        {
            return Err(StoreError::RetentionDenied(
                "frozen archive source proof does not match its retained artifact".into(),
            ));
        }
    }
    Ok(())
}

/// The grant-specific columns of `archive_frozen_grants` (the tenant, run and fence come from
/// the producer lease).
struct GrantRow<'a> {
    export: Uuid,
    binding: &'a [u8],
    epoch: SecretEpoch,
    class: &'a str,
    expires_at: Option<Timestamp>,
    count: i32,
}

/// Insert the grant row; `true` when this call created it, `false` for an identical retry.
async fn insert_grant<B: Sql>(
    conn: &mut Conn<B>,
    lease: &CustodyLease,
    row: &GrantRow<'_>,
) -> Result<bool, StoreError> {
    let GrantRow {
        export,
        binding,
        epoch,
        class,
        expires_at,
        count,
    } = *row;
    let insert = |nothing: &str| {
        format!(
            "INSERT INTO archive_frozen_grants(tenant_id,run_id,export_id,binding,fence,incarnation,secret_epoch,sensitivity,expires_at,source_count) \
             VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10){nothing}"
        )
    };
    if B::KIND == crate::backend::BackendKind::MariaDb {
        // A duplicate-key no-op update reports the row as matched, so a retry would look
        // like a creation. Insert plainly and read a duplicate as the retry it is.
        let bound = || {
            stmt!(B, insert(""))
                .uuid(lease.tenant.0)
                .uuid(lease.run.0)
                .uuid(export)
                .bytes(binding)
                .i64(lease.fence)
                .uuid(epoch.incarnation)
                .i64(epoch.epoch)
                .text(class)
                .opt_ts(expires_at)
                .i32(count)
        };
        return match bound().execute(conn).await {
            Ok(_) => Ok(true),
            Err(StoreError::Conflict(_)) => {
                let exists = stmt!(B, "SELECT EXISTS(SELECT 1 FROM archive_frozen_grants WHERE tenant_id=$1 AND export_id=$2 AND binding=$3) AS v")
                    .uuid(lease.tenant.0).uuid(export).bytes(binding).fetch_one(conn).await?.bool("v")?;
                if exists {
                    Ok(false)
                } else {
                    Err(denied("frozen archive grant could not be recorded"))
                }
            }
            Err(other) => Err(other),
        };
    }
    let inserted = stmt!(
        B,
        insert(&format!(
            " {}",
            frag::on_conflict_nothing::<B>(&["tenant_id", "export_id", "binding"])
        ))
    )
    .uuid(lease.tenant.0)
    .uuid(lease.run.0)
    .uuid(export)
    .bytes(binding)
    .i64(lease.fence)
    .uuid(epoch.incarnation)
    .i64(epoch.epoch)
    .text(class)
    .opt_ts(expires_at)
    .i32(count)
    .execute(conn)
    .await?;
    Ok(inserted == 1)
}

/// Insert the source proofs of a freshly created grant.
async fn insert_sources<B: Sql>(
    conn: &mut Conn<B>,
    lease: &CustodyLease,
    export: Uuid,
    binding: &[u8],
    sources: &[FrozenArchiveSource],
) -> Result<(), StoreError> {
    // multi-row VALUES, a bounded number of rows per statement (every engine)
    for chunk in sources.chunks(200) {
        let mut rows = Vec::with_capacity(chunk.len());
        for at in 0..chunk.len() {
            let first = 4 + at * 4;
            rows.push(format!(
                "($1,$2,$3,${},${},${},${})",
                first,
                first + 1,
                first + 2,
                first + 3
            ));
        }
        let template = format!(
            "INSERT INTO archive_frozen_sources(tenant_id,export_id,binding,artifact_id,digest,sensitivity,expires_at) VALUES {}",
            rows.join(",")
        );
        let mut statement = Stmt::<B>::dynamic(&template)
            .uuid(lease.tenant.0)
            .uuid(export)
            .bytes(binding);
        for source in chunk {
            statement = statement
                .uuid(source.artifact.id.0)
                .bytes(source.artifact.digest.0.as_slice())
                .text(class_name(&source.custody)?)
                .opt_ts(source.custody.expires_at);
        }
        statement.execute(conn).await?;
    }
    Ok(())
}

impl<B: Sql> SecretAuthority<B> {
    /// Persist a frozen archive grant for the claimed export of a terminal run.
    ///
    /// The aggregate class and deadline are `custody` narrowed by every source. Registers
    /// nothing and never touches the volatile registry. Retrying the same inputs is
    /// idempotent; a reclaimed export (new fence) needs a new grant.
    ///
    /// # Errors
    /// Rejects non-export producers, stale or unclaimed fences, non-terminal and ZDR runs,
    /// open secret operations, and any source whose identity, fixity, class or deadline
    /// differs from its catalog row.
    pub async fn issue_frozen_archive(
        &self,
        lease: &CustodyLease,
        custody: &ArchiveCustodyV1,
        sources: &[FrozenArchiveSource],
    ) -> Result<FrozenArchiveGrant, StoreError> {
        scope(lease.tenant)?;
        lease.check_local_cancellation()?;
        let export = export_of(lease)?;
        let mut tx = self.transaction().await?;
        run_lock::<B>(tx.conn(), lease.tenant, lease.run, false).await?;
        let epoch = frozen_epoch::<B>(tx.conn(), lease.tenant, lease.run, export, lease.fence).await?;
        let now = database_now::<B>(tx.conn()).await?;
        let mut narrowed = *custody;
        narrowed.validate(now)?;
        for source in sources {
            narrowed = narrowed.narrow(source.custody, now)?;
        }
        let grant = FrozenArchiveGrant::new(lease, epoch, narrowed, sources.to_vec())?;
        verify_sources::<B>(tx.conn(), lease, export, grant.sources(), now).await?;
        let count =
            i32::try_from(grant.sources().len()).map_err(|_| denied("frozen archive source count"))?;
        let created = insert_grant::<B>(
            tx.conn(),
            lease,
            &GrantRow {
                export,
                binding: grant.binding().0.as_slice(),
                epoch,
                class: class_name(&grant.custody)?,
                expires_at: grant.custody.expires_at,
                count,
            },
        )
        .await?;
        if created {
            insert_sources::<B>(
                tx.conn(),
                lease,
                export,
                grant.binding().0.as_slice(),
                grant.sources(),
            )
            .await?;
        }
        lease.check_local_cancellation()?;
        tx.commit().await?;
        lease.check_local_cancellation()?;
        Ok(grant)
    }

    /// Atomically publish one sealed archive output under its frozen grant.
    ///
    /// Everything is revalidated in one transaction: the export is still recording at the
    /// grant's exact fence, the run is terminal, the closed epoch and incarnation are
    /// unchanged, the persisted grant matches, every source still matches its catalog row,
    /// and the output stays inside the grant's class, deadline, kind and media types. The
    /// catalog row, its output binding and the wrapped key commit together. An identical
    /// retry is idempotent; nothing is rescanned and no secret is registered.
    ///
    /// # Errors
    /// Rejects any other producer, run, fence, epoch or grant, drifted or revoked sources,
    /// outputs outside the grant and changed retries of an immutable publication.
    pub async fn publish_frozen_archive(
        &self,
        grant: &FrozenArchiveGrant,
        lease: &CustodyLease,
        artifact: &ArtifactRow,
        ciphertext: &CiphertextIdentity,
        envelope: &ArtifactKeyEnvelope,
    ) -> Result<(), StoreError> {
        scope(lease.tenant)?;
        lease.check_local_cancellation()?;
        grant.check_lease(lease)?;
        let export = export_of(lease)?;
        if artifact.tenant != lease.tenant || artifact.run != lease.run {
            return Err(denied("artifact publication scope mismatch"));
        }
        if artifact.bucket.len() > 1024 || artifact.object_key.len() > 4096 {
            return Err(denied("artifact publication metadata bound exceeded"));
        }
        grant.check_output(
            artifact.sensitivity,
            artifact.expires_at,
            &artifact.kind,
            &artifact.content_type,
        )?;
        let ciphertext = CiphertextIdentity::new(ciphertext.digest, ciphertext.size_bytes)?;
        if artifact.object_key
            != super::encrypted_object_key(artifact.tenant, artifact.run, artifact.id, ciphertext.digest)
        {
            return Err(denied(
                "artifact ciphertext key must bind unique artifact identity",
            ));
        }
        envelope.validate(lease.tenant, lease.run, artifact.id)?;
        let row_json =
            serde_json::to_value(artifact).map_err(|_| denied("artifact publication metadata invalid"))?;
        let envelope_json =
            serde_json::to_value(envelope).map_err(|_| denied("artifact key custody metadata invalid"))?;
        let plaintext_size =
            i64::try_from(artifact.size_bytes).map_err(|_| denied("artifact plaintext size overflow"))?;
        let ciphertext_size =
            i64::try_from(ciphertext.size_bytes).map_err(|_| denied("artifact ciphertext size overflow"))?;
        let mut tx = self.transaction().await?;
        run_lock::<B>(tx.conn(), lease.tenant, lease.run, false).await?;
        let epoch = frozen_epoch::<B>(tx.conn(), lease.tenant, lease.run, export, lease.fence).await?;
        if epoch != grant.epoch {
            return Err(denied(PUBLISH_STALE));
        }
        let now = database_now::<B>(tx.conn()).await?;
        let binding = grant.binding();
        let clock = frag::clock::<B>();
        let same_deadline = frag::null_safe_eq::<B>("g.expires_at", "$9");
        let granted = stmt!(
            B,
            format!(
                "SELECT EXISTS(SELECT 1 FROM archive_frozen_grants g WHERE g.tenant_id=$1 AND g.run_id=$2 \
             AND g.export_id=$3 AND g.binding=$4 AND g.fence=$5 AND g.incarnation=$6 AND g.secret_epoch=$7 \
             AND g.sensitivity=$8 AND {same_deadline} AND g.source_count=$10 \
             AND (g.expires_at IS NULL OR g.expires_at>{clock})) AS v"
            )
        )
        .uuid(lease.tenant.0)
        .uuid(lease.run.0)
        .uuid(export)
        .bytes(binding.0.as_slice())
        .i64(lease.fence)
        .uuid(epoch.incarnation)
        .i64(epoch.epoch)
        .text(class_name(&grant.custody)?)
        .opt_ts(grant.custody.expires_at)
        .i32(i32::try_from(grant.sources().len()).map_err(|_| denied("frozen archive source count"))?)
        .fetch_one(tx.conn())
        .await?
        .bool("v")?;
        if !granted {
            return Err(StoreError::LeaseLost);
        }
        // Sources stay bound to the run or to a live (not erased) record of this export or of an
        // export it depends on, so erasure of a source export revokes this grant.
        let drifted = stmt!(
            B,
            format!(
                "SELECT (SELECT count(*) FROM archive_frozen_sources s WHERE s.tenant_id=$1 AND s.export_id=$2 AND s.binding=$3) \
             - (SELECT count(*) FROM archive_frozen_sources s JOIN artifacts a ON a.artifact_id=s.artifact_id AND a.tenant_id=s.tenant_id \
                WHERE s.tenant_id=$1 AND s.export_id=$2 AND s.binding=$3 AND a.deleted_at IS NULL \
                AND (a.expires_at IS NULL OR a.expires_at>{clock}) \
                AND a.content_digest=s.digest AND a.sensitivity::text=s.sensitivity \
                AND (s.expires_at IS NULL OR s.expires_at>{clock}) \
                AND (a.run_id=$4 OR EXISTS(SELECT 1 FROM archive_records r JOIN archive_exports e \
                    ON e.tenant_id=r.tenant_id AND e.export_id=r.export_id \
                    WHERE r.tenant_id=a.tenant_id AND r.artifact_id=a.artifact_id AND e.state<>'deleted' \
                    AND (e.export_id=$2 OR e.export_id IN (SELECT d.source_export FROM archive_dependencies d \
                        WHERE d.tenant_id=a.tenant_id AND d.export_id=$2))))) AS v"
            )
        )
        .uuid(lease.tenant.0)
        .uuid(export)
        .bytes(binding.0.as_slice())
        .uuid(lease.run.0)
        .fetch_one(tx.conn())
        .await?
        .i64("v")?;
        if drifted != 0 {
            return Err(StoreError::RetentionDenied(
                "frozen archive source changed or was revoked".into(),
            ));
        }
        if artifact.expires_at.is_some_and(|expiry| expiry <= now) {
            return Err(StoreError::RetentionDenied(
                "archive source expired before publication".into(),
            ));
        }
        let existing = stmt!(
            B,
            "SELECT artifact_payload,envelope,incarnation,secret_epoch,ciphertext_digest,ciphertext_size,object_key \
             FROM artifact_key_custody WHERE tenant_id=$1 AND run_id=$2 AND artifact_id=$3"
        )
        .uuid(lease.tenant.0)
        .uuid(lease.run.0)
        .uuid(artifact.id.0)
        .fetch_optional(tx.conn())
        .await?;
        lease.check_local_cancellation()?;
        if let Some(existing) = existing {
            // Idempotent retry only: the frozen epoch is never rewritten.
            if existing.json("artifact_payload")? != row_json
                || existing.json("envelope")? != envelope_json
                || existing.uuid("incarnation")? != epoch.incarnation
                || existing.i64("secret_epoch")? != epoch.epoch
                || existing.bytes("ciphertext_digest")?.as_slice() != ciphertext.digest.0.as_slice()
                || existing.i64("ciphertext_size")? != ciphertext_size
                || existing.text("object_key")? != artifact.object_key
            {
                return Err(denied("artifact publication retry changed immutable custody"));
            }
        } else {
            stmt!(
                B,
                "INSERT INTO archive_frozen_outputs(tenant_id,run_id,export_id,binding,artifact_id,kind,bucket,object_key,size_bytes,\
                 content_digest,content_type,sensitivity,created_at,expires_at,incarnation,secret_epoch,ciphertext_digest,ciphertext_size) \
                 VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)"
            )
            .uuid(lease.tenant.0)
            .uuid(lease.run.0)
            .uuid(export)
            .bytes(binding.0.as_slice())
            .uuid(artifact.id.0)
            .text(&artifact.kind)
            .text(&artifact.bucket)
            .text(&artifact.object_key)
            .i64(plaintext_size)
            .bytes(artifact.digest.0.as_slice())
            .text(&artifact.content_type)
            .text(artifact.sensitivity.as_str())
            .ts(artifact.created_at)
            .opt_ts(artifact.expires_at)
            .uuid(epoch.incarnation)
            .i64(epoch.epoch)
            .bytes(ciphertext.digest.0.as_slice())
            .i64(ciphertext_size)
            .execute(tx.conn())
            .await?;
            insert_artifact::<B>(tx.conn(), artifact, plaintext_size).await?;
            stmt!(B, "INSERT INTO artifact_key_custody(artifact_id,tenant_id,run_id,incarnation,secret_epoch,object_key,plaintext_digest,plaintext_size,ciphertext_digest,ciphertext_size,envelope,artifact_payload,created_at) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)")
                .uuid(artifact.id.0).uuid(lease.tenant.0).uuid(lease.run.0).uuid(epoch.incarnation).i64(epoch.epoch)
                .text(&artifact.object_key).bytes(artifact.digest.0.as_slice()).i64(plaintext_size)
                .bytes(ciphertext.digest.0.as_slice()).i64(ciphertext_size)
                .json(&envelope_json).json(&row_json).ts(artifact.created_at)
                .execute(tx.conn()).await?;
        }
        lease.check_local_cancellation()?;
        tx.commit().await?;
        lease.check_local_cancellation()?;
        Ok(())
    }
}

/// Run `work` with the frozen grant of a terminal run's claimed export.
///
/// A live run is not frozen: `work` runs unchanged under the caller's producer and the
/// normal epoch-checked publication. A terminal run's grant is issued from `sources` (the
/// exact retained artifacts the output derives from, each with its [`ArchiveCustodyV1`]) and
/// `requested`, and scopes only `work`. The grant is not inherited by spawned tasks.
///
/// # Errors
/// Fails closed with [`StoreError::Unavailable`] when a terminal run has no custody, and
/// otherwise with the errors of [`SecretAuthority::issue_frozen_archive`].
pub async fn with_terminal_grant<F: Future>(
    custody: Option<&dyn ArtifactCustody>,
    terminal: bool,
    export: &ArchiveExportV1,
    requested: &ArchiveCustodyV1,
    sources: Vec<FrozenArchiveSource>,
    work: F,
) -> Result<F::Output, StoreError> {
    if !terminal {
        return Ok(work.await);
    }
    let custody =
        custody.ok_or_else(|| StoreError::Unavailable("terminal archive custody unavailable".into()))?;
    let lease = CustodyLease::for_archive_export(
        export.tenant,
        export.run,
        export.id,
        WorkerId(export.id),
        export.fence,
    );
    let grant = custody.issue_frozen_archive(&lease, requested, &sources).await?;
    Ok(with_frozen_archive(grant, work).await)
}
