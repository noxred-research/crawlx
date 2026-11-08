//! `StateRepo` over `states`, `state_clusters`, `state_cluster_membership`.

use crate::codec::{
    conv, digest, from_json, get, opt_digest, pack_u64s, signed_bits, to_json, unpack_u64s, unsigned_bits,
};
use crate::error::{db, not_found};
use crate::pg::Pg;
use crate::repos::event::append_event;
use crate::repos::ledger::{key_from_row, KEY_COLS};
use async_trait::async_trait;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ClusterSplitRecord, NewState, SplitApplied, StateRepo};
use crawlx_core::state::StateSignature;
use crawlx_core::url::CanonicalUrl;
use crawlx_core::{ArtifactRef, CrawlRunId, SessionId, StateClusterId, StateId, StoreError};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use sqlx::postgres::PgRow;
use sqlx::PgConnection;
use std::collections::{BTreeMap, BTreeSet};

/// Insert one observation, its cluster (when new) and its active membership.
/// Idempotent on `state_id`: re-putting an existing state is a no-op (states are immutable).
pub(crate) async fn insert_state(
    pg: &Pg,
    conn: &mut PgConnection,
    run: CrawlRunId,
    s: &NewState,
) -> Result<(), StoreError> {
    let (tenant, zdr) = Pg::privacy_scope_tx(conn, run).await?;
    let sig = &s.signature;
    let manifest = if zdr {
        None
    } else {
        s.artifacts
            .iter()
            .find(|(kind, _)| kind == "manifest")
            .map(|(_, artifact)| artifact.id.0)
    };
    let inserted = sqlx::query(
        "INSERT INTO states (state_id, run_id, session_id, route_key, semantic_affordance_minhash, dom_structure_simhash, visible_identity_digest, \
           frame_tree_digest, network_operation_digest, visual_phash, browser_storage_digest, masks, epoch_navigation, epoch_document, epoch_mutation, \
           state_algo_version, manifest_artifact_id, observed_at, expires_at, observed_url, artifacts) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, \
           (SELECT expires_at FROM crawl_runs WHERE run_id = $2), $19, $20) \
         ON CONFLICT (state_id) DO NOTHING",
    )
    .bind(s.id.0)
    .bind(run.0)
    .bind(s.session.0)
    .bind(sig.route_key.to_hex())
    .bind(pack_u64s(&sig.semantic_affordance_minhash))
    .bind(signed_bits(sig.dom_structure_simhash)?)
    .bind(sig.visible_element_identity_digest.0.to_vec())
    .bind(sig.frame_tree_digest.0.to_vec())
    .bind(sig.network_operation_digest.0.to_vec())
    .bind(sig.visual_phash.map(signed_bits).transpose()?)
    .bind(sig.browser_storage_digest.map(|d| d.0.to_vec()))
    .bind(if zdr { serde_json::json!([]) } else { to_json(&s.masks)? })
    .bind(conv::<u64, i64>(s.epoch.navigation_seq, "navigation_seq")?)
    .bind(conv::<u64, i64>(s.epoch.document_seq, "document_seq")?)
    .bind(conv::<u64, i64>(s.epoch.mutation_seq, "mutation_seq")?)
    .bind(conv::<u16, i16>(sig.version, "state_algo_version")?)
    .bind(manifest)
    .bind(s.observed_at)
    .bind(if zdr { None } else { Some(to_json(&s.url)?) })
    .bind(if zdr { serde_json::json!([]) } else { to_json(&s.artifacts)? })
    .execute(&mut *conn)
    .await
    .map_err(db)?;
    if inserted.rows_affected() == 0 {
        return Ok(());
    }
    if zdr {
        pg.ephemeral_put(tenant, run, i64::MIN + 1, &format!("_state:{}", s.id), s)
            .await?;
    }
    if s.cluster_is_new {
        sqlx::query(
            "INSERT INTO state_clusters (cluster_id, run_id, prototype_state_id, algo_version) VALUES ($1, $2, $3, $4) ON CONFLICT (cluster_id) DO NOTHING",
        )
        .bind(s.cluster.0)
        .bind(run.0)
        .bind(s.id.0)
        .bind(conv::<u16, i16>(sig.version, "state_algo_version")?)
        .execute(&mut *conn)
        .await
        .map_err(db)?;
    } else {
        let exists: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT cluster_id FROM state_clusters WHERE cluster_id = $1")
                .bind(s.cluster.0)
                .fetch_optional(&mut *conn)
                .await
                .map_err(db)?;
        if exists.is_none() {
            return Err(not_found("state_cluster", s.cluster));
        }
    }
    sqlx::query("INSERT INTO state_cluster_membership (state_id, cluster_id, decision_version, similarity) VALUES ($1, $2, 1, $3)")
        .bind(s.id.0)
        .bind(s.cluster.0)
        .bind(s.cluster_similarity)
        .execute(&mut *conn)
        .await
        .map_err(db)?;
    Ok(())
}

/// Rebuild a signature from `states`-shaped columns of `r`.
fn signature_from_row(r: &PgRow) -> Result<StateSignature, StoreError> {
    let route_key = Digest::from_hex(&get::<String>(r, "route_key")?)
        .map_err(|e| StoreError::Serialization(e.to_string()))?;
    Ok(StateSignature {
        version: conv(get::<i16>(r, "state_algo_version")?, "state_algo_version")?,
        route_key,
        semantic_affordance_minhash: unpack_u64s(&get::<Vec<u8>>(r, "semantic_affordance_minhash")?)?,
        dom_structure_simhash: unsigned_bits(get(r, "dom_structure_simhash")?)?,
        visible_element_identity_digest: digest(&get::<Vec<u8>>(r, "visible_identity_digest")?)?,
        frame_tree_digest: digest(&get::<Vec<u8>>(r, "frame_tree_digest")?)?,
        network_operation_digest: digest(
            &get::<Option<Vec<u8>>>(r, "network_operation_digest")?.ok_or_else(|| {
                StoreError::Serialization("state without network_operation_digest".to_owned())
            })?,
        )?,
        visual_phash: get::<Option<i64>>(r, "visual_phash")?
            .map(unsigned_bits)
            .transpose()?,
        browser_storage_digest: opt_digest(get(r, "browser_storage_digest")?)?,
    })
}

#[async_trait]
impl StateRepo for Pg {
    async fn put_state(&self, state: &NewState) -> Result<(), StoreError> {
        let _timer = self.query_timer("state.put_state");
        let mut tx = self.pool.begin().await.map_err(db)?;
        let run: Option<uuid::Uuid> =
            sqlx::query_scalar("SELECT run_id FROM crawl_sessions WHERE session_id = $1")
                .bind(state.session.0)
                .fetch_optional(&mut *tx)
                .await
                .map_err(db)?;
        let run = CrawlRunId(run.ok_or_else(|| not_found("crawl_session", state.session))?);
        insert_state(self, &mut tx, run, state).await?;
        tx.commit().await.map_err(db)
    }

    async fn list_states(&self, run: CrawlRunId) -> Result<Vec<NewState>, StoreError> {
        let _timer = self.query_timer("state.list_states");
        let rows = sqlx::query(
            "SELECT s.state_id, s.session_id, s.route_key, s.semantic_affordance_minhash, s.dom_structure_simhash, s.visible_identity_digest, \
               s.frame_tree_digest, s.network_operation_digest, s.visual_phash, s.browser_storage_digest, s.masks, s.epoch_navigation, \
               s.epoch_document, s.epoch_mutation, s.state_algo_version, s.observed_at, s.observed_url, s.artifacts, \
               m.cluster_id, m.similarity, (c.prototype_state_id = s.state_id) AS cluster_is_new \
             FROM states s JOIN state_cluster_membership m ON m.state_id = s.state_id AND m.active \
             JOIN state_clusters c ON c.cluster_id = m.cluster_id \
             WHERE s.run_id = $1 ORDER BY s.observed_at, s.state_id",
        )
        .bind(run.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        let mut states = Vec::with_capacity(rows.len());
        for r in &rows {
            if zdr {
                let id = StateId(get(r, "state_id")?);
                let mut state: NewState = self
                    .ephemeral_get(tenant, run, i64::MIN + 1, &format!("_state:{id}"))
                    .await?;
                state.cluster = StateClusterId(get(r, "cluster_id")?);
                state.cluster_similarity = get(r, "similarity")?;
                state.cluster_is_new = get(r, "cluster_is_new")?;
                states.push(state);
                continue;
            }
            let url: serde_json::Value = get::<Option<serde_json::Value>>(r, "observed_url")?
                .ok_or_else(|| StoreError::Serialization("state without observed_url".to_owned()))?;
            states.push(NewState {
                id: StateId(get(r, "state_id")?),
                session: SessionId(get(r, "session_id")?),
                epoch: ObservationEpoch {
                    navigation_seq: conv(get::<i64>(r, "epoch_navigation")?, "epoch_navigation")?,
                    document_seq: conv(get::<i64>(r, "epoch_document")?, "epoch_document")?,
                    mutation_seq: conv(get::<i64>(r, "epoch_mutation")?, "epoch_mutation")?,
                },
                url: from_json::<CanonicalUrl>(url)?,
                signature: signature_from_row(r)?,
                masks: from_json(get::<serde_json::Value>(r, "masks")?)?,
                cluster: StateClusterId(get(r, "cluster_id")?),
                cluster_similarity: get(r, "similarity")?,
                cluster_is_new: get(r, "cluster_is_new")?,
                artifacts: from_json::<Vec<(String, ArtifactRef)>>(get::<serde_json::Value>(
                    r,
                    "artifacts",
                )?)?,
                observed_at: get(r, "observed_at")?,
            });
        }
        Ok(states)
    }

    async fn list_clusters(
        &self,
        run: CrawlRunId,
    ) -> Result<Vec<(StateClusterId, StateSignature, u32)>, StoreError> {
        let _timer = self.query_timer("state.list_clusters");
        let rows = sqlx::query(
            "SELECT c.cluster_id, p.route_key, p.semantic_affordance_minhash, p.dom_structure_simhash, p.visible_identity_digest, \
               p.frame_tree_digest, p.network_operation_digest, p.visual_phash, p.browser_storage_digest, p.state_algo_version, \
               (SELECT count(*) FROM state_cluster_membership m WHERE m.cluster_id = c.cluster_id AND m.active) AS members \
             FROM state_clusters c JOIN states p ON p.state_id = c.prototype_state_id \
             WHERE c.run_id = $1 AND c.status = 'active' ORDER BY c.created_at, c.cluster_id",
        )
        .bind(run.0)
        .fetch_all(&self.pool)
        .await
        .map_err(db)?;
        rows.iter()
            .map(|r| {
                Ok((
                    StateClusterId(get(r, "cluster_id")?),
                    signature_from_row(r)?,
                    conv(get::<i64>(r, "members")?, "members")?,
                ))
            })
            .collect()
    }

    async fn apply_split(&self, split: &ClusterSplitRecord) -> Result<SplitApplied, StoreError> {
        let _timer = self.query_timer("state.apply_split");
        let mut tx = self.pool.begin().await.map_err(db)?;
        let applied = self.apply_split_tx(&mut tx, split).await?;
        tx.commit().await.map_err(db)?;
        Metrics::global().counter(names::STATES_SPLITS).inc();
        Ok(applied)
    }
}

impl Pg {
    async fn apply_split_tx(
        &self,
        tx: &mut PgConnection,
        split: &ClusterSplitRecord,
    ) -> Result<SplitApplied, StoreError> {
        let source = sqlx::query(
            "SELECT version, status FROM state_clusters WHERE cluster_id = $1 AND run_id = $2 FOR UPDATE",
        )
        .bind(split.source.0)
        .bind(split.run.0)
        .fetch_optional(&mut *tx)
        .await
        .map_err(db)?
        .ok_or_else(|| not_found("state_cluster", split.source))?;
        if get::<String>(&source, "status")? != "active" {
            return Err(StoreError::Conflict(format!(
                "state cluster {} is already superseded",
                split.source
            )));
        }
        let version: u32 = conv(get::<i32>(&source, "version")?, "version")?;
        if version != split.source_version {
            return Err(StoreError::Conflict(format!(
                "state cluster {} is at version {version}, split computed against {}",
                split.source, split.source_version
            )));
        }
        let successor_ids: Vec<uuid::Uuid> = split.successors.iter().map(|s| s.cluster.0).collect();
        let taken: i64 = sqlx::query_scalar("SELECT count(*) FROM state_clusters WHERE cluster_id = ANY($1)")
            .bind(&successor_ids)
            .fetch_one(&mut *tx)
            .await
            .map_err(db)?;
        if taken != 0 {
            return Err(StoreError::Conflict(
                "split successor id already exists".to_owned(),
            ));
        }
        let active: Vec<uuid::Uuid> = sqlx::query_scalar(
            "SELECT state_id FROM state_cluster_membership WHERE cluster_id = $1 AND active FOR UPDATE",
        )
        .bind(split.source.0)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let active: BTreeSet<StateId> = active.into_iter().map(StateId).collect();
        let assigned = split_assignment(split, &active)?;

        for s in &split.successors {
            sqlx::query(
                "INSERT INTO state_clusters (cluster_id, run_id, version, prototype_state_id, algo_version, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
            )
            .bind(s.cluster.0)
            .bind(split.run.0)
            .bind(conv::<u32, i32>(s.version, "version")?)
            .bind(s.prototype.0)
            .bind(conv::<u16, i16>(s.signature.version, "state_algo_version")?)
            .bind(split.decided_at)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        }
        sqlx::query("UPDATE state_cluster_membership SET active = false WHERE cluster_id = $1 AND active")
            .bind(split.source.0)
            .execute(&mut *tx)
            .await
            .map_err(db)?;
        for s in &split.successors {
            for m in &s.members {
                sqlx::query(
                    "INSERT INTO state_cluster_membership (state_id, cluster_id, decision_version, similarity, assigned_at) \
                     VALUES ($1, $2, $3, $4, $5)",
                )
                .bind(m.state.0)
                .bind(s.cluster.0)
                .bind(conv::<u32, i32>(s.version, "decision_version")?)
                .bind(m.similarity)
                .bind(split.decided_at)
                .execute(&mut *tx)
                .await
                .map_err(db)?;
            }
        }
        sqlx::query(
            "UPDATE state_clusters SET status = 'superseded', superseded_by = $2 WHERE cluster_id = $1",
        )
        .bind(split.source.0)
        .bind(successor_ids[0])
        .execute(&mut *tx)
        .await
        .map_err(db)?;

        // Re-key the ledger: every context of the source goes to the successor its actions'
        // `before_state`s fall in (memberships are already moved, so the join reads the
        // successor); ties and contexts without action evidence go to the first successor.
        let evidence_rows = sqlx::query(
            "SELECT c.context_id, m.cluster_id, count(*) AS n \
             FROM action_contexts c JOIN actions a ON a.context_id = c.context_id \
             JOIN state_cluster_membership m ON m.state_id = a.before_state_id AND m.active \
             WHERE c.run_id = $1 AND c.state_cluster_id = $2 AND m.cluster_id = ANY($3) \
             GROUP BY c.context_id, m.cluster_id ORDER BY c.context_id, m.cluster_id",
        )
        .bind(split.run.0)
        .bind(split.source.0)
        .bind(&successor_ids)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let mut evidence: BTreeMap<i64, BTreeMap<StateClusterId, u32>> = BTreeMap::new();
        for r in &evidence_rows {
            let n: u32 = conv(get::<i64>(r, "n")?, "n")?;
            evidence
                .entry(get(r, "context_id")?)
                .or_default()
                .insert(StateClusterId(get(r, "cluster_id")?), n);
        }
        let contexts = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT c.context_id, {KEY_COLS} FROM action_contexts c \
         WHERE c.run_id = $1 AND c.state_cluster_id = $2 ORDER BY c.context_id FOR UPDATE"
        )))
        .bind(split.run.0)
        .bind(split.source.0)
        .fetch_all(&mut *tx)
        .await
        .map_err(db)?;
        let mut rekeyed = 0_u32;
        for r in &contexts {
            let context_id: i64 = get(r, "context_id")?;
            let mut key = key_from_row(self, r).await?;
            key.state_cluster = pick_successor(split, evidence.get(&context_id));
            let (tenant, zdr) = Pg::privacy_scope_tx(tx, split.run).await?;
            if zdr {
                self.ephemeral_put(
                    tenant,
                    split.run,
                    i64::MIN + 1,
                    &format!("_context:{}", key.id()),
                    &key,
                )
                .await?;
            }
            sqlx::query(
                "UPDATE action_contexts SET state_cluster_id = $2, context_hash = $3 WHERE context_id = $1",
            )
            .bind(context_id)
            .bind(key.state_cluster.0)
            .bind(key.id().0.to_vec())
            .execute(&mut *tx)
            .await
            .map_err(db)?;
            rekeyed += 1;
        }
        let applied = SplitApplied {
            memberships_moved: u32::try_from(assigned.len()).unwrap_or(u32::MAX),
            action_contexts_rekeyed: rekeyed,
        };
        append_event(
            self,
            tx,
            split.run,
            "state_cluster_split",
            split_event(split, applied),
        )
        .await?;
        Ok(applied)
    }
}

/// Successor of every active member; fails unless the successors partition `active`
/// exactly and every prototype is one of its own members.
fn split_assignment(
    split: &ClusterSplitRecord,
    active: &BTreeSet<StateId>,
) -> Result<BTreeMap<StateId, StateClusterId>, StoreError> {
    if split.successors.is_empty() {
        return Err(StoreError::Conflict("split without successors".to_owned()));
    }
    let mut assigned = BTreeMap::new();
    for s in &split.successors {
        if s.members.is_empty() {
            return Err(StoreError::Conflict(format!(
                "split successor {} has no members",
                s.cluster
            )));
        }
        if !s.members.iter().any(|m| m.state == s.prototype) {
            return Err(StoreError::Conflict(format!(
                "split successor {} prototype {} is not a member",
                s.cluster, s.prototype
            )));
        }
        for m in &s.members {
            if !active.contains(&m.state) {
                return Err(StoreError::Conflict(format!(
                    "state {} is not an active member of cluster {}",
                    m.state, split.source
                )));
            }
            if assigned.insert(m.state, s.cluster).is_some() {
                return Err(StoreError::Conflict(format!(
                    "state {} is assigned to two split successors",
                    m.state
                )));
            }
        }
    }
    if assigned.len() != active.len() {
        return Err(StoreError::Conflict(format!(
            "split moves {} of {} active members of cluster {}",
            assigned.len(),
            active.len(),
            split.source
        )));
    }
    Ok(assigned)
}

/// Successor with the most action evidence; ties and no evidence pick the first successor.
pub(crate) fn pick_successor(
    split: &ClusterSplitRecord,
    evidence: Option<&BTreeMap<StateClusterId, u32>>,
) -> StateClusterId {
    let mut best = (split.successors[0].cluster, 0_u32);
    for s in &split.successors {
        let n = evidence.and_then(|e| e.get(&s.cluster)).copied().unwrap_or(0);
        if n > best.1 {
            best = (s.cluster, n);
        }
    }
    best.0
}

/// Payload of the `state_cluster_split` run event.
pub(crate) fn split_event(split: &ClusterSplitRecord, applied: SplitApplied) -> serde_json::Value {
    serde_json::json!({
        "source": split.source,
        "source_version": split.source_version,
        "successors": split.successors.iter().map(|s| serde_json::json!({
            "cluster": s.cluster,
            "version": s.version,
            "prototype": s.prototype,
            "members": s.members.len(),
        })).collect::<Vec<_>>(),
        "memberships_moved": applied.memberships_moved,
        "action_contexts_rekeyed": applied.action_contexts_rekeyed,
        "decided_at": split.decided_at,
    })
}
