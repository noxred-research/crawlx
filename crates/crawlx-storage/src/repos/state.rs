//! `StateRepo` over `states`, `state_clusters`, `state_cluster_membership`.

use crate::backend::strategy::Conn;
use crate::backend::{Dialect, RowLock};
use crate::codec::{
    conv, digest, from_json, opt_digest, pack_u64s, signed_bits, to_json, unpack_u64s, unsigned_bits,
};
use crate::error::not_found;
use crate::repos::event::append_event;
use crate::repos::ledger::{key_from_row, KEY_COLS};
use crate::sql::{in_list, insert_once, stmt, Sql, SqlRow, Stmt};
use crate::store::Store;
use async_trait::async_trait;
use crawlx_core::epoch::ObservationEpoch;
use crawlx_core::hash::Digest;
use crawlx_core::repo::{ClusterSplitRecord, NewState, SplitApplied, StateRepo};
use crawlx_core::state::StateSignature;
use crawlx_core::url::CanonicalUrl;
use crawlx_core::{ArtifactRef, CrawlRunId, SessionId, StateClusterId, StateId, StoreError};
use crawlx_telemetry::metrics::names;
use crawlx_telemetry::Metrics;
use std::collections::{BTreeMap, BTreeSet};

/// Insert one observation, its cluster (when new) and its active membership.
/// Idempotent on `state_id`: re-putting an existing state is a no-op (states are immutable).
pub(crate) async fn insert_state<B: Sql>(
    store: &Store<B>,
    conn: &mut Conn<B>,
    run: CrawlRunId,
    s: &NewState,
) -> Result<(), StoreError> {
    let (tenant, zdr) = Store::<B>::privacy_scope_tx(conn, run).await?;
    let sig = &s.signature;
    let manifest = if zdr {
        None
    } else {
        s.artifacts
            .iter()
            .find(|(kind, _)| kind == "manifest")
            .map(|(_, artifact)| artifact.id.0)
    };
    let route_key = sig.route_key.to_hex();
    let minhash = pack_u64s(&sig.semantic_affordance_minhash);
    let masks = if zdr {
        serde_json::json!([])
    } else {
        to_json(&s.masks)?
    };
    let observed_url = if zdr { None } else { Some(to_json(&s.url)?) };
    let artifacts = if zdr {
        serde_json::json!([])
    } else {
        to_json(&s.artifacts)?
    };
    let do_nothing = <B::Dialect as Dialect>::upsert_do_nothing(&["state_id"]);
    let inserted = insert_once::<B>(
        conn,
        stmt!(B, "SELECT state_id FROM states WHERE state_id = $1").uuid(s.id.0),
        stmt!(
            B,
            format!(
                "INSERT INTO states (state_id, run_id, session_id, route_key, semantic_affordance_minhash, dom_structure_simhash, visible_identity_digest, \
                   frame_tree_digest, network_operation_digest, visual_phash, browser_storage_digest, masks, epoch_navigation, epoch_document, epoch_mutation, \
                   state_algo_version, manifest_artifact_id, observed_at, expires_at, observed_url, artifacts) \
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, \
                   (SELECT expires_at FROM crawl_runs WHERE run_id = $2), $19, $20) \
                 {do_nothing}"
            )
        )
        .uuid(s.id.0)
        .uuid(run.0)
        .uuid(s.session.0)
        .text(&route_key)
        .bytes(&minhash)
        .i64(signed_bits(sig.dom_structure_simhash)?)
        .bytes(&sig.visible_element_identity_digest.0)
        .bytes(&sig.frame_tree_digest.0)
        .bytes(&sig.network_operation_digest.0)
        .opt_i64(sig.visual_phash.map(signed_bits).transpose()?)
        .opt_bytes(sig.browser_storage_digest.as_ref().map(|d| d.0.as_slice()))
        .json(&masks)
        .i64(conv::<u64, i64>(s.epoch.navigation_seq, "navigation_seq")?)
        .i64(conv::<u64, i64>(s.epoch.document_seq, "document_seq")?)
        .i64(conv::<u64, i64>(s.epoch.mutation_seq, "mutation_seq")?)
        .i16(conv::<u16, i16>(sig.version, "state_algo_version")?)
        .opt_uuid(manifest)
        .ts(s.observed_at)
        .opt_json(observed_url.as_ref())
        .json(&artifacts),
    )
    .await?;
    if !inserted {
        return Ok(());
    }
    if zdr {
        store
            .ephemeral_put(tenant, run, i64::MIN + 1, &format!("_state:{}", s.id), s)
            .await?;
    }
    if s.cluster_is_new {
        let cluster_conflict = <B::Dialect as Dialect>::upsert_do_nothing(&["cluster_id"]);
        stmt!(
            B,
            format!(
                "INSERT INTO state_clusters (cluster_id, run_id, prototype_state_id, algo_version) VALUES ($1, $2, $3, $4) {cluster_conflict}"
            )
        )
        .uuid(s.cluster.0)
        .uuid(run.0)
        .uuid(s.id.0)
        .i16(conv::<u16, i16>(sig.version, "state_algo_version")?)
        .execute(&mut *conn)
        .await?;
    } else {
        let exists = stmt!(B, "SELECT cluster_id FROM state_clusters WHERE cluster_id = $1")
            .uuid(s.cluster.0)
            .fetch_optional(&mut *conn)
            .await?;
        if exists.is_none() {
            return Err(not_found("state_cluster", s.cluster));
        }
    }
    stmt!(
        B,
        "INSERT INTO state_cluster_membership (state_id, cluster_id, decision_version, similarity) VALUES ($1, $2, 1, $3)"
    )
    .uuid(s.id.0)
    .uuid(s.cluster.0)
    .f32(s.cluster_similarity)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Rebuild a signature from `states`-shaped columns of `r`.
fn signature_from_row<R: SqlRow>(r: &R) -> Result<StateSignature, StoreError> {
    let route_key =
        Digest::from_hex(&r.text("route_key")?).map_err(|e| StoreError::Serialization(e.to_string()))?;
    Ok(StateSignature {
        version: conv(r.i16("state_algo_version")?, "state_algo_version")?,
        route_key,
        semantic_affordance_minhash: unpack_u64s(&r.bytes("semantic_affordance_minhash")?)?,
        dom_structure_simhash: unsigned_bits(r.i64("dom_structure_simhash")?)?,
        visible_element_identity_digest: digest(&r.bytes("visible_identity_digest")?)?,
        frame_tree_digest: digest(&r.bytes("frame_tree_digest")?)?,
        network_operation_digest: digest(&r.opt_bytes("network_operation_digest")?.ok_or_else(|| {
            StoreError::Serialization("state without network_operation_digest".to_owned())
        })?)?,
        visual_phash: r.opt_i64("visual_phash")?.map(unsigned_bits).transpose()?,
        browser_storage_digest: opt_digest(r.opt_bytes("browser_storage_digest")?)?,
    })
}

#[async_trait]
impl<B: Sql> StateRepo for Store<B> {
    async fn put_state(&self, state: &NewState) -> Result<(), StoreError> {
        let _timer = self.query_timer("state.put_state");
        let mut tx = self.begin_write().await?;
        let run = stmt!(B, "SELECT run_id FROM crawl_sessions WHERE session_id = $1")
            .uuid(state.session.0)
            .fetch_optional(tx.conn())
            .await?
            .map(|row| row.uuid("run_id"))
            .transpose()?;
        let run = CrawlRunId(run.ok_or_else(|| not_found("crawl_session", state.session))?);
        insert_state(self, tx.conn(), run, state).await?;
        tx.commit().await
    }

    async fn list_states(&self, run: CrawlRunId) -> Result<Vec<NewState>, StoreError> {
        let _timer = self.query_timer("state.list_states");
        let rows = stmt!(
            B,
            "SELECT s.state_id, s.session_id, s.route_key, s.semantic_affordance_minhash, s.dom_structure_simhash, s.visible_identity_digest, \
               s.frame_tree_digest, s.network_operation_digest, s.visual_phash, s.browser_storage_digest, s.masks, s.epoch_navigation, \
               s.epoch_document, s.epoch_mutation, s.state_algo_version, s.observed_at, s.observed_url, s.artifacts, \
               m.cluster_id, m.similarity, (c.prototype_state_id = s.state_id) AS cluster_is_new \
             FROM states s JOIN state_cluster_membership m ON m.state_id = s.state_id AND m.active \
             JOIN state_clusters c ON c.cluster_id = m.cluster_id \
             WHERE s.run_id = $1 ORDER BY s.observed_at, s.state_id"
        )
        .uuid(run.0)
        .fetch_all_pool(&self.pool)
        .await?;
        let (tenant, zdr) = self.privacy_scope(run).await?;
        let mut states = Vec::with_capacity(rows.len());
        for r in &rows {
            if zdr {
                let id = StateId(r.uuid("state_id")?);
                let mut state: NewState = self
                    .ephemeral_get(tenant, run, i64::MIN + 1, &format!("_state:{id}"))
                    .await?;
                state.cluster = StateClusterId(r.uuid("cluster_id")?);
                state.cluster_similarity = r.f32("similarity")?;
                state.cluster_is_new = r.flag("cluster_is_new")?;
                states.push(state);
                continue;
            }
            let url: serde_json::Value = r
                .opt_json("observed_url")?
                .ok_or_else(|| StoreError::Serialization("state without observed_url".to_owned()))?;
            states.push(NewState {
                id: StateId(r.uuid("state_id")?),
                session: SessionId(r.uuid("session_id")?),
                epoch: ObservationEpoch {
                    navigation_seq: conv(r.i64("epoch_navigation")?, "epoch_navigation")?,
                    document_seq: conv(r.i64("epoch_document")?, "epoch_document")?,
                    mutation_seq: conv(r.i64("epoch_mutation")?, "epoch_mutation")?,
                },
                url: from_json::<CanonicalUrl>(url)?,
                signature: signature_from_row(r)?,
                masks: from_json(r.json("masks")?)?,
                cluster: StateClusterId(r.uuid("cluster_id")?),
                cluster_similarity: r.f32("similarity")?,
                cluster_is_new: r.flag("cluster_is_new")?,
                artifacts: from_json::<Vec<(String, ArtifactRef)>>(r.json("artifacts")?)?,
                observed_at: r.ts("observed_at")?,
            });
        }
        Ok(states)
    }

    async fn list_clusters(
        &self,
        run: CrawlRunId,
    ) -> Result<Vec<(StateClusterId, StateSignature, u32)>, StoreError> {
        let _timer = self.query_timer("state.list_clusters");
        let rows = stmt!(
            B,
            "SELECT c.cluster_id, p.route_key, p.semantic_affordance_minhash, p.dom_structure_simhash, p.visible_identity_digest, \
               p.frame_tree_digest, p.network_operation_digest, p.visual_phash, p.browser_storage_digest, p.state_algo_version, \
               (SELECT count(*) FROM state_cluster_membership m WHERE m.cluster_id = c.cluster_id AND m.active) AS members \
             FROM state_clusters c JOIN states p ON p.state_id = c.prototype_state_id \
             WHERE c.run_id = $1 AND c.status = 'active' ORDER BY c.created_at, c.cluster_id"
        )
        .uuid(run.0)
        .fetch_all_pool(&self.pool)
        .await?;
        rows.iter()
            .map(|r| {
                Ok((
                    StateClusterId(r.uuid("cluster_id")?),
                    signature_from_row(r)?,
                    conv(r.i64("members")?, "members")?,
                ))
            })
            .collect()
    }

    async fn apply_split(&self, split: &ClusterSplitRecord) -> Result<SplitApplied, StoreError> {
        let _timer = self.query_timer("state.apply_split");
        let mut tx = self.begin_write().await?;
        let applied = self.apply_split_tx(tx.conn(), split).await?;
        tx.commit().await?;
        Metrics::global().counter(names::STATES_SPLITS).inc();
        Ok(applied)
    }
}

impl<B: Sql> Store<B> {
    async fn apply_split_tx(
        &self,
        tx: &mut Conn<B>,
        split: &ClusterSplitRecord,
    ) -> Result<SplitApplied, StoreError> {
        let update = <B::Dialect as Dialect>::row_lock(RowLock::Update);
        let source = stmt!(
            B,
            format!(
                "SELECT version, status FROM state_clusters WHERE cluster_id = $1 AND run_id = $2{update}"
            )
        )
        .uuid(split.source.0)
        .uuid(split.run.0)
        .fetch_optional(&mut *tx)
        .await?
        .ok_or_else(|| not_found("state_cluster", split.source))?;
        if source.text("status")? != "active" {
            return Err(StoreError::Conflict(format!(
                "state cluster {} is already superseded",
                split.source
            )));
        }
        let version: u32 = conv(source.i32("version")?, "version")?;
        if version != split.source_version {
            return Err(StoreError::Conflict(format!(
                "state cluster {} is at version {version}, split computed against {}",
                split.source, split.source_version
            )));
        }
        let successor_ids: Vec<uuid::Uuid> = split.successors.iter().map(|s| s.cluster.0).collect();
        let taken = Stmt::<B>::dynamic(&format!(
            "SELECT count(*) AS n FROM state_clusters WHERE cluster_id {}",
            in_list::<B>(1, successor_ids.len())
        ))
        .uuid_list(&successor_ids)
        .fetch_one(&mut *tx)
        .await?
        .i64("n")?;
        if taken != 0 {
            return Err(StoreError::Conflict(
                "split successor id already exists".to_owned(),
            ));
        }
        let active: Vec<uuid::Uuid> = stmt!(
            B,
            format!("SELECT state_id FROM state_cluster_membership WHERE cluster_id = $1 AND active{update}")
        )
        .uuid(split.source.0)
        .fetch_all(&mut *tx)
        .await?
        .iter()
        .map(|row| row.uuid("state_id"))
        .collect::<Result<_, _>>()?;
        let active: BTreeSet<StateId> = active.into_iter().map(StateId).collect();
        let assigned = split_assignment(split, &active)?;

        for s in &split.successors {
            stmt!(
                B,
                "INSERT INTO state_clusters (cluster_id, run_id, version, prototype_state_id, algo_version, created_at) \
                 VALUES ($1, $2, $3, $4, $5, $6)"
            )
            .uuid(s.cluster.0)
            .uuid(split.run.0)
            .i32(conv::<u32, i32>(s.version, "version")?)
            .uuid(s.prototype.0)
            .i16(conv::<u16, i16>(s.signature.version, "state_algo_version")?)
            .ts(split.decided_at)
            .execute(&mut *tx)
            .await?;
        }
        stmt!(
            B,
            "UPDATE state_cluster_membership SET active = false WHERE cluster_id = $1 AND active"
        )
        .uuid(split.source.0)
        .execute(&mut *tx)
        .await?;
        for s in &split.successors {
            for m in &s.members {
                stmt!(
                    B,
                    "INSERT INTO state_cluster_membership (state_id, cluster_id, decision_version, similarity, assigned_at) \
                     VALUES ($1, $2, $3, $4, $5)"
                )
                .uuid(m.state.0)
                .uuid(s.cluster.0)
                .i32(conv::<u32, i32>(s.version, "decision_version")?)
                .f32(m.similarity)
                .ts(split.decided_at)
                .execute(&mut *tx)
                .await?;
            }
        }
        stmt!(
            B,
            "UPDATE state_clusters SET status = 'superseded', superseded_by = $2 WHERE cluster_id = $1"
        )
        .uuid(split.source.0)
        .uuid(successor_ids[0])
        .execute(&mut *tx)
        .await?;

        // Re-key the ledger: every context of the source goes to the successor its actions'
        // `before_state`s fall in (memberships are already moved, so the join reads the
        // successor); ties and contexts without action evidence go to the first successor.
        let evidence_rows = Stmt::<B>::dynamic(&format!(
            "SELECT c.context_id, m.cluster_id, count(*) AS n \
             FROM action_contexts c JOIN actions a ON a.context_id = c.context_id \
             JOIN state_cluster_membership m ON m.state_id = a.before_state_id AND m.active \
             WHERE c.run_id = $1 AND c.state_cluster_id = $2 AND m.cluster_id {} \
             GROUP BY c.context_id, m.cluster_id ORDER BY c.context_id, m.cluster_id",
            in_list::<B>(3, successor_ids.len())
        ))
        .uuid(split.run.0)
        .uuid(split.source.0)
        .uuid_list(&successor_ids)
        .fetch_all(&mut *tx)
        .await?;
        let mut evidence: BTreeMap<i64, BTreeMap<StateClusterId, u32>> = BTreeMap::new();
        for r in &evidence_rows {
            let n: u32 = conv(r.i64("n")?, "n")?;
            evidence
                .entry(r.i64("context_id")?)
                .or_default()
                .insert(StateClusterId(r.uuid("cluster_id")?), n);
        }
        let contexts = stmt!(
            B,
            format!(
                "SELECT c.context_id, {KEY_COLS} FROM action_contexts c \
                 WHERE c.run_id = $1 AND c.state_cluster_id = $2 ORDER BY c.context_id{update}"
            )
        )
        .uuid(split.run.0)
        .uuid(split.source.0)
        .fetch_all(&mut *tx)
        .await?;
        let mut rekeyed = 0_u32;
        for r in &contexts {
            let context_id: i64 = r.i64("context_id")?;
            let mut key = key_from_row(self, r).await?;
            key.state_cluster = pick_successor(split, evidence.get(&context_id));
            let (tenant, zdr) = Store::<B>::privacy_scope_tx(tx, split.run).await?;
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
            stmt!(
                B,
                "UPDATE action_contexts SET state_cluster_id = $2, context_hash = $3 WHERE context_id = $1"
            )
            .i64(context_id)
            .uuid(key.state_cluster.0)
            .bytes(&key.id().0)
            .execute(&mut *tx)
            .await?;
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
