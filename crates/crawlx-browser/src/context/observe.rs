//! Observation capture: AX snapshot, DOM supplement for
//! escalated nodes, optional `DOMSnapshot`/screenshot blobs, HTML, frames and tabs.

use super::page_ops::admit_text;
use super::state::{join_node_id, ChildFrame};
use super::CdpContext;
use crate::cdp::CdpSession;
use crate::snapshot::{
    ax_is_candidate, ax_nodes, drop_zone_probes, has_interactive_ancestor, parse_snapshot,
    snapshot_only_candidates, supplement_for, SnapshotIndex, LISTENER_EVENTS, LISTENER_PROBE_BUDGET,
    MAX_SUPPLEMENT_NODES,
};
use crawlx_core::browser::BrowserError;
use crawlx_core::hash::Digest;
use crawlx_core::ids::{BackendNodeId, FrameId, TabId};
use crawlx_core::observation::{
    AxSnapshot, BoundingBox, DomSupplement, FrameInfo, MutationStats, ObservationBundle, ObservationCost,
    ObservationSpec,
};
use crawlx_core::parser_memory::{AdmittedBytes, AdmittedText, Budgeted};
use crawlx_url::Canonicalizer;
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

const PROBE_GROUP: &str = "crawlx-probe";

fn frame_lineages(frames: &[crate::cdp::RawFrame]) -> Vec<FrameInfo> {
    let main_origin = frames
        .first()
        .map(|f| f.security_origin.clone())
        .unwrap_or_default();
    let mut lineage_of: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut out = Vec::with_capacity(frames.len());
    for f in frames {
        let lineage = match &f.parent {
            None => Vec::new(),
            Some(p) => {
                let mut l = lineage_of.get(p).cloned().unwrap_or_default();
                let origin = url::Url::parse(&f.url)
                    .map(|u| format!("{}{}", u.origin().ascii_serialization(), u.path()))
                    .unwrap_or_default();
                let digest = Digest::of(
                    "crawlx/frame-identity/v1",
                    format!("{}|{origin}", f.name).as_bytes(),
                );
                l.push(digest.to_hex().chars().take(16).collect());
                l
            }
        };
        lineage_of.insert(f.id.clone(), lineage.clone());
        out.push(FrameInfo {
            id: FrameId(f.id.clone()),
            parent: f.parent.clone().map(FrameId),
            url: f.url.clone(),
            same_origin: f.security_origin == main_origin,
            lineage,
        });
    }
    out
}

impl CdpContext {
    pub(crate) async fn observe_impl(
        &mut self,
        spec: ObservationSpec,
    ) -> Result<ObservationBundle, BrowserError> {
        if self.ctl.config.captcha.is_some() && (spec.screenshot || spec.dom_snapshot) {
            return Err(BrowserError::Unsupported(
                "binary and raw DOM captures are unavailable with captcha solving".to_owned(),
            ));
        }
        let started = Instant::now();
        let calls_before = self.ctl.client.call_count();
        let (target_id, sess) = self.session_for(None)?;

        // Refresh mutation counters first so the bundle's epoch covers every change seen so far.
        if let Err(e) = self.poll_counters(None).await {
            if e.is_target_crash() {
                return Err(e);
            }
        }
        let (url_str, epoch, counters, prev_counters, net) = {
            let mut st = self.state.lock();
            let t = st.tabs.get_mut(&target_id).ok_or(BrowserError::TargetClosed)?;
            let prev = t.counters_at_observe;
            if !spec.revalidation_only {
                t.counters_at_observe = t.counters;
            }
            (
                t.url.clone(),
                t.epoch,
                t.counters,
                prev,
                t.network_summary(Instant::now()),
            )
        };
        let parsed = url::Url::parse(&url_str)
            .map_err(|e| BrowserError::Navigation(format!("no observable document ({url_str}): {e}")))?;
        let canonical = Canonicalizer::canonicalize_url(&parsed, &self.ctl.shared.canon)
            .map_err(|e| BrowserError::Navigation(format!("no observable document ({url_str}): {e}")))?;

        let tab = TabId(target_id.clone());
        // out-of-process iframes: their own sessions, parents before children (attach order)
        self.wait_child_frames(&target_id).await;
        let children: Vec<(String, ChildFrame)> = {
            let st = self.state.lock();
            let mut v: Vec<(String, ChildFrame)> = st
                .tabs
                .get(&target_id)
                .map(|t| {
                    t.frames
                        .iter()
                        .filter(|(_, f)| f.ready)
                        .map(|(id, f)| (id.clone(), f.clone()))
                        .collect()
                })
                .unwrap_or_default();
            v.sort_by_key(|(_, f)| f.index);
            v
        };
        let session_of = |index: u32| CdpSession {
            client: self.ctl.client.clone(),
            session_id: match index {
                0 => sess.session_id.clone(),
                i => children
                    .iter()
                    .find(|(_, f)| f.index == i)
                    .map(|(_, f)| f.session.clone())
                    .unwrap_or_default(),
            },
        };

        let mut raw_frames = sess.frame_tree().await?;
        // session index of every frame seen so far (frame owners of nested child frames)
        let mut index_of_frame: BTreeMap<String, u32> =
            raw_frames.iter().map(|f| (f.id.clone(), 0)).collect();
        // per session: `(index, frames of its tree)`; the AX pass below runs over all of them
        let mut trees: Vec<(u32, Vec<crate::cdp::RawFrame>)> = vec![(0, raw_frames.clone())];

        let want_snapshot = spec.ax || spec.dom_supplement || spec.dom_snapshot;
        let snap_raw: Option<Budgeted<Value>> = if want_snapshot {
            Some(sess.dom_snapshot().await?)
        } else {
            None
        };
        let mut snap: SnapshotIndex = snap_raw
            .as_ref()
            .map(|raw| parse_snapshot(raw.value()))
            .unwrap_or_default();
        for (root, child) in &children {
            let csess = session_of(child.index);
            let child_frames = match csess.frame_tree().await {
                Ok(f) => f,
                // detached or navigating away between the state read and now
                Err(BrowserError::Protocol { .. }) => continue,
                Err(e) => return Err(e),
            };
            if child_frames.first().is_none_or(|f| &f.id != root) {
                continue;
            }
            let Some(parent_index) = index_of_frame.get(&child.parent_frame).copied() else {
                continue;
            };
            let base = join_node_id(child.index, 0);
            if want_snapshot {
                // the frame's boxes are relative to its own viewport: shift by its owner's box
                let owner = session_of(parent_index)
                    .send("DOM.getFrameOwner", json!({ "frameId": root }))
                    .await
                    .ok()
                    .and_then(|v| v.get("backendNodeId").and_then(Value::as_i64))
                    .map(|raw| join_node_id(parent_index, raw))
                    .and_then(|id| snap.nodes.get(&id).and_then(|n| n.bounds));
                let (dx, dy) = owner.map_or((0.0, 0.0), |b| (b.x, b.y));
                let mut csnap = match csess.dom_snapshot().await {
                    Ok(v) => parse_snapshot(v.value()),
                    Err(BrowserError::Protocol { .. }) => continue,
                    Err(e) => return Err(e),
                };
                csnap.relocate(base, dx, dy);
                snap.merge(csnap);
            }
            for f in &child_frames {
                index_of_frame.insert(f.id.clone(), child.index);
            }
            trees.push((child.index, child_frames.clone()));
            raw_frames.extend(child_frames);
        }
        let frames = frame_lineages(&raw_frames);
        let bbox_of = |id: i64| -> Option<BoundingBox> {
            snap.nodes.get(&id).and_then(|n| n.bounds).map(|r| r.to_bbox())
        };

        let mut ax = AxSnapshot::default();
        if spec.ax || spec.dom_supplement {
            for (index, tree) in &trees {
                let fsess = session_of(*index);
                let base = join_node_id(*index, 0);
                for (i, f) in tree.iter().enumerate() {
                    let mut raw = match fsess.ax_full_tree(Some(&f.id)).await {
                        Ok(r) => r,
                        // frames that live in another process have no tree on this session
                        Err(BrowserError::Protocol { .. }) if i > 0 || *index > 0 => continue,
                        Err(e) => return Err(e),
                    };
                    for n in &mut raw {
                        n.backend_dom_node_id = n.backend_dom_node_id.map(|b| b + base);
                    }
                    ax.nodes.extend(ax_nodes(
                        &raw,
                        &tab,
                        &FrameId(f.id.clone()),
                        i == 0 && *index == 0,
                        epoch,
                        &bbox_of,
                    ));
                }
            }
        }

        let mut dom_supplement = DomSupplement::default();
        if spec.dom_supplement {
            dom_supplement = self.build_supplement(&target_id, &ax, &snap).await?;
        }

        // Page-hooks discovery sink: navigation-sink URLs for the frontier and
        // delegated-listener evidence for the candidate ladder.
        let mut discovered_urls: Vec<(String, String)> = Vec::new();
        if self.ctl.config.page_hooks && !spec.revalidation_only {
            match self.drain_discovery().await {
                Ok(sink) => {
                    discovered_urls = sink.urls();
                    for l in &sink.listeners {
                        let Some(id) = l.backend_node_id else { continue };
                        if !LISTENER_EVENTS.contains(&l.event_type.as_str()) {
                            continue;
                        }
                        if let Some(entry) = dom_supplement.nodes.get_mut(&id) {
                            if !entry.listeners.contains(&l.event_type) {
                                entry.listeners.push(l.event_type.clone());
                                entry.listeners.sort();
                            }
                        }
                        if !dom_supplement.listener_candidates.contains(&BackendNodeId(id)) {
                            dom_supplement.listener_candidates.push(BackendNodeId(id));
                        }
                    }
                }
                Err(e) if e.is_target_crash() => return Err(e),
                Err(e) => tracing::debug!(error = %e, "page hooks sink unavailable"),
            }
        }

        // remember role/name for revalidation's identity check
        if spec.ax && !spec.revalidation_only {
            let mut st = self.state.lock();
            if let Some(t) = st.tabs.get_mut(&target_id) {
                t.identity = ax
                    .nodes
                    .iter()
                    .filter(|n| ax_is_candidate(n))
                    .map(|n| (n.locator.backend_node_id.0, (n.role.clone(), n.name.clone())))
                    .collect();
            }
        }

        let mut raw_artifacts: Vec<(String, AdmittedBytes)> = Vec::new();
        if spec.dom_snapshot {
            if let Some(v) = &snap_raw {
                let bytes = crate::cdp::to_admitted_json(self.ctl.client.budget(), v.value())?;
                raw_artifacts.push(("dom_snapshot".to_owned(), bytes));
            }
        }
        if spec.screenshot {
            let shot = sess
                .send_budgeted(
                    "Page.captureScreenshot",
                    json!({ "format": "png", "captureBeyondViewport": false }),
                )
                .await?;
            let data = shot
                .value()
                .get("data")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let bytes =
                crate::cdp::decode_admitted_base64(self.ctl.client.budget(), "Page.captureScreenshot", data)?;
            raw_artifacts.push(("screenshot".to_owned(), bytes));
        }

        let (html, title, tabs) = if spec.revalidation_only {
            (None, None, Vec::new())
        } else {
            let html = self.capture_html(&sess, &snap).await;
            let title = sess
                .client
                .call("Target.getTargetInfo", None, json!({ "targetId": target_id }))
                .await
                .ok()
                .and_then(|v| {
                    v.get("targetInfo")
                        .and_then(|i| i.get("title"))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                })
                .filter(|t| !t.is_empty());
            let tabs = self.refresh_tabs(&sess).await;
            (html, title, tabs)
        };

        if !spec.revalidation_only {
            self.seq += 1;
        }
        let dialogs = if spec.revalidation_only {
            Vec::new()
        } else {
            let mut st = self.state.lock();
            st.tabs
                .get_mut(&target_id)
                .map(|t| std::mem::take(&mut t.dialogs))
                .unwrap_or_default()
        };
        let mut bundle = ObservationBundle::empty(self.ctl.config.session_id, tab, canonical);
        bundle.seq = self.seq;
        bundle.epoch = epoch;
        bundle.captured_at = self.ctl.shared.clock.now();
        bundle.viewport = self.ctl.config.viewport;
        bundle.frames = frames;
        bundle.ax = ax;
        bundle.dom_supplement = dom_supplement;
        bundle.mutation = MutationStats {
            records: counters.records.saturating_sub(prev_counters.records),
            added_nodes: counters.added.saturating_sub(prev_counters.added),
            removed_nodes: counters.removed.saturating_sub(prev_counters.removed),
            attribute_changes: counters.attrs.saturating_sub(prev_counters.attrs),
            text_changes: counters.text.saturating_sub(prev_counters.text),
            volatile_permille: {
                let records = counters.records.saturating_sub(prev_counters.records);
                let volatile = counters
                    .volatile
                    .saturating_sub(prev_counters.volatile)
                    .min(records);
                u16::try_from(volatile.saturating_mul(1000).checked_div(records).unwrap_or(0)).unwrap_or(1000)
            },
        };
        bundle.network = net;
        bundle.settle = if spec.revalidation_only {
            self.last_settle.clone()
        } else {
            self.last_settle.take()
        };
        bundle.dialogs = dialogs;
        bundle.tabs = tabs;
        bundle.title = title;
        let bytes = html.as_ref().map_or(0, |html| html.len())
            + raw_artifacts.iter().map(|(_, b)| b.len()).sum::<usize>();
        bundle.html = html;
        bundle.raw_artifacts = raw_artifacts;
        bundle.discovered_urls = discovered_urls;
        bundle.cost = ObservationCost {
            cdp_calls: u32::try_from(self.ctl.client.call_count().saturating_sub(calls_before))
                .unwrap_or(u32::MAX),
            bytes: bytes as u64,
            wall_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        self.mask_captcha_observation(bundle)
    }

    /// Main-document HTML via `DOM.getOuterHTML`, falling back to the documentElement. The text
    /// is moved out of the charged response and carries its own reservation.
    async fn capture_html(&self, sess: &CdpSession, snap: &SnapshotIndex) -> Option<AdmittedText> {
        let root = match snap.document_roots.first() {
            Some(r) => Some(*r),
            None => sess
                .send("DOM.getDocument", json!({ "depth": 0 }))
                .await
                .ok()
                .and_then(|v| {
                    v.get("root")
                        .and_then(|r| r.get("backendNodeId"))
                        .and_then(Value::as_i64)
                }),
        };
        if let Some(root) = root {
            if let Ok(mut reply) = sess
                .send_budgeted("DOM.getOuterHTML", json!({ "backendNodeId": root }))
                .await
            {
                if let Some(Value::String(html)) = reply.value_mut().get_mut("outerHTML") {
                    let html = std::mem::take(html);
                    let (rest, permit) = reply.into_parts();
                    return admit_text(html, rest, permit).ok();
                }
            }
        }
        self.document_element_html().await
    }

    /// `documentElement.outerHTML` from the isolated world, retrying once if the context was
    /// replaced; the text is moved out of the charged response.
    async fn document_element_html(&self) -> Option<AdmittedText> {
        const EXPRESSION: &str = "document.documentElement ? document.documentElement.outerHTML : ''";
        for attempt in 0..2 {
            let (target_id, sess, ctx) = self.world(None).await.ok()?;
            match sess.evaluate_in_budgeted(ctx, EXPRESSION, false).await {
                Err(BrowserError::Protocol { message, .. })
                    if attempt == 0 && message.to_ascii_lowercase().contains("context") =>
                {
                    self.invalidate_world(&target_id);
                }
                Err(_) => return None,
                Ok(mut reply) => {
                    if reply.value().get("exceptionDetails").is_some() {
                        return None;
                    }
                    let Some(Value::String(html)) = reply.value_mut().pointer_mut("/result/value") else {
                        return None;
                    };
                    let html = std::mem::take(html);
                    let (rest, permit) = reply.into_parts();
                    return admit_text(html, rest, permit).ok();
                }
            }
        }
        None
    }

    /// Tabs of this context from `Target.getTargets`, merged into the tab graph.
    async fn refresh_tabs(&mut self, sess: &CdpSession) -> Vec<crawlx_core::observation::TabInfo> {
        if let Ok(v) = sess.client.call("Target.getTargets", None, json!({})).await {
            let mut st = self.state.lock();
            if let Some(infos) = v.get("targetInfos").and_then(Value::as_array) {
                for i in infos {
                    let ours = i.get("browserContextId").and_then(Value::as_str)
                        == Some(self.ctl.browser_context_id.as_str());
                    let page = i.get("type").and_then(Value::as_str) == Some("page");
                    if ours && page {
                        if let (Some(id), Some(url)) = (
                            i.get("targetId").and_then(Value::as_str),
                            i.get("url").and_then(Value::as_str),
                        ) {
                            st.graph.set_url(id, url);
                        }
                    }
                }
            }
        }
        // Scope policy must see the first real URL, not the transient about:blank.
        // Deadlines are anchored at target creation, never restarted by observations.
        loop {
            let deadline = self.state.lock().graph.blank_deadline(Instant::now());
            let Some(deadline) = deadline else { break };
            tokio::select! {
                _ = tokio::time::sleep_until(deadline.into()) => {},
                changed = self.notified.changed() => {
                    if changed.is_err() { break; }
                }
            }
        }
        let st = self.state.lock();
        st.graph.infos(&st.active)
    }

    /// DOM evidence for candidate nodes (AX candidates plus snapshot-only rungs 1–2) and
    /// targeted listener inspection (rung 3, budget [`LISTENER_PROBE_BUDGET`]). Node ids are
    /// public ids: probes go to the session that owns each node (`node_session`).
    async fn build_supplement(
        &self,
        tab: &str,
        ax: &AxSnapshot,
        snap: &SnapshotIndex,
    ) -> Result<DomSupplement, BrowserError> {
        let mut out = DomSupplement::default();
        let ax_cands: BTreeSet<i64> = ax
            .nodes
            .iter()
            .filter(|n| ax_is_candidate(n))
            .map(|n| n.locator.backend_node_id.0)
            .collect();
        let names: BTreeMap<i64, &str> = ax
            .nodes
            .iter()
            .filter_map(|n| n.name.as_deref().map(|s| (n.locator.backend_node_id.0, s)))
            .collect();
        for id in &ax_cands {
            if out.nodes.len() >= MAX_SUPPLEMENT_NODES {
                break;
            }
            if let Some(n) = snap.nodes.get(id) {
                out.nodes.insert(*id, supplement_for(n, names.get(id).copied()));
            }
        }
        let extra = snapshot_only_candidates(snap, &ax_cands);
        let mut probe: Vec<i64> = Vec::new();
        let mut drag_sources: Vec<i64> = Vec::new();
        for id in extra {
            if out.nodes.len() >= MAX_SUPPLEMENT_NODES {
                break;
            }
            let Some(n) = snap.nodes.get(&id) else { continue };
            out.nodes.insert(id, supplement_for(n, names.get(&id).copied()));
            let generic = !n.natively_interactive();
            let hint =
                n.action_cursor() || n.attrs.contains_key("tabindex") || n.clickable || n.drag_source();
            if generic && hint && !has_interactive_ancestor(snap, id, &ax_cands) {
                probe.push(id);
            }
            if n.drag_source() || n.drag_cursor() {
                drag_sources.push(id);
            }
        }
        // drop zones are probed only on pages that have something to drag
        for id in drop_zone_probes(snap, &drag_sources) {
            if probe.len() >= LISTENER_PROBE_BUDGET || out.nodes.len() >= MAX_SUPPLEMENT_NODES {
                break;
            }
            if probe.contains(&id) {
                continue;
            }
            let Some(n) = snap.nodes.get(&id) else { continue };
            out.nodes
                .entry(id)
                .or_insert_with(|| supplement_for(n, names.get(&id).copied()));
            probe.push(id);
        }
        probe.truncate(LISTENER_PROBE_BUDGET);
        let mut probed_sessions: BTreeMap<String, CdpSession> = BTreeMap::new();
        for id in probe {
            let Ok((sess, raw, _)) = self.node_session(tab, id) else {
                continue;
            };
            let Ok(object_id) = sess.resolve_node(raw, None, PROBE_GROUP).await else {
                continue;
            };
            let listeners = sess.event_listeners(&object_id).await.unwrap_or_default();
            probed_sessions.entry(sess.session_id.clone()).or_insert(sess);
            let mut kinds: Vec<String> = listeners
                .into_iter()
                .map(|l| l.kind)
                .filter(|k| LISTENER_EVENTS.contains(&k.as_str()))
                .collect();
            kinds.sort();
            kinds.dedup();
            if !kinds.is_empty() {
                if let Some(entry) = out.nodes.get_mut(&id) {
                    entry.listeners = kinds;
                }
                out.listener_candidates.push(BackendNodeId(id));
            }
        }
        // Form declarations supply semantics and ownership, not new action candidates.
        for (id, node) in &snap.nodes {
            if node.tag == "form" && out.nodes.len() < MAX_SUPPLEMENT_NODES {
                out.nodes
                    .entry(*id)
                    .or_insert_with(|| supplement_for(node, names.get(id).copied()));
            }
        }
        for (id, entry) in &mut out.nodes {
            snap.project_form_attributes(*id, &mut entry.attributes);
        }
        for sess in probed_sessions.values() {
            sess.release_group(PROBE_GROUP).await;
        }
        Ok(out)
    }
}
