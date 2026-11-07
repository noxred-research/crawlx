//! Recorded-flow selector resolution: `css` through `DOM.querySelector`,
//! `xpath` and `text` through `DOM.performSearch` / `DOM.getSearchResults`, `aria` through the
//! accessibility tree. Semantics follow projectdiscovery/katana
//! `pkg/engine/headless/auth/replay.go` (`queryElements`, `findVisible`) at commit 9662cd7
//! (MIT): the first match wins; a selector that matches nothing resolves to `None` rather
//! than an error. Visibility is left to `revalidate` (the actor's protocol checks it before
//! every action).

use super::CdpContext;
use crate::cdp::{ax_value_text, CdpSession};
use crawlx_core::browser::BrowserError;
use crawlx_core::ids::{AxNodeId, BackendNodeId, FrameId, TabId};
use crawlx_core::observation::{DomSelector, DomSelectorKind, RuntimeLocator};
use serde_json::{json, Value};

/// Search hits inspected before giving up on an element node (`text` queries also return
/// text nodes and attribute matches).
const MAX_SEARCH_HITS: usize = 32;

/// Element node type of `DOM.Node.nodeType`.
const ELEMENT_NODE: i64 = 1;
/// Text node type of `DOM.Node.nodeType`.
const TEXT_NODE: i64 = 3;

/// Split `Name[role="button"]` (Recorder `aria/` syntax) into the name and the optional role.
fn split_aria(expr: &str) -> (String, Option<String>) {
    let expr = expr.trim();
    if let Some(start) = expr.rfind("[role=") {
        if expr.ends_with(']') {
            let role = expr[start + "[role=".len()..expr.len() - 1]
                .trim()
                .trim_matches(|c| c == '"' || c == '\'')
                .to_ascii_lowercase();
            return (expr[..start].trim().to_owned(), Some(role));
        }
    }
    (expr.to_owned(), None)
}

/// Whitespace-normalized, case-insensitive name comparison.
fn same_name(a: &str, b: &str) -> bool {
    let norm = |s: &str| s.split_whitespace().collect::<Vec<_>>().join(" ").to_lowercase();
    norm(a) == norm(b)
}

/// `(nodeType, backendNodeId, parentId)` of a frontend node id.
pub(super) async fn describe(sess: &CdpSession, node_id: i64) -> Option<(i64, i64, Option<i64>)> {
    let v = sess
        .send("DOM.describeNode", json!({ "nodeId": node_id }))
        .await
        .ok()?;
    let node = v.get("node")?;
    Some((
        node.get("nodeType").and_then(Value::as_i64)?,
        node.get("backendNodeId").and_then(Value::as_i64)?,
        node.get("parentId").and_then(Value::as_i64),
    ))
}

async fn css(sess: &CdpSession, expr: &str) -> Result<Option<i64>, BrowserError> {
    let root = sess.send("DOM.getDocument", json!({ "depth": 0 })).await?;
    let Some(root_id) = root
        .get("root")
        .and_then(|r| r.get("nodeId"))
        .and_then(Value::as_i64)
    else {
        return Ok(None);
    };
    let found = match sess
        .send(
            "DOM.querySelector",
            json!({ "nodeId": root_id, "selector": expr }),
        )
        .await
    {
        Ok(v) => v.get("nodeId").and_then(Value::as_i64).filter(|id| *id != 0),
        // an invalid selector is a protocol error, not a transport failure
        Err(BrowserError::Protocol { .. }) => None,
        Err(e) => return Err(e),
    };
    let Some(node_id) = found else {
        return Ok(None);
    };
    Ok(describe(sess, node_id).await.map(|(_, backend, _)| backend))
}

/// `DOM.performSearch` (plain text, XPath or CSS, as the protocol decides from the query);
/// the first hit that is an element, or the parent element of a text-node hit.
async fn search(sess: &CdpSession, query: &str) -> Result<Option<i64>, BrowserError> {
    // the search needs a document pushed to the frontend
    sess.send("DOM.getDocument", json!({ "depth": 0 })).await?;
    let started = match sess
        .send(
            "DOM.performSearch",
            json!({ "query": query, "includeUserAgentShadowDOM": false }),
        )
        .await
    {
        Ok(v) => v,
        Err(BrowserError::Protocol { .. }) => return Ok(None),
        Err(e) => return Err(e),
    };
    let Some(search_id) = started.get("searchId").and_then(Value::as_str) else {
        return Ok(None);
    };
    let count = started
        .get("resultCount")
        .and_then(Value::as_u64)
        .and_then(|n| usize::try_from(n).ok())
        .unwrap_or(0)
        .min(MAX_SEARCH_HITS);
    let mut found = None;
    if count > 0 {
        let results = sess
            .send(
                "DOM.getSearchResults",
                json!({ "searchId": search_id, "fromIndex": 0, "toIndex": count }),
            )
            .await;
        if let Ok(results) = results {
            let ids: Vec<i64> = results
                .get("nodeIds")
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(Value::as_i64).collect())
                .unwrap_or_default();
            for id in ids {
                let Some((kind, backend, parent)) = describe(sess, id).await else {
                    continue;
                };
                if kind == ELEMENT_NODE {
                    found = Some(backend);
                    break;
                }
                if kind == TEXT_NODE {
                    if let Some(p) = parent {
                        if let Some((ELEMENT_NODE, b, _)) = describe(sess, p).await {
                            found = Some(b);
                            break;
                        }
                    }
                }
            }
        }
    }
    let _ = sess
        .send("DOM.discardSearchResults", json!({ "searchId": search_id }))
        .await;
    Ok(found)
}

/// First AX node (document order) whose computed name equals `expr` (and whose role equals
/// the optional `[role=..]` suffix), with a DOM counterpart.
async fn aria(sess: &CdpSession, expr: &str) -> Result<Option<(i64, String)>, BrowserError> {
    let (name, role) = split_aria(expr);
    let nodes = sess.ax_full_tree(None).await?;
    Ok(nodes
        .iter()
        .filter(|n| !n.ignored)
        .filter(|n| n.backend_dom_node_id.is_some_and(|b| b > 0))
        .filter(|n| ax_value_text(n.name.as_ref()).is_some_and(|live| same_name(&live, &name)))
        .filter(|n| {
            role.as_deref().is_none_or(|want| {
                ax_value_text(n.role.as_ref()).is_some_and(|live| live.eq_ignore_ascii_case(want))
            })
        })
        .find_map(|n| n.backend_dom_node_id.map(|b| (b, n.node_id.clone()))))
}

impl CdpContext {
    pub(crate) async fn resolve_selector_impl(
        &mut self,
        selector: &DomSelector,
    ) -> Result<Option<RuntimeLocator>, BrowserError> {
        let (target_id, sess) = self.session_for(None)?;
        let (main_frame, epoch) = {
            let st = self.state.lock();
            let t = st.tabs.get(&target_id).ok_or(BrowserError::TargetClosed)?;
            (t.main_frame.clone(), t.epoch)
        };
        let expr = selector.expr.trim();
        if expr.is_empty() {
            return Ok(None);
        }
        let (backend, ax_node_id) = match selector.kind {
            DomSelectorKind::Css => (css(&sess, expr).await?, None),
            DomSelectorKind::XPath | DomSelectorKind::Text => (search(&sess, expr).await?, None),
            DomSelectorKind::Aria => match aria(&sess, expr).await? {
                Some((b, ax)) => (Some(b), Some(AxNodeId(ax))),
                None => (None, None),
            },
            // kinds added later resolve to nothing until this adapter learns them
            _ => (None, None),
        };
        // keep `current_epoch()` fresh for the caller's epoch policy
        let _ = self.poll_counters(Some(&target_id)).await;
        Ok(backend.map(|b| RuntimeLocator {
            tab: TabId(target_id),
            frame: FrameId(main_frame),
            backend_node_id: BackendNodeId(b),
            object_id: None,
            ax_node_id,
            epoch,
        }))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn aria_suffix_splits_name_and_role() {
        assert_eq!(
            split_aria("Sign in[role=\"button\"]"),
            ("Sign in".to_owned(), Some("button".to_owned()))
        );
        assert_eq!(split_aria("  Sign in "), ("Sign in".to_owned(), None));
        assert_eq!(
            split_aria("Name[role='link']"),
            ("Name".to_owned(), Some("link".to_owned()))
        );
    }

    #[test]
    fn names_compare_without_case_or_whitespace() {
        assert!(same_name("Sign  In", "sign in"));
        assert!(!same_name("Sign in", "Sign out"));
    }
}
