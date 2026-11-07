//! Tree view over the flat AX snapshot: parent/child indices, depth,
//! pre-order and stable node keys (role + sibling-ordinal path digest).

use crawlx_core::hash::Digest;
use crawlx_core::observation::{AxNode, AxSnapshot, DomSupplement};
#[allow(clippy::disallowed_types, reason = "lookup-only; never iterated")]
use std::collections::HashMap;

const NODE_KEY_DOMAIN: &str = "crawlx/state/node-key/v1";

/// Index-based tree over `AxSnapshot.nodes`.
#[derive(Debug)]
pub struct AxTree {
    pub parent: Vec<Option<usize>>,
    pub children: Vec<Vec<usize>>,
    /// Previous sibling in snapshot order (roots are siblings of each other).
    pub prev_sibling: Vec<Option<usize>>,
    pub depth: Vec<u16>,
    /// Pre-order indices; every node appears exactly once.
    pub order: Vec<usize>,
    /// Stable per-node keys: role + same-role sibling ordinal chained from the root.
    pub keys: Vec<Digest>,
}

impl AxTree {
    /// Build the tree. Parents come from `AxNode.parent`, falling back to a
    /// parent's `children` list; nodes whose parent cannot be resolved (or
    /// that sit on a cycle) become roots.
    #[must_use]
    pub fn build(snapshot: &AxSnapshot) -> Self {
        let nodes = &snapshot.nodes;
        let n = nodes.len();
        // Lookup-only: resolved by key, never iterated, so hash order cannot reach the tree.
        #[allow(clippy::disallowed_types, reason = "lookup-only; never iterated")]
        let mut by_id: HashMap<&str, usize> = HashMap::with_capacity(n);
        for (i, node) in nodes.iter().enumerate() {
            if let Some(id) = &node.locator.ax_node_id {
                by_id.entry(id.0.as_str()).or_insert(i);
            }
        }
        let mut parent: Vec<Option<usize>> = nodes
            .iter()
            .enumerate()
            .map(|(i, node)| {
                node.parent
                    .as_ref()
                    .and_then(|p| by_id.get(p.0.as_str()).copied())
                    .filter(|p| *p != i)
            })
            .collect();
        for (j, node) in nodes.iter().enumerate() {
            for c in &node.children {
                if let Some(&ci) = by_id.get(c.0.as_str()) {
                    if ci != j && parent[ci].is_none() {
                        parent[ci] = Some(j);
                    }
                }
            }
        }
        let mut children: Vec<Vec<usize>> = vec![Vec::new(); n];
        let mut roots: Vec<usize> = Vec::new();
        for (i, p) in parent.iter().enumerate() {
            match p {
                Some(p) => children[*p].push(i),
                None => roots.push(i),
            }
        }

        let mut prev_sibling: Vec<Option<usize>> = vec![None; n];
        for list in children.iter().chain(std::iter::once(&roots)) {
            for w in list.windows(2) {
                prev_sibling[w[1]] = Some(w[0]);
            }
        }
        let mut tree = Self {
            parent,
            children,
            prev_sibling,
            depth: vec![0; n],
            order: Vec::with_capacity(n),
            keys: vec![Digest([0; 32]); n],
        };
        let mut visited = vec![false; n];
        let mut buf: Vec<u8> = Vec::with_capacity(96);
        let root_key = Digest::of(NODE_KEY_DOMAIN, b"root");
        tree.walk(nodes, &roots, &root_key, &mut visited, &mut buf);
        // nodes on parent cycles are unreachable from any root: re-root them deterministically
        for i in 0..n {
            if !visited[i] {
                if let Some(p) = tree.parent[i] {
                    tree.children[p].retain(|c| *c != i);
                }
                tree.parent[i] = None;
                tree.walk(nodes, &[i], &root_key, &mut visited, &mut buf);
            }
        }
        tree
    }

    /// Iterative pre-order walk of `starts` (siblings under `parent_key`).
    fn walk(
        &mut self,
        nodes: &[AxNode],
        starts: &[usize],
        parent_key: &Digest,
        visited: &mut [bool],
        buf: &mut Vec<u8>,
    ) {
        // stack entries: (node, depth, key of the parent, ordinal among same-role siblings)
        let mut stack: Vec<(usize, u16, Digest, u32)> = Vec::new();
        let ordinals = sibling_ordinals(nodes, starts);
        for (&s, &ord) in starts.iter().zip(&ordinals).rev() {
            stack.push((s, 0, *parent_key, ord));
        }
        while let Some((i, depth, pkey, ord)) = stack.pop() {
            if visited[i] {
                continue;
            }
            visited[i] = true;
            buf.clear();
            buf.extend_from_slice(&pkey.0);
            buf.extend_from_slice(nodes[i].role.as_bytes());
            buf.push(0);
            buf.extend_from_slice(&ord.to_le_bytes());
            let key = Digest::of(NODE_KEY_DOMAIN, buf);
            self.keys[i] = key;
            self.depth[i] = depth;
            self.order.push(i);
            let kids = &self.children[i];
            let ords = sibling_ordinals(nodes, kids);
            for (&c, &o) in kids.iter().zip(&ords).rev() {
                stack.push((c, depth.saturating_add(1), key, o));
            }
        }
    }

    /// Is `i` masked itself or inside a masked subtree? `flags[i]` is the
    /// per-node "directly masked" array; the result is per-node inherited.
    #[must_use]
    pub fn inherit(&self, direct: &[bool]) -> Vec<bool> {
        let mut out = vec![false; direct.len()];
        for &i in &self.order {
            let inherited = self.parent[i].is_some_and(|p| out[p]);
            out[i] = direct[i] || inherited;
        }
        out
    }
}

/// Ordinal of each node among earlier siblings with the same role.
fn sibling_ordinals(nodes: &[AxNode], siblings: &[usize]) -> Vec<u32> {
    let mut seen: Vec<(&str, u32)> = Vec::new();
    let mut out = Vec::with_capacity(siblings.len());
    for &s in siblings {
        let role = nodes[s].role.as_str();
        if let Some(slot) = seen.iter_mut().find(|(r, _)| *r == role) {
            out.push(slot.1);
            slot.1 += 1;
        } else {
            seen.push((role, 1));
            out.push(0);
        }
    }
    out
}

/// Does the supplement list any listener for `node`?
#[must_use]
pub fn has_listeners(node: &AxNode, supplement: &DomSupplement) -> bool {
    supplement
        .nodes
        .get(&node.locator.backend_node_id.0)
        .is_some_and(|s| !s.listeners.is_empty())
}
