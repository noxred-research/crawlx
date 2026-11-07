//! Surfaces the crawler cannot reason about from structure (rung 4 of the
//! candidate ladder): `canvas`, WebGL, `embed`, `object`.
//!
//! They are reported, never turned into candidates and never clicked; the
//! optional visual-action plugin is the only consumer that may act on them.

use crawlx_core::observation::{ObservationBundle, RuntimeLocator};

use crate::index::BundleIndex;

/// Attribute the DOM supplement producer sets on a `canvas` whose rendering
/// context is WebGL (`webgl`, `webgl2`, `experimental-webgl`).
pub const CONTEXT_ATTRIBUTE: &str = "data-crawlx-context";

/// Why a node has no structural action surface.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[non_exhaustive]
pub enum SurfaceKind {
    /// `<canvas>` (or AX role `canvas`) with a 2D or unknown rendering context.
    Canvas,
    /// `<canvas>` whose rendering context is WebGL (see [`CONTEXT_ATTRIBUTE`]).
    WebGl,
    /// `<embed>` plugin content.
    Embed,
    /// `<object>` plugin or nested content.
    Object,
}

impl SurfaceKind {
    /// Stable lowercase label of the kind, as written into reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Canvas => "canvas",
            Self::WebGl => "webgl",
            Self::Embed => "embed",
            Self::Object => "object",
        }
    }
}

/// A node reported as unsupported.
#[derive(Clone, PartialEq, Debug)]
#[non_exhaustive]
pub struct UnsupportedSurface {
    /// Runtime handle of the node (AX locator when the node has an AX
    /// counterpart, otherwise a main-frame DOM locator).
    pub locator: RuntimeLocator,
    /// Why the node cannot be reasoned about structurally.
    pub kind: SurfaceKind,
}

/// Is `tag_or_role` (lowercase compare) a surface kind?
#[must_use]
pub fn is_surface_tag(tag_or_role: &str) -> bool {
    kind_of(tag_or_role, false).is_some()
}

fn kind_of(tag_or_role: &str, webgl: bool) -> Option<SurfaceKind> {
    match tag_or_role.trim().to_ascii_lowercase().as_str() {
        "canvas" => Some(if webgl {
            SurfaceKind::WebGl
        } else {
            SurfaceKind::Canvas
        }),
        "embed" => Some(SurfaceKind::Embed),
        "object" => Some(SurfaceKind::Object),
        _ => None,
    }
}

/// Unsupported surfaces of a bundle, ordered by backend node id: DOM
/// supplement tags first, then AX-only nodes whose role names a surface.
#[must_use]
pub fn detect(bundle: &ObservationBundle) -> Vec<UnsupportedSurface> {
    let index = BundleIndex::new(bundle);
    let mut found: std::collections::BTreeMap<i64, UnsupportedSurface> = std::collections::BTreeMap::new();
    for (&id, d) in &bundle.dom_supplement.nodes {
        let webgl = d
            .attributes
            .get(CONTEXT_ATTRIBUTE)
            .is_some_and(|c| c.trim().to_ascii_lowercase().contains("webgl"));
        if let Some(kind) = kind_of(&d.tag, webgl) {
            let locator = index
                .ax_by_backend(id)
                .map(|n| n.locator.clone())
                .unwrap_or_else(|| index.dom_locator(id));
            found.insert(id, UnsupportedSurface { locator, kind });
        }
    }
    for n in &bundle.ax.nodes {
        let id = n.locator.backend_node_id.0;
        if found.contains_key(&id) {
            continue;
        }
        if let Some(kind) = kind_of(&n.role, false) {
            found.insert(
                id,
                UnsupportedSurface {
                    locator: n.locator.clone(),
                    kind,
                },
            );
        }
    }
    found.into_values().collect()
}
