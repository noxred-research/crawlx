//! Pure-geometry interactability evidence.
//!
//! The browser performs the real hit test during `revalidate`; this module
//! only decides where to aim and whether a scroll is needed first.

use crawlx_core::observation::{BoundingBox, Viewport};

use crate::ladder::Candidate;

/// Sample points for hit testing one box.
pub struct HitTestPlan;

impl HitTestPlan {
    /// Centre first, then the four points inset 25% from each corner
    /// (`x + 0.25w`/`x + 0.75w` × `y + 0.25h`/`y + 0.75h`). Every point lies
    /// inside the box. `K = 5` is the default sample count.
    #[must_use]
    pub fn for_bbox(b: &BoundingBox) -> [(f64, f64); 5] {
        let at = |fx: f64, fy: f64| (b.x + b.width * fx, b.y + b.height * fy);
        [
            at(0.5, 0.5),
            at(0.25, 0.25),
            at(0.75, 0.25),
            at(0.25, 0.75),
            at(0.75, 0.75),
        ]
    }
}

/// Geometry facts for one candidate against one viewport.
#[derive(Clone, PartialEq, Debug)]
pub struct Assessment {
    /// The whole box lies inside the viewport.
    pub in_viewport: bool,
    /// Scrolling can bring (more of) the box into view: the box is not
    /// zero-sized and is either entirely outside the viewport or partly
    /// outside while small enough to fit.
    pub needs_scroll: bool,
    /// No box, or width or height ≤ 0.
    pub zero_size: bool,
    /// [`HitTestPlan`] points over the visible part of the box (empty when
    /// zero-sized or fully outside), centre first.
    pub hit_points: Vec<(f64, f64)>,
}

/// Interactability assessment.
pub struct Interactability;

impl Interactability {
    /// Assess `candidate`'s box in `viewport` (CSS pixels, origin top-left).
    #[must_use]
    pub fn assess(candidate: &Candidate, viewport: Viewport) -> Assessment {
        Self::assess_bbox(candidate.descriptor.bbox.as_ref(), viewport)
    }

    /// Assess a box directly.
    #[must_use]
    pub fn assess_bbox(bbox: Option<&BoundingBox>, viewport: Viewport) -> Assessment {
        let Some(b) = bbox.filter(|b| b.width > 0.0 && b.height > 0.0) else {
            return Assessment {
                in_viewport: false,
                needs_scroll: false,
                zero_size: true,
                hit_points: Vec::new(),
            };
        };
        let (vw, vh) = (f64::from(viewport.width), f64::from(viewport.height));
        let in_viewport = b.x >= 0.0 && b.y >= 0.0 && b.x + b.width <= vw && b.y + b.height <= vh;
        let visible = intersect(b, vw, vh);
        let fits = b.width <= vw && b.height <= vh;
        Assessment {
            in_viewport,
            needs_scroll: visible.is_none() || (!in_viewport && fits),
            zero_size: false,
            hit_points: visible
                .map(|v| HitTestPlan::for_bbox(&v).to_vec())
                .unwrap_or_default(),
        }
    }
}

fn intersect(b: &BoundingBox, vw: f64, vh: f64) -> Option<BoundingBox> {
    let x0 = b.x.max(0.0);
    let y0 = b.y.max(0.0);
    let x1 = (b.x + b.width).min(vw);
    let y1 = (b.y + b.height).min(vh);
    (x1 > x0 && y1 > y0).then_some(BoundingBox {
        x: x0,
        y: y0,
        width: x1 - x0,
        height: y1 - y0,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use proptest::prelude::*;

    fn b(x: f64, y: f64, w: f64, h: f64) -> BoundingBox {
        BoundingBox {
            x,
            y,
            width: w,
            height: h,
        }
    }

    #[test]
    fn plan_points() {
        let p = HitTestPlan::for_bbox(&b(100.0, 200.0, 80.0, 40.0));
        assert_eq!(p[0], (140.0, 220.0));
        assert_eq!(p[1], (120.0, 210.0));
        assert_eq!(p[2], (160.0, 210.0));
        assert_eq!(p[3], (120.0, 230.0));
        assert_eq!(p[4], (160.0, 230.0));
    }

    proptest! {
        #[test]
        fn points_lie_inside_the_box(x in -500.0f64..500.0, y in -500.0f64..500.0, w in 0.5f64..800.0, h in 0.5f64..800.0) {
            let bb = b(x, y, w, h);
            for (px, py) in HitTestPlan::for_bbox(&bb) {
                prop_assert!(px >= x && px <= x + w && py >= y && py <= y + h);
            }
            // the four corner samples are strictly interior
            for (px, py) in &HitTestPlan::for_bbox(&bb)[1..] {
                prop_assert!(*px > x && *px < x + w && *py > y && *py < y + h);
            }
        }
    }

    #[test]
    fn assessments() {
        let vp = Viewport {
            width: 1000,
            height: 800,
        };
        let inside = Interactability::assess_bbox(Some(&b(10.0, 10.0, 100.0, 30.0)), vp);
        assert!(inside.in_viewport && !inside.needs_scroll && !inside.zero_size);
        assert_eq!(inside.hit_points.len(), 5);

        let below = Interactability::assess_bbox(Some(&b(10.0, 900.0, 100.0, 30.0)), vp);
        assert!(!below.in_viewport && below.needs_scroll && below.hit_points.is_empty());

        let partial = Interactability::assess_bbox(Some(&b(10.0, 780.0, 100.0, 40.0)), vp);
        assert!(!partial.in_viewport && partial.needs_scroll);
        assert_eq!(partial.hit_points.len(), 5);
        assert!(partial.hit_points.iter().all(|(_, y)| *y >= 780.0 && *y <= 800.0));

        let huge = Interactability::assess_bbox(Some(&b(0.0, -50.0, 2000.0, 3000.0)), vp);
        assert!(
            !huge.in_viewport && !huge.needs_scroll,
            "oversize boxes cannot be fully scrolled in"
        );
        assert!(!huge.hit_points.is_empty());

        for bb in [
            None,
            Some(b(10.0, 10.0, 0.0, 30.0)),
            Some(b(10.0, 10.0, 30.0, -1.0)),
        ] {
            let z = Interactability::assess_bbox(bb.as_ref(), vp);
            assert!(z.zero_size && !z.in_viewport && !z.needs_scroll && z.hit_points.is_empty());
        }
    }

    #[test]
    fn assess_uses_descriptor_box() {
        use crate::ladder::{Candidate, CandidateEvidence, Rung};
        let mut d = crate::testutil::descriptor("button", "Go");
        d.bbox = Some(b(5.0, 5.0, 50.0, 20.0));
        let c = Candidate {
            descriptor: d,
            evidence: CandidateEvidence {
                ax_widget_role: Some("button".into()),
                native_semantics: true,
                aria_semantics: false,
                focusable: true,
                direct_listener: false,
                hover_listener: false,
                delegated_likelihood: 0.0,
                action_cursor: false,
                draggable: false,
                drop_zone: false,
                visible: true,
                enabled: true,
            },
            rung: Rung::Ax,
        };
        assert!(Interactability::assess(&c, Viewport::default()).in_viewport);
    }
}
