//! `ObservationSpec` presets: AX every
//! observation, DOM supplement for escalation targets, DOMSnapshot at
//! checkpoints, screenshots on novel states.

use crawlx_core::observation::ObservationSpec;

/// After every executed action: AX tree plus the targeted DOM supplement.
#[must_use]
pub const fn after_action() -> ObservationSpec {
    ObservationSpec {
        ax: true,
        dom_supplement: true,
        dom_snapshot: false,
        screenshot: false,
        revalidation_only: false,
    }
}

/// Checkpoint (novel state, error, interval): adds the DOMSnapshot.
#[must_use]
pub const fn checkpoint() -> ObservationSpec {
    ObservationSpec {
        ax: true,
        dom_supplement: true,
        dom_snapshot: true,
        screenshot: false,
        revalidation_only: false,
    }
}

/// First sighting of a state: everything, including the screenshot.
#[must_use]
pub const fn novel_state() -> ObservationSpec {
    ObservationSpec {
        ax: true,
        dom_supplement: true,
        dom_snapshot: true,
        screenshot: true,
        revalidation_only: false,
    }
}

/// Cheapest useful observation: AX only (probes, postcondition polling).
#[must_use]
pub const fn cheap() -> ObservationSpec {
    ObservationSpec {
        ax: true,
        dom_supplement: false,
        dom_snapshot: false,
        screenshot: false,
        revalidation_only: false,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn presets_are_ordered_by_cost() {
        let cost = |s: ObservationSpec| {
            u8::from(s.ax) + u8::from(s.dom_supplement) + u8::from(s.dom_snapshot) + u8::from(s.screenshot)
        };
        assert!(cost(cheap()) < cost(after_action()));
        assert!(cost(after_action()) < cost(checkpoint()));
        assert!(cost(checkpoint()) < cost(novel_state()));
        assert!(cheap().ax && !cheap().dom_supplement);
        assert!(novel_state().screenshot && !checkpoint().screenshot);
    }
}
