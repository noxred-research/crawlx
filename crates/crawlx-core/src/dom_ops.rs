//! Browser-plane operations of the surface-discovery headless parity set that need the
//! document itself and are neither a journaled [`crate::BrowserAction`] nor a scrape
//! [`crate::page_op::PageOp`]:
//!
//! * [`LazyScrollSpec`] / [`LazyScrollReport`]: reveal lazily loaded content
//!   (`dynamic.maxScrollSteps`, compatibility flag `-max-scroll-steps`) through
//!   [`crate::BrowserContext::lazy_scroll`];
//! * [`CssFilter`]: restrict interaction candidates by CSS (`dynamic.interactionSelector`,
//!   `dynamic.interactionExclude`, compatibility flags `-interaction-selector` / `-interaction-exclude`)
//!   through [`crate::BrowserContext::css_filter`].
//!
//! Neither operation clicks, types or submits anything. Contexts that cannot run them (the
//! scripted fake without a script for them, decorators that do not forward) answer
//! [`crate::BrowserError::Unsupported`].

use serde::{Deserialize, Serialize};

/// Largest number of scroll steps one [`LazyScrollSpec`] may ask for (`dynamic.maxScrollSteps`
/// is clamped to the same bound).
pub const MAX_LAZY_SCROLL_STEPS: u8 = 100;

/// A request to scroll the active tab's document so lazily loaded content appears.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct LazyScrollSpec {
    /// Most viewport-sized scroll steps to perform; the scroll stops earlier once the bottom of
    /// the document is reached and the document stopped growing. Clamped to
    /// [`MAX_LAZY_SCROLL_STEPS`].
    pub max_steps: u8,
    /// Milliseconds the page must stay quiet (no DOM mutation, no blocking request) after each
    /// step before the next one; this is what lets an `IntersectionObserver` or scroll handler
    /// append its content.
    pub settle_ms: u32,
}

impl LazyScrollSpec {
    /// Quiet window after each step used by `dynamic.maxScrollSteps` (300 ms).
    pub const DEFAULT_SETTLE_MS: u32 = 300;

    /// `max_steps` steps with [`Self::DEFAULT_SETTLE_MS`].
    #[must_use]
    pub const fn steps(max_steps: u8) -> Self {
        Self {
            max_steps,
            settle_ms: Self::DEFAULT_SETTLE_MS,
        }
    }
}

/// What a lazy scroll did.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct LazyScrollReport {
    /// Scroll steps performed (re-checks of a document that stopped growing are not steps).
    pub steps: u8,
    /// The last step ended at the bottom of a document that did not grow any further.
    pub reached_bottom: bool,
    /// Height of the document in CSS pixels when the scroll ended.
    pub document_height: u64,
}

/// CSS restrictions over interaction candidates, evaluated in the page: an element is admitted
/// when it matches one of `include` (or `include` is empty) and neither it nor an ancestor
/// matches one of `exclude`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct CssFilter {
    /// Selectors an element must match itself (`Element.matches`); empty admits every element.
    pub include: Vec<String>,
    /// Selectors whose matching elements and all their descendants are rejected
    /// (`Element.closest`).
    pub exclude: Vec<String>,
}

/// One XHR or `fetch()` request the page issued, as the browser observed it
/// ([`crate::BrowserContext::drain_xhr`], `extract.xhr`, compatibility flag `-xhr-extraction`).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct XhrRecord {
    /// URL of the page (main document) that issued the request.
    pub page_url: String,
    /// HTTP method, upper case.
    pub method: String,
    /// Request URL, already redacted like every captured URL.
    pub url: String,
    /// HTTP status of the response; `None` when none arrived.
    pub status: Option<u16>,
    /// `xhr` or `fetch`.
    pub resource_type: String,
    /// Response `Content-Type`, when a response arrived.
    pub content_type: Option<String>,
}

impl CssFilter {
    /// `true` when the filter admits everything, so evaluating it can be skipped.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.include.is_empty() && self.exclude.is_empty()
    }
}

/// Bounded, opt-in collection of exact `textContent` rows from one virtualized container.
/// Text is diagnostic content, not HTML, article text, or a live locator.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct VirtualRowsSpec {
    /// CSS selector matching exactly one container.
    pub container: String,
    /// CSS selector evaluated only inside that container.
    pub rows: String,
    /// Maximum native, journaled downward scrolls; initial capture does not count.
    pub max_steps: u8,
    /// Quiet period required after each scroll, in milliseconds.
    pub settle_ms: u32,
    /// Maximum rows returned by one window.
    pub max_rows_per_window: u32,
    /// Maximum rows transferred across all windows, including duplicates.
    pub max_rows: u32,
    /// Maximum serialized diagnostic bytes across all windows, including transport overhead.
    pub max_bytes: u32,
}

impl VirtualRowsSpec {
    /// Validate all work and transport limits before touching the page.
    ///
    /// # Errors
    /// Returns a bounded diagnostic for invalid selectors or resource limits.
    pub fn validate(&self) -> Result<(), String> {
        if [&self.container, &self.rows]
            .iter()
            .any(|s| s.is_empty() || s.len() > 1_024)
        {
            return Err("virtual rows: selectors must contain 1..=1024 bytes".into());
        }
        if self.max_steps > 100
            || !(1..=1_000).contains(&self.settle_ms)
            || !(1..=1_000).contains(&self.max_rows_per_window)
            || !(1..=10_000).contains(&self.max_rows)
            || self.max_rows_per_window > self.max_rows
            || !(1_024..=1_048_576).contains(&self.max_bytes)
        {
            return Err("virtual rows: invalid step, settle, row or byte limit".into());
        }
        Ok(())
    }
}

/// Why virtualized collection stopped; a cap is never completeness.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VirtualRowsStop {
    /// Container reached its current bottom.
    Bottom,
    /// Last permitted scroll was captured.
    StepCap,
    /// A row or serialized-byte allowance was exhausted.
    OutputCap,
    /// Container or document identity changed.
    Replaced,
    /// Native operation failed; no fabricated completeness.
    Failed,
    /// Caller ended before normal cleanup, including cancellation or deadline expiry.
    Interrupted,
}

/// Result of original-position restoration.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum VirtualRowsRestoration {
    /// Original element reached its saved horizontal and vertical positions.
    Restored,
    /// Original document or element no longer exists.
    Replaced,
    /// Restoration was attempted but failed or position did not match.
    Failed,
    /// No collection was active.
    Inactive,
}

/// One settled window; row strings preserve exact punctuation, whitespace and Unicode.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct VirtualRowsWindow {
    /// Document, navigation and mutation counters at capture.
    pub epoch: crate::ObservationEpoch,
    /// Exact row text; consumer projects secrets before exact deduplication.
    pub rows: Vec<String>,
    /// Current container bottom was visible.
    pub bottom: bool,
    /// A transport allowance prevented transferring all matched rows.
    pub capped: bool,
    /// Viewport-sized native scroll delta, with one-pixel overlap.
    pub scroll_step: u32,
    /// Conservative serialized charge, checked inside Chromium before transfer.
    pub transport_bytes: u32,
}

/// Diagnostic transformed rendition, retained only through a content artifact.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct VirtualRowsReport {
    /// Initial window followed by every settled scroll window, including the capped step.
    pub windows: Vec<VirtualRowsWindow>,
    /// Number of native scroll actions dispatched.
    pub steps: u8,
    /// Explicit completion or truncation reason.
    pub stop: VirtualRowsStop,
    /// Cleanup outcome, independent of collection completeness.
    pub restoration: VirtualRowsRestoration,
    /// Caller output cap, also enforced after privacy projection.
    pub max_bytes: u32,
}

impl VirtualRowsReport {
    /// Begin a diagnostic report; cleanup remains explicit until completed.
    #[must_use]
    pub fn new(initial: VirtualRowsWindow, max_bytes: u32) -> Self {
        Self {
            windows: vec![initial],
            steps: 0,
            stop: VirtualRowsStop::StepCap,
            restoration: VirtualRowsRestoration::Inactive,
            max_bytes,
        }
    }

    /// Project every row before exact first-seen deduplication, without normalized text keys.
    ///
    /// # Errors
    /// Returns the projector's failure without deduplicating unapproved content.
    pub fn project_rows<E>(&mut self, mut project: impl FnMut(&str) -> Result<String, E>) -> Result<(), E> {
        for window in &mut self.windows {
            for row in &mut window.rows {
                *row = project(row)?;
            }
        }
        let mut seen = std::collections::BTreeSet::new();
        let keep: Vec<bool> = self
            .windows
            .iter()
            .flat_map(|window| &window.rows)
            .map(|row| seen.insert(row.as_str()))
            .collect();
        drop(seen);
        let mut keep = keep.into_iter();
        for window in &mut self.windows {
            window.rows.retain(|_| keep.next().unwrap_or(false));
        }
        Ok(())
    }
}

#[cfg(test)]
mod virtual_rows_tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn spec() -> VirtualRowsSpec {
        serde_json::from_value(serde_json::json!({
            "container": "#virtual", "rows": ".row", "maxSteps": 2,
            "settleMs": 50, "maxRowsPerWindow": 10, "maxRows": 100,
            "maxBytes": 65536
        }))
        .unwrap()
    }

    #[test]
    fn virtual_rows_rejects_one_over_limits_and_unknown_fields() {
        assert!(spec().validate().is_ok());
        for changed in [
            VirtualRowsSpec {
                container: "é".repeat(513),
                ..spec()
            },
            VirtualRowsSpec {
                rows: String::new(),
                ..spec()
            },
            VirtualRowsSpec {
                max_steps: 101,
                ..spec()
            },
            VirtualRowsSpec {
                settle_ms: 0,
                ..spec()
            },
            VirtualRowsSpec {
                settle_ms: 1001,
                ..spec()
            },
            VirtualRowsSpec {
                max_rows_per_window: 1001,
                ..spec()
            },
            VirtualRowsSpec {
                max_rows: 10001,
                ..spec()
            },
            VirtualRowsSpec {
                max_bytes: 1023,
                ..spec()
            },
            VirtualRowsSpec {
                max_bytes: 1048577,
                ..spec()
            },
        ] {
            assert!(changed.validate().is_err(), "{changed:?}");
        }
        let mut wire = serde_json::to_value(spec()).unwrap();
        wire["script"] = serde_json::json!("not executable");
        assert!(serde_json::from_value::<VirtualRowsSpec>(wire).is_err());
    }

    fn window(rows: &[&str]) -> VirtualRowsWindow {
        VirtualRowsWindow {
            epoch: crate::ObservationEpoch::default(),
            rows: rows.iter().map(|row| (*row).to_owned()).collect(),
            bottom: false,
            capped: false,
            scroll_step: 99,
            transport_bytes: 1024,
        }
    }

    #[test]
    fn virtual_rows_projects_before_exact_first_seen_dedupe() {
        let mut report = VirtualRowsReport::new(
            window(&[
                "C++",
                "C#",
                "naïve",
                "naive",
                "東京",
                "pré\n  texte",
                "secret-one",
            ]),
            65536,
        );
        report
            .windows
            .push(window(&["C#", "東京", "🙂", "secret-two", "tail!"]));
        report
            .project_rows(|row| {
                Ok::<_, std::convert::Infallible>(if row.starts_with("secret-") {
                    "[REDACTED]".into()
                } else {
                    row.into()
                })
            })
            .unwrap();
        let rows: Vec<&str> = report
            .windows
            .iter()
            .flat_map(|w| &w.rows)
            .map(String::as_str)
            .collect();
        assert_eq!(
            rows,
            [
                "C++",
                "C#",
                "naïve",
                "naive",
                "東京",
                "pré\n  texte",
                "[REDACTED]",
                "🙂",
                "tail!"
            ]
        );
        let mut refused = VirtualRowsReport::new(window(&["unapproved"]), 65536);
        assert_eq!(
            refused.project_rows(|_| Err::<String, _>("unavailable")),
            Err("unavailable")
        );
    }
}
