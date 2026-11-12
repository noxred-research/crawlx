//! Adaptive static/browser render prediction.
//!
//! The heuristic classifier of the URL plane says which fetched pages need a browser. On its own
//! it can never learn that it is wrong about a page it calls static. This module adds the
//! exploration step: with a seeded probability a URL the heuristic calls static is also *probed*,
//! handed to the browser plane once so the two renderings can be compared.
//!
//! Everything here is deterministic and wall-clock free:
//!
//! * the draw is [`CrawlSeed::draw_per_mille`] over the predictor name, its version and the URL
//!   key, so a replay of the run recomputes exactly the draw it recorded;
//! * a probe is paid for in effects before it is selected for dispatch, and a probe nobody can
//!   pay for is denied and recorded, never run for free;
//! * every decision is a [`PredictorRecordV1`], the unit the worker persists and replays.

use crawlx_core::adaptive::{AdaptiveRendering, PREDICTOR_VERSION};
use crawlx_core::seed::CrawlSeed;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Purpose string of the predictor's seed derivation.
const PURPOSE: &str = "adaptive-render-predictor";

/// Why a selected probe was not paid for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ProbeDenial {
    /// The request's effect budget could not cover the probe.
    EffectBudget,
    /// The run-wide probe allowance (`maxProbes`) is spent.
    ProbeAllowance,
}

/// Whether the effect charge for a selected probe went through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProbeCharge {
    /// The effects were reserved.
    Charged,
    /// They were not.
    Denied(ProbeDenial),
}

/// The seeded draw for one URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct ProbeDraw {
    /// Predictor version the draw was made under.
    pub version: u32,
    /// The draw, in `0..1000`.
    pub draw_per_mille: u16,
    /// Whether the draw selects this URL for a probe (`draw < probePerMille`).
    pub selected: bool,
}

/// What the plane does with a page.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RenderVerdict {
    /// Static: the browser plane never sees the page.
    Static,
    /// The heuristic found a dynamic signal; the page goes to the browser plane.
    Escalate {
        /// The heuristic signal's stable name.
        signal: &'static str,
    },
    /// The heuristic said static but the draw selected the page and the probe was paid for: the
    /// page goes to the browser plane once, as an exploration.
    Probe,
    /// The draw selected the page but the probe could not be paid for: static.
    ProbeDenied(ProbeDenial),
}

impl RenderVerdict {
    /// Stable `snake_case` name recorded with the page.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Static => "static",
            Self::Escalate { .. } => "escalate",
            Self::Probe => "probe",
            Self::ProbeDenied(_) => "probe_denied",
        }
    }

    /// Whether the page is handed to the browser plane.
    #[must_use]
    pub const fn renders(self) -> bool {
        matches!(self, Self::Escalate { .. } | Self::Probe)
    }
}

/// One recorded predictor decision. Persisted by the worker; a replay verifies its draw.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct PredictorRecordV1 {
    /// Predictor version.
    pub version: u32,
    /// The draw, in `0..1000`.
    pub draw_per_mille: u16,
    /// Whether the draw selected the URL.
    pub selected: bool,
    /// Whether the probe's effects were reserved.
    pub charged: bool,
    /// The heuristic signal, if any.
    pub signal: Option<String>,
    /// The verdict's stable name.
    pub verdict: String,
    /// The denial, when the probe was selected but not paid for.
    pub denial: Option<ProbeDenial>,
}

/// A recorded draw that a replay cannot reproduce.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum PredictorError {
    /// The record was made by another predictor version.
    #[error("recorded predictor version {recorded} is not this build's version {current}")]
    Version {
        /// Version in the record.
        recorded: u32,
        /// Version this build implements.
        current: u32,
    },
    /// The same seed and URL no longer give the recorded draw.
    #[error("recorded predictor draw {recorded} differs from the replayed draw {replayed}")]
    Draw {
        /// Draw in the record.
        recorded: u16,
        /// Draw this build computes.
        replayed: u16,
    },
}

/// The render predictor of one run.
#[derive(Clone, Debug)]
pub struct RenderPredictor {
    seed: CrawlSeed,
    config: AdaptiveRendering,
}

impl RenderPredictor {
    /// A predictor over the run seed and its configuration.
    #[must_use]
    pub const fn new(seed: CrawlSeed, config: AdaptiveRendering) -> Self {
        Self { seed, config }
    }

    /// The configuration.
    #[must_use]
    pub const fn config(&self) -> &AdaptiveRendering {
        &self.config
    }

    /// The draw for the URL whose canonical key bytes are `url_key`. A pure function of the run
    /// seed, the predictor version and the key.
    #[must_use]
    pub fn draw(&self, url_key: &[u8]) -> ProbeDraw {
        let draw_per_mille = self
            .seed
            .draw_per_mille(PURPOSE, &[&PREDICTOR_VERSION.to_le_bytes(), url_key]);
        ProbeDraw {
            version: PREDICTOR_VERSION,
            draw_per_mille,
            selected: draw_per_mille < self.config.probe_per_mille,
        }
    }

    /// The verdict for a page. `heuristic` is the classifier's signal; `charge` is the outcome of
    /// paying for the probe and is only consulted when the draw selected the page and the
    /// heuristic called it static (`None` means no payment was attempted, which denies it).
    #[must_use]
    pub fn verdict(
        &self,
        draw: &ProbeDraw,
        heuristic: Option<&'static str>,
        charge: Option<ProbeCharge>,
    ) -> RenderVerdict {
        if let Some(signal) = heuristic {
            return RenderVerdict::Escalate { signal };
        }
        if !draw.selected {
            return RenderVerdict::Static;
        }
        match charge {
            Some(ProbeCharge::Charged) => RenderVerdict::Probe,
            Some(ProbeCharge::Denied(denial)) => RenderVerdict::ProbeDenied(denial),
            None => RenderVerdict::ProbeDenied(ProbeDenial::EffectBudget),
        }
    }

    /// The record of a decision.
    #[must_use]
    pub fn record(
        draw: &ProbeDraw,
        heuristic: Option<&'static str>,
        charge: Option<ProbeCharge>,
        verdict: RenderVerdict,
    ) -> PredictorRecordV1 {
        PredictorRecordV1 {
            version: draw.version,
            draw_per_mille: draw.draw_per_mille,
            selected: draw.selected,
            charged: matches!(charge, Some(ProbeCharge::Charged)),
            signal: heuristic.map(str::to_owned),
            verdict: verdict.as_str().to_owned(),
            denial: match verdict {
                RenderVerdict::ProbeDenied(denial) => Some(denial),
                _ => None,
            },
        }
    }

    /// Check that a recorded decision for `url_key` is what this build computes.
    ///
    /// # Errors
    /// A different predictor version, or a draw this seed no longer reproduces.
    pub fn replay(&self, recorded: &PredictorRecordV1, url_key: &[u8]) -> Result<ProbeDraw, PredictorError> {
        if recorded.version != PREDICTOR_VERSION {
            return Err(PredictorError::Version {
                recorded: recorded.version,
                current: PREDICTOR_VERSION,
            });
        }
        let draw = self.draw(url_key);
        if draw.draw_per_mille != recorded.draw_per_mille {
            return Err(PredictorError::Draw {
                recorded: recorded.draw_per_mille,
                replayed: draw.draw_per_mille,
            });
        }
        Ok(draw)
    }
}

/// The run-wide probe allowance. A row that already paid for a probe is never charged twice, so
/// a retried or replayed row cannot use up the allowance.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProbeLedger {
    max: u32,
    charged: BTreeSet<i64>,
}

impl ProbeLedger {
    /// An empty ledger allowing `max` probes.
    #[must_use]
    pub const fn new(max: u32) -> Self {
        Self {
            max,
            charged: BTreeSet::new(),
        }
    }

    /// Whether `row` can pay for a probe now (it already did, or the allowance has room).
    #[must_use]
    pub fn has_room(&self, row: i64) -> bool {
        self.charged.contains(&row) || self.charged.len() < usize::try_from(self.max).unwrap_or(usize::MAX)
    }

    /// Whether `row` has already paid for its probe (a retried row does not pay twice).
    #[must_use]
    pub fn paid(&self, row: i64) -> bool {
        self.charged.contains(&row)
    }

    /// Mark `row` as having paid for a probe.
    pub fn charge(&mut self, row: i64) {
        self.charged.insert(row);
    }

    /// Return `row`'s probe: its effect reservation failed.
    pub fn refund(&mut self, row: i64) {
        self.charged.remove(&row);
    }

    /// Probes paid for so far.
    #[must_use]
    pub fn charged(&self) -> usize {
        self.charged.len()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn predictor(seed: u64, per_mille: u16) -> RenderPredictor {
        RenderPredictor::new(CrawlSeed(seed), AdaptiveRendering::new(per_mille, 16))
    }

    #[test]
    fn the_draw_is_a_pure_function_of_seed_version_and_url() {
        let a = predictor(7, 100);
        let b = predictor(7, 100);
        let urls: Vec<[u8; 4]> = (0u32..300).map(u32::to_le_bytes).collect();
        let first: Vec<u16> = urls.iter().map(|u| a.draw(&u[..]).draw_per_mille).collect();
        let second: Vec<u16> = urls.iter().map(|u| b.draw(&u[..]).draw_per_mille).collect();
        assert_eq!(first, second, "same seed replays the same draws");
        let other: Vec<u16> = urls
            .iter()
            .map(|u| predictor(8, 100).draw(&u[..]).draw_per_mille)
            .collect();
        assert_ne!(first, other);
        // the selection threshold is the configured probability
        let selected = urls.iter().filter(|u| a.draw(&u[..]).selected).count();
        assert!((10..=60).contains(&selected), "about 10% of 300, got {selected}");
        assert!(urls.iter().all(|u| !predictor(7, 0).draw(&u[..]).selected));
        assert!(urls.iter().all(|u| predictor(7, 1000).draw(&u[..]).selected));
    }

    #[test]
    fn a_static_page_never_escalates_and_a_dynamic_one_always_does() {
        let p = predictor(3, 1000);
        let draw = p.draw(b"k");
        assert!(draw.selected);
        // static heuristic, probe not paid for: stays static
        assert_eq!(
            p.verdict(&draw, None, Some(ProbeCharge::Denied(ProbeDenial::EffectBudget))),
            RenderVerdict::ProbeDenied(ProbeDenial::EffectBudget)
        );
        assert!(!p.verdict(&draw, None, None).renders());
        // a dynamic signal escalates whatever the draw says
        let unselected = predictor(3, 0).draw(b"k");
        assert!(!unselected.selected);
        assert_eq!(
            p.verdict(&unselected, Some("spa_root"), None),
            RenderVerdict::Escalate { signal: "spa_root" }
        );
        assert_eq!(p.verdict(&unselected, None, None), RenderVerdict::Static);
        // paid-for probe of a static page renders once
        assert_eq!(
            p.verdict(&draw, None, Some(ProbeCharge::Charged)),
            RenderVerdict::Probe
        );
    }

    #[test]
    fn records_replay_and_detect_a_changed_draw_or_version() {
        let p = predictor(11, 1000);
        let draw = p.draw(b"https://a.test/x");
        let verdict = p.verdict(&draw, None, Some(ProbeCharge::Charged));
        let record = RenderPredictor::record(&draw, None, Some(ProbeCharge::Charged), verdict);
        assert_eq!(record.verdict, "probe");
        assert!(record.charged && record.selected);
        assert_eq!(p.replay(&record, b"https://a.test/x").unwrap(), draw);
        let json = serde_json::to_string(&record).unwrap();
        assert_eq!(serde_json::from_str::<PredictorRecordV1>(&json).unwrap(), record);
        assert!(matches!(
            predictor(12, 1000).replay(&record, b"https://a.test/x"),
            Err(PredictorError::Draw { .. })
        ));
        let mut old = record;
        old.version = 0;
        assert!(matches!(
            p.replay(&old, b"https://a.test/x"),
            Err(PredictorError::Version { .. })
        ));
    }

    #[test]
    fn the_probe_allowance_charges_a_row_once() {
        let mut ledger = ProbeLedger::new(2);
        assert!(ledger.has_room(1));
        ledger.charge(1);
        ledger.charge(1);
        assert_eq!(ledger.charged(), 1, "a retried row is not charged twice");
        ledger.charge(2);
        assert!(!ledger.has_room(3), "allowance spent");
        assert!(ledger.has_room(2), "a row that paid keeps its probe");
        ledger.refund(2);
        assert!(ledger.has_room(3));
    }
}
