//! Query-driven adaptive stop policy.
//!
//! A crawl with a question ("what does this site say about X?") should end when more pages stop
//! adding to the answer, not only when a page counter runs out. [`AdaptiveStop`] watches the text
//! of each evaluated page and tracks three things about the query's normalized terms:
//!
//! * **relevance** of a page: the share of query terms it contains;
//! * **gain** of a page: its relevance times its novelty, where novelty is the share of the page's
//!   distinct terms not yet seen on any earlier relevant page;
//! * **confidence**: how many query terms the relevant pages cover, scaled by how many relevant
//!   pages support that coverage.
//!
//! The crawl stops at the first of a confidence target, saturation (the average gain of the last
//! `window` pages below the threshold) and the page limit. Confidence is a coverage *estimate*
//! over the pages fetched: it is capped at [`CONFIDENCE_CEILING_PERMILLE`], below certainty, and
//! no stop reason claims that the site was exhausted.
//!
//! State is exported as a versioned [`AdaptiveStopExportV1`] of terms and counts (no page text, no
//! URLs) bound to the query by digest, so a later run of the same query can continue from it.
//!
//! The policy is pure integer arithmetic over `BTreeMap`/`BTreeSet`, reads no clock and draws no
//! randomness: the same pages in the same order give the same observations and the same export.

use crawlx_core::adaptive::{
    query_digest, query_terms, terms, AdaptiveStopConfigV1, AdaptiveStopExportV1, AdaptiveStopReason,
    ADAPTIVE_EXPORT_VERSION, CONFIDENCE_CEILING_PERMILLE,
};
use crawlx_core::hash::Digest;
use crawlx_core::CoreError;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

/// Bytes of one page's text that are evaluated.
const MAX_PAGE_BYTES: usize = 1024 * 1024;
/// Distinct terms of one page that are evaluated.
const MAX_PAGE_TERMS: usize = 8192;
/// Relevant pages that give the coverage estimate full support, in thousandths per page.
const SUPPORT_PER_PAGE_PERMILLE: u32 = 250;

/// The adaptive stop policy refused its configuration.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AdaptiveStopError {
    /// The configuration, or the state it imports, is invalid.
    #[error("invalid adaptive stop policy")]
    Config(#[from] CoreError),
    /// Imported state is not this policy's.
    #[error("adaptive stop import refused: {0}")]
    Import(&'static str),
}

/// What one evaluated page contributed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct Observation {
    /// Share of query terms on the page, in thousandths.
    pub relevance_permille: u16,
    /// Share of the page's distinct terms not seen on an earlier relevant page, in thousandths.
    pub novelty_permille: u16,
    /// `relevance * novelty`, in thousandths; zero for a page with no query term.
    pub gain_permille: u16,
    /// Coverage estimate after this page, in thousandths, at most
    /// [`CONFIDENCE_CEILING_PERMILLE`]. Never a claim of exhaustive coverage.
    pub confidence_permille: u16,
    /// Pages evaluated so far, this one included.
    pub pages: u32,
    /// Why the crawl should stop, once it should.
    pub stop: Option<AdaptiveStopReason>,
}

/// The policy state of one run.
#[derive(Clone, Debug)]
pub struct AdaptiveStop {
    config: AdaptiveStopConfigV1,
    terms: Vec<String>,
    digest: Digest,
    pages: u32,
    relevant_pages: u32,
    recent: VecDeque<u16>,
    term_pages: BTreeMap<String, u32>,
    vocabulary: BTreeSet<String>,
    stopped: Option<AdaptiveStopReason>,
}

fn permille(part: usize, whole: usize) -> u16 {
    if whole == 0 {
        return 0;
    }
    let value = part.saturating_mul(1000) / whole;
    u16::try_from(value.min(1000)).unwrap_or(1000)
}

impl AdaptiveStop {
    /// A policy for `config`, continuing from `config.import` when it carries state.
    ///
    /// # Errors
    /// An invalid configuration, or imported state that is not this query's.
    pub fn new(config: AdaptiveStopConfigV1) -> Result<Self, AdaptiveStopError> {
        config.validate()?;
        let mut policy = Self {
            terms: query_terms(&config.query),
            digest: query_digest(&config.query),
            pages: 0,
            relevant_pages: 0,
            recent: VecDeque::new(),
            term_pages: BTreeMap::new(),
            vocabulary: BTreeSet::new(),
            stopped: None,
            config,
        };
        if let Some(state) = policy.config.import.take() {
            policy.import(&state)?;
        }
        Ok(policy)
    }

    /// Replace this policy's state with `state`.
    ///
    /// # Errors
    /// State of another version or query, or state that does not fit this policy's bounds. The
    /// policy is unchanged on error.
    pub fn import(&mut self, state: &AdaptiveStopExportV1) -> Result<(), AdaptiveStopError> {
        if state.version != ADAPTIVE_EXPORT_VERSION {
            return Err(AdaptiveStopError::Import("unsupported export version"));
        }
        if state.query_digest != self.digest {
            return Err(AdaptiveStopError::Import("export belongs to a different query"));
        }
        state
            .check(&self.config.query, self.config.window, self.config.max_vocabulary)
            .map_err(AdaptiveStopError::Import)?;
        self.pages = state.pages;
        self.relevant_pages = state.relevant_pages;
        self.recent = state.recent_gains.iter().copied().collect();
        self.term_pages.clone_from(&state.term_pages);
        self.vocabulary = state.vocabulary.iter().cloned().collect();
        // A page limit is this run's budget, not a finding about the query: an imported state is
        // judged again under this policy's own limits. Saturation and a reached confidence
        // target describe the pages themselves and carry over.
        self.stopped = state
            .stopped
            .filter(|reason| *reason != AdaptiveStopReason::PageLimit);
        if self.stopped.is_none() && self.pages > 0 {
            self.stopped = self.stop_reason(self.confidence_permille());
        }
        Ok(())
    }

    /// The portable state. Terms and counts only; never page text or a URL.
    #[must_use]
    pub fn export(&self) -> AdaptiveStopExportV1 {
        let mut state = AdaptiveStopExportV1 {
            version: ADAPTIVE_EXPORT_VERSION,
            query_digest: self.digest,
            pages: self.pages,
            relevant_pages: self.relevant_pages,
            recent_gains: self.recent.iter().copied().collect(),
            term_pages: self.term_pages.clone(),
            vocabulary: self.vocabulary.iter().cloned().collect(),
            stopped: self.stopped,
        };
        // a `window` smaller than the imported tail cannot happen after `check`, but keep the
        // invariant local: the tail never outgrows the window
        let window = usize::try_from(self.config.window).unwrap_or(usize::MAX);
        let excess = state.recent_gains.len().saturating_sub(window);
        state.recent_gains.drain(..excess);
        state
    }

    /// Pages evaluated so far.
    #[must_use]
    pub const fn pages(&self) -> u32 {
        self.pages
    }

    /// Pages left before `maxPages`.
    #[must_use]
    pub const fn pages_left(&self) -> u32 {
        self.config.max_pages.saturating_sub(self.pages)
    }

    /// Why the crawl should stop, once it should.
    #[must_use]
    pub const fn stopped(&self) -> Option<AdaptiveStopReason> {
        self.stopped
    }

    /// Coverage estimate now, in thousandths, at most [`CONFIDENCE_CEILING_PERMILLE`].
    #[must_use]
    pub fn confidence_permille(&self) -> u16 {
        let covered = self.term_pages.values().filter(|count| **count > 0).count();
        let coverage = u32::from(permille(covered, self.terms.len()));
        let support = self
            .relevant_pages
            .saturating_mul(SUPPORT_PER_PAGE_PERMILLE)
            .min(1000);
        let estimate = coverage.saturating_mul(support) / 1000;
        u16::try_from(estimate.min(u32::from(CONFIDENCE_CEILING_PERMILLE)))
            .unwrap_or(CONFIDENCE_CEILING_PERMILLE)
    }

    /// Evaluate one page's text and update the state. Pages observed after the policy has
    /// stopped are still counted; the first stop reason stays.
    pub fn observe(&mut self, text: &str) -> Observation {
        let mut end = text.len().min(MAX_PAGE_BYTES);
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        let mut distinct = BTreeSet::new();
        for term in terms(&text[..end]) {
            if distinct.len() >= MAX_PAGE_TERMS && !distinct.contains(&term) {
                continue;
            }
            distinct.insert(term);
        }
        let matched: Vec<&String> = self
            .terms
            .iter()
            .filter(|term| distinct.contains(*term))
            .collect();
        let relevance = permille(matched.len(), self.terms.len());
        let (novelty, gain) = if matched.is_empty() {
            (0, 0)
        } else {
            let novel = distinct
                .iter()
                .filter(|term| !self.vocabulary.contains(*term))
                .count();
            let novelty = permille(novel, distinct.len());
            let gain = u16::try_from(u32::from(relevance) * u32::from(novelty) / 1000).unwrap_or(1000);
            self.relevant_pages = self.relevant_pages.saturating_add(1);
            for term in matched {
                let count = self.term_pages.entry(term.clone()).or_insert(0);
                *count = count.saturating_add(1);
            }
            let room = usize::try_from(self.config.max_vocabulary).unwrap_or(usize::MAX);
            for term in distinct {
                if self.vocabulary.len() >= room {
                    break;
                }
                self.vocabulary.insert(term);
            }
            (novelty, gain)
        };
        self.pages = self.pages.saturating_add(1);
        self.recent.push_back(gain);
        let window = usize::try_from(self.config.window).unwrap_or(usize::MAX);
        while self.recent.len() > window {
            self.recent.pop_front();
        }
        let confidence = self.confidence_permille();
        if self.stopped.is_none() {
            self.stopped = self.stop_reason(confidence);
        }
        Observation {
            relevance_permille: relevance,
            novelty_permille: novelty,
            gain_permille: gain,
            confidence_permille: confidence,
            pages: self.pages,
            stop: self.stopped,
        }
    }

    fn stop_reason(&self, confidence: u16) -> Option<AdaptiveStopReason> {
        let target = self.config.target_confidence_permille;
        if target > 0 && confidence >= target {
            return Some(AdaptiveStopReason::ConfidenceTarget);
        }
        let window = usize::try_from(self.config.window).unwrap_or(usize::MAX);
        if self.pages >= self.config.min_pages && self.recent.len() >= window {
            let sum: u64 = self.recent.iter().map(|gain| u64::from(*gain)).sum();
            if sum
                < u64::from(self.config.min_gain_permille)
                    .saturating_mul(u64::try_from(window).unwrap_or(u64::MAX))
            {
                return Some(AdaptiveStopReason::Saturated);
            }
        }
        (self.pages >= self.config.max_pages).then_some(AdaptiveStopReason::PageLimit)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    /// A page naming both query terms plus four words nobody else uses, so each one adds gain.
    fn fresh(n: usize) -> String {
        format!("rust async alpha{n} beta{n} gamma{n} delta{n}")
    }

    fn policy(tune: impl FnOnce(&mut AdaptiveStopConfigV1)) -> AdaptiveStop {
        let mut config = AdaptiveStopConfigV1::new("Rust async");
        tune(&mut config);
        AdaptiveStop::new(config).unwrap()
    }

    #[test]
    fn repeating_pages_saturate_at_the_hand_computed_page() {
        let mut stop = policy(|_| {});
        let page = "rust async runtime tokio executor scheduler";
        let first = stop.observe(page);
        assert_eq!(
            (
                first.relevance_permille,
                first.novelty_permille,
                first.gain_permille
            ),
            (1000, 1000, 1000)
        );
        // 2 of 2 terms covered, one relevant page of four needed: 1000 * 250 / 1000
        assert_eq!(first.confidence_permille, 250);
        for n in 2..=3 {
            let seen = stop.observe(page);
            assert_eq!(
                (seen.novelty_permille, seen.gain_permille),
                (0, 0),
                "page {n} adds nothing"
            );
            assert_eq!(seen.stop, None, "window [1000,0,0] averages 333");
        }
        let fourth = stop.observe(page);
        assert_eq!(fourth.pages, 4);
        assert_eq!(fourth.stop, Some(AdaptiveStopReason::Saturated), "window [0,0,0]");
    }

    #[test]
    fn irrelevant_pages_have_no_gain_and_do_not_grow_the_vocabulary() {
        let mut stop = policy(|c| c.min_pages = 0);
        stop.observe("rust async");
        let vocabulary = stop.export().vocabulary.len();
        let noise = stop.observe("gardening tomatoes compost weekend");
        assert_eq!((noise.relevance_permille, noise.gain_permille), (0, 0));
        assert_eq!(stop.export().vocabulary.len(), vocabulary);
        assert_eq!(stop.export().relevant_pages, 1);
        assert_eq!(stop.export().pages, 2);
    }

    #[test]
    fn the_page_limit_stops_a_crawl_that_still_gains() {
        let mut stop = policy(|c| c.max_pages = 3);
        assert_eq!(stop.observe(&fresh(1)).stop, None);
        assert_eq!(stop.pages_left(), 2);
        assert_eq!(stop.observe(&fresh(2)).stop, None);
        let third = stop.observe(&fresh(3));
        assert_eq!(third.stop, Some(AdaptiveStopReason::PageLimit));
        assert_eq!(stop.pages_left(), 0);
        // the first reason stays after the stop
        assert_eq!(stop.observe(&fresh(4)).stop, Some(AdaptiveStopReason::PageLimit));
    }

    #[test]
    fn the_confidence_target_stops_early_and_confidence_is_never_certainty() {
        let mut stop = policy(|c| c.target_confidence_permille = 900);
        let mut stopped_at = None;
        for n in 1..=4 {
            let seen = stop.observe(&fresh(n));
            if stopped_at.is_none() && seen.stop.is_some() {
                stopped_at = Some((n, seen.stop, seen.confidence_permille));
            }
        }
        // 250, 500, 750, 950 after pages 1..=4 (the ceiling caps the fourth)
        assert_eq!(
            stopped_at,
            Some((4, Some(AdaptiveStopReason::ConfidenceTarget), 950))
        );
        let mut endless = policy(|c| c.max_pages = 1000);
        for n in 1..=50 {
            let seen = endless.observe(&fresh(n));
            assert!(seen.confidence_permille <= CONFIDENCE_CEILING_PERMILLE);
            assert!(
                seen.confidence_permille < 1000,
                "never reported as exhaustive coverage"
            );
        }
        assert_eq!(endless.confidence_permille(), CONFIDENCE_CEILING_PERMILLE);
    }

    #[test]
    fn export_import_round_trips_and_continues_identically() {
        let mut original = policy(|c| c.max_pages = 6);
        for n in 1..=3 {
            original.observe(&fresh(n));
        }
        let exported = original.export();
        let wire = serde_json::to_string(&exported).unwrap();
        assert!(
            !wire.contains("rust async alpha1"),
            "terms and counts only, never page text"
        );
        let decoded: AdaptiveStopExportV1 = serde_json::from_str(&wire).unwrap();
        assert_eq!(decoded, exported, "versioned JSON round-trips");

        let mut config = AdaptiveStopConfigV1::new("async RUST");
        config.max_pages = 6;
        config.import = Some(decoded);
        let mut resumed = AdaptiveStop::new(config).unwrap();
        assert_eq!(resumed.export(), exported, "import restores the exact state");
        for n in 4..=6 {
            assert_eq!(original.observe(&fresh(n)), resumed.observe(&fresh(n)));
        }
        assert_eq!(original.export(), resumed.export());
        assert_eq!(resumed.stopped(), Some(AdaptiveStopReason::PageLimit));
    }

    #[test]
    fn an_imported_page_limit_is_rejudged_under_the_new_limits() {
        let mut first = policy(|c| {
            c.max_pages = 2;
            c.min_pages = 1;
        });
        first.observe(&fresh(1));
        assert_eq!(first.observe(&fresh(2)).stop, Some(AdaptiveStopReason::PageLimit));
        let exported = first.export();
        assert_eq!(exported.stopped, Some(AdaptiveStopReason::PageLimit));

        let mut config = AdaptiveStopConfigV1::new("rust async");
        config.max_pages = 4;
        config.import = Some(exported.clone());
        let mut second = AdaptiveStop::new(config).unwrap();
        assert_eq!(second.stopped(), None, "the larger limit lets the crawl continue");
        assert_eq!(second.pages(), 2);
        assert_eq!(second.pages_left(), 2);
        assert_eq!(second.observe(&fresh(3)).stop, None);
        assert_eq!(
            second.observe(&fresh(4)).stop,
            Some(AdaptiveStopReason::PageLimit)
        );

        // under the same limit it is still over
        let mut same = AdaptiveStopConfigV1::new("rust async");
        same.max_pages = 2;
        same.min_pages = 1;
        same.import = Some(exported);
        let mut third = AdaptiveStop::new(same).unwrap();
        assert_eq!(third.observe(&fresh(3)).stop, Some(AdaptiveStopReason::PageLimit));

        // saturation is a finding about the pages and carries over
        let mut saturated = policy(|_| {});
        let page = "rust async runtime tokio executor scheduler";
        (0..4).for_each(|_| {
            saturated.observe(page);
        });
        assert_eq!(saturated.stopped(), Some(AdaptiveStopReason::Saturated));
        let mut config = AdaptiveStopConfigV1::new("rust async");
        config.import = Some(saturated.export());
        assert_eq!(
            AdaptiveStop::new(config).unwrap().stopped(),
            Some(AdaptiveStopReason::Saturated)
        );
    }

    #[test]
    fn import_refuses_another_query_version_or_shape() {
        let mut source = policy(|_| {});
        source.observe(&fresh(1));
        let exported = source.export();

        let mut other = AdaptiveStopConfigV1::new("rust tokio");
        other.import = Some(exported.clone());
        assert!(AdaptiveStop::new(other).is_err(), "different query");

        let mut future = exported.clone();
        future.version = 2;
        let mut config = AdaptiveStopConfigV1::new("rust async");
        config.import = Some(future.clone());
        assert!(AdaptiveStop::new(config).is_err(), "unknown version");
        let mut fine = policy(|_| {});
        assert!(matches!(fine.import(&future), Err(AdaptiveStopError::Import(_))));

        let mut inconsistent = exported.clone();
        inconsistent.relevant_pages = inconsistent.pages + 1;
        assert!(fine.import(&inconsistent).is_err());
        let mut foreign_term = exported;
        foreign_term.term_pages.insert("zebra".to_owned(), 1);
        assert!(fine.import(&foreign_term).is_err());
        assert_eq!(fine.pages(), 0, "a refused import leaves the policy untouched");
    }

    #[test]
    fn determinism_same_pages_same_state() {
        let pages: Vec<String> = (1..=8).map(fresh).collect();
        let run = |pages: &[String]| {
            let mut stop = policy(|c| c.target_confidence_permille = 700);
            let seen: Vec<Observation> = pages.iter().map(|p| stop.observe(p)).collect();
            (seen, stop.export())
        };
        assert_eq!(run(&pages), run(&pages));
    }

    #[test]
    fn oversized_text_is_cut_on_a_character_boundary() {
        let mut stop = policy(|_| {});
        let mut text = "rust async ".to_owned();
        text.push_str(&"é".repeat(MAX_PAGE_BYTES));
        let seen = stop.observe(&text);
        assert_eq!(seen.relevance_permille, 1000);
    }
}
