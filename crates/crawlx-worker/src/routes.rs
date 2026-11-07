//! Online route-template learning (`RouteLearner`): sibling paths the crawl
//! observes (`/user/alice`, `/user/bob`, …) become one learned slot (`/user/:slug`) once
//! `min_distinct` of them share a structure, so the route keys of the URL plane, the browser
//! plane and the state fingerprint agree on what is one route. Top-level
//! segments are never slotted: `/about`, `/pricing`, `/blog` are an application's sections.
//!
//! The learner feeds the run's shared [`RouteTemplater`] (`CanonicalizeOptions::templater`,
//! behind a lock every holder of the options shares). Learning is bounded (at most
//! [`MAX_LEARN_PATHS`] distinct paths; past that the rules freeze) and deterministic: the
//! rules are recomputed from scratch from the sorted set of observed paths on a schedule
//! that depends only on the count of distinct paths ([`recompute_due`]: every new path up to
//! eight, then every eighth of the set), so they are a pure function of the set at each step.
//! Every rule change is persisted as a `route_templates` run event ([`ROUTE_TEMPLATES_EVENT`]) so a
//! resumed run restores the rules its predecessor keyed URLs with ([`RouteLearner::restore`]).

use crawlx_core::repo::EventRepo;
use crawlx_core::{CrawlRunId, StoreError};
use crawlx_url::RouteTemplater;
use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Distinct paths the learner keeps; later paths are ignored and the rules freeze.
pub const MAX_LEARN_PATHS: usize = 10_000;
/// Run event kind carrying a [`LearnedRoutes`] payload.
pub const ROUTE_TEMPLATES_EVENT: &str = "route_templates";
/// Page size used when scanning the event log for the last `route_templates` event.
const EVENT_PAGE: u32 = 1000;

/// Is a recomputation due with `len` distinct paths, the last one done at `learned_at`?
/// Every new path while fewer than eight are known, then once the set grew by an eighth:
/// `O(log n)` recomputations of `O(n)` each over the life of a run.
#[must_use]
pub const fn recompute_due(len: usize, learned_at: usize) -> bool {
    len > learned_at && len - learned_at >= if learned_at / 8 > 1 { learned_at / 8 } else { 1 }
}

/// The learned route rules at one version: what the `route_templates` run event carries.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct LearnedRoutes {
    /// Increments on every rule change of the run (1 = first learned slot).
    pub version: u32,
    /// Distinct paths observed when the rules were computed.
    pub paths_seen: u64,
    /// Distinct sibling values a learned slot needed.
    pub min_distinct: u64,
    /// Templated prefix → literal siblings (`RouteTemplater::learned`).
    pub learned: BTreeMap<String, BTreeSet<String>>,
}

struct LearnerState {
    paths: BTreeSet<String>,
    /// `paths.len()` at the last recomputation.
    learned_at: usize,
    version: u32,
}

/// Learns sibling route slots from observed paths into the run's shared templater.
#[derive(Clone)]
pub struct RouteLearner {
    templater: Arc<RwLock<RouteTemplater>>,
    state: Arc<Mutex<LearnerState>>,
}

impl RouteLearner {
    /// A learner writing into `templater` (the run's `CanonicalizeOptions::templater`).
    #[must_use]
    pub fn new(templater: Arc<RwLock<RouteTemplater>>) -> Self {
        Self {
            templater,
            state: Arc::new(Mutex::new(LearnerState {
                paths: BTreeSet::new(),
                learned_at: 0,
                version: 0,
            })),
        }
    }

    /// The templater this learner writes into.
    #[must_use]
    pub fn templater(&self) -> &Arc<RwLock<RouteTemplater>> {
        &self.templater
    }

    /// Distinct paths observed so far.
    #[must_use]
    pub fn paths_seen(&self) -> usize {
        self.state.lock().paths.len()
    }

    /// Current rules as a persistable snapshot.
    #[must_use]
    pub fn snapshot(&self) -> LearnedRoutes {
        let s = self.state.lock();
        let t = self.templater.read();
        LearnedRoutes {
            version: s.version,
            paths_seen: s.paths.len() as u64,
            min_distinct: t.min_distinct() as u64,
            learned: t.learned().clone(),
        }
    }

    /// Note one observed path (a query or fragment suffix is ignored). Returns the new rules
    /// when this observation changed them; the caller persists that snapshot.
    #[must_use]
    pub fn observe(&self, path: &str) -> Option<LearnedRoutes> {
        self.observe_all(std::iter::once(path))
    }

    /// [`Self::observe`] over several paths; recomputes at most once.
    pub fn observe_all<I, S>(&self, paths: I) -> Option<LearnedRoutes>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut s = self.state.lock();
        for p in paths {
            let p = p.as_ref().split(['?', '#']).next().unwrap_or("");
            if p.is_empty() || s.paths.len() >= MAX_LEARN_PATHS || s.paths.contains(p) {
                continue;
            }
            s.paths.insert(p.to_owned());
        }
        if !recompute_due(s.paths.len(), s.learned_at) {
            return None;
        }
        s.learned_at = s.paths.len();
        let fresh = {
            let current = self.templater.read();
            let min_distinct = current.min_distinct();
            let mut t = RouteTemplater::new().with_min_distinct(min_distinct);
            t.learn(&s.paths);
            // top-level segments are an application's sections (`/about`, `/pricing`, …),
            // never instances of one object: the root prefix is not slotted, nor are the
            // rules the templater derived below a root slot
            let mut learned = t.learned().clone();
            learned.retain(|prefix, _| {
                !prefix.is_empty() && !prefix.starts_with(crawlx_url::route_template::LEARNED_SLOT)
            });
            (learned != *current.learned()).then(|| {
                RouteTemplater::new()
                    .with_min_distinct(min_distinct)
                    .with_learned(learned)
            })
        }?;
        s.version = s.version.saturating_add(1);
        let snapshot = LearnedRoutes {
            version: s.version,
            paths_seen: s.paths.len() as u64,
            min_distinct: fresh.min_distinct() as u64,
            learned: fresh.learned().clone(),
        };
        *self.templater.write() = fresh;
        tracing::info!(
            version = snapshot.version,
            paths = snapshot.paths_seen,
            slots = snapshot.learned.len(),
            "route templates learned"
        );
        Some(snapshot)
    }

    /// Restore a persisted snapshot and the paths the run had observed (its frontier and
    /// state URLs): the templater renders exactly as before the restart, and learning
    /// continues from the restored set.
    pub fn restore<I, S>(&self, snapshot: &LearnedRoutes, paths: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut s = self.state.lock();
        for p in paths {
            let p = p.as_ref().split(['?', '#']).next().unwrap_or("");
            if p.is_empty() || s.paths.len() >= MAX_LEARN_PATHS {
                continue;
            }
            s.paths.insert(p.to_owned());
        }
        s.learned_at = s.paths.len();
        s.version = snapshot.version;
        let min_distinct = usize::try_from(snapshot.min_distinct).unwrap_or(usize::MAX);
        *self.templater.write() = RouteTemplater::new()
            .with_min_distinct(min_distinct)
            .with_learned(snapshot.learned.clone());
    }

    /// The last `route_templates` event of `run`, if any.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn persisted(
        events: &dyn EventRepo,
        run: CrawlRunId,
    ) -> Result<Option<LearnedRoutes>, StoreError> {
        let mut after = 0_u64;
        let mut last: Option<LearnedRoutes> = None;
        loop {
            let page = events.list_after(run, after, EVENT_PAGE).await?;
            let Some(tail) = page.last() else { break };
            after = tail.seq;
            for e in page.iter().filter(|e| e.kind == ROUTE_TEMPLATES_EVENT) {
                if let Ok(snapshot) = serde_json::from_value::<LearnedRoutes>(e.payload.clone()) {
                    last = Some(snapshot);
                }
            }
            if page.len() < EVENT_PAGE as usize {
                break;
            }
        }
        Ok(last)
    }

    /// Append `snapshot` as the run's `route_templates` event.
    ///
    /// # Errors
    /// Fails when a storage, browser or network operation it depends on fails.
    pub async fn persist(
        events: &dyn EventRepo,
        run: CrawlRunId,
        snapshot: &LearnedRoutes,
    ) -> Result<u64, StoreError> {
        let payload = serde_json::to_value(snapshot).map_err(|e| StoreError::Serialization(e.to_string()))?;
        events.append(run, ROUTE_TEMPLATES_EVENT, payload).await
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn learner() -> RouteLearner {
        RouteLearner::new(Arc::new(RwLock::new(RouteTemplater::new())))
    }

    #[test]
    fn top_level_sections_are_never_slotted() {
        let l = learner();
        let sections = [
            "/", "/p1", "/p2", "/p3", "/p4", "/p5", "/p6", "/about", "/pricing",
        ];
        assert!(l.observe_all(sections).is_none());
        assert_eq!(l.templater().read().learned_len(), 0);
        assert_eq!(l.templater().read().template("/p7").0, "/p7");
        // ...while siblings one level down still are
        let users: Vec<String> = (0..5).map(|i| format!("/user/u{i}")).collect();
        assert!(l.observe_all(&users).is_some());
        assert_eq!(l.templater().read().template("/user/zoe").0, "/user/:slug");
        assert_eq!(l.templater().read().template("/p7").0, "/p7");
    }

    #[test]
    fn siblings_become_one_slot_after_min_distinct_paths_and_the_rules_are_reported_once() {
        let l = learner();
        let users = ["alice", "bob", "carol", "dave"];
        for u in users {
            assert!(l.observe(&format!("/user/{u}?tab=1")).is_none(), "{u}");
        }
        assert_eq!(l.templater().read().template("/user/zoe").0, "/user/zoe");
        let snap = l.observe("/user/erin").expect("fifth sibling learns the slot");
        assert_eq!(snap.version, 1);
        assert_eq!(snap.paths_seen, 5);
        assert_eq!(l.templater().read().template("/user/zoe").0, "/user/:slug");
        // the same paths again change nothing and report nothing
        assert!(l
            .observe_all(users.iter().map(|u| format!("/user/{u}")))
            .is_none());
        assert_eq!(l.snapshot(), snap);
    }

    #[test]
    fn rules_are_a_pure_function_of_the_observed_set() {
        let a = learner();
        let b = learner();
        let paths: Vec<String> = (0..12).map(|i| format!("/p/{}", (b'a' + i) as char)).collect();
        let a_changes = paths.iter().filter(|p| a.observe(p).is_some()).count();
        let b_changes = paths.iter().rev().filter(|p| b.observe(p).is_some()).count();
        assert_eq!(a_changes, 1);
        assert_eq!(b_changes, 1);
        assert_eq!(a.snapshot(), b.snapshot());
        assert!(a.snapshot().version >= 1);
    }

    #[test]
    fn restore_reproduces_the_rules_and_continues_learning() {
        let l = learner();
        let paths: Vec<String> = (0..5).map(|i| format!("/doc/{i}x")).collect();
        let snap = l.observe_all(&paths).unwrap();
        let fresh = learner();
        fresh.restore(&snap, &paths);
        assert_eq!(fresh.snapshot(), snap);
        assert_eq!(fresh.templater().read().template("/doc/9x").0, "/doc/:slug");
        // five more siblings under another prefix are learned on top of the restored rules
        let more: Vec<String> = (0..5).map(|i| format!("/tag/{i}y")).collect();
        let next = fresh.observe_all(&more).unwrap();
        assert_eq!(next.version, snap.version + 1);
        assert_eq!(fresh.templater().read().template("/tag/zz").0, "/tag/:slug");
        assert_eq!(fresh.templater().read().template("/doc/9x").0, "/doc/:slug");
    }

    #[test]
    fn learning_freezes_at_the_path_cap() {
        let l = learner();
        let paths: Vec<String> = (0..MAX_LEARN_PATHS).map(|i| format!("/a/{i}z")).collect();
        assert!(l.observe_all(&paths).is_some());
        assert_eq!(l.paths_seen(), MAX_LEARN_PATHS);
        let before = l.snapshot();
        for i in 0..20 {
            assert!(l.observe(&format!("/b/{i}q")).is_none());
        }
        assert_eq!(l.paths_seen(), MAX_LEARN_PATHS);
        assert_eq!(l.snapshot(), before);
    }
}
