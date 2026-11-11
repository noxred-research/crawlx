//! `RunPlanner`: `roles[] × runsPerRole` into run slots.

use crawlx_core::config::{CrawlMode, RoleOrder};
use crawlx_core::repo::{CrawlSession, SessionKind, SessionStatus};
use crawlx_core::{CrawlRunId, CreateCrawl, PrincipalId, SessionId};
use rand::seq::SliceRandom;

/// One `(role, run_index)` execution slot.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct RunSlot {
    /// Declaration order of the role, starting at 0.
    pub role_index: u16,
    /// Principal that executes this slot.
    pub role: PrincipalId,
    /// 1-based run number of this role.
    pub run_index: u16,
    /// `(run_index - 1) * n_roles + position`, where `position` is the role's place in
    /// the round (its declared index, or its place in the seeded permutation).
    pub schedule_slot: u32,
}

impl RunSlot {
    /// The `pending` session row for this slot.
    #[must_use]
    pub fn into_session(&self, run: CrawlRunId) -> CrawlSession {
        CrawlSession {
            id: SessionId::new(),
            run,
            kind: SessionKind::Browser,
            role: self.role.clone(),
            run_index: self.run_index,
            schedule_slot: self.schedule_slot,
            status: SessionStatus::Pending,
            browser: None,
            action_seq: 0,
        }
    }
}

/// Expands a request into slots.
pub struct RunPlanner;

impl RunPlanner {
    /// Slots ordered by `schedule_slot`: for run 1 every role in round order, then run 2, ...
    /// Round order is the declared order, or for `roleOrder: seeded_shuffle` one permutation
    /// drawn from the effective crawl seed and applied to every round, so two plans of the
    /// same request agree. A request without roles plans the implicit `anonymous` principal.
    #[must_use]
    pub fn plan(cfg: &CreateCrawl) -> Vec<RunSlot> {
        let roles = cfg.effective_roles();
        let n_roles = u32::try_from(roles.len()).unwrap_or(u32::MAX);
        let mut order: Vec<usize> = (0..roles.len()).collect();
        if cfg.role_order == RoleOrder::SeededShuffle {
            let mut rng = cfg.effective_seed().rng("role_order", &[]);
            order.shuffle(&mut rng);
        }
        let mut slots = Vec::with_capacity(roles.len() * usize::from(cfg.runs_per_role));
        for run_index in 1..=u16::from(cfg.runs_per_role) {
            for (position, &ordinal) in order.iter().enumerate() {
                let role_index = u16::try_from(ordinal).unwrap_or(u16::MAX);
                let position = u32::try_from(position).unwrap_or(u32::MAX);
                slots.push(RunSlot {
                    role_index,
                    role: PrincipalId(roles[ordinal].name.clone()),
                    run_index,
                    schedule_slot: u32::from(run_index - 1) * n_roles + position,
                });
            }
        }
        slots
    }

    /// Session rows for `run`, ready for `RunRepo::create_sessions`.
    /// Static runs coordinate HTTP work; hybrid and dynamic slots execute browser actors.
    #[must_use]
    pub fn sessions(run: CrawlRunId, cfg: &CreateCrawl) -> Vec<CrawlSession> {
        Self::plan(cfg)
            .iter()
            .map(|slot| {
                let mut session = slot.into_session(run);
                if cfg.mode == CrawlMode::Static {
                    session.kind = SessionKind::HttpCoordinator;
                }
                session
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_storage::testkit::create_crawl;
    use proptest::prelude::*;

    #[test]
    fn slots_follow_the_formula() {
        let cfg = create_crawl("https://example.test/", &["admin", "member", "guest"], 2);
        let slots = RunPlanner::plan(&cfg);
        assert_eq!(slots.len(), 6);
        let order: Vec<(&str, u16, u32)> = slots
            .iter()
            .map(|s| (s.role.0.as_str(), s.run_index, s.schedule_slot))
            .collect();
        assert_eq!(
            order,
            vec![
                ("admin", 1, 0),
                ("member", 1, 1),
                ("guest", 1, 2),
                ("admin", 2, 3),
                ("member", 2, 4),
                ("guest", 2, 5)
            ]
        );
    }

    #[test]
    fn no_roles_plans_anonymous() {
        let cfg = create_crawl("https://example.test/", &[], 3);
        let slots = RunPlanner::plan(&cfg);
        assert_eq!(
            slots
                .iter()
                .map(|s| (s.role.0.as_str(), s.schedule_slot))
                .collect::<Vec<_>>(),
            vec![("anonymous", 0), ("anonymous", 1), ("anonymous", 2)]
        );
    }

    #[test]
    fn session_kind_follows_execution_mode_not_browser_launch_state() {
        let mut cfg = create_crawl("https://example.test/", &[], 1);
        for (mode, kind) in [
            (CrawlMode::Static, SessionKind::HttpCoordinator),
            (CrawlMode::Hybrid, SessionKind::Browser),
            (CrawlMode::Dynamic, SessionKind::Browser),
        ] {
            cfg.mode = mode;
            let sessions = RunPlanner::sessions(CrawlRunId::new(), &cfg);
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions[0].kind, kind);
            assert!(sessions[0].browser.is_none());
        }
    }

    #[test]
    fn seeded_shuffle_is_stable_per_seed_and_keeps_the_barrier() {
        let names = ["admin", "member", "guest", "auditor", "viewer"];
        let mut cfg = create_crawl("https://example.test/", &names, 3);
        cfg.role_order = RoleOrder::SeededShuffle;
        cfg.seed = Some(42);
        let a = RunPlanner::plan(&cfg);
        let b = RunPlanner::plan(&cfg);
        assert_eq!(a, b, "same seed, same plan");
        let round = |slots: &[RunSlot], n: u16| -> Vec<String> {
            slots
                .iter()
                .filter(|s| s.run_index == n)
                .map(|s| s.role.0.clone())
                .collect()
        };
        assert_eq!(round(&a, 1), round(&a, 2));
        assert_eq!(round(&a, 2), round(&a, 3), "one permutation for every round");
        let mut sorted_round = round(&a, 1);
        sorted_round.sort();
        let mut sorted_names: Vec<String> = names.iter().map(|n| (*n).to_owned()).collect();
        sorted_names.sort();
        assert_eq!(sorted_round, sorted_names, "a permutation of the declared roles");
        assert_ne!(
            round(&a, 1),
            names.map(str::to_owned).to_vec(),
            "seed 42 does shuffle"
        );
        for s in &a {
            assert_eq!(
                names[usize::from(s.role_index)],
                s.role.0,
                "role_index stays declared"
            );
        }
        let mut by_slot = a.clone();
        by_slot.sort_by_key(|s| s.schedule_slot);
        for w in by_slot.windows(2) {
            assert!(w[0].run_index <= w[1].run_index, "barrier: run n before run n+1");
        }
        let slots: Vec<u32> = by_slot.iter().map(|s| s.schedule_slot).collect();
        assert_eq!(slots, (0..15).collect::<Vec<_>>());

        cfg.seed = Some(43);
        let c = RunPlanner::plan(&cfg);
        assert_ne!(round(&a, 1), round(&c, 1), "another seed, another permutation");
        cfg.role_order = RoleOrder::Declared;
        let d = RunPlanner::plan(&cfg);
        assert_eq!(round(&d, 1), names.map(str::to_owned).to_vec());
    }

    proptest! {
        /// Round-robin: in slot order, every role's run n precedes any role's run n+1.
        #[test]
        fn run_n_of_every_role_precedes_run_n_plus_1(n_roles in 1usize..6, runs in 1u8..6) {
            let names: Vec<String> = (0..n_roles).map(|i| format!("r{i}")).collect();
            let refs: Vec<&str> = names.iter().map(String::as_str).collect();
            let cfg = create_crawl("https://example.test/", &refs, runs);
            let slots = RunPlanner::plan(&cfg);
            prop_assert_eq!(slots.len(), n_roles * usize::from(runs));
            let mut sorted = slots.clone();
            sorted.sort_by_key(|s| s.schedule_slot);
            for w in sorted.windows(2) {
                prop_assert!(w[0].run_index <= w[1].run_index);
            }
            let mut seen: Vec<u32> = slots.iter().map(|s| s.schedule_slot).collect();
            seen.sort_unstable();
            seen.dedup();
            prop_assert_eq!(seen.len(), slots.len(), "slots are unique");
            prop_assert_eq!(seen.first().copied(), Some(0));
        }
    }
}
