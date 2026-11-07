//! The strategy switching policy.
//!
//! ```text
//! Greedy ⇄ System1 (overlay) → StateRecovery → EnablementRecovery → Planner → Done
//! ```
//!
//! `System1` is the greedy phase with the model overlay active (a large
//! candidate set); it is not a separate recovery stage. The policy is a pure
//! function of its own state and the inputs of [`SwitchingPolicy::next`], so a
//! recorded run replays to the same phase sequence. The planner is never
//! entered without budget (`BudgetView::planner_available`).
//!
//! Exhausting the configured exploration strategies ends the admissible frontier, even when
//! known keys remain uncovered. That is not a browser/session recovery failure: coverage
//! retains those deficits, while `RecoveryExhausted` is reserved for the worker's failed
//! session recovery ladder.

use crate::context::{BudgetView, StallCounters};
use crawlx_core::counters::TerminalReason;

/// Phase of the exploration state machine.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub enum Phase {
    /// Never-exercised safe keys exist: interaction BFS + novelty.
    #[default]
    Greedy,
    /// No `Q0` key left or `stall ≥ 50`: go to the cluster with the best expected gain.
    StateRecovery,
    /// Hidden targets known: follow enablement paths.
    EnablementRecovery,
    /// Greedy with the System-1 model overlay (large candidate set).
    System1,
    /// Deterministic recovery exhausted: ask the LLM planner.
    Planner,
    /// Terminal.
    Done,
}

impl Phase {
    /// Stable snake_case name of the phase, as recorded in events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Greedy => "greedy",
            Self::StateRecovery => "state_recovery",
            Self::EnablementRecovery => "enablement_recovery",
            Self::System1 => "system1",
            Self::Planner => "planner",
            Self::Done => "done",
        }
    }
}

/// Thresholds (planning defaults; paper references in brackets).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SwitchingConfig {
    /// Greedy → StateRecovery at this many consecutive non-novel trusted actions [paper: 50].
    pub stall_threshold: u32,
    /// StateRecovery → EnablementRecovery at this many non-novel interactions [25].
    pub recovery_stall_threshold: u32,
    /// Enablement-recovery interaction budget per run [paper Phase 2: 500].
    pub enablement_budget: u32,
    /// Leave `EnablementRecovery` after this many non-novel trusted actions in it.
    pub enablement_stall_threshold: u32,
    /// Candidate count at which the System-1 overlay engages (`n < 12` skips the model).
    pub system1_min_candidates: usize,
    /// Whether a System-1 engine is configured at all.
    pub system1_enabled: bool,
    /// Consecutive planner failures that end the run.
    pub planner_max_failures: u32,
}

impl Default for SwitchingConfig {
    fn default() -> Self {
        Self {
            stall_threshold: 50,
            recovery_stall_threshold: 25,
            enablement_budget: 500,
            enablement_stall_threshold: 50,
            system1_min_candidates: 12,
            system1_enabled: false,
            planner_max_failures: 2,
        }
    }
}

/// The state machine. Cheap, `Clone`, deterministic.
#[derive(Clone, Debug)]
pub struct SwitchingPolicy {
    cfg: SwitchingConfig,
    phase: Phase,
    /// `trusted_actions` when the current non-greedy phase was entered.
    entry_actions: u64,
    /// `planner_successes` when `Planner` was entered.
    entry_planner_successes: u32,
    done: Option<TerminalReason>,
}

impl SwitchingPolicy {
    /// Start in `Greedy` with thresholds `cfg`.
    #[must_use]
    pub fn new(cfg: SwitchingConfig) -> Self {
        Self {
            cfg,
            phase: Phase::Greedy,
            entry_actions: 0,
            entry_planner_successes: 0,
            done: None,
        }
    }

    /// Thresholds this policy was created with.
    #[must_use]
    pub const fn config(&self) -> &SwitchingConfig {
        &self.cfg
    }

    /// Current phase (the result of the last [`Self::next`]).
    #[must_use]
    pub const fn phase(&self) -> Phase {
        self.phase
    }

    /// Why the run ended, once `Done`.
    #[must_use]
    pub const fn done_reason(&self) -> Option<TerminalReason> {
        self.done
    }

    fn enter(&mut self, phase: Phase, s: &StallCounters) -> Phase {
        self.phase = phase;
        self.entry_actions = s.trusted_actions;
        self.entry_planner_successes = s.planner_successes;
        phase
    }

    fn finish(&mut self, reason: TerminalReason) -> Phase {
        self.phase = Phase::Done;
        self.done = Some(reason);
        Phase::Done
    }

    /// The phase for the next round.
    ///
    /// * `hidden_targets_exist`: identities seen earlier but not visible now.
    /// * `candidate_count`: current actionable candidates.
    pub fn next(
        &mut self,
        s: &StallCounters,
        b: &BudgetView,
        hidden_targets_exist: bool,
        candidate_count: usize,
    ) -> Phase {
        if self.phase == Phase::Done {
            return Phase::Done;
        }
        if let Some(r) = b.exhausted {
            return self.finish(r);
        }
        if b.actions_remaining == Some(0) {
            return self.finish(TerminalReason::LimitReached);
        }
        let since_entry = s.trusted_actions.saturating_sub(self.entry_actions);
        // a novel action happened since entry iff the stall run is shorter than the time spent
        let progressed = u64::from(s.stall) < since_entry;
        let greedy_ok = s.unexercised_here > 0 && s.stall < self.cfg.stall_threshold;
        match self.phase {
            Phase::Greedy | Phase::System1 => {
                if !greedy_ok {
                    return self.enter(Phase::StateRecovery, s);
                }
                let overlay = self.cfg.system1_enabled && candidate_count >= self.cfg.system1_min_candidates;
                self.phase = if overlay { Phase::System1 } else { Phase::Greedy };
                self.phase
            }
            Phase::StateRecovery => {
                if greedy_ok {
                    return self.enter(Phase::Greedy, s);
                }
                let escalate = s.unexercised_known == 0
                    || (!progressed && since_entry >= u64::from(self.cfg.recovery_stall_threshold));
                if !escalate {
                    return Phase::StateRecovery;
                }
                if hidden_targets_exist && s.enablement_used < self.cfg.enablement_budget {
                    self.enter(Phase::EnablementRecovery, s)
                } else {
                    self.after_deterministic(s, b)
                }
            }
            Phase::EnablementRecovery => {
                if greedy_ok && progressed {
                    return self.enter(Phase::Greedy, s);
                }
                let stalled = !progressed && since_entry >= u64::from(self.cfg.enablement_stall_threshold);
                if hidden_targets_exist && s.enablement_used < self.cfg.enablement_budget && !stalled {
                    return Phase::EnablementRecovery;
                }
                self.after_deterministic(s, b)
            }
            Phase::Planner => {
                if s.planner_successes > self.entry_planner_successes {
                    return self.enter(Phase::Greedy, s);
                }
                if s.planner_failures >= self.cfg.planner_max_failures || !b.planner_available() {
                    return self.finish(TerminalReason::FrontierExhausted);
                }
                Phase::Planner
            }
            Phase::Done => Phase::Done,
        }
    }

    /// Deterministic recovery is exhausted: planner when allowed, else done.
    fn after_deterministic(&mut self, s: &StallCounters, b: &BudgetView) -> Phase {
        if b.planner_available() && s.planner_failures < self.cfg.planner_max_failures {
            self.enter(Phase::Planner, s)
        } else {
            self.finish(TerminalReason::FrontierExhausted)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::config::LlmPlannerMode;

    fn counters(stall: u32, trusted: u64, here: u32, known: u32) -> StallCounters {
        StallCounters {
            stall,
            trusted_actions: trusted,
            unexercised_here: here,
            unexercised_known: known,
            ..StallCounters::default()
        }
    }

    #[test]
    fn greedy_while_unexercised_keys_exist() {
        let mut p = SwitchingPolicy::new(SwitchingConfig::default());
        assert_eq!(
            p.next(&counters(3, 3, 4, 4), &BudgetView::default(), false, 6),
            Phase::Greedy
        );
    }

    #[test]
    fn stall_threshold_triggers_state_recovery_then_escalates() {
        let mut p = SwitchingPolicy::new(SwitchingConfig::default());
        let b = BudgetView::default();
        assert_eq!(p.next(&counters(49, 49, 3, 3), &b, true, 6), Phase::Greedy);
        assert_eq!(p.next(&counters(50, 50, 3, 3), &b, true, 6), Phase::StateRecovery);
        // 24 more non-novel actions: still recovering
        assert_eq!(p.next(&counters(74, 74, 3, 3), &b, true, 6), Phase::StateRecovery);
        // 25 more: escalate; hidden targets exist
        assert_eq!(
            p.next(&counters(75, 75, 3, 3), &b, true, 6),
            Phase::EnablementRecovery
        );
    }

    #[test]
    fn novelty_in_recovery_returns_to_greedy() {
        let mut p = SwitchingPolicy::new(SwitchingConfig::default());
        let b = BudgetView::default();
        assert_eq!(
            p.next(&counters(50, 50, 3, 3), &b, false, 6),
            Phase::StateRecovery
        );
        // a novel action reset the stall counter
        assert_eq!(p.next(&counters(0, 51, 5, 5), &b, false, 6), Phase::Greedy);
    }

    #[test]
    fn no_unexercised_key_enters_recovery_without_waiting_for_the_stall() {
        let mut p = SwitchingPolicy::new(SwitchingConfig::default());
        assert_eq!(
            p.next(&counters(2, 2, 0, 5), &BudgetView::default(), false, 6),
            Phase::StateRecovery
        );
    }

    #[test]
    fn empty_frontier_goes_to_planner_only_with_budget() {
        let b = BudgetView::default();
        let mut p = SwitchingPolicy::new(SwitchingConfig::default());
        assert_eq!(
            p.next(&counters(10, 10, 0, 0), &b, false, 0),
            Phase::StateRecovery
        );
        // nothing known anywhere and no hidden targets: planner (budget available)
        assert_eq!(p.next(&counters(10, 10, 0, 0), &b, false, 0), Phase::Planner);

        // planner off -> straight to Done(frontier_exhausted)
        let off = BudgetView {
            llm_planner: LlmPlannerMode::Off,
            ..BudgetView::default()
        };
        let mut p = SwitchingPolicy::new(SwitchingConfig::default());
        p.next(&counters(10, 10, 0, 0), &off, false, 0);
        assert_eq!(p.next(&counters(10, 10, 0, 0), &off, false, 0), Phase::Done);
        assert_eq!(p.done_reason(), Some(TerminalReason::FrontierExhausted));
    }

    #[test]
    fn planner_never_entered_without_budget() {
        for b in [
            BudgetView {
                remaining_fraction: 0.10,
                ..BudgetView::default()
            },
            BudgetView {
                planner_calls: 8,
                ..BudgetView::default()
            },
            BudgetView {
                llm_planner: LlmPlannerMode::Off,
                ..BudgetView::default()
            },
        ] {
            let mut p = SwitchingPolicy::new(SwitchingConfig::default());
            let mut seen = Vec::new();
            for i in 0..40 {
                seen.push(p.next(&counters(60, 60 + i, 0, 3), &b, false, 4));
            }
            assert!(!seen.contains(&Phase::Planner), "{b:?} -> {seen:?}");
            assert_eq!(p.phase(), Phase::Done);
            assert_eq!(p.done_reason(), Some(TerminalReason::FrontierExhausted));
        }
    }

    #[test]
    fn exhausted_hidden_target_recovery_is_not_a_failed_browser_session() {
        let b = BudgetView {
            llm_planner: LlmPlannerMode::Off,
            ..BudgetView::default()
        };
        let mut p = SwitchingPolicy::new(SwitchingConfig::default());
        assert_eq!(p.next(&counters(50, 50, 0, 3), &b, true, 4), Phase::StateRecovery);
        assert_eq!(
            p.next(&counters(75, 75, 0, 3), &b, true, 4),
            Phase::EnablementRecovery
        );
        assert_eq!(p.next(&counters(125, 125, 0, 3), &b, true, 4), Phase::Done);
        assert_eq!(p.done_reason(), Some(TerminalReason::FrontierExhausted));
    }

    #[test]
    fn planner_success_returns_to_greedy_and_two_failures_end_the_run() {
        let b = BudgetView::default();
        let mut p = SwitchingPolicy::new(SwitchingConfig::default());
        p.next(&counters(10, 10, 0, 0), &b, false, 0);
        assert_eq!(p.next(&counters(10, 10, 0, 0), &b, false, 0), Phase::Planner);
        let ok = StallCounters {
            planner_successes: 1,
            unexercised_here: 3,
            unexercised_known: 3,
            trusted_actions: 12,
            ..StallCounters::default()
        };
        assert_eq!(p.next(&ok, &b, false, 4), Phase::Greedy);

        let mut p = SwitchingPolicy::new(SwitchingConfig::default());
        p.next(&counters(10, 10, 0, 0), &b, false, 0);
        assert_eq!(p.next(&counters(10, 10, 0, 0), &b, false, 0), Phase::Planner);
        let failed = StallCounters {
            planner_failures: 2,
            ..counters(10, 10, 0, 3)
        };
        assert_eq!(p.next(&failed, &b, false, 0), Phase::Done);
        assert_eq!(p.done_reason(), Some(TerminalReason::FrontierExhausted));
    }

    #[test]
    fn enablement_budget_is_enforced() {
        let b = BudgetView::default();
        let spent = StallCounters {
            enablement_used: 500,
            ..counters(80, 80, 0, 3)
        };
        // budget spent: the escalation skips EnablementRecovery
        let mut q = SwitchingPolicy::new(SwitchingConfig::default());
        q.next(&counters(50, 50, 0, 3), &b, true, 0);
        assert_eq!(q.next(&spent, &b, true, 0), Phase::Planner);
        // budget left: the same escalation enters it
        let mut p = SwitchingPolicy::new(SwitchingConfig::default());
        p.next(&counters(50, 50, 0, 3), &b, true, 0);
        assert_eq!(
            p.next(&counters(80, 80, 0, 3), &b, true, 0),
            Phase::EnablementRecovery
        );
    }

    #[test]
    fn enablement_recovery_gives_up_after_a_stall_without_progress() {
        let b = BudgetView::default();
        let mut p = SwitchingPolicy::new(SwitchingConfig::default());
        p.next(&counters(50, 50, 0, 3), &b, true, 0);
        assert_eq!(
            p.next(&counters(75, 75, 0, 3), &b, true, 0),
            Phase::EnablementRecovery
        );
        // 49 more non-novel actions in recovery: still trying
        assert_eq!(
            p.next(&counters(124, 124, 0, 3), &b, true, 0),
            Phase::EnablementRecovery
        );
        // 50: deterministic recovery is exhausted
        assert_eq!(p.next(&counters(125, 125, 0, 3), &b, true, 0), Phase::Planner);
    }

    #[test]
    fn system1_overlay_follows_candidate_count_and_config() {
        let cfg = SwitchingConfig {
            system1_enabled: true,
            ..SwitchingConfig::default()
        };
        let mut p = SwitchingPolicy::new(cfg);
        let b = BudgetView::default();
        assert_eq!(p.next(&counters(0, 0, 9, 9), &b, false, 11), Phase::Greedy);
        assert_eq!(p.next(&counters(0, 0, 9, 9), &b, false, 12), Phase::System1);
        assert_eq!(p.next(&counters(1, 1, 9, 9), &b, false, 40), Phase::System1);
        let mut off = SwitchingPolicy::new(SwitchingConfig::default());
        assert_eq!(off.next(&counters(0, 0, 9, 9), &b, false, 400), Phase::Greedy);
    }

    #[test]
    fn done_is_terminal_and_budget_exhaustion_maps_reasons() {
        let mut p = SwitchingPolicy::new(SwitchingConfig::default());
        let b = BudgetView {
            exhausted: Some(TerminalReason::DeadlineReached),
            ..BudgetView::default()
        };
        assert_eq!(p.next(&counters(0, 0, 9, 9), &b, false, 4), Phase::Done);
        assert_eq!(p.done_reason(), Some(TerminalReason::DeadlineReached));
        assert_eq!(
            p.next(&counters(0, 0, 9, 9), &BudgetView::default(), false, 4),
            Phase::Done
        );

        let mut q = SwitchingPolicy::new(SwitchingConfig::default());
        let zero = BudgetView {
            actions_remaining: Some(0),
            ..BudgetView::default()
        };
        assert_eq!(q.next(&counters(0, 0, 9, 9), &zero, false, 4), Phase::Done);
        assert_eq!(q.done_reason(), Some(TerminalReason::LimitReached));
    }
}
