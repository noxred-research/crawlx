//! Concurrent strategy fan-out under per-strategy deadlines.
//!
//! A strategy that times out or fails contributes nothing and is reported in
//! [`StrategyRound::errors`]; it never fails the round. Results are returned in
//! the order of the input slice, so the merged proposal list is deterministic.

use crate::context::DecisionContext;
use crate::error::StrategyError;
use crate::Strategy;
use crawlx_core::proposal::ActionProposal;
use futures::future::join_all;
use std::sync::Arc;
use std::time::Duration;

/// Names of the model-backed strategies (their deadline is the longer one).
const MODEL_BACKED: [&str; 2] = [crate::system1::NAME, crate::llm_planner::NAME];

/// Per-strategy deadlines (planning defaults).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct StrategyDeadlines {
    /// Time budget of a deterministic strategy before it counts as timed out.
    pub deterministic: Duration,
    /// Time budget of a model-backed strategy (System-1, LLM planner) before it counts as timed out.
    pub model: Duration,
}

impl Default for StrategyDeadlines {
    fn default() -> Self {
        Self {
            deterministic: Duration::from_millis(250),
            model: Duration::from_millis(1500),
        }
    }
}

impl StrategyDeadlines {
    /// Deadline for the strategy named `name`: `model` for model-backed ones, else `deterministic`.
    #[must_use]
    pub fn for_strategy(&self, name: &str) -> Duration {
        if MODEL_BACKED.contains(&name) {
            self.model
        } else {
            self.deterministic
        }
    }
}

/// Everything one fan-out produced.
#[derive(Debug, Default)]
pub struct StrategyRound {
    /// Proposals of all strategies that finished, in strategy order.
    pub proposals: Vec<ActionProposal>,
    /// Strategies that failed or timed out (`strategy.timeouts` / `strategy_error` events).
    pub errors: Vec<(&'static str, StrategyError)>,
}

/// Run every strategy concurrently against the same frozen context.
pub async fn run_strategies(
    strategies: &[Arc<dyn Strategy>],
    ctx: &DecisionContext<'_>,
    deadlines: &StrategyDeadlines,
) -> StrategyRound {
    let futs = strategies.iter().map(|s| {
        let limit = deadlines.for_strategy(s.name());
        let s = Arc::clone(s);
        async move {
            let name = s.name();
            let res = match tokio::time::timeout(limit, s.propose(ctx)).await {
                Ok(r) => r,
                Err(_) => Err(StrategyError::Timeout(limit)),
            };
            (name, res)
        }
    });
    let mut round = StrategyRound::default();
    for (name, res) in join_all(futs).await {
        match res {
            Ok(mut p) => round.proposals.append(&mut p),
            Err(e) => {
                tracing::warn!(strategy = name, error = %e, "strategy contributed nothing");
                round.errors.push((name, e));
            }
        }
    }
    round
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::interaction_bfs::InteractionBfs;
    use crate::testutil::{Fixture, Spec};
    use async_trait::async_trait;

    struct Slow;
    #[async_trait]
    impl Strategy for Slow {
        async fn propose(&self, _c: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError> {
            tokio::time::sleep(Duration::from_secs(5)).await;
            Ok(Vec::new())
        }
        fn name(&self) -> &'static str {
            "slow"
        }
        fn version(&self) -> u32 {
            1
        }
    }

    struct Broken;
    #[async_trait]
    impl Strategy for Broken {
        async fn propose(&self, _c: &DecisionContext<'_>) -> Result<Vec<ActionProposal>, StrategyError> {
            Err(StrategyError::Internal("boom".into()))
        }
        fn name(&self) -> &'static str {
            "broken"
        }
        fn version(&self) -> u32 {
            1
        }
    }

    #[tokio::test(start_paused = true)]
    async fn timeouts_and_errors_contribute_nothing_but_never_fail_the_round() {
        let f = Fixture::new(&[Spec::button("Open"), Spec::button("Next")]);
        let ctx = f.ctx();
        let strategies: Vec<Arc<dyn Strategy>> = vec![
            Arc::new(Slow),
            Arc::new(Broken),
            Arc::new(InteractionBfs::default()),
        ];
        let round = run_strategies(&strategies, &ctx, &StrategyDeadlines::default()).await;
        assert!(!round.proposals.is_empty());
        assert!(round.proposals.iter().all(|p| p.strategy == "interaction_bfs"));
        assert_eq!(round.errors.len(), 2);
        assert!(
            matches!(round.errors[0], ("slow", StrategyError::Timeout(d)) if d == Duration::from_millis(250))
        );
        assert!(matches!(round.errors[1], ("broken", StrategyError::Internal(_))));
    }

    #[test]
    fn model_backed_strategies_get_the_longer_deadline() {
        let d = StrategyDeadlines::default();
        assert_eq!(d.for_strategy("system1"), Duration::from_millis(1500));
        assert_eq!(d.for_strategy("llm_planner"), Duration::from_millis(1500));
        assert_eq!(d.for_strategy("interaction_bfs"), Duration::from_millis(250));
    }
}
