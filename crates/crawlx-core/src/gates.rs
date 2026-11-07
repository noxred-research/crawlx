//! Milestone gates: which of G1 (deterministic traceability) and G3 (model
//! authority) the running build has passed.
//!
//! This type performs no I/O. `crawlx_strategies::registry::Gates::load` reads and validates
//! the `gates/*.passed` files and produces a [`GateStatus`]; request validation
//! ([`CreateCrawl::check_gates`](crate::config::CreateCrawl::check_gates)) and the strategy
//! registry consume it.

/// Which gates have passed for this build. `Default` is "none passed".
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Default)]
pub struct GateStatus {
    /// G1: state clusters may suppress frontier entries (`state_novelty`, `enablement`).
    pub g1: bool,
    /// G3: `system1Mode` values above `shadow` may be requested.
    pub g3: bool,
}

impl GateStatus {
    /// No gate passed: the safe default for a build without `gates/` evidence.
    pub const NONE: Self = Self { g1: false, g3: false };
    /// Every gate passed. For tests and in-process harnesses that supply their own evidence;
    /// production entry points load the gate files instead.
    pub const ALL: Self = Self { g1: true, g3: true };
}
