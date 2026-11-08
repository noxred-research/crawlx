//! Process-wide parse-memory budget.
//!
//! `scraper`/`html5ever` allocate while they parse, so the parse cannot be refused part way.
//! The release bar is therefore an *admission* bound, not a fully fallible parser:
//!
//! * every HTML parse in this crate that can report a typed error first charges
//!   [`charge_bytes`]`(input_len)` against the process-wide [`global`] budget;
//! * the charge is a nonwaiting compare-and-swap, so a refused parse never blocks while it
//!   holds a CPU-pool permit or a parent's permit;
//! * the [`ParseCharge`] guard lives until the parsed DOM and everything derived from it have
//!   been dropped;
//! * [`PARSE_BYTES_PER_INPUT_BYTE`] is the measured worst-case peak heap per input byte plus a
//!   margin, enforced by `tests/parse_memory_ceiling.rs`.
//!
//! # Ceiling factor
//!
//! The adversarial corpus of `tests/parse_memory_ceiling.rs` (28 shapes, each sized at the
//! 16 MiB input cap or the 1,000,000 `<` node cap) peaks at **364 bytes of live heap per input
//! byte** (a repeated unclosed `<a><b><i><em><strong><font><u><s><big><small><p>t`, which makes
//! the tree builder reconstruct ten formatting elements per paragraph). Every other shape stays
//! below 180 B/B; realistic article markup measures 13-29 B/B; one huge token measures 1-10 B/B.
//! The factor is 500: the measured worst case plus a 37% margin. The margin covers the
//! allocator-class rounding of the production allocator (mimalloc rounds each request up to its
//! size class, at most 12.5% extra), which the requested-bytes counter of the test does not see;
//! fragmentation and non-parse process memory are outside the ceiling and are covered by the
//! container limit (`deploy/helm/crawlx/values.yaml`).
//!
//! # Budget
//!
//! The limit is set by the binary when it builds its runtime
//! (`crawlx_worker::RuntimeConfig::parse_memory_bytes`, environment `CRAWLX_PARSE_MEMORY_BYTES`)
//! and defaults to [`DEFAULT_PARSE_MEMORY_BYTES`]: 4 GiB, i.e. eight concurrent parses of a
//! 1 MiB document (the reference input) at the worst-case factor, or one parse of up to
//! 8.1 MiB. An input whose charge exceeds the whole budget is always refused. Fully fallible,
//! per-allocation charged parsing remains post-release work.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

/// Charged heap bytes per input byte of HTML. See the module docs and the ceiling test, which
/// fails when any adversarial case exceeds `input_len * PARSE_BYTES_PER_INPUT_BYTE`.
pub const PARSE_BYTES_PER_INPUT_BYTE: usize = 500;

/// Default size of the process-wide budget: 4 GiB.
pub const DEFAULT_PARSE_MEMORY_BYTES: usize = 4 * 1024 * 1024 * 1024;

/// Heap bytes to charge for parsing `input_len` bytes of HTML, `None` on overflow.
#[must_use]
pub fn charge_bytes(input_len: usize) -> Option<usize> {
    input_len.checked_mul(PARSE_BYTES_PER_INPUT_BYTE)
}

/// The budget refused a charge; nothing was reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("parse memory budget exhausted: requested {requested} bytes, {available} of {limit} available")]
#[non_exhaustive]
pub struct ParseBudgetExhausted {
    /// Bytes the parse asked for (`usize::MAX` when the charge overflowed).
    pub requested: usize,
    /// Bytes unreserved when the request was refused.
    pub available: usize,
    /// Configured size of the budget.
    pub limit: usize,
}

impl ParseBudgetExhausted {
    /// The request is larger than the whole budget, so it is refused no matter how many other
    /// parses finish: a terminal "page exceeds the parse-memory budget", not transient pressure.
    /// At the default limit this is any input above `limit / 500` bytes (about 8 MiB for 4 GiB).
    #[must_use]
    pub const fn exceeds_budget(&self) -> bool {
        self.requested > self.limit
    }
}

/// A nonwaiting byte budget shared by all parses of the process.
#[derive(Debug)]
pub struct ParseBudget {
    limit: AtomicUsize,
    used: AtomicUsize,
}

impl ParseBudget {
    /// A budget of `limit` bytes with nothing charged.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            limit: AtomicUsize::new(limit),
            used: AtomicUsize::new(0),
        }
    }

    /// Replace the limit. Charges already held stay valid; new charges are refused until
    /// enough of them are released to fit under the new limit.
    pub fn set_limit(&self, bytes: usize) {
        self.limit.store(bytes, Ordering::Release);
    }

    /// Configured size of the budget.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Acquire)
    }

    /// Bytes currently charged.
    #[must_use]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    /// Bytes that a charge could still take right now.
    #[must_use]
    pub fn available(&self) -> usize {
        self.limit().saturating_sub(self.used())
    }

    /// Charge [`charge_bytes`]`(input_len)` without waiting.
    ///
    /// # Errors
    /// [`ParseBudgetExhausted`] when the charge overflows or does not fit in what is left.
    pub fn try_charge_input(self: &Arc<Self>, input_len: usize) -> Result<ParseCharge, ParseBudgetExhausted> {
        let mut charge = ParseCharge {
            budget: Arc::clone(self),
            bytes: 0,
        };
        charge.cover(input_len)?;
        Ok(charge)
    }

    fn try_take(&self, bytes: usize) -> Result<(), ParseBudgetExhausted> {
        let limit = self.limit();
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|total| *total <= limit)
            })
            .map(drop)
            .map_err(|used| ParseBudgetExhausted {
                requested: bytes,
                available: limit.saturating_sub(used),
                limit,
            })
    }
}

/// Bytes reserved from a [`ParseBudget`]; released on drop.
///
/// Not `Clone`: one parse owns one charge, and it must outlive the parsed DOM.
#[derive(Debug)]
#[must_use = "dropping the charge releases the reservation immediately"]
pub struct ParseCharge {
    budget: Arc<ParseBudget>,
    bytes: usize,
}

impl ParseCharge {
    /// Grow the reservation so it covers `input_len` input bytes; a no-op when it already does.
    ///
    /// # Errors
    /// [`ParseBudgetExhausted`] when the larger charge does not fit; the existing charge is kept.
    pub fn cover(&mut self, input_len: usize) -> Result<(), ParseBudgetExhausted> {
        let Some(wanted) = charge_bytes(input_len) else {
            return Err(ParseBudgetExhausted {
                requested: usize::MAX,
                available: self.budget.available(),
                limit: self.budget.limit(),
            });
        };
        if wanted > self.bytes {
            self.budget.try_take(wanted - self.bytes)?;
            self.bytes = wanted;
        }
        Ok(())
    }

    /// Bytes this guard holds.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.bytes
    }
}

impl Drop for ParseCharge {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

static GLOBAL: LazyLock<Arc<ParseBudget>> =
    LazyLock::new(|| Arc::new(ParseBudget::new(DEFAULT_PARSE_MEMORY_BYTES)));

/// The process-wide budget every production parse charges.
#[must_use]
pub fn global() -> &'static Arc<ParseBudget> {
    &GLOBAL
}

/// Charge the process-wide budget for parsing `input_len` bytes.
///
/// # Errors
/// [`ParseBudgetExhausted`] when the budget cannot take the charge right now.
pub fn charge(input_len: usize) -> Result<ParseCharge, ParseBudgetExhausted> {
    global().try_charge_input(input_len)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn charge_is_nonwaiting_typed_and_released_on_drop() {
        let budget = Arc::new(ParseBudget::new(5 * PARSE_BYTES_PER_INPUT_BYTE));
        let first = budget.try_charge_input(3).unwrap();
        assert_eq!(budget.used(), 3 * PARSE_BYTES_PER_INPUT_BYTE);
        let refused = budget.try_charge_input(3).unwrap_err();
        assert_eq!(refused.requested, 3 * PARSE_BYTES_PER_INPUT_BYTE);
        assert_eq!(refused.available, 2 * PARSE_BYTES_PER_INPUT_BYTE);
        assert_eq!(
            budget.used(),
            3 * PARSE_BYTES_PER_INPUT_BYTE,
            "a refusal reserves nothing"
        );
        let second = budget.try_charge_input(2).unwrap();
        assert_eq!(budget.available(), 0);
        drop(first);
        assert_eq!(budget.used(), 2 * PARSE_BYTES_PER_INPUT_BYTE);
        drop(second);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn cover_grows_in_place_and_keeps_the_old_charge_on_refusal() {
        let budget = Arc::new(ParseBudget::new(4 * PARSE_BYTES_PER_INPUT_BYTE));
        let mut charge = budget.try_charge_input(2).unwrap();
        charge.cover(1).unwrap();
        assert_eq!(charge.bytes(), 2 * PARSE_BYTES_PER_INPUT_BYTE);
        charge.cover(4).unwrap();
        assert_eq!(budget.used(), 4 * PARSE_BYTES_PER_INPUT_BYTE);
        assert!(charge.cover(5).is_err());
        assert_eq!(budget.used(), 4 * PARSE_BYTES_PER_INPUT_BYTE);
        drop(charge);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn overflow_and_oversize_requests_are_refused() {
        let budget = Arc::new(ParseBudget::new(PARSE_BYTES_PER_INPUT_BYTE));
        assert_eq!(
            budget.try_charge_input(usize::MAX).unwrap_err().requested,
            usize::MAX
        );
        assert!(budget.try_charge_input(2).unwrap_err().exceeds_budget());
        let held = budget.try_charge_input(1).unwrap();
        assert!(
            !budget.try_charge_input(1).unwrap_err().exceeds_budget(),
            "a request that would fit once `held` drops is pressure, not oversize"
        );
        drop(held);
        budget.set_limit(0);
        assert!(budget.try_charge_input(1).is_err());
        assert_eq!(budget.used(), 0);
    }
}
