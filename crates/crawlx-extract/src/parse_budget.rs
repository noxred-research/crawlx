//! Process-wide parse-memory budget.
//!
//! A parse is bounded twice. Admission refuses it up front; the fallible tree sink then keeps
//! the tree it builds inside what was admitted:
//!
//! * every HTML parse in this crate that can report a typed error first charges
//!   [`charge_bytes`]`(input_len)` against the process-wide [`global`] budget;
//! * the charge is a nonwaiting compare-and-swap, so a refused parse never blocks while it
//!   holds a CPU-pool permit or a parent's permit;
//! * the tree is built by [`crate::dom::parse_document`] / [`crate::dom::parse_fragment`], which
//!   spend that reservation allocation by allocation *before* each allocation happens (node
//!   storage is reserved fallibly, every payload is charged first) and, when the model needs
//!   more than was admitted, grow the reservation from this same budget. A refusal there is
//!   [`ParseBudgetExhausted`], the partial tree is dropped with the parser and the growth is
//!   released at once;
//! * the [`ParseCharge`] guard lives until the parsed DOM and everything derived from it have
//!   been dropped;
//! * [`PARSE_BYTES_PER_INPUT_BYTE`] is the measured worst-case peak heap per input byte plus a
//!   margin, enforced by `tests/parse_memory_ceiling.rs`, which also checks that the sink's own
//!   model never undercounts the measured peak of a corpus shape.
//!
//! What the sink cannot charge individually: the tokenizer's token strings, the tree builder's
//! stacks and the parser's own vectors are allocated inside `html5ever` and are covered by a
//! modelled allowance (per input byte and per element), not by a fallible call of their own;
//! the derived content tree ([`crate::dom::convert_node`]) and selector indexes are charged only
//! through the input multiplier.
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
//! and defaults to [`DEFAULT_PARSE_MEMORY_BYTES`]: 4 GiB shared with decoded acquisition
//! inputs and transient sink buffers. An input whose charge exceeds the whole budget is
//! always refused.

use crawlx_core::parser_memory::{ByteAdmissionError, ByteBudget, BytePermit};
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
///
/// `requested == usize::MAX` with `limit == 0` is the sentinel for an isolated parser helper that
/// ran out of address space, CPU time or wall-clock time: no budget numbers exist for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ParseBudgetExhausted {
    /// Bytes the parse asked for (`usize::MAX` when the charge overflowed or the allocator
    /// refused node storage the budget had admitted).
    pub requested: usize,
    /// Bytes unreserved when the request was refused.
    pub available: usize,
    /// Configured size of the budget.
    pub limit: usize,
}

impl std::fmt::Display for ParseBudgetExhausted {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.requested == usize::MAX && self.limit == 0 {
            write!(
                f,
                "the isolated parser helper exhausted its address-space, CPU or time limit \
                 (raise CRAWLX_PARSER_HELPER_ADDRESS_SPACE_BYTES, CRAWLX_PARSER_HELPER_CPU_SECONDS or \
                 CRAWLX_PARSER_HELPER_TIMEOUT_MS for pages above the in-process size)"
            )
        } else {
            write!(
                f,
                "parse memory budget exhausted: requested {} bytes, {} of {} available",
                self.requested, self.available, self.limit
            )
        }
    }
}

impl std::error::Error for ParseBudgetExhausted {}

impl ParseBudgetExhausted {
    /// The request is larger than the whole budget, so it is refused no matter how many other
    /// parses finish: a terminal "page exceeds the parse-memory budget", not transient pressure.
    /// At the default limit this is any input above `limit / 500` bytes (about 8 MiB for 4 GiB).
    /// A `usize::MAX` request (an overflowed charge, or node storage the allocator refused) exceeds
    /// every budget, however large.
    #[must_use]
    pub const fn exceeds_budget(&self) -> bool {
        self.requested > self.limit || self.requested == usize::MAX
    }
}

/// A nonwaiting byte budget shared by all parses of the process.
#[derive(Debug)]
pub struct ParseBudget {
    bytes: Arc<ByteBudget>,
}

impl ParseBudget {
    /// A budget of `limit` bytes with nothing charged.
    #[must_use]
    pub fn new(limit: usize) -> Self {
        Self {
            bytes: Arc::new(ByteBudget::new(limit)),
        }
    }

    /// Replace the limit. Charges already held stay valid; new charges are refused until
    /// enough of them are released to fit under the new limit.
    pub fn set_limit(&self, bytes: usize) {
        self.bytes.set_limit(bytes);
    }

    /// Configured size of the budget.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.bytes.limit()
    }

    /// Bytes currently charged.
    #[must_use]
    pub fn used(&self) -> usize {
        self.bytes.used()
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
        let wanted = charge_bytes(input_len).ok_or(ParseBudgetExhausted {
            requested: usize::MAX,
            available: self.available(),
            limit: self.limit(),
        })?;
        let permit = self.bytes.try_reserve(wanted).map_err(memory_error)?;
        Ok(ParseCharge {
            budget: Arc::clone(self),
            permit,
            tree_bytes: 0,
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
    permit: BytePermit,
    /// Peak bytes the fallible tree sink modelled for the last tree built under this charge.
    tree_bytes: usize,
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
        self.permit.grow_to(wanted).map_err(memory_error)
    }

    /// Bytes this guard holds.
    #[must_use]
    pub fn bytes(&self) -> usize {
        self.permit.bytes()
    }

    /// Peak live parse heap the fallible tree sink ([`crate::dom::parse_document`]) modelled
    /// for the tree it last built under this charge. It is spent from the reservation this
    /// guard holds, which grows only when the model needs more.
    #[must_use]
    pub const fn tree_bytes(&self) -> usize {
        self.tree_bytes
    }

    /// Move ownership to a document or sink carrier after parsing finishes.
    pub fn into_permit(self) -> BytePermit {
        self.permit
    }

    pub(crate) fn budget(&self) -> &ParseBudget {
        &self.budget
    }

    /// Start a tree build: the prepaid bytes, an empty permit the build grows past them, and
    /// the budget the growth is taken from.
    pub(crate) fn begin_tree(
        &mut self,
    ) -> Result<(BytePermit, usize, Arc<ParseBudget>), ParseBudgetExhausted> {
        let extra = self.permit.split(0).map_err(memory_error)?;
        Ok((extra, self.permit.bytes(), Arc::clone(&self.budget)))
    }

    /// Keep what a finished tree build grew: the tree lives as long as this guard.
    pub(crate) fn end_tree(&mut self, grown: BytePermit, peak: usize) {
        // `grown` was split from this guard's permit, so the budgets always match
        if let Err(donor) = self.permit.merge(grown) {
            drop(donor);
        }
        self.tree_bytes = peak;
    }
}

fn memory_error(error: ByteAdmissionError) -> ParseBudgetExhausted {
    ParseBudgetExhausted {
        requested: error.requested,
        available: error.available,
        limit: error.limit,
    }
}

static GLOBAL: LazyLock<Arc<ParseBudget>> = LazyLock::new(|| {
    Arc::new(ParseBudget {
        bytes: Arc::clone(crawlx_core::parser_memory::global()),
    })
});

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
    fn helper_resource_sentinel_names_the_limits_not_budget_numbers() {
        let helper = ParseBudgetExhausted {
            requested: usize::MAX,
            available: 0,
            limit: 0,
        };
        let text = helper.to_string();
        assert!(text.contains("isolated parser helper"), "{text}");
        assert!(
            text.contains("CRAWLX_PARSER_HELPER_ADDRESS_SPACE_BYTES"),
            "{text}"
        );
        assert!(!text.contains("18446744073709551615"), "{text}");
        let real = ParseBudgetExhausted {
            requested: 1000,
            available: 10,
            limit: 500,
        };
        assert_eq!(
            real.to_string(),
            "parse memory budget exhausted: requested 1000 bytes, 10 of 500 available"
        );
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

    #[test]
    fn production_dom_budget_shares_acquisition_and_sink_authority() {
        assert!(Arc::ptr_eq(&global().bytes, crawlx_core::parser_memory::global()));
        let budget = Arc::new(ParseBudget::new(2 * PARSE_BYTES_PER_INPUT_BYTE));
        let charge = budget.try_charge_input(1).unwrap();
        let sink_permit = charge.into_permit();
        assert_eq!(budget.used(), PARSE_BYTES_PER_INPUT_BYTE);
        assert!(budget.try_charge_input(2).is_err());
        drop(sink_permit);
        assert_eq!(budget.used(), 0);
    }
}
