//! Shared decoded-input, parser and transient-output byte admission.
//!
//! Reservations precede allocation and move with owned bytes. This is admission,
//! not an allocator: an infallible third-party parser remains infallible.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};

/// Default shared admission ceiling, in bytes.
pub const DEFAULT_MEMORY_BYTES: usize = 4 * 1024 * 1024 * 1024;

/// A nonwaiting reservation failed without changing existing ownership.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("byte admission exhausted: requested {requested} bytes, {available} of {limit} available")]
#[non_exhaustive]
pub struct ByteAdmissionError {
    /// Requested reservation size; maximum integer denotes arithmetic overflow.
    pub requested: usize,
    /// Unreserved bytes at refusal.
    pub available: usize,
    /// Configured ceiling.
    pub limit: usize,
}

impl ByteAdmissionError {
    /// Whether the request cannot fit even after all existing owners finish.
    #[must_use]
    pub const fn exceeds_budget(&self) -> bool {
        self.requested > self.limit
    }
}

/// Process-local weighted byte admission shared by all pipeline phases.
#[derive(Debug)]
pub struct ByteBudget {
    limit: AtomicUsize,
    used: AtomicUsize,
}

impl ByteBudget {
    /// Construct an empty budget with the given ceiling.
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            limit: AtomicUsize::new(limit),
            used: AtomicUsize::new(0),
        }
    }

    /// Replace the ceiling without revoking live reservations.
    pub fn set_limit(&self, limit: usize) {
        self.limit.store(limit, Ordering::Release);
    }

    /// Current ceiling.
    #[must_use]
    pub fn limit(&self) -> usize {
        self.limit.load(Ordering::Acquire)
    }

    /// Total bytes held by live owners.
    #[must_use]
    pub fn used(&self) -> usize {
        self.used.load(Ordering::Acquire)
    }

    /// Unreserved bytes; zero when an operator lowered the ceiling below usage.
    #[must_use]
    pub fn available(&self) -> usize {
        self.limit().saturating_sub(self.used())
    }

    /// Reserve before allocating, without waiting while another owner holds memory.
    ///
    /// # Errors
    /// Returns typed pressure or an oversized request. Refusal reserves nothing.
    pub fn try_reserve(self: &Arc<Self>, bytes: usize) -> Result<BytePermit, ByteAdmissionError> {
        self.take(bytes)?;
        Ok(BytePermit {
            budget: Arc::clone(self),
            bytes,
        })
    }

    fn take(&self, bytes: usize) -> Result<(), ByteAdmissionError> {
        let limit = self.limit();
        self.used
            .try_update(Ordering::AcqRel, Ordering::Acquire, |used| {
                used.checked_add(bytes).filter(|total| *total <= limit)
            })
            .map(drop)
            .map_err(|used| ByteAdmissionError {
                requested: bytes,
                available: limit.saturating_sub(used),
                limit,
            })
    }
}

/// Transferable RAII ownership of admitted bytes. Never clone this permit.
///
/// An `Arc<BytePermit>` may accompany immutable shared bytes. Copying bytes needs
/// another reservation; cloning only the permit does not admit a deep copy.
#[derive(Debug)]
#[must_use = "keep the permit alive until all associated bytes have dropped"]
pub struct BytePermit {
    budget: Arc<ByteBudget>,
    bytes: usize,
}

impl BytePermit {
    /// Number of bytes owned by this permit.
    #[must_use]
    pub const fn bytes(&self) -> usize {
        self.bytes
    }

    /// Grow before allocation; shrinking is deliberately not implicit.
    ///
    /// # Errors
    /// Refusal keeps the original reservation unchanged.
    pub fn grow_to(&mut self, total: usize) -> Result<(), ByteAdmissionError> {
        if total > self.bytes {
            self.budget.take(total - self.bytes).map_err(|mut error| {
                error.requested = total;
                error
            })?;
            self.bytes = total;
        }
        Ok(())
    }

    /// Add a checked incremental reservation before allocation.
    ///
    /// # Errors
    /// Returns pressure or arithmetic overflow without losing existing ownership.
    pub fn grow_by(&mut self, additional: usize) -> Result<(), ByteAdmissionError> {
        let total = self.bytes.checked_add(additional).ok_or(ByteAdmissionError {
            requested: usize::MAX,
            available: self.budget.available(),
            limit: self.budget.limit(),
        })?;
        self.grow_to(total)
    }

    /// Transfer part of this reservation without changing total admitted bytes.
    ///
    /// # Errors
    /// Refuses to transfer more than this permit owns.
    pub fn split(&mut self, bytes: usize) -> Result<Self, ByteAdmissionError> {
        if bytes > self.bytes {
            return Err(ByteAdmissionError {
                requested: bytes,
                available: self.bytes,
                limit: self.bytes,
            });
        }
        self.bytes -= bytes;
        Ok(Self {
            budget: Arc::clone(&self.budget),
            bytes,
        })
    }

    /// Merge same-budget ownership without releasing bytes.
    ///
    /// # Errors
    /// Returns the unchanged donor when budgets differ or arithmetic overflows.
    pub fn merge(&mut self, mut donor: Self) -> Result<(), Self> {
        if !Arc::ptr_eq(&self.budget, &donor.budget) {
            return Err(donor);
        }
        let Some(total) = self.bytes.checked_add(donor.bytes) else {
            return Err(donor);
        };
        self.bytes = total;
        donor.bytes = 0;
        Ok(())
    }
}

impl Drop for BytePermit {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::AcqRel);
    }
}

/// Owned data and its reservation, dropped in that order.
#[derive(Debug)]
#[must_use = "dropping this value releases both data and its byte reservation"]
pub struct Budgeted<T> {
    value: T,
    permit: BytePermit,
}

impl<T> Budgeted<T> {
    /// Attach a reservation covering capacity not already owned transitively by `value`.
    ///
    /// A zero-byte carrier is valid only when the value already owns its source admission,
    /// for example immutable bytes backed by an admitted allocation owner.
    #[must_use = "retain admitted data until its work and sink I/O finish"]
    pub const fn new(value: T, permit: BytePermit) -> Self {
        Self { value, permit }
    }

    /// Borrow admitted data.
    #[must_use]
    pub const fn value(&self) -> &T {
        &self.value
    }

    /// Borrow data for in-place work. Growth still requires prior admission.
    pub fn value_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Borrow the reservation, for growth before allocation.
    pub fn permit_mut(&mut self) -> &mut BytePermit {
        &mut self.permit
    }

    /// Move both components to the next phase. Neither may outlive the other.
    #[must_use = "both data and permit must move to the next owner together"]
    pub fn into_parts(self) -> (T, BytePermit) {
        (self.value, self.permit)
    }
}

/// Immutable admitted text; cloning shares the same bytes and reservation.
#[derive(Clone)]
pub struct AdmittedText(Arc<Budgeted<String>>);

impl AdmittedText {
    /// Share an empty payload without consulting mutable process admission.
    #[must_use]
    pub fn empty() -> Self {
        static EMPTY: LazyLock<AdmittedText> =
            LazyLock::new(|| AdmittedText::new(String::new(), empty_permit()));
        EMPTY.clone()
    }

    /// Attach a permit reserved before allocating `text`, covering its capacity.
    #[must_use]
    pub fn new(text: String, permit: BytePermit) -> Self {
        Self(Arc::new(Budgeted::new(text, permit)))
    }

    /// Borrow shared text without copying its allocation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        self.0.value().as_str()
    }
}

impl std::ops::Deref for AdmittedText {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}

impl AsRef<str> for AdmittedText {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl PartialEq for AdmittedText {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}

impl Eq for AdmittedText {}

impl std::hash::Hash for AdmittedText {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        std::hash::Hash::hash(self.as_str(), state);
    }
}

impl std::fmt::Display for AdmittedText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl std::fmt::Debug for AdmittedText {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedText")
            .field("bytes", &self.len())
            .finish_non_exhaustive()
    }
}

/// Immutable admitted bytes; cloning shares the same bytes and reservation.
#[derive(Clone)]
pub struct AdmittedBytes(Arc<Budgeted<Vec<u8>>>);

impl AdmittedBytes {
    /// Share an empty payload without consulting mutable process admission.
    #[must_use]
    pub fn empty() -> Self {
        static EMPTY: LazyLock<AdmittedBytes> =
            LazyLock::new(|| AdmittedBytes::new(Vec::new(), empty_permit()));
        EMPTY.clone()
    }

    /// Attach a permit reserved before allocating `bytes`, covering its capacity.
    #[must_use]
    pub fn new(bytes: Vec<u8>, permit: BytePermit) -> Self {
        Self(Arc::new(Budgeted::new(bytes, permit)))
    }

    /// Borrow shared bytes without copying their allocation.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.value().as_slice()
    }
}

impl std::ops::Deref for AdmittedBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl AsRef<[u8]> for AdmittedBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl PartialEq for AdmittedBytes {
    fn eq(&self, other: &Self) -> bool {
        self.as_slice() == other.as_slice()
    }
}

impl Eq for AdmittedBytes {}

impl std::fmt::Debug for AdmittedBytes {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AdmittedBytes")
            .field("bytes", &self.len())
            .finish_non_exhaustive()
    }
}

fn empty_permit() -> BytePermit {
    static EMPTY_BUDGET: LazyLock<Arc<ByteBudget>> = LazyLock::new(|| Arc::new(ByteBudget::new(0)));
    BytePermit {
        budget: Arc::clone(&EMPTY_BUDGET),
        bytes: 0,
    }
}

static GLOBAL: LazyLock<Arc<ByteBudget>> = LazyLock::new(|| Arc::new(ByteBudget::new(DEFAULT_MEMORY_BYTES)));

/// Shared production budget for acquisition, parsing and output delivery.
#[must_use]
pub fn global() -> &'static Arc<ByteBudget> {
    &GLOBAL
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn transfer_split_merge_and_overflow_preserve_exact_ownership() {
        let budget = Arc::new(ByteBudget::new(100));
        let mut permit = budget.try_reserve(60).unwrap();
        let second = permit.split(20).unwrap();
        assert_eq!((permit.bytes(), second.bytes(), budget.used()), (40, 20, 60));
        permit.merge(second).unwrap();
        assert_eq!(budget.used(), 60);
        assert!(permit.grow_by(usize::MAX).is_err());
        assert!(permit.grow_to(101).is_err());
        assert_eq!(budget.used(), 60);
        drop(permit);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn data_drops_before_reservation_and_shared_owners_do_not_double_release() {
        struct Probe(Arc<ByteBudget>);
        impl Drop for Probe {
            fn drop(&mut self) {
                assert_eq!(self.0.used(), 10);
            }
        }
        let budget = Arc::new(ByteBudget::new(10));
        drop(Budgeted::new(
            Probe(Arc::clone(&budget)),
            budget.try_reserve(10).unwrap(),
        ));
        assert_eq!(budget.used(), 0);
        let shared = Arc::new(budget.try_reserve(10).unwrap());
        let clone = Arc::clone(&shared);
        drop(shared);
        assert_eq!(budget.used(), 10);
        drop(clone);
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn thirty_two_concurrent_bodies_cannot_over_admit() {
        let budget = Arc::new(ByteBudget::new(8 * 1024));
        let ready = Arc::new(std::sync::Barrier::new(33));
        let release = Arc::new(std::sync::Barrier::new(33));
        std::thread::scope(|scope| {
            for _ in 0..32 {
                let budget = Arc::clone(&budget);
                let ready = Arc::clone(&ready);
                let release = Arc::clone(&release);
                scope.spawn(move || {
                    let owned = budget
                        .try_reserve(1024)
                        .ok()
                        .map(|permit| Budgeted::new(vec![0u8; 1024], permit));
                    ready.wait();
                    release.wait();
                    drop(owned);
                });
            }
            ready.wait();
            let used = budget.used();
            release.wait();
            assert_eq!(used, 8 * 1024);
        });
        assert_eq!(budget.used(), 0);
    }

    #[test]
    fn immutable_payload_clones_share_memory_and_debug_hides_content() {
        let budget = Arc::new(ByteBudget::new(64));
        let permit = budget.try_reserve(32).unwrap();
        let text = AdmittedText::new(String::from("payload-owned"), permit);
        let clone = text.clone();
        assert_eq!(text, clone);
        assert_eq!(text.as_str().as_ptr(), clone.as_str().as_ptr());
        assert!(!format!("{text:?}").contains("payload-owned"));
        drop(text);
        assert_eq!(budget.used(), 32);
        drop(clone);
        assert_eq!(budget.used(), 0);

        let permit = budget.try_reserve(16).unwrap();
        let bytes = AdmittedBytes::new(vec![1; 8], permit);
        let clone = bytes.clone();
        assert_eq!(bytes.as_slice().as_ptr(), clone.as_slice().as_ptr());
        drop(bytes);
        assert_eq!(budget.used(), 16);
        drop(clone);
        assert_eq!(budget.used(), 0);
    }
}
