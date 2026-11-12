//! Deployment-wide origin admission shared by HTTP and browser effects.
//!
//! Admission is keyed by an opaque string. An origin (`scheme://host[:port]`) is one kind of key;
//! a checked physical address is the other ([`physical_address_key`]). The first caps what a
//! site sees from the whole deployment under any host alias, the second caps what one machine
//! sees, so aliases that resolve to one address cannot add up past the cap across workers.

use crate::StoreError;
use async_trait::async_trait;
use std::fmt::Debug;
use std::net::IpAddr;
use std::time::Duration;

/// Prefix of the admission key of a physical address. No origin key starts with it.
pub const PHYSICAL_ADDRESS_KEY_PREFIX: &str = "ip:";

/// The deployment admission key of one checked physical address, canonical form: an IPv4
/// address mapped into IPv6 and the plain IPv4 address are one key.
#[must_use]
pub fn physical_address_key(ip: IpAddr) -> String {
    format!("{PHYSICAL_ADDRESS_KEY_PREFIX}{}", ip.to_canonical())
}

/// Whether `key` names a physical address rather than an origin. Address keys carry capacity
/// only: no per-run slot, pacing or cooldown follows them.
#[must_use]
pub fn is_physical_address_key(key: &str) -> bool {
    key.starts_with(PHYSICAL_ADDRESS_KEY_PREFIX)
}

/// An origin slot held until this value is dropped.
///
/// Implementations must release on cancellation and drop, without a detached renewal task.
/// A database implementation may hold a transaction-scoped advisory lock: its rollback
/// on drop fences the lifetime without relying on an expiring wall-clock lease.
#[async_trait]
#[must_use = "hold the permit for the complete network or browser operation"]
pub trait OriginPermit: Send + Debug {
    /// Atomically admit a start, or return its remaining pacing/cooldown wait.
    ///
    /// This operation never sleeps while the caller holds run-global capacity.
    /// Returning `None` commits a real start; `Some(wait)` does not advance pacing.
    ///
    /// # Errors
    /// Returns a storage error when the shared pacing authority is unavailable.
    async fn try_start(&mut self, spacing: Duration) -> Result<Option<Duration>, StoreError>;

    /// Wait for and admit an actual operation start.
    ///
    /// # Errors
    /// Returns a storage error when the shared pacing authority is unavailable.
    async fn start(&mut self, spacing: Duration) -> Result<(), StoreError>;
}

/// Admission authority shared by every tenant and worker in a deployment.
///
/// Implementations isolate queues by origin and grant waiters fairly. `spacing` is
/// a lower bound between admitted starts, not a delay after the operation finishes.
#[async_trait]
pub trait OriginAdmission: Send + Sync {
    /// Reserve capacity without advancing the origin's start clock.
    ///
    /// Queue here before taking run-global capacity so a saturated origin cannot
    /// block unrelated origins. Call [`OriginPermit::start`] just before the effect.
    ///
    /// # Errors
    /// Returns a storage error when the admission authority is unavailable.
    async fn reserve(&self, origin: &str) -> Result<Box<dyn OriginPermit>, StoreError>;

    /// Read committed origin cooldown before leasing/creating effect work.
    ///
    /// An origin without a feedback row has no cooldown. Read failures remain errors.
    ///
    /// # Errors
    /// Returns a storage error when shared eligibility cannot be observed.
    async fn cooldown_remaining(&self, origin: &str) -> Result<Duration, StoreError>;

    /// Publish an origin-wide cooldown before completing response processing.
    ///
    /// A positive `minimum` is never shortened. Exponential mode coalesces concurrent
    /// responses into one wave and doubles a two-second baseline up to sixty seconds.
    /// The returned duration is the remaining shared cooldown.
    ///
    /// # Errors
    /// Returns a storage error when shared feedback cannot be committed.
    async fn cooldown(
        &self,
        origin: &str,
        minimum: Duration,
        exponential: bool,
    ) -> Result<Duration, StoreError>;

    /// Wait for capacity and the next permitted start for `origin`.
    ///
    /// Dropping the future must release any capacity already acquired. The returned
    /// permit must remain held through the operation, including response-body reads.
    ///
    /// # Errors
    /// Returns a storage error when the shared admission authority is unavailable.
    async fn acquire(&self, origin: &str, spacing: Duration) -> Result<Box<dyn OriginPermit>, StoreError> {
        let mut permit = self.reserve(origin).await?;
        permit.start(spacing).await?;
        Ok(permit)
    }
}
