//! Durable egress observation checks subordinate to the scheduler's real session lease.

use crawlx_core::hash::Digest;
use crawlx_core::TenantId;
use crawlx_fetch::proxyx::{PoolPinAuthority, ProxyxError};
use crawlx_storage::{Pg, SessionLease};
use std::sync::Arc;

struct SessionPoolPins {
    pg: Pg,
    lease: SessionLease,
    tenant: TenantId,
    generation: u64,
}

/// Capture the existing owner lease; this adapter never mints or renews authority.
pub(crate) fn authority(
    pg: Pg,
    lease: SessionLease,
    tenant: TenantId,
    generation: u64,
) -> Arc<dyn PoolPinAuthority> {
    Arc::new(SessionPoolPins {
        pg,
        lease,
        tenant,
        generation,
    })
}

#[async_trait::async_trait]
impl PoolPinAuthority for SessionPoolPins {
    async fn verify_or_bind(&self, pin: Digest) -> Result<(), ProxyxError> {
        self.pg
            .check_session_egress_pin(&self.lease, self.tenant, self.generation, pin)
            .await
            .map_err(|source| ProxyxError::PinAuthority(Arc::new(source)))
    }
}
