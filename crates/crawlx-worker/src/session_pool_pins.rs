//! Durable egress observation checks subordinate to the scheduler's real session lease.

use crate::durable::DurableStore;
use crawlx_core::hash::Digest;
use crawlx_core::TenantId;
use crawlx_fetch::proxyx::{PoolPinAuthority, ProxyxError};
use crawlx_storage::SessionLease;
use std::sync::Arc;

struct SessionPoolPins {
    store: DurableStore,
    lease: SessionLease,
    tenant: TenantId,
    generation: u64,
}

/// Capture the existing owner lease; this adapter never mints or renews authority.
pub(crate) fn authority(
    store: DurableStore,
    lease: SessionLease,
    tenant: TenantId,
    generation: u64,
) -> Arc<dyn PoolPinAuthority> {
    Arc::new(SessionPoolPins {
        store,
        lease,
        tenant,
        generation,
    })
}

#[async_trait::async_trait]
impl PoolPinAuthority for SessionPoolPins {
    async fn verify_or_bind(&self, pin: Digest) -> Result<(), ProxyxError> {
        crate::on_store!(&self.store, store => {
            store
                .check_session_egress_pin(&self.lease, self.tenant, self.generation, pin)
                .await
                .map_err(|source| ProxyxError::PinAuthority(Arc::new(source)))
        })
    }
}
