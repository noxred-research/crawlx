//! In-memory vault for the content of zero-data-retention agent runs.
//!
//! A ZDR run never writes prompt, result or step content to the durable store: the job row keeps
//! status and billing metadata only. The result envelope is held here until the job's `expiresAt`
//! (24 hours) and then dropped; a lookup after that (or after a restart) finds nothing, which the
//! status route answers as `410 zdr_expired`. Time comes from the caller (the API clock).

use crawlx_core::{TenantId, Timestamp};
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

/// Most envelopes held at once; the one expiring first is dropped beyond it.
pub const MAX_ENTRIES: usize = 4096;

#[derive(Debug)]
struct Entry {
    tenant: TenantId,
    expires_at: Timestamp,
    envelope: Value,
}

/// Result envelopes of ZDR agent runs by job id.
#[derive(Debug, Default)]
pub struct ZdrVault {
    entries: Mutex<BTreeMap<Uuid, Entry>>,
}

impl ZdrVault {
    /// An empty vault.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Keep `envelope` of job `id` until `expires_at`, dropping entries expired at `now` first and
    /// the soonest-to-expire one when the vault is full.
    pub fn put(&self, tenant: TenantId, id: Uuid, envelope: Value, expires_at: Timestamp, now: Timestamp) {
        let mut entries = self.entries.lock();
        entries.retain(|_, e| e.expires_at > now);
        while entries.len() >= MAX_ENTRIES {
            let oldest = entries.iter().min_by_key(|(_, e)| e.expires_at).map(|(k, _)| *k);
            match oldest {
                Some(k) => entries.remove(&k),
                None => break,
            };
        }
        entries.insert(
            id,
            Entry {
                tenant,
                expires_at,
                envelope,
            },
        );
    }

    /// The envelope of job `id` of `tenant`, `None` once expired or never stored. An expired
    /// entry is removed by the lookup.
    #[must_use]
    pub fn get(&self, tenant: TenantId, id: Uuid, now: Timestamp) -> Option<Value> {
        let mut entries = self.entries.lock();
        match entries.get(&id) {
            Some(e) if e.tenant == tenant && e.expires_at > now => Some(e.envelope.clone()),
            Some(e) if e.expires_at <= now => {
                entries.remove(&id);
                None
            }
            _ => None,
        }
    }

    /// Number of envelopes held (expired ones included until the next write or lookup).
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.lock().len()
    }

    /// Whether the vault holds nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.lock().is_empty()
    }
}
