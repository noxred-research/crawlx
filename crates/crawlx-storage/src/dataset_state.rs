//! Bounded metadata-only transaction patches for MemoryStore. No whole-state clones.

use super::*;
use crawlx_core::ActionId;
use std::collections::BTreeMap;

type Namespace = (CrawlRunId, String);
type ItemIdentity = (i64, Option<ActionId>, String, String);
type KvKey = (CrawlRunId, String, String);

#[derive(Default)]
pub(crate) struct MemoryDataset {
    pub(crate) rows: BTreeMap<u64, DatasetItemV1>,
    identities: BTreeMap<ItemIdentity, u64>,
    bytes: u64,
    next_ordinal: u64,
}
#[derive(Clone)]
pub(crate) struct MemoryDelivery {
    pub(crate) receipt: DurableDeliveryOutboxV1,
    pub(crate) lease_expires: Option<Timestamp>,
    pub(crate) not_before: Timestamp,
    pub(crate) erased: bool,
}
#[derive(Clone, Copy, Default)]
struct KvUsage {
    keys: u64,
    bytes: u64,
}

/// Existing MemoryStore mutex owns these indexed metadata records.
#[derive(Default)]
pub(crate) struct DatasetState {
    pub(crate) items: BTreeMap<Namespace, MemoryDataset>,
    pub(crate) kv: BTreeMap<KvKey, KvValueV1>,
    pub(crate) deliveries: BTreeMap<i64, MemoryDelivery>,
    kv_usage: BTreeMap<Namespace, KvUsage>,
    pub(crate) dropped_kv: std::collections::BTreeSet<Namespace>,
    delivery_keys: BTreeMap<(CrawlRunId, String, String), i64>,
    next_delivery: i64,
}
impl DatasetState {
    pub(crate) fn purge_run(&mut self, run: CrawlRunId) {
        self.items.retain(|(owner, _), _| *owner != run);
        self.kv.retain(|(owner, _, _), _| *owner != run);
        self.kv_usage.retain(|(owner, _), _| *owner != run);
        self.dropped_kv.retain(|(owner, _)| *owner != run);
        self.deliveries.retain(|_, row| row.receipt.run != run);
        self.delivery_keys.retain(|(owner, _, _), _| *owner != run);
    }
    pub(crate) fn drop_kv(&mut self, run: CrawlRunId, store: &str) {
        self.dropped_kv.insert((run, store.to_owned()));
        self.kv
            .retain(|(owner, name, _), _| *owner != run || name != store);
        self.kv_usage.remove(&(run, store.to_owned()));
    }
}

#[derive(Default)]
struct DatasetPatch {
    rows: BTreeMap<u64, DatasetItemV1>,
    identities: BTreeMap<ItemIdentity, u64>,
    bytes: u64,
    next_ordinal: u64,
}
/// Fully validated bounded write set. Applying it cannot produce a storage error.
pub(crate) struct PreparedDatasetDelta {
    datasets: BTreeMap<Namespace, DatasetPatch>,
    kv: BTreeMap<KvKey, KvValueV1>,
    kv_usage: BTreeMap<Namespace, KvUsage>,
    deliveries: Vec<(i64, MemoryDelivery)>,
    next_delivery: i64,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_memory(
    state: &DatasetState,
    run: &CrawlRun,
    request: i64,
    accepted: &[AcceptedBatchV1],
    deltas: &[KvCasV1],
    outbox: &[DeliveryBatchV1],
    now: Timestamp,
) -> Result<PreparedDatasetDelta, StoreError> {
    prepare(state, run, request, None, accepted, deltas, outbox, now)
}
#[allow(clippy::too_many_arguments)]
pub(crate) fn prepare_memory_action(
    state: &DatasetState,
    run: &CrawlRun,
    action: ActionId,
    accepted: &[AcceptedBatchV1],
    deltas: &[KvCasV1],
    outbox: &[DeliveryBatchV1],
    now: Timestamp,
) -> Result<PreparedDatasetDelta, StoreError> {
    prepare(state, run, 0, Some(action), accepted, deltas, outbox, now)
}

fn identity(request: i64, action: Option<ActionId>, item: &AcceptedItemV1) -> ItemIdentity {
    (
        request,
        action,
        item.item_key.clone(),
        item.transform_version.clone(),
    )
}
fn lookup<'a>(
    state: &'a DatasetState,
    patch: &'a PreparedDatasetDelta,
    namespace: &Namespace,
    ordinal: u64,
) -> Option<&'a DatasetItemV1> {
    patch
        .datasets
        .get(namespace)
        .and_then(|dataset| dataset.rows.get(&ordinal))
        .or_else(|| {
            state
                .items
                .get(namespace)
                .and_then(|dataset| dataset.rows.get(&ordinal))
        })
}

#[allow(clippy::too_many_arguments)]
fn prepare(
    state: &DatasetState,
    run: &CrawlRun,
    request: i64,
    action: Option<ActionId>,
    accepted: &[AcceptedBatchV1],
    deltas: &[KvCasV1],
    outbox: &[DeliveryBatchV1],
    now: Timestamp,
) -> Result<PreparedDatasetDelta, StoreError> {
    let config = &run.config.datasets;
    config.validate()?;
    let zdr = run.config.retention.mode == RetentionMode::Zdr;
    let count = accepted.iter().try_fold(0usize, |count, batch| {
        count
            .checked_add(batch.items.len())
            .ok_or_else(|| conflict("accepted item batch overflow"))
    })?;
    if accepted.len() > 64
        || count > MAX_BATCH_ITEMS
        || deltas.len() > MAX_BATCH_ITEMS
        || outbox.len() > MAX_BATCH_ITEMS
    {
        return Err(conflict("dataset transaction batch limit"));
    }
    let mut patch = PreparedDatasetDelta {
        datasets: BTreeMap::new(),
        kv: BTreeMap::new(),
        kv_usage: BTreeMap::new(),
        deliveries: Vec::new(),
        next_delivery: state.next_delivery,
    };
    let mut source_ordinals: BTreeMap<Namespace, Vec<u64>> = BTreeMap::new();
    for batch in accepted {
        validate_identifier(&batch.dataset)?;
        let declaration = config
            .stores
            .iter()
            .find(|store| store.name == batch.dataset)
            .ok_or_else(|| conflict("undeclared dataset namespace"))?;
        let namespace = (run.id, batch.dataset.clone());
        let original = state.items.get(&namespace);
        let dataset = patch
            .datasets
            .entry(namespace.clone())
            .or_insert_with(|| DatasetPatch {
                rows: BTreeMap::new(),
                identities: BTreeMap::new(),
                bytes: original.map_or(0, |dataset| dataset.bytes),
                next_ordinal: original.map_or(1, |dataset| dataset.next_ordinal.max(1)),
            });
        for item in &batch.items {
            item_valid(item, zdr, now)?;
            if item.schema_version != declaration.schema_version {
                return Err(conflict("dataset schema mismatch"));
            }
            let key = identity(request, action, item);
            if let Some(ordinal) = dataset
                .identities
                .get(&key)
                .or_else(|| original.and_then(|dataset| dataset.identities.get(&key)))
            {
                let row = dataset
                    .rows
                    .get(ordinal)
                    .or_else(|| original.and_then(|dataset| dataset.rows.get(ordinal)))
                    .ok_or_else(|| StoreError::Backend("dataset identity index inconsistent".into()))?;
                if row.item != *item {
                    return Err(conflict("accepted item identity changed"));
                }
                source_ordinals
                    .entry(namespace.clone())
                    .or_default()
                    .push(*ordinal);
                continue;
            }
            let ordinal = dataset.next_ordinal;
            let bytes = dataset
                .bytes
                .checked_add(item.size_bytes)
                .ok_or_else(|| conflict("dataset byte counter overflow"))?;
            if ordinal > declaration.max_items || bytes > declaration.max_bytes {
                return Err(conflict("dataset quota exhausted"));
            }
            dataset.next_ordinal = ordinal
                .checked_add(1)
                .ok_or_else(|| conflict("dataset ordinal overflow"))?;
            dataset.bytes = bytes;
            let mut row = DatasetItemV1::new(ordinal, request, item.clone());
            row.source_action = action;
            dataset.rows.insert(ordinal, row);
            dataset.identities.insert(key, ordinal);
            source_ordinals
                .entry(namespace.clone())
                .or_default()
                .push(ordinal);
        }
    }
    for delta in deltas {
        delta_valid(delta, config, zdr, now)?;
        if state.dropped_kv.contains(&(run.id, delta.store.clone())) {
            return Err(conflict("kv namespace dropped"));
        }
        let key = (run.id, delta.store.clone(), delta.key.clone());
        let old = patch.kv.get(&key).or_else(|| state.kv.get(&key));
        if old.map_or(0, |row| row.version) != delta.expected_version {
            return Err(conflict("kv compare-and-set collision"));
        }
        if old.is_some_and(|row| row.value.expires_at.is_some_and(|end| end <= now)) {
            return Err(expired());
        }
        if old.is_some_and(|row| row.value.expires_at != delta.expires_at) {
            return Err(conflict("kv expiry is immutable"));
        }
        let declaration = config
            .kv_stores
            .iter()
            .find(|store| store.name == delta.store)
            .ok_or_else(|| conflict("undeclared kv namespace"))?;
        let namespace = (run.id, delta.store.clone());
        let usage = patch
            .kv_usage
            .entry(namespace.clone())
            .or_insert_with(|| state.kv_usage.get(&namespace).copied().unwrap_or_default());
        let old_bytes = old.map_or(0, |row| row.value.size_bytes);
        usage.bytes = usage
            .bytes
            .checked_sub(old_bytes)
            .and_then(|bytes| bytes.checked_add(delta.size_bytes))
            .ok_or_else(|| conflict("kv byte counter overflow"))?;
        if old.is_none() {
            usage.keys = usage
                .keys
                .checked_add(1)
                .ok_or_else(|| conflict("kv key counter overflow"))?;
        }
        if usage.keys > u64::from(declaration.max_keys) || usage.bytes > declaration.max_bytes {
            return Err(conflict("kv quota exhausted"));
        }
        let version = delta
            .expected_version
            .checked_add(1)
            .ok_or_else(|| conflict("kv version overflow"))?;
        patch.kv.insert(key, KvValueV1::new(version, delta.clone()));
    }
    let mut new_keys = BTreeMap::new();
    for candidate in outbox {
        let feed = config
            .feeds
            .iter()
            .find(|feed| feed.id == candidate.feed)
            .ok_or_else(|| conflict("undeclared delivery feed"))?;
        let namespace = (run.id, feed.source.clone());
        let mut batch = candidate.clone();
        if matches!(batch.range, DeliveryRangeV1::AcceptedRequest) {
            let ordinals = source_ordinals
                .get_mut(&namespace)
                .ok_or_else(|| conflict("delivery source not accepted in this transaction"))?;
            ordinals.sort_unstable();
            ordinals.dedup();
            let first = *ordinals
                .first()
                .ok_or_else(|| conflict("delivery source empty"))?;
            let last = *ordinals.last().ok_or_else(|| conflict("delivery source empty"))?;
            if last.checked_sub(first).and_then(|count| count.checked_add(1))
                != u64::try_from(ordinals.len()).ok()
            {
                return Err(conflict("delivery source range is not contiguous"));
            }
            batch.range = DeliveryRangeV1::Committed { first, last };
        }
        delivery_valid(&batch, config, zdr, now)?;
        let (first, last) = match batch.range {
            DeliveryRangeV1::Committed { first, last } => (first, last),
            _ => return Err(conflict("delivery source range unresolved")),
        };
        for ordinal in first..=last {
            let row = lookup(state, &patch, &namespace, ordinal)
                .ok_or_else(|| conflict("delivery references uncommitted items"))?;
            if row.item.expires_at.is_some_and(|end| end <= now) {
                return Err(expired());
            }
        }
        let key = (run.id, batch.feed.clone(), batch.idempotency_key.clone());
        if let Some(id) = state.delivery_keys.get(&key).or_else(|| new_keys.get(&key)) {
            let old = state
                .deliveries
                .get(id)
                .or_else(|| {
                    patch
                        .deliveries
                        .iter()
                        .find(|(candidate, _)| candidate == id)
                        .map(|(_, row)| row)
                })
                .ok_or_else(|| StoreError::Backend("delivery identity index inconsistent".into()))?;
            if old.receipt.batch != batch {
                return Err(conflict("delivery identity changed"));
            }
            continue;
        }
        patch.next_delivery = patch
            .next_delivery
            .checked_add(1)
            .ok_or_else(|| conflict("delivery id overflow"))?;
        let id = patch.next_delivery;
        new_keys.insert(key, id);
        patch.deliveries.push((
            id,
            MemoryDelivery {
                receipt: DurableDeliveryOutboxV1::pending(id, run.id, batch),
                lease_expires: None,
                not_before: now,
                erased: false,
            },
        ));
    }
    Ok(patch)
}

pub(crate) fn apply_prepared(state: &mut DatasetState, patch: PreparedDatasetDelta) {
    for (namespace, patch) in patch.datasets {
        let dataset = state.items.entry(namespace).or_default();
        dataset.rows.extend(patch.rows);
        dataset.identities.extend(patch.identities);
        dataset.bytes = patch.bytes;
        dataset.next_ordinal = patch.next_ordinal;
    }
    state.kv.extend(patch.kv);
    state.kv_usage.extend(patch.kv_usage);
    for (id, row) in patch.deliveries {
        state.delivery_keys.insert(
            (
                row.receipt.run,
                row.receipt.batch.feed.clone(),
                row.receipt.batch.idempotency_key.clone(),
            ),
            id,
        );
        state.deliveries.insert(id, row);
    }
    state.next_delivery = patch.next_delivery;
}
