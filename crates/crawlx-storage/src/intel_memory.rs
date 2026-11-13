//! In-memory [`IntelRepo`] for tests and the in-memory API.
//!
//! [`MemoryIntel`] keeps every table of migration `0016_intel.sql` in `BTreeMap`s behind one
//! mutex and follows the same rules as the PostgreSQL implementation: tenant filtering (a row of
//! another tenant is absent), the orderings and cursors of the trait, the terminal-status rule of
//! [`JobPatch`], the claim lease of [`IntelRepo::monitor_claim_due`], cascade deletes and
//! [`IntelRepo::purge_expired`]. Foreign keys of the schema surface as
//! [`StoreError::Conflict`] (a check for an unknown monitor, pages for an unknown check, baselines
//! for an unknown monitor) or [`StoreError::NotFound`] where the trait says so (trace and
//! snapshots of an unknown job). The tenant foreign key is not modelled: the in-memory API has no
//! tenant table. No method awaits while the lock is held.

use crate::intel::{
    Baseline, CheckPage, CheckRecord, IntelRepo, IntelResult, JobCount, JobKind, JobPatch, JobRecord,
    JobStatus, MonitorRecord, MonitorStatus, PurgeReport, Snapshot, ThreadRecord, TraceEvent, UsageDay,
    UsageEvent, UsageTotals,
};
use async_trait::async_trait;
use crawlx_core::{StoreError, TenantId, Timestamp};
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Default)]
struct State {
    jobs: BTreeMap<Uuid, JobRecord>,
    /// Events per job, in sequence order (`seq == index + 1`).
    trace: BTreeMap<Uuid, Vec<TraceEvent>>,
    /// Snapshots per job in creation order; a replacement keeps its position.
    snapshots: BTreeMap<Uuid, Vec<Snapshot>>,
    threads: BTreeMap<Uuid, ThreadRecord>,
    monitors: BTreeMap<Uuid, MonitorRecord>,
    checks: BTreeMap<Uuid, CheckRecord>,
    /// Keyed `(check, target_id, url)`: byte order, like `COLLATE "C"`.
    pages: BTreeMap<(Uuid, String, String), CheckPage>,
    /// Keyed `(monitor, url)`.
    baselines: BTreeMap<(Uuid, String), Baseline>,
    /// Insertion order breaks ties between rows with the same `at`.
    usage: Vec<UsageEvent>,
    settings: BTreeMap<(TenantId, String), Value>,
}

/// In-memory [`IntelRepo`]; see the module docs for what it mirrors.
#[derive(Debug, Default)]
pub struct MemoryIntel {
    state: Mutex<State>,
}

impl MemoryIntel {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

fn count_to_u64(n: usize) -> IntelResult<u64> {
    u64::try_from(n).map_err(|_| StoreError::Serialization("count out of range".to_owned()))
}

fn to_usize(n: u32) -> usize {
    usize::try_from(n).unwrap_or(usize::MAX)
}

fn not_found(entity: &'static str, id: impl std::fmt::Display) -> StoreError {
    StoreError::NotFound {
        entity,
        id: id.to_string(),
    }
}

fn add_usage(totals: &mut UsageTotals, e: &UsageEvent) {
    totals.credits = totals.credits.saturating_add(e.credits);
    totals.prompt_tokens = totals.prompt_tokens.saturating_add(e.prompt_tokens);
    totals.completion_tokens = totals.completion_tokens.saturating_add(e.completion_tokens);
    totals.events = totals.events.saturating_add(1);
}

#[async_trait]
impl IntelRepo for MemoryIntel {
    async fn job_insert(&self, job: &JobRecord) -> IntelResult<()> {
        let mut s = self.state.lock();
        if s.jobs.contains_key(&job.id) {
            return Err(StoreError::Conflict(format!("job {} exists", job.id)));
        }
        s.jobs.insert(job.id, job.clone());
        Ok(())
    }

    async fn job_get(&self, tenant: TenantId, id: Uuid) -> IntelResult<Option<JobRecord>> {
        Ok(self
            .state
            .lock()
            .jobs
            .get(&id)
            .filter(|j| j.tenant == tenant)
            .cloned())
    }

    async fn job_update(
        &self,
        tenant: TenantId,
        id: Uuid,
        patch: &JobPatch,
    ) -> IntelResult<Option<JobRecord>> {
        let mut s = self.state.lock();
        let Some(job) = s.jobs.get_mut(&id).filter(|j| j.tenant == tenant) else {
            return Ok(None);
        };
        job.updated_at = patch.at;
        if !job.status.is_terminal() {
            if let Some(status) = patch.status {
                job.status = status;
            }
            if let Some(result) = &patch.result {
                job.result = Some(result.clone());
            }
            if let Some(error) = &patch.error {
                job.error = Some(error.clone());
            }
            if let Some(reason) = &patch.stop_reason {
                job.stop_reason = Some(reason.clone());
            }
            if let Some(at) = patch.finished_at {
                job.finished_at = Some(at);
            }
        }
        if let Some(tokens) = patch.tokens_used {
            job.tokens_used = tokens;
        }
        if let Some(credits) = patch.credits_used {
            job.credits_used = credits;
        }
        Ok(Some(job.clone()))
    }

    async fn job_list(
        &self,
        tenant: TenantId,
        kind: Option<JobKind>,
        limit: u32,
        after: Option<(Timestamp, Uuid)>,
    ) -> IntelResult<Vec<JobRecord>> {
        let s = self.state.lock();
        let mut rows: Vec<&JobRecord> = s
            .jobs
            .values()
            .filter(|j| {
                j.tenant == tenant
                    && kind.is_none_or(|k| j.kind == k)
                    && after.is_none_or(|cursor| (j.created_at, j.id) < cursor)
            })
            .collect();
        rows.sort_by_key(|r| std::cmp::Reverse((r.created_at, r.id)));
        Ok(rows.into_iter().take(to_usize(limit)).cloned().collect())
    }

    async fn job_counts(&self, tenant: TenantId) -> IntelResult<Vec<JobCount>> {
        let s = self.state.lock();
        let mut counts: BTreeMap<(JobKind, JobStatus), u64> = BTreeMap::new();
        for job in s.jobs.values().filter(|j| j.tenant == tenant) {
            let n = counts.entry((job.kind, job.status)).or_insert(0);
            *n = n.saturating_add(1);
        }
        Ok(counts
            .into_iter()
            .map(|((kind, status), count)| JobCount { kind, status, count })
            .collect())
    }

    async fn trace_append(&self, job: Uuid, kind: &str, data: Value, at: Timestamp) -> IntelResult<u64> {
        let mut s = self.state.lock();
        if !s.jobs.contains_key(&job) {
            return Err(not_found("job", job));
        }
        let events = s.trace.entry(job).or_default();
        let seq = count_to_u64(events.len())?.saturating_add(1);
        events.push(TraceEvent {
            job,
            seq,
            kind: kind.to_owned(),
            data,
            at,
        });
        Ok(seq)
    }

    async fn trace_list(&self, job: Uuid, after: u64, limit: u32) -> IntelResult<Vec<TraceEvent>> {
        let s = self.state.lock();
        Ok(s.trace
            .get(&job)
            .map(|events| {
                events
                    .iter()
                    .filter(|e| e.seq > after)
                    .take(to_usize(limit))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn snapshot_put(&self, job: Uuid, id: &str, data: Value, at: Timestamp) -> IntelResult<()> {
        let mut s = self.state.lock();
        if !s.jobs.contains_key(&job) {
            return Err(not_found("job", job));
        }
        let snapshots = s.snapshots.entry(job).or_default();
        match snapshots.iter_mut().find(|snap| snap.id == id) {
            Some(existing) => {
                existing.data = data;
                existing.created_at = at;
            }
            None => snapshots.push(Snapshot {
                job,
                id: id.to_owned(),
                data,
                created_at: at,
            }),
        }
        Ok(())
    }

    async fn snapshot_get(&self, job: Uuid, id: &str) -> IntelResult<Option<Snapshot>> {
        let s = self.state.lock();
        Ok(s.snapshots
            .get(&job)
            .and_then(|snapshots| snapshots.iter().find(|snap| snap.id == id))
            .cloned())
    }

    async fn snapshot_ids(&self, job: Uuid) -> IntelResult<Vec<String>> {
        let s = self.state.lock();
        Ok(s.snapshots
            .get(&job)
            .map(|snapshots| snapshots.iter().map(|snap| snap.id.clone()).collect())
            .unwrap_or_default())
    }

    async fn thread_get(&self, tenant: TenantId, id: Uuid) -> IntelResult<Option<ThreadRecord>> {
        Ok(self
            .state
            .lock()
            .threads
            .get(&id)
            .filter(|t| t.tenant == tenant)
            .cloned())
    }

    async fn thread_put(&self, tenant: TenantId, id: Uuid, state: Value, at: Timestamp) -> IntelResult<()> {
        let mut s = self.state.lock();
        match s.threads.get_mut(&id) {
            Some(existing) if existing.tenant != tenant => Err(StoreError::Conflict(format!(
                "thread {id} belongs to another tenant"
            ))),
            Some(existing) => {
                existing.state = state;
                existing.updated_at = at;
                Ok(())
            }
            None => {
                s.threads.insert(
                    id,
                    ThreadRecord {
                        id,
                        tenant,
                        state,
                        created_at: at,
                        updated_at: at,
                    },
                );
                Ok(())
            }
        }
    }

    async fn monitor_insert(&self, m: &MonitorRecord) -> IntelResult<()> {
        let mut s = self.state.lock();
        if s.monitors.contains_key(&m.id) {
            return Err(StoreError::Conflict(format!("monitor {} exists", m.id)));
        }
        s.monitors.insert(m.id, m.clone());
        Ok(())
    }

    async fn monitor_update(&self, m: &MonitorRecord) -> IntelResult<bool> {
        let mut s = self.state.lock();
        let Some(stored) = s
            .monitors
            .get_mut(&m.id)
            .filter(|stored| stored.tenant == m.tenant)
        else {
            return Ok(false);
        };
        // Scheduling state (`last_run_at`, `last_check_id`, `claimed_until`) belongs to
        // `monitor_claim_due` / `monitor_finish_run`: a PATCH that read the row before a claim
        // must not release the lease.
        stored.name.clone_from(&m.name);
        stored.status = m.status;
        stored.schedule.clone_from(&m.schedule);
        stored.cron.clone_from(&m.cron);
        stored.timezone.clone_from(&m.timezone);
        stored.goal.clone_from(&m.goal);
        stored.targets.clone_from(&m.targets);
        stored.retention_days = m.retention_days;
        stored.webhook.clone_from(&m.webhook);
        stored.notification.clone_from(&m.notification);
        stored.next_run_at = m.next_run_at;
        stored.updated_at = m.updated_at;
        Ok(true)
    }

    async fn monitor_get(&self, tenant: TenantId, id: Uuid) -> IntelResult<Option<MonitorRecord>> {
        Ok(self
            .state
            .lock()
            .monitors
            .get(&id)
            .filter(|m| m.tenant == tenant)
            .cloned())
    }

    async fn monitor_list(
        &self,
        tenant: TenantId,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<MonitorRecord>> {
        let s = self.state.lock();
        let mut rows: Vec<&MonitorRecord> = s.monitors.values().filter(|m| m.tenant == tenant).collect();
        rows.sort_by_key(|r| std::cmp::Reverse((r.created_at, r.id)));
        Ok(rows
            .into_iter()
            .skip(to_usize(offset))
            .take(to_usize(limit))
            .cloned()
            .collect())
    }

    async fn monitor_count(&self, tenant: TenantId) -> IntelResult<u64> {
        count_to_u64(
            self.state
                .lock()
                .monitors
                .values()
                .filter(|m| m.tenant == tenant)
                .count(),
        )
    }

    async fn monitor_delete(&self, tenant: TenantId, id: Uuid) -> IntelResult<bool> {
        let mut s = self.state.lock();
        if !s.monitors.get(&id).is_some_and(|m| m.tenant == tenant) {
            return Ok(false);
        }
        s.monitors.remove(&id);
        s.checks.retain(|_, c| c.monitor != id);
        let State { checks, pages, .. } = &mut *s;
        pages.retain(|(check, _, _), _| checks.contains_key(check));
        s.baselines.retain(|(monitor, _), _| *monitor != id);
        Ok(true)
    }

    async fn monitor_claim_due(
        &self,
        now: Timestamp,
        lease_until: Timestamp,
        limit: u32,
    ) -> IntelResult<Vec<MonitorRecord>> {
        let mut s = self.state.lock();
        let mut due: Vec<(Timestamp, Uuid)> = s
            .monitors
            .values()
            .filter(|m| {
                m.status == MonitorStatus::Active
                    && m.next_run_at.is_some_and(|at| at <= now)
                    && m.claimed_until.is_none_or(|until| until <= now)
            })
            .filter_map(|m| m.next_run_at.map(|at| (at, m.id)))
            .collect();
        due.sort_unstable();
        due.truncate(to_usize(limit));
        let mut claimed = Vec::with_capacity(due.len());
        for (_, id) in due {
            if let Some(m) = s.monitors.get_mut(&id) {
                m.claimed_until = Some(lease_until);
                claimed.push(m.clone());
            }
        }
        Ok(claimed)
    }

    async fn monitor_finish_run(
        &self,
        tenant: TenantId,
        id: Uuid,
        last_run_at: Timestamp,
        last_check_id: Uuid,
        next_run_at: Option<Timestamp>,
    ) -> IntelResult<()> {
        let mut s = self.state.lock();
        if let Some(m) = s.monitors.get_mut(&id).filter(|m| m.tenant == tenant) {
            m.last_run_at = Some(last_run_at);
            m.last_check_id = Some(last_check_id);
            m.next_run_at = next_run_at;
            m.claimed_until = None;
        }
        Ok(())
    }

    async fn check_insert(&self, c: &CheckRecord) -> IntelResult<()> {
        let mut s = self.state.lock();
        if s.checks.contains_key(&c.id) {
            return Err(StoreError::Conflict(format!("check {} exists", c.id)));
        }
        if !s.monitors.get(&c.monitor).is_some_and(|m| m.tenant == c.tenant) {
            return Err(StoreError::Conflict(format!(
                "monitor {} does not exist for the check's tenant",
                c.monitor
            )));
        }
        s.checks.insert(c.id, c.clone());
        Ok(())
    }

    async fn check_update(&self, c: &CheckRecord) -> IntelResult<bool> {
        let mut s = self.state.lock();
        let Some(stored) = s
            .checks
            .get_mut(&c.id)
            .filter(|stored| stored.tenant == c.tenant && stored.monitor == c.monitor)
        else {
            return Ok(false);
        };
        stored.state = c.state;
        stored.status.clone_from(&c.status);
        stored.summary.clone_from(&c.summary);
        stored.error.clone_from(&c.error);
        stored.finished_at = c.finished_at;
        Ok(true)
    }

    async fn check_get(&self, tenant: TenantId, monitor: Uuid, id: Uuid) -> IntelResult<Option<CheckRecord>> {
        Ok(self
            .state
            .lock()
            .checks
            .get(&id)
            .filter(|c| c.tenant == tenant && c.monitor == monitor)
            .cloned())
    }

    async fn check_list(
        &self,
        tenant: TenantId,
        monitor: Uuid,
        status: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<CheckRecord>> {
        let s = self.state.lock();
        let mut rows: Vec<&CheckRecord> = s
            .checks
            .values()
            .filter(|c| {
                c.tenant == tenant
                    && c.monitor == monitor
                    && status.is_none_or(|want| c.status.as_deref() == Some(want))
            })
            .collect();
        rows.sort_by_key(|r| std::cmp::Reverse((r.started_at, r.id)));
        Ok(rows
            .into_iter()
            .skip(to_usize(offset))
            .take(to_usize(limit))
            .cloned()
            .collect())
    }

    async fn check_pages_put(&self, pages: &[CheckPage]) -> IntelResult<()> {
        let mut s = self.state.lock();
        if let Some(missing) = pages.iter().find(|p| !s.checks.contains_key(&p.check)) {
            return Err(StoreError::Conflict(format!(
                "check {} does not exist",
                missing.check
            )));
        }
        for page in pages {
            s.pages.insert(
                (page.check, page.target_id.clone(), page.url.clone()),
                page.clone(),
            );
        }
        Ok(())
    }

    async fn check_pages(
        &self,
        check: Uuid,
        status: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<CheckPage>> {
        let s = self.state.lock();
        Ok(s.pages
            .range((check, String::new(), String::new())..)
            .take_while(|((c, _, _), _)| *c == check)
            .map(|(_, page)| page)
            .filter(|page| status.is_none_or(|want| page.status == want))
            .skip(to_usize(offset))
            .take(to_usize(limit))
            .cloned()
            .collect())
    }

    async fn baselines(&self, monitor: Uuid) -> IntelResult<Vec<Baseline>> {
        let s = self.state.lock();
        Ok(s.baselines
            .range((monitor, String::new())..)
            .take_while(|((m, _), _)| *m == monitor)
            .map(|(_, b)| b.clone())
            .collect())
    }

    async fn baselines_put(&self, rows: &[Baseline]) -> IntelResult<()> {
        let mut s = self.state.lock();
        if let Some(missing) = rows.iter().find(|b| !s.monitors.contains_key(&b.monitor)) {
            return Err(StoreError::Conflict(format!(
                "monitor {} does not exist",
                missing.monitor
            )));
        }
        for row in rows {
            s.baselines.insert((row.monitor, row.url.clone()), row.clone());
        }
        Ok(())
    }

    async fn baselines_remove(&self, monitor: Uuid, urls: &[String]) -> IntelResult<()> {
        let mut s = self.state.lock();
        for url in urls {
            s.baselines.remove(&(monitor, url.clone()));
        }
        Ok(())
    }

    async fn usage_record(&self, e: &UsageEvent) -> IntelResult<()> {
        self.state.lock().usage.push(e.clone());
        Ok(())
    }

    async fn usage_totals(
        &self,
        tenant: TenantId,
        from: Timestamp,
        to: Timestamp,
    ) -> IntelResult<UsageTotals> {
        let s = self.state.lock();
        let mut totals = UsageTotals::default();
        for e in s
            .usage
            .iter()
            .filter(|e| e.tenant == tenant && e.at >= from && e.at < to)
        {
            add_usage(&mut totals, e);
        }
        Ok(totals)
    }

    async fn usage_by_day(
        &self,
        tenant: TenantId,
        from: Timestamp,
        to: Timestamp,
    ) -> IntelResult<Vec<UsageDay>> {
        let s = self.state.lock();
        let mut days: BTreeMap<String, UsageTotals> = BTreeMap::new();
        for e in s
            .usage
            .iter()
            .filter(|e| e.tenant == tenant && e.at >= from && e.at < to)
        {
            add_usage(days.entry(e.at.format("%Y-%m-%d").to_string()).or_default(), e);
        }
        Ok(days
            .into_iter()
            .map(|(day, totals)| UsageDay { day, totals })
            .collect())
    }

    async fn usage_recent(
        &self,
        tenant: TenantId,
        endpoint: Option<&str>,
        limit: u32,
        offset: u32,
    ) -> IntelResult<Vec<UsageEvent>> {
        let s = self.state.lock();
        let mut rows: Vec<(usize, &UsageEvent)> = s
            .usage
            .iter()
            .enumerate()
            .filter(|(_, e)| e.tenant == tenant && endpoint.is_none_or(|want| e.endpoint == want))
            .collect();
        rows.sort_by_key(|(i, r)| std::cmp::Reverse((r.at, *i)));
        Ok(rows
            .into_iter()
            .skip(to_usize(offset))
            .take(to_usize(limit))
            .map(|(_, e)| e.clone())
            .collect())
    }

    async fn usage_by_ref(&self, tenant: TenantId, ref_id: Uuid) -> IntelResult<Option<UsageEvent>> {
        let s = self.state.lock();
        Ok(s.usage
            .iter()
            .enumerate()
            .filter(|(_, e)| e.tenant == tenant && e.ref_id == Some(ref_id))
            .max_by_key(|(i, e)| (e.at, *i))
            .map(|(_, e)| e.clone()))
    }

    async fn setting_get(&self, tenant: TenantId, key: &str) -> IntelResult<Option<Value>> {
        Ok(self.state.lock().settings.get(&(tenant, key.to_owned())).cloned())
    }

    async fn setting_put(
        &self,
        tenant: TenantId,
        key: &str,
        value: Value,
        _at: Timestamp,
    ) -> IntelResult<()> {
        self.state.lock().settings.insert((tenant, key.to_owned()), value);
        Ok(())
    }

    async fn setting_put_if_absent(
        &self,
        tenant: TenantId,
        key: &str,
        value: Value,
        _at: Timestamp,
    ) -> IntelResult<bool> {
        let mut s = self.state.lock();
        let slot = (tenant, key.to_owned());
        if s.settings.contains_key(&slot) {
            return Ok(false);
        }
        s.settings.insert(slot, value);
        Ok(true)
    }

    async fn setting_delete(&self, tenant: TenantId, key: &str) -> IntelResult<bool> {
        Ok(self
            .state
            .lock()
            .settings
            .remove(&(tenant, key.to_owned()))
            .is_some())
    }

    async fn setting_list_prefix(
        &self,
        tenant: TenantId,
        prefix: &str,
        limit: u32,
    ) -> IntelResult<Vec<(String, Value)>> {
        if prefix.contains(['%', '_', '\\']) {
            return Err(StoreError::Backend(
                "setting prefix must not hold wildcards".to_owned(),
            ));
        }
        let s = self.state.lock();
        Ok(s.settings
            .range((tenant, prefix.to_owned())..)
            .take_while(|((t, k), _)| *t == tenant && k.starts_with(prefix))
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .map(|((_, k), v)| (k.clone(), v.clone()))
            .collect())
    }

    async fn purge_expired(&self, now: Timestamp, usage_before: Timestamp) -> IntelResult<PurgeReport> {
        let mut s = self.state.lock();
        let expired_jobs: Vec<Uuid> = s
            .jobs
            .values()
            .filter(|j| j.expires_at <= now)
            .map(|j| j.id)
            .collect();
        for id in &expired_jobs {
            s.jobs.remove(id);
            s.trace.remove(id);
            s.snapshots.remove(id);
        }
        let expired_checks: Vec<Uuid> = s
            .checks
            .values()
            .filter(|c| c.expires_at <= now)
            .map(|c| c.id)
            .collect();
        for id in &expired_checks {
            s.checks.remove(id);
        }
        let State { checks, pages, .. } = &mut *s;
        pages.retain(|(check, _, _), _| checks.contains_key(check));
        s.usage.retain(|e| e.at >= usage_before);
        Ok(PurgeReport {
            jobs: count_to_u64(expired_jobs.len())?,
            checks: count_to_u64(expired_checks.len())?,
        })
    }
}
