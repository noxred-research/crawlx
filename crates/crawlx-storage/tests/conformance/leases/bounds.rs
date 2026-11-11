#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! The edges of leases: time sentinels and expiry, batches larger than one statement can bind,
//! the atomic outcome under injected statement failures, and two processes sharing one
//! SQLite file.

use super::support::{epoch, lease_all, new_run, open_sibling, sqlite_file, tenant, Raw, V};
use crate::rig::Rig;
use chrono::{DateTime, Duration, TimeZone as _, Utc};
use crawlx_core::counters::ActionStatus;
use crawlx_core::repo::{ActionJournal, FrontierRepo, RunRepo, SessionStatus};
use crawlx_core::{ActionId, CrawlRunId, SessionId, StateClusterId, WorkerId};
use crawlx_storage::backend::{BackendKind, Dialect, MariaDbDialect, PostgresDialect, SqliteDialect};
#[cfg(feature = "chaos")]
use crawlx_storage::testkit::new_state;
use crawlx_storage::testkit::{allow_verdict, canonical_url, proposal, sessions};
use crawlx_storage::{Backend, Database, LeaseRepo, StoreConfig};
use std::collections::BTreeSet;

conformance! { databases:
    session_expiry_sentinels_and_ttl_order_the_claims,
    frontier_expiry_sentinels_order_the_reaper,
    reap_frontier_and_heartbeat_cover_more_rows_than_one_statement_binds,
    reap_covers_more_sessions_than_one_statement_binds,
}

#[cfg(feature = "chaos")]
conformance! { databases:
    every_t2_statement_failing_once_leaves_nothing_behind,
}

/// Instants far from now that every engine represents: the start of the Unix epoch and the
/// year 9000 (inside `DATETIME(6)`, integer microseconds and `timestamptz` alike).
fn long_ago() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(1970, 1, 1, 0, 0, 0).unwrap()
}

fn far_future() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(9000, 1, 1, 0, 0, 0).unwrap()
}

db_case! {
    /// A session that never held a lease has no expiry at all (not a sentinel instant) and is
    /// claimable at once; a live lease keeps the session out of every claim until it runs out
    /// (a short TTL here), an expiry in the distant past or future orders the claim the same
    /// way, and a claim after expiry grants a higher fence.
    async fn session_expiry_sentinels_and_ttl_order_the_claims<B>(rig, store) {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;

        // a fresh session has a NULL expiry and is claimable
        let run = new_run(store, tenant, &["a"], 1).await;
        let slots = sessions(run.id, 1, 1);
        store.create_sessions(&slots).await.unwrap();
        let fresh = raw
            .one(
                "SELECT lease_expires_at, fencing_token FROM crawl_sessions WHERE session_id = $1",
                &[V::Uuid(slots[0].id.0)],
            )
            .await;
        assert_eq!(fresh.opt_ts("lease_expires_at"), None, "no sentinel instant for 'never leased'");
        assert_eq!(fresh.opt_i64("fencing_token"), None);

        // a short TTL: the lease is live for a moment and then claimable again
        let short = open_sibling(
            rig,
            StoreConfig {
                session_ttl: std::time::Duration::from_millis(1500),
                ..StoreConfig::default()
            },
        )
        .await;
        let quick = B::store_of(&short);
        let first = quick
            .claim_session(run.id, WorkerId::new(), true)
            .await
            .unwrap()
            .expect("a never-leased session is claimable");
        assert_eq!(first.session.status, SessionStatus::Running);
        assert!(first.expires_at > raw.now().await, "the lease is live");
        assert!(first.expires_at < raw.now().await + Duration::seconds(5), "the TTL is the short one");
        // a running session is never claimed, live or not
        assert!(quick.claim_session(run.id, WorkerId::new(), true).await.unwrap().is_none());

        // the reaper makes it `recovering` (no expiry again), so it is claimable at once
        let report = quick.reap(raw.now().await + Duration::hours(1)).await.unwrap();
        assert_eq!(report.sessions_recovering, vec![first.session.id]);
        let after_reap = raw
            .one(
                "SELECT lease_expires_at FROM crawl_sessions WHERE session_id = $1",
                &[V::Uuid(first.session.id.0)],
            )
            .await;
        assert_eq!(after_reap.opt_ts("lease_expires_at"), None);
        let second = quick
            .claim_session(run.id, WorkerId::new(), true)
            .await
            .unwrap()
            .expect("a recovering session without expiry is claimable");
        assert_eq!(second.session.status, SessionStatus::Recovering);
        assert!(second.fencing_token > first.fencing_token);

        // a live lease on a recovering session is not claimable ...
        assert!(
            quick.claim_session(run.id, WorkerId::new(), true).await.unwrap().is_none(),
            "a live lease keeps the session out of the claim"
        );
        // ... until it expires
        tokio::time::sleep(std::time::Duration::from_millis(1800)).await;
        let third = quick
            .claim_session(run.id, WorkerId::new(), true)
            .await
            .unwrap()
            .expect("the lease expired");
        assert_eq!(third.session.id, first.session.id);
        assert!(third.fencing_token > second.fencing_token, "a claim after expiry grants a higher fence");
        assert!(
            matches!(
                quick.heartbeat(&second).await,
                Err(crawlx_core::StoreError::LeaseLost)
            ),
            "the holder of the expired lease is fenced"
        );
        short.close().await;

        // expiries at the extremes: the distant past is expired, the distant future is live
        let run = new_run(store, tenant, &["a"], 2).await;
        let slots = sessions(run.id, 1, 2);
        store.create_sessions(&slots).await.unwrap();
        for (slot, expiry) in slots.iter().zip([long_ago(), far_future()]) {
            raw.run(
                "UPDATE crawl_sessions SET status = 'recovering', lease_expires_at = $1 WHERE session_id = $2",
                &[V::Ts(expiry), V::Uuid(slot.id.0)],
            )
            .await;
        }
        let claimed = store
            .claim_session(run.id, WorkerId::new(), true)
            .await
            .unwrap()
            .expect("the session that expired long ago is claimable");
        assert_eq!(claimed.session.id, slots[0].id);
        assert!(
            store.claim_session(run.id, WorkerId::new(), true).await.unwrap().is_none(),
            "the session whose lease runs to the year 9000 is not"
        );
        assert!(
            store.reap(raw.now().await + Duration::days(365)).await.unwrap().sessions_recovering.is_empty(),
            "a recovering session is never reaped, whatever its expiry"
        );
        // the lease stored for the claim round-trips as an instant after the claim time
        assert!(claimed.expires_at > raw.now().await);
    }
}

db_case! {
    /// URL leases expire the same way: an expiry in the distant past is reaped, one in the
    /// distant future is untouched, and rows that were never leased have no expiry to reap.
    async fn frontier_expiry_sentinels_order_the_reaper<B>(rig, store) {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let mut ids = Vec::new();
        for page in ["old", "new", "idle"] {
            ids.push(
                store
                    .discover(
                        run.id,
                        &canonical_url(&format!("https://example.test/{page}")),
                        0,
                        None,
                        None,
                    )
                    .await
                    .unwrap()
                    .1
                    .unwrap(),
            );
        }
        let worker = WorkerId::new();
        let leased = store.lease_batch(run.id, worker, 2).await.unwrap();
        assert_eq!(leased.len(), 2);
        let leased_ids: BTreeSet<i64> = leased.iter().map(|e| e.id).collect();
        assert_eq!(leased_ids, BTreeSet::from([ids[0], ids[1]]));
        for (id, expiry) in [(ids[0], long_ago()), (ids[1], far_future())] {
            raw.run(
                "UPDATE url_frontier SET lease_expires_at = $1 WHERE frontier_id = $2",
                &[V::Ts(expiry), V::I64(id)],
            )
            .await;
        }
        let never = raw
            .one(
                "SELECT lease_expires_at FROM url_frontier WHERE frontier_id = $1",
                &[V::I64(ids[2])],
            )
            .await;
        assert_eq!(never.opt_ts("lease_expires_at"), None);
        let reaped = store.reap_frontier(store.now().await.unwrap(), 5).await.unwrap();
        assert_eq!((reaped.requeued, reaped.failed), (1, 0));
        let status = |id: i64| {
            async move {
                raw.one("SELECT status FROM url_frontier WHERE frontier_id = $1", &[V::I64(id)])
                    .await
                    .text("status")
            }
        };
        assert_eq!(status(ids[0]).await, "pending", "expired in 1970");
        assert_eq!(status(ids[1]).await, "leased", "leased until the year 9000");
        assert_eq!(status(ids[2]).await, "pending", "never leased");
        let again = store.reap_frontier(store.now().await.unwrap(), 5).await.unwrap();
        assert_eq!((again.requeued, again.failed), (0, 0), "nothing else expired");
    }
}

/// More rows than one `IN` list of the engine binds, so every chunked statement of the
/// portable algorithms runs more than once: one past the engine's placeholder cap.
fn over_one_statement<B: Backend>() -> usize {
    <B::Dialect as Dialect>::MAX_BIND_PARAMS + 1
}

/// Who owns the rows [`bulk_leased_rows`] inserts and when their leases end.
struct LeasedRows {
    run: CrawlRunId,
    tenant: crawlx_core::TenantId,
    worker: WorkerId,
    expires_at: DateTime<Utc>,
}

/// One batch of rows: ids `first..first + count`, each with `attempts` attempts.
struct Batch<'a> {
    first: usize,
    count: usize,
    attempts: i32,
    label: &'a str,
}

/// Insert `batch.count` leased URL rows of the owner's run. Row `i` has the fencing token `i`
/// and `batch.attempts` attempts. One statement per engine generates the rows on the server:
/// a recursive CTE, a sequence table or `generate_series`.
async fn bulk_leased_rows(raw: &Raw<'_>, owner: &LeasedRows, batch: Batch<'_>) {
    let LeasedRows {
        run,
        tenant,
        worker,
        expires_at,
    } = *owner;
    let Batch {
        first,
        count,
        attempts,
        label,
    } = batch;
    let last = first + count - 1;
    let binds = [
        V::Uuid(run.0),
        V::Uuid(tenant.0),
        V::Text(label),
        V::I32(attempts),
        V::Uuid(worker.0),
        V::Ts(expires_at),
    ];
    let sql = match raw.kind() {
        BackendKind::Sqlite => format!(
            "WITH RECURSIVE n(i) AS (SELECT {first} UNION ALL SELECT i + 1 FROM n WHERE i < {last}) \
             INSERT INTO url_frontier (run_id, tenant_id, canonical_key, canonical_url, origin, depth, via, status, \
               attempts, lease_owner, lease_expires_at, fencing_token) \
             SELECT $1, $2, CAST($3 || i AS BLOB), NULL, 'https://example.test', 1, 'link', 'leased', \
               $4, $5, $6, i FROM n"
        ),
        BackendKind::MariaDb => format!(
            "INSERT INTO url_frontier (run_id, tenant_id, canonical_key, canonical_url, origin, depth, via, status, \
               attempts, lease_owner, lease_expires_at, fencing_token) \
             SELECT $1, $2, CAST(CONCAT($3, seq) AS BINARY), NULL, 'https://example.test', 1, 'link', 'leased', \
               $4, $5, $6, seq FROM seq_{first}_to_{last}"
        ),
        _ => format!(
            "INSERT INTO url_frontier (run_id, tenant_id, canonical_key, canonical_url, origin, depth, via, status, \
               attempts, lease_owner, lease_expires_at, fencing_token) \
             SELECT $1::uuid, $2::uuid, convert_to($3::text || g::text, 'UTF8'), NULL, 'https://example.test', 1, 'link', \
               'leased', $4::int, $5::uuid, $6::timestamptz, g FROM generate_series({first}, {last}) g"
        ),
    };
    assert_eq!(raw.run(&sql, &binds).await, u64::try_from(count).unwrap());
}

db_case! {
    /// `reap_frontier` and `heartbeat_frontier` carry their row ids in `IN` lists of at most
    /// the engine's placeholder cap. With more than one list of rows to renew and to reap, both
    /// requeued and failed rows, every row must be handled exactly once.
    async fn reap_frontier_and_heartbeat_cover_more_rows_than_one_statement_binds<B>(rig, store) {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let run = new_run(store, tenant, &[], 1).await;
        let worker = WorkerId::new();
        let n = over_one_statement::<B>();
        let live = raw.now().await + Duration::hours(1);
        // `n` rows with one attempt (requeued) and `n` with the last allowed attempt (failed)
        let owner = LeasedRows { run: run.id, tenant, worker, expires_at: live };
        bulk_leased_rows(&raw, &owner, Batch { first: 1, count: n, attempts: 1, label: "a" }).await;
        bulk_leased_rows(&raw, &owner, Batch { first: n + 1, count: n, attempts: 5, label: "b" }).await;
        let rows = raw
            .rows(
                "SELECT frontier_id, fencing_token FROM url_frontier WHERE run_id = $1",
                &[V::Uuid(run.id.0)],
            )
            .await;
        assert_eq!(rows.len(), 2 * n);
        let leases: Vec<(i64, i64)> = rows
            .iter()
            .map(|r| (r.i64("frontier_id"), r.i64("fencing_token")))
            .collect();

        // every row of the holder is renewed: one id per pair, however many statements it took
        let renewed = store.heartbeat_frontier(worker, &leases).await.unwrap();
        let renewed: BTreeSet<i64> = renewed.into_iter().collect();
        let expected: BTreeSet<i64> = leases.iter().map(|(id, _)| *id).collect();
        assert_eq!(renewed, expected, "every row was renewed");
        // a stranger renews none of them
        let mut stranger_leases = leases.clone();
        stranger_leases.truncate(n);
        assert!(store
            .heartbeat_frontier(WorkerId::new(), &stranger_leases)
            .await
            .unwrap()
            .is_empty());

        // the leases run out and one pass returns every row
        raw.run(
            "UPDATE url_frontier SET lease_expires_at = $1 WHERE run_id = $2",
            &[V::Ts(long_ago()), V::Uuid(run.id.0)],
        )
        .await;
        let reaped = store.reap_frontier(store.now().await.unwrap(), 5).await.unwrap();
        assert_eq!((reaped.requeued, reaped.failed), (u64::try_from(n).unwrap(), u64::try_from(n).unwrap()));
        let by_status = |status: &'static str| {
            let run = run.id;
            async move {
                raw.count(
                    "SELECT count(*) AS n FROM url_frontier WHERE run_id = $1 AND status = $2",
                    &[V::Uuid(run.0), V::Text(status)],
                )
                .await
            }
        };
        let n = i64::try_from(n).unwrap();
        assert_eq!(by_status("pending").await, n, "requeued rows");
        assert_eq!(by_status("failed").await, n, "rows out of attempts");
        assert_eq!(by_status("leased").await, 0, "no row stayed leased");
        let owned = raw
            .count(
                "SELECT count(*) AS n FROM url_frontier WHERE run_id = $1 AND lease_owner IS NOT NULL",
                &[V::Uuid(run.id.0)],
            )
            .await;
        assert_eq!(owned, 0, "no row kept its holder");
    }
}

/// Insert `count` expired `running` sessions of `run`, one per slot starting at `first`.
/// The ids are the numbers `first..` as 16 big-endian bytes, which sort before any UUIDv7.
async fn bulk_running_sessions(
    raw: &Raw<'_>,
    run: CrawlRunId,
    worker: WorkerId,
    expires_at: DateTime<Utc>,
    first: usize,
    count: usize,
) {
    let last = first + count - 1;
    let binds = [V::Uuid(run.0), V::Uuid(worker.0), V::Ts(expires_at)];
    let sql = match raw.kind() {
        BackendKind::Sqlite => format!(
            "WITH RECURSIVE n(i) AS (SELECT {first} UNION ALL SELECT i + 1 FROM n WHERE i < {last}) \
             INSERT INTO crawl_sessions (session_id, run_id, role, run_index, schedule_slot, status, lease_owner, \
               lease_expires_at, fencing_token) \
             SELECT unhex(printf('%032x', i)), $1, 'bulk', i, i, 'running', $2, $3, i FROM n"
        ),
        BackendKind::MariaDb => format!(
            "INSERT INTO crawl_sessions (session_id, run_id, role, run_index, schedule_slot, status, lease_owner, \
               lease_expires_at, fencing_token) \
             SELECT UNHEX(LPAD(HEX(seq), 32, '0')), $1, 'bulk', seq, seq, 'running', $2, $3, seq \
             FROM seq_{first}_to_{last}"
        ),
        _ => format!(
            "INSERT INTO crawl_sessions (session_id, run_id, role, run_index, schedule_slot, status, lease_owner, \
               lease_expires_at, fencing_token) \
             SELECT lpad(to_hex(g), 32, '0')::uuid, $1::uuid, 'bulk', g, g, 'running', $2::uuid, $3::timestamptz, g \
             FROM generate_series({first}, {last}) g"
        ),
    };
    assert_eq!(raw.run(&sql, &binds).await, u64::try_from(count).unwrap());
}

db_case! {
    /// The session reaper moves expired holders to `recovering` and flips their `intended`
    /// actions to `unknown` in lists of at most the engine's placeholder cap. With more
    /// expired sessions than one list holds, the sessions at both ends of the set (their
    /// actions are in the first and the last list) are all handled.
    async fn reap_covers_more_sessions_than_one_statement_binds<B>(rig, store) {
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        let mut intended: BTreeSet<ActionId> = BTreeSet::new();
        let mut real: BTreeSet<SessionId> = BTreeSet::new();

        // two holders with an intent before the bulk rows exist ...
        let mut held = Vec::new();
        for k in 0..2u32 {
            let run = new_run(store, tenant, &[], 1).await;
            let session = lease_all(store, &run, 1, 1).await.remove(0).session.id;
            let id = store
                .propose(
                    run.id,
                    session,
                    &proposal("anonymous", StateClusterId::new(), k + 1),
                    &allow_verdict(),
                )
                .await
                .unwrap();
            store.intend(id, session, epoch(1, 1, 0)).await.unwrap();
            held.push((session, id));
        }
        // ... then more expired sessions than one `IN` list binds ...
        let bulk_run = new_run(store, tenant, &["bulk"], 1).await;
        let n = over_one_statement::<B>();
        let expired = raw.now().await - Duration::minutes(10);
        bulk_running_sessions(&raw, bulk_run.id, WorkerId::new(), expired, 1, n).await;
        // ... and two holders with an intent after them
        for k in 2..4u32 {
            let run = new_run(store, tenant, &[], 1).await;
            let session = lease_all(store, &run, 1, 1).await.remove(0).session.id;
            let id = store
                .propose(
                    run.id,
                    session,
                    &proposal("anonymous", StateClusterId::new(), k + 1),
                    &allow_verdict(),
                )
                .await
                .unwrap();
            store.intend(id, session, epoch(1, 1, 0)).await.unwrap();
            held.push((session, id));
        }
        for (session, id) in &held {
            real.insert(*session);
            intended.insert(*id);
        }
        // every holder's lease ran out, at the same instant
        raw.run(
            "UPDATE crawl_sessions SET lease_expires_at = $1 WHERE status = 'running'",
            &[V::Ts(expired)],
        )
        .await;

        let report = store.reap(store.now().await.unwrap()).await.unwrap();
        assert_eq!(report.sessions_recovering.len(), n + 4, "every expired session was reaped");
        let reaped: BTreeSet<SessionId> = report.sessions_recovering.iter().copied().collect();
        assert_eq!(reaped.len(), n + 4, "none twice");
        assert!(real.is_subset(&reaped));
        let flipped: BTreeSet<ActionId> = report.actions_unknown.iter().copied().collect();
        assert_eq!(flipped, intended, "the intents of both ends of the set became unknown");
        assert_eq!(report.actions_unknown.len(), 4);
        for (_, id) in &held {
            assert_eq!(ActionJournal::get(store, *id).await.unwrap().status, ActionStatus::Unknown);
        }
        let still_running = raw
            .count("SELECT count(*) AS n FROM crawl_sessions WHERE status = 'running'", &[])
            .await;
        assert_eq!(still_running, 0, "no session stayed running");
        let recovering = raw
            .count("SELECT count(*) AS n FROM crawl_sessions WHERE status = 'recovering'", &[])
            .await;
        assert_eq!(recovering, i64::try_from(n + 4).unwrap());
    }
}

/// The T2 statements of the atomic-outcome drill: a full outcome reaches every one.
#[cfg(feature = "chaos")]
fn full_outcome(session: SessionId, cluster: StateClusterId) -> crawlx_core::repo::OutcomeRecord {
    use crawlx_core::observation::{ActionReceipt, SettleReport};
    use crawlx_core::traffic::{Fidelity, TrafficEvent, TrafficOrigin};
    let now = Utc::now();
    let after = new_state(session, cluster, false, 2, epoch(1, 1, 5));
    crawlx_core::repo::OutcomeRecord {
        status: ActionStatus::Succeeded,
        receipt: Some(ActionReceipt {
            network_epoch: crawlx_core::NetworkEpochId::new(),
            fidelity: Fidelity::ScriptedNavigation,
            lane: Fidelity::ScriptedNavigation.lane(),
            started_at: now,
            finished_at: now,
        }),
        settle: Some(SettleReport::default()),
        after_state: Some(after),
        traffic: (0..2)
            .map(|i| TrafficEvent {
                seq: i,
                epoch_id: None,
                unattributed_reason: None,
                protocol: None,
                origin: TrafficOrigin::Page,
                method: "GET".to_owned(),
                url: format!("https://example.test/api/{i}"),
                status: Some(200),
                request_headers: Vec::new(),
                response_headers: Vec::new(),
                request_body: None,
                response_body: None,
                third_party: false,
                late: false,
                started_at: now,
                finished_at: Some(now),
            })
            .collect(),
        error: None,
        finished_at: now,
    }
}

#[cfg(feature = "chaos")]
db_case! {
    /// Atomic outcome: each statement of T2 (`ActionJournal::finish`) fails once; nothing of
    /// T2 is visible afterwards and the next full attempt succeeds. The failpoint table is
    /// process-global, so this is one case per engine, serialized against every other case
    /// that finishes an action.
    async fn every_t2_statement_failing_once_leaves_nothing_behind<B>(rig, store) {
        use crawlx_storage::chaos;
        use std::error::Error as _;

        let _serial = super::FAILPOINT_SERIAL.lock().await;
        let raw = Raw::new(rig);
        let tenant = tenant(rig).await;
        // `(transitions, network_epochs, traffic_events, crawl_events, states)` of `run`
        let t2_rows = |run: CrawlRunId| {
            async move {
                let mut counts = Vec::new();
                for table in ["transitions", "network_epochs", "traffic_events", "crawl_events", "states"] {
                    counts.push(
                        raw.count(
                            &format!("SELECT count(*) AS n FROM {table} WHERE run_id = $1"),
                            &[V::Uuid(run.0)],
                        )
                        .await,
                    );
                }
                counts
            }
        };
        for &point in chaos::T2_FAILPOINTS {
            // one intended action with a before-state, ready for T2
            let run = new_run(store, tenant, &[], 1).await;
            let session = lease_all(store, &run, 1, 1).await.remove(0).session.id;
            let cluster = StateClusterId::new();
            let before = new_state(session, cluster, true, 1, epoch(1, 1, 0));
            crawlx_core::repo::StateRepo::put_state(store, &before).await.unwrap();
            let id = store
                .propose(run.id, session, &proposal("anonymous", cluster, 1), &allow_verdict())
                .await
                .unwrap();
            store.intend(id, session, epoch(1, 1, 3)).await.unwrap();

            chaos::reset();
            chaos::arm(point, 1);
            let err = store
                .finish(id, full_outcome(session, cluster))
                .await
                .expect_err(point);
            assert!(matches!(err, crawlx_core::StoreError::Database { .. }), "{point}: {err:?}");
            assert!(
                err.source().unwrap().is::<chaos::ChaosFault>(),
                "{point}: the injected fault is the source"
            );
            assert_eq!(chaos::hits(point), 1, "{point} was reached exactly once");

            // nothing of T2 is visible: the action is `intended`, only the before-state exists,
            // the ledger row and the run's event sequence are untouched
            let rec = ActionJournal::get(store, id).await.unwrap();
            assert_eq!(rec.status, ActionStatus::Intended, "{point}: action status");
            assert_eq!(rec.finished_at, None, "{point}: finished_at");
            assert_eq!(t2_rows(run.id).await, vec![0, 0, 0, 0, 1], "{point}: T2 rows");
            let ledger = raw
                .one(
                    "SELECT c.succeeded, c.failed, c.unknown, c.last_action_id FROM action_contexts c \
                     JOIN actions a ON a.context_id = c.context_id WHERE a.action_id = $1",
                    &[V::Uuid(id.0)],
                )
                .await;
            assert_eq!(
                (
                    ledger.i32("succeeded"),
                    ledger.i32("failed"),
                    ledger.i32("unknown"),
                    ledger.opt_uuid("last_action_id")
                ),
                (0, 0, 0, None),
                "{point}: ledger counters"
            );
            let event_seq = raw
                .one("SELECT event_seq FROM crawl_runs WHERE run_id = $1", &[V::Uuid(run.id.0)])
                .await
                .i64("event_seq");
            assert_eq!(event_seq, 0, "{point}: event_seq");

            store
                .finish(id, full_outcome(session, cluster))
                .await
                .unwrap_or_else(|e| panic!("{point}: retry after the fault: {e:?}"));
            assert_eq!(chaos::hits(point), 2, "{point}: the retry reached it again");
            let rec = ActionJournal::get(store, id).await.unwrap();
            assert_eq!(rec.status, ActionStatus::Succeeded, "{point}: retry");
            assert_eq!(t2_rows(run.id).await, vec![1, 1, 2, 1, 2], "{point}: full T2 after retry");
        }
        chaos::reset();
    }
}

/// The two-process drill: this test is its own child. The parent (no `CRAWLX_LEASE_CHILD`)
/// prepares a SQLite file with leaseable URL rows and starts two copies of this test binary
/// on that file; the children (`CRAWLX_LEASE_CHILD` set) wait for the go file, then claim
/// batches until the frontier is empty and print `CLAIMED <frontier id> <token>` per row.
/// Both children complete one batch before either drains the remainder, so both participate.
/// Their union leases every row exactly once, with unique fencing tokens.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn two_sqlite_processes_never_lease_the_same_row() {
    if let Ok(path) = std::env::var("CRAWLX_LEASE_CHILD") {
        child_claims(&path).await;
        return;
    }
    let rows = super::support::lease_scale().1.max(300);
    let rig = Rig::sqlite().await;
    rig.migrate().await;
    let db = rig.database();
    let store = db.sqlite_store().expect("a sqlite rig has a store");
    let tenant = tenant(&rig).await;
    let run = new_run(store, tenant, &[], 1).await;
    for i in 0..rows {
        store
            .discover(
                run.id,
                &canonical_url(&format!("https://example.test/p{i}")),
                1,
                None,
                None,
            )
            .await
            .unwrap();
    }
    let file = sqlite_file(&rig);
    let gate = rig.directory().unwrap().join("go");
    let exe = std::env::current_exe().expect("the path of this test binary");
    let mut children = Vec::new();
    for _ in 0..2 {
        children.push(
            std::process::Command::new(&exe)
                .args([
                    "leases::bounds::two_sqlite_processes_never_lease_the_same_row",
                    "--exact",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("CRAWLX_LEASE_CHILD", &file)
                .env("CRAWLX_LEASE_RUN", run.id.0.to_string())
                .env("CRAWLX_LEASE_GATE", &gate)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
                .expect("spawn the child process"),
        );
    }
    // both children have the file open: release the start barrier
    let ready_dir = gate.parent().unwrap().to_path_buf();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let ready = std::fs::read_dir(&ready_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("ready-"))
            .count();
        if ready == 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the children never became ready"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    std::fs::write(&gate, b"go").unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let claimed = std::fs::read_dir(&ready_dir)
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with("claimed-"))
            .count();
        if claimed == 2 {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "both children must claim a batch"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    std::fs::write(gate.with_extension("continue"), b"go").unwrap();
    let mut all: Vec<(i64, i64)> = Vec::new();
    let mut per_process = Vec::new();
    for child in children {
        let output = tokio::task::spawn_blocking(move || child.wait_with_output().unwrap())
            .await
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.lines().any(|l| l == "CHILD DONE"),
            "child failed: {}\n{}\n{}",
            output.status,
            stdout,
            String::from_utf8_lossy(&output.stderr)
        );
        // the harness announces the test on the same line as the child's first output
        let claimed: Vec<(i64, i64)> = stdout
            .lines()
            .filter_map(|line| line.split_once("CLAIMED ").map(|(_, rest)| rest))
            .map(|rest| {
                let (id, token) = rest.split_once(' ').expect("an id and a token");
                (id.parse().unwrap(), token.parse().unwrap())
            })
            .collect();
        assert!(!claimed.is_empty(), "both processes participate");
        per_process.push(claimed.len());
        all.extend(claimed);
    }
    eprintln!("rows leased per process: {per_process:?}");
    let ids: BTreeSet<i64> = all.iter().map(|(id, _)| *id).collect();
    let tokens: BTreeSet<i64> = all.iter().map(|(_, token)| *token).collect();
    assert_eq!(all.len(), rows, "every row was leased");
    assert_eq!(ids.len(), rows, "no row was leased twice, across processes");
    assert_eq!(tokens.len(), rows, "fencing tokens are unique across processes");
    let listed: BTreeSet<i64> = FrontierRepo::list(store, run.id)
        .await
        .unwrap()
        .into_iter()
        .map(|entry| entry.id)
        .collect();
    assert_eq!(ids, listed, "nothing was lost");
    assert_eq!(store.pending_count(run.id).await.unwrap(), 0);
    rig.close().await;
}

/// The child half of [`two_sqlite_processes_never_lease_the_same_row`].
async fn child_claims(file: &str) {
    let run = CrawlRunId(
        std::env::var("CRAWLX_LEASE_RUN")
            .expect("the run id")
            .parse()
            .expect("a uuid"),
    );
    let gate = std::path::PathBuf::from(std::env::var("CRAWLX_LEASE_GATE").expect("the go file"));
    let db = Database::open(&format!("sqlite://{file}"), StoreConfig::default())
        .await
        .expect("open the shared file");
    let store = db.sqlite_store().expect("a sqlite database");
    // tell the parent this process has the file open, then wait at the gate
    std::fs::write(
        gate.parent()
            .unwrap()
            .join(format!("ready-{}", std::process::id())),
        b"ready",
    )
    .unwrap();
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !gate.exists() {
        assert!(std::time::Instant::now() < deadline, "the go file never appeared");
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    let worker = WorkerId::new();
    let first = store.lease_batch_fenced(run, worker, 4).await.unwrap();
    assert!(!first.is_empty(), "each child gets an initial batch");
    for (entry, token) in first {
        println!("CLAIMED {} {token}", entry.id);
    }
    std::fs::write(
        gate.parent()
            .unwrap()
            .join(format!("claimed-{}", std::process::id())),
        b"claimed",
    )
    .unwrap();
    let next_gate = gate.with_extension("continue");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !next_gate.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "the drain gate never appeared"
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    loop {
        let batch = store.lease_batch_fenced(run, worker, 4).await.unwrap();
        if batch.is_empty() {
            break;
        }
        for (entry, token) in batch {
            println!("CLAIMED {} {token}", entry.id);
        }
    }
    println!("CHILD DONE");
    db.close().await;
}

/// The caps the batch cases are sized from: SQLite binds at most 32 766 values per statement,
/// MariaDB and PostgreSQL 65 535.
#[test]
fn placeholder_caps_are_the_ones_the_batch_cases_assume() {
    assert_eq!(SqliteDialect::MAX_BIND_PARAMS, 32_766);
    assert_eq!(MariaDbDialect::MAX_BIND_PARAMS, 65_535);
    assert_eq!(PostgresDialect::MAX_BIND_PARAMS, 65_535);
}
