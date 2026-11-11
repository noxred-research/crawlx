#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Conformance cases of leases and the action journal: session and URL leases with their
//! fencing tokens, the round-robin barrier, the reaper, the T1/T2 journal with its status
//! machine and lane constraints, durable approvals, and the placeholder and process
//! boundaries of each engine.
//!
//! Each file under `leases/` owns one family. A case is written once and runs on every
//! engine: `on_db!` hands a generic case body the `Store` of the rig's engine, `on_store!`
//! also hands it the in-memory store for the cases the executable specification implements
//! the same way. `db_case!` declares a case as a function generic over the engine, so the
//! body type checks once and runs on all three.

/// Run the generic case function `$case(rig, store)` with the `Store` of the rig's engine.
macro_rules! on_db {
    ($rig:expr, $case:path) => {{
        use crawlx_storage::testkit::Engine;
        let rig: &crate::rig::Rig = $rig;
        match rig.engine() {
            Engine::Sqlite => {
                $case(
                    rig,
                    rig.database().sqlite_store().expect("a sqlite rig has a store"),
                )
                .await
            }
            Engine::MariaDb => {
                $case(
                    rig,
                    rig.database().mariadb_store().expect("a mariadb rig has a store"),
                )
                .await
            }
            Engine::Postgres => {
                $case(
                    rig,
                    rig.database().postgres().expect("a postgres rig has a store"),
                )
                .await
            }
            _ => panic!("this case runs on database engines only"),
        }
    }};
}

/// [`on_db!`] that also runs the case on the in-memory store.
macro_rules! on_store {
    ($rig:expr, $case:path) => {
        on_store!($rig, |store| $case($rig, store).await)
    };
    ($rig:expr, |$repo:ident| $body:expr) => {{
        use crawlx_storage::testkit::Engine;
        match $rig.engine() {
            Engine::Memory => {
                let $repo = $rig.store().as_ref();
                $body
            }
            Engine::Sqlite => {
                let $repo = $rig.database().sqlite_store().expect("a sqlite rig has a store");
                $body
            }
            Engine::MariaDb => {
                let $repo = $rig
                    .database()
                    .mariadb_store()
                    .expect("a mariadb rig has a store");
                $body
            }
            Engine::Postgres => {
                let $repo = $rig.database().postgres().expect("a postgres rig has a store");
                $body
            }
            _ => panic!("every engine of the suite is handled above"),
        }
    }};
}

/// Declare a case `async fn name<B>(rig, store) { .. }` that runs on every database engine:
/// the migrated database of the rig and its `Store<B>` are in scope as `rig` and `store`.
macro_rules! db_case {
    ($(#[$meta:meta])* async fn $name:ident<$engine:ident>($rig:ident, $store:ident) $body:block) => {
        $(#[$meta])*
        async fn $name(rig: &crate::rig::Rig) {
            #[allow(unused_variables, reason = "a case may not need every handle")]
            async fn run<$engine>($rig: &crate::rig::Rig, $store: &crawlx_storage::Store<$engine>)
            where
                $engine: crawlx_storage::sql::Sql + $crate::leases::support::StoreOf,
            $body
            rig.migrate().await;
            on_db!(rig, run);
        }
    };
}

/// Declare a case that uses repository traits shared by database stores and MemoryStore.
macro_rules! all_case {
    ($(#[$meta:meta])* async fn $name:ident<$store_type:ident>($rig:ident, $store:ident) $body:block) => {
        $(#[$meta])*
        async fn $name(rig: &crate::rig::Rig) {
            async fn run<$store_type>($rig: &crate::rig::Rig, $store: &$store_type)
            where
                $store_type: crawlx_core::repo::RunRepo
                    + crawlx_core::repo::ActionJournal
                    + crawlx_storage::LeaseRepo,
            $body
            rig.migrate().await;
            on_store!(rig, run);
        }
    };
}

/// The chaos failpoints and their hit counters are process-global, and every case that runs
/// `ActionJournal::finish` passes through them. Cases of this family that finish an action
/// take this lock, so one case's armed failpoint never fires inside another's outcome.
static FAILPOINT_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[path = "leases/support.rs"]
mod support;

#[path = "leases/approvals.rs"]
mod approvals;
#[path = "leases/bounds.rs"]
mod bounds;
#[path = "leases/frontier_leases.rs"]
mod frontier_leases;
#[path = "leases/journal.rs"]
mod journal;
#[path = "leases/scheduler.rs"]
mod scheduler;
#[path = "leases/session_leases.rs"]
mod session_leases;
