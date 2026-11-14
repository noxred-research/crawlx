//! One generic conformance suite, run against every storage engine.
//!
//! Each case is an `async fn case(rig: &Rig)`. `conformance!` expands it into one test per
//! engine: `sqlite_case` always runs, `mariadb_case` when `CRAWLX_TEST_MARIADB_URL` is set,
//! `postgres_case` when `CRAWLX_TEST_DATABASE_URL` is set (both skip with a note on stderr),
//! and `memory_case` for cases the in-memory specification also implements. Filter by engine
//! with `cargo test -p crawlx-storage --test conformance -- mariadb_`.
//!
//! A case file owns its slice of the suite; add `mod <file>;` below the macro.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod rig;

/// Expand cases into per-engine tests.
///
/// `conformance! { databases: a, b }` runs on SQLite, MariaDB and PostgreSQL;
/// `conformance! { all: a }` also runs on the in-memory store.
macro_rules! conformance {
    (databases: $($case:ident),+ $(,)?) => {
        conformance! { @expand no $($case),+ }
    };
    (all: $($case:ident),+ $(,)?) => {
        conformance! { @expand yes $($case),+ }
    };
    (@expand $memory:ident $($case:ident),+) => {
        $(
            mod $case {
                #[tokio::test]
                async fn sqlite_case() {
                    let rig = crate::rig::Rig::sqlite().await;
                    super::$case(&rig).await;
                    rig.close().await;
                }

                #[tokio::test]
                async fn mariadb_case() {
                    if let Some(rig) = crate::rig::Rig::mariadb().await {
                        super::$case(&rig).await;
                        rig.close().await;
                    }
                }

                #[tokio::test]
                async fn postgres_case() {
                    if let Some(rig) = crate::rig::Rig::postgres().await {
                        super::$case(&rig).await;
                        rig.close().await;
                    }
                }

                conformance! { @memory $memory $case }
            }
        )+
    };
    (@memory yes $case:ident) => {
        #[tokio::test]
        async fn memory_case() {
            let rig = crate::rig::Rig::memory();
            super::$case(&rig).await;
        }
    };
    (@memory no $case:ident) => {};
}

mod approvals;
mod authorization;
mod bootstrap;
#[path = "core.rs"]
mod core_repos;
mod custody;
mod data;
mod deployment;
mod foundation;
mod leases;
mod retention;
mod tenancy;
