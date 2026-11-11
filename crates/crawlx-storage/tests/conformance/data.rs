//! Conformance cases of the data plane: datasets, KV and delivery outbox, feed finalization,
//! source memo, adaptive selectors, the archive catalog, session bindings, report history,
//! the URL graph and the JSON column contract.
//!
//! Each file under `data/` owns one family. A case is written once against the repository
//! traits and runs on every engine: `on_repo!` hands it the engine's repository value (the
//! in-memory store, or the `Store` of SQLite, MariaDB or PostgreSQL), so the case body is
//! generic over the traits it needs.

/// Run `$body` with `$repo` bound to the repository of the rig's engine. The body is
/// instantiated once per engine, so it may call generic functions over repository traits.
macro_rules! on_repo {
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

#[path = "data/archive.rs"]
mod archive;
#[path = "data/bindings.rs"]
mod bindings;
#[path = "data/dataset.rs"]
mod dataset;
#[path = "data/json.rs"]
mod json;
#[path = "data/raw.rs"]
mod raw;
#[path = "data/reports.rs"]
mod reports;
#[path = "data/selectors.rs"]
mod selectors;
#[path = "data/url_graph.rs"]
mod url_graph;
