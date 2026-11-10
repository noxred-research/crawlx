//! The WebSocket watchers of crawls and batch scrapes (`GET .../crawl/{id}` and
//! `GET .../batch/scrape/{id}` with `Upgrade: websocket`, and their `/ws` siblings).

use super::common::Document;
use super::crawl::{CrawlStatus, CrawlStatusQuery};
use super::scrape::{BatchStatus, BatchStatusQuery};
use super::Spec;
use schemars::JsonSchema;

/// The `data` of a `catchup` frame: the status body with every document stored so far.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct WatchCatchup {
    /// `scraping`, `completed`, `failed` or `cancelled`.
    status: String,
    /// Pages in the job.
    total: u64,
    /// Pages completed.
    completed: u64,
    /// Credits the stored pages cost.
    credits_used: u64,
    /// RFC 3339 time the job is deleted; `null` until a crawl is terminal.
    expires_at: Option<String>,
    /// Always `null`: the documents are streamed, not paged.
    next: Option<String>,
    /// Every document stored when the watcher connected.
    data: Vec<Document>,
}

/// The `data` of a `done` frame: the terminal status and totals.
#[derive(JsonSchema)]
#[serde(rename_all = "camelCase")]
pub(super) struct WatchDone {
    /// `completed`, `failed` or `cancelled`.
    status: String,
    /// Always empty: the documents were already streamed.
    data: Vec<Document>,
    /// Pages in the job.
    total: u64,
    /// Pages completed.
    completed: u64,
    /// Credits the stored pages cost.
    credits_used: u64,
}

/// A frame of the watcher: a JSON text message. The sequence is one `catchup`, one `document` per
/// page stored after it (each page exactly once) and a `done`, then a normal close; a failure is
/// an `error` frame and a close.
#[derive(JsonSchema)]
#[serde(tag = "type")]
#[allow(
    clippy::large_enum_variant,
    reason = "a schema-only mirror, never constructed"
)]
pub(super) enum WatchFrame {
    /// The status and every document stored so far.
    #[serde(rename = "catchup")]
    Catchup {
        /// The status body.
        data: WatchCatchup,
    },
    /// One page stored after the catchup.
    #[serde(rename = "document")]
    Document {
        /// The page.
        data: Document,
    },
    /// The job is terminal.
    #[serde(rename = "done")]
    Done {
        /// The terminal status and totals.
        data: WatchDone,
    },
    /// The job could not be followed.
    #[serde(rename = "error")]
    Error {
        /// What went wrong.
        error: String,
    },
}

/// The 101 response every status and watcher path can answer to an upgrade request.
pub(super) const UPGRADE: &str = "With `Upgrade: websocket` the connection becomes a watcher; every message is a JSON text frame (schema WatchFrame). The API key may be the `Sec-WebSocket-Protocol` subprotocol, which the handshake echoes.";

pub(super) fn spec(id: &str) -> Option<Spec> {
    let s = match id {
        "compatCrawlWatch" => Spec::new(&[400, 404])
            .path("id", "Id of the crawl.", Some("uuid"))
            .query::<CrawlStatusQuery>()
            .reply::<CrawlStatus>(
                "200",
                "Without `Upgrade: websocket` the status of the crawl, as `GET /crawl/{id}`.",
            )
            .reply::<WatchFrame>("101", UPGRADE),
        "compatBatchScrapeWatch" => Spec::new(&[400, 404])
            .path("id", "Id of the batch.", Some("uuid"))
            .query::<BatchStatusQuery>()
            .reply::<BatchStatus>(
                "200",
                "Without `Upgrade: websocket` the status of the batch, as `GET /batch/scrape/{id}`.",
            )
            .reply::<WatchFrame>("101", UPGRADE),
        _ => return None,
    };
    Some(s)
}
