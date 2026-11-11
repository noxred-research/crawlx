//! Route table.

pub mod adaptive_selectors;
pub mod approvals;
pub mod archives;
pub mod artifacts;
pub mod authorizations;
pub mod capabilities;
pub mod compat;
pub mod compat_agent;
pub mod compat_crawl;
pub mod compat_extract;
pub mod compat_map;
pub mod compat_monitor;
pub mod compat_parse;
pub mod compat_scrape;
pub mod compat_search;
pub mod compat_team;
pub mod compat_ws;
pub mod coverage;
pub mod crawls;
pub mod datasets;
pub mod datasets_import;
pub mod events;
pub mod extensions;
pub mod kv;
pub mod login_flows;
pub mod memo;
pub mod pages;
pub mod replays;
pub mod reports;
pub mod requests;
pub mod states;
pub mod traffic;
pub mod transitions;

use crate::auth::auth_layer;
use crate::errors::HttpError;
use crate::metrics::request_metrics;
use crate::state::AppState;
use crate::util::{envelope_layer, json_response};
use axum::http::StatusCode;
use axum::middleware::{from_fn, from_fn_with_state};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;

async fn openapi() -> Response {
    json_response(StatusCode::OK, &crate::openapi::document())
}

async fn not_found() -> HttpError {
    HttpError::not_found("route")
}

/// The full router (authentication on everything except `/v1/openapi.json`). Every request,
/// matched or not, is counted by [`request_metrics`] inside the envelope middleware.
pub fn router(state: AppState) -> Router {
    let authed = Router::new()
        .route("/v1/capabilities/acquisition", get(capabilities::acquisition))
        .route("/v1/capabilities/extensions", get(extensions::registry))
        .route("/v1/crawls", post(crawls::create))
        .route("/v1/crawls/{id}/login-flows", post(login_flows::create))
        .route(
            "/v1/crawls/{id}",
            get(crawls::get).post(crawls::verb).delete(crawls::erase),
        )
        .route("/v1/crawls/{id}/reports", get(reports::inventory))
        .route("/v1/crawls/{id}/reports/{report}", get(reports::search))
        .route("/v1/crawls/{id}/archives", get(archives::list))
        .route(
            "/v1/crawls/{id}/archives/{export_id}",
            get(archives::get).delete(archives::erase),
        )
        .route(
            "/v1/crawls/{id}/archives/{export_id}/records",
            get(archives::records),
        )
        .route(
            "/v1/crawls/{id}/archives/{export_id}/export",
            get(archives::export),
        )
        .route("/v1/crawls/{id}/pages", get(pages::pages))
        .route(
            "/v1/crawls/{id}/requests",
            get(requests::list).post(requests::append),
        )
        .route("/v1/crawls/{id}/requests/seal", post(requests::seal))
        .route("/v1/crawls/{id}/requests/import", post(requests::import))
        .route(
            "/v1/crawls/{id}/adaptive-selectors/{selector_id}",
            get(adaptive_selectors::get).put(adaptive_selectors::put),
        )
        .route(
            "/v1/crawls/{id}/adaptive-selectors/{selector_id}/relocate",
            post(adaptive_selectors::relocate),
        )
        .route("/v1/crawls/{id}/extensions", get(extensions::effective))
        .route("/v1/crawls/{id}/source-memo", axum::routing::delete(memo::reset))
        .route("/v1/crawls/{id}/datasets", get(datasets::list))
        .route("/v1/crawls/{id}/datasets/{name}/items", get(datasets::items))
        .route(
            "/v1/crawls/{id}/datasets/import",
            post(datasets_import::apply).layer(axum::extract::DefaultBodyLimit::max(
                crawlx_core::dataset::import::MAX_IMPORT_BYTES,
            )),
        )
        .route("/v1/crawls/{id}/kv/{store}", get(kv::list).delete(kv::drop_store))
        .route(
            "/v1/crawls/{id}/kv/{store}/{key}",
            get(kv::get).put(kv::put).delete(kv::delete),
        )
        .route("/v1/crawls/{id}/export", get(pages::export))
        .route("/v1/crawls/{id}/events", get(events::events))
        .route("/v1/crawls/{id}/errors", get(pages::errors))
        .route("/v1/crawls/{id}/states", get(states::states))
        .route("/v1/crawls/{id}/transitions", get(transitions::transitions))
        .route("/v1/crawls/{id}/coverage", get(coverage::coverage))
        .route("/v1/crawls/{id}/traffic", get(traffic::traffic))
        .route(
            "/v1/crawls/{id}/artifacts/{artifact_id}",
            get(artifacts::artifact),
        )
        .route("/v1/crawls/{id}/approvals", get(approvals::list))
        .route(
            "/v1/crawls/{id}/approvals/{approval_action}",
            post(approvals::decide),
        )
        .route("/v1/replays", post(replays::create))
        .route("/v1/authorizations", post(authorizations::create))
        .route(
            "/v1/authorizations/evidence",
            post(authorizations::upload_evidence),
        )
        .route("/v1/authorizations/{id}", get(authorizations::get))
        .route("/v1/authorizations/{id}/revoke", post(authorizations::revoke))
        .route("/v1/authorizations/{id}/verify", post(authorizations::verify))
        .route("/compat/v2/crawl", post(compat::create))
        .route(
            "/compat/v2/crawl/{id}",
            get(compat_ws::crawl).delete(compat::cancel),
        )
        .route("/compat/v2/crawl/{id}/errors", get(compat::errors))
        .merge(compat_search::routes())
        .merge(compat_crawl::routes())
        .merge(compat_map::routes())
        .merge(compat_scrape::routes())
        .merge(compat_extract::routes())
        .merge(compat_agent::routes())
        .merge(compat_parse::routes())
        .merge(compat_monitor::routes())
        .merge(compat_ws::routes())
        .merge(compat_team::routes())
        .route("/metrics", get(crate::metrics::prometheus))
        .layer(from_fn_with_state(state.clone(), auth_layer));
    Router::new()
        .route("/v1/openapi.json", get(openapi))
        .merge(compat_team::health_routes())
        .merge(authed)
        .fallback(not_found)
        .with_state(state)
        .layer(from_fn(request_metrics))
        .layer(from_fn(envelope_layer))
}
