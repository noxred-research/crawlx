//! `POST /map`.

use super::common::Warning;
use super::crawl::SitemapMode;
use super::scrape::Location;
use super::Spec;
use schemars::JsonSchema;

/// `POST /map` body. `auditMetadata` and `threatProtection` are accepted and ignored with an
/// `unsupported_option` warning. A `location.country` adds a `location_no_proxy` warning (no
/// geo-located proxy).
#[derive(JsonSchema)]
pub(super) struct MapRequest {
    /// The site to map (`http` or `https`; a bare host is read as `http://host`).
    #[schemars(extend("format" = "uri"))]
    url: String,
    /// Order the links by relevance to this text.
    search: Option<String>,
    /// How sitemaps are used (default `include`).
    sitemap: Option<SitemapMode>,
    /// Include subdomains of the registrable domain (default `true`).
    #[serde(rename = "includeSubdomains")]
    include_subdomains: Option<bool>,
    /// Drop query parameters and merge the URLs (default `true`).
    #[serde(rename = "ignoreQueryParameters")]
    ignore_query_parameters: Option<bool>,
    /// Default `false`: the live results are extended with URLs earlier crawls, scrapes and maps of
    /// the same tenant stored for the site (the `map_cached_sources` warning counts them;
    /// zero-data-retention, expired, error and not-cacheable pages are never read). `true` reads
    /// nothing from the store.
    #[serde(rename = "ignoreCache")]
    ignore_cache: Option<bool>,
    /// Most links to return (1 to 100000, default 5000).
    #[schemars(range(min = 1, max = 100000))]
    limit: Option<u32>,
    /// Milliseconds the request waits for the map (at least 1; default 300000).
    timeout: Option<u32>,
    /// `languages` (else the country's main language) become the weighted `Accept-Language`
    /// (`de-DE,en;q=0.9`) of the fetches; a `country` is emulated by that header, not a proxy.
    location: Option<Location>,
}

/// One link of a map.
#[derive(JsonSchema)]
pub(super) struct MapLink {
    /// The URL (fragment dropped; query dropped under `ignoreQueryParameters`).
    url: String,
    /// Page title, when the page was fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    title: Option<String>,
    /// Page description, when the page was fetched.
    #[serde(skip_serializing_if = "Option::is_none")]
    description: Option<String>,
}

/// `POST /map` response.
#[derive(JsonSchema)]
pub(super) struct MapResponse {
    /// Always `true`.
    #[schemars(extend("const" = true))]
    success: bool,
    /// The URLs of the site in discovery order (by relevance with `search`), cut to `limit`.
    links: Vec<MapLink>,
    /// Options that were not applied, and `map_cached_sources` / `location_no_proxy`.
    #[serde(skip_serializing_if = "Option::is_none")]
    warnings: Option<Vec<Warning>>,
}

pub(super) fn spec(id: &str) -> Option<Spec> {
    match id {
        "compatMap" => Some(
            Spec::new(&[400, 403, 408, 413, 422])
                .json::<MapRequest>("The site and the map options.")
                .reply::<MapResponse>("200", "The links of the site."),
        ),
        _ => None,
    }
}
