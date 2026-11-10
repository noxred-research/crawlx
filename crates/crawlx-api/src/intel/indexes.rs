//! Self-hosted equivalents of the compat API's hosted indexes, answered from the configured search
//! backend (category `developer`/`github`, `gov`, `research`) and the page tools:
//!
//! * `/search/developer`: issues, pull requests, READMEs (GitHub hits classified by URL) and docs;
//! * `/search/gov`: web hits restricted to government hosts;
//! * `/search/research/papers`: scholarly hits with canonical ids (`arxiv:`, `doi:`, `pmid:`,
//!   `pmcid:`, else `web:<url>`); `/papers/{id}` fetches metadata, or with `query` the passages of
//!   the paper that best match it (lexical scoring, deterministic); `/papers/{id}/similar` searches
//!   for related papers (`similar`), papers citing it (`citers`) or its references.
//!
//! Filters the web backend cannot honour (stars, licenses, courts, date ranges, ...) are listed in
//! the response `warning` rather than silently dropped.

use crate::auth::Principal;
use crate::errors::{ApiResult, Detail, HttpError};
use crate::intel::common;
use crate::intel::request::Body;
use crate::intel::search::{SearchCategory, SearchQuery, SearchResults, WebHit};
use crate::intel::usage::{self, Cost};
use crate::state::AppState;
use crate::store::Scope;
use crate::util::{json_response, JsonBody, Params};
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::Response;
use axum::Extension;
use serde_json::{json, Map, Value};
use std::collections::BTreeMap;
use uuid::Uuid;

const DEV_TYPES: [&str; 4] = ["doc", "issue", "pull_request", "readme"];

/// Parameters of an index query, from the query string (GET, lists comma-separated) or a JSON body.
#[derive(Debug, Default)]
struct IndexParams {
    query: String,
    k: usize,
    lists: BTreeMap<String, Vec<String>>,
    scalars: BTreeMap<String, String>,
}

impl IndexParams {
    fn list(&self, key: &str) -> &[String] {
        self.lists.get(key).map_or(&[], Vec::as_slice)
    }

    fn scalar(&self, key: &str) -> Option<&str> {
        self.scalars.get(key).map(String::as_str)
    }

    fn from_query(p: &Params, list_keys: &[&str], default_k: usize, max_k: u64) -> ApiResult<Self> {
        let mut details = Vec::new();
        let query = p.get("query").map(str::trim).unwrap_or_default().to_owned();
        if query.is_empty() {
            details.push(Detail::new("/query", "required", "query is required"));
        }
        let k = match p.get("k") {
            None => default_k,
            Some(s) => match s.parse::<u64>() {
                Ok(n) if (1..=max_k).contains(&n) => usize::try_from(n).unwrap_or(default_k),
                _ => {
                    details.push(Detail::new(
                        "/k",
                        "out_of_range",
                        format!("expected 1 to {max_k}"),
                    ));
                    default_k
                }
            },
        };
        if !details.is_empty() {
            return Err(HttpError::validation(details));
        }
        let mut out = Self {
            query,
            k,
            ..Self::default()
        };
        for (key, value) in &p.0 {
            if key == "query" || key == "k" {
                continue;
            }
            if list_keys.contains(&key.as_str()) {
                let items = value
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect();
                out.lists.insert(key.clone(), items);
            } else {
                out.scalars.insert(key.clone(), value.clone());
            }
        }
        Ok(out)
    }

    fn from_body(body: &Value, list_keys: &[&str], default_k: usize, max_k: u64) -> ApiResult<Self> {
        let mut b = Body::new(body)?;
        let query = b.required_string("query", 1000).unwrap_or_default();
        let k = b
            .integer("k", 1, max_k)
            .map_or(default_k, |n| usize::try_from(n).unwrap_or(default_k));
        let mut out = Self {
            query,
            k,
            ..Self::default()
        };
        if let Some(map) = body.as_object() {
            for (key, value) in map {
                if key == "query" || key == "k" || value.is_null() {
                    continue;
                }
                if list_keys.contains(&key.as_str()) {
                    if let Some(items) = b.strings(key, 100, 512) {
                        out.lists.insert(key.clone(), items);
                    }
                } else {
                    let text = match value {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    out.scalars.insert(key.clone(), text);
                }
            }
        }
        b.finish()?;
        Ok(out)
    }
}

fn warning(items: &[String]) -> Value {
    if items.is_empty() {
        Value::Null
    } else {
        Value::String(items.join("; "))
    }
}

/// `scalars` keys set that the web backend cannot filter on, as warning text.
fn ignored(p: &IndexParams, keys: &[&str]) -> Vec<String> {
    let set: Vec<&str> = keys
        .iter()
        .copied()
        .filter(|k| p.scalars.contains_key(*k) || p.lists.contains_key(*k))
        .collect();
    if set.is_empty() {
        Vec::new()
    } else {
        vec![format!(
            "filters not supported by the configured search backend were ignored: {}",
            set.join(", ")
        )]
    }
}

async fn run(
    state: &AppState,
    query_text: &str,
    limit: usize,
    categories: Vec<SearchCategory>,
    include: Vec<String>,
) -> ApiResult<SearchResults> {
    let provider = common::search(state)?;
    let mut q = SearchQuery::web(query_text, limit);
    q.categories = categories;
    q.include_domains = include;
    provider.search(&q).await.map_err(|e| common::search_error(&e))
}

// ---- developer -----------------------------------------------------------------------------------

/// Kind and stable id of a hit, by URL.
fn developer_kind(url: &str) -> (&'static str, String) {
    let parsed = url::Url::parse(url).ok();
    let github = parsed.as_ref().is_some_and(|u| {
        u.host_str()
            .is_some_and(|h| h.eq_ignore_ascii_case("github.com") || h.eq_ignore_ascii_case("www.github.com"))
    });
    if github {
        if let Some(u) = &parsed {
            let seg: Vec<&str> = u.path_segments().map(Iterator::collect).unwrap_or_default();
            if let [owner, repo, kind, number, ..] = seg.as_slice() {
                match *kind {
                    "issues" => return ("issue", format!("issue:{owner}/{repo}#{number}")),
                    "pull" => return ("pull_request", format!("pull_request:{owner}/{repo}#{number}")),
                    _ => {}
                }
            }
            if let [owner, repo, rest @ ..] = seg.as_slice() {
                let readme = rest.is_empty()
                    || rest
                        .last()
                        .is_some_and(|f| f.to_ascii_lowercase().starts_with("readme"));
                if readme {
                    return ("readme", format!("readme:{owner}/{repo}"));
                }
            }
        }
    }
    ("doc", format!("doc:{url}"))
}

async fn developer(state: AppState, principal: Principal, p: IndexParams) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let wanted: Vec<String> = if p.list("types").is_empty() {
        DEV_TYPES.iter().map(|s| (*s).to_owned()).collect()
    } else {
        let bad: Vec<&String> = p
            .list("types")
            .iter()
            .filter(|t| !DEV_TYPES.contains(&t.as_str()))
            .collect();
        if !bad.is_empty() {
            return Err(HttpError::validation(vec![Detail::new(
                "/types",
                "invalid",
                "expected doc, issue, pull_request or readme",
            )]));
        }
        p.list("types").to_vec()
    };
    let wants_repo = wanted.iter().any(|t| t != "doc");
    let wants_doc = wanted.iter().any(|t| t == "doc");
    let mut coverage: Map<String, Value> = DEV_TYPES
        .iter()
        .map(|t| ((*t).to_owned(), json!("skipped")))
        .collect();
    let mut hits: Vec<WebHit> = Vec::new();
    let mut last_error = None;
    let mut served = 0_u32;
    if wants_repo {
        let repos = p.list("repos");
        let text = if repos.is_empty() {
            p.query.clone()
        } else {
            let sites: Vec<String> = repos.iter().map(|r| format!("site:github.com/{r}")).collect();
            format!("{} ({})", p.query, sites.join(" OR "))
        };
        match run(
            &state,
            &text,
            p.k.saturating_mul(2),
            vec![SearchCategory::Github],
            vec!["github.com".to_owned()],
        )
        .await
        {
            Ok(r) => {
                let in_repo = |url: &str| {
                    let u = url.to_ascii_lowercase();
                    repos.is_empty()
                        || repos
                            .iter()
                            .any(|repo| u.contains(&format!("github.com/{}", repo.to_ascii_lowercase())))
                };
                hits.extend(r.web.into_iter().filter(|h| in_repo(&h.url)));
                served += 1;
                for t in wanted.iter().filter(|t| *t != "doc") {
                    coverage.insert(t.clone(), json!("ok"));
                }
            }
            Err(e) => {
                for t in wanted.iter().filter(|t| *t != "doc") {
                    coverage.insert(t.clone(), json!("unavailable"));
                }
                last_error = Some(e);
            }
        }
    }
    if wants_doc {
        let include: Vec<String> = p.list("sources").to_vec();
        match run(
            &state,
            &p.query,
            p.k.saturating_mul(2),
            vec![SearchCategory::Developer],
            include,
        )
        .await
        {
            Ok(r) => {
                hits.extend(r.web);
                served += 1;
                coverage.insert("doc".to_owned(), json!("ok"));
            }
            Err(e) => {
                coverage.insert("doc".to_owned(), json!("unavailable"));
                last_error = Some(e);
            }
        }
    }
    if served == 0 {
        if let Some(e) = last_error {
            return Err(e);
        }
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut results = Vec::new();
    for h in &hits {
        let (kind, id) = developer_kind(&h.url);
        if !wanted.iter().any(|t| t == kind) || !seen.insert(id.clone()) {
            continue;
        }
        results.push(json!({
            "id": id,
            "type": kind,
            "url": h.url,
            "passages": [{ "text": if h.description.is_empty() { h.title.clone() } else { h.description.clone() } }],
        }));
        if results.len() >= p.k {
            break;
        }
    }
    let warn = ignored(
        &p,
        &[
            "skills",
            "passages",
            "language",
            "topic",
            "license",
            "min_stars",
            "max_stars",
            "archived",
            "fork",
        ],
    );
    usage::record(
        &state,
        principal.tenant,
        "search",
        Some(Uuid::now_v7()),
        "completed",
        Cost::credits(2),
    )
    .await;
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "success": true,
            "results": results,
            "coverage": coverage,
            "reranked": false,
            "warning": warning(&warn),
        }),
    ))
}

const DEV_LISTS: [&str; 3] = ["types", "repos", "sources"];

/// `GET /compat/v2/search/developer` (list parameters comma-separated).
///
/// # Errors
/// `403`, `422` (missing `query`, bad `k` or `types`), `503 search_not_configured`, `502/504`
/// backend failures.
pub async fn developer_get(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    params: Params,
) -> ApiResult<Response> {
    developer(
        state,
        principal,
        IndexParams::from_query(&params, &DEV_LISTS, 10, 100)?,
    )
    .await
}

/// `POST /compat/v2/search/developer`.
///
/// # Errors
/// As [`developer_get`].
pub async fn developer_post(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    developer(
        state,
        principal,
        IndexParams::from_body(&body, &DEV_LISTS, 10, 100)?,
    )
    .await
}

// ---- gov ---------------------------------------------------------------------------------------------

async fn gov(state: AppState, principal: Principal, p: IndexParams) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let include: Vec<String> = p.scalar("domain").map(|d| vec![d.to_owned()]).unwrap_or_default();
    let r = run(&state, &p.query, p.k, vec![SearchCategory::Gov], include).await?;
    let web: Vec<Value> = r
        .web
        .iter()
        .map(|h| {
            json!({
                "url": h.url,
                "description": if h.description.is_empty() { &h.title } else { &h.description },
                "position": h.position,
            })
        })
        .collect();
    let mut warn = ignored(&p, &["jurisdiction", "court", "courtType", "cites"]);
    warn.extend(r.warnings);
    usage::record(
        &state,
        principal.tenant,
        "search",
        Some(Uuid::now_v7()),
        "completed",
        Cost::credits(2),
    )
    .await;
    Ok(json_response(
        StatusCode::OK,
        &json!({ "success": true, "data": { "web": web }, "warning": warning(&warn) }),
    ))
}

/// `GET /compat/v2/search/gov`.
///
/// # Errors
/// `403`, `422`, `503 search_not_configured`, `502/504` backend failures.
pub async fn gov_get(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    params: Params,
) -> ApiResult<Response> {
    gov(state, principal, IndexParams::from_query(&params, &[], 10, 100)?).await
}

/// `POST /compat/v2/search/gov`.
///
/// # Errors
/// As [`gov_get`].
pub async fn gov_post(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    JsonBody(body): JsonBody,
) -> ApiResult<Response> {
    gov(state, principal, IndexParams::from_body(&body, &[], 10, 100)?).await
}

// ---- research ------------------------------------------------------------------------------------

/// `(primaryId, ids)` of a result URL.
fn paper_ids(url: &str) -> (String, Map<String, Value>) {
    let mut ids = Map::new();
    let Ok(u) = url::Url::parse(url) else {
        return (format!("web:{url}"), ids);
    };
    let host = u.host_str().unwrap_or_default().to_ascii_lowercase();
    let path = u.path().trim_matches('/');
    let tail = |prefix: &str| {
        path.strip_prefix(prefix)
            .map(|s| s.trim_end_matches(".pdf").to_owned())
    };
    if host.ends_with("arxiv.org") {
        if let Some(id) = tail("abs/").or_else(|| tail("pdf/")) {
            ids.insert("arxiv".to_owned(), json!([id]));
            return (format!("arxiv:{id}"), ids);
        }
    }
    if host == "doi.org" || host == "dx.doi.org" {
        ids.insert("doi".to_owned(), json!([path]));
        return (format!("doi:{path}"), ids);
    }
    if host == "pubmed.ncbi.nlm.nih.gov" && path.chars().all(|c| c.is_ascii_digit()) && !path.is_empty() {
        ids.insert("pmid".to_owned(), json!([path]));
        return (format!("pmid:{path}"), ids);
    }
    if host.ends_with("ncbi.nlm.nih.gov") {
        if let Some(id) = path.split('/').find(|s| s.starts_with("PMC")) {
            ids.insert("pmcid".to_owned(), json!([id]));
            return (format!("pmcid:{id}"), ids);
        }
    }
    (format!("web:{url}"), ids)
}

fn paper_json(h: &WebHit) -> Value {
    let (primary, ids) = paper_ids(&h.url);
    // reciprocal-rank score in (0, 1]; the backend returns no relevance number
    let score = 1.0 / (f64::from(h.position.max(1)));
    json!({
        "paperId": primary,
        "primaryId": primary,
        "ids": ids,
        "title": h.title,
        "abstract": h.description,
        "score": score,
    })
}

/// `GET /compat/v2/search/research/papers`.
///
/// # Errors
/// `403`, `422` (missing `query`, `k` outside 1 to 500), `503 search_not_configured`, `502/504`.
pub async fn papers(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let p = IndexParams::from_query(&params, &["categories"], 40, 500)?;
    let mut text = p.query.clone();
    if let Some(a) = p.scalar("authors") {
        text.push_str(&format!(" {a}"));
    }
    let r = run(&state, &text, p.k, vec![SearchCategory::Research], Vec::new()).await?;
    let results: Vec<Value> = r.web.iter().map(paper_json).collect();
    let mut warn = ignored(&p, &["categories", "from", "to"]);
    warn.extend(r.warnings);
    usage::record(
        &state,
        principal.tenant,
        "search",
        Some(Uuid::now_v7()),
        "completed",
        Cost::credits(2),
    )
    .await;
    Ok(json_response(
        StatusCode::OK,
        &json!({ "success": true, "results": results, "warning": warning(&warn) }),
    ))
}

/// Pages that describe paper `id`: `(abstract page, full-text page)`.
fn paper_urls(id: &str) -> Option<(String, String)> {
    let (ns, rest) = id.split_once(':')?;
    let rest = rest.trim();
    if rest.is_empty() {
        return None;
    }
    match ns {
        "arxiv" => Some((
            format!("https://arxiv.org/abs/{rest}"),
            format!("https://arxiv.org/pdf/{rest}"),
        )),
        "doi" => Some((
            format!("https://doi.org/{rest}"),
            format!("https://doi.org/{rest}"),
        )),
        "pmid" => Some((
            format!("https://pubmed.ncbi.nlm.nih.gov/{rest}/"),
            format!("https://pubmed.ncbi.nlm.nih.gov/{rest}/"),
        )),
        "pmcid" => Some((
            format!("https://www.ncbi.nlm.nih.gov/pmc/articles/{rest}/"),
            format!("https://www.ncbi.nlm.nih.gov/pmc/articles/{rest}/"),
        )),
        "web" if crate::intel::request::is_http_url(rest) => Some((rest.to_owned(), rest.to_owned())),
        _ => None,
    }
}

fn first_text(meta: &Value, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| {
        let v = meta.get(*k)?;
        match v {
            Value::String(s) if !s.trim().is_empty() => Some(s.trim().to_owned()),
            Value::Array(a) => {
                let parts: Vec<&str> = a.iter().filter_map(Value::as_str).collect();
                Some(parts.join(", ")).filter(|s| !s.is_empty())
            }
            _ => None,
        }
    })
}

fn paper_metadata(id: &str, document: &Value) -> Value {
    let meta = document.get("metadata").cloned().unwrap_or(Value::Null);
    let markdown = document
        .get("markdown")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let abstract_text = first_text(&meta, &["citation_abstract", "description", "og:description"])
        .unwrap_or_else(|| {
            markdown
                .split("\n\n")
                .find(|p| p.len() > 80)
                .unwrap_or_default()
                .to_owned()
        });
    let (ns, rest) = id.split_once(':').unwrap_or(("web", id));
    let mut ids = Map::new();
    ids.insert(ns.to_owned(), json!([rest]));
    json!({
        "paperId": id,
        "ids": ids,
        "title": first_text(&meta, &["citation_title", "title", "og:title"]).unwrap_or_default(),
        "abstract": abstract_text,
        "authors": first_text(&meta, &["citation_author", "author"]).unwrap_or_default(),
        "categories": meta.get("categories").cloned().unwrap_or_else(|| json!([])),
        "createdDate": first_text(&meta, &["citation_publication_date", "citation_date", "article:published_time"]).unwrap_or_default(),
        "updateDate": first_text(&meta, &["citation_online_date", "article:modified_time"]).unwrap_or_default(),
    })
}

/// Lowercased alphanumeric tokens of at least two characters.
fn tokens(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.chars().count() >= 2)
        .map(str::to_lowercase)
        .collect()
}

/// The `k` paragraphs of `markdown` with the highest query-term coverage, as `(text, score)`;
/// score is the covered share of distinct query terms weighted by term frequency saturation.
fn rank_passages(markdown: &str, query: &str, k: usize) -> Vec<(String, f64)> {
    let terms: std::collections::BTreeSet<String> = tokens(query).into_iter().collect();
    if terms.is_empty() {
        return Vec::new();
    }
    let mut scored: Vec<(usize, String, f64)> = Vec::new();
    for (i, para) in markdown
        .split("\n\n")
        .map(str::trim)
        .filter(|p| p.len() >= 40)
        .enumerate()
    {
        let toks = tokens(para);
        let mut score = 0.0_f64;
        for t in &terms {
            let tf = toks.iter().filter(|x| *x == t).count();
            if tf > 0 {
                // saturating term frequency, as BM25 with k1 = 1.2 and no length normalisation
                let tf = f64::from(u32::try_from(tf).unwrap_or(u32::MAX));
                score += (tf * 2.2) / (tf + 1.2);
            }
        }
        if score > 0.0 {
            let norm = f64::from(u32::try_from(terms.len()).unwrap_or(u32::MAX)) * 2.2;
            scored.push((i, para.to_owned(), score / norm));
        }
    }
    scored.sort_by(|a, b| b.2.total_cmp(&a.2).then(a.0.cmp(&b.0)));
    scored.into_iter().take(k).map(|(_, t, s)| (t, s)).collect()
}

/// `GET /compat/v2/search/research/papers/{paperId}`: metadata, or with `query` the
/// best matching passages of the full text (`k`, default 4, at most 50).
///
/// # Errors
/// `403`, `404 not_found` for an unknown id namespace or an unreachable paper, `422`.
pub async fn paper(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(paper_id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let (abs_url, text_url) = paper_urls(&paper_id).ok_or_else(|| HttpError::not_found("paper"))?;
    let tools = common::tools(&state)?;
    let options = json!({ "formats": ["markdown"], "onlyMainContent": true });
    let page = tools
        .scrape(principal.tenant, &abs_url, &options)
        .await
        .map_err(|_| HttpError::not_found("paper"))?;
    let meta = paper_metadata(&paper_id, &page.document);
    let mut credits = page.credits;
    let body = match params.get("query").map(str::trim).filter(|q| !q.is_empty()) {
        None => json!({ "success": true, "paper": meta }),
        Some(query) => {
            let k = match params.get("k") {
                None => 4,
                Some(s) => match s.parse::<usize>() {
                    Ok(n) if (1..=50).contains(&n) => n,
                    _ => {
                        return Err(HttpError::validation(vec![Detail::new(
                            "/k",
                            "out_of_range",
                            "expected 1 to 50",
                        )]))
                    }
                },
            };
            let full = if text_url == abs_url {
                page
            } else {
                let p = tools
                    .scrape(principal.tenant, &text_url, &options)
                    .await
                    .map_err(|_| HttpError::not_found("paper full text"))?;
                credits = credits.saturating_add(p.credits);
                p
            };
            let passages: Vec<Value> = rank_passages(full.markdown(), query, k)
                .into_iter()
                .map(|(text, score)| json!({ "text": text, "score": score }))
                .collect();
            json!({
                "success": true,
                "paper": meta,
                "paperId": paper_id,
                "query": query,
                "passages": passages,
            })
        }
    };
    usage::record(
        &state,
        principal.tenant,
        "search",
        Some(Uuid::now_v7()),
        "completed",
        Cost::credits(credits),
    )
    .await;
    Ok(json_response(StatusCode::OK, &body))
}

/// `GET /compat/v2/search/research/papers/{paperId}/similar` (`intent` required, `mode`
/// `similar|citers|references`, `k` up to 500, optional `anchor` text instead of the fetched title).
///
/// # Errors
/// `403`, `404`, `422`, `503 search_not_configured`, `502/504` backend failures.
pub async fn similar(
    State(state): State<AppState>,
    Extension(principal): Extension<Principal>,
    Path(paper_id): Path<String>,
    params: Params,
) -> ApiResult<Response> {
    principal.require(Scope::CrawlsWrite)?;
    let intent = params.get("intent").map(str::trim).filter(|s| !s.is_empty());
    let Some(intent) = intent else {
        return Err(HttpError::validation(vec![Detail::new(
            "/intent",
            "required",
            "intent is required",
        )]));
    };
    let mode = params.get("mode").unwrap_or("similar");
    if !matches!(mode, "similar" | "citers" | "references") {
        return Err(HttpError::validation(vec![Detail::new(
            "/mode",
            "invalid",
            "expected similar, citers or references",
        )]));
    }
    let k = match params.get("k") {
        None => 40,
        Some(s) => match s.parse::<usize>() {
            Ok(n) if (1..=500).contains(&n) => n,
            _ => {
                return Err(HttpError::validation(vec![Detail::new(
                    "/k",
                    "out_of_range",
                    "expected 1 to 500",
                )]))
            }
        },
    };
    let (abs_url, _) = paper_urls(&paper_id).ok_or_else(|| HttpError::not_found("paper"))?;
    let anchor = match params.get("anchor").map(str::trim).filter(|a| !a.is_empty()) {
        Some(a) => a.to_owned(),
        None => {
            let tools = common::tools(&state)?;
            let page = tools
                .scrape(
                    principal.tenant,
                    &abs_url,
                    &json!({ "formats": ["markdown"], "onlyMainContent": true }),
                )
                .await
                .map_err(|_| HttpError::not_found("paper"))?;
            paper_metadata(&paper_id, &page.document)["title"]
                .as_str()
                .unwrap_or_default()
                .to_owned()
        }
    };
    let text = match mode {
        "citers" => format!("\"{anchor}\" cited by {intent}"),
        "references" => format!("\"{anchor}\" references bibliography {intent}"),
        _ => format!("{intent} {anchor}"),
    };
    let r = run(
        &state,
        &text,
        k.saturating_add(1),
        vec![SearchCategory::Research],
        Vec::new(),
    )
    .await?;
    let results: Vec<Value> = r
        .web
        .iter()
        .filter(|h| paper_ids(&h.url).0 != paper_id)
        .take(k)
        .map(paper_json)
        .collect();
    let mut warn = r.warnings;
    if params.get("rerank").is_some() {
        warn.push("rerank is not supported by the configured search backend; ignored".to_owned());
    }
    usage::record(
        &state,
        principal.tenant,
        "search",
        Some(Uuid::now_v7()),
        "completed",
        Cost::credits(2),
    )
    .await;
    Ok(json_response(
        StatusCode::OK,
        &json!({
            "success": true,
            "results": results,
            "poolSize": r.web.len(),
            "truncated": false,
            "note": warning(&warn),
        }),
    ))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn github_urls_are_classified() {
        assert_eq!(
            developer_kind("https://github.com/o/r/issues/12").1,
            "issue:o/r#12"
        );
        assert_eq!(developer_kind("https://github.com/o/r/pull/3").0, "pull_request");
        assert_eq!(developer_kind("https://github.com/o/r").0, "readme");
        assert_eq!(
            developer_kind("https://github.com/o/r/blob/main/README.md").0,
            "readme"
        );
        assert_eq!(
            developer_kind("https://github.com/o/r/blob/main/src/lib.rs").0,
            "doc"
        );
        assert_eq!(developer_kind("https://docs.rs/x").0, "doc");
    }

    #[test]
    fn paper_ids_by_host() {
        assert_eq!(
            paper_ids("https://arxiv.org/abs/2401.00001").0,
            "arxiv:2401.00001"
        );
        assert_eq!(
            paper_ids("https://arxiv.org/pdf/2401.00001.pdf").0,
            "arxiv:2401.00001"
        );
        assert_eq!(paper_ids("https://doi.org/10.1000/xyz").0, "doi:10.1000/xyz");
        assert_eq!(paper_ids("https://pubmed.ncbi.nlm.nih.gov/123/").0, "pmid:123");
        assert_eq!(
            paper_ids("https://www.ncbi.nlm.nih.gov/pmc/articles/PMC999/").0,
            "pmcid:PMC999"
        );
        assert_eq!(paper_ids("https://example.org/p").0, "web:https://example.org/p");
    }

    #[test]
    fn paper_urls_resolve_namespaces() {
        assert_eq!(
            paper_urls("arxiv:2401.1").unwrap().1,
            "https://arxiv.org/pdf/2401.1"
        );
        assert_eq!(paper_urls("web:https://a.org/p").unwrap().0, "https://a.org/p");
        assert!(
            paper_urls("nope:1").is_none()
                && paper_urls("arxiv:").is_none()
                && paper_urls("web:javascript:x").is_none()
        );
    }

    #[test]
    fn passages_are_ranked_by_term_coverage() {
        let md = "Intro paragraph about something unrelated to the topic at all here.\n\n\
                  Transformers use attention heads; attention is all you need for sequence modelling.\n\n\
                  A third paragraph mentions attention only once but nothing else of interest to us.";
        let r = rank_passages(md, "attention heads", 2);
        assert_eq!(r.len(), 2);
        assert!(r[0].0.starts_with("Transformers") && r[0].1 > r[1].1);
        assert!(rank_passages(md, "zzzz", 2).is_empty());
        assert!(
            rank_passages(md, "a", 2).is_empty(),
            "single-character terms are ignored"
        );
    }
}
