//! Query-string drift: the parameters documented for an operation are the ones its handler reads.
//!
//! The handlers of the pagination and listing operations read `Params` by literal name, so their
//! sources are scanned. The search indexes take any parameter, so each documented one is exercised
//! against the real handler.

use super::rigs::*;
use super::*;

/// The query parameters an operation documents.
fn documented_query(doc: &Value, id: &str) -> BTreeSet<String> {
    let (_, _, op) = op_by_id(doc, id);
    op["parameters"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["in"] == "query")
        .map(|p| p["name"].as_str().unwrap().to_owned())
        .collect()
}

/// The names a handler source reads from `Params`.
fn query_literals(src: &str) -> BTreeSet<String> {
    let src: String = src
        .split("#[cfg(test)]")
        .next()
        .unwrap()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let src = src.as_str();
    let mut out = BTreeSet::new();
    let quoted_at = |rest: &str| -> Option<String> {
        let rest = rest.trim_start().strip_prefix('"')?;
        Some(rest[..rest.find('"')?].to_owned())
    };
    for (i, _) in src.match_indices("params.get(") {
        if let Some(name) = quoted_at(&src[i + "params.get(".len()..]) {
            out.insert(name);
        }
    }
    for call in ["int_param(", "enum_param(", "number_param("] {
        for (i, _) in src.match_indices(call) {
            let rest = src[i + call.len()..].trim_start();
            if let Some(rest) = rest.strip_prefix("&params") {
                if let Some(rest) = rest.trim_start().strip_prefix(',') {
                    if let Some(name) = quoted_at(rest) {
                        out.insert(name);
                    }
                }
            }
        }
    }
    if src.contains("params.limit(") {
        out.insert("limit".to_owned());
    }
    if src.contains("params.cursor_key(") {
        out.insert("cursor".to_owned());
    }
    out
}

#[test]
fn documented_query_parameters_are_the_ones_the_handlers_read() {
    let doc = doc();
    let handlers: [(&str, &[&str]); 5] = [
        (include_str!("../../src/routes/compat.rs"), &["firecrawlGetCrawl"]),
        (
            include_str!("../../src/routes/compat_scrape.rs"),
            &["firecrawlBatchScrapeStatus"],
        ),
        (
            include_str!("../../src/routes/compat_agent.rs"),
            &["firecrawlListAgents", "firecrawlGetAgentTrace"],
        ),
        (
            include_str!("../../src/routes/compat_monitor.rs"),
            &["listMonitors", "listMonitorChecks", "getMonitorCheck"],
        ),
        (
            include_str!("../../src/routes/compat_team.rs"),
            &["firecrawlActivity"],
        ),
    ];
    for (src, ids) in handlers {
        let documented: BTreeSet<String> = ids.iter().flat_map(|id| documented_query(&doc, id)).collect();
        let read = query_literals(src);
        assert!(!read.is_empty(), "{ids:?}: the scan found nothing");
        assert_eq!(
            documented, read,
            "{ids:?}: documented query parameters vs the handler's source"
        );
    }
}

fn detail_paths(r: &Reply) -> Vec<String> {
    r.body["details"]
        .as_array()
        .map(|d| {
            d.iter()
                .map(|x| x["path"].as_str().unwrap_or_default().to_owned())
                .collect()
        })
        .unwrap_or_default()
}

#[tokio::test]
async fn query_parameters_of_the_search_indexes_are_read() {
    let doc = doc();
    let t = intel(None);
    t.tools.set_markdown(
        "https://arxiv.org/abs/2401.00001",
        "Attention is all you need.\n\nAn attention mechanism relates positions of a sequence. It is the whole paper and a long enough paragraph to be a passage.",
    );
    t.tools.set_markdown(
        "https://arxiv.org/pdf/2401.00001",
        "Attention is all you need.\n\nAn attention mechanism relates positions of a sequence. It is the whole paper and a long enough paragraph to be a passage.",
    );
    let mut exercised: BTreeMap<&str, BTreeSet<&str>> = BTreeMap::new();
    let mut mark = |id: &'static str, names: &[&'static str]| {
        exercised.entry(id).or_default().extend(names.iter().copied());
    };

    // developer
    let r = t.get("/search/developer?k=3").await;
    assert_eq!(r.status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(detail_paths(&r).contains(&"/query".to_owned()), "{}", r.body);
    let r = t.get("/search/developer?query=x&k=0").await;
    assert!(detail_paths(&r).contains(&"/k".to_owned()), "{}", r.body);
    let r = t.get("/search/developer?query=x&types=nope").await;
    assert!(detail_paths(&r).contains(&"/types".to_owned()), "{}", r.body);
    let r = t
        .get("/search/developer?query=tokio&k=3&types=doc,issue&repos=a/b&sources=docs.rs&skills=1&passages=1&language=rust&topic=t&license=mit&min_stars=1&max_stars=2&archived=true&fork=false")
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let ignored = [
        "skills",
        "passages",
        "language",
        "topic",
        "license",
        "min_stars",
        "max_stars",
        "archived",
        "fork",
    ];
    let warning = r.body["warning"].as_str().unwrap();
    for k in ignored {
        assert!(warning.contains(k), "{k} in {warning}");
    }
    let queries = t.search.queries();
    assert!(
        queries.iter().any(|q| q.query.contains("site:github.com/a/b")),
        "repos"
    );
    assert!(
        queries.iter().any(|q| q.include_domains == ["docs.rs"]),
        "sources"
    );
    mark(
        "firecrawlSearchDeveloperGet",
        &[
            "query",
            "k",
            "types",
            "repos",
            "sources",
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

    // gov
    let r = t.get("/search/gov").await;
    assert!(detail_paths(&r).contains(&"/query".to_owned()), "{}", r.body);
    let r = t.get("/search/gov?query=x&k=0").await;
    assert!(detail_paths(&r).contains(&"/k".to_owned()), "{}", r.body);
    let r = t
        .get("/search/gov?query=tax&k=3&domain=irs.gov&jurisdiction=us&court=c&courtType=t&cites=x")
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let warning = r.body["warning"].as_str().unwrap();
    for k in ["jurisdiction", "court", "courtType", "cites"] {
        assert!(warning.contains(k), "{k} in {warning}");
    }
    assert_eq!(
        t.search.queries().last().unwrap().include_domains,
        ["irs.gov"],
        "domain"
    );
    mark(
        "firecrawlSearchGovGet",
        &[
            "query",
            "k",
            "domain",
            "jurisdiction",
            "court",
            "courtType",
            "cites",
        ],
    );

    // papers
    let r = t.get("/search/research/papers?query=x&k=0").await;
    assert!(detail_paths(&r).contains(&"/k".to_owned()), "{}", r.body);
    let r = t
        .get("/search/research/papers?query=attention&k=3&authors=Vaswani&categories=cs&from=2017&to=2018")
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert!(
        t.search.queries().last().unwrap().query.contains("Vaswani"),
        "authors"
    );
    let warning = r.body["warning"].as_str().unwrap();
    for k in ["categories", "from", "to"] {
        assert!(warning.contains(k), "{k} in {warning}");
    }
    mark(
        "firecrawlResearchPapers",
        &["query", "k", "authors", "categories", "from", "to"],
    );

    // one paper
    let r = t
        .get("/search/research/papers/arxiv:2401.00001?query=attention&k=1")
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    assert_eq!(r.body["query"], "attention");
    assert!(r.body["passages"].as_array().unwrap().len() <= 1, "k");
    let r = t
        .get("/search/research/papers/arxiv:2401.00001?query=attention&k=0")
        .await;
    assert!(detail_paths(&r).contains(&"/k".to_owned()), "{}", r.body);
    mark("firecrawlResearchPaper", &["query", "k"]);

    // similar papers
    let r = t.get("/search/research/papers/arxiv:2401.00001/similar").await;
    assert!(detail_paths(&r).contains(&"/intent".to_owned()), "{}", r.body);
    let r = t
        .get("/search/research/papers/arxiv:2401.00001/similar?intent=x&mode=zz")
        .await;
    assert!(detail_paths(&r).contains(&"/mode".to_owned()), "{}", r.body);
    let r = t
        .get("/search/research/papers/arxiv:2401.00001/similar?intent=x&k=0")
        .await;
    assert!(detail_paths(&r).contains(&"/k".to_owned()), "{}", r.body);
    let r = t
        .get("/search/research/papers/arxiv:2401.00001/similar?intent=methods&mode=citers&k=2&anchor=Transformers&rerank=true")
        .await;
    assert_eq!(r.status, StatusCode::OK, "{}", r.body);
    let q = t.search.queries().last().unwrap().query.clone();
    assert!(
        q.contains("Transformers") && q.contains("cited by") && q.contains("methods"),
        "anchor, mode, intent: {q}"
    );
    assert!(r.body["note"].as_str().unwrap().contains("rerank"), "{}", r.body);
    mark(
        "firecrawlResearchSimilar",
        &["intent", "mode", "k", "anchor", "rerank"],
    );

    for (id, names) in &exercised {
        let documented = documented_query(&doc, id);
        let exercised: BTreeSet<String> = names.iter().map(|n| (*n).to_owned()).collect();
        assert_eq!(
            documented, exercised,
            "{id}: documented vs exercised query parameters"
        );
    }
}
