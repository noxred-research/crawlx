//! Behavioral request-schema agreement.
//!
//! Examples must validate against the documented schema and be accepted by the
//! real parser or handler. Unknown keys and wrongly typed supplied properties
//! must be rejected where the endpoint promises strict validation.
//!
//! Examples are representative contracts, not an exhaustive inventory of every
//! schema property or enum member. Parser source layout and private key-list
//! constants are deliberately not part of the public API contract.

use super::rigs::*;
use super::*;

#[test]
fn selector_wait_schema_accepts_optional_states_but_not_null() {
    let document = doc();
    let operation = &document["paths"][format!("{V2}/scrape")]["post"];
    let (_, schema) = request_schema(operation).unwrap();
    let validate = validator(&document, &schema);
    let mut request = json!({
        "url": "https://example.test/",
        "actions": [{"type": "wait", "selector": "#ready"}],
    });
    assert!(
        validate.is_valid(&request),
        "{:?}",
        errors_of(&validate, &request)
    );
    for state in ["attached", "visible", "hidden", "detached"] {
        request["actions"][0]["state"] = json!(state);
        assert!(
            validate.is_valid(&request),
            "{:?}",
            errors_of(&validate, &request)
        );
    }
    request["actions"][0]["state"] = Value::Null;
    assert!(!validate.is_valid(&request));
}

// ---- walking schemas and examples ----------------------------------------------------------------

/// What a request schema says, by *schema path*: `/a/b` for member `b` of member `a`, `/a[]/b` for
/// member `b` of the elements of array `a`.
#[derive(Default, Debug)]
struct SchemaMap {
    /// Every property, in any branch of any union.
    props: BTreeSet<String>,
    /// Free-form objects (and any-value nodes): their members are not described.
    open: BTreeSet<String>,
}

fn type_has(node: &Value, t: &str) -> bool {
    match &node["type"] {
        Value::String(s) => s == t,
        Value::Array(a) => a.iter().any(|x| x == t),
        _ => false,
    }
}

fn walk_schema(doc: &Value, node: &Value, path: &str, out: &mut SchemaMap, stack: &mut Vec<String>) {
    if let Value::Bool(open) = node {
        if *open {
            out.open.insert(path.to_owned());
        }
        return;
    }
    if let Some(r) = node.get("$ref").and_then(Value::as_str) {
        if stack.iter().any(|s| s == r) {
            return;
        }
        stack.push(r.to_owned());
        walk_schema(doc, deref_one(doc, r), path, out, stack);
        stack.pop();
        return;
    }
    let union = ["anyOf", "oneOf", "allOf"].iter().any(|k| node.get(*k).is_some());
    if let Some(props) = node.get("properties").and_then(Value::as_object) {
        for (k, s) in props {
            let p = format!("{path}/{k}");
            out.props.insert(p.clone());
            walk_schema(doc, s, &p, out, stack);
        }
    }
    match node.get("additionalProperties") {
        None | Some(Value::Bool(false)) => {}
        Some(_) => {
            out.open.insert(path.to_owned());
        }
    }
    let described = [
        "type",
        "properties",
        "items",
        "enum",
        "const",
        "anyOf",
        "oneOf",
        "allOf",
    ]
    .iter()
    .any(|k| node.get(*k).is_some());
    if !described || (type_has(node, "object") && node.get("properties").is_none() && !union) {
        out.open.insert(path.to_owned());
    }
    if let Some(items) = node.get("items") {
        walk_schema(doc, items, &format!("{path}[]"), out, stack);
    }
    for k in ["anyOf", "oneOf", "allOf"] {
        if let Some(branches) = node.get(k).and_then(Value::as_array) {
            for b in branches {
                walk_schema(doc, b, path, out, stack);
            }
        }
    }
}

/// One node of an example.
struct Node {
    pointer: String,
    spath: String,
    /// Reached through an object key (an array element is not a member).
    member: bool,
    value: Value,
}

fn escape(key: &str) -> String {
    key.replace('~', "~0").replace('/', "~1")
}

fn walk_example(v: &Value, pointer: &str, spath: &str, member: bool, out: &mut Vec<Node>) {
    out.push(Node {
        pointer: pointer.to_owned(),
        spath: spath.to_owned(),
        member,
        value: v.clone(),
    });
    match v {
        Value::Object(m) => {
            for (k, x) in m {
                walk_example(
                    x,
                    &format!("{pointer}/{}", escape(k)),
                    &format!("{spath}/{k}"),
                    true,
                    out,
                );
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                walk_example(x, &format!("{pointer}/{i}"), &format!("{spath}[]"), false, out);
            }
        }
        _ => {}
    }
}

/// `spath` is `prefix` or below it.
fn under(spath: &str, prefix: &str) -> bool {
    spath == prefix || spath.starts_with(&format!("{prefix}/")) || spath.starts_with(&format!("{prefix}[]"))
}

/// `spath` lies inside a free-form object.
fn inside_open(map: &SchemaMap, spath: &str) -> bool {
    map.open.iter().any(|o| spath != o && under(spath, o))
}

/// `spath` lies below a subtree another case checks.
fn excluded(spath: &str, skip: &[&str]) -> bool {
    skip.iter().any(|p| spath != *p && under(spath, p))
}

/// Validate representative examples and ensure their keys are documented.
/// Unused optional schema properties do not require incidental example entries.
fn validate_representative_examples(
    doc: &Value,
    what: &str,
    schema: &Value,
    examples: &[Value],
    skip: &[&str],
) -> SchemaMap {
    let mut map = SchemaMap::default();
    walk_schema(doc, schema, "", &mut map, &mut Vec::new());
    let v = validator(doc, schema);
    let mut nodes = Vec::new();
    for e in examples {
        let errs = errors_of(&v, e);
        assert!(
            errs.is_empty(),
            "{what}: an example does not validate against its schema: {errs:?}\n{e}"
        );
        walk_example(e, "", "", false, &mut nodes);
    }
    let in_scope = |p: &str| !excluded(p, skip);
    let schema_props: BTreeSet<&String> = map.props.iter().filter(|p| in_scope(p)).collect();
    let example_props: BTreeSet<&String> = nodes
        .iter()
        .filter(|n| n.member && !inside_open(&map, &n.spath) && in_scope(&n.spath))
        .map(|n| &n.spath)
        .collect();
    let undescribed: Vec<_> = example_props.difference(&schema_props).collect();
    assert!(
        undescribed.is_empty(),
        "{what}: example keys absent from the schema: {undescribed:?}"
    );
    map
}

// ---- cases --------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum Target {
    /// `POST /scrape`: the options parser called directly (the `url` through the route).
    Scrape,
    Crawl,
    Batch,
    Map,
    Search,
    Extract,
    Agent,
    /// The `options` part of `POST /parse`.
    Parse,
    MonitorCreate,
    MonitorPatch,
    SearchFeedback,
    Feedback,
    DeveloperPost,
    GovPost,
    ParamsPreview,
    DocsSearch,
    SupportAsk,
}

struct Example {
    body: Value,
    /// Statuses of an accepted request (`200`, or a later failure such as an unknown thread).
    statuses: &'static [u16],
}

fn ex(body: Value) -> Example {
    Example {
        body,
        statuses: &[200],
    }
}

fn ex_status(body: Value, statuses: &'static [u16]) -> Example {
    Example { body, statuses }
}

struct Case {
    id: &'static str,
    target: Target,
    examples: Vec<Example>,
    /// Schema paths the parser reads without type-checking them.
    silent: &'static [&'static str],
    /// `(alias pointer, pointer the parser blames)`.
    aliases: &'static [(&'static str, &'static str)],
    /// Subtrees another case checks (the shared `ScrapeOptions`).
    skip: &'static [&'static str],
    /// Keys the parser accepts and reports as unsupported on purpose.
    unsupported_ok: &'static [&'static str],
    /// The parser reports unknown keys.
    reports_unknown: bool,
    /// Keys the first example's `warning` text must name (accepted filters the backend ignores).
    warned: &'static [&'static str],
}

fn case(id: &'static str, target: Target, examples: Vec<Example>) -> Case {
    Case {
        id,
        target,
        examples,
        silent: &[],
        aliases: &[],
        skip: &[],
        unsupported_ok: &[],
        reports_unknown: false,
        warned: &[],
    }
}

/// The parent of a JSON Pointer (`""` for a top-level pointer).
fn parent(pointer: &str) -> &str {
    pointer.rfind('/').map_or("", |i| &pointer[..i])
}

/// Does a violation sit at `pointer`, below it, or at its parent (parsers that validate a whole
/// element report the element)?
fn reported_at(details: &[(String, String)], pointer: &str) -> bool {
    let parent = parent(pointer);
    details.iter().any(|(path, _)| {
        path == pointer || path.starts_with(&format!("{pointer}/")) || (!parent.is_empty() && path == parent)
    })
}

fn other_type(v: &Value) -> Option<Value> {
    match v {
        Value::String(_) => Some(json!(12345)),
        Value::Number(_) | Value::Bool(_) | Value::Array(_) | Value::Object(_) => Some(json!("zz")),
        Value::Null => None,
    }
}

impl Rigs {
    /// Send `body` as a request of `target` and report what came back.
    pub async fn send(&self, target: Target, body: &Value) -> Report {
        let ai = &self.ai;
        let reply = match target {
            Target::Scrape => {
                if body.get("url").is_some_and(|u| !u.is_string()) {
                    json_call(
                        &self.plain.app,
                        Some(&self.plain.key),
                        Method::POST,
                        &format!("{V2}/scrape"),
                        Some(body),
                    )
                    .await
                } else {
                    // These are the public scrape request envelope members, not
                    // scrape options; URL type behavior is exercised above.
                    let envelope = ["url", "origin", "integration"];
                    return match crawlx_api::scrape_service::parse_scrape_options_in(
                        body.as_object().unwrap(),
                        "",
                        &envelope,
                    ) {
                        Ok(p) => Report {
                            status: 200,
                            warnings: p
                                .warnings
                                .iter()
                                .map(|w| (w.code.clone(), w.path.clone()))
                                .collect(),
                            ..Report::default()
                        },
                        Err(d) => Report {
                            status: 400,
                            details: d.iter().map(|x| (x.path.clone(), x.code.clone())).collect(),
                            ..Report::default()
                        },
                    };
                }
            }
            Target::Crawl => ai.post("/crawl", body).await,
            Target::Batch => ai.post("/batch/scrape", body).await,
            Target::Map => {
                json_call(
                    &self.rig.env.app,
                    Some(&self.rig.env.key),
                    Method::POST,
                    &format!("{V2}/map"),
                    Some(body),
                )
                .await
            }
            Target::Search => ai.post("/search", body).await,
            Target::Extract => ai.post("/extract", body).await,
            Target::Agent => ai.post("/agent", body).await,
            Target::Parse => upload(&ai.app, &ai.key, Some(body)).await,
            Target::MonitorCreate => ai.post("/monitor", body).await,
            Target::MonitorPatch => {
                let id = self.monitor_id().await;
                ai.call(Method::PATCH, &format!("/monitor/{id}"), Some(body))
                    .await
            }
            Target::SearchFeedback => {
                let id = self.search_job_id().await;
                ai.post(&format!("/search/{id}/feedback"), body).await
            }
            Target::Feedback => ai.post("/feedback", body).await,
            Target::DeveloperPost => ai.post("/search/developer", body).await,
            Target::GovPost => ai.post("/search/gov", body).await,
            Target::ParamsPreview => ai.post("/crawl/params-preview", body).await,
            Target::DocsSearch => ai.post("/support/docs-search", body).await,
            Target::SupportAsk => ai.post("/support/ask", body).await,
        };
        Report::of(&reply)
    }
}

/// The schema a case's examples are checked against: the request body, or for an upload the JSON
/// the `options` part holds.
fn case_schema(doc: &Value, id: &str) -> Value {
    let (_, _, op) = op_by_id(doc, id);
    let (media, schema) = request_schema(op).unwrap_or_else(|| panic!("{id} has no request schema"));
    if media != "multipart/form-data" {
        return schema;
    }
    let upload = resolve(doc, &schema);
    let props = upload["properties"].as_object().unwrap();
    assert_eq!(
        props.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from(["file", "options"]),
        "the parts of the upload"
    );
    assert_eq!(props["file"]["format"], "binary");
    assert_eq!(props["options"]["contentMediaType"], "application/json");
    assert_eq!(upload["required"], json!(["file"]));
    props["options"]["contentSchema"].clone()
}

async fn run_case(rigs: &Rigs, doc: &Value, case: &Case) {
    let id = case.id;
    let schema = case_schema(doc, id);
    let bodies: Vec<Value> = case.examples.iter().map(|e| e.body.clone()).collect();
    let map = validate_representative_examples(doc, id, &schema, &bodies, case.skip);

    // 2. the examples are accepted
    let mut first = None;
    for (i, e) in case.examples.iter().enumerate() {
        let r = rigs.send(case.target, &e.body).await;
        assert!(
            r.details.is_empty() && e.statuses.contains(&r.status),
            "{id}: example {i} was not accepted: {} {:?}\n{}\nresponse: {}",
            r.status,
            r.details,
            e.body,
            r.body
        );
        if i == 0 {
            first = Some(r);
        }
    }
    let first = first.unwrap();
    let flagged: BTreeSet<String> = first
        .unsupported()
        .into_iter()
        .filter(|p| !case.unsupported_ok.contains(&p.as_str()))
        .collect();
    assert!(
        flagged.is_empty(),
        "{id}: the parser reports schema keys as unsupported options: {flagged:?}"
    );
    for key in case.warned {
        assert!(
            first.text.contains(key),
            "{id}: the response does not name the ignored filter `{key}`: {:?}",
            first.text
        );
    }

    // 3. a key absent from the schema is reported
    if case.reports_unknown {
        let mut e = case.examples[0].body.clone();
        e.as_object_mut()
            .unwrap()
            .insert("zzUnknownKey".to_owned(), json!(1));
        let r = rigs.send(case.target, &e).await;
        assert!(
            r.unsupported().contains("/zzUnknownKey"),
            "{id}: an unknown key is not reported: {} {:?} {:?}",
            r.status,
            r.warnings,
            r.text
        );
    }

    // 4. the parser reads every documented key
    let mut unread: Vec<String> = Vec::new();
    for body in &bodies {
        let mut nodes = Vec::new();
        walk_example(body, "", "", false, &mut nodes);
        for n in nodes {
            if n.pointer.is_empty() || inside_open(&map, &n.spath) || excluded(&n.spath, case.skip) {
                continue;
            }
            if case.silent.iter().any(|s| under(&n.spath, s)) {
                continue;
            }
            let Some(bad) = other_type(&n.value) else {
                continue;
            };
            let mut m = body.clone();
            *m.pointer_mut(&n.pointer).unwrap() = bad.clone();
            let r = rigs.send(case.target, &m).await;
            let blamed = case
                .aliases
                .iter()
                .find(|(from, _)| *from == n.pointer)
                .map_or(n.pointer.as_str(), |(_, to)| *to);
            if !reported_at(&r.details, blamed) {
                unread.push(format!("{} (as {bad}: {} {:?})", n.pointer, r.status, r.details));
            }
        }
    }
    unread.sort();
    unread.dedup();
    assert!(
        unread.is_empty(),
        "{id}: the parser did not report a violation for a wrongly typed value at these pointers. Either the schema documents a key the parser does not read, or the key is read without a type check (list it in `silent` with the reason):\n  {}",
        unread.join("\n  ")
    );
}

// ---- the examples -------------------------------------------------------------------------------

/// The scrape options: together they use every property and enum value of `ScrapeOptions`.
fn scrape_options_examples() -> Vec<Value> {
    vec![
        json!({
            "formats": [
                "markdown", "html", "rawHtml", "links", "images", "branding", "summary",
                "screenshot@fullPage", "json", "changeTracking", "audio", "video",
                { "type": "screenshot", "fullPage": true, "quality": 80, "viewport": { "width": 1280, "height": 720 } },
                { "type": "attributes", "selectors": [{ "selector": "a", "attribute": "href" }] },
                { "type": "json", "schema": { "type": "object", "properties": { "title": { "type": "string" } } },
                  "prompt": "Extract the title", "checkPromptInjection": true },
                { "type": "question", "question": "What is the answer?" },
                { "type": "highlights", "query": "the answer" },
                { "type": "query", "prompt": "Summarize", "mode": "directQuote" },
                { "type": "query", "prompt": "Summarize", "mode": "freeform" },
                { "type": "changeTracking", "modes": ["git-diff", "json"],
                  "schema": { "type": "object" }, "prompt": "price", "tag": "daily" },
                { "type": "markdown" }, { "type": "html" }, { "type": "rawHtml" }, { "type": "links" },
                { "type": "images" }, { "type": "branding" }, { "type": "summary" },
                { "type": "audio" }, { "type": "video" }
            ],
            "onlyMainContent": false,
            "includeTags": ["main", "article"],
            "excludeTags": ["nav"],
            "maxAge": 1000,
            "minAge": 10,
            "headers": { "X-Test": "1" },
            "waitFor": 100,
            "mobile": true,
            "skipTlsVerification": false,
            "timeout": 30000,
            "parsers": [
                "pdf", "image",
                { "type": "pdf", "mode": "fast", "maxPages": 3, "pages": true, "blocks": true, "pageMarkers": true },
                { "type": "pdf", "mode": "auto" },
                { "type": "pdf", "mode": "ocr" },
                { "type": "image" }
            ],
            "actions": [
                { "type": "wait", "milliseconds": 50 },
                { "type": "wait", "selector": "#ready", "state": "visible" },
                { "type": "screenshot", "fullPage": true, "quality": 70, "viewport": { "width": 800, "height": 600 } },
                { "type": "click", "selector": "#go", "all": true },
                { "type": "write", "text": "hello" },
                { "type": "press", "key": "Enter" },
                { "type": "scroll", "direction": "up", "selector": "#list" },
                { "type": "scroll", "direction": "down" },
                { "type": "scrape" },
                { "type": "executeJavascript", "script": "1 + 1" },
                { "type": "pdf", "format": "A4", "landscape": true, "scale": 1.5 }
            ],
            "location": { "country": "US", "languages": ["en-US", "de"] },
            "removeBase64Images": true,
            "blockAds": true,
            "proxy": "basic",
            "storeInCache": true,
            "extract": { "schema": { "type": "object" }, "prompt": "p" },
            "jsonOptions": { "schema": { "type": "object" }, "prompt": "p" },
            "onlyCleanContent": false,
            "profile": { "name": "main_profile-1", "saveChanges": false },
            "checkPromptInjection": true,
            "redactPII": { "mode": "accurate", "entities": ["PERSON", "EMAIL", "PHONE", "LOCATION", "FINANCIAL", "SECRET"], "replaceStyle": "tag" }
        }),
        json!({ "formats": ["rawBase64"] }),
        json!({ "formats": ["screenshot", "json"], "proxy": "enhanced", "redactPII": true }),
        json!({ "formats": [{ "type": "rawBase64" }], "lockdown": true, "zeroDataRetention": true }),
        json!({ "proxy": "auto", "redactPII": { "mode": "aggressive", "replaceStyle": "mask" } }),
        json!({ "redactPII": { "mode": "fast", "replaceStyle": "remove" } }),
    ]
}

/// A scrape-options key the `legacy` parser reads without checking its members.
const SCRAPE_SILENT: &[&str] = &[
    // v1 `extract` / `jsonOptions`: `schema` and `prompt` are read when they have the right type
    "/extract/schema",
    "/extract/prompt",
    "/jsonOptions/schema",
    "/jsonOptions/prompt",
    // a scroll `direction` that is not a string reads as the default
    "/actions[]/direction",
    // accepted without effect
    "/origin",
    "/integration",
];

fn with(mut base: Value, extra: &Value) -> Value {
    for (k, v) in extra.as_object().unwrap() {
        base[k] = v.clone();
    }
    base
}

fn scrape_case() -> Case {
    let examples: Vec<Example> = scrape_options_examples()
        .into_iter()
        .enumerate()
        .map(|(i, o)| {
            let mut base = json!({ "url": "https://a.example.test/" });
            if i == 0 {
                base["origin"] = json!("sdk");
                base["integration"] = json!("sdk");
            }
            ex(with(base, &o))
        })
        .collect();
    let mut c = case("firecrawlScrape", Target::Scrape, examples);
    c.silent = SCRAPE_SILENT;
    c.reports_unknown = true;
    c
}

fn batch_case() -> Case {
    let examples: Vec<Example> = scrape_options_examples()
        .into_iter()
        .enumerate()
        .map(|(i, o)| {
            let mut base = json!({ "urls": ["https://a.example.test/", "https://b.example.test/"] });
            if i == 0 {
                base["webhook"] = json!({
                    "url": "https://hooks.example.test/batch",
                    "headers": { "X-Auth": "s" },
                    "metadata": { "run": 1 },
                    "events": ["started", "page", "completed", "failed"],
                });
                base["maxConcurrency"] = json!(3);
                base["ignoreInvalidURLs"] = json!(true);
            }
            ex(with(base, &o))
        })
        .collect();
    let mut c = case("firecrawlBatchScrape", Target::Batch, examples);
    c.reports_unknown = true;
    c.silent = &[
        "/extract/schema",
        "/extract/prompt",
        "/jsonOptions/schema",
        "/jsonOptions/prompt",
        "/actions[]/direction",
    ];
    c
}

fn crawl_case() -> Case {
    let mut examples = vec![ex(json!({
        "url": "https://docs.example.test/",
        "prompt": "crawl the documentation",
        "limit": 10,
        "includePaths": ["^/docs/"],
        "excludePaths": ["^/old/"],
        "regexOnFullURL": false,
        "maxDiscoveryDepth": 3,
        "sitemap": "include",
        "ignoreQueryParameters": false,
        "crawlEntireDomain": true,
        "allowExternalLinks": false,
        "allowSubdomains": true,
        "ignoreRobotsTxt": false,
        "robotsUserAgent": "BotX",
        "delay": 0.5,
        "maxConcurrency": 4,
        "webhook": {
            "url": "https://hooks.example.test/crawl",
            "headers": { "X-Auth": "s" },
            "metadata": { "run": 1 },
            "events": ["started", "page"],
        },
        "scrapeOptions": scrape_options_examples()[0].clone(),
        "zeroDataRetention": false,
        "deduplicateSimilarURLs": true,
        "integration": "sdk",
        "origin": "sdk",
    }))];
    // the v1 spellings count only without their v2 keys
    examples.push(ex(json!({
        "url": "https://docs.example.test/",
        "maxDepth": 2,
        "ignoreSitemap": true,
        "allowBackwardLinks": true,
        "crawlerOptions": { "limit": 5 },
    })));
    for o in scrape_options_examples().into_iter().skip(1) {
        examples.push(ex(
            json!({ "url": "https://docs.example.test/", "scrapeOptions": o }),
        ));
    }
    examples.push(ex(
        json!({ "url": "https://docs.example.test/", "sitemap": "skip" }),
    ));
    examples.push(ex(
        json!({ "url": "https://docs.example.test/", "sitemap": "only" }),
    ));
    let mut c = case("firecrawlCreateCrawl", Target::Crawl, examples);
    c.reports_unknown = true;
    c.silent = &[
        "/integration",
        "/origin",
        "/scrapeOptions/extract/schema",
        "/scrapeOptions/extract/prompt",
        "/scrapeOptions/jsonOptions/schema",
        "/scrapeOptions/jsonOptions/prompt",
        "/scrapeOptions/actions[]/direction",
    ];
    // v1 spellings are read as their v2 keys and blamed there
    c.aliases = &[
        ("/maxDepth", "/maxDiscoveryDepth"),
        ("/allowBackwardLinks", "/crawlEntireDomain"),
    ];
    c
}

fn map_case(site: &str) -> Case {
    let mut examples = vec![ex(json!({
        "url": site,
        "search": "page",
        "sitemap": "include",
        "includeSubdomains": true,
        "ignoreQueryParameters": true,
        "ignoreCache": true,
        "limit": 50,
        "timeout": 30000,
        "location": { "country": "US", "languages": ["en"] },
    }))];
    examples.push(ex(json!({ "url": site, "sitemap": "skip" })));
    examples.push(ex(json!({ "url": site, "sitemap": "only" })));
    let mut c = case("firecrawlMap", Target::Map, examples);
    c.reports_unknown = true;
    // `location.country` is accepted and reported (no geo-located proxy)
    c.unsupported_ok = &["/location/country"];
    c
}

fn search_case() -> Case {
    let mut c = case(
        "firecrawlSearch",
        Target::Search,
        vec![
            ex(json!({
                "query": "rust",
                "limit": 5,
                "sources": ["web", "news", "images", "alexandria",
                            { "type": "web", "tbs": "qdr:w", "location": "Berlin" }, { "type": "news" }],
                "categories": ["github", "developer", "research", "pdf", "gov"],
                "tbs": "qdr:d",
                "location": "Berlin",
                "country": "DE",
                "safe": true,
                "timeout": 30000,
                "ignoreInvalidURLs": false,
                "scrapeOptions": scrape_options_examples()[1].clone(),
                "includeDomains": ["rust-lang.org"],
                "domainTools": { "x": 1 },
                "toolDetail": "full",
                "integration": "sdk",
                "origin": "sdk",
            })),
            ex(json!({
                "query": "rust",
                "categories": [{ "type": "github" }, { "type": "developer" }, { "type": "research" },
                               { "type": "pdf" }, { "type": "gov" }],
                "excludeDomains": ["example.com"],
            })),
        ],
    );
    c.reports_unknown = true;
    c.skip = &["/scrapeOptions"];
    c.silent = &[
        // read leniently: a source object's `tbs` and `location` are used when they are strings
        "/sources[]/tbs",
        "/sources[]/location",
        // accepted for Firecrawl compatibility and reported as ignored
        "/domainTools",
        "/toolDetail",
        "/integration",
        "/origin",
    ];
    c
}

fn extract_case() -> Case {
    let mut c = case(
        "firecrawlExtract",
        Target::Extract,
        vec![ex(json!({
            "urls": ["https://example.com/*", "https://example.com/about"],
            "prompt": "Extract the title",
            "schema": { "type": "object", "properties": { "title": { "type": "string" } } },
            "enableWebSearch": true,
            "ignoreSitemap": true,
            "includeSubdomains": false,
            "showSources": true,
            "scrapeOptions": scrape_options_examples()[1].clone(),
            "ignoreInvalidURLs": true,
            "webhook": {
                "url": "https://hooks.example.test/extract",
                "headers": { "X-Auth": "s" },
                "metadata": { "run": 1 },
                "events": ["started", "completed", "failed"],
            },
            "threatProtection": { "x": 1 },
            "integration": "sdk",
            "origin": "sdk",
        }))],
    );
    c.reports_unknown = true;
    c.skip = &["/scrapeOptions"];
    c.silent = &["/threatProtection", "/integration", "/origin"];
    c
}

fn agent_case() -> Case {
    let approval = "0198a3c2-0000-7000-8000-000000000001";
    let mut c = case(
        "firecrawlStartAgent",
        Target::Agent,
        vec![
            ex(json!({
                "prompt": "Find the founders of Acme",
                "urls": ["https://acme.example.test/about"],
                "schema": { "type": "object", "properties": { "founders": { "type": "array" } } },
                "maxCredits": 100.5,
                "strictConstrainToURLs": true,
                "model": "spark-2",
                "effort": "high",
                "webhook": {
                    "url": "https://hooks.example.test/agent",
                    "headers": { "X-Auth": "s" },
                    "metadata": { "run": 1 },
                    "events": ["started", "action", "completed", "failed", "cancelled"],
                },
                "auditMetadata": { "username": "u" },
                "threatProtection": { "x": 1 },
                "mode": "chat",
                "zeroDataRetention": false,
                "location": { "country": "us" },
                "exchange": {
                    "enabled": true,
                    "toolkits": ["apollo"],
                    "maxCalls": 5,
                    "requireApproval": true,
                    "onTermsRequired": "ask",
                },
                "integration": "sdk",
                "origin": "sdk",
            })),
            ex(
                json!({ "prompt": "p", "model": "spark-1-mini", "effort": "low", "mode": "extract",
                       "exchange": { "onTermsRequired": "skip" } }),
            ),
            ex(json!({ "prompt": "p", "model": "spark-1-pro", "effort": "medium" })),
            // the thread does not exist: the body was read, the thread lookup answers 404
            ex_status(
                json!({ "prompt": "p", "threadId": "0198a3c2-0000-7000-8000-0000000000aa",
                        "exchange": { "approve": { "approvalId": approval, "callIds": ["c1"], "always": true } } }),
                &[404],
            ),
            ex_status(
                json!({ "prompt": "p", "threadId": "0198a3c2-0000-7000-8000-0000000000aa",
                        "exchange": { "decline": { "approvalId": approval } } }),
                &[404],
            ),
        ],
    );
    c.reports_unknown = true;
    // `threatProtection` is a known key that is reported as unsupported on purpose
    c.unsupported_ok = &["/threatProtection"];
    c.silent = &[
        // free-form; the parser keeps them
        "/threatProtection",
        "/integration",
        "/origin",
        // a non-boolean `always` reads as `false`
        "/exchange/approve/always",
    ];
    c
}

fn parse_case() -> Case {
    let mut c = case(
        "firecrawlParse",
        Target::Parse,
        vec![
            ex(json!({
                "formats": [
                    "markdown", "html", "rawHtml", "text", "links", "images", "summary",
                    { "type": "json", "schema": { "type": "object", "properties": { "title": { "type": "string" } } },
                      "prompt": "Extract the title", "checkPromptInjection": true },
                    { "type": "question", "question": "What is this?" },
                    { "type": "highlights", "query": "hello" },
                ],
                "onlyMainContent": true,
                "includeTags": ["main"],
                "excludeTags": ["nav"],
                "headers": { "X-Test": "1" },
                "timeout": 30000,
                "parsers": [{ "type": "pdf", "mode": "fast", "maxPages": 2, "pages": true, "blocks": true, "pageMarkers": true }],
                "skipTlsVerification": true,
                "removeBase64Images": true,
                "blockAds": true,
                "checkPromptInjection": true,
                "redactPII": { "mode": "accurate", "entities": ["PERSON", "EMAIL", "PHONE", "LOCATION", "FINANCIAL", "SECRET"], "replaceStyle": "tag" },
                "proxy": "basic",
                "origin": "sdk",
                "integration": "sdk",
                "auditMetadata": { "username": "u" },
                "zeroDataRetention": true,
            })),
            ex(json!({
                "formats": [{ "type": "markdown" }, { "type": "html" }, { "type": "rawHtml" }, { "type": "text" },
                            { "type": "links" }, { "type": "images" }, { "type": "summary" }],
                "parsers": [{ "type": "pdf", "mode": "auto" }],
                "proxy": "auto",
                "redactPII": { "mode": "aggressive", "replaceStyle": "mask" },
            })),
            ex(
                json!({ "parsers": [{ "type": "pdf", "mode": "ocr" }], "redactPII": { "mode": "fast", "replaceStyle": "remove" } }),
            ),
        ],
    );
    c.reports_unknown = true;
    c
}

fn monitor_examples() -> (Vec<Example>, Vec<Example>) {
    let webhook = json!({
        "url": "https://hooks.example.test/monitor",
        "headers": { "X-Auth": "s" },
        "metadata": { "run": 1 },
        "events": ["monitor.page", "monitor.check.completed"],
    });
    let notification =
        json!({ "email": { "enabled": true, "includeDiffs": true, "recipients": ["ops@example.test"] } });
    let targets = json!([
        { "type": "scrape", "id": "0198a3c2-0000-7000-8000-0000000000b1", "urls": ["https://a.example.test/"],
          "scrapeOptions": scrape_options_examples()[1].clone() },
        { "type": "scrape", "url": "https://b.example.test/" },
        { "type": "crawl", "id": "0198a3c2-0000-7000-8000-0000000000b2", "url": "https://c.example.test/",
          "crawlOptions": { "limit": 20, "maxDepth": 3, "maxDiscoveryDepth": 4,
                            "includePaths": ["^/docs"], "excludePaths": ["^/old"] },
          "scrapeOptions": { "formats": ["markdown"] } },
        { "type": "search", "id": "0198a3c2-0000-7000-8000-0000000000b3", "queries": ["rust"], "searchWindow": "5m",
          "maxResults": 5, "includeDomains": ["rust-lang.org"] },
        { "type": "search", "queries": ["rust"], "searchWindow": "15m", "excludeDomains": ["example.com"] },
        { "type": "search", "queries": ["rust"], "searchWindow": "1h" },
        { "type": "search", "queries": ["rust"], "searchWindow": "6h" },
        { "type": "search", "queries": ["rust"], "searchWindow": "24h" },
        { "type": "search", "queries": ["rust"], "searchWindow": "7d" },
    ]);
    let create = vec![
        ex(json!({
            "name": "Everything",
            "schedule": { "cron": "*/30 * * * *", "timezone": "Europe/Berlin" },
            "targets": targets,
            "goal": "Tell me about price changes",
            "judgeEnabled": true,
            "retentionDays": 7,
            "webhook": webhook,
            "notification": notification,
        })),
        ex(json!({
            "name": "In words",
            "schedule": { "text": "every 2 hours" },
            "targets": [{ "type": "scrape", "urls": ["https://a.example.test/"] }],
        })),
    ];
    let patch = vec![
        ex(json!({
            "name": "Renamed",
            "schedule": { "cron": "*/30 * * * *", "text": null, "timezone": "UTC" },
            "targets": targets,
            "goal": "Tell me about price changes",
            "judgeEnabled": true,
            "retentionDays": 9,
            "webhook": webhook,
            "notification": notification,
            "status": "paused",
        })),
        ex(json!({ "status": "active", "schedule": { "text": "every 3 hours" } })),
    ];
    (create, patch)
}

fn monitor_cases() -> Vec<Case> {
    let (create, patch) = monitor_examples();
    let mut c = case("createMonitor", Target::MonitorCreate, create);
    c.skip = &["/targets[]/scrapeOptions"];
    c.silent = MONITOR_SILENT;
    // a scrape target's single `url` is read as a one-element `urls` and blamed there
    c.aliases = &[("/targets/1/url", "/targets/1/urls")];
    let mut p = case("updateMonitor", Target::MonitorPatch, patch);
    p.skip = &["/targets[]/scrapeOptions"];
    p.silent = MONITOR_SILENT;
    p.aliases = &[("/targets/1/url", "/targets/1/urls")];
    vec![c, p]
}

/// Members a monitor stores or forwards without checking their type.
const MONITOR_SILENT: &[&str] = &[
    // a webhook's free-form `metadata` is an object whose members are not checked; the whole
    // value is
    "/webhook/metadata",
    // the schedule's unused members: `cron` and `text` are exclusive, a null `text` is absent
    "/schedule/text",
    // each target keeps the request object it came from; a member the target kind does not use is
    // stored as sent
    "/targets[]/scrapeOptions",
];

async fn feedback_cases(rigs: &Rigs) -> Vec<Case> {
    let job = rigs.search_job_id().await;
    let fields = json!({
        "rating": "good",
        "valuableSources": [{ "url": "https://rust-lang.org/" }],
        "valuableResults": [{ "source": "web", "position": 1 }],
        "missingContent": [{ "topic": "benchmarks" }],
        "querySuggestions": "rust language",
        "note": "useful",
        "issues": ["slow_results"],
        "tags": ["docs"],
        "url": "https://rust-lang.org/",
        "pageNumbers": [1, 2],
        "metadata": { "k": 1 },
    });
    let search = vec![
        ex(fields.clone()),
        ex(json!({ "rating": "partial", "missingContent": [{ "topic": "x" }] })),
        ex(json!({ "rating": "bad", "querySuggestions": "better" })),
    ];
    let mut general = vec![ex(with(json!({ "endpoint": "search", "jobId": job }), &fields))];
    general.push(ex(
        json!({ "endpoint": "search", "jobId": job, "rating": "partial",
                            "missingContent": [{ "topic": "x" }] }),
    ));
    for endpoint in ["scrape", "parse", "map"] {
        general.push(ex(
            json!({ "endpoint": endpoint, "jobId": job, "rating": "bad", "note": "n" }),
        ));
    }
    let mut a = case("firecrawlSearchFeedback", Target::SearchFeedback, search);
    // the page numbers are counted, not read one by one
    a.silent = &["/pageNumbers"];
    let mut b = case("firecrawlFeedback", Target::Feedback, general);
    b.silent = &["/pageNumbers"];
    vec![a, b]
}

fn index_cases() -> Vec<Case> {
    let mut dev = case(
        "firecrawlSearchDeveloper",
        Target::DeveloperPost,
        vec![ex(json!({
            "query": "tokio",
            "k": 5,
            "types": ["doc", "issue", "pull_request", "readme"],
            "repos": ["tokio-rs/tokio"],
            "sources": ["docs.rs"],
            "skills": "async",
            "passages": "3",
            "language": "rust",
            "topic": "runtime",
            "license": "mit",
            "min_stars": "10",
            "max_stars": "100000",
            "archived": "false",
            "fork": "false",
        }))],
    );
    // scalar filters the web backend cannot apply are read and named in the response `warning`
    dev.warned = &[
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
    dev.silent = &[
        "/skills",
        "/passages",
        "/language",
        "/topic",
        "/license",
        "/min_stars",
        "/max_stars",
        "/archived",
        "/fork",
    ];
    let mut gov = case(
        "firecrawlSearchGov",
        Target::GovPost,
        vec![ex(json!({
            "query": "tax",
            "k": 5,
            "domain": "irs.gov",
            "jurisdiction": "us",
            "court": "scotus",
            "courtType": "federal",
            "cites": "x",
        }))],
    );
    gov.warned = &["jurisdiction", "court", "courtType", "cites"];
    gov.silent = &["/domain", "/jurisdiction", "/court", "/courtType", "/cites"];
    vec![dev, gov]
}

fn other_cases() -> Vec<Case> {
    let preview = case(
        "firecrawlCrawlParamsPreview",
        Target::ParamsPreview,
        vec![ex(
            json!({ "url": "https://docs.example.test/", "prompt": "crawl the docs" }),
        )],
    );
    let docs = case(
        "firecrawlSupportDocsSearch",
        Target::DocsSearch,
        vec![ex(json!({ "question": "How do I crawl a site?" }))],
    );
    let mut ask = case(
        "firecrawlSupportAsk",
        Target::SupportAsk,
        vec![ex(
            json!({ "question": "Why did my scrape fail?", "rationale": "it timed out" }),
        )],
    );
    // read as text and appended to the search query
    ask.silent = &["/rationale"];
    vec![preview, docs, ask]
}

async fn all_cases(rigs: &Rigs) -> Vec<Case> {
    let mut cases = vec![
        scrape_case(),
        batch_case(),
        crawl_case(),
        map_case(&rigs.rig.url("/")),
        search_case(),
        extract_case(),
        agent_case(),
        parse_case(),
    ];
    cases.extend(monitor_cases());
    cases.extend(feedback_cases(rigs).await);
    cases.extend(index_cases());
    cases.extend(other_cases());
    cases
}

/// Every operation that parses a request body has a drift case (or is named here with the reason
/// it has none).
const NO_DRIFT_CASE: &[(&str, &str)] = &[("runMonitor", "no request body")];

#[tokio::test]
async fn request_schemas_match_what_the_parsers_read() {
    let doc = doc();
    let rigs = Rigs::start().await;
    let cases = all_cases(&rigs).await;
    // every body operation of the facade is covered
    let covered: BTreeSet<&str> = cases.iter().map(|c| c.id).collect();
    for (method, path, op) in facade_operations(&doc) {
        let id = op["operationId"].as_str().unwrap();
        if matches!(method.as_str(), "post" | "put" | "patch") && !NO_DRIFT_CASE.iter().any(|(i, _)| *i == id)
        {
            assert!(
                covered.contains(id),
                "{id} ({method} {path}) has no request drift case"
            );
        }
    }
    for c in &cases {
        run_case(&rigs, &doc, c).await;
    }
    rigs.rig.cancel.cancel();
}

#[tokio::test]
async fn accepted_request_headers_are_volatile_and_recovered_only_for_execution() {
    let ai = intel(Some(generic_llm()));
    for (path, body) in [
        (
            "/batch/scrape",
            json!({
                "urls": ["https://a.example.test/"],
                "headers": { "X-Test": "fixture-secret" }
            }),
        ),
        (
            "/crawl",
            json!({
                "url": "https://a.example.test/",
                "scrapeOptions": { "headers": { "X-Test": "fixture-secret" } }
            }),
        ),
    ] {
        let reply = ai.post(path, &body).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}: {}", reply.body);
        let id = reply.body["id"]
            .as_str()
            .unwrap()
            .parse::<crawlx_core::CrawlRunId>()
            .unwrap();
        let stored = ai.state.repos.runs.get(id).await.unwrap();
        assert_eq!(
            stored.config.fetch.extra_headers.get("x-test"),
            Some(crawlx_core::traffic::REDACTED_PLACEHOLDER)
        );
        let execution = ai.state.repos.runs.get_for_execution(id).await.unwrap();
        assert_eq!(
            execution.config.fetch.extra_headers.get("x-test"),
            Some("fixture-secret")
        );
        ai.state.zdr.ack(stored.tenant, id, i64::MIN).await.unwrap();
        assert!(matches!(
            ai.state.repos.runs.get_for_execution(id).await,
            Err(crawlx_core::StoreError::RetentionDenied(_))
        ));
        assert!(ai.state.repos.runs.get(id).await.is_ok());
    }
}

#[test]
fn native_content_policy_schema_matches_parser_and_extraction_behavior() {
    use crawlx_core::extraction::QualityStatusV1;
    let document = doc();
    let schema = case_schema(&document, "firecrawlScrape");
    let validate = validator(&document, &schema);
    let base = url::Url::parse("https://fixture.example.test/article").unwrap();
    let html = b"<html><body><article><h1>Native policy fixture</h1><p>This local article paragraph has enough ordinary words to select meaningful content without making any network request.</p></article></body></html>";
    for (minimum, expected) in [(0, QualityStatusV1::Accepted), (256, QualityStatusV1::Rejected)] {
        let request = json!({
            "url": base,
            "contentPolicy": {
                "version": 1,
                "algorithm": "article_rules_v1",
                "minMainChars": minimum,
                "maxOutputChars": 512,
                "dateTimezone": "UTC",
                "chunks": {"strategy": {"kind": "fixed", "window": 4}}
            }
        });
        assert!(errors_of(&validate, &request).is_empty(), "{request}");
        let parsed =
            crawlx_api::scrape_service::parse_scrape_options_in(request.as_object().unwrap(), "", &["url"])
                .unwrap();
        let policy = parsed.options.content_policy.unwrap();
        assert_eq!(policy.min_main_chars, minimum);
        let extracted = crawlx_extract::Extractor::extract_bytes_with_projection(
            html,
            &base,
            &crawlx_extract::ExtractOptions {
                content: Some(policy),
                ..crawlx_extract::ExtractOptions::default()
            },
            &|_| None,
        )
        .unwrap();
        let article = extracted.article.as_ref().unwrap();
        assert_eq!(article.quality.status, expected);
        let chunks = article.chunks.as_ref().unwrap();
        chunks.validate(&extracted.text, &chunks.policy).unwrap();
    }
    for policy in [
        json!({"algorithm": "unregistered_algorithm"}),
        json!({"modulePath": "unreviewed.Plugin"}),
        json!({"chunks": {"strategy": {"kind": "regex", "patterns": ["x"]}}}),
        json!({"chunks": {"strategy": {"kind": "sliding", "window": 3, "step": 0}}}),
    ] {
        let request = json!({"url": base, "contentPolicy": policy});
        assert!(!errors_of(&validate, &request).is_empty(), "{request}");
        let details =
            crawlx_api::scrape_service::parse_scrape_options_in(request.as_object().unwrap(), "", &["url"])
                .unwrap_err();
        assert!(
            details
                .iter()
                .any(|detail| detail.path.starts_with("/contentPolicy")),
            "{details:?}"
        );
    }
}
