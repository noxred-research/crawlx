//! The tool catalogue: names, descriptions and input schemas (mirroring the tools of the
//! drop-in MCP server), and the translation of validated arguments into requests against the
//! crawlx compatibility API (`/compat/v2/*`).

use super::schema;
use base64::Engine as _;
use serde_json::{json, Map, Value};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// Largest file the parse tool uploads (the facade rejects larger bodies anyway).
pub(crate) const MAX_UPLOAD_BYTES: usize = 64 * 1024 * 1024;

/// One MCP tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Tool {
    /// The scrape tool: one page.
    Scrape,
    /// The map tool: URL discovery.
    Map,
    /// The search tool: web search.
    Search,
    /// The crawl tool: start a crawl.
    Crawl,
    /// The crawl-status tool: read a crawl.
    CheckCrawlStatus,
    /// The extract tool: LLM extraction job.
    Extract,
    /// The extract-status tool: read an extraction job.
    ExtractStatus,
    /// The parse tool: upload and parse a local file.
    Parse,
    /// The agent tool: research agent job.
    Agent,
    /// The agent-status tool: read an agent job.
    AgentStatus,
}

/// How the API response becomes the tool's text result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Shape {
    /// The response's `data` member (the whole body when it has none), minus the `success`
    /// envelope flag. For endpoints whose payload is the document or result set. A top-level
    /// `warning` (for example "unsupported options ignored: ...") is kept: the result is then
    /// `{"warning": ..., "data": ...}`.
    Data,
    /// The whole body minus `success`. For job endpoints, where `status`, `id` and
    /// progress counters matter as much as `data`.
    Body,
}

impl Shape {
    /// Apply the shape to a response body.
    pub(crate) fn apply(self, body: Value) -> Value {
        let Value::Object(mut map) = body else {
            return body;
        };
        map.remove("success");
        match self {
            Shape::Data => match map.remove("data") {
                Some(data) if !data.is_null() => match map.remove("warning") {
                    Some(warning) if !warning.is_null() => json!({"warning": warning, "data": data}),
                    _ => data,
                },
                _ => Value::Object(map),
            },
            Shape::Body => Value::Object(map),
        }
    }
}

/// Where the bytes of an upload come from.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Source {
    /// A local file, read when the call runs.
    File(PathBuf),
    /// Bytes decoded from `contentBase64`.
    Bytes(Vec<u8>),
}

/// A multipart upload to `/parse`.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Upload {
    /// File content.
    pub(crate) source: Source,
    /// File name sent in the multipart part.
    pub(crate) filename: String,
    /// MIME type of the part.
    pub(crate) content_type: String,
    /// Parse options, sent as the JSON `options` form field when present.
    pub(crate) options: Option<Value>,
}

/// The HTTP request a tool call makes.
#[derive(Debug, PartialEq)]
pub(crate) enum Call {
    /// `GET` of the path segments below `/compat/v2`.
    Get(Vec<String>),
    /// `POST` of a JSON body.
    Post(Vec<String>, Value),
    /// `POST /parse` multipart.
    Upload(Upload),
}

/// A validated tool call, ready to send.
#[derive(Debug, PartialEq)]
pub(crate) struct Plan {
    /// The request.
    pub(crate) call: Call,
    /// How to present its response.
    pub(crate) shape: Shape,
    /// When set, the response carries a job `id` to poll at `<endpoint>/{id}` until the job
    /// reaches a terminal status.
    pub(crate) wait: Option<&'static str>,
}

impl Tool {
    /// Every tool, in `tools/list` order.
    pub(crate) const ALL: [Tool; 10] = [
        Tool::Scrape,
        Tool::Map,
        Tool::Search,
        Tool::Crawl,
        Tool::CheckCrawlStatus,
        Tool::Extract,
        Tool::ExtractStatus,
        Tool::Parse,
        Tool::Agent,
        Tool::AgentStatus,
    ];

    /// Wire name.
    pub(crate) fn name(self) -> &'static str {
        match self {
            Tool::Scrape => "firecrawl_scrape", // wire-compat: MCP tool name
            Tool::Map => "firecrawl_map",       // wire-compat: MCP tool name
            Tool::Search => "firecrawl_search", // wire-compat: MCP tool name
            Tool::Crawl => "firecrawl_crawl",   // wire-compat: MCP tool name
            Tool::CheckCrawlStatus => "firecrawl_check_crawl_status", // wire-compat: MCP tool name
            Tool::Extract => "firecrawl_extract", // wire-compat: MCP tool name
            Tool::ExtractStatus => "firecrawl_extract_status", // wire-compat: MCP tool name
            Tool::Parse => "firecrawl_parse",   // wire-compat: MCP tool name
            Tool::Agent => "firecrawl_agent",   // wire-compat: MCP tool name
            Tool::AgentStatus => "firecrawl_agent_status", // wire-compat: MCP tool name
        }
    }

    /// Look a tool up by wire name.
    pub(crate) fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|tool| tool.name() == name)
    }

    fn title(self) -> &'static str {
        match self {
            Tool::Scrape => "Scrape a page",
            Tool::Map => "Map a website",
            Tool::Search => "Search the web",
            Tool::Crawl => "Start a crawl",
            Tool::CheckCrawlStatus => "Check a crawl",
            Tool::Extract => "Extract structured data",
            Tool::ExtractStatus => "Check an extraction",
            Tool::Parse => "Parse a file",
            Tool::Agent => "Run the research agent",
            Tool::AgentStatus => "Check an agent run",
        }
    }

    fn description(self) -> &'static str {
        match self {
            Tool::Scrape => {
                "Fetch one web page and return its content as markdown (default), HTML, links, \
                 a summary or structured JSON. For structured data pass formats [\"json\"] with \
                 jsonOptions {prompt, schema}. Takes one URL per call; use the map tool to find \
                 URLs and the crawl tool for many pages."
            }
            Tool::Map => {
                "List the URLs of a website without fetching their content. Pass `search` to \
                 rank URLs by relevance to a term. Use it to choose pages before scraping them."
            }
            Tool::Search => {
                "Search the web and return ranked results (title, URL, description). Pass \
                 `scrapeOptions` to also fetch the content of each result; leave it unset for \
                 plain results and scrape only the URLs you need."
            }
            Tool::Crawl => {
                "Start a crawl of a website and return its job id at once. Read progress and \
                 pages with the crawl-status tool. Bound the crawl with `limit`, \
                 `maxDiscoveryDepth`, `includePaths` and `excludePaths`."
            }
            Tool::CheckCrawlStatus => {
                "Read the status, progress counters and scraped pages of a crawl started with \
                 the crawl tool."
            }
            Tool::Extract => {
                "Extract structured data from one or more URLs (globs such as https://x.com/* \
                 allowed) with an LLM, guided by `prompt` and/or a JSON `schema`. Waits until the \
                 job ends; with wait=false it returns the job id at once and you read it with \
                 the extract-status tool."
            }
            Tool::ExtractStatus => {
                "Read the status and extracted data of a job started with the extract tool."
            }
            Tool::Parse => {
                "Upload a local file (pdf, docx, doc, odt, rtf, xlsx, xls, html, csv, epub, ...) \
                 and return it as markdown or structured JSON. Give `filePath` (a path readable \
                 by this server) or `contentBase64` with `filename`."
            }
            Tool::Agent => {
                "Start a research agent that searches, reads pages and returns structured data \
                 when the URLs are not known or the answer spans several sites. Returns a job id \
                 (and threadId) at once; read the result with the agent-status tool, or set \
                 wait=true to block until the run ends."
            }
            Tool::AgentStatus => {
                "Read the status, progress and result of a run started with the agent tool. \
                 `processing` is not final: check again until `completed` or `failed`."
            }
        }
    }

    /// `(readOnlyHint, idempotentHint, openWorldHint)`.
    fn hints(self) -> (bool, bool, bool) {
        match self {
            Tool::Scrape | Tool::Map | Tool::Search => (true, true, true),
            Tool::Crawl | Tool::Extract | Tool::Agent => (false, false, true),
            Tool::CheckCrawlStatus | Tool::ExtractStatus | Tool::Parse | Tool::AgentStatus => {
                (true, true, false)
            }
        }
    }

    /// The `tools/list` entry of this tool.
    pub(crate) fn descriptor(self) -> Value {
        let (read_only, idempotent, open_world) = self.hints();
        json!({
            "name": self.name(),
            "description": self.description(),
            "inputSchema": self.input_schema(),
            "annotations": {
                "title": self.title(),
                "readOnlyHint": read_only,
                "destructiveHint": false,
                "idempotentHint": idempotent,
                "openWorldHint": open_world,
            },
        })
    }

    /// JSON Schema of the tool's arguments.
    pub(crate) fn input_schema(self) -> Value {
        match self {
            Tool::Scrape => {
                let mut props = scrape_properties();
                props.extend(into_map(json!({
                    "url": {"type": "string", "format": "uri", "description": "Page URL (http or https)."},
                    "timeout": {"type": "integer", "minimum": 1, "description": "Fetch timeout in milliseconds."},
                })));
                object(props, &["url"])
            }
            Tool::Map => object(
                into_map(json!({
                    "url": {"type": "string", "format": "uri", "description": "Site to map (http or https)."},
                    "search": {"type": "string", "description": "Rank and filter URLs by this term."},
                    "sitemap": {"type": "string", "enum": ["include", "skip", "only"], "description": "How to use the sitemap. Default include."},
                    "includeSubdomains": {"type": "boolean"},
                    "limit": {"type": "integer", "minimum": 1, "description": "Most URLs to return."},
                    "ignoreQueryParameters": {"type": "boolean"},
                })),
                &["url"],
            ),
            Tool::Search => object(search_properties(), &["query"]),
            Tool::Crawl => object(crawl_properties(), &["url"]),
            Tool::CheckCrawlStatus => id_schema("Crawl id returned by the crawl tool."),
            Tool::Extract => object(extract_properties(), &["urls"]),
            Tool::ExtractStatus => id_schema("Job id returned by the extract tool."),
            Tool::Parse => object(parse_properties(), &[]),
            Tool::Agent => object(agent_properties(), &["prompt"]),
            Tool::AgentStatus => id_schema("Job id returned by the agent tool."),
        }
    }

    /// Validate `arguments` against the schema and turn them into the request to send.
    ///
    /// # Errors
    /// Returns the list of problems with the arguments.
    pub(crate) fn plan(self, arguments: Value) -> Result<Plan, Vec<String>> {
        let checked = schema::check(&self.input_schema(), arguments)?;
        let Value::Object(args) = checked else {
            return Err(vec!["arguments must be an object".to_owned()]);
        };
        match self {
            Tool::Scrape => plan_scrape(args),
            Tool::Map => Ok(post(&["map"], args, Shape::Body)),
            Tool::Search => plan_search(args),
            Tool::Crawl => plan_crawl(args),
            Tool::CheckCrawlStatus => Ok(get_by_id("crawl", &args)),
            Tool::Extract => plan_job(args, "extract", true),
            Tool::ExtractStatus => Ok(get_by_id("extract", &args)),
            Tool::Parse => plan_parse(args),
            Tool::Agent => plan_job(args, "agent", false),
            Tool::AgentStatus => Ok(get_by_id("agent", &args)),
        }
    }
}

fn into_map(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

fn object(properties: Map<String, Value>, required: &[&str]) -> Value {
    let mut schema = into_map(json!({"type": "object", "properties": properties}));
    if !required.is_empty() {
        schema.insert("required".to_owned(), json!(required));
    }
    Value::Object(schema)
}

fn id_schema(description: &str) -> Value {
    object(
        into_map(json!({"id": {"type": "string", "minLength": 1, "description": description}})),
        &["id"],
    )
}

/// Scrape options shared by scrape, search, crawl, extract and parse (everything but `url`).
fn scrape_properties() -> Map<String, Value> {
    let mut props = into_map(json!({
        "formats": {
            "type": "array",
            "description": "Output formats; markdown when omitted. `json` uses jsonOptions, `query` uses queryOptions.",
            "items": {"type": "string", "enum": [
                "markdown", "html", "rawHtml", "screenshot", "links", "images", "summary",
                "changeTracking", "branding", "json", "query", "audio"
            ]},
        },
        "jsonOptions": {
            "type": "object",
            "description": "With formats [\"json\"]: what to extract.",
            "properties": {
                "prompt": {"type": "string"},
                "schema": {"type": "object", "description": "JSON Schema of the result."},
            },
        },
        "queryOptions": {
            "type": "object",
            "description": "With formats [\"query\"]: a question about the page.",
            "properties": {
                "prompt": {"type": "string", "maxLength": 10000},
                "mode": {"type": "string", "enum": ["directQuote", "freeform"]},
            },
            "required": ["prompt"],
        },
        "screenshotOptions": {
            "type": "object",
            "description": "With formats [\"screenshot\"].",
            "properties": {
                "fullPage": {"type": "boolean"},
                "quality": {"type": "number"},
                "viewport": {
                    "type": "object",
                    "properties": {"width": {"type": "number"}, "height": {"type": "number"}},
                    "required": ["width", "height"],
                },
            },
        },
        "parsers": {
            "type": "array",
            "items": {"type": "string", "enum": ["pdf"]},
        },
        "pdfOptions": {
            "type": "object",
            "description": "With parsers [\"pdf\"].",
            "properties": {"maxPages": {"type": "integer", "minimum": 1, "maximum": 10000}},
        },
    }));
    props.extend(into_map(json!({
        "onlyMainContent": {"type": "boolean", "description": "Drop navigation, headers and footers."},
        "redactPII": {"type": "boolean"},
        "includeTags": {"type": "array", "items": {"type": "string"}},
        "excludeTags": {"type": "array", "items": {"type": "string"}},
        "waitFor": {"type": "integer", "minimum": 0, "description": "Milliseconds to wait before capturing the page."},
        "mobile": {"type": "boolean"},
        "skipTlsVerification": {"type": "boolean"},
        "removeBase64Images": {"type": "boolean"},
        "storeInCache": {"type": "boolean"},
        "zeroDataRetention": {"type": "boolean"},
        "maxAge": {"type": "integer", "minimum": 0, "description": "Accept a cached copy up to this many milliseconds old."},
        "lockdown": {"type": "boolean"},
        "proxy": {"type": "string", "enum": ["basic", "stealth", "enhanced", "auto"]},
    })));
    props.extend(into_map(json!({
        "actions": {
            "type": "array",
            "description": "Browser actions run before capture.",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": [
                        "wait", "screenshot", "scroll", "scrape", "click", "write", "press",
                        "executeJavascript", "generatePDF"
                    ]},
                    "selector": {"type": "string"},
                    "state": {
                        "type": "string",
                        "enum": ["attached", "visible", "hidden", "detached"],
                        "default": "attached",
                        "description": "Wait for the first CSS match. Visible needs a positive layout box and computed visibility, not full actionability. Hidden also succeeds when absent. Nondefault state requires selector."
                    },
                    "milliseconds": {"type": "integer", "minimum": 0},
                    "text": {"type": "string"},
                    "key": {"type": "string"},
                    "direction": {"type": "string", "enum": ["up", "down"]},
                    "script": {"type": "string"},
                    "fullPage": {"type": "boolean"},
                },
                "required": ["type"],
            },
        },
        "location": {
            "type": "object",
            "description": "Geolocation and languages to emulate.",
            "properties": {
                "country": {"type": "string"},
                "languages": {"type": "array", "items": {"type": "string"}},
            },
        },
        "profile": {
            "type": "object",
            "description": "Named browser profile.",
            "properties": {"name": {"type": "string"}, "saveChanges": {"type": "boolean"}},
            "required": ["name"],
        },
    })));
    props
}

/// `scrapeOptions` member of search, crawl and extract.
fn scrape_options_property() -> Value {
    json!({
        "type": "object",
        "description": "Options applied to every page fetched by this call (same fields as the scrape tool, without url).",
        "properties": scrape_properties(),
    })
}

fn search_properties() -> Map<String, Value> {
    let mut props = into_map(json!({
        "query": {"type": "string", "minLength": 1, "description": "Search query; quoted phrases, -term, site:host and similar operators work."},
        "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        "sources": {"type": "array", "items": {"type": "string", "enum": ["web", "images", "news"]}},
        "categories": {"type": "array", "items": {"type": "string", "enum": ["github", "research", "pdf", "developer", "gov"]}},
        "tbs": {"type": "string", "description": "Time filter such as qdr:d (past day) or qdr:w."},
        "filter": {"type": "string"},
        "location": {"type": "string", "description": "Location to search from."},
        "country": {"type": "string", "description": "ISO country code."},
        "includeDomains": {"type": "array", "items": {"type": "string"}, "description": "Restrict results to these hosts. Exclusive with excludeDomains."},
        "excludeDomains": {"type": "array", "items": {"type": "string"}, "description": "Leave out these hosts. Exclusive with includeDomains."},
        "highlights": {"type": "boolean", "description": "Return query-relevant excerpts."},
        "enterprise": {"type": "array", "items": {"type": "string", "enum": ["default", "anon", "zdr"]}},
        "timeout": {"type": "integer", "minimum": 1},
    }));
    props.insert("scrapeOptions".to_owned(), scrape_options_property());
    props
}

fn crawl_properties() -> Map<String, Value> {
    let mut props = into_map(json!({
        "url": {"type": "string", "minLength": 1, "description": "Start URL."},
        "prompt": {"type": "string", "description": "Describe the crawl in words; explicit fields win."},
        "includePaths": {"type": "array", "items": {"type": "string"}, "description": "Path regexes to include."},
        "excludePaths": {"type": "array", "items": {"type": "string"}, "description": "Path regexes to skip."},
        "maxDiscoveryDepth": {"type": "integer", "minimum": 0},
        "sitemap": {"type": "string", "enum": ["skip", "include", "only"]},
        "limit": {"type": "integer", "minimum": 1, "description": "Most pages to crawl."},
        "allowExternalLinks": {"type": "boolean"},
        "allowSubdomains": {"type": "boolean"},
        "crawlEntireDomain": {"type": "boolean"},
        "delay": {"type": "number", "minimum": 0, "description": "Seconds between requests to one host."},
        "maxConcurrency": {"type": "integer", "minimum": 1},
        "webhook": {"type": "string", "format": "uri", "description": "URL notified about crawl events."},
        "webhookHeaders": {"type": "object", "additionalProperties": {"type": "string"}, "description": "Headers sent with webhook calls."},
        "deduplicateSimilarURLs": {"type": "boolean"},
        "ignoreQueryParameters": {"type": "boolean"},
    }));
    props.insert("scrapeOptions".to_owned(), scrape_options_property());
    props
}

fn extract_properties() -> Map<String, Value> {
    let mut props = into_map(json!({
        "urls": {"type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}, "description": "URLs to extract from; globs allowed."},
        "prompt": {"type": "string", "description": "What to extract."},
        "schema": {"type": "object", "description": "JSON Schema of the result."},
        "enableWebSearch": {"type": "boolean", "description": "Also search the web for more data."},
        "allowExternalLinks": {"type": "boolean"},
        "includeSubdomains": {"type": "boolean"},
        "ignoreSitemap": {"type": "boolean"},
        "showSources": {"type": "boolean"},
        "ignoreInvalidURLs": {"type": "boolean"},
        "wait": {"type": "boolean", "description": "Poll until the job ends (default true). False returns the job id at once."},
    }));
    props.insert("scrapeOptions".to_owned(), scrape_options_property());
    props
}

fn agent_properties() -> Map<String, Value> {
    into_map(json!({
        "prompt": {"type": "string", "minLength": 1, "maxLength": 10000, "description": "What to research and which fields to return."},
        "urls": {"type": "array", "items": {"type": "string", "format": "uri"}, "description": "Seed URLs."},
        "schema": {"type": "object", "description": "JSON Schema of the result."},
        "effort": {"type": "string", "enum": ["low", "medium", "high"]},
        "maxCredits": {"type": "integer", "minimum": 1, "description": "Spending cap for the run."},
        "strictConstrainToURLs": {"type": "boolean", "description": "Visit only the URLs in `urls`."},
        "threadId": {"type": "string", "format": "uuid", "description": "Continue this thread."},
        "mode": {"type": "string", "enum": ["extract", "chat"]},
        "exchange": {"type": "object", "description": "Provider settings, forwarded as sent."},
        "wait": {"type": "boolean", "description": "Poll until the run ends (default false: return the job id at once)."},
    }))
}

fn parse_properties() -> Map<String, Value> {
    const KEPT: [&str; 13] = [
        "jsonOptions",
        "queryOptions",
        "parsers",
        "pdfOptions",
        "onlyMainContent",
        "redactPII",
        "includeTags",
        "excludeTags",
        "removeBase64Images",
        "skipTlsVerification",
        "storeInCache",
        "zeroDataRetention",
        "maxAge",
    ];
    let mut props: Map<String, Value> = scrape_properties()
        .into_iter()
        .filter(|(key, _)| KEPT.contains(&key.as_str()))
        .collect();
    props.extend(into_map(json!({
        "filePath": {"type": "string", "minLength": 1, "description": "Path of a local file (absolute, or relative to the server's working directory)."},
        "path": {"type": "string", "minLength": 1, "description": "Alias of filePath."},
        "contentBase64": {"type": "string", "description": "File content, base64 encoded. Needs `filename`."},
        "filename": {"type": "string", "description": "File name for contentBase64; its extension selects the parser."},
        "contentType": {"type": "string", "description": "MIME type; inferred from the extension when omitted."},
        "formats": {
            "type": "array",
            "items": {"type": "string", "enum": ["markdown", "html", "rawHtml", "links", "summary", "json", "query"]},
        },
        "proxy": {"type": "string", "enum": ["basic", "auto"]},
    })));
    props
}

fn post(path: &[&str], mut body: Map<String, Value>, shape: Shape) -> Plan {
    drop_empty(&mut body);
    Plan {
        call: Call::Post(
            path.iter().map(|s| (*s).to_owned()).collect(),
            Value::Object(body),
        ),
        shape,
        wait: None,
    }
}

fn get_by_id(endpoint: &str, args: &Map<String, Value>) -> Plan {
    let id = args.get("id").and_then(Value::as_str).unwrap_or_default();
    Plan {
        call: Call::Get(vec![endpoint.to_owned(), id.to_owned()]),
        shape: Shape::Body,
        wait: None,
    }
}

/// Remove `null`, blank strings, empty arrays and empty objects at the top level of a body.
fn drop_empty(map: &mut Map<String, Value>) {
    map.retain(|_, value| match value {
        Value::Null => false,
        Value::String(text) => !text.trim().is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(members) => !members.is_empty(),
        _ => true,
    });
}

fn take_bool(args: &mut Map<String, Value>, key: &str) -> Option<bool> {
    args.remove(key).and_then(|value| value.as_bool())
}

/// `(options key, list key, entry)`: `jsonOptions` configures the `json` entry of `formats`.
const OPTION_PAIRS: [(&str, &str, &str); 4] = [
    ("jsonOptions", "formats", "json"),
    ("queryOptions", "formats", "query"),
    ("screenshotOptions", "formats", "screenshot"),
    ("pdfOptions", "parsers", "pdf"),
];

/// Entries that are always sent as `{type, ...options}` objects, even without options.
const OBJECT_ENTRIES: [&str; 2] = ["json", "query"];

/// Fold `jsonOptions`, `queryOptions`, `screenshotOptions` and `pdfOptions` into the
/// object-form `formats` / `parsers` entries the compatibility API takes (for example
/// `formats: ["json"]` + `jsonOptions: {prompt}` becomes `formats: [{type: "json", prompt}]`).
fn fold_options(args: &mut Map<String, Value>) -> Result<(), Vec<String>> {
    let mut issues = Vec::new();
    let mut folded: Vec<(&str, &str, Map<String, Value>)> = Vec::new();
    for (options_key, list_key, entry) in OPTION_PAIRS {
        let Some(options) = args.remove(options_key) else {
            continue;
        };
        let listed = args
            .get(list_key)
            .and_then(Value::as_array)
            .is_some_and(|items| items.iter().any(|item| item.as_str() == Some(entry)));
        if !listed {
            issues.push(format!("{options_key} needs {list_key} to include \"{entry}\""));
            continue;
        }
        folded.push((list_key, entry, into_map(options)));
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    for list_key in ["formats", "parsers"] {
        let Some(Value::Array(items)) = args.get_mut(list_key) else {
            continue;
        };
        for item in items.iter_mut() {
            let Some(entry) = item.as_str().map(str::to_owned) else {
                continue;
            };
            let options = folded
                .iter()
                .find(|(list, name, _)| *list == list_key && *name == entry)
                .map(|(_, _, options)| options.clone());
            if options.is_some() || OBJECT_ENTRIES.contains(&entry.as_str()) {
                let mut object = Map::new();
                object.insert("type".to_owned(), Value::String(entry));
                object.extend(options.unwrap_or_default());
                *item = Value::Object(object);
            }
        }
    }
    Ok(())
}

/// Fold the options of a nested `scrapeOptions` object, when there is one.
fn fold_nested(args: &mut Map<String, Value>) -> Result<(), Vec<String>> {
    if let Some(Value::Object(nested)) = args.get_mut("scrapeOptions") {
        fold_options(nested).map_err(|issues| {
            issues
                .into_iter()
                .map(|issue| format!("scrapeOptions: {issue}"))
                .collect::<Vec<_>>()
        })?;
        drop_empty(nested);
    }
    Ok(())
}

fn plan_scrape(mut args: Map<String, Value>) -> Result<Plan, Vec<String>> {
    fold_options(&mut args)?;
    Ok(post(&["scrape"], args, Shape::Data))
}

fn non_empty_list(args: &Map<String, Value>, key: &str) -> bool {
    args.get(key)
        .and_then(Value::as_array)
        .is_some_and(|items| !items.is_empty())
}

fn plan_search(mut args: Map<String, Value>) -> Result<Plan, Vec<String>> {
    let mut issues = Vec::new();
    if non_empty_list(&args, "includeDomains") && non_empty_list(&args, "excludeDomains") {
        issues.push("includeDomains and excludeDomains cannot both be set".to_owned());
    }
    let categories: Vec<&str> = args
        .get("categories")
        .and_then(Value::as_array)
        .map(|items| items.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if categories.len() > 1 && categories.iter().any(|c| matches!(*c, "developer" | "gov")) {
        issues.push("the developer and gov categories cannot be combined with other categories".to_owned());
    }
    if !issues.is_empty() {
        return Err(issues);
    }
    fold_nested(&mut args)?;
    Ok(post(&["search"], args, Shape::Data))
}

fn plan_crawl(mut args: Map<String, Value>) -> Result<Plan, Vec<String>> {
    fold_nested(&mut args)?;
    let headers = args.remove("webhookHeaders");
    if let (Some(url), Some(Value::Object(headers))) = (args.get("webhook").cloned(), headers) {
        if !headers.is_empty() {
            args.insert("webhook".to_owned(), json!({"url": url, "headers": headers}));
        }
    }
    Ok(post(&["crawl"], args, Shape::Body))
}

/// Extract and agent: start a job, optionally poll it.
fn plan_job(
    mut args: Map<String, Value>,
    endpoint: &'static str,
    wait_default: bool,
) -> Result<Plan, Vec<String>> {
    let wait = take_bool(&mut args, "wait").unwrap_or(wait_default);
    fold_nested(&mut args)?;
    let mut plan = post(&[endpoint], args, Shape::Body);
    plan.wait = wait.then_some(endpoint);
    Ok(plan)
}

fn plan_parse(mut args: Map<String, Value>) -> Result<Plan, Vec<String>> {
    let mut issues = Vec::new();
    let file_path = args.remove("filePath");
    let alias = args.remove("path");
    let file_path = match (file_path, alias) {
        (Some(a), Some(b)) if a != b => {
            issues.push("filePath and path name different files; give one".to_owned());
            None
        }
        (Some(a), _) | (None, Some(a)) => a.as_str().map(str::to_owned),
        (None, None) => None,
    };
    let content = args
        .remove("contentBase64")
        .and_then(|value| value.as_str().map(str::to_owned));
    let filename = args
        .remove("filename")
        .and_then(|value| value.as_str().map(str::to_owned));
    let content_type = args
        .remove("contentType")
        .and_then(|value| value.as_str().map(str::to_owned));
    if file_path.is_some() == content.is_some() && issues.is_empty() {
        issues.push("give exactly one of filePath (or path) and contentBase64".to_owned());
    }
    if content.is_some() && filename.is_none() {
        issues.push("contentBase64 needs filename".to_owned());
    }
    let (source, name) = match (file_path, content) {
        (Some(path), None) => {
            let name = file_name_of(&path);
            (Some(Source::File(PathBuf::from(path))), name)
        }
        (None, Some(encoded)) => {
            let compact: String = encoded.split_whitespace().collect();
            match base64::engine::general_purpose::STANDARD.decode(compact.as_bytes()) {
                Ok(bytes) if bytes.is_empty() => {
                    issues.push("contentBase64 decodes to an empty file".to_owned());
                    (None, None)
                }
                Ok(bytes) if bytes.len() > MAX_UPLOAD_BYTES => {
                    issues.push(format!(
                        "the file exceeds the {MAX_UPLOAD_BYTES} byte upload limit"
                    ));
                    (None, None)
                }
                Ok(bytes) => (
                    Some(Source::Bytes(bytes)),
                    filename.as_deref().and_then(file_name_of),
                ),
                Err(error) => {
                    issues.push(format!("contentBase64 is not valid base64: {error}"));
                    (None, None)
                }
            }
        }
        _ => (None, None),
    };
    let name = name.unwrap_or_else(|| "upload".to_owned());
    let content_type = content_type.unwrap_or_else(|| infer_content_type(&name).to_owned());
    if reqwest::multipart::Part::bytes(Vec::new())
        .mime_str(&content_type)
        .is_err()
    {
        issues.push(format!("contentType {content_type:?} is not a valid MIME type"));
    }
    if let Err(fold_issues) = fold_options(&mut args) {
        issues.extend(fold_issues);
    }
    let Some(source) = source else {
        return Err(issues);
    };
    if !issues.is_empty() {
        return Err(issues);
    }
    drop_empty(&mut args);
    Ok(Plan {
        call: Call::Upload(Upload {
            source,
            filename: name,
            content_type,
            options: (!args.is_empty()).then_some(Value::Object(args)),
        }),
        shape: Shape::Data,
        wait: None,
    })
}

/// Final path component of `path`, or `None` when it has none.
fn file_name_of(path: &str) -> Option<String> {
    Path::new(path)
        .file_name()
        .and_then(OsStr::to_str)
        .map(str::to_owned)
}

/// MIME type for a file name's extension.
pub(crate) fn infer_content_type(filename: &str) -> &'static str {
    let extension = Path::new(filename)
        .extension()
        .and_then(OsStr::to_str)
        .map(str::to_ascii_lowercase);
    match extension.as_deref() {
        Some("html" | "htm") => "text/html",
        Some("xhtml") => "application/xhtml+xml",
        Some("pdf") => "application/pdf",
        Some("docx") => "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        Some("doc") => "application/msword",
        Some("odt") => "application/vnd.oasis.opendocument.text",
        Some("rtf") => "application/rtf",
        Some("xlsx") => "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        Some("xls") => "application/vnd.ms-excel",
        Some("pptx") => "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        Some("csv") => "text/csv",
        Some("epub") => "application/epub+zip",
        _ => "application/octet-stream",
    }
}
