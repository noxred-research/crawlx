//! JSONL records (the `-jsonl` compatibility flag): one request/response object per page.
//!
//! Shape after an MIT-licensed upstream's result and request/response types (see THIRD_PARTY_NOTICES.md)
//! (MIT): `timestamp`, `request {method, endpoint, body, headers, tag, attribute, source,
//! custom_fields, raw}`, `response {status_code, headers, body, content_length,
//! technologies, raw, forms, xhr_requests, stored_response_path, knowledgebase, extra}`,
//! `error`. crawlx adds `response.page_type`, `response.custom_fields` (the same values as
//! `request.custom_fields`, kept for older consumers) and `response.secrets` (kind + keyed
//! hash only, never a value). Additive `fidelity` records payload availability, representation,
//! redaction, binary lossiness and truncation; unknown facts stay unknown. Explicit policy
//! omissions and `-eof` exclusions are distinct from unavailable captures.
//!
//! Where each key comes from (`PageRecord.metadata`, written by the URL plane / browser
//! plane):
//!
//! | record key | metadata |
//! |---|---|
//! | `request.method` | `request.method` (legacy static default `GET`; unavailable on browser documents without an observed method) |
//! | `request.body`, `.headers`, `.raw`, `.custom_fields` | `request.{body,headers,raw,custom_fields}` (`custom_fields` falls back to the top-level `custom_fields`) |
//! | `request.tag`, `.attribute`, `.source` | `request.{tag,attribute,source}` |
//! | `response.headers` | `response_headers` |
//! | `response.content_length` | `content_length` |
//! | `response.xhr_requests` | `xhr_requests` (`url` is renamed `endpoint`, the rest is kept) |
//! | `response.knowledgebase` | `page_type`, `forms`, `secrets`, `endpoints`; only when the exporter's `knowledge_base` is set ([`Record::attach_knowledgebase`]) |
//!
//! The body and the raw response text are not metadata; the caller supplies them
//! ([`super::PageText`]). `-eof` field exclusion is [`Record::exclude_fields`]; the names it
//! accepts are [`field_names`].

use super::stored::ExchangeFidelity;
use super::OutputError;
use crawlx_core::repo::PageRecord;
use crawlx_core::Timestamp;
use crawlx_extract::kb::KbForm;
use crawlx_extract::{StaticForm, Technology};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::Write;

/// Top-level record keys.
const TOP_FIELDS: [&str; 5] = ["timestamp", "request", "response", "error", "fidelity"];
/// Keys inside `request`.
const REQUEST_FIELDS: [&str; 9] = [
    "method",
    "endpoint",
    "body",
    "headers",
    "tag",
    "attribute",
    "source",
    "custom_fields",
    "raw",
];
/// Keys inside `response`.
const RESPONSE_FIELDS: [&str; 14] = [
    "status_code",
    "headers",
    "body",
    "content_length",
    "technologies",
    "raw",
    "forms",
    "xhr_requests",
    "stored_response_path",
    "knowledgebase",
    "extra",
    "page_type",
    "custom_fields",
    "secrets",
];

/// Every JSONL field name `-eof` accepts and `-lof` lists: sorted, deduplicated. A name that
/// exists in both `request` and `response` (`body`, `headers`, `raw`, `custom_fields`) is
/// excluded from both, as in the reference.
#[must_use]
pub fn field_names() -> Vec<&'static str> {
    let mut names: Vec<&'static str> = TOP_FIELDS
        .iter()
        .chain(&REQUEST_FIELDS)
        .chain(&RESPONSE_FIELDS)
        .copied()
        .collect();
    names.sort_unstable();
    names.dedup();
    names
}

fn is_zero(n: &u16) -> bool {
    *n == 0
}

/// How the page's URL was requested and discovered.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Request {
    /// Recorded HTTP method; legacy static rows default to `GET`, browser documents do not.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub method: String,
    /// The page URL.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub endpoint: String,
    /// Request body; only recorded form requests have one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Request headers (lowercase names; credential values are `[redacted]`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// HTML tag the URL was found in (`metadata.request.tag`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Attribute of that tag (`metadata.request.attribute`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
    /// Page the URL was discovered on (`metadata.request.source`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Custom regex field values (the reference puts them under `request`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom_fields: BTreeMap<String, Vec<String>>,
    /// Compatibility HTTP-like request text, not necessarily wire capture; see [`Record::fidelity`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
}

/// What the page returned.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Response {
    /// HTTP status; omitted when none was recorded.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub status_code: u16,
    /// Response headers (lowercase names; credentials omitted at extraction time).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub headers: BTreeMap<String, String>,
    /// Body text projection, only when requested; source facts are in [`Record::fidelity`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    /// Bytes of the body that were read (`metadata.content_length`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content_length: Option<u64>,
    /// Detected technologies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub technologies: Vec<Technology>,
    /// Compatibility HTTP-like response text, only when supplied by the caller.
    /// This may be decoded, redacted or reconstructed; see [`Record::fidelity`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<String>,
    /// Static forms (`crawlx_extract::StaticForm` as JSON).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub forms: Vec<Value>,
    /// Browser-plane XHR/fetch requests (`{method, endpoint, status?, resource_type?,
    /// endpoint_class?}`), only when `extract.xhr` ran.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub xhr_requests: Vec<Value>,
    /// Absolute path of the stored raw request/response text (`-sr`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stored_response_path: Option<String>,
    /// Knowledge base (`{PageType, Forms, secrets, endpoints}`), only with `-kb`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub knowledgebase: Option<Value>,
    /// Caller-defined data attached by an embedder (the reference `Response.Extra`); never set by
    /// crawlx itself.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub extra: BTreeMap<String, Value>,
    /// Deterministic page type (`login`, `error`, ... `unknown`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub page_type: Option<String>,
    /// Custom regex field values (same data as `request.custom_fields`).
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub custom_fields: BTreeMap<String, Vec<String>>,
    /// Secret findings (`{kind, location, value_hash, validation?}`), only when detection ran.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<Value>>,
}

/// One JSONL line.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Record {
    /// When the page was fetched.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timestamp: Option<Timestamp>,
    /// The request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<Request>,
    /// The response.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<Response>,
    /// Why the URL could not be fetched (a failed frontier row); absent for stored pages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Representation and omission facts, independent of compatibility payload fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fidelity: Option<ExchangeFidelity>,
}

fn string_at(meta: &Value, path: &[&str]) -> Option<String> {
    let mut v = meta;
    for k in path {
        v = v.get(k)?;
    }
    v.as_str().map(str::to_owned)
}

fn array_at(meta: &Value, key: &str) -> Option<Vec<Value>> {
    meta.get(key).and_then(Value::as_array).cloned()
}

fn string_map(v: Option<&Value>) -> BTreeMap<String, String> {
    v.and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_owned())))
                .collect()
        })
        .unwrap_or_default()
}

fn custom_fields(v: Option<&Value>) -> BTreeMap<String, Vec<String>> {
    v.cloned()
        .and_then(|v| serde_json::from_value(v).ok())
        .unwrap_or_default()
}

/// `metadata.xhr_requests` in the reference request shape: `url` becomes `endpoint`.
fn xhr_requests(meta: &Value) -> Vec<Value> {
    meta.get("xhr_requests")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_object)
                .map(|o| {
                    let mut out = serde_json::Map::new();
                    for (k, v) in o {
                        let key = if k == "url" { "endpoint" } else { k.as_str() };
                        out.insert(key.to_owned(), v.clone());
                    }
                    out.entry("method").or_insert_with(|| Value::from("GET"));
                    Value::Object(out)
                })
                .collect()
        })
        .unwrap_or_default()
}

impl Record {
    /// Build the record of a stored page; `body` is included verbatim when given.
    #[must_use]
    pub fn from_page(page: &PageRecord, body: Option<String>) -> Self {
        let meta = &page.metadata;
        let request_meta = meta.get("request");
        let browser_document = meta
            .pointer("/acquisition/backend/backendId")
            .and_then(Value::as_str)
            == Some("native_browser")
            || meta
                .pointer("/acquisition/representation")
                .and_then(Value::as_str)
                == Some("rendered_dom");
        let technologies = meta
            .get("technologies")
            .cloned()
            .and_then(|v| serde_json::from_value(v).ok())
            .unwrap_or_default();
        let fields = custom_fields(meta.get("custom_fields"));
        let request_fields = request_meta
            .and_then(|r| r.get("custom_fields"))
            .map_or_else(|| fields.clone(), |v| custom_fields(Some(v)));
        let mut record = Self {
            timestamp: Some(page.fetched_at),
            request: Some(Request {
                method: string_at(meta, &["request", "method"]).unwrap_or_else(|| {
                    if browser_document {
                        String::new()
                    } else {
                        "GET".to_owned()
                    }
                }),
                endpoint: page.url.url.to_string(),
                body: string_at(meta, &["request", "body"]),
                headers: string_map(request_meta.and_then(|r| r.get("headers"))),
                tag: string_at(meta, &["request", "tag"]),
                attribute: string_at(meta, &["request", "attribute"]),
                source: string_at(meta, &["request", "source"]),
                custom_fields: request_fields,
                raw: string_at(meta, &["request", "raw"]),
            }),
            response: Some(Response {
                status_code: page.status,
                headers: string_map(meta.get("response_headers")),
                body,
                content_length: meta.get("content_length").and_then(Value::as_u64),
                technologies,
                raw: None,
                forms: array_at(meta, "forms").unwrap_or_default(),
                xhr_requests: xhr_requests(meta),
                stored_response_path: None,
                knowledgebase: None,
                extra: BTreeMap::new(),
                page_type: string_at(meta, &["page_type"]),
                custom_fields: fields,
                secrets: array_at(meta, "secrets"),
            }),
            error: None,
            fidelity: None,
        };
        record.fidelity = Some(ExchangeFidelity::from_record(meta, &record));
        record
    }

    /// The record of a URL that could not be fetched: the request, the status when one was
    /// seen, and the reason in `error` (the reference emits such results with `error` set).
    #[must_use]
    pub fn from_failure(url: &str, status: Option<u16>, reason: &str) -> Self {
        Self {
            timestamp: None,
            request: Some(Request {
                method: "GET".to_owned(),
                endpoint: url.to_owned(),
                ..Request::default()
            }),
            response: status.filter(|s| *s != 0).map(|status_code| Response {
                status_code,
                ..Response::default()
            }),
            error: Some(reason.to_owned()),
            fidelity: Some(ExchangeFidelity::default()),
        }
    }

    /// Attach `response.knowledgebase` (the `-kb` compatibility flag): `PageType`, `Forms` (each stored form
    /// classified as `{type, fields}` by [`crawlx_extract::kb::KbForm`]), `secrets` and
    /// `endpoints` as far as the page metadata has them. Nothing is attached when it has none.
    pub fn attach_knowledgebase(&mut self, page: &PageRecord) {
        let meta = &page.metadata;
        let mut kb = serde_json::Map::new();
        if let Some(page_type) = string_at(meta, &["page_type"]) {
            kb.insert("PageType".to_owned(), Value::from(page_type));
        }
        let forms: Vec<Value> = array_at(meta, "forms")
            .unwrap_or_default()
            .into_iter()
            .filter_map(|form| serde_json::from_value::<StaticForm>(form).ok())
            .filter_map(|form| serde_json::to_value(KbForm::new(&form)).ok())
            .collect();
        if !forms.is_empty() {
            kb.insert("Forms".to_owned(), Value::Array(forms));
        }
        if let Some(secrets) = array_at(meta, "secrets") {
            kb.insert("secrets".to_owned(), Value::Array(secrets));
        }
        if let Some(endpoints) = array_at(meta, "endpoints") {
            kb.insert("endpoints".to_owned(), Value::Array(endpoints));
        }
        if kb.is_empty() {
            return;
        }
        if let Some(response) = self.response.as_mut() {
            response.knowledgebase = Some(Value::Object(kb));
        }
    }

    /// Drop fields by name (the `-eof` compatibility flag): any name in [`field_names`]. A top-level name
    /// removes that part; a request/response name is removed from both parts that have it
    /// (`body` clears `request.body` and `response.body`). A part left without any field is
    /// dropped. Unknown names are ignored.
    pub fn exclude_fields(&mut self, names: &[String]) {
        for name in names {
            if name != "fidelity"
                && (TOP_FIELDS.contains(&name.as_str())
                    || REQUEST_FIELDS.contains(&name.as_str())
                    || RESPONSE_FIELDS.contains(&name.as_str()))
            {
                if let Some(fidelity) = &mut self.fidelity {
                    match name.as_str() {
                        "body" | "raw" => {
                            fidelity.omit(&format!("request.{name}"));
                            fidelity.omit(&format!("response.{name}"));
                        }
                        "request" | "response" => {
                            fidelity.omit(&format!("{name}.body"));
                            fidelity.omit(&format!("{name}.raw"));
                            fidelity.omit(name);
                        }
                        other => fidelity.omit(other),
                    }
                }
            }
            match name.as_str() {
                "timestamp" => self.timestamp = None,
                "request" => self.request = None,
                "response" => self.response = None,
                "error" => self.error = None,
                other => {
                    if let Some(r) = self.request.as_mut() {
                        r.clear(other);
                    }
                    if let Some(r) = self.response.as_mut() {
                        r.clear(other);
                    }
                }
            }
        }
        if names.iter().any(|name| name == "fidelity") {
            self.fidelity = None;
        }
        if self.request.as_ref().is_some_and(|r| *r == Request::default()) {
            self.request = None;
        }
        if self.response.as_ref().is_some_and(|r| *r == Response::default()) {
            self.response = None;
        }
    }
}

impl Request {
    fn clear(&mut self, name: &str) {
        match name {
            "method" => self.method.clear(),
            "endpoint" => self.endpoint.clear(),
            "body" => self.body = None,
            "headers" => self.headers.clear(),
            "tag" => self.tag = None,
            "attribute" => self.attribute = None,
            "source" => self.source = None,
            "custom_fields" => self.custom_fields.clear(),
            "raw" => self.raw = None,
            _ => {}
        }
    }
}

impl Response {
    fn clear(&mut self, name: &str) {
        match name {
            "status_code" => self.status_code = 0,
            "headers" => self.headers.clear(),
            "body" => self.body = None,
            "content_length" => self.content_length = None,
            "technologies" => self.technologies.clear(),
            "raw" => self.raw = None,
            "forms" => self.forms.clear(),
            "xhr_requests" => self.xhr_requests.clear(),
            "stored_response_path" => self.stored_response_path = None,
            "knowledgebase" => self.knowledgebase = None,
            "extra" => self.extra.clear(),
            "page_type" => self.page_type = None,
            "custom_fields" => self.custom_fields.clear(),
            "secrets" => self.secrets = None,
            _ => {}
        }
    }
}

/// Write `record` as one JSON line.
///
/// # Errors
/// [`OutputError::Json`] when serialization fails, [`OutputError::Io`] on write failure.
pub fn write_line(record: &Record, out: &mut (impl Write + ?Sized)) -> Result<(), OutputError> {
    serde_json::to_writer(&mut *out, record)?;
    out.write_all(b"\n")?;
    Ok(())
}

#[cfg(test)]
pub(super) mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_core::hash::Digest;
    use crawlx_core::{CrawlRunId, TrustLane};
    use crawlx_extract::StaticInput;
    use serde_json::json;

    pub(crate) fn page(url: &str, meta: Value) -> PageRecord {
        PageRecord {
            run: CrawlRunId::new(),
            frontier_id: 1,
            url: crawlx_storage::testkit::canonical_url(url),
            status: 200,
            content_type: Some("text/html".to_owned()),
            content_digest: Digest::of("t", b"x"),
            title: Some("T".to_owned()),
            markdown: None,
            html: None,
            metadata: meta,
            links: Vec::new(),
            fetched_at: chrono::DateTime::from_timestamp(1_700_000_000, 0).unwrap(),
            lane: TrustLane::Diagnostic,
        }
    }

    /// A stored login form (`StaticForm` as the URL plane writes it into `metadata.forms`).
    pub(crate) fn login_form() -> Value {
        let input = |name: &str, kind: &str| StaticInput {
            name: name.to_owned(),
            kind: kind.to_owned(),
            ..StaticInput::default()
        };
        serde_json::to_value(StaticForm {
            action: "https://e.com/login".parse().unwrap(),
            method: "POST".to_owned(),
            enctype: Some("application/x-www-form-urlencoded".to_owned()),
            inputs: vec![input("username", "text"), input("password", "password")],
            submit_labels: vec!["Log in".to_owned()],
        })
        .unwrap()
    }

    /// Metadata with every key the record reads.
    pub(crate) fn full_metadata() -> Value {
        json!({
            "request": {
                "tag": "form", "attribute": "action", "source": "https://e.com/",
                "method": "POST",
                "headers": {"content-type": "application/x-www-form-urlencoded", "cookie": "[redacted]"},
                "body": "user=a&pass=b",
                "raw": "POST /p HTTP/1.1\r\nhost: e.com\r\n\r\nuser=a&pass=b",
                "custom_fields": {"email": ["a@e.com"]}
            },
            "response_headers": {"content-type": "text/html", "x-n": 1},
            "content_length": 1234,
            "technologies": [{"name": "nginx", "evidence": "header:server"}],
            "page_type": "login",
            "forms": [login_form()],
            "custom_fields": {"email": ["a@e.com"]},
            "secrets": [{"kind": "jwt", "location": {"body": {"offset": 3}}, "value_hash": "ab", "validation": "unknown"}],
            "xhr_requests": [{"method": "POST", "url": "https://e.com/api", "status": 201, "resource_type": "xhr", "endpoint_class": "rest"}],
            "endpoints": [{"url": "https://e.com/api", "method": "POST", "class": "rest"}]
        })
    }

    /// A record with every field set.
    pub(crate) fn full_record() -> Record {
        let p = page("https://e.com/p?x=1", full_metadata());
        let mut r = Record::from_page(&p, Some("<b>".to_owned()));
        r.attach_knowledgebase(&p);
        let response = r.response.as_mut().unwrap();
        response.raw = Some("HTTP/1.1 200 OK\r\n\r\n<b>".to_owned());
        response.stored_response_path = Some("/tmp/x.txt".to_owned());
        response.extra.insert("hook".to_owned(), json!(1));
        r.error = Some("boom".to_owned());
        r.fidelity = Some(ExchangeFidelity::from_record(&p.metadata, &r));
        r
    }

    #[test]
    fn from_page_reads_the_metadata_contract() {
        let meta = json!({
            "request": {"tag": "a", "attribute": "href", "source": "https://e.com/"},
            "response_headers": {"content-type": "text/html", "x-n": 1},
            "technologies": [{"name": "nginx", "evidence": "header:server"}],
            "page_type": "article",
            "forms": [{"action": "https://e.com/s", "method": "post"}],
            "custom_fields": {"email": ["a@e.com"]},
            "secrets": [{"kind": "jwt", "location": {"body": {"offset": 3}}, "value_hash": "ab"}]
        });
        let r = Record::from_page(&page("https://e.com/p?x=1", meta), Some("<b>".to_owned()));
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["timestamp"], "2023-11-14T22:13:20Z");
        assert_eq!(v["request"]["method"], "GET");
        assert_eq!(v["request"]["endpoint"], "https://e.com/p?x=1");
        assert_eq!(v["request"]["tag"], "a");
        assert_eq!(v["request"]["source"], "https://e.com/");
        assert_eq!(v["response"]["status_code"], 200);
        assert_eq!(v["response"]["headers"], json!({"content-type": "text/html"}));
        assert_eq!(v["response"]["body"], "<b>");
        assert_eq!(v["response"]["technologies"][0]["name"], "nginx");
        assert_eq!(v["response"]["page_type"], "article");
        assert_eq!(v["response"]["forms"][0]["method"], "post");
        assert_eq!(v["response"]["custom_fields"]["email"][0], "a@e.com");
        assert_eq!(
            v["request"]["custom_fields"]["email"][0], "a@e.com",
            "the reference puts custom fields under request; the top-level metadata key is the fallback"
        );
        assert_eq!(v["response"]["secrets"][0]["kind"], "jwt");
        assert!(v.get("error").is_none());
        let back: Record = serde_json::from_value(v).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn new_compat_fields_come_from_the_metadata_contract() {
        let p = page("https://e.com/p", full_metadata());
        let mut r = Record::from_page(&p, None);
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["request"]["method"], "POST");
        assert_eq!(v["request"]["body"], "user=a&pass=b");
        assert_eq!(v["request"]["headers"]["cookie"], "[redacted]");
        assert_eq!(
            v["request"]["raw"],
            "POST /p HTTP/1.1\r\nhost: e.com\r\n\r\nuser=a&pass=b"
        );
        assert_eq!(v["request"]["custom_fields"]["email"][0], "a@e.com");
        assert_eq!(v["response"]["content_length"], 1234);
        assert_eq!(
            v["response"]["xhr_requests"],
            json!([{"method": "POST", "endpoint": "https://e.com/api", "status": 201, "resource_type": "xhr", "endpoint_class": "rest"}])
        );
        assert!(
            v["response"].get("knowledgebase").is_none(),
            "only with attach_knowledgebase"
        );
        assert!(
            v["response"].get("raw").is_none(),
            "raw text is supplied by the caller"
        );

        r.attach_knowledgebase(&p);
        let kb = serde_json::to_value(&r).unwrap()["response"]["knowledgebase"].clone();
        assert_eq!(kb["PageType"], "login");
        assert_eq!(kb["Forms"][0]["type"], "login");
        assert_eq!(kb["Forms"][0]["fields"]["password"], "password");
        assert_eq!(kb["secrets"][0]["validation"], "unknown");
        assert_eq!(kb["endpoints"][0]["class"], "rest");
    }

    #[test]
    fn request_custom_fields_win_over_the_fallback() {
        let meta = json!({
            "request": {"custom_fields": {"a": ["req"]}},
            "custom_fields": {"a": ["top"]}
        });
        let r = Record::from_page(&page("https://e.com/", meta), None);
        assert_eq!(r.request.unwrap().custom_fields["a"], ["req"]);
        assert_eq!(r.response.unwrap().custom_fields["a"], ["top"]);
    }

    #[test]
    fn absent_metadata_omits_optional_fields() {
        let mut p = page("https://e.com/", json!({}));
        let r = Record::from_page(&p, None);
        let v = serde_json::to_value(&r).unwrap();
        let resp = v["response"].as_object().unwrap();
        assert_eq!(resp.keys().collect::<Vec<_>>(), ["status_code"]);
        let req = v["request"].as_object().unwrap();
        assert_eq!(req.keys().collect::<Vec<_>>(), ["endpoint", "method"]);
        let mut r = r;
        r.attach_knowledgebase(&p);
        assert!(
            r.response.unwrap().knowledgebase.is_none(),
            "empty knowledge base is not attached"
        );
        p.status = 0;
        let v = serde_json::to_value(Record::from_page(&p, None)).unwrap();
        assert!(
            v["response"].get("status_code").is_none(),
            "the reference omits a zero status"
        );
    }

    #[test]
    fn failure_records_carry_the_error() {
        let r = Record::from_failure("https://e.com/x", Some(503), "unreachable");
        let v = serde_json::to_value(&r).unwrap();
        assert_eq!(v["error"], "unreachable");
        assert_eq!(v["request"]["endpoint"], "https://e.com/x");
        assert_eq!(v["response"]["status_code"], 503);
        assert!(v.get("timestamp").is_none());
        let v = serde_json::to_value(Record::from_failure("https://e.com/x", None, "dns")).unwrap();
        assert!(v.get("response").is_none());
    }

    #[test]
    fn exclude_fields_removes_top_level_and_nested_names() {
        let meta = json!({"response_headers": {"a": "b"}, "page_type": "form"});
        let mut r = Record::from_page(&page("https://e.com/", meta), Some("body".to_owned()));
        r.exclude_fields(&[
            "timestamp".to_owned(),
            "headers".to_owned(),
            "body".to_owned(),
            "nope".to_owned(),
        ]);
        let v = serde_json::to_value(&r).unwrap();
        assert!(v.get("timestamp").is_none());
        assert!(v["response"].get("headers").is_none());
        assert!(v["response"].get("body").is_none());
        assert_eq!(v["response"]["page_type"], "form");
        r.exclude_fields(&["request".to_owned()]);
        assert!(serde_json::to_value(&r).unwrap().get("request").is_none());
        let mut line = Vec::new();
        write_line(&r, &mut line).unwrap();
        assert!(line.ends_with(b"}\n"));
        assert_eq!(line.iter().filter(|b| **b == b'\n').count(), 1);
    }

    /// Every key of `v` at any depth below the record's three levels.
    fn keys(v: &Value) -> Vec<String> {
        let mut out = Vec::new();
        for part in ["request", "response"] {
            if let Some(o) = v.get(part).and_then(Value::as_object) {
                out.extend(o.keys().cloned());
            }
        }
        if let Some(o) = v.as_object() {
            out.extend(o.keys().cloned());
        }
        out
    }

    #[test]
    fn every_listed_field_can_be_excluded() {
        let full = full_record();
        let present = keys(&serde_json::to_value(&full).unwrap());
        for name in field_names() {
            assert!(present.iter().any(|k| k == name), "full record lacks `{name}`");
            let mut r = full.clone();
            r.exclude_fields(&[name.to_owned()]);
            let after = keys(&serde_json::to_value(&r).unwrap());
            assert!(
                !after.iter().any(|k| k == name),
                "`-eof {name}` left the field in: {after:?}"
            );
        }
    }

    #[test]
    fn shared_names_clear_request_and_response() {
        let mut r = full_record();
        r.exclude_fields(&[
            "body".to_owned(),
            "headers".to_owned(),
            "raw".to_owned(),
            "custom_fields".to_owned(),
        ]);
        let v = serde_json::to_value(&r).unwrap();
        for part in ["request", "response"] {
            for k in ["body", "headers", "raw", "custom_fields"] {
                assert!(v[part].get(k).is_none(), "{part}.{k}");
            }
        }
        assert_eq!(v["request"]["method"], "POST");
    }

    #[test]
    fn emptied_parts_are_dropped() {
        let mut r = Record::from_failure("https://e.com/x", Some(500), "boom");
        r.exclude_fields(&[
            "method".to_owned(),
            "endpoint".to_owned(),
            "status_code".to_owned(),
        ]);
        let v = serde_json::to_value(&r).unwrap();
        assert!(v.get("request").is_none());
        assert!(v.get("response").is_none());
        assert_eq!(v["error"], "boom");
    }

    #[test]
    fn field_names_are_sorted_and_unique() {
        let names = field_names();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(names, sorted);
        for expected in [
            "error",
            "request",
            "response",
            "timestamp",
            "method",
            "endpoint",
            "body",
            "headers",
            "raw",
            "custom_fields",
            "content_length",
            "xhr_requests",
            "stored_response_path",
            "knowledgebase",
            "extra",
            "status_code",
            "technologies",
            "forms",
        ] {
            assert!(names.contains(&expected), "{expected}");
        }
    }

    #[test]
    fn fidelity_schema_keeps_unavailable_distinct_from_known_empty() {
        let mut p = page("https://e.com/", json!({}));
        p.status = 0;
        let mut record = Record::from_page(&p, Some(String::new()));
        record
            .response
            .as_mut()
            .unwrap()
            .extra
            .insert("caller".to_owned(), json!({"n": 7}));
        let value = serde_json::to_value(&record).unwrap();
        assert_eq!(
            value["fidelity"],
            json!({
                "request_body": {
                    "availability": "unavailable", "representation": "unknown",
                    "redacted": null, "binary_lossy": null, "truncated": null
                },
                "request_raw": {
                    "availability": "unavailable", "representation": "unknown",
                    "redacted": null, "binary_lossy": null, "truncated": null
                },
                "response_body": {
                    "availability": "available", "representation": "unknown",
                    "redacted": null, "binary_lossy": null, "truncated": null
                },
                "response_raw": {
                    "availability": "unavailable", "representation": "unknown",
                    "redacted": null, "binary_lossy": null, "truncated": null
                },
                "omitted_fields": []
            })
        );
        assert_eq!(
            value["response"],
            json!({"body": "", "extra": {"caller": {"n": 7}}})
        );
        let unavailable = Record::from_page(&p, None);
        let value = serde_json::to_value(unavailable).unwrap();
        assert!(value["response"].get("body").is_none());
        assert!(value["response"].get("status_code").is_none());
        assert_eq!(value["fidelity"]["response_body"]["availability"], "unavailable");
        assert_eq!(
            serde_json::from_value::<Record>(serde_json::to_value(&record).unwrap()).unwrap(),
            record
        );
    }

    #[test]
    fn every_projection_preserves_all_other_compatibility_fields_including_extra() {
        let full = full_record();
        assert_eq!(full.response.as_ref().unwrap().extra["hook"], 1);
        for name in field_names() {
            let mut expected = serde_json::to_value(&full).unwrap();
            let mut projected = full.clone();
            projected.exclude_fields(&[name.to_owned()]);
            let mut actual = serde_json::to_value(projected).unwrap();
            expected.as_object_mut().unwrap().remove("fidelity");
            actual.as_object_mut().unwrap().remove("fidelity");
            expected.as_object_mut().unwrap().remove(name);
            for part in ["request", "response"] {
                if let Some(object) = expected.get_mut(part).and_then(Value::as_object_mut) {
                    object.remove(name);
                }
            }
            assert_eq!(actual, expected, "projection of {name}");
        }
    }

    #[test]
    fn field_projection_labels_omissions_and_can_remove_fidelity_itself() {
        let mut record = full_record();
        record.exclude_fields(&["raw".to_owned(), "body".to_owned(), "extra".to_owned()]);
        let facts = record.fidelity.as_ref().unwrap();
        assert_eq!(
            facts.response_body.availability,
            super::super::stored::Availability::Omitted
        );
        assert_eq!(
            facts.request_raw.availability,
            super::super::stored::Availability::Omitted
        );
        assert!(facts.omitted_fields.contains("extra"));
        assert!(facts.omitted_fields.contains("response.body"));
        record.exclude_fields(&["not_a_field".to_owned()]);
        assert!(!record
            .fidelity
            .as_ref()
            .unwrap()
            .omitted_fields
            .contains("not_a_field"));
        record.exclude_fields(&["fidelity".to_owned()]);
        assert!(serde_json::to_value(record).unwrap().get("fidelity").is_none());
    }

    #[test]
    fn browser_documents_do_not_invent_a_get_method() {
        for metadata in [
            json!({"acquisition": {"backend": {"backendId": "native_browser"}}}),
            json!({"acquisition": {"representation": "rendered_dom"}}),
        ] {
            let page = page("https://e.com/post-action", metadata);
            let record = Record::from_page(&page, None);
            let value = serde_json::to_value(&record).unwrap();
            assert!(value["request"].get("method").is_none());
            let exchange = super::super::stored::exchange(
                &page.url.url,
                record.request.as_ref(),
                record.response.as_ref(),
                record.fidelity.as_ref().unwrap(),
            );
            assert!(!exchange.contains("GET "));
            assert!(exchange.contains("# request unavailable: method not recorded"));
        }
        let explicit = Record::from_page(
            &page(
                "https://e.com/",
                json!({
                    "acquisition": {"backend": {"backendId": "native_browser"}},
                    "request": {"method": "POST"}
                }),
            ),
            None,
        );
        assert_eq!(explicit.request.unwrap().method, "POST");
        let legacy = Record::from_page(&page("https://e.com/", json!({})), None);
        assert_eq!(legacy.request.unwrap().method, "GET");
    }
}
