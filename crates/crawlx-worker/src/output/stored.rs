//! Stored diagnostic exchanges (`-sr/-srd`) and per-record output fidelity.
//!
//! Compatibility names such as `raw` do not promise original wire bytes. Each stored
//! section carries its representation, body availability, truncation and lossiness facts.
//! Unknown facts stay unknown. Reconstruction never invents a status or an empty body.
//! Files use `<dir>/<host>/<sha1(url)>.txt`; later exchanges use numbered siblings,
//! reserved with exclusive creation so repeated or concurrent exports cannot overwrite.
//! `index.txt` is append-only. `-ncb` also numbers a reused non-empty directory.

use super::jsonl::{Record, Request, Response};
use super::text_file::unclobbered;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha1::{Digest, Sha1};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use url::Url;

/// Default directory of `-sr` without `-srd`.
pub const DEFAULT_DIR: &str = "crawlx_response";
/// Name of the index file inside the directory.
pub const INDEX_FILE: &str = "index.txt";

/// Whether a payload was supplied, unavailable, or intentionally left out.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Availability {
    /// Supplied, including an explicitly known empty payload.
    Available,
    /// No payload was supplied; this does not mean an empty payload.
    #[default]
    Unavailable,
    /// Export policy or field projection intentionally removed the payload.
    Omitted,
}

/// Provenance of the exported bytes, independent of redaction or truncation.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Representation {
    /// No source fact establishes the representation.
    #[default]
    Unknown,
    /// Original wire bytes, only with an explicit source attestation.
    CapturedWire,
    /// Text projected from a decoded response or request body.
    DecodedText,
    /// Serialized browser DOM, not the HTTP response body.
    RenderedDom,
    /// An HTTP-like diagnostic assembled from recorded fields.
    Reconstructed,
}

/// Facts about one exported payload. `None` means unknown, never `false`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct PayloadFidelity {
    /// Export availability, not whether the original exchange had a body.
    pub availability: Availability,
    /// Attested representation; absence of facts is `unknown`.
    pub representation: Representation,
    /// Whether a privacy/redaction transformation was applied.
    pub redacted: Option<bool>,
    /// Whether conversion of binary bytes to text lost information.
    pub binary_lossy: Option<bool>,
    /// Whether the payload was capped; `None` does not assert completeness.
    pub truncated: Option<bool>,
}

/// Additive JSONL fidelity facts, retained even when payload fields are projected out.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
#[non_exhaustive]
pub struct ExchangeFidelity {
    /// Request body facts.
    pub request_body: PayloadFidelity,
    /// Request diagnostic/raw text facts.
    pub request_raw: PayloadFidelity,
    /// Response body facts.
    pub response_body: PayloadFidelity,
    /// Response diagnostic/raw text facts.
    pub response_raw: PayloadFidelity,
    /// Explicitly excluded field names and policy-omitted payload paths, sorted.
    pub omitted_fields: BTreeSet<String>,
}

impl ExchangeFidelity {
    /// Read source attestations from `metadata.output_fidelity`.
    /// Supplied fields determine availability; metadata cannot fabricate a payload.
    #[must_use]
    pub fn from_record(metadata: &Value, record: &Record) -> Self {
        let source = metadata.get("output_fidelity");
        let request = record.request.as_ref();
        let response = record.response.as_ref();
        let mut facts = Self {
            request_body: payload(source, "request_body", request.and_then(|r| r.body.as_deref())),
            request_raw: payload(source, "request_raw", request.and_then(|r| r.raw.as_deref())),
            response_body: payload(source, "response_body", response.and_then(|r| r.body.as_deref())),
            response_raw: payload(source, "response_raw", response.and_then(|r| r.raw.as_deref())),
            omitted_fields: BTreeSet::new(),
        };
        if metadata
            .pointer("/acquisition/representation")
            .and_then(Value::as_str)
            == Some("rendered_dom")
        {
            facts.response_body.representation = Representation::RenderedDom;
        }
        facts
    }

    /// Mark intentional omission without discarding the known source facts.
    pub fn omit(&mut self, field: &str) {
        let payload = match field {
            "request.body" => Some(&mut self.request_body),
            "request.raw" => Some(&mut self.request_raw),
            "response.body" => Some(&mut self.response_body),
            "response.raw" => Some(&mut self.response_raw),
            _ => None,
        };
        if let Some(payload) = payload {
            payload.availability = Availability::Omitted;
        }
        self.omitted_fields.insert(field.to_owned());
    }
}

fn payload(source: Option<&Value>, key: &str, text: Option<&str>) -> PayloadFidelity {
    let mut facts: PayloadFidelity = source
        .and_then(|source| source.get(key))
        .and_then(|value| PayloadFidelity::deserialize(value).ok())
        .unwrap_or_default();
    facts.availability = if text.is_some() {
        Availability::Available
    } else if facts.availability == Availability::Omitted {
        Availability::Omitted
    } else {
        Availability::Unavailable
    };
    facts
}

/// Where raw request/response text is stored.
#[derive(Clone, Debug)]
pub struct StoredResponses {
    dir: PathBuf,
}

impl StoredResponses {
    /// Create the store: the directory (and `index.txt` inside it). With `no_clobber` an
    /// existing non-empty directory is left alone and `<dir><N>` is used.
    ///
    /// # Errors
    /// I/O errors from creating the directory or the index.
    pub fn new(dir: impl AsRef<Path>, no_clobber: bool) -> io::Result<Self> {
        let dir = if no_clobber {
            unclobbered(dir.as_ref())?
        } else {
            dir.as_ref().to_owned()
        };
        fs::create_dir_all(&dir)?;
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(INDEX_FILE))?;
        Ok(Self { dir })
    }

    /// The directory in use (differs from the requested one under `no_clobber`).
    #[must_use]
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// The index file.
    #[must_use]
    pub fn index_path(&self) -> PathBuf {
        self.dir.join(INDEX_FILE)
    }

    /// File name directory of `url`: host with `:` replaced by `_`.
    fn host_dir(url: &Url) -> String {
        let mut host = url.host_str().unwrap_or("unknown-host").to_owned();
        if let Some(port) = url.port() {
            let _ = write!(host, ":{port}");
        }
        host.replace(':', "_")
    }

    /// The file `url` is stored in.
    #[must_use]
    pub fn path_for(&self, url: &Url) -> PathBuf {
        let mut hash = String::with_capacity(40);
        for byte in Sha1::digest(url.as_str().as_bytes()) {
            let _ = write!(hash, "{byte:02x}");
        }
        self.dir.join(Self::host_dir(url)).join(format!("{hash}.txt"))
    }

    /// Store supplied diagnostic text with unknown provenance, without overwriting any
    /// prior exchange. Use [`Self::store_record`] to retain per-record fidelity facts.
    ///
    /// # Errors
    /// I/O errors from writing the file or the index.
    pub fn store(
        &self,
        url: &Url,
        status: u16,
        request_raw: &str,
        response_raw: &str,
    ) -> io::Result<PathBuf> {
        let facts = PayloadFidelity {
            availability: Availability::Available,
            ..PayloadFidelity::default()
        };
        let mut data = String::new();
        section(
            &mut data,
            "request",
            Some(request_raw),
            &facts,
            &PayloadFidelity::default(),
        );
        section(
            &mut data,
            "response",
            Some(response_raw),
            &facts,
            &PayloadFidelity::default(),
        );
        self.write_exchange(url, status, &data)
    }

    /// Store a labelled exchange from the compatibility record, including missing parts.
    ///
    /// # Errors
    /// I/O errors from reserving/writing the file or appending its index entry.
    pub fn store_record(&self, url: &Url, record: &Record) -> io::Result<PathBuf> {
        let facts = record.fidelity.as_ref().map_or_else(
            || Cow::Owned(ExchangeFidelity::from_record(&Value::Null, record)),
            Cow::Borrowed,
        );
        let text = exchange(url, record.request.as_ref(), record.response.as_ref(), &facts);
        self.write_exchange(url, record.response.as_ref().map_or(0, |r| r.status_code), &text)
    }

    fn write_exchange(&self, url: &Url, status: u16, data: &str) -> io::Result<PathBuf> {
        let base = self.path_for(url);
        if let Some(parent) = base.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut path = base.clone();
        let mut suffix = 0_u64;
        let mut file = loop {
            match OpenOptions::new().write(true).create_new(true).open(&path) {
                Ok(file) => break file,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    suffix = suffix
                        .checked_add(1)
                        .ok_or_else(|| io::Error::other("stored exchange suffix exhausted"))?;
                    path = base.with_extension(format!("{suffix}.txt"));
                }
                Err(error) => return Err(error),
            }
        };
        writeln!(file, "{url}\n\n\n{data}")?;

        let status = if status == 0 {
            "unavailable".to_owned()
        } else {
            http::StatusCode::from_u16(status)
                .ok()
                .and_then(|s| s.canonical_reason().map(|r| format!("{} {r}", s.as_u16())))
                .unwrap_or_else(|| status.to_string())
        };
        let mut index = OpenOptions::new().append(true).open(self.index_path())?;
        writeln!(index, "{} {} ({status})", path.display(), url)?;
        Ok(std::path::absolute(&path).unwrap_or(path))
    }
}

/// Render labelled diagnostic sections without claiming reconstructed text is wire evidence.
/// Missing records and bodies remain explicitly unavailable; known empty bodies stay empty.
#[must_use]
pub fn exchange(
    url: &Url,
    request: Option<&Request>,
    response: Option<&Response>,
    fidelity: &ExchangeFidelity,
) -> String {
    let mut text = String::new();
    let request_text = request.map(|r| {
        if fidelity.request_raw.availability == Availability::Omitted {
            Cow::Borrowed("# exchange omitted")
        } else {
            r.raw.as_deref().map_or_else(
                || Cow::Owned(request_diagnostic(url, r, fidelity.request_body.availability)),
                Cow::Borrowed,
            )
        }
    });
    let response_text = response.map(|r| {
        if fidelity.response_raw.availability == Availability::Omitted {
            Cow::Borrowed("# exchange omitted")
        } else {
            r.raw.as_deref().map_or_else(
                || Cow::Owned(response_diagnostic(r, fidelity.response_body.availability)),
                Cow::Borrowed,
            )
        }
    });
    let reconstructed = |facts: PayloadFidelity, body: PayloadFidelity, has_raw: bool, present: bool| {
        if facts.availability == Availability::Omitted || has_raw || !present {
            facts
        } else {
            PayloadFidelity {
                availability: Availability::Available,
                representation: Representation::Reconstructed,
                truncated: body.truncated,
                binary_lossy: body.binary_lossy,
                redacted: facts.redacted.or(body.redacted.filter(|redacted| *redacted)),
            }
        }
    };
    section(
        &mut text,
        "request",
        request_text.as_deref(),
        &reconstructed(
            fidelity.request_raw,
            fidelity.request_body,
            request.is_some_and(|r| r.raw.is_some()),
            request.is_some_and(|r| !r.method.is_empty()),
        ),
        &fidelity.request_body,
    );
    section(
        &mut text,
        "response",
        response_text.as_deref(),
        &reconstructed(
            fidelity.response_raw,
            fidelity.response_body,
            response.is_some_and(|r| r.raw.is_some()),
            response.is_some_and(|r| r.status_code != 0),
        ),
        &fidelity.response_body,
    );
    text
}

fn section(
    text: &mut String,
    name: &str,
    raw: Option<&str>,
    facts: &PayloadFidelity,
    body: &PayloadFidelity,
) {
    let fact = |value: Option<bool>| value.map_or("unknown", |value| if value { "true" } else { "false" });
    let _ = writeln!(
        text,
        "# {name}: representation={:?}; availability={:?}; body={:?}; truncated={}; redacted={}; binary_lossy={}",
        facts.representation, facts.availability, body.availability,
        fact(facts.truncated), fact(facts.redacted), fact(facts.binary_lossy),
    );
    text.push_str(raw.unwrap_or(if facts.availability == Availability::Omitted {
        "# exchange omitted"
    } else {
        "# exchange unavailable"
    }));
    text.push_str("\n\n");
}

/// A request text for a page whose run did not capture the raw one: request line, `host`,
/// the recorded headers and the body.
#[must_use]
pub fn synthesize_request(url: &Url, request: &Request) -> String {
    request_diagnostic(url, request, Availability::Unavailable)
}

fn request_diagnostic(url: &Url, request: &Request, availability: Availability) -> String {
    if request.method.is_empty() {
        return "# request unavailable: method not recorded".to_owned();
    }
    let method = &request.method;
    let mut target = url.path().to_owned();
    if let Some(q) = url.query() {
        target.push('?');
        target.push_str(q);
    }
    let mut text = format!("{method} {target} HTTP/1.1\r\n");
    if let Some(host) = url.host_str() {
        let _ = write!(text, "host: {host}");
        if let Some(port) = url.port() {
            let _ = write!(text, ":{port}");
        }
        text.push_str("\r\n");
    }
    for (name, value) in &request.headers {
        let _ = write!(text, "{name}: {value}\r\n");
    }
    text.push_str("\r\n");
    append_body(&mut text, request.body.as_deref(), availability);
    text
}

/// A response text for a page whose run did not capture the raw one: status line, the
/// recorded headers and the body when it is known.
#[must_use]
pub fn synthesize_response(response: &Response) -> String {
    response_diagnostic(response, Availability::Unavailable)
}

fn response_diagnostic(response: &Response, availability: Availability) -> String {
    if response.status_code == 0 {
        return "# response unavailable: status not recorded".to_owned();
    }
    let reason = http::StatusCode::from_u16(response.status_code)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("");
    let mut text = format!("HTTP/1.1 {} {reason}\r\n", response.status_code);
    for (name, value) in &response.headers {
        let _ = write!(text, "{name}: {value}\r\n");
    }
    text.push_str("\r\n");
    append_body(&mut text, response.body.as_deref(), availability);
    text
}

fn append_body(text: &mut String, body: Option<&str>, availability: Availability) {
    if availability == Availability::Omitted {
        text.push_str("# body omitted");
    } else {
        text.push_str(body.unwrap_or("# body unavailable"));
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn layout_and_index_follow_the_reference() {
        let dir = tempfile::tempdir().unwrap();
        let store = StoredResponses::new(dir.path().join("resp"), false).unwrap();
        assert!(store.index_path().is_file(), "index exists before any response");
        let u = url("http://127.0.0.1:8080/a?b=1");
        let path = store
            .store(
                &u,
                200,
                "GET /a?b=1 HTTP/1.1\r\n\r\n",
                "HTTP/1.1 200 OK\r\n\r\nhi",
            )
            .unwrap();
        assert!(path.is_absolute());
        // sha1 of the URL string, host with ':' replaced by '_'
        assert_eq!(path.parent().unwrap().file_name().unwrap(), "127.0.0.1_8080");
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        assert_eq!(name.len(), 44, "40 hex digits + .txt");
        assert!(name.ends_with(".txt"));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            concat!(
                "http://127.0.0.1:8080/a?b=1\n\n\n",
                "# request: representation=Unknown; availability=Available; body=Unavailable; ",
                "truncated=unknown; redacted=unknown; binary_lossy=unknown\n",
                "GET /a?b=1 HTTP/1.1\r\n\r\n\n\n",
                "# response: representation=Unknown; availability=Available; body=Unavailable; ",
                "truncated=unknown; redacted=unknown; binary_lossy=unknown\n",
                "HTTP/1.1 200 OK\r\n\r\nhi\n\n\n"
            )
        );
        let index = fs::read_to_string(store.index_path()).unwrap();
        assert_eq!(
            index,
            format!(
                "{} http://127.0.0.1:8080/a?b=1 (200 OK)\n",
                store.path_for(&u).display()
            )
        );
    }

    #[test]
    fn sha1_matches_the_known_digest() {
        let dir = tempfile::tempdir().unwrap();
        let store = StoredResponses::new(dir.path(), false).unwrap();
        // sha1("http://e.com/") = 0b4e... computed independently with `sha1sum`
        let p = store.path_for(&url("http://e.com/"));
        let mut expected = String::new();
        for byte in Sha1::digest(b"http://e.com/") {
            let _ = write!(expected, "{byte:02x}");
        }
        assert_eq!(
            p.file_name().unwrap().to_string_lossy(),
            format!("{expected}.txt")
        );
        assert_eq!(expected.len(), 40);
    }

    #[test]
    fn a_reused_directory_appends_to_its_index() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("resp");
        let first = StoredResponses::new(&target, false).unwrap();
        first.store(&url("https://e.com/1"), 200, "q", "r").unwrap();
        let second = StoredResponses::new(&target, false).unwrap();
        second.store(&url("https://e.com/2"), 404, "q", "r").unwrap();
        let index = fs::read_to_string(second.index_path()).unwrap();
        assert_eq!(index.lines().count(), 2);
        assert!(index
            .lines()
            .next()
            .unwrap()
            .ends_with("https://e.com/1 (200 OK)"));
        assert!(index
            .lines()
            .nth(1)
            .unwrap()
            .ends_with("https://e.com/2 (404 Not Found)"));
    }

    #[test]
    fn no_clobber_numbers_a_non_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("resp");
        let first = StoredResponses::new(&target, true).unwrap();
        assert_eq!(first.dir(), target, "a missing directory is used as is");
        first.store(&url("https://e.com/1"), 200, "q", "r").unwrap();
        let second = StoredResponses::new(&target, true).unwrap();
        assert_eq!(second.dir(), dir.path().join("resp1"));
        second.store(&url("https://e.com/2"), 200, "q", "r").unwrap();
        let third = StoredResponses::new(&target, true).unwrap();
        assert_eq!(third.dir(), dir.path().join("resp2"));
        assert_eq!(
            fs::read_to_string(first.index_path()).unwrap().lines().count(),
            1,
            "the first directory is untouched"
        );
    }

    #[test]
    fn synthesized_texts_carry_headers_and_body() {
        let u = url("https://e.com:8443/p?q=1");
        let req = Request {
            method: "POST".to_owned(),
            headers: [("content-type".to_owned(), "text/plain".to_owned())].into(),
            body: Some("x=1".to_owned()),
            ..Request::default()
        };
        assert_eq!(
            synthesize_request(&u, &req),
            "POST /p?q=1 HTTP/1.1\r\nhost: e.com:8443\r\ncontent-type: text/plain\r\n\r\nx=1"
        );
        let resp = Response {
            status_code: 404,
            headers: [("server".to_owned(), "nginx".to_owned())].into(),
            body: Some("nope".to_owned()),
            ..Response::default()
        };
        assert_eq!(
            synthesize_response(&resp),
            "HTTP/1.1 404 Not Found\r\nserver: nginx\r\n\r\nnope"
        );
        assert_eq!(
            synthesize_request(&url("https://e.com/"), &Request::default()),
            "# request unavailable: method not recorded"
        );
    }

    #[test]
    fn repeated_exports_reserve_distinct_files_and_keep_the_first_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let store = StoredResponses::new(dir.path(), false).unwrap();
        let u = url("https://e.com/repeated");
        let first = store.store(&u, 200, "first request", "first response").unwrap();
        let before = fs::read(&first).unwrap();
        let second = store.store(&u, 201, "second request", "second response").unwrap();
        assert_ne!(first, second);
        assert_eq!(fs::read(&first).unwrap(), before);
        assert!(fs::read_to_string(second).unwrap().contains("second response"));
        assert_eq!(fs::read_to_string(store.index_path()).unwrap().lines().count(), 2);
    }

    #[test]
    fn concurrent_exports_cannot_replace_an_exchange() {
        let dir = tempfile::tempdir().unwrap();
        let store = StoredResponses::new(dir.path(), false).unwrap();
        let u = url("https://e.com/concurrent");
        let paths = std::thread::scope(|scope| {
            let tasks: Vec<_> = (0..4)
                .map(|number| {
                    let store = &store;
                    let u = &u;
                    scope.spawn(move || store.store(u, 200, "request", &number.to_string()).unwrap())
                })
                .collect();
            tasks
                .into_iter()
                .map(|task| task.join().unwrap())
                .collect::<BTreeSet<_>>()
        });
        assert_eq!(paths.len(), 4);
        assert!(paths.iter().all(|path| path.is_file()));
    }

    #[test]
    fn missing_exchange_does_not_invent_success_or_empty_body() {
        let record = Record::default();
        let facts = ExchangeFidelity::from_record(&Value::Null, &record);
        let text = exchange(&url("https://e.com/"), None, None, &facts);
        assert!(text.contains("availability=Unavailable"));
        assert!(text.contains("# exchange unavailable"));
        assert!(!text.contains("HTTP/1.1"));
        assert!(!text.contains("200"));
        assert_eq!(
            synthesize_response(&Response::default()),
            "# response unavailable: status not recorded"
        );
        let dir = tempfile::tempdir().unwrap();
        let store = StoredResponses::new(dir.path(), false).unwrap();
        store.store_record(&url("https://e.com/"), &record).unwrap();
        assert!(fs::read_to_string(store.index_path())
            .unwrap()
            .contains("(unavailable)"));
    }

    #[test]
    fn reconstructed_exchange_labels_missing_and_known_empty_bodies() {
        let mut record = Record {
            request: Some(Request {
                method: "GET".to_owned(),
                ..Request::default()
            }),
            response: Some(Response {
                status_code: 204,
                body: Some(String::new()),
                ..Response::default()
            }),
            ..Record::default()
        };
        let facts = ExchangeFidelity::from_record(&Value::Null, &record);
        let text = exchange(
            &url("https://e.com/"),
            record.request.as_ref(),
            record.response.as_ref(),
            &facts,
        );
        assert!(text.contains("representation=Reconstructed"));
        assert!(text.contains("# body unavailable"));
        assert_eq!(text.matches("# body unavailable").count(), 1);
        assert!(text.contains("body=Available"));
        assert!(text.contains("HTTP/1.1 204 No Content"));
        record.response.as_mut().unwrap().status_code = 0;
        let text = exchange(&url("https://e.com/"), None, record.response.as_ref(), &facts);
        assert!(!text.contains("HTTP/1.1 0"));
        assert!(!text.contains("HTTP/1.1 200"));
    }

    #[test]
    fn source_facts_separate_wire_decoded_redacted_lossy_and_unknown() {
        let record = Record {
            request: Some(Request {
                raw: Some("captured".to_owned()),
                ..Request::default()
            }),
            response: Some(Response {
                raw: Some("diagnostic".to_owned()),
                body: Some("\u{fffd}".to_owned()),
                ..Response::default()
            }),
            ..Record::default()
        };
        let metadata = serde_json::json!({
            "output_fidelity": {
                "request_raw": {"representation": "captured_wire", "redacted": false, "binary_lossy": false, "truncated": false},
                "response_raw": {"representation": "reconstructed", "redacted": true, "binary_lossy": true, "truncated": true},
                "response_body": {"representation": "decoded_text", "binary_lossy": true, "truncated": true}
            }
        });
        let facts = ExchangeFidelity::from_record(&metadata, &record);
        assert_eq!(facts.request_raw.representation, Representation::CapturedWire);
        assert_eq!(facts.response_body.representation, Representation::DecodedText);
        assert_eq!(facts.response_raw.redacted, Some(true));
        assert_eq!(facts.response_raw.binary_lossy, Some(true));
        assert_eq!(facts.response_raw.truncated, Some(true));
        let text = exchange(
            &url("https://e.com/"),
            record.request.as_ref(),
            record.response.as_ref(),
            &facts,
        );
        assert!(text.contains("representation=CapturedWire"));
        assert!(text.contains("binary_lossy=true"));
        let unknown = ExchangeFidelity::from_record(&Value::Null, &record);
        assert_eq!(unknown.response_raw.representation, Representation::Unknown);
        assert_eq!(unknown.response_raw.truncated, None);
        assert_eq!(
            unknown.response_body.binary_lossy, None,
            "replacement characters do not prove loss"
        );
        let absent = ExchangeFidelity::from_record(&metadata, &Record::default());
        assert_eq!(absent.request_raw.availability, Availability::Unavailable);
    }

    #[test]
    fn separate_retained_capture_flags_do_not_claim_exported_text_completeness() {
        let record = Record::default();
        let facts = ExchangeFidelity::from_record(
            &serde_json::json!({"response_body_capture": {"truncated": true}}),
            &record,
        );
        assert_eq!(facts.response_body.truncated, None);
        assert_eq!(facts.response_raw.truncated, None);
        let unknown = ExchangeFidelity::from_record(&serde_json::json!({"content_length": 0}), &record);
        assert_eq!(unknown.response_body.truncated, None);
    }

    #[test]
    fn omitted_payloads_are_not_reconstructed_or_revealed() {
        let record = Record {
            request: Some(Request {
                method: "POST".to_owned(),
                raw: Some("private diagnostic".to_owned()),
                ..Request::default()
            }),
            response: Some(Response {
                status_code: 200,
                body: Some("private body".to_owned()),
                ..Response::default()
            }),
            ..Record::default()
        };
        let mut facts = ExchangeFidelity::from_record(&Value::Null, &record);
        facts.omit("request.raw");
        facts.omit("response.body");
        let text = exchange(
            &url("https://e.com/"),
            record.request.as_ref(),
            record.response.as_ref(),
            &facts,
        );
        assert!(text.contains("# exchange omitted"));
        assert!(text.contains("# body omitted"));
        assert!(text.contains("availability=Omitted"));
        assert!(!text.contains("private diagnostic"));
        assert!(!text.contains("private body"));
    }
}
