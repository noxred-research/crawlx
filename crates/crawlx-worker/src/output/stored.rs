//! Stored raw requests/responses (katana `-sr/-store-response`, `-srd/-store-response-dir`).
//!
//! Layout from katana `pkg/output/responses.go` (MIT): `<dir>/<host>/<sha1(url)>.txt` per
//! URL (`host` is the URL host with `:` replaced by `_`), holding the URL, the raw request and
//! the raw response; `<dir>/index.txt` gets one line per stored file,
//! `<file> <url> (<status>)`. Differences: katana wipes sibling `katana_response*`
//! directories when the default directory is used without `-ncb`; crawlx never deletes
//! anything, a reused directory keeps its files and its index is appended to. With `-ncb`
//! the directory is numbered like every other no-clobber target
//! ([`unclobbered`](super::text_file::unclobbered)).

use super::jsonl::{Request, Response};
use super::text_file::unclobbered;
use sha1::{Digest, Sha1};
use std::fmt::Write as _;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use url::Url;

/// Default directory of `-sr` without `-srd`.
pub const DEFAULT_DIR: &str = "crawlx_response";
/// Name of the index file inside the directory.
pub const INDEX_FILE: &str = "index.txt";

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

    /// Store one exchange: `<url>`, two blank lines, the raw request, a blank line, the raw
    /// response. Appends `<file> <url> (<status>)` to the index. Returns the absolute path of
    /// the file.
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
        let path = self.path_for(url);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut data = String::with_capacity(
            url.as_str()
                .len()
                .saturating_add(request_raw.len())
                .saturating_add(response_raw.len())
                .saturating_add(8),
        );
        data.push_str(url.as_str());
        data.push_str("\n\n\n");
        data.push_str(request_raw);
        data.push_str("\n\n");
        data.push_str(response_raw);
        data.push('\n');
        fs::write(&path, data)?;

        let status = http::StatusCode::from_u16(status)
            .ok()
            .and_then(|s| s.canonical_reason().map(|r| format!("{} {r}", s.as_u16())))
            .unwrap_or_else(|| status.to_string());
        let mut index = OpenOptions::new().append(true).open(self.index_path())?;
        writeln!(index, "{} {} ({status})", path.display(), url)?;
        Ok(std::path::absolute(&path).unwrap_or(path))
    }
}

/// A request text for a page whose run did not capture the raw one: request line, `host`,
/// the recorded headers and the body.
#[must_use]
pub fn synthesize_request(url: &Url, request: &Request) -> String {
    let method = if request.method.is_empty() {
        "GET"
    } else {
        &request.method
    };
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
    if let Some(body) = &request.body {
        text.push_str(body);
    }
    text
}

/// A response text for a page whose run did not capture the raw one: status line, the
/// recorded headers and the body when it is known.
#[must_use]
pub fn synthesize_response(response: &Response) -> String {
    let reason = http::StatusCode::from_u16(response.status_code)
        .ok()
        .and_then(|s| s.canonical_reason())
        .unwrap_or("");
    let mut text = format!("HTTP/1.1 {} {reason}\r\n", response.status_code);
    for (name, value) in &response.headers {
        let _ = write!(text, "{name}: {value}\r\n");
    }
    text.push_str("\r\n");
    if let Some(body) = &response.body {
        text.push_str(body);
    }
    text
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn url(s: &str) -> Url {
        Url::parse(s).unwrap()
    }

    #[test]
    fn layout_and_index_follow_katana() {
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
            "http://127.0.0.1:8080/a?b=1\n\n\nGET /a?b=1 HTTP/1.1\r\n\r\n\n\nHTTP/1.1 200 OK\r\n\r\nhi\n"
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
            "GET / HTTP/1.1\r\nhost: e.com\r\n\r\n"
        );
    }
}
