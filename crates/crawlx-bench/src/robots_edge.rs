//! The `robots-edge` fixture family: a deterministic loopback site per RFC 9309 edge case and
//! an oracle that compares what the origin *received* with the request set the RFC prescribes.
//!
//! A case is a `robots.txt` answer, a few nodes (pages, redirects, sitemaps) and the exact set
//! of paths a robots-obeying crawler may request. The expected sets are derived from the RFC
//! and from the case's own `robots.txt`, never from the crawler's counters: the origin's request
//! log is the only evidence, so a crawl that reports `robots_blocked` yet still sends the
//! request fails here.
//!
//! The static plane runs through the production worker ([`run_static`]); the browser plane runs
//! the same cases in real Chromium ([`run_browser`]) where one is installed. A browser also asks
//! for `/favicon.ico` and walks pages in its own order, so for it the oracle is the weaker
//! "nothing in [`Case::never`] was requested, and [`Case::browser_reaches`] was".
//!
//! Every case lives on `127.0.0.1` with an ephemeral port; there is no external network.

use crate::error::BenchError;
use axum::extract::State;
use axum::http::{header, HeaderValue, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::Router;
use parking_lot::Mutex;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// Crawl seed of every run: the fixture is deterministic, so is the crawl.
pub const SEED: u64 = 20_261_121;

/// What `/robots.txt` answers.
#[derive(Clone, Debug)]
pub enum Robots {
    /// An error or empty answer with this status (404, 429, 500, 503...).
    Status(u16),
    /// A 200 with this body; `{base}` stands for the site's origin.
    Text(String),
    /// A redirect to `/robots-moved.txt`, which serves the body.
    MovedTo(String),
}

/// One path of the site.
#[derive(Clone, Debug)]
pub enum Node {
    /// An HTML page linking to `links` (paths).
    Page(Vec<String>),
    /// A redirect with this status to this path.
    Redirect(u16, String),
    /// An XML document; `{base}` stands for the site's origin.
    Xml(String),
}

/// One RFC 9309 edge case.
#[derive(Clone, Debug)]
pub struct Case {
    /// Stable id.
    pub id: &'static str,
    /// The RFC 9309 section the verdict comes from.
    pub rfc: &'static str,
    /// The `/robots.txt` answer.
    pub robots: Robots,
    /// The site's paths; `/` is the crawl's seed.
    pub nodes: BTreeMap<String, Node>,
    /// The exact set of paths the origin sees from the static plane (sitemap discovery on).
    pub static_requests: BTreeSet<String>,
    /// Paths no robots-obeying crawler of any plane may request.
    pub never: BTreeSet<String>,
    /// Paths a browser run must have requested (besides `/robots.txt`).
    pub browser_reaches: BTreeSet<String>,
}

fn set<const N: usize>(paths: [&str; N]) -> BTreeSet<String> {
    paths.into_iter().map(str::to_owned).collect()
}

fn page(links: &[&str]) -> Node {
    Node::Page(links.iter().map(|l| (*l).to_owned()).collect())
}

fn text(body: &str) -> Robots {
    Robots::Text(body.to_owned())
}

/// A site made of a seed page linking to `links`, every link a leaf page, plus `extra` nodes.
fn site(links: &[&str], extra: Vec<(&str, Node)>) -> BTreeMap<String, Node> {
    let mut nodes = BTreeMap::new();
    nodes.insert("/".to_owned(), page(links));
    for link in links {
        nodes.entry((*link).to_owned()).or_insert_with(|| page(&[]));
    }
    for (path, node) in extra {
        nodes.insert(path.to_owned(), node);
    }
    nodes
}

/// Every case of the family.
#[must_use]
pub fn cases() -> Vec<Case> {
    let mut out = Vec::new();

    // ---- section 2.3.1: what each outcome of the /robots.txt fetch means ----
    for (id, status) in [
        ("robots-404-allows-everything", 404u16),
        ("robots-403-allows-everything", 403),
        ("robots-429-allows-everything", 429),
    ] {
        out.push(Case {
            id,
            rfc: "2.3.1.3",
            robots: Robots::Status(status),
            nodes: site(&["/a", "/b"], vec![]),
            static_requests: set(["/robots.txt", "/", "/a", "/b", "/sitemap.xml"]),
            never: set([]),
            browser_reaches: set(["/", "/a"]),
        });
    }
    out.push(Case {
        id: "robots-moved-then-200-applies-the-moved-file",
        rfc: "2.3.1.2",
        robots: Robots::MovedTo("User-agent: *\nDisallow: /closed\n".to_owned()),
        nodes: site(&["/open", "/closed"], vec![]),
        static_requests: set(["/robots.txt", "/robots-moved.txt", "/", "/open", "/sitemap.xml"]),
        never: set(["/closed"]),
        browser_reaches: set(["/", "/open"]),
    });
    out.push(Case {
        id: "robots-empty-file-allows-everything",
        rfc: "2.3.1.1",
        robots: text(""),
        nodes: site(&["/a"], vec![]),
        static_requests: set(["/robots.txt", "/", "/a", "/sitemap.xml"]),
        never: set([]),
        browser_reaches: set(["/", "/a"]),
    });

    // ---- section 2.2: groups, matching and precedence ----
    out.push(Case {
        id: "longest-match-allow-carves-out-a-disallow",
        rfc: "2.2.2",
        robots: text("User-agent: *\nDisallow: /p/\nAllow: /p/open\n"),
        nodes: site(&["/p/closed", "/p/open", "/p/open/x"], vec![]),
        static_requests: set(["/robots.txt", "/", "/sitemap.xml", "/p/open", "/p/open/x"]),
        never: set(["/p/closed"]),
        browser_reaches: set(["/", "/p/open"]),
    });
    out.push(Case {
        id: "equal-length-allow-wins-the-tie",
        rfc: "2.2.2",
        robots: text("User-agent: *\nDisallow: /tie\nAllow: /tie\n"),
        nodes: site(&["/tie/page"], vec![]),
        static_requests: set(["/robots.txt", "/", "/sitemap.xml", "/tie/page"]),
        never: set([]),
        browser_reaches: set(["/", "/tie/page"]),
    });
    out.push(Case {
        id: "dollar-anchors-the-end-of-the-path",
        rfc: "2.2.2",
        robots: text("User-agent: *\nDisallow: /*.dat$\n"),
        nodes: site(&["/x.dat", "/x.dat.html", "/d/y.dat"], vec![]),
        static_requests: set(["/robots.txt", "/", "/sitemap.xml", "/x.dat.html"]),
        never: set(["/x.dat", "/d/y.dat"]),
        browser_reaches: set(["/", "/x.dat.html"]),
    });
    out.push(Case {
        id: "star-matches-any-sequence",
        rfc: "2.2.2",
        robots: text("User-agent: *\nDisallow: /a*/secret\n"),
        nodes: site(&["/abc/secret", "/abc/public", "/zzz/secret"], vec![]),
        static_requests: set(["/robots.txt", "/", "/sitemap.xml", "/abc/public", "/zzz/secret"]),
        never: set(["/abc/secret"]),
        browser_reaches: set(["/", "/abc/public"]),
    });
    out.push(Case {
        id: "path-matching-is-case-sensitive",
        rfc: "2.2.2",
        robots: text("User-agent: *\nDisallow: /Private\n"),
        nodes: site(&["/Private/x", "/private/x"], vec![]),
        static_requests: set(["/robots.txt", "/", "/sitemap.xml", "/private/x"]),
        never: set(["/Private/x"]),
        browser_reaches: set(["/", "/private/x"]),
    });
    out.push(Case {
        id: "a-named-group-excludes-the-star-group",
        rfc: "2.2.1",
        robots: text("User-agent: *\nDisallow: /star-only\n\nUser-agent: crawlx\nDisallow: /own-only\n"),
        nodes: site(&["/star-only", "/own-only"], vec![]),
        static_requests: set(["/robots.txt", "/", "/sitemap.xml", "/star-only"]),
        never: set(["/own-only"]),
        browser_reaches: set(["/", "/star-only"]),
    });
    out.push(Case {
        id: "consecutive-agent-lines-share-one-group",
        rfc: "2.2.1",
        robots: text("User-agent: otherbot\nUser-agent: crawlx\nDisallow: /shared\n"),
        nodes: site(&["/shared", "/free"], vec![]),
        static_requests: set(["/robots.txt", "/", "/sitemap.xml", "/free"]),
        never: set(["/shared"]),
        browser_reaches: set(["/", "/free"]),
    });
    out.push(Case {
        id: "another-agents-group-does-not-apply",
        rfc: "2.2.1",
        robots: text("User-agent: otherbot\nDisallow: /\n"),
        nodes: site(&["/a"], vec![]),
        static_requests: set(["/robots.txt", "/", "/a", "/sitemap.xml"]),
        never: set([]),
        browser_reaches: set(["/", "/a"]),
    });

    // ---- sitemaps are documents of the origin like any other ----
    out.push(Case {
        id: "sitemap-entries-are-judged-one-by-one",
        rfc: "2.2.2",
        robots: text("User-agent: *\nDisallow: /private/\n"),
        nodes: site(
            &[],
            vec![(
                "/sitemap.xml",
                Node::Xml(
                    "<?xml version=\"1.0\"?><urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\"><url><loc>{base}/pub</loc></url><url><loc>{base}/private/x</loc></url></urlset>"
                        .to_owned(),
                ),
            ), ("/pub", page(&[])), ("/private/x", page(&[]))],
        ),
        static_requests: set(["/robots.txt", "/", "/sitemap.xml", "/pub"]),
        never: set(["/private/x"]),
        browser_reaches: set(["/"]),
    });

    // ---- a redirect hop is a request: it meets the same rules as the page ----
    out.push(Case {
        id: "an-allowed-redirect-is-followed",
        rfc: "2.2.2",
        robots: text("User-agent: *\nDisallow: /private/\n"),
        nodes: site(
            &["/moved"],
            vec![
                ("/moved", Node::Redirect(301, "/landing".to_owned())),
                ("/landing", page(&[])),
            ],
        ),
        static_requests: set(["/robots.txt", "/", "/sitemap.xml", "/moved", "/landing"]),
        never: set([]),
        browser_reaches: set(["/"]),
    });
    out
}

struct EdgeState {
    robots: Robots,
    nodes: BTreeMap<String, Node>,
    base: String,
    log: Mutex<Vec<String>>,
}

/// The loopback origin of one case, with the log of every request it received.
pub struct EdgeServer {
    /// `http://127.0.0.1:<port>`.
    pub base: String,
    state: Arc<EdgeState>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for EdgeServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl EdgeServer {
    /// Serve `case` on an ephemeral loopback port.
    ///
    /// # Errors
    /// [`BenchError::Bind`] when the listener cannot bind, [`BenchError::LocalAddr`] when its
    /// address cannot be read.
    pub async fn start(case: &Case) -> Result<Self, BenchError> {
        let addr: std::net::SocketAddr = std::net::SocketAddr::from(([127, 0, 0, 1], 0));
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|source| BenchError::Bind { addr, source })?;
        let base = format!("http://{}", listener.local_addr().map_err(BenchError::LocalAddr)?);
        let state = Arc::new(EdgeState {
            robots: case.robots.clone(),
            nodes: case.nodes.clone(),
            base: base.clone(),
            log: Mutex::new(Vec::new()),
        });
        let app = Router::new().fallback(serve).with_state(Arc::clone(&state));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self { base, state, task })
    }

    /// Paths of every request, in arrival order (the query is dropped).
    #[must_use]
    pub fn log(&self) -> Vec<String> {
        self.state.log.lock().clone()
    }

    /// The distinct paths requested.
    #[must_use]
    pub fn requested(&self) -> BTreeSet<String> {
        self.state.log.lock().iter().cloned().collect()
    }
}

fn html(body: String) -> Response {
    ([(header::CONTENT_TYPE, "text/html; charset=utf-8")], body).into_response()
}

async fn serve(State(state): State<Arc<EdgeState>>, uri: Uri) -> Response {
    let path = uri.path().to_owned();
    state.log.lock().push(path.clone());
    let robots_body = |body: &str| {
        (
            [(header::CONTENT_TYPE, "text/plain")],
            body.replace("{base}", &state.base),
        )
    };
    match path.as_str() {
        "/robots.txt" => match &state.robots {
            Robots::Status(status) => (
                StatusCode::from_u16(*status).unwrap_or(StatusCode::IM_A_TEAPOT),
                "",
            )
                .into_response(),
            Robots::Text(body) => robots_body(body).into_response(),
            Robots::MovedTo(_) => redirect(301, "/robots-moved.txt"),
        },
        "/robots-moved.txt" => match &state.robots {
            Robots::MovedTo(body) => robots_body(body).into_response(),
            _ => StatusCode::NOT_FOUND.into_response(),
        },
        other => match state.nodes.get(other) {
            Some(Node::Page(links)) => {
                let links: String = links
                    .iter()
                    .map(|l| format!("<a href=\"{l}\">{l}</a> "))
                    .collect();
                html(format!(
                    "<!doctype html><html><head><title>{other}</title></head><body><main><h1>{other}</h1><p>Fixture page {other}.</p>{links}</main></body></html>"
                ))
            }
            Some(Node::Redirect(status, to)) => redirect(*status, to),
            Some(Node::Xml(body)) => (
                [(header::CONTENT_TYPE, "application/xml")],
                body.replace("{base}", &state.base),
            )
                .into_response(),
            None => (StatusCode::NOT_FOUND, "not found").into_response(),
        },
    }
}

fn redirect(status: u16, to: &str) -> Response {
    let mut response = StatusCode::from_u16(status)
        .unwrap_or(StatusCode::FOUND)
        .into_response();
    if let Ok(value) = HeaderValue::from_str(to) {
        response.headers_mut().insert(header::LOCATION, value);
    }
    response
}
