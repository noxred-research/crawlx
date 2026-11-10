//! Configurable in-process sites for the compatibility flag tests: every request is recorded, pages can
//! be slow, and several sites can share one in-flight gauge.

use axum::body::Body;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderName, HeaderValue, Request, StatusCode};
use axum::response::Response;
use axum::Router;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// One page of a site.
#[derive(Clone)]
pub struct Page {
    pub status: u16,
    pub content_type: &'static str,
    pub body: String,
    pub delay: Duration,
    pub headers: Vec<(&'static str, &'static str)>,
}

impl Page {
    /// An HTML page with status 200.
    pub fn html(body: impl Into<String>) -> Self {
        Self {
            status: 200,
            content_type: "text/html; charset=utf-8",
            body: body.into(),
            delay: Duration::ZERO,
            headers: Vec::new(),
        }
    }

    /// A page wrapped in the usual boilerplate.
    pub fn doc(title: &str, inner: &str) -> Self {
        Self::html(format!(
            "<html><head><title>{title}</title></head><body><main><h1>{title}</h1>{inner}</main></body></html>"
        ))
    }

    /// The same page, answered after `delay`.
    pub fn slow(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// The same page with an extra response header.
    pub fn header(mut self, name: &'static str, value: &'static str) -> Self {
        self.headers.push((name, value));
        self
    }

    /// A plain 404.
    pub fn not_found() -> Self {
        Self {
            status: 404,
            ..Self::html("not found")
        }
    }
}

/// What a site saw: path with query, and the request headers (lower-case names).
#[derive(Clone, Debug)]
pub struct Hit {
    pub target: String,
    pub headers: BTreeMap<String, String>,
}

/// Requests in flight across every site sharing the gauge, and the most there ever were.
#[derive(Default)]
pub struct Gauge {
    now: AtomicUsize,
    max: AtomicUsize,
}

impl Gauge {
    pub fn max(&self) -> usize {
        self.max.load(Ordering::SeqCst)
    }
}

struct Shared {
    pages: BTreeMap<String, Page>,
    hits: Mutex<Vec<Hit>>,
    gauge: Arc<Gauge>,
}

/// A running site.
pub struct Site {
    pub base: String,
    shared: Arc<Shared>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(State(shared): State<Arc<Shared>>, request: Request<Body>) -> Response {
    let target = request
        .uri()
        .path_and_query()
        .map_or_else(|| request.uri().path().to_owned(), |pq| pq.as_str().to_owned());
    let headers: BTreeMap<String, String> = request
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_owned(),
                String::from_utf8_lossy(v.as_bytes()).into_owned(),
            )
        })
        .collect();
    shared.hits.lock().unwrap().push(Hit {
        target: target.clone(),
        headers,
    });
    let path = request.uri().path();
    let page = shared.pages.get(path).cloned().unwrap_or_else(Page::not_found);
    let now = shared.gauge.now.fetch_add(1, Ordering::SeqCst) + 1;
    shared.gauge.max.fetch_max(now, Ordering::SeqCst);
    if !page.delay.is_zero() {
        tokio::time::sleep(page.delay).await;
    }
    shared.gauge.now.fetch_sub(1, Ordering::SeqCst);
    let mut response = Response::new(Body::from(page.body));
    *response.status_mut() = StatusCode::from_u16(page.status).unwrap();
    let h: &mut HeaderMap = response.headers_mut();
    h.insert("content-type", HeaderValue::from_static(page.content_type));
    for (name, value) in page.headers {
        h.insert(HeaderName::from_static(name), HeaderValue::from_static(value));
    }
    response
}

impl Site {
    /// Start a site whose pages are built from its own base URL (`http://127.0.0.1:port`).
    pub async fn start(pages: impl FnOnce(&str) -> Vec<(&'static str, Page)>) -> Self {
        Self::start_with_gauge(pages, Arc::new(Gauge::default())).await
    }

    /// [`Site::start`] counting in-flight requests on `gauge`.
    pub async fn start_with_gauge(
        pages: impl FnOnce(&str) -> Vec<(&'static str, Page)>,
        gauge: Arc<Gauge>,
    ) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let base = format!("http://{addr}");
        let shared = Arc::new(Shared {
            pages: pages(&base)
                .into_iter()
                .map(|(p, page)| (p.to_owned(), page))
                .collect(),
            hits: Mutex::new(Vec::new()),
            gauge,
        });
        let app = Router::new().fallback(serve).with_state(Arc::clone(&shared));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { base, shared, task }
    }

    /// The `host:port` of the site.
    pub fn authority(&self) -> String {
        self.base.trim_start_matches("http://").to_owned()
    }

    /// Everything the site was asked for, in order.
    pub fn hits(&self) -> Vec<Hit> {
        self.shared.hits.lock().unwrap().clone()
    }

    /// The paths (with query) of the page requests: `robots.txt` and `sitemap.xml` left out.
    pub fn pages_hit(&self) -> Vec<String> {
        self.hits()
            .into_iter()
            .map(|h| h.target)
            .filter(|t| t != "/robots.txt" && t != "/sitemap.xml")
            .collect()
    }

    /// How many times `target` (path with query) was requested.
    pub fn count(&self, target: &str) -> usize {
        self.hits().iter().filter(|h| h.target == target).count()
    }
}
