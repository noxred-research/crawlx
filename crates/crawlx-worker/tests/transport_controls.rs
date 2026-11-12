//! Realm credentials and TLS client certificates through a real local run: references resolve
//! once for the run, the credential reaches only the origin and realm it names, and no secret
//! appears in the report, page metadata or events.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[path = "common/authorization.rs"]
mod authorization_fixture;

use axum::extract::{Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use crawlx_core::config::{CrawlMode, HostScope, SitemapMode};
use crawlx_core::error::CoreError;
use crawlx_core::secret::{CredentialRef, SecretOr, SecretResolver};
use crawlx_core::transport_policy::{ClientCertificate, RealmCredentialRef};
use crawlx_core::CreateCrawl;
use crawlx_fetch::StaticResolver;
use crawlx_storage::MemoryStore;
use crawlx_worker::secrets::{ChainResolver, FileSecretResolver};
use crawlx_worker::{run_local_with, EgressConfig, LocalRun, RunReport, Stores, WorkerConfig};
use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

const SECRET: &str = "alice:s3cr3t-pass";
/// `Basic base64(SECRET)`.
const BASIC: &str = "Basic YWxpY2U6czNjcjN0LXBhc3M=";

#[derive(Clone, Debug)]
struct Hit {
    host: String,
    path: String,
    authorization: Option<String>,
}

type Hits = Arc<Mutex<Vec<Hit>>>;

struct Site {
    port: u16,
    hits: Hits,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Site {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn hit_of(req: &Request) -> Hit {
    let header = |name: &str| {
        req.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned)
    };
    Hit {
        host: header("host")
            .unwrap_or_default()
            .split(':')
            .next()
            .unwrap_or_default()
            .to_owned(),
        path: req.uri().path().to_owned(),
        authorization: header("authorization"),
    }
}

async fn record(State(hits): State<Hits>, req: Request, next: Next) -> Response {
    let hit = hit_of(&req);
    hits.lock().unwrap().push(hit);
    next.run(req).await
}

fn html(title: &str, links: &str) -> Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!(
            "<html><head><title>{title}</title></head><body><main><h1>{title}</h1><p>{title} text.</p>{links}</main></body></html>"
        ),
    )
        .into_response()
}

/// `/members/*` answers `401` with a `members` challenge unless the right credential is sent.
async fn members(req: Request) -> Response {
    let authorized = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        == Some(BASIC);
    if authorized {
        html("Members", "")
    } else {
        (
            StatusCode::UNAUTHORIZED,
            [(header::WWW_AUTHENTICATE, "Basic realm=\"members\"")],
            "denied",
        )
            .into_response()
    }
}

async fn start() -> Site {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits: Hits = Arc::default();
    let app = Router::new()
        .route(
            "/",
            get(move || async move {
                html(
                    "Home",
                    &format!(
                        r#"<a href="/members/a">a</a> <a href="/members/b">b</a>
                        <a href="http://other.test:{port}/members/c">c</a>"#
                    ),
                )
            }),
        )
        .route("/members/a", get(members))
        .route("/members/b", get(members))
        .route(
            "/robots.txt",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/plain")],
                    "User-agent: *\nDisallow:\n",
                )
            }),
        )
        .fallback(get(members))
        .layer(axum::middleware::from_fn_with_state(Arc::clone(&hits), record));
    let task = tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Site { port, hits, task }
}

struct MapResolver {
    values: BTreeMap<String, String>,
    lookups: Mutex<Vec<String>>,
}

impl MapResolver {
    fn new(values: &[(&str, &str)]) -> Arc<Self> {
        Arc::new(Self {
            values: values
                .iter()
                .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
                .collect(),
            lookups: Mutex::new(Vec::new()),
        })
    }
}

#[async_trait::async_trait]
impl SecretResolver for MapResolver {
    async fn resolve(&self, reference: &CredentialRef) -> Result<SecretOr<String>, CoreError> {
        self.lookups.lock().unwrap().push(reference.0.clone());
        self.values
            .get(&reference.0)
            .map(|v| SecretOr::secret(v.clone()))
            .ok_or_else(|| CoreError::CredentialUnavailable(reference.0.clone()))
    }
}

fn config(dir: &std::path::Path) -> WorkerConfig {
    let resolver = StaticResolver::new();
    for host in ["a.test", "other.test"] {
        resolver.set(host, [IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(resolver)),
            ..EgressConfig::default()
        },
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        ..WorkerConfig::default()
    }
}

fn crawl(site: &Site, edit: impl FnOnce(&mut CreateCrawl)) -> CreateCrawl {
    let mut c = CreateCrawl::new(url::Url::parse(&format!("http://a.test:{}/", site.port)).unwrap());
    c.mode = CrawlMode::Static;
    c.seed = Some(20_261_027);
    c.safety.allow_private_networks = true;
    c.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    c.politeness.delay_ms = 0;
    c.scope.sitemap = SitemapMode::Skip;
    c.scope.host_scope = HostScope::None;
    edit(&mut c);
    c
}

struct Crawled {
    report: RunReport,
    stores: Stores,
    resolver: Arc<MapResolver>,
}

async fn run(c: CreateCrawl) -> Crawled {
    let dir = tempfile::tempdir().unwrap();
    let stores = Stores::over_memory(Arc::new(MemoryStore::new()), dir.path())
        .await
        .unwrap();
    let resolver = MapResolver::new(&[("env://E2E_REALM", SECRET)]);
    let mut record = authorization_fixture::verified_record(&c, stores.tenant);
    let mut other = c.seed_url.clone();
    other.set_host(Some("other.test")).unwrap();
    record.origins.push(other.origin().ascii_serialization());
    let report = run_local_with(
        LocalRun::new(c, config(dir.path()))
            .with_stores(stores.clone())
            .with_secrets(Arc::clone(&resolver) as Arc<dyn SecretResolver>)
            .with_authorization(record),
    )
    .await
    .unwrap();
    Crawled {
        report,
        stores,
        resolver,
    }
}

#[tokio::test]
async fn a_realm_credential_reaches_only_its_origin_and_never_leaks_into_outputs() {
    let site = start().await;
    let origin = url::Url::parse(&format!("http://a.test:{}", site.port)).unwrap();
    let crawled = run(crawl(&site, |c| {
        c.fetch
            .realm_credentials
            .push(RealmCredentialRef::basic(origin, "members", "env://E2E_REALM"));
    }))
    .await;

    let hits = site.hits.lock().unwrap().clone();
    // On the credential's origin each protected page is answered once and then served.
    for path in ["/members/a", "/members/b"] {
        let served = hits
            .iter()
            .any(|h| h.host == "a.test" && h.path == path && h.authorization.as_deref() == Some(BASIC));
        assert!(served, "{path} never carried the credential: {hits:?}");
    }
    assert!(
        crawled
            .report
            .pages
            .iter()
            .any(|p| p.url.url.path() == "/members/a" && p.url.url.host_str() == Some("a.test")),
        "the protected page was crawled"
    );
    // Another host name is another origin: it is challenged but never offered the credential.
    let other: Vec<_> = hits.iter().filter(|h| h.host == "other.test").collect();
    assert!(!other.is_empty(), "the other origin was requested: {hits:?}");
    assert!(
        other.iter().all(|h| h.authorization.is_none()),
        "other origin saw a credential: {other:?}"
    );
    // robots.txt and the seed are not in a protection space.
    assert!(hits
        .iter()
        .filter(|h| h.path == "/" || h.path == "/robots.txt")
        .all(|h| h.authorization.is_none()));

    // The reference was resolved exactly once for the run.
    assert_eq!(*crawled.resolver.lookups.lock().unwrap(), ["env://E2E_REALM"]);
    // Neither the credential nor its wire encoding appears in anything the run reports.
    let events = crawled
        .stores
        .events
        .list_after(crawled.report.run_id, 0, 10_000)
        .await
        .unwrap();
    let events_json =
        serde_json::to_string(&events.iter().map(|e| (&e.kind, &e.payload)).collect::<Vec<_>>()).unwrap();
    let metadata = serde_json::to_string(
        &crawled
            .report
            .pages
            .iter()
            .map(|p| &p.metadata)
            .collect::<Vec<_>>(),
    )
    .unwrap();
    let report = format!("{:?}", crawled.report);
    let stored_run = crawled.stores.runs.get(crawled.report.run_id).await.unwrap();
    let stored = format!(
        "{:?} {}",
        stored_run.config,
        serde_json::to_string(&stored_run.config.redacted()).unwrap()
    );
    for (what, text) in [
        ("events", &events_json),
        ("metadata", &metadata),
        ("report", &report),
        ("stored config", &stored),
    ] {
        for secret in ["s3cr3t-pass", "YWxpY2U6", SECRET] {
            assert!(!text.contains(secret), "{what} leaks {secret}");
        }
    }
    // The stored run keeps the reference; every outward view of it masks it.
    assert_eq!(
        stored_run.config.fetch.realm_credentials[0].credential,
        "env://E2E_REALM"
    );
    assert!(!serde_json::to_string(&stored_run.config.redacted())
        .unwrap()
        .contains("E2E_REALM"));
}

#[tokio::test]
async fn client_certificate_references_resolve_through_the_secret_chain_without_echoing_values() {
    // A key file that anyone can read is refused, and the error names the file, not its content.
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("client.crt");
    let key = dir.path().join("client.key");
    let key_text = "-----BEGIN PRIVATE KEY-----\nWORKERKEYBODYWORKERKEYBODY\n-----END PRIVATE KEY-----\n";
    std::fs::write(
        &cert,
        "-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n",
    )
    .unwrap();
    std::fs::write(&key, key_text).unwrap();
    let chain = ChainResolver::new().with("file", Arc::new(FileSecretResolver));
    let fetch = crawlx_core::config::Fetch {
        client_certificate: Some(ClientCertificate::new(
            format!("file://{}", cert.display()),
            format!("file://{}", key.display()),
        )),
        ..crawlx_core::config::Fetch::default()
    };
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&cert, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
    let Err(error) =
        crawlx_core::request_controls::RequestControls::resolve(&fetch, "a.test", Some(&chain)).await
    else {
        panic!("a world-readable key file must be refused");
    };
    let text = error.to_string();
    assert!(text.contains("world-readable"), "{text}");
    assert!(!text.contains("WORKERKEYBODY"), "{text}");

    std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
    let controls = crawlx_core::request_controls::RequestControls::resolve(&fetch, "a.test", Some(&chain))
        .await
        .unwrap();
    let identity = controls.client_identity().unwrap();
    assert_eq!(identity.private_key_pem(), key_text.trim_end_matches('\n'));
    assert!(!format!("{controls:?}").contains("WORKERKEYBODY"));
    assert!(controls
        .secret_values()
        .any(|value| value.contains("WORKERKEYBODY")));
}
