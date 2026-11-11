//! Body-bearing requests on the URL plane: typed, authorized intent through the safety verdict and
//! the write journal, sent at most once.
//!
//! Every scenario runs a static crawl over the in-memory store against a loopback site that
//! records what it received, with write rows appended the way the API appends them.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use crawlx_core::config::{CrawlMode, DestructiveActions, SafetyProfile, SitemapMode};
use crawlx_core::counters::{PlaneCounters, RunStatus};
use crawlx_core::hash::Digest;
use crawlx_core::orchestration::{OrchestrationConfigV1, RequestBatchV1};
use crawlx_core::repo::{CrawlRun, EventRepo, FrontierStatus, RunEvent, Sensitivity};
use crawlx_core::request::{keyed_body_digest, RequestBodyV1, RequestEnvelopeV1, WriteApprovalV1};
use crawlx_core::safety::RiskClass;
use crawlx_core::secret::SecretOr;
use crawlx_core::{Clock, CrawlRunId, CreateCrawl, SystemClock};
use crawlx_fetch::StaticResolver;
use crawlx_policy::AuthorizationRecord;
use crawlx_scheduler::RunPlanner;
use crawlx_storage::MemoryStore;
use crawlx_worker::lease_loop::run_with;
use crawlx_worker::{EgressConfig, StaticAuthorizationSource, Stores, WorkerConfig};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio_util::sync::CancellationToken;

const KEY: [u8; 32] = [71; 32];
const CANARY: &str = "canary-secret-body-7f3a";
const WRITER: &str = "anonymous";

/// What the site received for one write.
#[derive(Clone, Debug)]
struct Seen {
    method: String,
    path: String,
    content_type: Option<String>,
    body: Vec<u8>,
    /// Whether the journal already held this write's intent when it arrived.
    journaled: bool,
}

#[derive(Default)]
struct Shared {
    seen: Mutex<Vec<Seen>>,
    events: Mutex<Option<(Arc<dyn EventRepo>, CrawlRunId)>>,
}

impl Shared {
    async fn journaled(&self, method: &str, body_bytes: usize) -> bool {
        let Some((events, run)) = self.events.lock().unwrap().clone() else {
            return false;
        };
        events
            .list_after(run, 0, 4096)
            .await
            .unwrap()
            .iter()
            .any(|event| {
                event.kind == "request.write_intent"
                    && event.payload["method"] == method
                    && event.payload["bodyBytes"] == body_bytes
            })
    }
}

async fn site(shared: Arc<Shared>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let path = parts.uri.path().to_owned();
    if parts.method == "GET" {
        return match path.as_str() {
            "/" => (
                [(header::CONTENT_TYPE, "text/html")],
                "<html><title>Home</title><p>The only page of the site.</p></html>",
            )
                .into_response(),
            _ => StatusCode::NOT_FOUND.into_response(),
        };
    }
    let body = axum::body::to_bytes(Body::new(body), 1 << 20)
        .await
        .unwrap()
        .to_vec();
    let journaled = shared.journaled(parts.method.as_str(), body.len()).await;
    shared.seen.lock().unwrap().push(Seen {
        method: parts.method.to_string(),
        path: path.clone(),
        content_type: parts
            .headers
            .get(header::CONTENT_TYPE)
            .map(|value| value.to_str().unwrap().to_owned()),
        body,
        journaled,
    });
    match path.as_str() {
        "/stall" => {
            std::future::pending::<()>().await;
            unreachable!()
        }
        "/unavailable" => (
            StatusCode::SERVICE_UNAVAILABLE,
            [(header::RETRY_AFTER, "0")],
            "later",
        )
            .into_response(),
        "/redirect" => {
            let mut response = StatusCode::TEMPORARY_REDIRECT.into_response();
            response
                .headers_mut()
                .insert(header::LOCATION, HeaderValue::from_static("/elsewhere"));
            response
        }
        _ => (StatusCode::CREATED, "created").into_response(),
    }
}

struct Rig {
    base: String,
    shared: Arc<Shared>,
    server: tokio::task::JoinHandle<()>,
    dir: tempfile::TempDir,
    stores: Stores,
    run: CrawlRunId,
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.server.abort();
    }
}

struct Setup {
    profile: SafetyProfile,
    destructive: DestructiveActions,
    record: fn(&mut AuthorizationRecord),
    orchestration: fn(&mut OrchestrationConfigV1),
    store: Option<Arc<MemoryStore>>,
}

impl Default for Setup {
    fn default() -> Self {
        Self {
            profile: SafetyProfile::TestEnvironment,
            destructive: DestructiveActions::Approval,
            record: |_| {},
            orchestration: |_| {},
            store: None,
        }
    }
}

async fn rig(setup: Setup) -> Rig {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let dir = tempfile::tempdir().unwrap();
    let store = setup.store.unwrap_or_else(|| Arc::new(MemoryStore::new()));
    let stores = Stores::over_memory(store, dir.path()).await.unwrap();
    let mut crawl = CreateCrawl::new(url::Url::parse(&format!("{base}/")).unwrap());
    crawl.mode = CrawlMode::Static;
    crawl.seed = Some(20_261_111);
    crawl.safety.allow_private_networks = true;
    crawl.safety.profile = setup.profile;
    crawl.safety.destructive_actions = setup.destructive;
    crawl.safety.authorization_record_ref = Some(crawlx_core::AuthorizationRecordId::new());
    crawl.politeness.delay_ms = 0;
    crawl.politeness.max_concurrency = 1;
    crawl.scope.crawl_entire_domain = true;
    crawl.scope.sitemap = SitemapMode::Skip;
    crawl.scope.known_files.clear();
    let mut orchestration = OrchestrationConfigV1::default();
    (setup.orchestration)(&mut orchestration);
    crawl.orchestration = Some(orchestration);
    let mut record = common::authorization::verified_record(&crawl, stores.tenant);
    (setup.record)(&mut record);
    let stores = stores.with_authorization_source(Arc::new(StaticAuthorizationSource::new(record)));
    crawl.normalize().unwrap();
    let run = CrawlRun {
        id: CrawlRunId::new(),
        tenant: stores.tenant,
        status: RunStatus::Queued,
        terminal_reason: None,
        seed: crawl.effective_seed(),
        config_digest: crawl.digest().unwrap(),
        config: crawl.clone(),
        policy_version: 1,
        counters: PlaneCounters::default(),
        created_at: SystemClock.now(),
        started_at: None,
        finished_at: None,
        trace_id: None,
    };
    stores.runs.create(&run, None).await.unwrap();
    stores
        .runs
        .create_sessions(&RunPlanner::sessions(run.id, &crawl))
        .await
        .unwrap();
    let shared = Arc::new(Shared::default());
    *shared.events.lock().unwrap() = Some((Arc::clone(&stores.events), run.id));
    let app = Router::new().fallback({
        let shared = Arc::clone(&shared);
        move |request: Request| {
            let shared = Arc::clone(&shared);
            async move { site(shared, request).await }
        }
    });
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    Rig {
        base,
        shared,
        server,
        dir,
        stores,
        run: run.id,
    }
}

fn worker(dir: &std::path::Path, idle: Duration) -> WorkerConfig {
    WorkerConfig {
        artifacts_dir: dir.to_path_buf(),
        egress: EgressConfig {
            resolver: Some(Arc::new(StaticResolver::new())),
            ..EgressConfig::default()
        },
        idle_exit_after: Some(idle),
        gates: crawlx_worker::Gates::from_status(crawlx_core::gates::GateStatus::ALL),
        request_identity_key: Some(SecretOr::secret(KEY)),
        ..WorkerConfig::default()
    }
}

impl Rig {
    fn canonical(&self, path: &str) -> crawlx_core::url::CanonicalUrl {
        common::canonical(&format!("{}{path}", self.base))
    }

    /// A write row as the API builds it: the body retained as a credential-bearing artifact and
    /// referenced by its tenant-keyed digest.
    async fn write(
        &self,
        method: &str,
        path: &str,
        body: Option<(&[u8], &str)>,
        approval: Option<RiskClass>,
    ) -> RequestEnvelopeV1 {
        let mut envelope = RequestEnvelopeV1::new(self.canonical(path), method.into(), 1, None);
        if let Some((bytes, media_type)) = body {
            let artifact = self
                .stores
                .artifacts
                .put(self.run, Sensitivity::CredentialBearing, media_type, bytes)
                .await
                .unwrap();
            envelope.body = Some(RequestBodyV1::for_artifact(
                &artifact,
                keyed_body_digest(&KEY, self.stores.tenant, bytes),
                1,
                u64::try_from(bytes.len()).unwrap(),
                media_type.into(),
            ));
        }
        envelope.approval =
            approval.map(|risk| WriteApprovalV1::new(risk, "api_key:reviewer".into(), SystemClock.now()));
        envelope
    }

    async fn append(&self, principal: &str, label: &str, rows: Vec<RequestEnvelopeV1>) -> Vec<i64> {
        self.stores
            .frontier
            .append_batch(RequestBatchV1::new(
                self.stores.tenant,
                self.run,
                principal.into(),
                Digest::of("write-fixture", label.as_bytes()),
                rows,
            ))
            .await
            .unwrap()
            .inserted
    }

    async fn serve(&self) {
        tokio::time::timeout(
            Duration::from_secs(60),
            run_with(
                worker(self.dir.path(), Duration::from_millis(800)),
                self.stores.clone(),
                None,
                CancellationToken::new(),
            ),
        )
        .await
        .unwrap()
        .unwrap();
    }

    async fn row(&self, id: i64) -> (FrontierStatus, Option<String>) {
        let entry = self
            .stores
            .frontier
            .get_request(self.run, id)
            .await
            .unwrap()
            .entry;
        (entry.status, entry.denial_reason)
    }

    async fn events(&self, kind: &str) -> Vec<RunEvent> {
        self.stores
            .events
            .list_after(self.run, 0, 4096)
            .await
            .unwrap()
            .into_iter()
            .filter(|event| event.kind == kind)
            .collect()
    }

    fn writes(&self) -> Vec<Seen> {
        self.shared.seen.lock().unwrap().clone()
    }
}

#[tokio::test]
async fn form_post_json_put_and_approved_delete_arrive_exactly_after_their_intent_is_journaled() {
    let rig = rig(Setup::default()).await;
    let form = format!("name=Ada+Lovelace&note={CANARY}&tick=%E2%9C%93");
    let json = format!(r#"{{"id":7,"secret":"{CANARY}","tags":["a","b"]}}"#);
    let delete = br#"{"reason":"cleanup"}"#;
    let rows = vec![
        rig.write(
            "POST",
            "/api/form",
            Some((form.as_bytes(), "application/x-www-form-urlencoded")),
            None,
        )
        .await,
        rig.write(
            "PUT",
            "/api/item/7",
            Some((json.as_bytes(), "application/json")),
            None,
        )
        .await,
        rig.write(
            "DELETE",
            "/api/item/7",
            Some((delete, "application/json")),
            Some(RiskClass::Destructive),
        )
        .await,
        // bodyless: still a write
        rig.write("DELETE", "/api/item/8", None, Some(RiskClass::Destructive))
            .await,
    ];
    let ids = rig.append(WRITER, "exact", rows).await;
    assert_eq!(ids.len(), 4);
    rig.serve().await;

    let mut seen = rig.writes();
    seen.sort_by(|a, b| (a.method.as_str(), a.path.as_str()).cmp(&(b.method.as_str(), b.path.as_str())));
    let expected: Vec<(&str, &str, Option<&str>, Vec<u8>)> = vec![
        ("DELETE", "/api/item/7", Some("application/json"), delete.to_vec()),
        ("DELETE", "/api/item/8", None, Vec::new()),
        (
            "POST",
            "/api/form",
            Some("application/x-www-form-urlencoded"),
            form.clone().into_bytes(),
        ),
        (
            "PUT",
            "/api/item/7",
            Some("application/json"),
            json.clone().into_bytes(),
        ),
    ];
    assert_eq!(seen.len(), expected.len(), "{seen:?}");
    for (got, (method, path, content_type, body)) in seen.iter().zip(&expected) {
        assert_eq!((got.method.as_str(), got.path.as_str()), (*method, *path));
        assert_eq!(got.content_type.as_deref(), *content_type, "{method} {path}");
        assert_eq!(&got.body, body, "{method} {path}: bytes must arrive exactly");
        assert!(
            got.journaled,
            "{method} {path}: intent must be durable before the send"
        );
    }
    for id in &ids {
        assert_eq!(
            rig.row(*id).await,
            (FrontierStatus::Succeeded, Some("http_201".to_owned()))
        );
    }

    let intents = rig.events("request.write_intent").await;
    let outcomes = rig.events("request.write_outcome").await;
    assert_eq!(intents.len(), 4);
    assert_eq!(outcomes.len(), 4);
    for intent in &intents {
        let id = intent.payload["requestId"].as_i64().unwrap();
        let outcome = outcomes.iter().find(|o| o.payload["requestId"] == id).unwrap();
        assert!(
            intent.seq < outcome.seq,
            "the journal records intent before outcome"
        );
        assert_eq!(outcome.payload["outcome"], "answered");
        assert_eq!(outcome.payload["status"], 201);
        assert_eq!(outcome.payload["attempts"], 1);
        assert_eq!(intent.payload["decision"], "allow");
        assert_eq!(intent.payload["principal"], WRITER);
        assert_eq!(intent.payload["effects"], 1);
    }
    let delete_intent = intents.iter().find(|e| e.payload["requestId"] == ids[2]).unwrap();
    assert_eq!(delete_intent.payload["riskClass"], "destructive");
    assert_eq!(delete_intent.payload["approvedBy"], "api_key:reviewer");
    assert!(delete_intent.payload["rules"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("approval.envelope")));
    let post_intent = intents.iter().find(|e| e.payload["requestId"] == ids[0]).unwrap();
    assert_eq!(post_intent.payload["riskClass"], "persistent_write_own");
    assert_eq!(
        post_intent.payload["bodyDigest"],
        keyed_body_digest(&KEY, rig.stores.tenant, form.as_bytes()).to_hex()
    );
    // The journal never carries request content or the target URL.
    let journal = serde_json::to_string(&[&intents, &outcomes]).unwrap();
    assert!(!journal.contains(CANARY), "{journal}");
    assert!(!journal.contains("/api/"), "{journal}");
}

#[tokio::test]
async fn different_bodies_methods_and_principals_do_not_dedupe_but_an_identical_write_does() {
    let rig = rig(Setup::default()).await;
    let a: &[u8] = b"a=1";
    let first = rig
        .append(
            WRITER,
            "one",
            vec![rig.write("POST", "/api/x", Some((a, "text/plain")), None).await],
        )
        .await;
    assert_eq!(first.len(), 1);
    // The same body, method, target and principal in another batch is the same request.
    let repeat = RequestBatchV1::new(
        rig.stores.tenant,
        rig.run,
        WRITER.into(),
        Digest::of("write-fixture", b"two"),
        vec![rig.write("POST", "/api/x", Some((a, "text/plain")), None).await],
    );
    let receipt = rig.stores.frontier.append_batch(repeat).await.unwrap();
    assert_eq!((receipt.inserted.len(), receipt.duplicates), (0, 1));
    let distinct = [
        (
            "body",
            WRITER,
            rig.write("POST", "/api/x", Some((b"a=2", "text/plain")), None)
                .await,
        ),
        (
            "method",
            WRITER,
            rig.write("PUT", "/api/x", Some((a, "text/plain")), None).await,
        ),
        (
            "media type",
            WRITER,
            rig.write("POST", "/api/x", Some((a, "application/json")), None)
                .await,
        ),
    ];
    for (label, principal, row) in distinct {
        let inserted = rig.append(principal, label, vec![row]).await;
        assert_eq!(inserted.len(), 1, "{label} must make a distinct request");
    }
    rig.serve().await;
    assert_eq!(
        rig.writes().len(),
        4,
        "each distinct write is sent once, the repeat never"
    );
}

#[tokio::test]
async fn read_only_profile_refuses_with_a_typed_reason_and_sends_nothing() {
    let rig = rig(Setup {
        profile: SafetyProfile::ReadOnly,
        destructive: DestructiveActions::Deny,
        ..Setup::default()
    })
    .await;
    let rows = vec![
        rig.write("POST", "/api/x", Some((b"a=1", "text/plain")), None)
            .await,
        rig.write("DELETE", "/api/x", None, Some(RiskClass::Destructive))
            .await,
    ];
    let ids = rig.append(WRITER, "ro", rows).await;
    rig.serve().await;
    assert!(rig.writes().is_empty(), "{:?}", rig.writes());
    for id in ids {
        assert_eq!(
            rig.row(id).await,
            (FrontierStatus::PolicyBlocked, Some("write_read_only".to_owned()))
        );
    }
    let refused = rig.events("request.write_refused").await;
    assert_eq!(refused.len(), 2);
    assert!(refused
        .iter()
        .all(|event| event.payload["reason"] == "write_read_only"));
    assert!(rig.events("request.write_intent").await.is_empty());
}

#[tokio::test]
async fn approval_never_lifts_a_denial_and_gated_classes_need_one() {
    // The record permits nothing: denied whatever the envelope says.
    let denied = rig(Setup {
        record: |record| record.permitted_risk_classes.clear(),
        ..Setup::default()
    })
    .await;
    let ids = denied
        .append(
            WRITER,
            "record",
            vec![
                denied
                    .write(
                        "POST",
                        "/api/x",
                        Some((b"a=1", "text/plain")),
                        Some(RiskClass::PersistentWriteOwn),
                    )
                    .await,
            ],
        )
        .await;
    denied.serve().await;
    assert_eq!(
        denied.row(ids[0]).await,
        (FrontierStatus::PolicyBlocked, Some("write_denied".to_owned()))
    );
    let refusal = &denied.events("request.write_refused").await[0];
    assert!(refusal.payload["rules"]
        .as_array()
        .unwrap()
        .contains(&serde_json::json!("record.class_not_permitted")));
    assert!(denied.writes().is_empty());

    // Destructive actions are denied by option: an approval does not change that.
    let option = rig(Setup {
        destructive: DestructiveActions::Deny,
        ..Setup::default()
    })
    .await;
    let ids = option
        .append(
            WRITER,
            "option",
            vec![
                option
                    .write("DELETE", "/api/x", None, Some(RiskClass::Destructive))
                    .await,
            ],
        )
        .await;
    option.serve().await;
    assert_eq!(
        option.row(ids[0]).await,
        (FrontierStatus::PolicyBlocked, Some("write_denied".to_owned()))
    );
    assert!(option.writes().is_empty());

    // Approval-gated and unapproved: refused with its own reason.
    let gated = rig(Setup::default()).await;
    let ids = gated
        .append(
            WRITER,
            "gated",
            vec![gated.write("DELETE", "/api/x", None, None).await],
        )
        .await;
    gated.serve().await;
    assert_eq!(
        gated.row(ids[0]).await,
        (
            FrontierStatus::PolicyBlocked,
            Some("write_approval_required".to_owned())
        )
    );
    assert!(gated.writes().is_empty());

    // The record can ask for approval of a class the profile allows.
    let record_gated = rig(Setup {
        record: |record| {
            record.approval_required.insert(RiskClass::PersistentWriteOwn);
        },
        ..Setup::default()
    })
    .await;
    let ids = record_gated
        .append(
            WRITER,
            "record-gated",
            vec![
                record_gated
                    .write("POST", "/api/a", Some((b"x=1", "text/plain")), None)
                    .await,
                record_gated
                    .write(
                        "POST",
                        "/api/b",
                        Some((b"x=2", "text/plain")),
                        Some(RiskClass::PersistentWriteOwn),
                    )
                    .await,
            ],
        )
        .await;
    record_gated.serve().await;
    assert_eq!(
        record_gated.row(ids[0]).await,
        (
            FrontierStatus::PolicyBlocked,
            Some("write_approval_required".to_owned())
        )
    );
    assert_eq!(record_gated.row(ids[1]).await.0, FrontierStatus::Succeeded);
    assert_eq!(record_gated.writes().len(), 1);
    assert_eq!(record_gated.writes()[0].path, "/api/b");
}

#[tokio::test]
async fn a_write_with_a_missing_or_altered_body_is_never_sent() {
    let rig = rig(Setup::default()).await;
    // A body whose retained bytes are not the bytes the digest was taken over.
    let mut altered = rig
        .write("POST", "/api/altered", Some((b"a=1", "text/plain")), None)
        .await;
    altered.body.as_mut().unwrap().digest = keyed_body_digest(&KEY, rig.stores.tenant, b"a=2");
    let mut short = rig
        .write("POST", "/api/short", Some((b"a=1", "text/plain")), None)
        .await;
    short.body.as_mut().unwrap().length = 2;
    // A body that was never retained.
    let mut gone = rig
        .write("POST", "/api/gone", Some((b"a=1", "text/plain")), None)
        .await;
    gone.body.as_mut().unwrap().handle = format!(
        "artifact:{}:{}",
        crawlx_core::ArtifactId::new(),
        Digest::of("x", b"y").to_hex()
    );
    let mut foreign = rig
        .write("POST", "/api/foreign", Some((b"a=1", "text/plain")), None)
        .await;
    foreign.body.as_mut().unwrap().handle = "volatile:body".into();
    let ids = rig
        .append(WRITER, "bodies", vec![altered, short, gone, foreign])
        .await;
    rig.serve().await;
    assert!(rig.writes().is_empty(), "{:?}", rig.writes());
    for (id, reason) in ids.iter().zip([
        "write_body_mismatch",
        "write_body_mismatch",
        "write_body_unavailable",
        "write_body_unavailable",
    ]) {
        assert_eq!(
            rig.row(*id).await,
            (FrontierStatus::Failed, Some(reason.to_owned()))
        );
    }
    assert!(rig.events("request.write_intent").await.is_empty());
}

#[tokio::test]
async fn a_mutating_request_is_never_retried_or_redirected_whatever_the_target_answers() {
    let rig = rig(Setup::default()).await;
    let ids = rig
        .append(
            WRITER,
            "answers",
            vec![
                rig.write("POST", "/unavailable", Some((b"pay=1", "text/plain")), None)
                    .await,
                rig.write("PUT", "/redirect", Some((b"v=1", "text/plain")), None)
                    .await,
            ],
        )
        .await;
    rig.serve().await;
    let seen = rig.writes();
    assert_eq!(
        seen.len(),
        2,
        "one dispatch per write and none for its retry or redirect: {seen:?}"
    );
    assert_eq!(
        rig.row(ids[0]).await,
        (FrontierStatus::Failed, Some("http_503".to_owned()))
    );
    assert_eq!(
        rig.row(ids[1]).await,
        (FrontierStatus::Failed, Some("http_307".to_owned()))
    );
    let outcomes = rig.events("request.write_outcome").await;
    assert!(outcomes.iter().all(|event| event.payload["attempts"] == 1));
}

#[tokio::test]
async fn an_effect_already_charged_to_the_row_counts_against_the_total_cap_before_any_send() {
    use crawlx_core::WorkerId;
    let rig = rig(Setup {
        orchestration: |config| config.attempts.max_total_effects = 1,
        ..Setup::default()
    })
    .await;
    let ids = rig
        .append(
            WRITER,
            "cap",
            vec![
                rig.write("POST", "/api/x", Some((b"a=1", "text/plain")), None)
                    .await,
            ],
        )
        .await;
    // An earlier holder charged the row's only effect and handed it back unsent.
    let earlier = WorkerId::new();
    let leased = rig
        .stores
        .frontier
        .lease_batch_fenced(rig.run, earlier, 8)
        .await
        .unwrap();
    let (entry, fence) = leased.iter().find(|(entry, _)| entry.id == ids[0]).unwrap();
    rig.stores
        .frontier
        .reserve_effects_fenced(rig.run, entry.id, *fence, 1)
        .await
        .unwrap();
    for (entry, fence) in &leased {
        rig.stores.frontier.give_back(entry.id, *fence).await.unwrap();
    }
    rig.serve().await;
    assert!(rig.writes().is_empty(), "{:?}", rig.writes());
    assert_eq!(
        rig.row(ids[0]).await,
        (FrontierStatus::Failed, Some("request_effect_budget".to_owned()))
    );
    assert!(rig.events("request.write_intent").await.is_empty());
}

/// A worker on a runtime of its own: dropping the runtime kills it without any cleanup.
struct Doomed(Option<tokio::runtime::Runtime>);

impl Doomed {
    fn start(rig: &Rig) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let stores = rig.stores.clone();
        let cfg = worker(rig.dir.path(), Duration::from_secs(600));
        runtime.spawn(async move {
            let _ = run_with(cfg, stores, None, CancellationToken::new()).await;
        });
        Self(Some(runtime))
    }

    fn kill(mut self) {
        if let Some(runtime) = self.0.take() {
            runtime.shutdown_background();
        }
    }
}

#[tokio::test]
async fn a_crawl_killed_mid_send_never_replays_the_write() {
    // Short URL leases so the dead holder's lease expires within the test.
    let store = Arc::new(MemoryStore::new().with_ttls(Duration::from_secs(30), Duration::from_secs(2)));
    let rig = rig(Setup {
        store: Some(Arc::clone(&store)),
        ..Setup::default()
    })
    .await;
    let ids = rig
        .append(
            WRITER,
            "kill",
            vec![
                // The target takes the write and never answers: the worker dies while sending.
                rig.write("POST", "/stall", Some((b"charge=1", "text/plain")), None)
                    .await,
                rig.write("PUT", "/api/after", Some((b"v=2", "text/plain")), None)
                    .await,
            ],
        )
        .await;

    let doomed = Doomed::start(&rig);
    let started = std::time::Instant::now();
    while rig.writes().is_empty() {
        assert!(
            started.elapsed() < Duration::from_secs(30),
            "the write never reached the site"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    doomed.kill();
    assert_eq!(rig.writes().len(), 1);
    assert_eq!(rig.writes()[0].path, "/stall");
    // The row is leased, with no recorded outcome: exactly what a SIGKILL leaves.
    assert_eq!(rig.row(ids[0]).await.0, FrontierStatus::Leased);

    // The dead holder's sessions and URL leases run out; the fleet reaper returns the row.
    for session in rig.stores.runs.list_sessions(rig.run).await.unwrap() {
        store.expire_session_lease(session.id, SystemClock.now() - chrono::Duration::hours(1));
    }
    let reaper = crawlx_scheduler::Reaper::new(
        Arc::clone(&rig.stores.leases),
        Arc::clone(&rig.stores.journal),
        crawlx_scheduler::ReaperConfig {
            interval: Duration::from_millis(100),
            ..crawlx_scheduler::ReaperConfig::default()
        },
    );
    let stop = CancellationToken::new();
    let sweeping = {
        let stop = stop.clone();
        tokio::spawn(async move {
            while !stop.is_cancelled() {
                let _ = reaper.run_once().await;
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        })
    };
    rig.serve().await;
    stop.cancel();
    sweeping.await.unwrap();

    let writes = rig.writes();
    let stalls = writes.iter().filter(|seen| seen.path == "/stall").count();
    assert_eq!(
        stalls, 1,
        "the interrupted write must not be sent again: {writes:?}"
    );
    assert_eq!(
        rig.row(ids[0]).await,
        (FrontierStatus::Failed, Some("write_outcome_unknown".to_owned()))
    );
    // Work the dead worker never started still runs, once.
    assert_eq!(writes.iter().filter(|seen| seen.path == "/api/after").count(), 1);
    assert_eq!(rig.row(ids[1]).await.0, FrontierStatus::Succeeded);
    let unknown = rig
        .events("request.write_outcome")
        .await
        .into_iter()
        .filter(|event| event.payload["outcome"] == "unknown")
        .count();
    assert_eq!(unknown, 1);
    let counters = rig.stores.runs.get(rig.run).await.unwrap().counters.urls;
    assert_eq!(counters.unknown_outcome, 1);
    assert!(counters.invariants_hold(), "{counters:?}");
}
