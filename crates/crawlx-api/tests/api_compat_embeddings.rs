#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The self-host provider overrides of the LLM products ("LLM providers"):
//! `CRAWLX_EMBEDDING_MODEL` ranks the pages of `/extract` before the LLM sees them, and
//! `EXTRACTION_PROVIDER_*` moves the extraction step (and only that step) to a second
//! chat-completions compatible endpoint.
//!
//! The first group injects a deterministic [`MockEmbeddings`] to dictate the ranking; the second
//! builds the backends from environment-variable maps exactly as `crawlx serve` does and talks
//! to wiremock servers standing in for the chat and embeddings endpoints (no network).

use axum::body::Body;
#[allow(
    clippy::disallowed_types,
    reason = "test fixture builds raw HTTP messages for a local peer"
)]
use axum::http::{Method, Request, StatusCode};
use axum::Router;
use crawlx_api::auth::{generate_key, key_record, tenant_id_for};
use crawlx_api::config::IntelConfig;
use crawlx_api::intel::rank::PageRanker;
use crawlx_api::intel::tools::MockPageTools;
use crawlx_api::intel::{backends, Backends};
use crawlx_api::{ApiConfig, AppState, Repos, Scope};
use crawlx_model::llm::{ExtractionRouter, LlmCall, LlmExtractor, MockEmbeddings, MockLlm};
use crawlx_policy::AdmissionPolicy;
use crawlx_storage::MemoryStore;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tower::ServiceExt;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, Request as WmRequest, Respond, ResponseTemplate};

const V2: &str = "/compat/v2";

const PAGE_A: &str = "https://shop.example.com/a";
const PAGE_B: &str = "https://shop.example.com/b";
const PAGE_C: &str = "https://shop.example.com/c";
const PAGE_D: &str = "https://shop.example.com/d";

/// Cosine against `[1, 0]` (the vector of the prompt below): B 1.0, C 0.71, A 0, D 0 (no
/// magnitude); A comes before D on the tie. Ranking order: B, C, A, D.
const PAGES: [(&str, &str); 4] = [
    (PAGE_A, "the company history page tells history stories"),
    (PAGE_B, "pricing table: price list, pricing plans"),
    (PAGE_C, "pricing and history"),
    (PAGE_D, "unrelated weather report"),
];
const PROMPT: &str = "Extract the pricing plans";

/// The backends a state is built from; [`Backends`] is `non_exhaustive`, so tests restate it.
#[derive(Default)]
struct Parts {
    llm: Option<Arc<dyn LlmExtractor>>,
    extraction: Option<Arc<ExtractionRouter>>,
    embeddings: Option<Arc<PageRanker>>,
}

impl From<Backends> for Parts {
    fn from(b: Backends) -> Self {
        Self {
            llm: b.llm,
            extraction: b.extraction,
            embeddings: b.embeddings,
        }
    }
}

struct T {
    app: Router,
    key: String,
}

impl T {
    fn new(backends: impl Into<Parts>) -> Self {
        let backends: Parts = backends.into();
        let store = Arc::new(MemoryStore::new());
        let repos = Repos::memory(store);
        let tools = Arc::new(MockPageTools::new());
        let config = ApiConfig {
            rate_limit_per_minute: 0,
            ..ApiConfig::default()
        };
        let clock: Arc<dyn crawlx_core::Clock> = Arc::new(crawlx_core::SystemClock);
        let mut b = AppState::builder(repos.clone(), AdmissionPolicy::new(clock.clone()), config)
            .clock(clock)
            .page_tools(tools.clone());
        if let Some(l) = backends.llm {
            b = b.llm(l);
        }
        if let Some(r) = backends.extraction {
            b = b.extraction_router(r);
        }
        if let Some(r) = backends.embeddings {
            b = b.page_ranker(r);
        }
        let state = b.build();
        let app = crawlx_api::router(state);
        let tenant = tenant_id_for("acme");
        let key = generate_key();
        let rec = key_record(&key, tenant, Scope::all_set()).unwrap();
        futures::executor::block_on(async { repos.api.key_insert(&rec, "acme").await.unwrap() });
        for (url, markdown) in PAGES {
            tools.set_markdown(url, markdown);
        }
        Self { app, key }
    }

    async fn call(&self, method: Method, uri: &str, body: Option<&Value>) -> (StatusCode, Value) {
        let b = Request::builder()
            .method(method)
            .uri(uri)
            .header("authorization", format!("Bearer {}", self.key));
        let req = match body {
            Some(v) => b
                .header("content-type", "application/json")
                .body(Body::from(v.to_string()))
                .unwrap(),
            None => b.body(Body::empty()).unwrap(),
        };
        let resp = self.app.clone().oneshot(req).await.unwrap();
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 16 * 1024 * 1024)
            .await
            .unwrap();
        (status, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    async fn post(&self, p: &str, body: &Value) -> (StatusCode, Value) {
        self.call(Method::POST, &format!("{V2}{p}"), Some(body)).await
    }

    /// Run `/extract` over every fixture page and wait for the job.
    async fn extract(&self, body: &Value) -> Value {
        let (s, v) = self.post("/extract", body).await;
        assert_eq!(s, StatusCode::OK, "{v}");
        let uri = format!("{V2}/extract/{}", v["id"].as_str().unwrap());
        for _ in 0..500 {
            let (s, v) = self.call(Method::GET, &uri, None).await;
            assert_eq!(s, StatusCode::OK, "{v}");
            if v["status"] != "processing" {
                return v;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("extract job never finished");
    }
}

fn all_pages_body() -> Value {
    json!({"urls": PAGES.map(|(u, _)| u), "prompt": PROMPT})
}

/// Positions of the page labels in the text the LLM received, in the order they appear.
fn pages_seen(user: &str) -> Vec<&'static str> {
    let mut found: Vec<(usize, &'static str)> = PAGES
        .iter()
        .filter_map(|(url, _)| user.find(&format!("Page {url}:")).map(|at| (at, *url)))
        .collect();
    found.sort_unstable();
    found.into_iter().map(|(_, url)| url).collect()
}

fn answering_llm() -> Arc<MockLlm> {
    Arc::new(MockLlm::from_fn(|_| Ok(json!({"plan": "pro"}))))
}

fn mock_embeddings(dims: usize) -> Arc<MockEmbeddings> {
    Arc::new(
        MockEmbeddings::new(dims)
            .with_rule("pricing plans", vec![1.0, 0.0]) // the prompt
            .with_rule("price list", vec![1.0, 0.0])
            .with_rule("pricing and history", vec![0.7, 0.7])
            .with_rule("history", vec![0.0, 1.0])
            .with_rule("weather", vec![0.0, 0.0]),
    )
}

fn only_call(llm: &MockLlm) -> LlmCall {
    let mut calls = llm.calls();
    assert_eq!(calls.len(), 1, "exactly one LLM call: {calls:?}");
    calls.remove(0)
}

// ---- injected mock embeddings -----------------------------------------------------------------

#[tokio::test]
async fn the_llm_receives_the_pages_in_cosine_rank_order_and_only_the_top_n() {
    let llm = answering_llm();
    let embeddings = mock_embeddings(2);
    let t = T::new(Parts {
        llm: Some(llm.clone()),
        embeddings: Some(Arc::new(PageRanker::new(embeddings.clone(), 2))),
        ..Parts::default()
    });
    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["data"], json!({"plan": "pro"}));

    let call = only_call(&llm);
    assert_eq!(
        pages_seen(&call.user),
        [PAGE_B, PAGE_C],
        "best page first, only the top 2 of 4: {}",
        call.user
    );
    assert!(
        done["warning"]
            .as_str()
            .unwrap()
            .contains("embedding ranking sent the 2 most relevant of 4 pages"),
        "{done}"
    );

    let sent = embeddings.calls();
    assert_eq!(sent.len(), 1, "one embeddings call for the prompt and the pages");
    assert_eq!(sent[0][0], PROMPT, "the prompt is the query");
    assert_eq!(sent[0].len(), 5);
    assert!(
        sent[0][1].starts_with(PAGE_A),
        "pages follow in scrape order: {:?}",
        sent[0][1]
    );
}

#[tokio::test]
async fn a_top_n_above_the_page_count_only_reorders() {
    let llm = answering_llm();
    let t = T::new(Parts {
        llm: Some(llm.clone()),
        embeddings: Some(Arc::new(PageRanker::new(mock_embeddings(2), 10))),
        ..Parts::default()
    });
    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(
        pages_seen(&only_call(&llm).user),
        [PAGE_B, PAGE_C, PAGE_A, PAGE_D]
    );
    assert!(done.get("warning").is_none(), "nothing was dropped: {done}");
}

#[tokio::test]
async fn without_an_embedding_model_the_order_and_the_page_set_are_unchanged() {
    let llm = answering_llm();
    let t = T::new(Parts {
        llm: Some(llm.clone()),
        ..Parts::default()
    });
    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(
        pages_seen(&only_call(&llm).user),
        [PAGE_A, PAGE_B, PAGE_C, PAGE_D]
    );
    assert!(done.get("warning").is_none(), "{done}");
    assert_eq!(
        done["tokensUsed"],
        llm_tokens(&llm),
        "only the LLM call is counted"
    );
}

fn llm_tokens(llm: &MockLlm) -> u64 {
    let call = &llm.calls()[0];
    let est = |chars: usize| u64::try_from(chars.div_ceil(4)).unwrap();
    est(call.system.chars().count() + call.user.chars().count())
        + est(json!({"plan": "pro"}).to_string().chars().count())
}

#[tokio::test]
async fn a_schema_without_a_prompt_ranks_by_the_schema_text() {
    let llm = answering_llm();
    let embeddings = Arc::new(
        MockEmbeddings::new(2)
            .with_rule("\"pricing\"", vec![1.0, 0.0])
            .with_rule("pricing", vec![0.9, 0.1])
            .with_rule("weather", vec![0.0, 1.0]),
    );
    let t = T::new(Parts {
        llm: Some(llm.clone()),
        embeddings: Some(Arc::new(PageRanker::new(embeddings.clone(), 1))),
        ..Parts::default()
    });
    let schema = json!({"type": "object", "properties": {"pricing": {"type": "string"}}});
    let done = t
        .extract(&json!({"urls": [PAGE_D, PAGE_B], "schema": schema}))
        .await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(embeddings.calls()[0][0], schema.to_string());
    assert!(
        pages_seen(&only_call(&llm).user) == [PAGE_B],
        "the pricing page won"
    );
}

#[tokio::test]
async fn a_failing_embeddings_endpoint_does_not_fail_the_job() {
    let llm = answering_llm();
    let failing =
        Arc::new(MockEmbeddings::new(2).failing(crawlx_model::llm::EmbeddingsError::Status { status: 503 }));
    let t = T::new(Parts {
        llm: Some(llm.clone()),
        embeddings: Some(Arc::new(PageRanker::new(failing, 1))),
        ..Parts::default()
    });
    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(
        pages_seen(&only_call(&llm).user),
        [PAGE_A, PAGE_B, PAGE_C, PAGE_D],
        "scrape order, nothing dropped"
    );
    assert!(
        done["warning"].as_str().unwrap().contains("ranking was skipped"),
        "{done}"
    );
}

// ---- backends built from environment variables, endpoints on wiremock --------------------------

/// Embeds every input as `[count("pric"), count("histor")]`.
struct KeywordVectors;

impl Respond for KeywordVectors {
    fn respond(&self, request: &WmRequest) -> ResponseTemplate {
        let body: Value = request.body_json().unwrap();
        let data: Vec<Value> = body["input"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(index, text)| {
                let text = text.as_str().unwrap();
                json!({
                    "object": "embedding",
                    "index": index,
                    "embedding": [text.matches("pric").count(), text.matches("histor").count()],
                })
            })
            .collect();
        ResponseTemplate::new(200).set_body_json(json!({
            "data": data,
            "usage": {"prompt_tokens": 7, "total_tokens": 7},
        }))
    }
}

fn chat_reply(content: &Value) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "choices": [{"message": {"role": "assistant", "content": content.to_string()}, "finish_reason":"stop"}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 5, "total_tokens": 16},
    }))
}

async fn chat_server(label: &str, expected_chat_calls: u64) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(chat_reply(&json!({"plan": label})))
        .expect(expected_chat_calls)
        .mount(&server)
        .await;
    server
}

fn env_map(pairs: &[(&str, String)]) -> impl Fn(&str) -> Option<String> {
    let map: BTreeMap<String, String> = pairs.iter().map(|(k, v)| ((*k).to_owned(), v.clone())).collect();
    move |k| map.get(k).cloned()
}

fn key_file(dir: &tempfile::TempDir, name: &str, key: &str) -> String {
    let p = dir.path().join(name);
    std::fs::write(&p, format!("{key}\n")).unwrap();
    format!("file:{}", p.display())
}

/// Chat requests a server received, parsed.
async fn chat_requests(server: &MockServer) -> Vec<Value> {
    server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.url.path() == "/v1/chat/completions")
        .map(|r| r.body_json().unwrap())
        .collect()
}

#[tokio::test]
async fn env_wiring_ranks_through_the_embeddings_endpoint_before_the_chat_call() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .and(header("authorization", "Bearer sk-embed"))
        .respond_with(KeywordVectors)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(chat_reply(&json!({"plan": "pro"})))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let mut intel = IntelConfig::default()
        .from_lookup(env_map(&[
            ("CRAWLX_LLM_BASE_URL", format!("{}/v1", server.uri())),
            ("CRAWLX_LLM_MODEL", "chat-model".to_owned()),
            ("CRAWLX_EMBEDDING_MODEL", "embed-model".to_owned()),
            ("EXTRACT_EMBEDDING_TOP_N", "2".to_owned()),
        ]))
        .unwrap();
    intel.embeddings.as_mut().unwrap().api_key_ref = Some(key_file(&dir, "embed-key", "sk-embed"));
    let t = T::new(backends(&intel).unwrap());

    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["data"], json!({"plan": "pro"}));
    assert_eq!(
        done["tokensUsed"],
        7 + 11 + 5,
        "embedding tokens count toward the job"
    );

    let embed_req: Value = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .find(|r| r.url.path() == "/v1/embeddings")
        .unwrap()
        .body_json()
        .unwrap();
    assert_eq!(embed_req["model"], "embed-model");
    assert_eq!(embed_req["input"][0], PROMPT);
    assert_eq!(embed_req["input"].as_array().unwrap().len(), 5);

    let chats = chat_requests(&server).await;
    assert_eq!(chats.len(), 1);
    assert_eq!(chats[0]["model"], "chat-model");
    let user = chats[0]["messages"][1]["content"].as_str().unwrap();
    assert_eq!(
        pages_seen(user),
        [PAGE_B, PAGE_C],
        "ranked, cut to EXTRACT_EMBEDDING_TOP_N: {user}"
    );
}

#[tokio::test]
async fn env_without_the_embedding_model_makes_no_embeddings_call() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .respond_with(KeywordVectors)
        .expect(0)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(chat_reply(&json!({"plan": "pro"})))
        .expect(1)
        .mount(&server)
        .await;
    let intel = IntelConfig::default()
        .from_lookup(env_map(&[
            ("CRAWLX_LLM_BASE_URL", format!("{}/v1", server.uri())),
            ("CRAWLX_LLM_MODEL", "chat-model".to_owned()),
            // an empty value is "unset", as docker compose passes it
            ("CRAWLX_EMBEDDING_MODEL", String::new()),
        ]))
        .unwrap();
    assert!(intel.embeddings.is_none());
    let t = T::new(backends(&intel).unwrap());
    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["tokensUsed"], 11 + 5);
    let user = chat_requests(&server).await[0]["messages"][1]["content"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        pages_seen(&user),
        [PAGE_A, PAGE_B, PAGE_C, PAGE_D],
        "scrape order, every page"
    );
    // `expect(0)` on the embeddings route is verified when `server` drops
}

#[tokio::test]
async fn an_embeddings_model_without_an_endpoint_override_uses_the_chat_endpoint_and_its_key() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/embeddings"))
        .and(header("authorization", "Bearer sk-shared"))
        .respond_with(KeywordVectors)
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer sk-shared"))
        .respond_with(chat_reply(&json!({"plan": "pro"})))
        .expect(1)
        .mount(&server)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let mut intel = IntelConfig::default()
        .from_lookup(env_map(&[
            ("CRAWLX_LLM_BASE_URL", format!("{}/v1", server.uri())),
            ("CRAWLX_LLM_API_KEY", "unused-here".to_owned()),
            ("CRAWLX_EMBEDDING_MODEL", "embed-model".to_owned()),
        ]))
        .unwrap();
    // the default key is a reference; point it at a file instead of the process environment
    intel.llm.as_mut().unwrap().api_key_ref = Some(key_file(&dir, "shared", "sk-shared"));
    let t = T::new(backends(&intel).unwrap());
    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["status"], "completed", "{done}");
}

// ---- per-step providers -----------------------------------------------------------------------

fn extraction_env(default: &MockServer, provider: &MockServer, extra: &[(&str, String)]) -> IntelConfig {
    let mut pairs = vec![
        ("CRAWLX_LLM_BASE_URL", format!("{}/v1", default.uri())),
        ("CRAWLX_LLM_MODEL", "default-model".to_owned()),
        ("EXTRACTION_PROVIDER_BASE_URL", format!("{}/v1", provider.uri())),
        ("EXTRACTION_PROVIDER_MODEL", "extract-model".to_owned()),
    ];
    pairs.extend(extra.iter().map(|(k, v)| (*k, v.clone())));
    IntelConfig::default().from_lookup(env_map(&pairs)).unwrap()
}

#[tokio::test]
async fn the_extraction_step_calls_the_provider_endpoint_while_other_steps_use_the_default() {
    let default = chat_server("default", 1).await;
    let provider = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .and(header("authorization", "Bearer sk-provider"))
        .respond_with(chat_reply(&json!({"plan": "provider"})))
        .expect(1)
        .mount(&provider)
        .await;
    let dir = tempfile::tempdir().unwrap();
    let mut intel = extraction_env(
        &default,
        &provider,
        &[("EXTRACTION_PROVIDER_ROLLOUT_PERCENT", "100".to_owned())],
    );
    intel.extraction.as_mut().unwrap().api_key_ref = Some(key_file(&dir, "provider-key", "sk-provider"));
    let t = T::new(backends(&intel).unwrap());

    // the extraction step: the provider answers, the default model is not called
    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["data"], json!({"plan": "provider"}));
    let at_provider = chat_requests(&provider).await;
    assert_eq!(at_provider.len(), 1);
    assert_eq!(at_provider[0]["model"], "extract-model");
    assert!(
        chat_requests(&default).await.is_empty(),
        "the default endpoint saw nothing yet"
    );

    // another LLM step (crawl planning) keeps using the default endpoint and model
    let (s, v) = t
        .post(
            "/crawl/params-preview",
            &json!({"url": "https://docs.example.com/", "prompt": "only the blog"}),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let at_default = chat_requests(&default).await;
    assert_eq!(at_default.len(), 1);
    assert_eq!(at_default[0]["model"], "default-model");
    assert!(
        at_default[0]["messages"][1]["content"]
            .as_str()
            .unwrap()
            .contains("only the blog"),
        "{:?}",
        at_default[0]
    );
    assert_eq!(
        chat_requests(&provider).await.len(),
        1,
        "the provider never sees the other step"
    );
}

#[tokio::test]
async fn a_tenant_outside_the_rollout_is_answered_by_the_default_model() {
    let default = chat_server("default", 1).await;
    let provider = chat_server("provider", 0).await;
    let intel = extraction_env(&default, &provider, &[]); // rollout 0, no team ids
    let t = T::new(backends(&intel).unwrap());
    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["data"], json!({"plan": "default"}), "{done}");
}

#[tokio::test]
async fn a_listed_tenant_is_routed_to_the_provider_even_at_zero_rollout() {
    let default = chat_server("default", 0).await;
    let provider = chat_server("provider", 1).await;
    let tenant = tenant_id_for("acme").to_string();
    let intel = extraction_env(&default, &provider, &[("EXTRACTION_PROVIDER_TEAM_IDS", tenant)]);
    let t = T::new(backends(&intel).unwrap());
    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["data"], json!({"plan": "provider"}), "{done}");
}

#[tokio::test]
async fn oversize_input_stays_on_the_default_model() {
    let default = chat_server("default", 1).await;
    let provider = chat_server("provider", 0).await;
    let intel = extraction_env(
        &default,
        &provider,
        &[
            ("EXTRACTION_PROVIDER_ROLLOUT_PERCENT", "100".to_owned()),
            ("EXTRACTION_PROVIDER_MAX_INPUT_BYTES", "20".to_owned()),
        ],
    );
    let t = T::new(backends(&intel).unwrap());
    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["data"], json!({"plan": "default"}), "{done}");
}

#[tokio::test]
async fn a_failing_provider_falls_back_to_the_default_model_for_that_request() {
    let default = chat_server("default", 1).await;
    let provider = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&provider)
        .await;
    let intel = extraction_env(
        &default,
        &provider,
        &[("EXTRACTION_PROVIDER_ROLLOUT_PERCENT", "100".to_owned())],
    );
    let t = T::new(backends(&intel).unwrap());
    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["status"], "completed", "{done}");
    assert_eq!(done["data"], json!({"plan": "default"}));
}

#[tokio::test]
async fn a_shadow_share_mirrors_the_call_but_answers_with_the_default_model() {
    let default = chat_server("default", 1).await;
    let provider = chat_server("provider", 1).await;
    // 100% shadow: every tenant is mirrored, none is routed
    let intel = extraction_env(
        &default,
        &provider,
        &[("EXTRACTION_PROVIDER_SHADOW_PERCENT", "100".to_owned())],
    );
    let t = T::new(backends(&intel).unwrap());
    let done = t.extract(&all_pages_body()).await;
    assert_eq!(done["data"], json!({"plan": "default"}), "{done}");
    for _ in 0..200 {
        if !chat_requests(&provider).await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let mirrored = chat_requests(&provider).await;
    assert_eq!(mirrored.len(), 1, "the provider got the mirrored request");
    assert_eq!(
        mirrored[0]["messages"],
        chat_requests(&default).await[0]["messages"]
    );
}

#[test]
fn an_extraction_provider_without_a_default_llm_is_a_configuration_error() {
    let intel = IntelConfig::default()
        .from_lookup(env_map(&[(
            "EXTRACTION_PROVIDER_BASE_URL",
            "http://p/v1".to_owned(),
        )]))
        .unwrap();
    let Err(e) = backends(&intel) else {
        panic!("the provider falls back to a default LLM that is not configured");
    };
    let text = e.to_string();
    assert!(
        text.contains("intel.extraction") && text.contains("default LLM"),
        "{text}"
    );
}
