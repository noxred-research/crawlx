//! Authenticated local profile control crosses the real API and worker registry.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use axum::http::{Method, StatusCode};
use crawlx_api::{ApiConfig, AppState, Scope, Settings};
use crawlx_core::hash::Digest;
use crawlx_core::repo::RunRepo;
use crawlx_core::session_binding::{SessionBindingV1, SessionIdentityV1};
use crawlx_core::time::{Clock, ManualClock};
use crawlx_core::Timestamp;
use crawlx_storage::testkit::{crawl_run, create_crawl, sessions};
use crawlx_worker::interactive_profiles::{
    InteractiveCommand, InteractiveControl, InteractiveProfiles, InteractiveReply,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

const HEADERS: &[(&str, &str)] = &[
    ("origin", "http://127.0.0.1:8080"),
    ("host", "127.0.0.1:8080"),
    ("x-crawlx-interactive", "1"),
    ("sec-fetch-site", "same-origin"),
];

async fn fixture() -> (common::Env, InteractiveControl, String, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(
        Timestamp::from_timestamp(1_700_000_000, 0).unwrap(),
    ));
    let mut env = common::env_with(ApiConfig::default(), Settings::default(), clock.clone());
    let registry = Arc::new(
        InteractiveProfiles::new(clock.clone(), url::Url::parse("http://127.0.0.1:8080/").unwrap()).unwrap(),
    );
    let config = env.state.config.clone();
    env.state = AppState::builder(
        env.state.repos.clone(),
        crawlx_api::admission_policy(&config, clock.clone()),
        config,
    )
    .clock(clock.clone())
    .interactive_profiles(registry.clone())
    .build();
    env.app = crawlx_api::router(env.state.clone());
    let mut run = crawl_run(env.tenant, create_crawl("https://profile.test/", &[], 1));
    run.created_at = clock.now();
    env.store.create(&run, None).await.unwrap();
    let session = sessions(run.id, 1, 1).remove(0);
    env.store
        .create_sessions(std::slice::from_ref(&session))
        .await
        .unwrap();
    let digest = Digest::of("test/profile-api", b"local");
    let identity = SessionIdentityV1::new(env.tenant, &session, digest, digest, digest, digest, None);
    let binding = SessionBindingV1::new(identity, 7, clock.now() + chrono::Duration::minutes(5));
    let control = registry.register(binding, CancellationToken::new()).unwrap();
    let path = format!("/v1/crawls/{}/interactive-profiles/{}", run.id, session.id);
    (env, control, path, clock)
}

fn start_body() -> Value {
    json!({"profileName":"local-login","expectedGeneration":0,"ttlSeconds":60,
        "retainedProfileConsent":true,"captureConsent":true,"privacyConsent":true})
}

fn path(base: &str, operation: &str) -> String {
    format!("{base}/{operation}?generation=1&leaseFence=7")
}

#[tokio::test]
async fn api_controls_authenticated_owner_and_exact_generation_before_worker_delivery() {
    let (env, mut control, base, _) = fixture().await;
    let request_path = path(&base, "start");
    let body = start_body();
    let (response, ()) = tokio::join!(env.post_with(&request_path, HEADERS, &body), async {
        let InteractiveCommand::Start {
            scope,
            request,
            reply,
        } = control.recv().await.unwrap()
        else {
            panic!("start required");
        };
        assert_eq!(scope.tenant, env.tenant);
        assert!(scope.owner.starts_with("api_key:"));
        assert_eq!(scope.generation, 1);
        assert_eq!(scope.lease_fence, 7);
        assert_eq!(request.profile_name, "local-login");
        reply.send(Ok(InteractiveReply::Ready)).unwrap();
    });
    assert_eq!(response.0, StatusCode::OK, "{}", response.2);
    assert_eq!(response.2["state"], "active");
    assert_eq!(response.2["framesSuppressed"], true);
    assert_eq!(response.1["cache-control"], "no-store");

    let other_owner = env.key_for("acme", &[Scope::CrawlsWrite]).await;
    let (status, _, _) = env
        .send(
            Method::POST,
            &path(&base, "status"),
            Some(&other_owner),
            HEADERS,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let foreign = env.key_for("foreign-profile-tenant", &[Scope::CrawlsWrite]).await;
    let (status, _, _) = env
        .send(
            Method::POST,
            &path(&base, "status"),
            Some(&foreign),
            HEADERS,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = env
        .send(
            Method::POST,
            &format!("{base}/status?generation=2&leaseFence=7"),
            Some(&env.key),
            HEADERS,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _, _) = env
        .send(
            Method::POST,
            &format!("{base}/status?generation=1&leaseFence=8"),
            Some(&env.key),
            HEADERS,
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(
        env.send(
            Method::POST,
            &path(&base, "cancel"),
            Some(&env.key),
            HEADERS,
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    assert!(control.recv().await.is_none());
}

#[tokio::test]
async fn csrf_origin_auth_scope_and_inline_secret_input_fail_before_actor_effects() {
    let (env, mut control, base, _) = fixture().await;
    let request_path = path(&base, "start");
    let (status, _, _) = env
        .send(Method::POST, &request_path, None, HEADERS, Some(&start_body()))
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let read_only = env.key_for("acme", &[Scope::CrawlsRead]).await;
    assert_eq!(
        env.send(
            Method::POST,
            &request_path,
            Some(&read_only),
            HEADERS,
            Some(&start_body())
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        env.post(&request_path, &start_body()).await.0,
        StatusCode::FORBIDDEN
    );
    let wrong_origin = [
        ("origin", "http://foreign.test"),
        ("host", "127.0.0.1:8080"),
        ("x-crawlx-interactive", "1"),
    ];
    assert_eq!(
        env.post_with(&request_path, &wrong_origin, &start_body()).await.0,
        StatusCode::FORBIDDEN
    );
    let mut invalid = start_body();
    invalid["rawPassword"] = json!("private-input-marker");
    let (status, _, response) = env.post_with(&request_path, HEADERS, &invalid).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!response.to_string().contains("private-input-marker"));
    assert!(!control.cancellation().is_cancelled());
    // No command should be delivered: cancellation wins over a receiver which never got input.
    control.cancellation().cancel();
    assert!(control.recv().await.is_none());
}

#[tokio::test]
async fn finish_reports_only_worker_confirmed_commit_and_cleanup_and_expiry_closes_status() {
    let (env, mut control, base, clock) = fixture().await;
    let start_path = path(&base, "start");
    let body = start_body();
    let (response, ()) = tokio::join!(env.post_with(&start_path, HEADERS, &body), async {
        let InteractiveCommand::Start { reply, .. } = control.recv().await.unwrap() else {
            panic!("start required");
        };
        reply.send(Ok(InteractiveReply::Ready)).unwrap();
    });
    assert_eq!(response.0, StatusCode::OK);
    let finish_path = path(&base, "finish");
    let (response, ()) = tokio::join!(
        env.send(Method::POST, &finish_path, Some(&env.key), HEADERS, None),
        async {
            let InteractiveCommand::Finish { reply, .. } = control.recv().await.unwrap() else {
                panic!("finish required");
            };
            control.committed(1).unwrap();
            reply
                .send(Ok(InteractiveReply::Committed { generation: 1 }))
                .unwrap();
        }
    );
    assert_eq!(response.0, StatusCode::OK);
    let body: Value = serde_json::from_slice(&response.2).unwrap();
    assert_eq!(body["state"], "finished");
    assert_eq!(body["committedGeneration"], 1);
    drop(control);
    clock.advance_ms(60_001);
    assert_eq!(
        env.send(
            Method::POST,
            &path(&base, "status"),
            Some(&env.key),
            HEADERS,
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn static_local_shell_needs_no_bearer_but_exposes_no_session_data() {
    let (env, _control, base, _) = fixture().await;
    let (status, headers, body) = env
        .send(
            Method::GET,
            "/v1/interactive-profiles/ui",
            None,
            &[("host", "127.0.0.1:8080")],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["cache-control"], "no-store");
    let policy = headers["content-security-policy"].to_str().unwrap();
    assert!(policy.contains("default-src 'none'"));
    assert!(policy.contains("script-src 'sha256-"));
    assert!(policy.contains("frame-ancestors 'none'"));
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.contains("Approved credential reference"));
    assert!(!body.contains(&env.key));
    assert!(!body.contains(&base));
    let (status, _, _) = env
        .send(
            Method::GET,
            "/v1/interactive-profiles/ui",
            None,
            &[("host", "untrusted.test")],
            None,
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}
