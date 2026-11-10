#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The `--ai-*` flags (`crawlx_cli::AiArgs`).

use clap::{error::ErrorKind, Parser};
use crawlx_cli::AiArgs;
use crawlx_extract::form_fill::UnresolvedField;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::path::Path;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[derive(Parser, Debug)]
struct Harness {
    #[command(flatten)]
    ai: AiArgs,
}

fn parse(args: &[&str]) -> Result<AiArgs, clap::Error> {
    let argv = std::iter::once("crawlx").chain(args.iter().copied());
    Harness::try_parse_from(argv).map(|h| h.ai)
}

fn field(name: &str) -> UnresolvedField {
    UnresolvedField {
        name: name.to_owned(),
        input_type: "text".to_owned(),
        placeholder: None,
        pattern: None,
    }
}

fn action(n: usize) -> Url {
    Url::parse(&format!("https://shop.example/order/{n}")).unwrap()
}

fn page() -> Url {
    Url::parse("https://shop.example/checkout").unwrap()
}

fn no_env(_: &str) -> Option<String> {
    None
}

async fn chat_completions_server() -> MockServer {
    let server = MockServer::start().await;
    let content = json!({"email_addr": "jane@example.com"}).to_string();
    Mock::given(method("POST"))
        .and(path("/v1/chat/completions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "choices": [{ "message": { "content": content } }],
            "usage": { "prompt_tokens": 7, "completion_tokens": 3 },
        })))
        .mount(&server)
        .await;
    server
}

fn endpoint(server: &MockServer) -> String {
    format!("{}/v1", server.uri())
}

fn expected() -> BTreeMap<String, String> {
    BTreeMap::from([("email_addr".to_owned(), "jane@example.com".to_owned())])
}

async fn requests(server: &MockServer) -> usize {
    server.received_requests().await.unwrap().len()
}

#[test]
fn flags_parse_into_fields_and_no_flag_means_unset() {
    let ai = parse(&[
        "--ai-url",
        "http://127.0.0.1:11434/v1",
        "--ai-model",
        "llama3",
        "--ai-key-env",
        "MY_KEY",
        "--ai-record",
        "rec.jsonl",
        "--ai-max-calls",
        "7",
    ])
    .unwrap();
    assert_eq!(ai.ai_url.as_deref(), Some("http://127.0.0.1:11434/v1"));
    assert_eq!(ai.ai_model.as_deref(), Some("llama3"));
    assert_eq!(ai.ai_key_env.as_deref(), Some("MY_KEY"));
    assert_eq!(ai.ai_record.as_deref(), Some(Path::new("rec.jsonl")));
    assert_eq!(ai.ai_replay, None);
    assert_eq!(ai.ai_max_calls, Some(7));
    assert!(!ai.is_unset());

    let replay = parse(&["--ai-replay", "rec.jsonl"]).unwrap();
    assert_eq!(replay.ai_replay.as_deref(), Some(Path::new("rec.jsonl")));
    assert!(!replay.is_unset());

    // Hermetic only when the developer's shell has no AI_URL/AI_MODEL exported.
    if std::env::var_os("AI_URL").is_none() && std::env::var_os("AI_MODEL").is_none() {
        let none = parse(&[]).unwrap();
        assert!(none.is_unset());
        assert!(none.settings_with(&no_env).unwrap().is_none());
    }
}

#[test]
fn record_and_replay_are_mutually_exclusive() {
    let err = parse(&["--ai-record", "a", "--ai-replay", "b"]).unwrap_err();
    assert_eq!(err.kind(), ErrorKind::ArgumentConflict);

    // A config-file layer can bypass clap; settings() refuses the combination too.
    let ai = AiArgs {
        ai_url: Some("http://127.0.0.1:1/v1".to_owned()),
        ai_model: Some("m".to_owned()),
        ai_record: Some("a".into()),
        ai_replay: Some("b".into()),
        ..AiArgs::default()
    };
    let err = ai.settings_with(&no_env).err().unwrap();
    assert!(format!("{err:#}").contains("mutually exclusive"), "{err:#}");
}

#[test]
fn url_and_model_are_required_without_replay() {
    for (args, needle) in [
        (vec!["--ai-model", "m"], "--ai-url"),
        (vec!["--ai-max-calls", "3"], "--ai-url"),
        (vec!["--ai-record", "x.jsonl"], "--ai-url"),
        (vec!["--ai-url", "http://127.0.0.1:1/v1"], "--ai-model"),
        (
            vec!["--ai-url", "http://127.0.0.1:1/v1", "--ai-model", "  "],
            "--ai-model",
        ),
    ] {
        let ai = parse(&args).unwrap();
        let err = ai
            .settings_with(&no_env)
            .err()
            .unwrap_or_else(|| panic!("{args:?} must fail"));
        assert!(format!("{err:#}").contains(needle), "{args:?}: {err:#}");
    }
}

#[test]
fn unusable_urls_and_recordings_are_reported() {
    let ai = parse(&["--ai-url", "ftp://models.example/v1", "--ai-model", "m"]).unwrap();
    assert!(
        ai.settings_with(&no_env).is_err(),
        "only http(s) endpoints are accepted"
    );

    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("none.jsonl");
    let ai = parse(&["--ai-replay", missing.to_str().unwrap()]).unwrap();
    let err = ai.settings_with(&no_env).err().unwrap();
    assert!(format!("{err:#}").contains("--ai-replay"), "{err:#}");

    let corrupt = dir.path().join("bad.jsonl");
    std::fs::write(&corrupt, "this is not json\n").unwrap();
    let ai = parse(&["--ai-replay", corrupt.to_str().unwrap()]).unwrap();
    let err = ai.settings_with(&no_env).err().unwrap();
    assert!(format!("{err:#}").contains("line 1"), "{err:#}");
}

#[tokio::test]
async fn settings_build_a_decider_that_asks_the_endpoint() {
    let server = chat_completions_server().await;
    let ai = parse(&["--ai-url", &endpoint(&server), "--ai-model", "test-model"]).unwrap();
    let decider = ai.settings_with(&no_env).unwrap().expect("a decider");
    let got = decider.decide(&page(), &action(0), &[field("email_addr")]).await;
    assert_eq!(got, expected());
    let seen = server.received_requests().await.unwrap();
    assert_eq!(seen.len(), 1);
    let body: Value = seen[0].body_json().unwrap();
    assert_eq!(body["model"], "test-model");
    assert!(
        seen[0].headers.get("authorization").is_none(),
        "no key configured, none sent"
    );
}

#[tokio::test]
async fn api_key_comes_from_the_named_environment_variable_only() {
    let server = chat_completions_server().await;
    let env = |name: &str| (name == "MY_AI_KEY").then(|| "sk-from-named-var".to_owned());
    let ai = parse(&[
        "--ai-url",
        &endpoint(&server),
        "--ai-model",
        "m",
        "--ai-key-env",
        "MY_AI_KEY",
    ])
    .unwrap();
    let decider = ai.settings_with(&env).unwrap().unwrap();
    decider.decide(&page(), &action(0), &[field("email_addr")]).await;
    let seen = server.received_requests().await.unwrap();
    assert_eq!(
        seen[0].headers.get("authorization").unwrap(),
        "Bearer sk-from-named-var"
    );

    // Without --ai-key-env the compatibility flags' AI_API_KEY is used.
    let server = chat_completions_server().await;
    let env = |name: &str| (name == "AI_API_KEY").then(|| "sk-default-name".to_owned());
    let ai = parse(&["--ai-url", &endpoint(&server), "--ai-model", "m"]).unwrap();
    let decider = ai.settings_with(&env).unwrap().unwrap();
    decider.decide(&page(), &action(0), &[field("email_addr")]).await;
    let seen = server.received_requests().await.unwrap();
    assert_eq!(
        seen[0].headers.get("authorization").unwrap(),
        "Bearer sk-default-name"
    );

    // A named variable that is not set is an error that names the variable, not a silent no-key run.
    let ai = parse(&[
        "--ai-url",
        &endpoint(&server),
        "--ai-model",
        "m",
        "--ai-key-env",
        "ABSENT_VAR",
    ])
    .unwrap();
    let err = ai.settings_with(&no_env).err().unwrap();
    assert!(format!("{err:#}").contains("ABSENT_VAR"), "{err:#}");
    let ai = parse(&[
        "--ai-url",
        &endpoint(&server),
        "--ai-model",
        "m",
        "--ai-key-env",
        " ",
    ])
    .unwrap();
    assert!(ai.settings_with(&no_env).is_err());
}

#[tokio::test]
async fn record_then_replay_answers_without_a_url_or_any_request() {
    let server = chat_completions_server().await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("answers.jsonl");
    let file_arg = file.to_str().unwrap();
    let env = |name: &str| (name == "AI_API_KEY").then(|| "sk-never-recorded".to_owned());

    let record = parse(&[
        "--ai-url",
        &endpoint(&server),
        "--ai-model",
        "m",
        "--ai-record",
        file_arg,
    ])
    .unwrap();
    let decider = record.settings_with(&env).unwrap().unwrap();
    assert_eq!(
        decider.decide(&page(), &action(0), &[field("email_addr")]).await,
        expected()
    );
    assert_eq!(requests(&server).await, 1);
    let recorded = std::fs::read_to_string(&file).unwrap();
    assert_eq!(recorded.lines().count(), 1);
    assert!(!recorded.contains("sk-never-recorded"));
    drop(decider);

    // The same recording file reused by a later --ai-record run costs no call.
    let again = parse(&[
        "--ai-url",
        &endpoint(&server),
        "--ai-model",
        "m",
        "--ai-record",
        file_arg,
    ])
    .unwrap();
    let decider = again.settings_with(&env).unwrap().unwrap();
    assert_eq!(
        decider.decide(&page(), &action(0), &[field("email_addr")]).await,
        expected()
    );
    assert_eq!(
        requests(&server).await,
        1,
        "a recorded answer is reused, not asked again"
    );
    drop(decider);

    // Replay needs no --ai-url and never touches the network.
    drop(server);
    let replay = parse(&["--ai-replay", file_arg]).unwrap();
    let decider = replay.settings_with(&no_env).unwrap().unwrap();
    assert_eq!(
        decider.decide(&page(), &action(0), &[field("email_addr")]).await,
        expected()
    );
    assert!(
        decider
            .decide(&page(), &action(0), &[field("never_recorded")])
            .await
            .is_empty(),
        "a form missing from the recording gets no AI values"
    );
}

#[tokio::test]
async fn replay_ignores_the_endpoint_flags() {
    let server = chat_completions_server().await;
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("answers.jsonl");
    let file_arg = file.to_str().unwrap();
    let record = parse(&[
        "--ai-url",
        &endpoint(&server),
        "--ai-model",
        "m",
        "--ai-record",
        file_arg,
    ])
    .unwrap();
    let decider = record.settings_with(&no_env).unwrap().unwrap();
    decider.decide(&page(), &action(0), &[field("email_addr")]).await;
    assert_eq!(requests(&server).await, 1);

    let replay = parse(&[
        "--ai-url",
        &endpoint(&server),
        "--ai-model",
        "m",
        "--ai-replay",
        file_arg,
    ])
    .unwrap();
    let decider = replay.settings_with(&no_env).unwrap().unwrap();
    decider
        .decide(&page(), &action(5), &[field("email_addr"), field("other")])
        .await;
    assert_eq!(
        requests(&server).await,
        1,
        "replay never calls the configured endpoint"
    );
}

#[tokio::test]
async fn max_calls_caps_the_model_and_zero_lifts_it() {
    let server = chat_completions_server().await;
    let ai = parse(&[
        "--ai-url",
        &endpoint(&server),
        "--ai-model",
        "m",
        "--ai-max-calls",
        "2",
    ])
    .unwrap();
    let decider = ai.settings_with(&no_env).unwrap().unwrap();
    let mut answered = 0;
    for n in 0..5 {
        if !decider
            .decide(&page(), &action(n), &[field("email_addr")])
            .await
            .is_empty()
        {
            answered += 1;
        }
    }
    assert_eq!(answered, 2);
    assert_eq!(requests(&server).await, 2);

    let server = chat_completions_server().await;
    let ai = parse(&[
        "--ai-url",
        &endpoint(&server),
        "--ai-model",
        "m",
        "--ai-max-calls",
        "0",
    ])
    .unwrap();
    let decider = ai.settings_with(&no_env).unwrap().unwrap();
    for n in 0..120 {
        assert!(!decider
            .decide(&page(), &action(n), &[field("email_addr")])
            .await
            .is_empty());
    }
    assert_eq!(requests(&server).await, 120, "0 means unlimited");
}

#[tokio::test]
async fn default_cap_is_one_hundred_calls() {
    let server = chat_completions_server().await;
    let ai = parse(&["--ai-url", &endpoint(&server), "--ai-model", "m"]).unwrap();
    let decider = ai.settings_with(&no_env).unwrap().unwrap();
    let mut answered = 0;
    for n in 0..105 {
        if !decider
            .decide(&page(), &action(n), &[field("email_addr")])
            .await
            .is_empty()
        {
            answered += 1;
        }
    }
    assert_eq!((answered, requests(&server).await), (100, 100));
}
