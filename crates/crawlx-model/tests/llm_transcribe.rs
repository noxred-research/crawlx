#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Speech-to-text seam of the `audio`/`video` scrape formats: [`LlmExtractor::transcribe`] over an
//! chat-completions compatible `audio/transcriptions` endpoint, the scripted double and the wrappers.

use crawlx_core::secret::SecretOr;
use crawlx_model::llm::{ChatCompletionsClient, LlmConfig, LlmError, LlmExtractor, MockLlm};
use crawlx_model::llm_cache::{CallCap, Offline, RecordingLlm};
use serde_json::json;
use std::time::Duration;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Bytes that look like MP3 frames and contain CR/LF and a quote, to prove the body is verbatim.
fn audio() -> Vec<u8> {
    let mut bytes = b"ID3\x04\x00\x00\x00\x00\x00\x00\xff\xfb\x90\x00\r\n\"--".to_vec();
    bytes.extend((0..=255u8).cycle().take(4096));
    bytes
}

fn config(server: &MockServer) -> LlmConfig {
    let mut cfg = LlmConfig::new(&format!("{}/v1", server.uri()), "chat-model");
    cfg.api_key = Some(SecretOr::secret("sk-test".to_owned()));
    cfg.timeout = Duration::from_secs(5);
    cfg.transcribe_endpoint = Some(format!("{}/stt/v1/", server.uri()));
    cfg
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[tokio::test]
async fn transcribe_posts_the_multipart_form_and_reads_text() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/stt/v1/audio/transcriptions"))
        .and(header("authorization", "Bearer sk-test"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "text": "  hello world \n",
            "usage": {"type": "tokens", "input_tokens": 14, "output_tokens": 2, "total_tokens": 16},
        })))
        .expect(1)
        .mount(&server)
        .await;
    let llm = ChatCompletionsClient::new(config(&server)).unwrap();
    assert!(llm.can_transcribe());
    let bytes = audio();
    let done = llm.transcribe(&bytes, "talk.mp3", "audio/mpeg").await.unwrap();
    assert_eq!(done.value, "hello world");
    assert_eq!((done.usage.prompt_tokens, done.usage.completion_tokens), (14, 2));

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1, "no chat call is made");
    let request = &requests[0];
    let content_type = request.headers.get("content-type").unwrap().to_str().unwrap();
    let boundary = content_type
        .strip_prefix("multipart/form-data; boundary=")
        .unwrap();
    let body = request.body.as_slice();
    let text = String::from_utf8_lossy(body);
    assert!(text.starts_with(&format!("--{boundary}\r\n")), "{text}");
    assert!(text.ends_with(&format!("\r\n--{boundary}--\r\n")));
    assert!(
        text.contains("name=\"model\"\r\n\r\nwhisper-1\r\n"), // wire-compat: default hosted speech-to-text model id
        "default model"
    );
    assert!(text.contains("name=\"response_format\"\r\n\r\njson\r\n"));
    assert!(text.contains("name=\"file\"; filename=\"talk.mp3\"\r\nContent-Type: audio/mpeg\r\n\r\n"));
    let file_at =
        find(body, b"Content-Type: audio/mpeg\r\n\r\n").unwrap() + b"Content-Type: audio/mpeg\r\n\r\n".len();
    assert_eq!(
        &body[file_at..file_at + bytes.len()],
        bytes.as_slice(),
        "audio is sent verbatim"
    );
    assert_eq!(
        body.len(),
        file_at + bytes.len() + format!("\r\n--{boundary}--\r\n").len()
    );
}

#[tokio::test]
async fn transcribe_uses_configured_model_full_url_and_hostile_names_are_neutralised() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/audio/transcriptions"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"text": "ok"})))
        .mount(&server)
        .await;
    let mut cfg = config(&server);
    cfg.transcribe_endpoint = Some(format!("{}/audio/transcriptions", server.uri()));
    cfg.transcribe_model = Some("distil-large".to_owned());
    cfg.api_key = None;
    let llm = ChatCompletionsClient::new(cfg).unwrap();
    let done = llm
        .transcribe(b"abc", "a\"b\r\nX-Evil: 1.mp3", "audio/x\r\nEvil: 1")
        .await
        .unwrap();
    assert_eq!((done.value.as_str(), done.usage.total()), ("ok", 0));
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests[0].headers.get("authorization").is_none(),
        "no key configured"
    );
    let text = String::from_utf8_lossy(&requests[0].body).into_owned();
    assert!(text.contains("name=\"model\"\r\n\r\ndistil-large\r\n"), "{text}");
    assert!(text.contains("filename=\"a_b__X-Evil:_1.mp3\""), "{text}");
    assert!(text.contains("Content-Type: audio/x__Evil:_1\r\n"), "{text}");
    assert!(!text.contains("\r\nX-Evil"), "no header injection: {text}");
}

#[tokio::test]
async fn transcribe_errors_are_typed() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/stt/v1/audio/transcriptions"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let llm = ChatCompletionsClient::new(config(&server)).unwrap();
    assert_eq!(
        llm.transcribe(b"abc", "a.mp3", "audio/mpeg").await,
        Err(LlmError::Status { status: 500 })
    );
    assert!(matches!(
        llm.transcribe(b"", "a.mp3", "audio/mpeg").await,
        Err(LlmError::InvalidRequest(_))
    ));
    let too_big = vec![0u8; crawlx_model::llm::chat_completions::MAX_TRANSCRIBE_BYTES + 1];
    assert!(matches!(
        llm.transcribe(&too_big, "a.mp3", "audio/mpeg").await,
        Err(LlmError::InvalidRequest(_))
    ));
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "empty and oversize audio never reach the endpoint"
    );

    let bad_reply = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"words": []})))
        .mount(&bad_reply)
        .await;
    let llm = ChatCompletionsClient::new(config(&bad_reply)).unwrap();
    assert!(matches!(
        llm.transcribe(b"abc", "a.mp3", "audio/mpeg").await,
        Err(LlmError::InvalidOutput(_))
    ));
}

#[tokio::test]
async fn transcribe_without_endpoint_is_not_configured() {
    let llm = ChatCompletionsClient::new(LlmConfig::new("http://127.0.0.1:1/v1", "m")).unwrap();
    assert!(!llm.can_transcribe());
    assert_eq!(
        llm.transcribe(b"abc", "a.mp3", "audio/mpeg").await,
        Err(LlmError::NotConfigured)
    );
    let mut cfg = LlmConfig::new("http://127.0.0.1:1/v1", "m");
    cfg.transcribe_endpoint = Some("ftp://h".to_owned());
    assert!(matches!(
        ChatCompletionsClient::new(cfg),
        Err(LlmError::InvalidRequest(_))
    ));
    assert!(!Offline.can_transcribe());
    assert_eq!(
        Offline.transcribe(b"abc", "a.mp3", "audio/mpeg").await,
        Err(LlmError::NotConfigured)
    );
}

#[test]
fn transcribe_environment_variables_are_read_with_the_llm_config() {
    let cfg = LlmConfig::from_lookup(|k| match k {
        "CRAWLX_LLM_API_KEY" => Some("sk-x".to_owned()),
        "CRAWLX_TRANSCRIBE_ENDPOINT" => Some(" http://speech:8000/v1 ".to_owned()),
        "CRAWLX_TRANSCRIBE_MODEL" => Some("large-v3".to_owned()),
        _ => None,
    })
    .unwrap();
    assert_eq!(cfg.transcribe_endpoint.as_deref(), Some("http://speech:8000/v1"));
    assert_eq!(cfg.transcribe_model.as_deref(), Some("large-v3"));
    let plain = LlmConfig::from_lookup(|k| (k == "CRAWLX_LLM_API_KEY").then(|| "sk-x".to_owned())).unwrap();
    assert!(plain.transcribe_endpoint.is_none() && plain.transcribe_model.is_none());
    let llm = ChatCompletionsClient::new(plain).unwrap();
    assert!(!llm.can_transcribe());
}

#[tokio::test]
async fn mock_transcript_and_wrappers_forward() {
    let mock = MockLlm::scripted(vec![]);
    assert!(!mock.can_transcribe());
    assert_eq!(
        mock.transcribe(b"x", "a.mp3", "audio/mpeg").await,
        Err(LlmError::NotConfigured)
    );

    let mock = MockLlm::scripted(vec![]).with_transcript("the transcript");
    assert!(mock.can_transcribe());
    let done = mock.transcribe(b"bytes", "a.mp3", "audio/mpeg").await.unwrap();
    assert_eq!(done.value, "the transcript");
    assert!(done.usage.completion_tokens > 0);
    let calls = mock.transcriptions();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        (
            calls[0].file_name.as_str(),
            calls[0].content_type.as_str(),
            calls[0].audio.as_slice()
        ),
        ("a.mp3", "audio/mpeg", b"bytes".as_slice())
    );

    let failing = MockLlm::scripted(vec![]).with_transcript_error(LlmError::Status { status: 502 });
    assert!(failing.can_transcribe());
    assert_eq!(
        failing.transcribe(b"x", "a.mp3", "audio/mpeg").await,
        Err(LlmError::Status { status: 502 })
    );

    let shared = std::sync::Arc::new(MockLlm::scripted(vec![]).with_transcript("t"));
    assert!(shared.can_transcribe());
    assert_eq!(
        shared.transcribe(b"x", "a", "audio/mpeg").await.unwrap().value,
        "t"
    );

    let recording = RecordingLlm::passthrough(
        MockLlm::scripted(vec![]).with_transcript("rt"),
        CallCap::limited(1),
    );
    assert!(recording.can_transcribe());
    assert_eq!(
        recording.transcribe(b"x", "a", "audio/mpeg").await.unwrap().value,
        "rt"
    );
    assert!(
        matches!(
            recording.transcribe(b"x", "a", "audio/mpeg").await,
            Err(LlmError::CallCapExceeded { max: 1 })
        ),
        "the call cap counts transcriptions"
    );
}
