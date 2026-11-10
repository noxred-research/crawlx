#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! The compat `audio` and `video` formats of the compat facade, run end to end through a REAL
//! worker lease loop (see `scrape_rig`): the worker downloads the media a page is or references
//! into the artifact store, the API answers with a URL of the stored file and, when the LLM
//! endpoint transcribes, the transcript. The fixture media routes are merged into the rig's site
//! (`RigConfig::site_routes`).
mod common;
#[path = "common/scrape_rig.rs"]
mod scrape_rig;

use axum::http::{header, HeaderMap, Method, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use bytes::Bytes;
use crawlx_model::llm::{LlmError, LlmExtractor, MockLlm};
use scrape_rig::{Rig, RigConfig};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Duration;

const V2: &str = "/compat/v2";

/// Deterministic payload of `len` bytes after `magic`.
fn payload(magic: &[u8], len: usize) -> Vec<u8> {
    let mut bytes = magic.to_vec();
    bytes.extend((0..len).map(|i| u8::try_from(i % 251).unwrap()));
    bytes
}

fn mp3() -> Vec<u8> {
    payload(b"ID3\x03\x00\x00\x00\x00\x00\x00", 4_096)
}

fn mp4() -> Vec<u8> {
    payload(b"\x00\x00\x00\x18ftypmp42", 6_000)
}

fn page(title: &str, markup: &str) -> axum::response::Response {
    (
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        format!(
            "<!doctype html><html><head><title>{title}</title></head><body><main><h1>{title}</h1>\
             <p>Words of {title}.</p></main>{markup}</body></html>"
        ),
    )
        .into_response()
}

/// The media fixtures: an episode page with an MP3 source, a watch page with `og:video` and an
/// audio link, and a page without media.
fn media_routes() -> Router {
    Router::new()
        .route(
            "/media/ep.mp3",
            get(|| async { ([(header::CONTENT_TYPE, "audio/mpeg")], mp3()) }),
        )
        .route(
            "/media/clip.mp4",
            get(|| async { ([(header::CONTENT_TYPE, "video/mp4")], mp4()) }),
        )
        .route(
            "/podcast",
            get(|| async {
                page(
                    "Podcast",
                    r#"<audio controls><source src="/media/ep.mp3" type="audio/mpeg"></audio>"#,
                )
            }),
        )
        .route(
            "/watch",
            get(|| async {
                page(
                    "Watch",
                    r#"<meta property="og:video" content="/media/clip.mp4">
                       <meta property="og:video:type" content="video/mp4">
                       <a href="/media/ep.mp3">download the audio</a>"#,
                )
            }),
        )
        .route("/silent", get(|| async { page("Silent", "") }))
}

async fn start(llm: Option<Arc<MockLlm>>) -> Rig {
    Rig::start(RigConfig {
        llm: llm.map(|l| l as Arc<dyn LlmExtractor>),
        site_routes: Some(media_routes()),
        ..RigConfig::default()
    })
    .await
}

/// `POST /v2/scrape` expecting `200 {success:true}`; returns the whole body.
async fn scrape(rig: &Rig, body: Value) -> Value {
    let (s, _, v) = rig.env.post(&format!("{V2}/scrape"), &body).await;
    assert_eq!(s, StatusCode::OK, "{v}");
    assert_eq!(v["success"], true, "{v}");
    v
}

/// Download the file a `data.audio` / `data.video` URL names: the API artifact endpoint with the
/// key (this rig's store cannot presign).
async fn download(rig: &Rig, url: &str) -> (HeaderMap, Bytes) {
    assert!(
        url.contains("/v1/crawls/") && url.contains("/artifacts/"),
        "an artifact URL: {url}"
    );
    let path = url.split_once("/v1/").map(|(_, p)| format!("/v1/{p}")).unwrap();
    let (status, headers, bytes) = rig
        .env
        .send(Method::GET, &path, Some(&rig.env.key), &[], None)
        .await;
    assert_eq!(status, StatusCode::OK);
    (headers, bytes)
}

fn transcribing(text: &str) -> Arc<MockLlm> {
    Arc::new(MockLlm::scripted(vec![]).with_transcript(text))
}

#[tokio::test]
async fn audio_returns_a_url_of_the_exact_bytes_and_the_transcript() {
    let llm = transcribing("Welcome to the show.");
    let rig = start(Some(Arc::clone(&llm))).await;
    let body = scrape(
        &rig,
        json!({ "url": rig.url("/podcast"), "formats": ["markdown", "audio"] }),
    )
    .await;
    let data = &body["data"];
    assert!(data["markdown"].as_str().unwrap().contains("Words of Podcast"));
    let (headers, bytes) = download(&rig, data["audio"].as_str().expect("data.audio is a URL string")).await;
    assert_eq!(
        bytes.as_ref(),
        mp3().as_slice(),
        "the exact bytes the site served"
    );
    assert_eq!(headers[header::CONTENT_TYPE], "audio/mpeg");
    assert_eq!(headers[header::CONTENT_LENGTH], "4106");
    assert_eq!(data["transcript"], "Welcome to the show.");
    assert!(
        data.get("video").is_none() && data.get("warning").is_none(),
        "{data}"
    );
    assert_eq!(data["metadata"]["creditsUsed"], 5, "1 + 4 for audio: {data}");
    let calls = llm.transcriptions();
    assert_eq!(calls.len(), 1);
    assert_eq!(
        (calls[0].file_name.as_str(), calls[0].content_type.as_str()),
        ("ep.mp3", "audio/mpeg")
    );
    assert_eq!(calls[0].audio, mp3());
    rig.stop().await;
}

#[tokio::test]
async fn video_and_audio_are_both_returned_and_both_billed() {
    let rig = start(Some(transcribing("clip and episode"))).await;
    let body = scrape(
        &rig,
        json!({ "url": rig.url("/watch"), "formats": ["video", "audio"] }),
    )
    .await;
    let data = &body["data"];
    let (headers, video) = download(&rig, data["video"].as_str().unwrap()).await;
    assert_eq!(video.as_ref(), mp4().as_slice());
    assert_eq!(headers[header::CONTENT_TYPE], "video/mp4");
    let (headers, audio) = download(&rig, data["audio"].as_str().unwrap()).await;
    assert_eq!(audio.as_ref(), mp3().as_slice());
    assert_eq!(headers[header::CONTENT_TYPE], "audio/mpeg");
    assert_eq!(data["transcript"], "clip and episode");
    assert_eq!(data["metadata"]["creditsUsed"], 9, "1 + 4 + 4: {data}");
    assert!(
        data.get("markdown").is_none(),
        "only the media formats were asked for"
    );
    rig.stop().await;
}

#[tokio::test]
async fn a_direct_media_url_is_the_file() {
    let rig = start(None).await;
    let body = scrape(
        &rig,
        json!({ "url": rig.url("/media/clip.mp4"), "formats": ["video"] }),
    )
    .await;
    let data = &body["data"];
    let (_, video) = download(&rig, data["video"].as_str().unwrap()).await;
    assert_eq!(video.as_ref(), mp4().as_slice());
    assert_eq!(data["metadata"]["statusCode"], 200);
    assert_eq!(data["metadata"]["contentType"], "video/mp4");
    assert_eq!(data["metadata"]["creditsUsed"], 5);
    rig.stop().await;
}

#[tokio::test]
async fn without_a_transcribing_llm_the_response_warns_and_has_no_transcript() {
    let rig = start(None).await;
    let body = scrape(&rig, json!({ "url": rig.url("/podcast"), "formats": ["audio"] })).await;
    let data = &body["data"];
    assert!(data["audio"].is_string());
    assert!(data.get("transcript").is_none(), "{data}");
    assert!(
        data["warning"]
            .as_str()
            .unwrap()
            .starts_with("transcription_unavailable:"),
        "{data}"
    );
    assert_eq!(data["metadata"]["creditsUsed"], 5, "the audio was delivered");
    rig.stop().await;

    // an LLM that cannot transcribe is the same; one that fails keeps the audio
    let rig = start(Some(Arc::new(
        MockLlm::scripted(vec![]).with_transcript_error(LlmError::Status { status: 502 }),
    )))
    .await;
    let body = scrape(&rig, json!({ "url": rig.url("/podcast"), "formats": ["audio"] })).await;
    let data = &body["data"];
    assert!(data["audio"].is_string() && data.get("transcript").is_none());
    assert_eq!(
        data["warning"],
        "transcription_failed: LLM endpoint returned HTTP 502"
    );
    rig.stop().await;
}

#[tokio::test]
async fn a_page_without_media_succeeds_with_a_warning_and_is_not_billed_for_it() {
    let rig = start(Some(transcribing("unused"))).await;
    let body = scrape(
        &rig,
        json!({ "url": rig.url("/silent"), "formats": ["markdown", "audio", "video"] }),
    )
    .await;
    let data = &body["data"];
    assert!(data["markdown"].as_str().unwrap().contains("Words of Silent"));
    assert!(data.get("audio").is_none() && data.get("video").is_none() && data.get("transcript").is_none());
    let warning = data["warning"].as_str().unwrap();
    assert!(
        warning.contains("audio_not_found:") && warning.contains("video_not_found:"),
        "{warning}"
    );
    assert_eq!(
        data["metadata"]["creditsUsed"], 1,
        "nothing delivered, nothing billed: {data}"
    );
    rig.stop().await;
}

#[tokio::test]
async fn crawl_pages_carry_the_media_formats() {
    let rig = start(Some(transcribing("crawled words"))).await;
    let (s, _, v) = rig
        .env
        .post(
            &format!("{V2}/crawl"),
            &json!({
                "url": rig.url("/podcast"),
                "limit": 1,
                "scrapeOptions": { "formats": ["markdown", "audio"] },
            }),
        )
        .await;
    assert_eq!(s, StatusCode::OK, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    let mut status = Value::Null;
    for _ in 0..600 {
        let (_, _, v) = rig.env.get(&format!("{V2}/crawl/{id}?limit=100")).await;
        if v["status"] != "scraping" {
            status = v;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(status["status"], "completed", "{status}");
    assert_eq!(status["creditsUsed"], 5, "{status}");
    let doc = &status["data"][0];
    let (_, audio) = download(&rig, doc["audio"].as_str().expect("audio on the crawled page")).await;
    assert_eq!(audio.as_ref(), mp3().as_slice());
    assert_eq!(doc["transcript"], "crawled words");
    rig.stop().await;
}
