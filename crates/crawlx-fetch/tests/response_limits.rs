//! Body limits, content codings, charset records, HTTP-error status sets, `HEAD` preflight
//! and validator revalidation of the fetch plane, against in-process servers.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod common;

use async_compression::tokio::write::{BrotliEncoder, GzipEncoder};
use common::{allow_private_policy, fast_config, fetcher, url, LOOPBACK};
use crawlx_fetch::{
    interpret_revalidation, BodyLimitKind, CharsetSource, FetchError, FetchOptions, HeadPreflight,
    HttpErrorStatuses, OversizePolicy, PreflightRefusal, ResponseDeclaration, Revalidation, StaticResolver,
    Validators,
};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

fn resolver() -> Arc<StaticResolver> {
    let r = StaticResolver::new();
    r.set("pub.test", [LOOPBACK]);
    Arc::new(r)
}

async fn gzip(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = GzipEncoder::new(&mut out);
    e.write_all(plain).await.unwrap();
    e.shutdown().await.unwrap();
    out
}

async fn brotli(plain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut e = BrotliEncoder::new(&mut out);
    e.write_all(plain).await.unwrap();
    e.shutdown().await.unwrap();
    out
}

async fn serve(path_: &str, template: ResponseTemplate) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(path(path_))
        .respond_with(template)
        .mount(&server)
        .await;
    server
}

#[tokio::test]
async fn encoded_bodies_are_decoded_with_independent_wire_and_decoded_records() {
    let plain = b"<html><body>hello compressed world</body></html> ".repeat(400);
    for (coding, wire) in [("gzip", gzip(&plain).await), ("br", brotli(&plain).await)] {
        let server = serve(
            "/doc",
            ResponseTemplate::new(200)
                .insert_header("content-encoding", coding)
                .insert_header("content-type", "text/html; charset=utf-8")
                .set_body_bytes(wire.clone()),
        )
        .await;
        let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
        let resp = f
            .fetch(&url("pub.test", &server, "/doc"), &FetchOptions::default())
            .await
            .unwrap();
        assert_eq!(resp.body.as_ref(), plain.as_slice(), "{coding}");
        assert!(!resp.truncated);
        assert!(
            resp.headers.get("content-encoding").is_none(),
            "decoded body keeps no coding header"
        );
        let evidence = resp.evidence().unwrap();
        assert!(evidence.body.decoded);
        assert_eq!(evidence.body.content_encoding, [coding]);
        assert_eq!(evidence.body.wire_bytes, u64::try_from(wire.len()).unwrap());
        assert_eq!(evidence.body.decoded_bytes, u64::try_from(plain.len()).unwrap());
        assert_eq!(
            evidence.body.wire_digest.as_deref(),
            Some(blake3::hash(&wire).to_hex().as_str()),
            "the original bytes stay identifiable"
        );
    }
}

#[tokio::test]
async fn a_decompression_bomb_is_refused_without_returning_any_of_it() {
    let bomb = gzip(&vec![0u8; 64 * 1024 * 1024]).await;
    assert!(bomb.len() < 200_000);
    let server = serve(
        "/bomb",
        ResponseTemplate::new(200)
            .insert_header("content-encoding", "gzip")
            .set_body_bytes(bomb),
    )
    .await;
    let mut cfg = fast_config();
    cfg.max_expansion_ratio = 50;
    let f = fetcher(cfg, allow_private_policy(&server), resolver());
    let error = f
        .fetch(&url("pub.test", &server, "/bomb"), &FetchOptions::default())
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            FetchError::BodyLimit {
                kind: BodyLimitKind::ExpansionRatio,
                limit: 50
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.code(), "body_limit");
}

#[tokio::test]
async fn the_decoded_cap_marks_a_decoded_body_partial_and_holds_at_the_cap() {
    let server = serve(
        "/big",
        ResponseTemplate::new(200)
            .insert_header("content-encoding", "gzip")
            .set_body_bytes(gzip(&vec![b'a'; 2 * 1024 * 1024]).await),
    )
    .await;
    let mut cfg = fast_config();
    cfg.max_expansion_ratio = 1 << 20;
    let f = fetcher(cfg, allow_private_policy(&server), resolver());
    let opts = FetchOptions {
        max_body_bytes: Some(4096),
        ..FetchOptions::default()
    };
    let resp = f.fetch(&url("pub.test", &server, "/big"), &opts).await.unwrap();
    assert!(resp.truncated);
    assert_eq!(resp.body.len(), 4096);
    assert_eq!(resp.evidence().unwrap().body.limit, Some(BodyLimitKind::Decoded));
}

#[tokio::test]
async fn the_wire_cap_is_independent_of_the_decoded_cap() {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    let noise: Vec<u8> = (0..300_000)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state.to_le_bytes()[0]
        })
        .collect();
    let server = serve(
        "/noise",
        ResponseTemplate::new(200)
            .insert_header("content-encoding", "gzip")
            .set_body_bytes(gzip(&noise).await),
    )
    .await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let opts = FetchOptions {
        max_wire_bytes: Some(20_000),
        ..FetchOptions::default()
    };
    let resp = f.fetch(&url("pub.test", &server, "/noise"), &opts).await.unwrap();
    assert!(resp.truncated);
    let evidence = resp.evidence().unwrap();
    assert_eq!(evidence.body.limit, Some(BodyLimitKind::Wire));
    assert_eq!(evidence.body.wire_bytes, 20_000);
    assert!(resp.body.len() < 300_000);
}

#[tokio::test]
async fn a_corrupt_encoded_body_is_a_decode_error_not_a_short_success() {
    let mut wire = gzip(&b"complete document ".repeat(500)).await;
    wire.truncate(wire.len() - 8);
    let server = serve(
        "/cut",
        ResponseTemplate::new(200)
            .insert_header("content-encoding", "gzip")
            .set_body_bytes(wire),
    )
    .await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let error = f
        .fetch(&url("pub.test", &server, "/cut"), &FetchOptions::default())
        .await
        .unwrap_err();
    assert_eq!(error.code(), "body_decode");
}

#[tokio::test]
async fn an_oversize_declared_length_is_refused_before_the_body_is_read() {
    let server = serve(
        "/large",
        ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 20_000]),
    )
    .await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let opts = FetchOptions {
        max_body_bytes: Some(1024),
        oversize: OversizePolicy::Reject,
        ..FetchOptions::default()
    };
    let error = f
        .fetch(&url("pub.test", &server, "/large"), &opts)
        .await
        .unwrap_err();
    assert!(
        matches!(
            error,
            FetchError::BodyLimit {
                kind: BodyLimitKind::Declared,
                limit: 1024
            }
        ),
        "{error:?}"
    );
    // The default policy still returns the capped prefix with an explicit partial marker.
    let opts = FetchOptions {
        max_body_bytes: Some(1024),
        ..FetchOptions::default()
    };
    let resp = f.fetch(&url("pub.test", &server, "/large"), &opts).await.unwrap();
    assert!(resp.truncated);
    assert_eq!(resp.body.len(), 1024);
}

#[tokio::test]
async fn zero_is_a_zero_byte_cap_never_unlimited() {
    let server = serve("/page", ResponseTemplate::new(200).set_body_string("some body")).await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let opts = FetchOptions {
        max_body_bytes: Some(0),
        ..FetchOptions::default()
    };
    let resp = f.fetch(&url("pub.test", &server, "/page"), &opts).await.unwrap();
    assert!(resp.body.is_empty());
    assert!(resp.truncated);
}

const LATIN1_PAGE: &[u8] = b"<html><head><title>caf\xe9</title></head><body>na\xefve</body></html>";

#[tokio::test]
async fn a_wrong_charset_decodes_deterministically_and_an_override_repairs_it() {
    let server = serve(
        "/latin1",
        ResponseTemplate::new(200).set_body_raw(LATIN1_PAGE, "text/html; charset=utf-8"),
    )
    .await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let target = url("pub.test", &server, "/latin1");

    let resp = f.fetch(&target, &FetchOptions::default()).await.unwrap();
    let charset = resp.evidence().unwrap().charset.unwrap();
    assert_eq!(
        (charset.label.as_str(), charset.source),
        ("utf-8", CharsetSource::Header)
    );
    assert_eq!(
        resp.text().unwrap_err().to_string(),
        "body is not valid utf-8 at byte 22"
    );
    assert!(resp.text_lossy().1, "lossy decoding reports its replacements");

    let opts = FetchOptions {
        declaration: ResponseDeclaration::default().with_charset("iso-8859-1"),
        ..FetchOptions::default()
    };
    let resp = f.fetch(&target, &opts).await.unwrap();
    let charset = resp.evidence().unwrap().charset.unwrap();
    assert_eq!(
        (charset.label.as_str(), charset.source),
        ("windows-1252", CharsetSource::Override)
    );
    let text = resp.text().unwrap();
    assert!(text.contains("café") && text.contains("naïve"));
    assert!(resp
        .content_type
        .as_deref()
        .unwrap()
        .contains("charset=iso-8859-1"));
    assert_eq!(
        resp.evidence().unwrap().wire_content_type.as_deref(),
        Some("text/html; charset=utf-8"),
        "the sender's value is kept"
    );
}

#[tokio::test]
async fn a_mime_override_replaces_the_effective_type_and_unknown_labels_are_refused_up_front() {
    let server = serve(
        "/feed",
        ResponseTemplate::new(200).set_body_raw("<rss/>", "application/octet-stream"),
    )
    .await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let opts = FetchOptions {
        declaration: ResponseDeclaration::default().with_content_type("application/rss+xml"),
        ..FetchOptions::default()
    };
    let resp = f.fetch(&url("pub.test", &server, "/feed"), &opts).await.unwrap();
    assert_eq!(resp.content_type.as_deref(), Some("application/rss+xml"));

    let bad = FetchOptions {
        declaration: ResponseDeclaration::default().with_charset("klingon"),
        ..FetchOptions::default()
    };
    let error = f
        .fetch(&url("pub.test", &server, "/feed"), &bad)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "invalid_declaration");
    assert!(
        server.received_requests().await.unwrap().len() == 1,
        "no request for a bad declaration"
    );
}

#[tokio::test]
async fn denied_statuses_are_refused_and_allowed_throttles_never_bypass_the_cooldown() {
    let server = MockServer::start().await;
    Mock::given(path("/gone"))
        .respond_with(ResponseTemplate::new(403))
        .mount(&server)
        .await;
    Mock::given(path("/slow"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "1"))
        .mount(&server)
        .await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let statuses = HttpErrorStatuses::default().denying([403]).allowing([429]);
    let opts = FetchOptions {
        declaration: ResponseDeclaration::default().with_statuses(statuses),
        ..FetchOptions::default()
    };

    let error = f
        .fetch(&url("pub.test", &server, "/gone"), &opts)
        .await
        .unwrap_err();
    assert!(
        matches!(error, FetchError::StatusDenied { status: 403 }),
        "{error:?}"
    );

    // The allowed 429 is delivered as a response and not retried ...
    let resp = f.fetch(&url("pub.test", &server, "/slow"), &opts).await.unwrap();
    assert_eq!(resp.status.as_u16(), 429);
    assert_eq!(resp.attempts, 1);
    // ... but it still reached the governor: the next start on the origin waits it out.
    let started = Instant::now();
    f.fetch(&url("pub.test", &server, "/slow"), &opts).await.unwrap();
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "second start after {:?}",
        started.elapsed()
    );
}

#[tokio::test]
async fn head_preflight_is_a_charged_request_and_a_refusal_prevents_the_get() {
    let server = MockServer::start().await;
    Mock::given(method("HEAD"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(200).insert_header("content-type", "text/html"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/ok"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("body", "text/html"))
        .mount(&server)
        .await;
    Mock::given(method("HEAD"))
        .and(path("/image"))
        .respond_with(ResponseTemplate::new(200).insert_header("content-type", "image/png"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/image"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("png", "image/png"))
        .mount(&server)
        .await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let preflight = HeadPreflight::new().with_content_types(["text/html"]);

    // Each of the HEAD and the GET spends one unit of the shared request allowance.
    let allowance = Arc::new(AtomicU32::new(2));
    let opts = FetchOptions {
        preflight: Some(preflight.clone()),
        request_allowance: Some(Arc::clone(&allowance)),
        ..FetchOptions::default()
    };
    let resp = f.fetch(&url("pub.test", &server, "/ok"), &opts).await.unwrap();
    assert_eq!(resp.body.as_ref(), b"body");
    assert_eq!(resp.attempts, 2);
    assert_eq!(allowance.load(Ordering::Acquire), 0);
    let seen: Vec<_> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.method.to_string())
        .collect();
    assert_eq!(seen, ["HEAD", "GET"]);

    // One unit is enough for the HEAD only: the GET is denied before any I/O.
    server.reset().await;
    Mock::given(path("/ok"))
        .respond_with(ResponseTemplate::new(200).insert_header("content-type", "text/html"))
        .mount(&server)
        .await;
    let tight = FetchOptions {
        preflight: Some(preflight.clone()),
        request_allowance: Some(Arc::new(AtomicU32::new(1))),
        ..FetchOptions::default()
    };
    let error = f
        .fetch(&url("pub.test", &server, "/ok"), &tight)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::AcquisitionAllowance), "{error:?}");
    let seen: Vec<_> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.method.to_string())
        .collect();
    assert_eq!(seen, ["HEAD"]);

    // A refused preflight never sends the GET.
    server.reset().await;
    Mock::given(method("HEAD"))
        .respond_with(ResponseTemplate::new(200).insert_header("content-type", "image/png"))
        .mount(&server)
        .await;
    let opts = FetchOptions {
        preflight: Some(preflight),
        ..FetchOptions::default()
    };
    let error = f
        .fetch(&url("pub.test", &server, "/image"), &opts)
        .await
        .unwrap_err();
    assert!(
        matches!(&error, FetchError::PreflightRefused { refusal: PreflightRefusal::ContentType(t) } if t == "image/png"),
        "{error:?}"
    );
    let seen: Vec<_> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.method.to_string())
        .collect();
    assert_eq!(seen, ["HEAD"]);
}

#[tokio::test]
async fn a_redirecting_head_is_checked_on_every_hop_before_the_get_starts() {
    let server = MockServer::start().await;
    Mock::given(method("HEAD"))
        .and(path("/start"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", "http://169.254.169.254/latest"))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let opts = FetchOptions {
        preflight: Some(HeadPreflight::new()),
        ..FetchOptions::default()
    };
    let error = f
        .fetch(&url("pub.test", &server, "/start"), &opts)
        .await
        .unwrap_err();
    assert_eq!(error.code(), "egress_denied");
    let seen: Vec<_> = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .map(|r| r.method.to_string())
        .collect();
    assert_eq!(seen, ["HEAD"], "no GET after a denied HEAD redirect");
}

#[tokio::test]
async fn a_304_confirms_the_stored_copy_only_for_the_etag_that_was_sent() {
    let server = MockServer::start().await;
    Mock::given(path("/same"))
        .respond_with(ResponseTemplate::new(304).insert_header("etag", "\"v1\""))
        .mount(&server)
        .await;
    Mock::given(path("/other"))
        .respond_with(ResponseTemplate::new(304).insert_header("etag", "\"v9\""))
        .mount(&server)
        .await;
    let f = fetcher(fast_config(), allow_private_policy(&server), resolver());
    let sent = Validators {
        etag: Some("\"v1\"".to_owned()),
        last_modified: None,
    };
    for (target, expected) in [
        ("/same", Revalidation::Reusable),
        ("/other", Revalidation::Unconfirmed),
    ] {
        let opts = FetchOptions {
            validators: Some(sent.clone()),
            ..FetchOptions::default()
        };
        let resp = f.fetch(&url("pub.test", &server, target), &opts).await.unwrap();
        assert!(resp.not_modified());
        assert_eq!(
            interpret_revalidation(&sent, resp.status.as_u16(), &resp.headers),
            expected,
            "{target}"
        );
    }
}
