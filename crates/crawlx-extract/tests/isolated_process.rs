//! The real helper binary under real resource limits: frames round-trip byte-identically and a
//! hostile page ends the helper, not the test process.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::{Read, Write};
use std::process::{Command, Stdio};

use crawlx_extract::isolated::{
    encode_request_header, extract_local, parse_response_stream, Engine, HelperLimits, IsolatedError,
    IsolatedSecrets, LanguageStage, Reply, HELPER_SUBCOMMAND,
};
use crawlx_extract::ExtractOptions;
use url::Url;

const PAGE: &[u8] = b"<html lang=\"en\"><head><title>Fixture</title></head><body><article><h1>Heading</h1>\
    <p>A paragraph with a <a href=\"/more\">link</a> and enough words to be counted properly.</p></article></body></html>";

struct Outcome {
    stdout: Vec<u8>,
    status: std::process::ExitStatus,
}

fn run_helper(limits: &HelperLimits, header: &[u8], body: &[u8]) -> Outcome {
    let mut child = Command::new(env!("CARGO_BIN_EXE_crawlx-parser"))
        .arg(HELPER_SUBCOMMAND)
        .args(&limits.helper_args()[1..])
        .env_clear()
        // A coverage build writes its profile when the helper exits; the production file-size
        // limit (zero) must stay, so send that write to a device the limit does not govern.
        .env("LLVM_PROFILE_FILE", "/dev/null")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (header, body) = (header.to_vec(), body.to_vec());
    let writer = std::thread::spawn(move || {
        // The helper may stop reading once it died; that is judged by its status.
        let _ = stdin.write_all(&header).and_then(|()| stdin.write_all(&body));
    });
    let mut out = Vec::new();
    stdout.read_to_end(&mut out).unwrap();
    writer.join().unwrap();
    Outcome {
        stdout: out,
        status: child.wait().unwrap(),
    }
}

fn base() -> Url {
    Url::parse("https://fixture.test/page").unwrap()
}

#[test]
fn the_helper_binary_returns_the_in_process_document_under_its_limits() {
    let limits = HelperLimits::default();
    let options = ExtractOptions::default();
    let secrets = IsolatedSecrets::default();
    for engine in [Engine::Pipeline, Engine::Extractor] {
        let header = encode_request_header(
            PAGE.len(),
            &base(),
            &options,
            engine,
            &secrets,
            &LanguageStage::None,
        )
        .unwrap();
        let outcome = run_helper(&limits, &header, PAGE);
        assert!(outcome.status.success(), "{:?}", outcome.status);
        let Reply::Page { document, .. } = parse_response_stream(&outcome.stdout, &limits).unwrap() else {
            panic!("expected a page");
        };
        let local = extract_local(PAGE, &base(), &options, engine, &secrets).unwrap();
        assert_eq!(*document, local);
        assert_eq!(
            serde_json::to_vec(&*document).unwrap(),
            serde_json::to_vec(&local).unwrap()
        );
    }
}

#[test]
fn address_space_exhaustion_ends_only_the_helper() {
    // 64 MiB is the smallest accepted limit; the unclosed-formatting shape needs hundreds.
    let mut limits = HelperLimits::default();
    limits.address_space_bytes = 64 * 1024 * 1024;
    let unit = b"<a><b><i><em><strong><font><u><s><big><small><p>t";
    let hostile: Vec<u8> = unit.iter().copied().cycle().take(12 * 1024 * 1024).collect();
    let options = ExtractOptions {
        max_nodes: 100_000_000,
        ..ExtractOptions::default()
    };
    let header = encode_request_header(
        hostile.len(),
        &base(),
        &options,
        Engine::Extractor,
        &IsolatedSecrets::default(),
        &LanguageStage::None,
    )
    .unwrap();
    let outcome = run_helper(&limits, &header, &hostile);
    // The helper aborted on a failed allocation (a signal), or exited with a typed refusal; it
    // never produced a document, and this process is still here to say so.
    match parse_response_stream(&outcome.stdout, &limits) {
        Ok(_) => panic!("a 64 MiB helper cannot parse this page"),
        Err(IsolatedError::Protocol { .. } | IsolatedError::Rejected(_)) => {}
        Err(other) => panic!("unexpected {other:?}"),
    }
    assert!(!outcome.status.success() || outcome.stdout.len() < 4096);
}

#[test]
fn malformed_requests_get_a_typed_refusal_not_a_crash() {
    let limits = HelperLimits::default();
    let outcome = run_helper(&limits, b"not a frame at all", b"");
    assert!(outcome.status.success());
    assert!(matches!(
        parse_response_stream(&outcome.stdout, &limits).unwrap_err(),
        IsolatedError::Rejected(_)
    ));
}
