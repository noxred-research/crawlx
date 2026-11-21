//! The isolated parser helper of the real `crawlx` executable over page sizes up to the fetch cap.
//!
//! The helper is the `crawlx` binary itself, whose allocator reserves a 1 GiB address-space
//! arena up front. With the old 512 MiB `RLIMIT_AS` every page above the in-process size failed
//! (issue #71: "5/8 failures at 1 MiB"). These tests drive the real helper under the default
//! limits and under limits too small for it, and show that the outcome depends on the input size
//! and the configuration only: every repetition of a size gives the same answer, and the
//! failure is the typed helper-limit refusal, never a variable one.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use bytes::Bytes;
use crawlx_core::parser_memory::{Budgeted, ByteBudget};
use crawlx_extract::{ExtractError, ExtractOptions};
use crawlx_worker::isolated_parser::{
    HelperLauncher, IsolatedError, IsolatedParser, IsolatedParserConfig, PageRequest,
};
use crawlx_worker::CpuPool;
use tokio_util::sync::CancellationToken;
use url::Url;

const KIB: usize = 1024;
/// Page sizes in KiB: 0.5 MiB up to the 8 MiB default response cap.
const SIZES_KIB: [usize; 7] = [512, 1024, 1536, 2048, 4096, 6144, 8192];
const REPEATS: usize = 3;

fn page(kib: usize) -> Vec<u8> {
    let mut body =
        String::from("<!doctype html><html lang=\"en\"><head><title>Size probe</title></head><body><main>");
    let mut n = 0_u32;
    while body.len() < kib * KIB {
        n += 1;
        // a link in every tenth paragraph keeps the response frame a realistic size
        let link = if n.is_multiple_of(10) {
            format!(" <a href=\"/more/{n}\">link</a>")
        } else {
            String::new()
        };
        body.push_str(&format!(
            "<p>Paragraph {n} of the size probe with several words to count and parse.{link}</p>\n"
        ));
    }
    body.push_str("</main></body></html>");
    body.into_bytes()
}

fn parser(config: IsolatedParserConfig, budget: &Arc<ByteBudget>) -> IsolatedParser {
    let mut config = config;
    config.launcher = Some(HelperLauncher::new(env!("CARGO_BIN_EXE_crawlx")).unwrap());
    IsolatedParser::new(config)
        .unwrap()
        .with_parse_budget(Arc::clone(budget))
}

async fn parse(
    parser: &IsolatedParser,
    budget: &Arc<ByteBudget>,
    body: &[u8],
) -> Result<usize, IsolatedError> {
    let input = Budgeted::new(Bytes::copy_from_slice(body), budget.try_reserve(0).unwrap());
    let request = PageRequest::new(
        Url::parse("https://fixture.test/size").unwrap(),
        // what a crawl asks for: endpoint discovery, forms and the native content pipeline
        ExtractOptions {
            discover_endpoints: true,
            forms: true,
            content: Some(crawlx_core::extraction::ExtractionPolicyV1::default()),
            ..ExtractOptions::default()
        },
    );
    parser
        .extract_page(&CpuPool::default(), input, request, &CancellationToken::new())
        .await
        .map(|page| page.document.value().links.len())
}

/// Every size from 0.5 to 8 MiB parses under the default limits, every time, with the same
/// links found: no size is "sometimes".
#[tokio::test]
async fn every_size_up_to_the_response_cap_parses_under_the_default_limits_every_time() {
    // the production default parse budget (4 GiB)
    let budget = Arc::new(ByteBudget::new(4 << 30));
    let parser = parser(IsolatedParserConfig::default(), &budget);
    for kib in SIZES_KIB {
        let body = page(kib);
        let mut links = Vec::new();
        for _ in 0..REPEATS {
            links.push(
                parse(&parser, &budget, &body)
                    .await
                    .unwrap_or_else(|e| panic!("{kib} KiB: {e:?}")),
            );
        }
        assert!(links[0] > 0, "{kib} KiB");
        assert!(links.iter().all(|n| *n == links[0]), "{kib} KiB: {links:?}");
    }
}

/// Limits the helper cannot work under fail the same way on every repetition, with the typed
/// helper-limit refusal the URL plane reports as `parser_limit_exceeded`.
#[tokio::test]
async fn a_helper_without_room_fails_the_same_typed_way_every_time() {
    let budget = Arc::new(ByteBudget::new(4 << 30));
    let mut config = IsolatedParserConfig::default();
    config.in_process_max_input = 0;
    // below the allocator's own 1 GiB reservation, whatever the input: the same for any size
    config.limits.address_space_bytes = 128 * 1024 * 1024;
    let parser = parser(config, &budget);
    for kib in [512, 1024, 4096] {
        let body = page(kib);
        let mut outcomes = Vec::new();
        for _ in 0..REPEATS {
            let error = parse(&parser, &budget, &body)
                .await
                .expect_err("no room for the helper");
            assert!(error.is_resource_exhausted(), "{kib} KiB: {error:?}");
            match error.into_extract_error() {
                ExtractError::ParseMemory(refused) => {
                    assert!(refused.is_helper_limit(), "{kib} KiB: {refused:?}");
                    outcomes.push(refused);
                }
                other => panic!("{kib} KiB: {other:?}"),
            }
        }
        assert!(outcomes.iter().all(|o| *o == outcomes[0]), "{kib} KiB");
    }
}
