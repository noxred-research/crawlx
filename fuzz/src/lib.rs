//! Fuzz target bodies. Each function takes raw bytes and must never panic;
//! the invariants in the plan's table are asserted here so a violation is a crash the fuzzer
//! records. The `fuzz_targets/*.rs` binaries are thin wrappers: libFuzzer entry points under
//! `cfg(fuzzing)`, stdin readers otherwise (crash replay on stable).

use crawlx_browser::cdp::{decode_frame, CdpFrame, FrameDecodeError, MAX_FRAME_BYTES};
use crawlx_core::config::CreateCrawl;
use crawlx_core::gates::GateStatus;
use crawlx_extract::{ExtractOptions, Extractor};
use crawlx_model::llm::{parse_and_validate, PlanContext, PlanStep};
use crawlx_model::provenance::{Provenance, Untrusted};
use crawlx_policy::egress::classify_ip;
use crawlx_policy::{DenyRule, EgressPolicy, RobotsTxt};
use crawlx_url::{
    CanonicalizeOptions, Canonicalizer, ParamClassifier, ParamObservation, PathFilter, SitemapParser,
};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::net::{IpAddr, Ipv4Addr};
use url::Url;

/// Runs `target` once over everything on stdin (the non-libFuzzer entry point).
pub fn run_stdin(target: fn(&[u8])) {
    let mut data = Vec::new();
    if std::io::stdin().read_to_end(&mut data).is_ok() {
        target(&data);
    }
}

fn base() -> Url {
    // Infallible: a literal.
    Url::parse("https://example.com/dir/page").unwrap_or_else(|_| unreachable!())
}

/// `fuzz_url_parse`: no panic; the canonical key is stable (idempotent); the result, when
/// re-canonicalized, keeps its key.
pub fn url_canonicalize(data: &[u8]) {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let base = base();
    let opts = CanonicalizeOptions::default();
    let Ok(first) = Canonicalizer::canonicalize(raw, &base, &opts) else {
        return;
    };
    let Ok(again) = Canonicalizer::canonicalize(first.url.as_str(), &base, &opts) else {
        panic!("canonical output `{}` does not re-canonicalize", first.url);
    };
    assert_eq!(first.key, again.key, "canonical key not idempotent for `{raw}`");
    assert_eq!(first.url, again.url, "canonical url not idempotent for `{raw}`");
    // A canonical URL always has a host; the authority was never misparsed into a path.
    assert!(
        first.url.host_str().is_some(),
        "canonical url without host for `{raw}`"
    );
}

/// `param_classify`: classification is total and deterministic for any name/value, and
/// session observations never panic however many sessions or values are fed.
pub fn param_classify(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let (name, value) = text.split_once('=').unwrap_or((text, ""));
    let route = crawlx_core::url::RouteTemplate("/r".to_owned());
    let classifier = ParamClassifier::new(&BTreeMap::new());
    let obs = ParamObservation {
        route: &route,
        name,
        value,
    };
    let a = classifier.classify(&obs);
    for (i, chunk) in value.as_bytes().chunks(8).enumerate() {
        let v = String::from_utf8_lossy(chunk);
        classifier.observe(name, &v, i as u64 % 3);
    }
    let b = classifier.classify(&obs);
    // Observations may only move a parameter towards `Session`; a built-in or override class
    // never changes.
    if a != crawlx_core::url::ParamClass::Session && b != a {
        assert_eq!(
            b,
            crawlx_core::url::ParamClass::Session,
            "classification drifted {a:?} -> {b:?}"
        );
    }
    let c = classifier.classify(&obs);
    assert_eq!(b, c, "classification not deterministic");
}

/// `fuzz_robots`: no panic; parsing is total; every decision is total.
pub fn robots_parse(data: &[u8]) {
    let robots = RobotsTxt::parse(data);
    let _ = robots.evaluate("crawlx", "/some/path?x=1");
    let _ = robots.evaluate("*", "/");
    let _ = robots.crawl_delay("crawlx");
    let _ = robots.sitemaps().len();
}

/// `fuzz_sitemap`: no panic; entry and depth caps hold.
pub fn sitemap_parse(data: &[u8]) {
    if let Ok(doc) = SitemapParser::parse(data) {
        assert!(doc.urls.len() <= crawlx_url::MAX_URLS, "entry cap exceeded");
    }
    if let Ok(doc) = SitemapParser::parse_limited(data, 16) {
        assert!(doc.urls.len() <= 16, "parse_limited cap exceeded");
    }
}

/// `fuzz_html_extract`: no panic; output is bounded by the input (≤ 4× input,
/// plus a fixed allowance for the frontmatter of tiny documents); every link is absolute.
pub fn html_extract(data: &[u8]) {
    let base = base();
    let opts = ExtractOptions::default();
    let Ok(doc) = Extractor::extract_bytes(data, &base, &opts) else {
        return;
    };
    let budget = data.len().saturating_mul(4).saturating_add(4096);
    assert!(
        doc.markdown.len() <= budget,
        "markdown {} > 4x input {}",
        doc.markdown.len(),
        data.len()
    );
    assert!(
        doc.text.len() <= budget,
        "text {} > 4x input {}",
        doc.text.len(),
        data.len()
    );
    for link in &doc.links {
        assert!(link.url.host_str().is_some(), "link without host: {}", link.url);
        assert!(
            link.url.fragment().is_none(),
            "fragment kept on link: {}",
            link.url
        );
    }
}

/// `fuzz_api_request`-style target for the planner DSL: parsing and validating arbitrary
/// model output never panics and never accepts a step outside the candidate list.
pub fn action_plan_validate(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let candidates_len = usize::from(data.first().copied().unwrap_or(0) % 8);
    let Ok(raw) = Untrusted::new(Provenance::ModelOutput, text.to_owned()) else {
        return;
    };
    let routes = ["/known".to_owned()];
    let ctx = PlanContext {
        candidates_len,
        known_routes: Some(&routes),
    };
    if let Ok(plan) = parse_and_validate(&raw, &ctx) {
        for step in plan.steps() {
            let target = match step {
                PlanStep::Click { target }
                | PlanStep::Type { target, .. }
                | PlanStep::Select { target, .. }
                | PlanStep::Hover { target } => Some(*target),
                PlanStep::Press { target, .. } => *target,
                PlanStep::NavigateKnownRoute { .. } | PlanStep::Expect { .. } => None,
            };
            if let Some(t) = target {
                assert!(
                    t.resolve(candidates_len).is_some(),
                    "validated step targets outside the shortlist"
                );
            }
        }
    }
    let _ = parse_and_validate(
        &raw,
        &PlanContext {
            candidates_len,
            known_routes: None,
        },
    );
}

/// `scope_pattern_compile`: compiling user-supplied include/exclude patterns never panics,
/// respects the size/nesting limits, and a compiled filter answers for any path.
pub fn scope_pattern_compile(data: &[u8]) {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut lines = text.lines().map(str::to_owned);
    let include: Vec<String> = lines.by_ref().take(4).collect();
    let exclude: Vec<String> = lines.take(4).collect();
    let Ok(filter) = PathFilter::new(&include, &exclude) else {
        return;
    };
    for path in ["/", "/docs/a", text] {
        let _ = filter.matches_include(path);
        let _ = filter.matches_exclude(path);
        let _ = filter.first_exclude(path);
    }
}

/// Reference deny decision from `std::net` alone: the ranges every SSRF guard must refuse.
/// The policy's table is a superset (CGNAT, metadata, benchmarking, reserved, ...), so the
/// invariant is one-directional: std-denied ⇒ policy-denied.
fn std_denied_v4(ip: Ipv4Addr) -> bool {
    ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_documentation()
}

fn std_denied(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => std_denied_v4(v4),
        IpAddr::V6(v6) => {
            v6.is_unspecified()
                || v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
                || v6.to_ipv4_mapped().is_some_and(std_denied_v4)
        }
    }
}

/// Metadata and link-local are never exemptable, whatever the authorization record says.
fn never_exempt(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            v6.is_unicast_link_local() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_link_local())
        }
    }
}

/// `fuzz_ssrf_ip_forms`: the egress guard never panics on any host string; for every
/// literal std parses, the deny decision agrees with the std reference; decimal/octal/hex,
/// IPv4-mapped, bracketed, trailing-dot and userinfo forms are never allowed when the
/// canonical address is denied.
pub fn ssrf_ip_forms(data: &[u8]) {
    let Ok(raw) = std::str::from_utf8(data) else {
        return;
    };
    let strict = EgressPolicy::default();
    let lenient = EgressPolicy::new(true);
    let host_decision = strict.check_host(raw);
    assert_eq!(
        host_decision,
        strict.check_host(raw),
        "check_host not deterministic for {raw:?}"
    );
    let _ = lenient.check_host(raw);

    // Reference 1: the string itself is an IP literal (optionally bracketed / trailing dot).
    let trimmed = raw.trim().trim_end_matches('.');
    let bare = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        check_literal(&strict, &lenient, ip, raw);
        if std_denied(ip) {
            assert!(
                host_decision.is_err(),
                "std denies {ip} but check_host allowed {raw:?}"
            );
        }
    }

    // Reference 2: the WHATWG host parser (decimal/octal/hex IPv4, userinfo, ports) via a URL
    // whose authority is the input. Any denied canonical address must deny the URL.
    let Ok(url) = Url::parse(&format!("https://{raw}/")) else {
        return;
    };
    let url_decision = strict.check_url(&url);
    let canonical = match url.host() {
        Some(url::Host::Ipv4(v4)) => Some(IpAddr::V4(v4)),
        Some(url::Host::Ipv6(v6)) => Some(IpAddr::V6(v6)),
        Some(url::Host::Domain(_)) | None => None,
    };
    if let Some(ip) = canonical {
        check_literal(&strict, &lenient, ip, raw);
        let denied = std_denied(ip) || classify_ip(ip).is_some();
        if denied {
            assert!(
                url_decision.is_err(),
                "canonical {ip} is denied but check_url allowed {raw:?} ({url})"
            );
            if let Some(h) = url.host_str() {
                assert!(
                    strict.check_host(h).is_err(),
                    "canonical {ip} is denied but check_host allowed {h:?} (from {raw:?})"
                );
            }
        }
    }
    if !url.username().is_empty() || url.password().is_some() {
        assert!(url_decision.is_err(), "userinfo URL {url} was allowed");
    }
}

fn check_literal(strict: &EgressPolicy, lenient: &EgressPolicy, ip: IpAddr, raw: &str) {
    let table = classify_ip(ip);
    let decision = strict.check_ip(ip);
    assert_eq!(
        table.is_some(),
        decision.is_err(),
        "classify_ip and check_ip disagree for {ip} (from {raw:?})"
    );
    if std_denied(ip) {
        assert!(decision.is_err(), "std denies {ip} but check_ip allowed it");
    }
    if let Err(e) = &decision {
        assert_eq!(
            Some(e.rule),
            table,
            "check_ip rule differs from classify_ip for {ip}"
        );
        assert!(!e.rule.as_str().is_empty());
    }
    if never_exempt(ip) || table == Some(DenyRule::Metadata) {
        assert!(
            lenient.check_ip(ip).is_err(),
            "{ip} must stay denied under allow_private"
        );
    }
}

/// Smallest frame over the limit: a valid response followed by whitespace, built once so the
/// oversized check costs nothing per input after the first.
static OVERSIZED_FRAME: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    let mut s = String::with_capacity(MAX_FRAME_BYTES + 1);
    s.push_str(r#"{"id":1,"result":{}}"#);
    s.extend(std::iter::repeat_n(' ', MAX_FRAME_BYTES + 1 - s.len()));
    s
});

/// `fuzz_cdp_decode`: decoding an inbound CDP frame never panics, tolerates unknown fields,
/// and rejects frames above [`MAX_FRAME_BYTES`]. The first byte is a selector: one value in
/// 256 also checks the (cached) oversized frame so that path is exercised without multi-MiB
/// corpus entries or a 64 MiB allocation per execution.
pub fn cdp_decode(data: &[u8]) {
    let Some((&selector, body)) = data.split_first() else {
        return;
    };
    let Ok(text) = std::str::from_utf8(body) else {
        return;
    };
    let decoded = decode_frame(text);
    match &decoded {
        Ok(CdpFrame::Response { id: _, outcome }) => {
            if let Err(e) = outcome {
                let _ = e.to_string();
            }
        }
        Ok(CdpFrame::Event(ev)) => {
            let _ = (ev.method.len(), ev.session_id.as_deref(), ev.params.is_null());
        }
        Ok(_) => {}
        Err(FrameDecodeError::Oversized { len, max }) => {
            assert!(
                *len == text.len() && *len > *max && *max == MAX_FRAME_BYTES,
                "{} byte frame wrongly reported oversized",
                text.len()
            );
        }
        Err(FrameDecodeError::Json(e)) => {
            let _ = e.to_string();
        }
        Err(_) => {}
    }
    // Unknown fields are tolerated: an extra key in an object frame keeps it decodable.
    if let (Ok(_), Some(rest)) = (&decoded, text.trim_start().strip_prefix('{')) {
        let injected = format!("{{\"crawlxUnknownField\":[1,{{\"x\":null}}],{rest}");
        assert!(
            decode_frame(&injected).is_ok(),
            "unknown field broke decoding of {text:?}"
        );
    }
    if selector == 0xA5 {
        let padded: &str = &OVERSIZED_FRAME;
        assert!(
            matches!(
                decode_frame(padded),
                Err(FrameDecodeError::Oversized { len, max }) if len == padded.len() && max == MAX_FRAME_BYTES
            ),
            "oversized frame was not rejected"
        );
    }
}

/// `fuzz_api_request`: the create-crawl body never panics through `serde_json` →
/// `CreateCrawl::normalize` → `check_gates` → `digest`; every validation failure is the typed
/// `CoreError` with a stable `code()` (in `details[]`), never a bare string.
pub fn api_request(data: &[u8]) {
    let Ok(mut req) = serde_json::from_slice::<CreateCrawl>(data) else {
        return;
    };
    if let Err(errs) = req.normalize() {
        assert!(!errs.is_empty(), "normalize returned Err without violations");
        for e in &errs {
            assert!(!e.code().is_empty(), "validation error without a code: {e}");
            let _ = e.to_string();
        }
    }
    for gates in [GateStatus::NONE, GateStatus::ALL] {
        if let Err(e) = req.check_gates(gates) {
            assert!(!e.code().is_empty(), "gate error without a code: {e}");
        }
    }
    let _ = req.effective_roles();
    let _ = req.effective_seed();
    assert!(req.digest().is_ok(), "normalized request does not serialize");
}
