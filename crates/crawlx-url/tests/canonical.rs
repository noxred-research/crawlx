#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Canonicalization, classification and destination-key tests.

use std::collections::BTreeMap;

use crawlx_core::config::QueryPolicy;
use crawlx_core::url::ParamClass;
use crawlx_url::{
    destination_key, CanonicalizeOptions, Canonicalizer, ParamClassifier, TrailingSlash, UrlError,
};
use proptest::prelude::*;
use url::Url;

fn base() -> Url {
    Url::parse("https://example.com/dir/page").unwrap()
}

fn canon(raw: &str) -> crawlx_core::CanonicalUrl {
    Canonicalizer::canonicalize(raw, &base(), &CanonicalizeOptions::default()).unwrap()
}

#[test]
fn golden_table() {
    let table: &[(&str, &str)] = &[
        ("HTTP://Example.COM:80/a/./b/../c", "http://example.com/a/c"),
        ("https://example.com:443/", "https://example.com/"),
        ("https://example.com", "https://example.com/"),
        ("https://example.com:8443/x", "https://example.com:8443/x"),
        (
            "https://example.com/a%7eb%2fc%2Fd",
            "https://example.com/a~b%2Fc%2Fd",
        ),
        ("https://example.com/path#section", "https://example.com/path"),
        ("https://example.com/path?", "https://example.com/path"),
        ("https://example.com/p?b=2&a=1", "https://example.com/p?a=1&b=2"),
        (
            "https://example.com/p?utm_source=x&gclid=1&a=1",
            "https://example.com/p?a=1",
        ),
        ("https://user:pw@example.com/p", "https://example.com/p"),
        ("https://example.com./p", "https://example.com/p"),
        ("https://bücher.example/p", "https://xn--bcher-kva.example/p"),
        ("../up", "https://example.com/up"),
        ("//cdn.example.com/x", "https://cdn.example.com/x"),
        ("?q=1", "https://example.com/dir/page?q=1"),
        (
            "https://example.com/invoice?id=8472&utm_source=email&page=2",
            "https://example.com/invoice?id=8472&page=2",
        ),
        (
            "https://example.com/p?sessionid=abc&PHPSESSID=x&k=v",
            "https://example.com/p?k=v",
        ),
        ("https://example.com/a/?x=%7e%41", "https://example.com/a/?x=~A"),
        (
            "https://example.com/a%20b?q=a%20b",
            "https://example.com/a%20b?q=a%20b",
        ),
        ("https://[::1]:8080/x", "https://[::1]:8080/x"),
        ("https://example.com//a//b/", "https://example.com//a//b/"),
        (
            "https://example.com/p?a=1&a=0&b",
            "https://example.com/p?a=1&a=0&b",
        ),
        ("https://example.com/p?x=%2f%2F", "https://example.com/p?x=%2F%2F"),
    ];
    for (raw, want) in table {
        assert_eq!(canon(raw).url.as_str(), *want, "{raw}");
    }
    assert!(table.len() >= 20);
}

#[test]
fn scheme_guard_and_errors() {
    let o = CanonicalizeOptions::default();
    for raw in [
        "javascript:alert(1)",
        "data:text/plain,hi",
        "file:///etc/passwd",
        "mailto:a@b.c",
        "ftp://example.com/x",
    ] {
        assert!(
            matches!(
                Canonicalizer::canonicalize(raw, &base(), &o),
                Err(UrlError::Scheme(_))
            ),
            "{raw}"
        );
    }
    assert_eq!(
        Canonicalizer::canonicalize("  ", &base(), &o).unwrap_err(),
        UrlError::Empty
    );
    assert!(matches!(
        Canonicalizer::canonicalize("http://", &base(), &o),
        Err(UrlError::Parse(_) | UrlError::NoHost)
    ));
    let long = format!("https://example.com/{}", "a".repeat(9000));
    assert!(matches!(
        Canonicalizer::canonicalize(&long, &base(), &o),
        Err(UrlError::TooLong { .. })
    ));
}

#[test]
fn equivalence_classes_share_a_key() {
    let a = canon("https://example.com/a/b?x=1");
    for raw in [
        "HTTPS://EXAMPLE.COM:443/a/b?x=1#frag",
        "https://example.com/a/./c/../b?x=1",
        "https://example.com/a/b?x=1&utm_medium=mail",
        "https://example.com/%61/b?x=1",
        "https://user@example.com/a/b?x=1",
    ] {
        assert_eq!(canon(raw).key, a.key, "{raw}");
    }
    assert_eq!(
        canon("https://example.com/p?").key,
        canon("https://example.com/p").key
    );
    assert_ne!(
        canon("https://example.com/a").key,
        canon("https://example.com/a/").key
    );
}

#[test]
fn canonicalization_worked_example() {
    let c = canon("https://shop.example/invoice/8472?id=8472&utm_source=email&page=2");
    assert_eq!(c.url.as_str(), "https://shop.example/invoice/8472?id=8472&page=2");
    assert_eq!(c.route_template.0, "/invoice/:id");
    assert_eq!(c.origin, "https://shop.example");
    let classes: Vec<(&str, ParamClass)> = c.params.iter().map(|p| (p.name.as_str(), p.class)).collect();
    assert_eq!(
        classes,
        [
            ("id", ParamClass::ResourceId),
            ("page", ParamClass::Navigation),
            ("utm_source", ParamClass::Tracking)
        ]
    );
    assert_eq!(c.params[1].value.as_deref(), Some("2"));
    assert_eq!(c.params[2].value, None);
    // resource ids are keyed hashes, never raw
    let hashed = c.params[0].value.as_deref().unwrap();
    assert_ne!(hashed, "8472");
    assert_eq!(hashed.len(), 32);
    assert_eq!(
        destination_key(&c),
        "https://shop.example/invoice/:id?id=:id&page=2".to_string()
    );
    let rk = c.route_key();
    assert_eq!(rk.query_schema.len(), 2);
}

#[test]
fn resource_id_hash_depends_on_run_key_only() {
    let o1 = CanonicalizeOptions {
        resource_key: [1; 32],
        ..Default::default()
    };
    let o2 = CanonicalizeOptions {
        resource_key: [2; 32],
        ..Default::default()
    };
    let a1 = Canonicalizer::canonicalize("https://e.example/x?id=5", &base(), &o1).unwrap();
    let a2 = Canonicalizer::canonicalize("https://e.example/x?id=5", &base(), &o1).unwrap();
    let b = Canonicalizer::canonicalize("https://e.example/x?id=5", &base(), &o2).unwrap();
    assert_eq!(a1.params[0].value, a2.params[0].value);
    assert_ne!(a1.params[0].value, b.params[0].value);
    assert_eq!(
        a1.key, b.key,
        "frontier key keeps raw values; only identity hashes are keyed"
    );
}

#[test]
fn no_silent_merge_of_resource_ids() {
    let a = canon("https://e.example/invoice?id=41");
    let b = canon("https://e.example/invoice?id=42");
    assert_ne!(a.key, b.key);
    assert_eq!(destination_key(&a), destination_key(&b), "identity uses the slot");
    assert_eq!(a.route_key(), b.route_key());
}

#[test]
fn unknown_params_are_kept_as_filter() {
    let c = canon("https://e.example/x?weird=1&other=zz");
    assert_eq!(c.url.query(), Some("other=zz&weird=1"));
    assert!(c.params.iter().all(|p| p.class == ParamClass::Filter));
    assert_eq!(c.params[0].value.as_deref(), Some("zz"));
    assert_eq!(c.params[1].value.as_deref(), Some("num"));
}

#[test]
fn permutation_and_tracking_invariance_of_destination_key() {
    let a = destination_key(&canon("https://e.example/list?sort=price&page=2&q=shoes"));
    let b = destination_key(&canon(
        "https://e.example/list?q=shoes&utm_source=a&page=2&gclid=zz&sort=price",
    ));
    assert_eq!(a, b);
    assert_eq!(a, "https://e.example/list?page=2&q=shoes&sort=price");
}

#[test]
fn query_policies_and_overrides() {
    let raw = "https://e.example/x?id=1&utm_source=a&sessionid=s&page=2";
    let mut o = CanonicalizeOptions {
        query_policy: QueryPolicy::StripAll,
        ..Default::default()
    };
    let c = Canonicalizer::canonicalize(raw, &base(), &o).unwrap();
    assert_eq!(c.url.as_str(), "https://e.example/x");
    assert!(c.params.is_empty());

    o.query_policy = QueryPolicy::KeepAll;
    let c = Canonicalizer::canonicalize(raw, &base(), &o).unwrap();
    assert_eq!(c.url.query(), Some("id=1&page=2&sessionid=s&utm_source=a"));

    let mut ov = BTreeMap::new();
    ov.insert("ID".to_owned(), ParamClass::Filter);
    ov.insert("page".to_owned(), ParamClass::Tracking);
    ov.insert("ref".to_owned(), ParamClass::Tracking);
    let o = CanonicalizeOptions {
        classifier: std::sync::Arc::new(ParamClassifier::new(&ov)),
        ..Default::default()
    };
    let c =
        Canonicalizer::canonicalize("https://e.example/x?id=1&page=2&ref=h&user_id=3", &base(), &o).unwrap();
    assert_eq!(c.url.query(), Some("id=1&user_id=3"));
    let by: BTreeMap<&str, ParamClass> = c.params.iter().map(|p| (p.name.as_str(), p.class)).collect();
    assert_eq!(by["id"], ParamClass::Filter);
    assert_eq!(
        by["user_id"],
        ParamClass::ResourceId,
        "override applies to the named parameter only"
    );
}

#[test]
fn session_values_never_leak() {
    let canary = "sess-CANARY-3f2a9c1e-77aa-4c3b-9d1e-0123456789ab";
    let d = Canonicalizer::canonicalize_detailed(
        &format!("https://e.example/x?sessionid={canary}&token={canary}&a=1"),
        &base(),
        &CanonicalizeOptions::default(),
    )
    .unwrap();
    let c = &d.url;
    let blob = format!(
        "{c} {:?} {:?} {:?} {}",
        c.params,
        c.key,
        c.route_key(),
        destination_key(c)
    );
    assert!(!blob.contains("CANARY"), "{blob}");
    assert!(!d.action_bearing && !d.had_userinfo && !d.fragment_dropped);
}

#[test]
fn audit_flags() {
    let d = Canonicalizer::canonicalize_detailed(
        "https://u:p@e.example/x?action=delete#top",
        &base(),
        &CanonicalizeOptions::default(),
    )
    .unwrap();
    assert!(d.had_userinfo && d.action_bearing && d.fragment_dropped);
    assert_eq!(d.url.url.as_str(), "https://e.example/x?action=delete");
}

#[test]
fn trailing_slash_policy_and_hash_routes() {
    let mut o = CanonicalizeOptions {
        trailing_slash: TrailingSlash::Strip,
        ..Default::default()
    };
    let c = |raw: &str, o: &CanonicalizeOptions| {
        Canonicalizer::canonicalize(raw, &base(), o)
            .unwrap()
            .url
            .to_string()
    };
    assert_eq!(c("https://e.example/a/b//", &o), "https://e.example/a/b");
    assert_eq!(c("https://e.example/", &o), "https://e.example/");
    o.trailing_slash = TrailingSlash::Add;
    assert_eq!(c("https://e.example/a/b", &o), "https://e.example/a/b/");
    assert_eq!(
        c("https://e.example/a/file.pdf", &o),
        "https://e.example/a/file.pdf"
    );
    o.keep_hash_route = true;
    assert_eq!(
        c("https://e.example/app#/inbox/1", &o),
        "https://e.example/app/#/inbox/1"
    );
    assert_eq!(c("https://e.example/app#section", &o), "https://e.example/app/");
}

// ---------- property tests ----------

fn arb_http_url() -> impl Strategy<Value = String> {
    let scheme = prop_oneof![Just("http"), Just("https"), Just("HTTP"), Just("Https")];
    let host = prop_oneof![
        "[a-zA-Z][a-zA-Z0-9-]{0,10}(\\.[a-zA-Z][a-zA-Z0-9]{0,6}){1,3}\\.?",
        Just("bücher.example".to_owned()),
        Just("127.0.0.1".to_owned()),
        Just("[::1]".to_owned()),
    ];
    let port = prop_oneof![
        Just(String::new()),
        Just(":80".to_owned()),
        Just(":443".to_owned()),
        Just(":8080".to_owned())
    ];
    let seg = prop_oneof![
        "[a-zA-Z0-9._~-]{0,8}",
        "(%[0-9a-fA-F]{2}|[a-z]){1,5}",
        Just("..".to_owned()),
        Just(".".to_owned()),
        Just("%2e%2E".to_owned()),
        "[0-9]{1,6}",
        "ü[a-z]{0,3}",
    ];
    let path = proptest::collection::vec(seg, 0..6).prop_map(|v| {
        if v.is_empty() {
            String::new()
        } else {
            format!("/{}", v.join("/"))
        }
    });
    let name = prop_oneof![
        "[a-zA-Z_]{1,6}",
        Just("utm_source".to_owned()),
        Just("id".to_owned()),
        Just("page".to_owned()),
        Just("sessionid".to_owned()),
        Just("action".to_owned()),
        "[a-z]{1,4}_id",
    ];
    let val = "(%[0-9a-fA-F]{2}|[a-zA-Z0-9 +._~-]){0,8}";
    let pair = (name, proptest::option::of(val)).prop_map(|(n, v)| match v {
        Some(v) => format!("{n}={v}"),
        None => n,
    });
    let query = proptest::collection::vec(pair, 0..5).prop_map(|v| {
        if v.is_empty() {
            String::new()
        } else {
            format!("?{}", v.join("&"))
        }
    });
    let frag = prop_oneof![Just(String::new()), "#[a-z/!]{0,6}"];
    (scheme, host, port, path, query, frag).prop_map(|(s, h, p, pa, q, f)| format!("{s}://{h}{p}{pa}{q}{f}"))
}

fn kept(c: &crawlx_core::CanonicalUrl) -> Vec<(String, ParamClass, Option<String>)> {
    c.params
        .iter()
        .filter(|p| p.class.kept())
        .map(|p| (p.name.clone(), p.class, p.value.clone()))
        .collect()
}

/// Found by the `url_canonicalize` fuzz target: a stray `%` next to an escaped unreserved
/// byte (`%6%66` → `%6f`) used to manufacture a new escape on the next pass.
#[test]
fn stray_percent_signs_do_not_break_idempotence() {
    let o = CanonicalizeOptions::default();
    for raw in [
        "http%0036666666666%6%6666%6%2E666666666://]::1]:8080/x",
        "https://e.example/a%6%66b",
        "https://e.example/100%/off?x=%zz",
        "https://e.example/%",
    ] {
        let once = Canonicalizer::canonicalize(raw, &base(), &o).unwrap();
        let twice = Canonicalizer::canonicalize(once.url.as_str(), &base(), &o).unwrap();
        assert_eq!(once.url, twice.url, "{raw}");
        assert_eq!(once.key, twice.key, "{raw}");
    }
    let c = Canonicalizer::canonicalize("https://e.example/a%6%66b", &base(), &o).unwrap();
    assert_eq!(c.url.path(), "/a%256fb");
}

proptest! {
    #[test]
    fn canonicalization_is_idempotent(raw in arb_http_url()) {
        let o = CanonicalizeOptions::default();
        if let Ok(once) = Canonicalizer::canonicalize(&raw, &base(), &o) {
            let twice = Canonicalizer::canonicalize(once.url.as_str(), &base(), &o).unwrap();
            prop_assert_eq!(&once.url, &twice.url);
            prop_assert_eq!(once.key, twice.key);
            prop_assert_eq!(&once.route_template, &twice.route_template);
            prop_assert_eq!(&once.origin, &twice.origin);
            prop_assert_eq!(kept(&once), kept(&twice));
        }
    }

    #[test]
    fn idempotent_under_every_policy(raw in arb_http_url(), pol in 0u8..3, ts in 0u8..3) {
        let o = CanonicalizeOptions {
            query_policy: [QueryPolicy::Classify, QueryPolicy::KeepAll, QueryPolicy::StripAll][usize::from(pol)],
            trailing_slash: [TrailingSlash::Keep, TrailingSlash::Strip, TrailingSlash::Add][usize::from(ts)],
            ..Default::default()
        };
        if let Ok(once) = Canonicalizer::canonicalize(&raw, &base(), &o) {
            let twice = Canonicalizer::canonicalize(once.url.as_str(), &base(), &o).unwrap();
            prop_assert_eq!(once.url, twice.url);
        }
    }

    #[test]
    fn totality_on_arbitrary_input(raw in ".{0,120}") {
        let o = CanonicalizeOptions::default();
        if let Ok(c) = Canonicalizer::canonicalize(&raw, &base(), &o) {
            prop_assert!(matches!(c.url.scheme(), "http" | "https"));
            prop_assert!(c.url.host_str().is_some_and(|h| !h.is_empty() && !h.ends_with('.')));
            prop_assert!(c.url.fragment().is_none());
            prop_assert!(c.url.username().is_empty() && c.url.password().is_none());
        }
    }

    #[test]
    fn host_case_and_default_port_do_not_matter(raw in arb_http_url()) {
        let o = CanonicalizeOptions::default();
        let Ok(a) = Canonicalizer::canonicalize(&raw, &base(), &o) else { return Ok(()) };
        let u = Url::parse(&raw).unwrap();
        let host = u.host_str().unwrap().to_uppercase();
        let port = if u.scheme() == "http" { ":80" } else { ":443" };
        let rebuilt = format!("{}://{}{}{}{}", u.scheme().to_uppercase(), host, if u.port().is_none() { port } else { "" }, u.path(), u.query().map(|q| format!("?{q}")).unwrap_or_default());
        if u.port().is_none() {
            let b = Canonicalizer::canonicalize(&rebuilt, &base(), &o).unwrap();
            prop_assert_eq!(a.key, b.key);
        }
    }

    #[test]
    fn param_permutation_keeps_destination_key(mut pairs in proptest::collection::btree_map("[a-z]{1,5}", "[a-z0-9]{0,5}", 0..5)) {
        let o = CanonicalizeOptions::default();
        let fwd: Vec<String> = pairs.iter().map(|(k, v)| format!("{k}={v}")).collect();
        let mut rev = fwd.clone();
        rev.reverse();
        let a = Canonicalizer::canonicalize(&format!("https://e.example/p?{}", fwd.join("&")), &base(), &o).unwrap();
        let b = Canonicalizer::canonicalize(&format!("https://e.example/p?{}", rev.join("&")), &base(), &o).unwrap();
        prop_assert_eq!(destination_key(&a), destination_key(&b));
        prop_assert_eq!(a.key, b.key);
        pairs.clear();
    }

    #[test]
    fn different_paths_never_collide(a in "[a-z]{1,6}", b in "[a-z]{1,6}") {
        prop_assume!(a != b);
        let ca = canon(&format!("https://e.example/{a}"));
        let cb = canon(&format!("https://e.example/{b}"));
        prop_assert_ne!(ca.key, cb.key);
    }
}

#[test]
#[ignore = "throughput measurement; run with --ignored --nocapture in release"]
fn throughput() {
    let o = CanonicalizeOptions::default();
    let b = base();
    let urls: Vec<String> = (0..1000)
        .map(|i| {
            format!(
                "https://Example.com:443/shop/item/{i}/../p{}?utm_source=x&id={i}&page={}&sort=price#f",
                i % 7,
                i % 13
            )
        })
        .collect();
    let n = 200_000usize;
    let start = std::time::Instant::now();
    let mut acc = 0u8;
    for i in 0..n {
        let c = Canonicalizer::canonicalize(&urls[i % urls.len()], &b, &o).unwrap();
        acc ^= c.key.0[0];
    }
    let secs = start.elapsed().as_secs_f64();
    println!(
        "canonicalize: {:.0} URLs/s ({n} in {secs:.3}s, acc {acc})",
        n as f64 / secs
    );
}

#[test]
fn scope_max_url_length_bounds_raw_and_resolved_urls() {
    let scope = crawlx_core::config::Scope {
        max_url_length: 300,
        ..crawlx_core::config::Scope::default()
    };
    let opts = CanonicalizeOptions::from_scope(&scope, [0; 32]);
    assert_eq!(opts.max_url_len, 300);
    let at_limit = format!(
        "https://example.com/{}",
        "a".repeat(300 - "https://example.com/".len())
    );
    assert!(Canonicalizer::canonicalize(&at_limit, &base(), &opts).is_ok());
    let over = format!("{at_limit}a");
    assert!(matches!(
        Canonicalizer::canonicalize(&over, &base(), &opts),
        Err(UrlError::TooLong { len: 301, max: 300 })
    ));
    // a short relative link that resolves past the limit is refused as well
    let deep_base = Url::parse(&format!("https://example.com/{}/", "d".repeat(280))).unwrap();
    assert!(matches!(
        Canonicalizer::canonicalize(&"x".repeat(40), &deep_base, &opts),
        Err(UrlError::TooLong { .. })
    ));
    // an already parsed redirect target goes through the same bound
    let parsed = Url::parse(&over).unwrap();
    assert!(matches!(
        Canonicalizer::canonicalize_url(&parsed, &opts),
        Err(UrlError::TooLong { .. })
    ));
    // the default scope keeps the historical 8 KiB bound
    assert_eq!(
        CanonicalizeOptions::from_scope(&crawlx_core::config::Scope::default(), [0; 32]).max_url_len,
        8192
    );
}
