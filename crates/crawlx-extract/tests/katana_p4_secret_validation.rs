#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Online secret validation plans (`-kb-validate-secrets`):
//! the empty embedded list, validator file loading and its errors, token
//! substitution safety, verdict mapping and the redacted `Debug` of every
//! type that holds a token.

use std::path::PathBuf;

use crawlx_extract::secret_validation::{SecretValidators, ValidatorError, Validity};
use crawlx_extract::secrets::{self, SecretKind};
use crawlx_extract::Extractor;

const FILE: &str = r#"{
  "version": 1,
  "validators": [
    {
      "kind": "github_token",
      "method": "GET",
      "url": "https://api.github.com/user",
      "headers": { "Authorization": "Bearer {token}", "Accept": "application/json" },
      "valid_status": [200],
      "invalid_status": [401, 403]
    },
    {
      "kind": "slack_token",
      "url": "https://slack.com/api/auth.test?token={token}",
      "valid_status": [200],
      "invalid_status": [401],
      "body_regex": "\"ok\"\\s*:\\s*true"
    },
    {
      "kind": "stripe_key",
      "method": "head",
      "url": "https://api.stripe.test/v1/keys/{token}/check",
      "valid_status": [200, 204],
      "invalid_status": [401]
    },
    {
      "kind": "google_api_key",
      "url": "http://localhost:8080/check?key={token}",
      "valid_status": [200],
      "allow_http": true
    }
  ]
}"#;

fn validators() -> SecretValidators {
    SecretValidators::from_json(FILE).unwrap()
}

// Synthetic detector canaries; provider-shaped values are assembled from parts so the
// source holds no contiguous token.
const GH_TOKEN: &str = concat!("gh", "p_abcdefghijklmnopqrstuvwxyz0123456789");
const SLACK_TOKEN: &str = concat!("xo", "xb-1234567890-abcdef");
const STRIPE_TEST_SHORT: &str = concat!("sk_", "test_abcdefghij");
const STRIPE_TEST_LONG: &str = concat!("sk_", "test_abcdefghijklmnop");
const GOOGLE_KEY: &str = concat!("AI", "zaSyA-1234567890123456789012345678901");
const AWS_KEY_ID: &str = concat!("AKIA", "ABCDEFGHIJKLMNOP");

fn one(entry: &str) -> Result<SecretValidators, ValidatorError> {
    SecretValidators::from_json(&format!(r#"{{"version":1,"validators":[{entry}]}}"#))
}

fn temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("crawlx-p4-validators-{}-{tag}.json", std::process::id()))
}

// ------------------------------------------------------------ builtin and load

#[test]
fn builtin_list_is_empty_and_validates_nothing() {
    let v = SecretValidators::builtin();
    assert!(v.is_empty());
    assert_eq!(v.len(), 0);
    assert!(v.plan("github_token", GH_TOKEN).is_none());
    assert_eq!(v.interpret("github_token", 200, b"{}"), Validity::Unknown);
}

#[test]
fn load_reads_a_file_and_reports_io_errors() {
    let path = temp_path("ok");
    std::fs::write(&path, FILE).unwrap();
    let v = SecretValidators::load(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert_eq!(v.len(), 4);
    assert!(v.handles("github_token") && v.handles("slack_token") && !v.handles("jwt"));

    let missing = temp_path("missing");
    let err = SecretValidators::load(&missing).unwrap_err();
    assert!(matches!(err, ValidatorError::Io { ref path, .. } if *path == missing));
    assert!(
        std::error::Error::source(&err).is_some(),
        "the io error is chained"
    );
}

#[test]
fn load_rejects_unsafe_or_malformed_files() {
    assert!(matches!(
        SecretValidators::from_json("not json"),
        Err(ValidatorError::Json(_))
    ));
    assert!(matches!(
        SecretValidators::from_json(r#"{"version":2,"validators":[]}"#),
        Err(ValidatorError::Version(2))
    ));
    assert!(matches!(
        SecretValidators::from_json(r#"{"version":1,"validators":[],"extra":1}"#),
        Err(ValidatorError::Json(_))
    ));
    let ok = r#""kind":"github_token","url":"https://h.test/{token}","valid_status":[200]"#;
    assert!(one(&format!("{{{ok}}}")).is_ok());
    assert!(matches!(
        one(&format!("{{{ok}}},{{{ok}}}")),
        Err(ValidatorError::DuplicateKind(k)) if k == "github_token"
    ));
    assert!(matches!(
        one(r#"{"kind":"made_up","url":"https://h.test/{token}","valid_status":[200]}"#),
        Err(ValidatorError::UnknownKind(k)) if k == "made_up"
    ));
    assert!(matches!(
        one(r#"{"kind":"jwt","method":"POST","url":"https://h.test/{token}","valid_status":[200]}"#),
        Err(ValidatorError::UnsupportedMethod { method, .. }) if method == "POST"
    ));
}

#[test]
fn load_rejects_urls_that_could_leak_or_redirect_the_token() {
    let bad =
        |url: &str| one(&format!(r#"{{"kind":"jwt","url":"{url}","valid_status":[200]}}"#)).unwrap_err();
    assert!(
        matches!(bad("http://h.test/{token}"), ValidatorError::BadUrl { reason, .. } if reason.contains("https"))
    );
    assert!(matches!(
        bad("ftp://h.test/{token}"),
        ValidatorError::BadUrl { .. }
    ));
    assert!(
        matches!(bad("https://{token}.h.test/x"), ValidatorError::BadUrl { reason, .. } if reason.contains("{token}"))
    );
    assert!(matches!(
        bad("https://h.test:{token}/x"),
        ValidatorError::BadUrl { .. }
    ));
    assert!(matches!(
        bad("https://{token}@h.test/x"),
        ValidatorError::BadUrl { .. }
    ));
    assert!(
        matches!(bad("https://user:pw@h.test/{token}"), ValidatorError::BadUrl { reason, .. } if reason.contains("credentials"))
    );
    assert!(matches!(bad("/relative/{token}"), ValidatorError::BadUrl { .. }));
    assert!(
        matches!(bad("https://h.test/{tokens}"), ValidatorError::BadUrl { reason, .. } if reason.contains("brace"))
    );
    assert!(
        one(r#"{"kind":"jwt","url":"http://h.test/{token}","valid_status":[200],"allow_http":true}"#).is_ok()
    );
}

#[test]
fn load_rejects_validators_that_do_not_use_the_token_or_have_bad_parts() {
    assert!(matches!(
        one(r#"{"kind":"jwt","url":"https://h.test/fixed","valid_status":[200]}"#),
        Err(ValidatorError::NoToken { .. })
    ));
    assert!(one(
        r#"{"kind":"jwt","url":"https://h.test/x","headers":{"X-Key":"{token}"},"valid_status":[200]}"#
    )
    .is_ok());
    assert!(matches!(
        one(r#"{"kind":"jwt","url":"https://h.test/{token}","headers":{"bad name":"v"},"valid_status":[200]}"#),
        Err(ValidatorError::BadHeader { name, .. }) if name == "bad name"
    ));
    assert!(matches!(
        one(r#"{"kind":"jwt","url":"https://h.test/{token}","valid_status":[]}"#),
        Err(ValidatorError::BadStatus { .. })
    ));
    assert!(matches!(
        one(r#"{"kind":"jwt","url":"https://h.test/{token}","valid_status":[200,201],"invalid_status":[201]}"#),
        Err(ValidatorError::BadStatus { reason, .. }) if reason.contains("overlap")
    ));
    let err = one(r#"{"kind":"jwt","url":"https://h.test/{token}","valid_status":[200],"body_regex":"("}"#)
        .unwrap_err();
    assert!(matches!(err, ValidatorError::BadBodyRegex { .. }));
    assert!(
        std::error::Error::source(&err).is_some(),
        "the regex error is chained"
    );
}

// ------------------------------------------------------------ plan

#[test]
fn plan_substitutes_the_token_into_headers_and_query() {
    let v = validators();
    let plan = v.plan("github_token", GH_TOKEN).unwrap();
    assert_eq!(plan.method, "GET");
    assert_eq!(plan.url.as_str(), "https://api.github.com/user");
    assert_eq!(
        plan.headers,
        [
            ("Accept".to_owned(), "application/json".to_owned()),
            ("Authorization".to_owned(), format!("Bearer {GH_TOKEN}")),
        ]
    );

    let slack = v.plan("slack_token", SLACK_TOKEN).unwrap();
    assert_eq!(
        slack.url.as_str(),
        format!("https://slack.com/api/auth.test?token={SLACK_TOKEN}")
    );
    assert!(slack.headers.is_empty());

    let head = v.plan("stripe_key", STRIPE_TEST_SHORT).unwrap();
    assert_eq!(head.method, "HEAD", "the method is upper-cased");
    assert_eq!(head.url.path(), format!("/v1/keys/{STRIPE_TEST_SHORT}/check"));

    let http = v.plan("google_api_key", GOOGLE_KEY).unwrap();
    assert_eq!(http.url.scheme(), "http", "allow_http permits a plain url");
}

#[test]
fn plan_returns_none_without_a_validator() {
    assert!(validators().plan("aws_access_key_id", AWS_KEY_ID).is_none());
    assert!(validators().plan("", GH_TOKEN).is_none());
}

#[test]
fn a_token_can_never_change_the_host_or_break_out_of_its_component() {
    let v = validators();
    for token in [
        "x/../../evil",
        "a@evil.test",
        "evil.test/",
        "a?b=c#d",
        "a\\b",
        "..%2f",
        "a:b@c",
        "a%00b",
    ] {
        let stripe = v.plan("stripe_key", token).unwrap();
        assert_eq!(stripe.url.host_str(), Some("api.stripe.test"), "{token}");
        assert_eq!(stripe.url.scheme(), "https");
        assert_eq!(stripe.url.port(), None);
        assert!(
            stripe.url.query().is_none() && stripe.url.fragment().is_none(),
            "{token}: {}",
            stripe.url
        );
        assert!(
            stripe.url.path().starts_with("/v1/keys/") && stripe.url.path().ends_with("/check"),
            "{token}"
        );
        assert_eq!(
            stripe.url.path().matches('/').count(),
            4,
            "{token}: one path segment only: {}",
            stripe.url
        );

        let slack = v.plan("slack_token", token).unwrap();
        assert_eq!(slack.url.host_str(), Some("slack.com"), "{token}");
        assert_eq!(slack.url.path(), "/api/auth.test");
        let pairs: Vec<(String, String)> = slack.url.query_pairs().into_owned().collect();
        assert_eq!(
            pairs,
            [("token".to_owned(), token.to_owned())],
            "{token} round-trips through the query"
        );
    }
}

#[test]
fn unsafe_tokens_are_never_planned() {
    let v = validators();
    let long = "a".repeat(4097);
    for token in [
        "",
        "a b",
        "line\nbreak",
        "tab\t",
        "caf\u{e9}",
        "nul\0",
        "..",
        ".",
        long.as_str(),
    ] {
        assert!(v.plan("github_token", token).is_none(), "{token:?}");
        assert!(v.plan("slack_token", token).is_none(), "{token:?}");
    }
    assert!(v.plan("github_token", &"a".repeat(4096)).is_some());
}

// ------------------------------------------------------------ interpret

#[test]
fn interpret_maps_statuses() {
    let v = validators();
    assert_eq!(v.interpret("github_token", 200, b"{}"), Validity::Valid);
    assert_eq!(v.interpret("github_token", 401, b""), Validity::Invalid);
    assert_eq!(v.interpret("github_token", 403, b""), Validity::Invalid);
    for inconclusive in [429, 500, 502, 404, 301] {
        assert_eq!(
            v.interpret("github_token", inconclusive, b""),
            Validity::Unknown,
            "{inconclusive}"
        );
    }
    assert_eq!(v.interpret("stripe_key", 204, b""), Validity::Valid);
    assert_eq!(
        v.interpret("jwt", 200, b"{}"),
        Validity::Unknown,
        "no validator for the kind"
    );
}

#[test]
fn interpret_applies_body_regex_to_valid_statuses_only() {
    let v = validators();
    assert_eq!(
        v.interpret("slack_token", 200, br#"{"ok": true, "user": "x"}"#),
        Validity::Valid
    );
    assert_eq!(
        v.interpret("slack_token", 200, br#"{"ok":false,"error":"invalid_auth"}"#),
        Validity::Invalid
    );
    assert_eq!(
        v.interpret("slack_token", 200, &[0xff, 0xfe]),
        Validity::Invalid,
        "non-utf8 bodies do not panic"
    );
    assert_eq!(
        v.interpret("slack_token", 401, br#"{"ok":true}"#),
        Validity::Invalid
    );
    assert_eq!(
        v.interpret("slack_token", 503, br#"{"ok":true}"#),
        Validity::Unknown
    );
    // Only the first 64 KiB are matched.
    let mut late = vec![b' '; 70_000];
    late.extend_from_slice(br#"{"ok":true}"#);
    assert_eq!(v.interpret("slack_token", 200, &late), Validity::Invalid);
}

#[test]
fn validity_wire_names() {
    assert_eq!(Validity::Valid.as_str(), "valid");
    assert_eq!(Validity::Invalid.as_str(), "invalid");
    assert_eq!(Validity::Unknown.as_str(), "unknown");
    assert_eq!(serde_json::to_string(&Validity::Valid).unwrap(), "\"valid\"");
    assert_eq!(
        serde_json::from_str::<Validity>("\"unknown\"").unwrap(),
        Validity::Unknown
    );
}

// ------------------------------------------------------------ transient tokens

#[test]
fn detect_secret_tokens_matches_detect_and_never_prints_the_token() {
    let key = [7u8; 32];
    let body = format!("config = {{ token: \"{GH_TOKEN}\" }}\naws {AWS_KEY_ID} end");
    let headers = vec![("x-key".to_owned(), STRIPE_TEST_LONG.to_owned())];

    let plain = Extractor::detect_secrets(&key, &headers, &body);
    let with_tokens = Extractor::detect_secret_tokens(&key, &headers, &body);
    assert_eq!(
        plain,
        with_tokens.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>(),
        "same findings, same order"
    );
    assert_eq!(
        plain,
        secrets::detect(&key, &headers, &body),
        "detect is unchanged"
    );

    let kinds: Vec<SecretKind> = with_tokens.iter().map(|(f, _)| f.kind).collect();
    assert_eq!(
        kinds,
        [
            SecretKind::StripeKey,
            SecretKind::GitHubToken,
            SecretKind::AwsAccessKeyId
        ]
    );
    assert_eq!(with_tokens[0].1.as_str(), STRIPE_TEST_LONG);
    assert_eq!(&*with_tokens[1].1, GH_TOKEN, "the token derefs to str");
    assert_eq!(with_tokens[1].0.preview_len, GH_TOKEN.len());

    let debug = format!("{with_tokens:?}");
    for (_, token) in &with_tokens {
        assert!(!debug.contains(token.as_str()), "Debug leaked a token: {debug}");
    }
    assert!(debug.contains("redacted"));
}

#[test]
fn a_detected_token_plans_a_request_whose_debug_hides_it() {
    let key = [1u8; 32];
    let found = Extractor::detect_secret_tokens(&key, &[], &format!("t={GH_TOKEN}"));
    let (finding, token) = &found[0];
    assert_eq!(finding.kind, SecretKind::GitHubToken);

    let v = validators();
    let plan = v.plan(finding.kind.as_str(), token).unwrap();
    assert!(
        plan.headers.iter().any(|(_, value)| value.contains(GH_TOKEN)),
        "the request does carry it"
    );
    let debug = format!("{plan:?}");
    assert!(!debug.contains(GH_TOKEN), "{debug}");
    assert!(debug.contains("api.github.com") && debug.contains("Authorization"));

    let slack = v.plan("slack_token", SLACK_TOKEN).unwrap();
    assert!(!format!("{slack:?}").contains(&SLACK_TOKEN[..15]));
    assert!(!format!("{v:?}").contains(GH_TOKEN));
}

#[test]
fn secret_kind_wire_names_round_trip() {
    for kind in SecretKind::ALL {
        assert_eq!(SecretKind::from_wire(kind.as_str()), Some(kind));
        // The serialized name (`metadata.secrets[].kind`) is the wire name validators are keyed by.
        assert_eq!(serde_json::to_value(kind).unwrap(), kind.as_str(), "{kind:?}");
        assert_eq!(
            serde_json::from_value::<SecretKind>(kind.as_str().into()).unwrap(),
            kind
        );
    }
    assert_eq!(
        serde_json::from_str::<SecretKind>("\"git_hub_token\"").unwrap(),
        SecretKind::GitHubToken,
        "pages stored before the rename still deserialize"
    );
    assert_eq!(SecretKind::from_wire("nope"), None);
}
