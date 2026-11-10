#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Static form filling (`-aff`, `-fc`): request shape per method
//! and enctype, value rules per control, per-class configuration, seed
//! determinism, model answers (`decided`) and the `unresolved` list.

use std::collections::BTreeMap;

use crawlx_core::config::FormFill;
use crawlx_core::seed::CrawlSeed;
use crawlx_extract::form_fill::{fill_form, parse_form_config, FilledForm, FormConfigError};
use crawlx_extract::forms::{self, StaticForm};
use regex::Regex;
use url::Url;

fn page() -> Url {
    Url::parse("https://shop.example/account/").unwrap()
}

fn form(html: &str) -> StaticForm {
    forms::extract_str(html, &page()).unwrap().remove(0)
}

fn no_answers() -> BTreeMap<String, String> {
    BTreeMap::new()
}

fn fill(html: &str, cfg: &FormFill, seed: u64) -> FilledForm {
    fill_form(&form(html), &page(), cfg, &CrawlSeed(seed), &no_answers())
}

fn plain(html: &str) -> FilledForm {
    fill(html, &FormFill::default(), 7)
}

fn query(url: &Url) -> Vec<(String, String)> {
    url.query_pairs().into_owned().collect()
}

// ------------------------------------------------------------ request shape

#[test]
fn get_form_encodes_fields_into_the_action_query() {
    let f = plain(
        r##"<form action="/search?old=1#frag" method="get">
            <input name="q" type="text">
            <select name="lang"><option value="en">EN</option><option value="de" selected>DE</option></select>
            <input type="hidden" name="src" value="nav">
            <input type="submit" name="go" value="Search">
            <input type="submit" name="go2" value="Second">
        </form>"##,
    );
    assert_eq!(f.method, "GET");
    assert_eq!(f.action.path(), "/search");
    assert_eq!(f.action.fragment(), None);
    assert!(f.body.is_none() && f.content_type.is_none());
    let pairs = query(&f.action);
    let names: Vec<&str> = pairs.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        names,
        ["q", "lang", "src", "go"],
        "the old query is replaced, only the first submit counts"
    );
    assert_eq!(f.fields["lang"], "de");
    assert_eq!(f.fields["src"], "nav");
    assert_eq!(f.fields["go"], "Search");
    assert!(!f.fields.contains_key("go2"));
    let from_query: BTreeMap<String, String> = pairs.into_iter().collect();
    assert_eq!(from_query, f.fields);
}

#[test]
fn get_form_without_fields_drops_the_action_query() {
    let f = plain(r#"<form action="/x?old=1" method="get"></form>"#);
    assert_eq!(f.action.as_str(), "https://shop.example/x");
    assert!(f.fields.is_empty());
}

#[test]
fn post_form_body_is_urlencoded_in_document_order() {
    let cfg = FormFill {
        email: Some("me@x.test".to_owned()),
        password: Some("S3cret!".to_owned()),
        ..FormFill::default()
    };
    let f = fill(
        r#"<form action="/login" method="post">
            <input name="email" type="email">
            <input name="pw" type="password">
            <input name="csrf" type="hidden" value="tok+/=">
            <input name="remember" type="checkbox">
            <input name="plan" type="radio" value="a">
            <input name="plan" type="radio" value="b" checked>
            <input name="plan" type="radio" value="c">
            <input name="ro" type="radio" value="x"><input name="ro" type="radio" value="y">
            <input name="off" disabled value="x">
            <input type="button" name="btn" value="b"><input type="reset" name="rs">
        </form>"#,
        &cfg,
        1,
    );
    assert_eq!(f.method, "POST");
    assert_eq!(f.action.as_str(), "https://shop.example/login");
    assert_eq!(
        f.content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(
        f.body.as_deref(),
        Some("email=me%40x.test&pw=S3cret%21&csrf=tok%2B%2F%3D&remember=on&plan=b&ro=x")
    );
    let expected: BTreeMap<String, String> = [
        ("email", "me@x.test"),
        ("pw", "S3cret!"),
        ("csrf", "tok+/="),
        ("remember", "on"),
        ("plan", "b"),
        ("ro", "x"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    assert_eq!(f.fields, expected);
}

#[test]
fn multipart_enctype_builds_parts_with_an_empty_file() {
    let html = r#"<form action="/upload" method="post" enctype="multipart/form-data">
        <input name="title" value="t"><input type="file" name="doc"><textarea name="note">n</textarea>
    </form>"#;
    let f = plain(html);
    let ct = f.content_type.clone().unwrap();
    let boundary = ct.strip_prefix("multipart/form-data; boundary=").unwrap();
    let body = f.body.clone().unwrap();
    assert!(body.starts_with(&format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nt\r\n"
    )));
    assert!(
        body.contains("name=\"doc\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n\r\n\r\n")
    );
    assert!(body.contains("name=\"note\"\r\n\r\nn\r\n"));
    assert!(body.ends_with(&format!("--{boundary}--\r\n")));
    assert_eq!(plain(html), f, "same seed, same boundary and body");
    let other = fill(html, &FormFill::default(), 8);
    assert_ne!(
        other.content_type, f.content_type,
        "the boundary derives from the seed"
    );
}

#[test]
fn text_plain_and_json_enctypes() {
    let plain_text = plain(
        r#"<form action="/p" method="post" enctype="text/plain"><input name="a" value="1"><input name="b" value="2"></form>"#,
    );
    assert_eq!(plain_text.content_type.as_deref(), Some("text/plain"));
    assert_eq!(plain_text.body.as_deref(), Some("a=1\r\nb=2\r\n"));

    let json = plain(
        r#"<form action="/j" method="post" enctype="application/json"><input name="a" value="1"><input name="b" value="2"></form>"#,
    );
    assert_eq!(json.content_type.as_deref(), Some("application/json"));
    let parsed: serde_json::Value = serde_json::from_str(json.body.as_deref().unwrap()).unwrap();
    assert_eq!(parsed, serde_json::json!({"a": "1", "b": "2"}));

    let unknown =
        plain(r#"<form action="/u" method="post" enctype="bogus/x"><input name="a" value="1"></form>"#);
    assert_eq!(
        unknown.content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
    assert_eq!(unknown.body.as_deref(), Some("a=1"));
}

// ------------------------------------------------------------ value rules

#[test]
fn configured_values_override_each_class() {
    let cfg = FormFill {
        enabled: true,
        email: Some("a@b.test".to_owned()),
        color: Some("#112233".to_owned()),
        password: Some("pw-123".to_owned()),
        phone: Some("5551230000".to_owned()),
        placeholder: Some("custom".to_owned()),
    };
    let f = fill(
        r#"<form method="post" action="/r">
            <input name="mail" type="email"><input name="mobile" type="tel">
            <input name="secret" type="password"><input name="shade" type="color">
            <input name="nickname" type="text">
            <input name="contact_email" type="text">
        </form>"#,
        &cfg,
        3,
    );
    assert_eq!(f.fields["mail"], "a@b.test");
    assert_eq!(f.fields["mobile"], "5551230000");
    assert_eq!(f.fields["secret"], "pw-123");
    assert_eq!(f.fields["shade"], "#112233");
    assert_eq!(
        f.fields["nickname"], "custom",
        "-fc placeholder fills every other text input"
    );
    assert_eq!(
        f.fields["contact_email"], "a@b.test",
        "a name containing `email` is an email field"
    );
}

#[test]
fn defaults_are_seeded_shaped_values() {
    let f = plain(
        r#"<form method="post" action="/r">
            <input name="mail" type="email"><input name="mobile" type="tel">
            <input name="secret" type="password"><input name="shade" type="color">
        </form>"#,
    );
    assert!(Regex::new(r"^[a-z0-9]{12}@example\.org$")
        .unwrap()
        .is_match(&f.fields["mail"]));
    assert!(Regex::new(r"^21255501[0-9]{2}$")
        .unwrap()
        .is_match(&f.fields["mobile"]));
    assert!(Regex::new(r"^#[0-9a-f]{6}$")
        .unwrap()
        .is_match(&f.fields["shade"]));
    let pw = &f.fields["secret"];
    assert_eq!(pw.len(), 14);
    assert!(pw.bytes().any(|b| b.is_ascii_uppercase()));
    assert!(pw.bytes().any(|b| b.is_ascii_lowercase()));
    assert!(pw.bytes().any(|b| b.is_ascii_digit()));
    assert!(pw.bytes().any(|b| !b.is_ascii_alphanumeric()));
}

#[test]
fn semantic_families_use_reference_constants() {
    let f = plain(
        r#"<form method="post" action="/r">
            <input name="username"><input name="first_name"><input name="lastName"><input name="full_name">
            <input name="city"><input name="state"><input name="country"><input name="company">
            <input name="zip_code"><input name="street"><input name="age"><input name="qty">
            <input name="card_number"><input name="cvv"><input name="homepage"><input name="ip_address">
            <input type="date" name="d1"><input type="time" name="d2"><input type="datetime-local" name="d3">
            <input type="month" name="d4"><input type="week" name="d5"><input type="url" name="u1">
            <input name="f" autocomplete="section-x shipping cc-exp">
        </form>"#,
    );
    let want = [
        ("username", "crawlx"),
        ("first_name", "John"),
        ("lastName", "Doe"),
        ("full_name", "John Doe"),
        ("city", "New York"),
        ("state", "NY"),
        ("country", "US"),
        ("company", "Example Inc"),
        ("zip_code", "10001"),
        ("street", "1 Main St"),
        ("age", "30"),
        ("qty", "1"),
        ("card_number", "4111111111111111"),
        ("cvv", "123"),
        ("homepage", "https://example.com"),
        ("ip_address", "192.0.2.1"),
        ("d1", "2024-01-15"),
        ("d2", "12:00"),
        ("d3", "2024-01-15T12:00"),
        ("d4", "2024-01"),
        ("d5", "2024-W03"),
        ("u1", "https://example.com"),
        ("f", "12/30"),
    ];
    for (name, value) in want {
        assert_eq!(f.fields[name], value, "{name}");
    }
    assert!(
        f.unresolved.is_empty(),
        "every field above has a rule: {:?}",
        f.unresolved
    );
}

#[test]
fn number_and_range_take_min_plus_step_within_max() {
    let f = plain(
        r#"<form method="post" action="/r">
            <input type="number" name="a">
            <input type="number" name="b" min="5">
            <input type="range" name="c" max="1">
            <input type="number" name="d" step="any">
            <input type="number" name="e" min="10" step="3" max="11">
            <input type="number" name="g" min="0" max="100" step="25">
            <input type="number" name="kept" value="42">
        </form>"#,
    );
    let got: Vec<&str> = ["a", "b", "c", "d", "e", "g", "kept"]
        .iter()
        .map(|n| f.fields[*n].as_str())
        .collect();
    assert_eq!(got, ["2", "6", "1", "2", "10", "25", "42"]);
}

#[test]
fn selects_and_prefilled_values() {
    let f = plain(
        r#"<form method="post" action="/r">
            <select name="s1"><option value="">-- pick --</option><option value="1">one</option></select>
            <select name="s2"><option value="a">a</option><option value="b" selected>b</option></select>
            <input name="keep" value="abc" pattern="[0-9]+">
            <input name="mail" type="email" value="given@x.test">
            <input name="hid" type="hidden">
        </form>"#,
    );
    assert_eq!(f.fields["s1"], "1", "the empty placeholder option is skipped");
    assert_eq!(f.fields["s2"], "b");
    assert_eq!(
        f.fields["keep"], "abc",
        "a prefilled value is kept even when the pattern rejects it"
    );
    assert_eq!(f.fields["mail"], "given@x.test");
    assert_eq!(f.fields["hid"], "");
}

#[test]
fn disabled_buttons_and_reset_are_not_submitted() {
    let f = plain(
        r#"<form method="post" action="/r">
            <input name="d" disabled value="x"><input type="button" name="b" value="b">
            <input type="reset" name="r"><input type="image" name="i"><input name="ok" value="1">
        </form>"#,
    );
    assert_eq!(f.fields.keys().map(String::as_str).collect::<Vec<_>>(), ["ok"]);
}

// ------------------------------------------------------------ pattern / length

#[test]
fn pattern_and_length_attributes_are_respected() {
    let f = plain(
        r#"<form method="post" action="/r">
            <input name="code" pattern="[A-Z]{3}-[0-9]{4}">
            <input name="zipcode" pattern="[0-9]{5}">
            <input name="state" pattern="[a-z]{3}">
            <input name="short" maxlength="3">
            <input name="long" minlength="12">
            <input name="bad" pattern="(?=x)x">
            <input name="num" type="number" pattern="[a-z]+">
        </form>"#,
    );
    assert!(
        Regex::new(r"^[A-Z]{3}-[0-9]{4}$")
            .unwrap()
            .is_match(&f.fields["code"]),
        "{:?}",
        f.fields["code"]
    );
    assert_eq!(
        f.fields["zipcode"], "10001",
        "a conforming semantic value is kept"
    );
    assert!(
        Regex::new(r"^[a-z]{3}$").unwrap().is_match(&f.fields["state"]),
        "NY does not match, a conforming value replaces it"
    );
    assert_eq!(f.fields["short"].chars().count(), 3);
    assert_eq!(f.fields["long"].chars().count(), 12);
    assert_eq!(
        f.fields["bad"].len(),
        8,
        "a pattern the engine cannot parse is ignored"
    );
    assert_eq!(f.fields["num"], "2", "pattern does not apply to number inputs");
    let again =
        plain(r#"<form method="post" action="/r"><input name="code" pattern="[A-Z]{3}-[0-9]{4}"></form>"#);
    assert_eq!(
        again.fields["code"], f.fields["code"],
        "generation is deterministic"
    );
}

#[test]
fn maxlength_applies_to_configured_values() {
    let cfg = FormFill {
        email: Some("averyverylongaddress@example.org".to_owned()),
        ..FormFill::default()
    };
    let f = fill(
        r#"<form method="post" action="/r"><input type="email" name="e" maxlength="10"></form>"#,
        &cfg,
        1,
    );
    assert_eq!(f.fields["e"], "averyveryl");
}

// ------------------------------------------------------------ seed / decided / unresolved

#[test]
fn same_seed_same_output_different_seed_differs() {
    let html = r#"<form method="post" action="/r">
        <input name="mail" type="email"><input name="secret" type="password">
        <input name="mobile" type="tel"><input name="nick">
    </form>"#;
    let a = fill(html, &FormFill::default(), 11);
    assert_eq!(a, fill(html, &FormFill::default(), 11));
    let b = fill(html, &FormFill::default(), 12);
    assert_ne!(a.fields["mail"], b.fields["mail"]);
    assert_ne!(a.fields["secret"], b.fields["secret"]);
    assert_ne!(a.fields["nick"], b.fields["nick"]);
    assert_ne!(a.body, b.body);
}

#[test]
fn identity_values_are_stable_across_forms_of_one_run() {
    let one = plain(r#"<form method="post" action="/a"><input name="mail" type="email"></form>"#);
    let two = plain(
        r#"<form method="post" action="/b"><input name="e" type="email"><input name="pw" type="password"></form>"#,
    );
    assert_eq!(one.fields["mail"], two.fields["e"]);
}

#[test]
fn filler_text_is_scoped_to_the_page() {
    let f = form(r#"<form method="post" action="/r"><input name="nick"></form>"#);
    let cfg = FormFill::default();
    let seed = CrawlSeed(5);
    let a = fill_form(
        &f,
        &Url::parse("https://a.example/p").unwrap(),
        &cfg,
        &seed,
        &no_answers(),
    );
    let a2 = fill_form(
        &f,
        &Url::parse("https://a.example/p").unwrap(),
        &cfg,
        &seed,
        &no_answers(),
    );
    let b = fill_form(
        &f,
        &Url::parse("https://a.example/q").unwrap(),
        &cfg,
        &seed,
        &no_answers(),
    );
    assert_eq!(a.fields["nick"], a2.fields["nick"]);
    assert_ne!(a.fields["nick"], b.fields["nick"]);
    assert!(Regex::new("^[a-z]{8}$").unwrap().is_match(&a.fields["nick"]));
}

#[test]
fn unresolved_lists_only_text_controls_no_rule_classified() {
    let f = plain(
        r#"<form method="post" action="/r">
            <input name="mail" type="email"><input name="username">
            <input name="nick" placeholder="Your nickname" pattern="[a-z]+">
            <textarea name="bio"></textarea>
            <input name="kept" value="x"><input name="n" type="number">
            <input name="weird" type="frobnicate">
        </form>"#,
    );
    let got: Vec<(&str, &str, Option<&str>, Option<&str>)> = f
        .unresolved
        .iter()
        .map(|u| {
            (
                u.name.as_str(),
                u.input_type.as_str(),
                u.placeholder.as_deref(),
                u.pattern.as_deref(),
            )
        })
        .collect();
    assert_eq!(
        got,
        [
            ("nick", "text", Some("Your nickname"), Some("[a-z]+")),
            ("bio", "textarea", None, None),
            ("weird", "frobnicate", None, None),
        ]
    );
    assert!(
        Regex::new("^[a-z]+$").unwrap().is_match(&f.fields["nick"]),
        "the pattern wins over the placeholder attribute"
    );
}

#[test]
fn fallback_order_is_placeholder_attribute_then_configured_placeholder() {
    let cfg = FormFill {
        placeholder: Some("cfg-value".to_owned()),
        ..FormFill::default()
    };
    let f = fill(
        r#"<form method="post" action="/r"><input name="a" placeholder="hint"><input name="b"></form>"#,
        &cfg,
        1,
    );
    assert_eq!(f.fields["a"], "hint");
    assert_eq!(f.fields["b"], "cfg-value");
    assert_eq!(
        f.unresolved.len(),
        2,
        "the model is still asked: the reference asks before it falls back"
    );
}

#[test]
fn decided_answers_win_and_clear_unresolved() {
    let html = r#"<form method="post" action="/r">
        <input name="nick"><textarea name="bio"></textarea>
        <input name="mail" type="email"><input name="code" pattern="[0-9]{3}"><input name="short" maxlength="3">
    </form>"#;
    let f = form(html);
    let cfg = FormFill {
        email: Some("cfg@x.test".to_owned()),
        ..FormFill::default()
    };
    let seed = CrawlSeed(2);
    let first = fill_form(&f, &page(), &cfg, &seed, &no_answers());
    let asked: Vec<&str> = first.unresolved.iter().map(|u| u.name.as_str()).collect();
    assert_eq!(asked, ["nick", "bio", "code", "short"]);

    let answers: BTreeMap<String, String> = [
        ("nick", "Zed"),
        ("mail", "ai@x.test"),
        ("code", "abc"),
        ("short", "zzzzzz"),
    ]
    .iter()
    .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
    .collect();
    let second = fill_form(&f, &page(), &cfg, &seed, &answers);
    assert_eq!(second.fields["nick"], "Zed");
    assert_eq!(
        second.fields["mail"], "ai@x.test",
        "an answer beats the configured value"
    );
    assert!(
        Regex::new("^[0-9]{3}$").unwrap().is_match(&second.fields["code"]),
        "an answer the pattern rejects is replaced by a conforming value"
    );
    assert_eq!(second.fields["short"], "zzz", "maxlength truncates an answer");
    let still: Vec<&str> = second.unresolved.iter().map(|u| u.name.as_str()).collect();
    assert_eq!(still, ["bio"]);
    assert_eq!(
        second.fields["bio"], first.fields["bio"],
        "unanswered fields keep their seeded value"
    );
}

#[test]
fn answers_do_not_touch_prefilled_or_hidden_fields() {
    let f = form(
        r#"<form method="post" action="/r"><input name="csrf" type="hidden" value="tok"><input name="keep" value="v"></form>"#,
    );
    let answers: BTreeMap<String, String> = [("csrf", "x"), ("keep", "y")]
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let out = fill_form(&f, &page(), &FormFill::default(), &CrawlSeed(1), &answers);
    assert_eq!(out.fields["csrf"], "tok");
    assert_eq!(out.fields["keep"], "v");
}

// ------------------------------------------------------------ -fc DSL and file

#[test]
fn form_config_yaml_resolves_helpers_per_seed() {
    let cfg = parse_form_config(
        "email: \"rand_email()\"\nphone: \"rand_phone()\"\nplaceholder: \"rand_first_name()\"\npassword: 'rand_base(16, \"\")'\ncolor: \"#e66465\"\n",
    )
    .unwrap();
    assert_eq!(cfg.email.as_deref(), Some("rand_email()"));
    assert_eq!(cfg.password.as_deref(), Some("rand_base(16, \"\")"));
    assert_eq!(cfg.color.as_deref(), Some("#e66465"));
    assert!(!cfg.enabled, "-fc supplies values; -aff enables filling");

    let html = r#"<form method="post" action="/r">
        <input name="mail" type="email"><input name="mobile" type="tel">
        <input name="secret" type="password"><input name="shade" type="color"><input name="nick">
    </form>"#;
    let a = fill(html, &cfg, 21);
    assert!(a.fields["mail"].ends_with("@example.org"));
    assert_ne!(a.fields["mail"], "rand_email()");
    assert_eq!(a.fields["mobile"].len(), 10);
    assert_eq!(a.fields["secret"].len(), 16);
    assert_eq!(a.fields["shade"], "#e66465");
    assert!(
        Regex::new("^[A-Z][a-z]+$").unwrap().is_match(&a.fields["nick"]),
        "{:?}",
        a.fields["nick"]
    );
    assert_eq!(a, fill(html, &cfg, 21), "helpers are deterministic for a seed");
    assert_ne!(a.fields["mail"], fill(html, &cfg, 22).fields["mail"]);
}

#[test]
fn unknown_helpers_stay_literal_and_nothing_executes() {
    let cfg = FormFill {
        email: Some("rand_nope()".to_owned()),
        password: Some("system('id')".to_owned()),
        ..FormFill::default()
    };
    let f = fill(
        r#"<form method="post" action="/r"><input name="e" type="email"><input name="p" type="password"></form>"#,
        &cfg,
        1,
    );
    assert_eq!(f.fields["e"], "rand_nope()");
    assert_eq!(f.fields["p"], "system('id')");
}

#[test]
fn parse_form_config_cases() {
    let cfg = parse_form_config("email: me@x.test\nphone: 2124567890\npassword: true\nplaceholder: \"\"\n")
        .unwrap();
    assert_eq!(cfg.email.as_deref(), Some("me@x.test"));
    assert_eq!(
        cfg.phone.as_deref(),
        Some("2124567890"),
        "numbers are accepted as scalars"
    );
    assert_eq!(cfg.password.as_deref(), Some("true"));
    assert_eq!(cfg.placeholder, None, "an empty string leaves the key unset");
    assert_eq!(
        cfg.color, None,
        "missing keys stay unset so the seeded default applies"
    );

    assert_eq!(parse_form_config("").unwrap(), FormFill::default());
    assert_eq!(parse_form_config("# nothing\n").unwrap(), FormFill::default());

    assert!(matches!(parse_form_config("emial: x\n"), Err(FormConfigError::UnknownKey(k)) if k == "emial"));
    assert!(matches!(
        parse_form_config("- a\n- b\n"),
        Err(FormConfigError::NotAMapping)
    ));
    assert!(matches!(parse_form_config("email: [a]\n"), Err(FormConfigError::NotScalar(k)) if k == "email"));
    let yaml_err = parse_form_config("email: [unclosed\n").unwrap_err();
    assert!(matches!(yaml_err, FormConfigError::Yaml(_)));
    assert!(
        std::error::Error::source(&yaml_err).is_some(),
        "the yaml error is chained"
    );
}
