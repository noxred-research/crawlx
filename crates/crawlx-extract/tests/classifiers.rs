#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Tables for the classifiers: custom regex fields, page type,
//! secrets (with the Debug-redaction assertion) and technologies.

use crawlx_extract::custom_fields::{self, CustomField, CustomFieldSpec, Part};
use crawlx_extract::page_type::{self, PageInput, PageType};
use crawlx_extract::secrets::{self, Location, SecretKind};
use crawlx_extract::technologies::{Catalog, CatalogFile, TechInput, CATALOG, CATALOG_JSON, CATEGORIES};
use crawlx_extract::{technologies, ExtractOptions, Extractor, Technology};
use scraper::Html;
use url::Url;

fn page() -> Url {
    Url::parse("https://example.com/p").unwrap()
}

fn hdrs(h: &[(&str, &str)]) -> Vec<(String, String)> {
    h.iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

// ---------------------------------------------------------------- custom fields

#[test]
fn custom_fields_body_header_response_and_group() {
    let specs = vec![
        CustomFieldSpec {
            name: "email".to_owned(),
            regex: vec![r"([a-zA-Z0-9._-]+)@([a-zA-Z0-9._-]+\.[a-zA-Z]+)".to_owned()],
            part: Part::Body,
            group: 1,
        },
        CustomFieldSpec {
            name: "server".to_owned(),
            regex: vec![r"(?i)^server: (\S+)".to_owned()],
            part: Part::Header,
            group: 1,
        },
        CustomFieldSpec {
            name: "ids".to_owned(),
            regex: vec![r"id-\d+".to_owned(), r"X-Req: (\w+)".to_owned()],
            part: Part::Response,
            group: 0,
        },
        CustomFieldSpec {
            name: "absent".to_owned(),
            regex: vec!["zzz".to_owned()],
            part: Part::Body,
            group: 0,
        },
    ];
    let fields = CustomField::compile_all(&specs).unwrap();
    let headers = hdrs(&[("Server", "nginx/1.25"), ("X-Req", "abc")]);
    let body = "contact alice@example.org or bob@example.net; id-1 id-2";
    let got = custom_fields::extract(&fields, &headers, body);
    assert_eq!(got["email"], vec!["alice", "bob"]);
    assert_eq!(got["server"], vec!["nginx/1.25"]);
    assert_eq!(got["ids"], vec!["id-1", "id-2", "X-Req: abc"]);
    assert!(!got.contains_key("absent"));

    // Through the extractor, with the request-level shape.
    let opts = ExtractOptions {
        custom_fields: fields,
        headers,
        ..ExtractOptions::default()
    };
    let doc = Extractor::extract(&format!("<p>{body}</p>"), &page(), &opts).unwrap();
    assert_eq!(doc.custom_fields["email"], vec!["alice", "bob"]);
    assert_eq!(doc.custom_fields["server"], vec!["nginx/1.25"]);
    let none = Extractor::extract("<p>x</p>", &page(), &ExtractOptions::default()).unwrap();
    assert!(none.custom_fields.is_empty());
}

// ---------------------------------------------------------------- page type

fn classify(html: &str, status: u16, headers: &[(&str, &str)]) -> PageType {
    let doc = Html::parse_document(html);
    let base = page();
    let forms = crawlx_extract::forms::extract(&doc, &base);
    let title = doc
        .select(&scraper::Selector::parse("title").unwrap())
        .next()
        .map(|t| t.text().collect::<String>());
    let text: String = doc
        .select(&scraper::Selector::parse("body").unwrap())
        .next()
        .map(|b| b.text().collect::<Vec<_>>().join(" "))
        .unwrap_or_default();
    page_type::classify(&PageInput {
        doc: &doc,
        title: title.as_deref(),
        text: &text,
        forms: &forms,
        status,
        headers: &hdrs(headers),
    })
}

fn long_article(words: usize) -> String {
    let body: String = (0..words).map(|i| format!("word{i} ")).collect();
    format!("<html><head><title>Why crawlers crawl</title></head><body><article><h1>Why</h1><p>{body}</p><p>{body}</p><p>{body}</p></article></body></html>")
}

fn listing(n: usize) -> String {
    let items: String = (0..n)
        .map(|i| format!(r#"<li class="card"><a href="/item/{i}">Item {i}</a><span>$1</span></li>"#))
        .collect();
    format!("<html><head><title>Catalog</title></head><body><ul class=grid>{items}</ul></body></html>")
}

/// `(name, html, status, headers, expected)`.
type PageCase = (
    &'static str,
    String,
    u16,
    Vec<(&'static str, &'static str)>,
    PageType,
);

#[test]
fn page_type_table() {
    let cases: Vec<PageCase> = vec![
        (
            "login: password input",
            r#"<title>Sign in</title><form method=post action=/login><input name=u><input type=password name=p></form>"#.to_owned(),
            200,
            vec![],
            PageType::Login,
        ),
        (
            "login: password wins over long text",
            format!("{}<form><input name=e type=email><input type=password name=p></form>", long_article(400)),
            200,
            vec![],
            PageType::Login,
        ),
        ("error: 404 status", "<title>Home</title><p>hello</p>".to_owned(), 404, vec![], PageType::Error),
        (
            "error: title on a short page",
            "<title>Page not found</title><p>Sorry, nothing here.</p>".to_owned(),
            200,
            vec![],
            PageType::Error,
        ),
        (
            "error: phrase in text",
            "<title>Site</title><p>The page you requested could not be found.</p>".to_owned(),
            200,
            vec![],
            PageType::Error,
        ),
        (
            "captcha: checkbox widget family A",
            r#"<title>Check</title><div class="g-recaptcha" data-sitekey="k"></div><script src="https://www.google.com/recaptcha/api.js"></script>"#.to_owned(), // wire-compat: markup and script URL of widget family A
            200,
            vec![],
            PageType::Captcha,
        ),
        (
            "challenge widget family C + vendor title",
            r#"<title>Just a moment...</title><div class="cf-turnstile"></div>"#.to_owned(), // wire-compat: markup class of widget family C
            403,
            vec![],
            PageType::Captcha,
        ),
        (
            "captcha: challenge widget family B script",
            r#"<title>Verify</title><script src="https://js.hcaptcha.com/1/api.js"></script><p>Please complete the security check</p>"#.to_owned(), // wire-compat: script URL of widget family B
            200,
            vec![],
            PageType::Captcha,
        ),
        (
            "captcha: cf-mitigated header",
            "<title>x</title><p>y</p>".to_owned(),
            503,
            vec![("cf-mitigated", "challenge")],
            PageType::Captcha,
        ),
        (
            "parked: for sale",
            "<title>example.com</title><p>This domain is for sale! Contact us.</p>".to_owned(),
            200,
            vec![],
            PageType::Parked,
        ),
        (
            "parked: sedo",
            "<title>example.com</title><p>Powered by Sedoparking. The domain owner has not yet put up a website.</p>".to_owned(),
            200,
            vec![],
            PageType::Parked,
        ),
        (
            "search: search input plus results",
            r#"<title>Search</title><form action=/s><input type=search name=q></form><p>12 results for "cats"</p><ul><li><a href=/1>a</a></li></ul>"#.to_owned(),
            200,
            vec![],
            PageType::Search,
        ),
        (
            "search: named q input plus repeated cards",
            format!(r#"<form action=/s><input name=q></form>{}"#, listing(6)),
            200,
            vec![],
            PageType::Search,
        ),
        ("listing: six linked cards", listing(6), 200, vec![], PageType::Listing),
        (
            "listing: repeated articles",
            (0..5)
                .map(|i| format!(r#"<article><h2><a href="/post/{i}">Post {i}</a></h2><p>teaser</p></article>"#))
                .collect::<String>(),
            200,
            vec![],
            PageType::Listing,
        ),
        ("article: long text in article markup", long_article(400), 200, vec![], PageType::Article),
        (
            "article: long text with paragraphs",
            format!("<title>Essay</title>{}", (0..4).map(|_| format!("<p>{}</p>", "lorem ".repeat(100))).collect::<String>()),
            200,
            vec![],
            PageType::Article,
        ),
        (
            "form: contact form",
            r#"<title>Contact</title><form method=post action=/contact><input name=name><input type=email name=email><textarea name=msg></textarea></form>"#.to_owned(),
            200,
            vec![],
            PageType::Form,
        ),
        (
            "form: signup without password field",
            r#"<form action=/subscribe><input name=first><input name=last><input type=hidden name=t value=1></form>"#.to_owned(),
            200,
            vec![],
            PageType::Form,
        ),
        ("unknown: short plain page", "<title>Hi</title><p>Hello world</p>".to_owned(), 200, vec![], PageType::Unknown),
        (
            "unknown: search box alone is not a search page",
            r#"<title>Home</title><form action=/s><input name=q></form><p>Welcome</p>"#.to_owned(),
            200,
            vec![],
            PageType::Unknown,
        ),
    ];
    for (name, html, status, headers, want) in &cases {
        assert_eq!(classify(html, *status, headers), *want, "{name}");
    }
    for ty in [
        PageType::Login,
        PageType::Error,
        PageType::Captcha,
        PageType::Parked,
        PageType::Search,
        PageType::Listing,
        PageType::Article,
        PageType::Form,
        PageType::Unknown,
    ] {
        assert!(
            cases.iter().filter(|c| c.4 == ty).count() >= 2,
            "{ty:?} needs two cases"
        );
    }
}

#[test]
fn extractor_fills_page_type_and_forms() {
    let html = r#"<title>Sign in</title><form method=post action=/login><input name=u><input type=password name=p></form>"#;
    let doc = Extractor::extract(html, &page(), &ExtractOptions::default()).unwrap();
    assert_eq!(doc.page_type, Some(PageType::Login));
    assert_eq!(doc.forms.len(), 1);
    assert_eq!(doc.forms[0].inputs[1].kind, "password");
    let off = Extractor::extract(
        html,
        &page(),
        &ExtractOptions {
            forms: false,
            page_type: false,
            technologies: false,
            ..ExtractOptions::default()
        },
    )
    .unwrap();
    assert!(off.forms.is_empty());
    assert!(off.page_type.is_none());
    assert!(off.technologies.is_empty());
    let err = Extractor::extract(
        "<title>Home</title><p>x</p>",
        &page(),
        &ExtractOptions {
            status: 500,
            ..ExtractOptions::default()
        },
    )
    .unwrap();
    assert_eq!(err.page_type, Some(PageType::Error));
}

// ---------------------------------------------------------------- secrets

const KEY: [u8; 32] = [7u8; 32];

#[test]
fn secrets_table_and_redaction() {
    assert!(secrets::rules_compiled());
    // Synthetic detector canaries; provider-shaped values are assembled from parts so the source holds no contiguous token.
    let cloud_id = concat!("AKIA", "IOSFODNN7EXAMPLE");
    let cloud_secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let ghp = format!(
        "{}{}",
        concat!("gh", "p_"),
        "A1b2C3d4".repeat(5).chars().take(36).collect::<String>()
    );
    let pat = concat!(
        "github_",
        "pat_11ABCDEFG0123456789_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRS"
    );
    let chat_tok = concat!("xo", "xb-123456789012-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx");
    let pay_tok = concat!("sk_", "live_4eC39HqLyjWDarjtT1zdp7dc");
    let search_tok = concat!("AI", "zaSyD-1234567890abcdefghijklmnopqrstu");
    let jwt = concat!(
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.",
        "eyJzdWIiOiIxMjM0NTY3ODkwIn0.",
        "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    );
    let pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK\nabc\n-----END RSA PRIVATE KEY-----";
    let generic_value = "Zx9kQpL2mN8vB4cR7tY1";

    // `(name, text containing the secret, the secret value, kind)`.
    let cases: Vec<(&str, String, &str, SecretKind)> = vec![
        (
            "cloud id",
            cloud_id.to_owned(),
            cloud_id,
            SecretKind::AwsAccessKeyId,
        ), // detection-data
        (
            "cloud secret",
            format!("aws_secret_access_key = \"{cloud_secret}\""), // detection-data
            cloud_secret,
            SecretKind::AwsSecretAccessKey, // detection-data
        ),
        (
            "cloud secret yaml",
            format!("AWS-SECRET: {cloud_secret}\n"), // detection-data
            cloud_secret,
            SecretKind::AwsSecretAccessKey, // detection-data
        ),
        ("ghp", ghp.clone(), &ghp, SecretKind::GitHubToken),
        ("github pat", pat.to_owned(), pat, SecretKind::GitHubToken),
        ("chat", chat_tok.to_owned(), chat_tok, SecretKind::SlackToken), // detection-data
        ("payment", pay_tok.to_owned(), pay_tok, SecretKind::StripeKey), // detection-data
        (
            "search",
            search_tok.to_owned(),
            search_tok,
            SecretKind::GoogleApiKey,
        ), // detection-data
        ("jwt", jwt.to_owned(), jwt, SecretKind::Jwt),
        ("pem", pem.to_owned(), pem, SecretKind::PrivateKey),
        (
            "generic",
            format!("api_key={generic_value}"),
            generic_value,
            SecretKind::GenericApiKey,
        ),
        (
            "generic json",
            format!(r#""apiKey": "{generic_value}""#),
            generic_value,
            SecretKind::GenericApiKey,
        ),
    ];
    for (name, text, value, kind) in &cases {
        let body = format!("prefix {text} suffix");
        let found = secrets::detect(&KEY, &[], &body);
        assert_eq!(found.len(), 1, "{name}: {found:?}");
        assert_eq!(found[0].kind, *kind, "{name}");
        assert!(
            matches!(found[0].location, Location::Body { offset } if offset >= 7),
            "{name}"
        );
        assert_eq!(found[0].preview_len, value.len(), "{name}");
        // The raw value never appears in Debug or JSON output.
        let dbg = format!("{found:?}");
        let json = serde_json::to_string(&found).unwrap();
        let needle: String = value
            .chars()
            .filter(|c| c.is_ascii_alphanumeric())
            .take(10)
            .collect();
        assert!(!dbg.contains(&needle), "{name}: Debug leaks value: {dbg}");
        assert!(!json.contains(&needle), "{name}: JSON leaks value: {json}");
        assert!(!dbg.contains(value) && !json.contains(value), "{name}");
    }

    // Headers: location names the header; hashes are keyed.
    let headers = hdrs(&[
        ("Authorization", &format!("Bearer {jwt}")),
        ("X-Api-Key", "nothing"),
    ]);
    let found = secrets::detect(&KEY, &headers, "");
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].location,
        Location::Header {
            name: "Authorization".to_owned()
        }
    );
    let other = secrets::detect(&[9u8; 32], &headers, "");
    assert_ne!(found[0].value_hash, other[0].value_hash);
    assert_eq!(
        found[0].value_hash,
        secrets::detect(&KEY, &headers, "")[0].value_hash
    );

    // Ordering: headers first, then body by offset; pay_tok is not re-reported as a generic key.
    let body = format!("api_key={pay_tok} then {cloud_id}");
    let found = secrets::detect(&KEY, &headers, &body);
    assert_eq!(
        found.iter().map(|f| f.kind).collect::<Vec<_>>(),
        vec![SecretKind::Jwt, SecretKind::StripeKey, SecretKind::AwsAccessKeyId] // detection-data
    );
    assert!(!format!("{found:?}").contains("4eC39HqLyjWDarjtT1zdp7dc"));

    // Clean text: nothing.
    assert!(secrets::detect(&KEY, &[], "hello world, nothing to see; version 1.2.3").is_empty());
    assert!(Extractor::detect_secrets(&KEY, &[], &format!("<p>{cloud_id}</p>")).len() == 1);
}

// ---------------------------------------------------------------- technologies

fn tech(headers: &[(&str, &str)], html: &str, url: Option<&Url>, globals: &[&str]) -> Vec<Technology> {
    let headers = hdrs(headers);
    let globals: Vec<String> = globals.iter().map(|g| (*g).to_owned()).collect();
    let doc = Html::parse_document(html);
    technologies::detect(
        &TechInput {
            url,
            headers: &headers,
            html,
            js_globals: &globals,
        },
        &doc,
    )
}

fn by_name<'a>(got: &'a [Technology], name: &str) -> &'a Technology {
    got.iter()
        .find(|t| t.name == name)
        .unwrap_or_else(|| panic!("{name} missing in {got:?}"))
}

/// The embedded catalog: valid schema, every pattern compiles, closed category set,
/// resolvable `implies`, no empty entries, at least 80 technologies.
#[test]
fn technology_catalog_schema() {
    let file: CatalogFile = serde_json::from_str(CATALOG_JSON).unwrap();
    assert_eq!(file.version, 1);
    assert!(
        file.technologies.len() >= 80,
        "{} entries",
        file.technologies.len()
    );
    for (name, e) in &file.technologies {
        assert!(
            CATEGORIES.contains(&e.category.as_str()),
            "{name}: {}",
            e.category
        );
        for implied in &e.implies {
            assert!(
                file.technologies.contains_key(implied),
                "{name} implies {implied}"
            );
            assert_ne!(implied, name, "{name} implies itself");
        }
        let keyed = e.headers.len() + e.cookies.len() + e.meta.len();
        let listed = e.script_src.len() + e.html.len() + e.js_globals.len() + e.url.len();
        let implied_only = ["Windows Server", "Python", "Node.js", "Ruby"].contains(&name.as_str());
        assert!(
            keyed + listed > 0 || implied_only,
            "{name} has no pattern and is not an implied-only entry"
        );
        for h in e.headers.keys() {
            assert_eq!(h, &h.to_ascii_lowercase(), "{name}: header names are lower-case");
        }
        for m in e.meta.keys() {
            assert_eq!(m, &m.to_ascii_lowercase(), "{name}: meta names are lower-case");
        }
    }
    let catalog = Catalog::parse(CATALOG_JSON).unwrap();
    assert_eq!(catalog.len(), file.technologies.len());
    assert!(!catalog.is_empty());
    assert!(CATALOG.is_some());
    assert!(catalog
        .names()
        .collect::<Vec<_>>()
        .windows(2)
        .all(|w| w[0] < w[1]));
    assert_eq!(catalog.category("nginx"), Some("web-server"));
    let categories: std::collections::BTreeSet<&str> =
        file.technologies.values().map(|e| e.category.as_str()).collect();
    for c in [
        "web-server",
        "cdn",
        "framework",
        "cms",
        "e-commerce",
        "analytics",
        "tag-manager",
        "js-library",
        "bundler",
        "hosting",
        "security",
        "auth",
    ] {
        assert!(categories.contains(c), "no {c} entry");
    }
}

#[test]
fn technologies_headers_with_version_and_implies() {
    let got = tech(
        &[
            ("Server", "nginx/1.25.3"),
            ("X-Powered-By", "PHP/8.2.4"),
            ("X-Generator", "Drupal 10 (https://www.drupal.org)"),
            ("cf-ray", "abc-FRA"),
            ("X-AspNet-Version", "4.0.30319"),
        ],
        "<html></html>",
        None,
        &[],
    );
    let nginx = by_name(&got, "nginx");
    assert_eq!(nginx.evidence, "header:server");
    assert_eq!(nginx.version.as_deref(), Some("1.25.3"));
    assert_eq!(nginx.category, "web-server");
    assert_eq!(by_name(&got, "PHP").version.as_deref(), Some("8.2.4"));
    let drupal = by_name(&got, "Drupal");
    assert_eq!(drupal.evidence, "header:x-generator");
    assert_eq!(drupal.version.as_deref(), Some("10"));
    assert_eq!(by_name(&got, "Cloudflare").evidence, "header:cf-ray"); // detection-data
    assert_eq!(by_name(&got, "ASP.NET").version.as_deref(), Some("4.0.30319"));
    // header names are case-insensitive, values are anchored
    assert!(tech(&[("SERVER", "not-nginx")], "", None, &[])
        .iter()
        .all(|t| t.name != "nginx"));
}

#[test]
fn technologies_cookies() {
    let got = tech(
        &[
            ("Set-Cookie", "laravel_session=abc; Path=/; HttpOnly"),
            ("set-cookie", "JSESSIONID=1234; Path=/"),
            ("Set-Cookie", "ASP.NET_SessionId=x"),
        ],
        "",
        None,
        &[],
    );
    assert_eq!(by_name(&got, "Laravel").evidence, "cookie:laravel_session");
    assert_eq!(by_name(&got, "PHP").evidence, "implied:Laravel");
    assert_eq!(by_name(&got, "Java").evidence, "cookie:JSESSIONID");
    assert_eq!(by_name(&got, "ASP.NET").evidence, "cookie:ASP.NET_SessionId");
}

#[test]
fn technologies_meta() {
    let html = r#"<html><head><meta name="Generator" content="WordPress 6.5.2"></head></html>"#;
    let got = tech(&[], html, None, &[]);
    let wp = by_name(&got, "WordPress");
    assert_eq!(wp.evidence, "meta:generator");
    assert_eq!(wp.version.as_deref(), Some("6.5.2"));
    assert_eq!(wp.category, "cms");
    assert_eq!(by_name(&got, "PHP").evidence, "implied:WordPress");
    let got = tech(
        &[],
        r#"<meta name="generator" content="Astro v4.5.0">"#,
        None,
        &[],
    );
    assert_eq!(by_name(&got, "Astro").version.as_deref(), Some("4.5.0"));
}

#[test]
fn technologies_script_src() {
    let html = r#"<html><head>
        <script src="https://code.jquery.com/jquery-3.7.1.min.js"></script>
        <script src="/_next/static/chunks/main.js"></script>
        <script src="https://unpkg.com/react@18.2.0/umd/react-dom.production.min.js"></script>
        <script src="https://www.googletagmanager.com/gtm.js?id=GTM-XXXX"></script>
        </head><body></body></html>"#;
    let got = tech(&[], html, None, &[]);
    let jq = by_name(&got, "jQuery");
    assert_eq!(jq.evidence, "script_src");
    assert_eq!(jq.version.as_deref(), Some("3.7.1"));
    assert_eq!(by_name(&got, "Next.js").evidence, "script_src");
    let react = by_name(&got, "React");
    assert_eq!(react.version.as_deref(), Some("18.2.0"));
    assert_eq!(by_name(&got, "unpkg").category, "cdn");
    assert_eq!(by_name(&got, "Google Tag Manager").category, "tag-manager"); // detection-data
    assert_eq!(by_name(&got, "Node.js").evidence, "implied:Next.js");
}

#[test]
fn technologies_html() {
    let html = r#"<html><head>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css">
        </head><body><div id="__nuxt"></div><form><input type="hidden" name="csrfmiddlewaretoken" value="x"></form>
        <script type="application/json" id="__NEXT_DATA__">{}</script></body></html>"#;
    let got = tech(&[], html, None, &[]);
    let bs = by_name(&got, "Bootstrap");
    assert_eq!(bs.evidence, "html");
    assert_eq!(by_name(&got, "Nuxt").evidence, "html");
    assert_eq!(by_name(&got, "Django").evidence, "html");
    assert_eq!(by_name(&got, "Python").evidence, "implied:Django");
    assert_eq!(by_name(&got, "Next.js").evidence, "html");
    // without the raw markup, html patterns do not fire
    let doc = Html::parse_document(html);
    let got = technologies::detect(
        &TechInput {
            url: None,
            headers: &[],
            html: "",
            js_globals: &[],
        },
        &doc,
    );
    assert!(got.iter().all(|t| t.name != "Bootstrap"), "{got:?}");
}

#[test]
fn technologies_js_globals_and_url() {
    let got = tech(&[], "", None, &["Shopify", "jQuery", "__NEXT_DATA__"]);
    assert_eq!(by_name(&got, "Shopify").evidence, "js_global:Shopify");
    assert_eq!(by_name(&got, "jQuery").evidence, "js_global:jQuery");
    assert_eq!(by_name(&got, "Next.js").evidence, "js_global:__NEXT_DATA__");
    assert_eq!(by_name(&got, "React").evidence, "implied:Next.js");
    let url = Url::parse("https://my-site.pages.dev/index.html").unwrap();
    let got = tech(&[], "", Some(&url), &[]);
    assert_eq!(by_name(&got, "Cloudflare Pages").evidence, "url"); // detection-data
    assert_eq!(by_name(&got, "Cloudflare").evidence, "implied:Cloudflare Pages");
    // detection-data
}

/// Evidence kinds rank headers > cookies > meta > script_src > js_globals > html > url;
/// output is sorted by name and identical across runs; the extractor reports the same list.
#[test]
fn technologies_deterministic_through_extractor() {
    let headers = [
        ("Server", "nginx/1.25.3"),
        ("Set-Cookie", "wordpress_test_cookie=1"),
    ];
    let html = r#"<html><head>
        <meta name="generator" content="WordPress 6.5">
        <script src="/wp-includes/js/jquery/jquery.min.js"></script>
        <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5/dist/css/bootstrap.min.css">
        </head><body></body></html>"#;
    let got = tech(&headers, html, Some(&page()), &[]);
    assert_eq!(got, tech(&headers, html, Some(&page()), &[]));
    assert!(got.windows(2).all(|w| w[0].name < w[1].name), "sorted output");
    assert_eq!(got.iter().filter(|t| t.name == "WordPress").count(), 1);
    assert_eq!(
        by_name(&got, "WordPress").evidence,
        "cookie:wordpress_test_cookie"
    );
    assert_eq!(by_name(&got, "jQuery").evidence, "script_src");
    assert_eq!(by_name(&got, "Bootstrap").evidence, "html");

    let doc = Extractor::extract(
        html,
        &page(),
        &ExtractOptions {
            headers: hdrs(&headers),
            ..ExtractOptions::default()
        },
    )
    .unwrap();
    assert_eq!(doc.technologies, got);
    assert!(
        Extractor::extract("<p>x</p>", &page(), &ExtractOptions::default())
            .unwrap()
            .technologies
            .is_empty()
    );
    // round trip keeps category and version; old records without them still load
    let json = serde_json::to_string(&got).unwrap();
    let back: Vec<Technology> = serde_json::from_str(&json).unwrap();
    assert_eq!(back, got);
    let old: Technology = serde_json::from_str(r#"{"name":"nginx","evidence":"header:server"}"#).unwrap();
    assert_eq!(old.category, "");
    assert_eq!(old.version, None);
}
