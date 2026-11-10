#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Knowledge base (`-kb`, `-kb-endpoints`): endpoint classes,
//! form labels and field roles, and the serialized `knowledgebase` record.

use crawlx_extract::endpoints::{body, Confidence, DiscoveredEndpoint, EndpointSource};
use crawlx_extract::forms::{self, StaticForm};
use crawlx_extract::kb::{
    classify_discovered, classify_endpoint, classify_form, field_roles, EndpointClass, KbEndpoint, KbForm,
    KbSecret, KnowledgeBase,
};
use crawlx_extract::page_type::PageType;
use crawlx_extract::secret_validation::Validity;
use crawlx_extract::secrets;
use http::Method;
use url::Url;

fn url(path: &str) -> Url {
    Url::parse(&format!("https://api.example{path}")).unwrap()
}

fn form(html: &str) -> StaticForm {
    forms::extract_str(html, &Url::parse("https://shop.example/").unwrap())
        .unwrap()
        .remove(0)
}

// ------------------------------------------------------------ endpoint classes

#[test]
fn classify_endpoint_table() {
    use EndpointClass::{Graphql, Rest, Soap, Static, Xhr};
    let json = Some("application/json");
    let table: &[(&str, &str, Option<&str>, &str, EndpointClass)] = &[
        // GraphQL: a path segment or the media type, never a substring or the query.
        ("/graphql", "POST", json, "", Graphql),
        ("/api/graphql", "GET", None, "", Graphql),
        ("/GraphQL", "POST", None, "", Graphql),
        ("/q", "POST", Some("application/graphql"), "", Graphql),
        ("/notgraphql/blob", "POST", json, "", Rest),
        ("/x?graphql=1", "GET", Some("text/html"), "", Static),
        // SOAP.
        (
            "/ws",
            "POST",
            Some("application/soap+xml; charset=utf-8"),
            "",
            Soap,
        ),
        ("/svc/Orders.asmx", "POST", Some("text/xml"), "", Soap),
        ("/soap/endpoint", "POST", Some("text/xml"), "", Soap),
        ("/x", "POST", None, "soapaction", Soap),
        // REST: structured body with a mutating verb or an API path.
        ("/data", "POST", json, "", Rest),
        ("/data", "PUT", json, "", Rest),
        ("/data", "PATCH", json, "", Rest),
        ("/data", "DELETE", json, "", Rest),
        ("/api/users", "GET", json, "", Rest),
        ("/v2/users", "GET", Some("application/vnd.api+json"), "", Rest),
        ("/rest/x", "GET", Some("application/xml"), "", Rest),
        ("/jsonrpc", "GET", Some("text/xml"), "", Rest),
        ("/x", "POST", Some("application/xml"), "", Rest),
        ("/x", "POST", Some("text/xml"), "", Rest),
        ("/x", "post", Some("Application/JSON; charset=UTF-8"), "", Rest),
        ("/x", "POST", Some("application/x-www-form-urlencoded"), "", Rest),
        ("/x", "POST", Some("multipart/form-data; boundary=zz"), "", Rest),
        // XHR: JSON GET off the API paths.
        ("/data", "GET", json, "", Xhr),
        ("/data", "GET", Some("Application/JSON; charset=UTF-8"), "", Xhr),
        ("/data", "GET", Some("application/vnd.api+json"), "", Xhr),
        // Everything else is static.
        ("/page", "GET", Some("text/html"), "", Static),
        ("/api/x", "GET", Some("text/html"), "", Static),
        (
            "/submit",
            "GET",
            Some("application/x-www-form-urlencoded"),
            "",
            Static,
        ),
        ("/x", "GET", Some("text/xml"), "", Static),
        ("/x", "HEAD", json, "", Static),
        ("/x", "GET", None, "", Static),
        ("/img.png", "GET", Some("image/png"), "fetch", Static),
        // The request tag stands in for a missing content type.
        ("/data", "GET", None, "xhr", Xhr),
        ("/data", "GET", None, "FETCH", Xhr),
        ("/data", "POST", None, "fetch", Rest),
        ("/api/v1/x", "GET", None, "axios", Rest),
        ("/data", "GET", None, "htmx", Xhr),
        ("/data", "GET", None, "a", Static),
        ("/data", "GET", None, "string", Static),
        ("/submit", "POST", None, "form", Rest),
        ("/submit", "GET", None, "form", Static),
        ("/data", "GET", Some("text/html"), "xhr", Static),
    ];
    for (path, method, ct, tag, want) in table {
        assert_eq!(
            classify_endpoint(&url(path), method, *ct, tag),
            *want,
            "{method} {path} ct={ct:?} tag={tag:?}"
        );
    }
}

#[test]
fn endpoint_class_wire_names_follow_the_observe_classifier() {
    let names: Vec<&str> = [
        EndpointClass::Rest,
        EndpointClass::Graphql,
        EndpointClass::Soap,
        EndpointClass::Xhr,
        EndpointClass::Static,
    ]
    .iter()
    .map(|c| c.as_str())
    .collect();
    assert_eq!(names, ["rest", "graphql", "soap", "xhr", "static"]);
    assert_eq!(
        serde_json::to_string(&EndpointClass::Graphql).unwrap(),
        "\"graphql\""
    );
}

fn discovered(
    source: EndpointSource,
    method: Method,
    path: &str,
    ct: Option<&str>,
    headers: &[&str],
) -> DiscoveredEndpoint {
    DiscoveredEndpoint {
        url: url(path),
        method,
        source,
        body: None,
        content_type: ct.map(str::to_owned),
        confidence: Confidence::Structural,
        depth: 1,
        headers: headers.iter().map(|h| (*h).to_owned()).collect(),
    }
}

#[test]
fn discovered_endpoints_classify_by_their_source() {
    use EndpointClass::{Rest, Soap, Static, Xhr};
    let get = Method::GET;
    let post = Method::POST;
    let rows = [
        (
            discovered(body::JS_FETCH, get.clone(), "/api/users", None, &[]),
            Rest,
        ),
        (discovered(body::JS_XHR, get.clone(), "/data", None, &[]), Xhr),
        (discovered(body::JS_AXIOS, post.clone(), "/data", None, &[]), Rest),
        (
            discovered(body::HTMX_POST, post.clone(), "/data", None, &[]),
            Rest,
        ),
        (
            discovered(
                body::FORM_ACTION,
                post.clone(),
                "/submit",
                Some("application/x-www-form-urlencoded"),
                &[],
            ),
            Rest,
        ),
        (
            discovered(body::FORM_ACTION, get.clone(), "/search", None, &[]),
            Static,
        ),
        (discovered(body::A_HREF, get.clone(), "/page", None, &[]), Static),
        (
            discovered(body::JS_STRING, get.clone(), "/api/x", None, &[]),
            Static,
        ),
        (
            discovered(
                body::JS_FETCH,
                post,
                "/rpc",
                None,
                &["content-type", "soapaction"],
            ),
            Soap,
        ),
    ];
    for (endpoint, want) in rows {
        assert_eq!(
            classify_discovered(&endpoint),
            want,
            "{} {}",
            endpoint.source.tag,
            endpoint.url
        );
        assert_eq!(KbEndpoint::from_discovered(&endpoint).is_some(), want != Static);
    }
}

#[test]
fn kb_endpoint_reports_reference_fields_without_credentials() {
    let u = Url::parse("https://user:pw@api.example/v1/items?id=1&q=2&id=3&=x#frag").unwrap();
    let e = KbEndpoint::new(
        &u,
        "post",
        Some("Application/JSON; charset=utf-8"),
        "",
        Some("Bearer abc.def"),
    )
    .unwrap();
    assert_eq!(e.class, EndpointClass::Rest);
    assert_eq!(e.method, "POST");
    assert_eq!(
        e.url, "https://api.example/v1/items?id=1&q=2&id=3&=x",
        "userinfo and fragment are stripped"
    );
    assert_eq!(e.content_type.as_deref(), Some("application/json"));
    assert_eq!(e.auth.as_deref(), Some("bearer"), "only the scheme is kept");
    assert_eq!(e.params, ["id", "q"], "first-seen order, deduplicated");
    let json = serde_json::to_string(&e).unwrap();
    assert!(!json.contains("abc.def") && !json.contains("user:pw"), "{json}");
    assert!(json.contains(r#""class":"rest""#));

    let bare = KbEndpoint::new(
        &url("/data"),
        "GET",
        Some("application/json"),
        "",
        Some("opaque-token"),
    )
    .unwrap();
    assert_eq!(
        bare.auth, None,
        "an Authorization value without a scheme is dropped"
    );
    assert!(bare.params.is_empty());
    let json = serde_json::to_string(&bare).unwrap();
    assert!(
        !json.contains("auth") && !json.contains("params"),
        "empty fields are omitted: {json}"
    );

    assert!(KbEndpoint::new(&url("/page"), "GET", Some("text/html"), "", None).is_none());
}

// ------------------------------------------------------------ forms

#[test]
fn classify_form_table() {
    let rows: &[(&str, &str)] = &[
        // login
        (
            r#"<form action="/session" method="post"><input name="user"><input type="password" name="pass">
               <input type="checkbox" name="remember"><button>Sign in</button></form>"#,
            "login",
        ),
        (
            r#"<form method="post"><input type="email" name="email"><input type="password" name="pw"></form>"#,
            "login",
        ),
        (
            r#"<form action="/login" method="post"><input name="username"></form>"#,
            "login",
        ),
        // registration
        (
            r#"<form method="post"><input type="email" name="email"><input type="password" name="password">
               <input type="password" name="password_confirm"></form>"#,
            "registration",
        ),
        (
            r#"<form action="/signup" method="post"><input type="email" name="email"><input name="username">
               <input type="password" name="password"></form>"#,
            "registration",
        ),
        (
            r#"<form method="post"><input name="first_name"><input type="email" name="email">
               <input type="password" name="password"></form>"#,
            "registration",
        ),
        (
            r#"<form action="/register" method="post"><input type="email" name="email"><input name="first_name"></form>"#,
            "registration",
        ),
        // password recovery
        (
            r#"<form action="/forgot-password" method="post"><input type="email" name="email"></form>"#,
            "password_recovery",
        ),
        (
            r#"<form method="post"><input type="password" name="password"><input type="password" name="password2">
               <button>Reset password</button></form>"#,
            "password_recovery",
        ),
        // payment
        (
            r#"<form action="/pay" method="post"><input name="card_number"><input name="cvv"><input name="expiry" autocomplete="cc-exp"></form>"#,
            "payment",
        ),
        // search
        (
            r#"<form action="/search" method="get"><input name="q"></form>"#,
            "search",
        ),
        (
            r#"<form method="post"><input type="search" name="term"></form>"#,
            "search",
        ),
        (
            r#"<form action="/find" method="post"><input name="x"><button>Find</button></form>"#,
            "search",
        ),
        // order
        (
            r#"<form action="/cart/add" method="post"><input type="hidden" name="product" value="7">
               <input type="number" name="quantity"></form>"#,
            "order",
        ),
        (
            r#"<form action="/p/7" method="post"><input type="hidden" name="id" value="7"><button>Add to cart</button></form>"#,
            "order",
        ),
        // contact
        (
            r#"<form method="post"><input name="name"><input type="email" name="email"><textarea name="msg"></textarea></form>"#,
            "contact",
        ),
        (
            r#"<form action="/contact-us" method="post"><input name="subject"></form>"#,
            "contact",
        ),
        // upload
        (
            r#"<form action="/import" method="post" enctype="multipart/form-data"><input type="file" name="doc"><input name="title"></form>"#,
            "upload",
        ),
        // newsletter
        (
            r#"<form action="/subscribe" method="post"><input type="email" name="email"><input name="first_name"></form>"#,
            "newsletter",
        ),
        (
            r#"<form action="/x" method="post"><input type="email" name="email"></form>"#,
            "newsletter",
        ),
        // other
        (
            r#"<form method="post"><input name="color"><input name="size"></form>"#,
            "other",
        ),
        (
            r#"<form method="get" action="/x"><input type="email" name="email"></form>"#,
            "other",
        ),
        (
            r#"<form method="post"><input type="hidden" name="a" value="1"></form>"#,
            "other",
        ),
        (
            r#"<form method="post"><input type="password" name="password" disabled><input name="x"></form>"#,
            "other",
        ),
    ];
    for (html, want) in rows {
        assert_eq!(classify_form(&form(html)), *want, "{html}");
    }
}

#[test]
fn payment_beats_login() {
    let paying_login =
        form(r#"<form method="post"><input type="password" name="password"><input name="cvv"></form>"#);
    assert_eq!(classify_form(&paying_login), "payment");
}

#[test]
fn endpoint_classes_agree_with_the_observe_classifier() {
    // Rows without a request tag, `SOAPAction` or soap-looking path: the two
    // classifiers share one decision tree there and must name classes alike.
    let json = Some("application/json");
    let rows: &[(&str, &str, Option<&str>)] = &[
        ("/graphql", "POST", json),
        ("/api/graphql", "GET", None),
        ("/notgraphql/blob", "POST", json),
        ("/q", "POST", Some("application/graphql")),
        ("/ws", "POST", Some("application/soap+xml")),
        ("/data", "POST", json),
        ("/data", "DELETE", json),
        ("/api/users", "GET", json),
        ("/v2/users", "GET", Some("application/vnd.api+json")),
        ("/rest/x", "GET", Some("application/xml")),
        ("/jsonrpc", "GET", Some("text/xml")),
        ("/x", "POST", Some("application/x-www-form-urlencoded")),
        ("/x", "POST", Some("multipart/form-data; boundary=zz")),
        ("/data", "GET", json),
        ("/data", "GET", Some("Application/JSON; charset=UTF-8")),
        ("/page", "GET", Some("text/html")),
        ("/api/x", "GET", Some("text/html")),
        ("/submit", "GET", Some("application/x-www-form-urlencoded")),
        ("/x", "GET", Some("text/xml")),
        ("/x", "HEAD", json),
        ("/x", "GET", None),
    ];
    for (path, method, ct) in rows {
        let target = url(path);
        let theirs = crawlx_observe::network::classify_endpoint(method, target.as_str(), *ct, b"");
        assert_eq!(
            classify_endpoint(&target, method, *ct, "").as_str(),
            theirs.as_str(),
            "{method} {path} ct={ct:?}"
        );
    }
}

#[test]
fn field_roles_name_what_each_visible_field_expects() {
    let login = form(
        r#"<form action="/login" method="post"><input name="username"><input type="password" name="password">
           <input type="checkbox" name="remember_me"><input type="hidden" name="csrf" value="t"><button>Go</button></form>"#,
    );
    let kb = KbForm::new(&login);
    assert_eq!(kb.form_type, "login");
    let fields: Vec<(&str, &str)> = kb.fields.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    assert_eq!(
        fields,
        [
            ("password", "password"),
            ("remember_me", "remember me"),
            ("username", "username or email")
        ],
        "hidden fields and buttons carry no role"
    );

    let signup = form(
        r#"<form action="/signup" method="post"><input type="email" name="email"><input name="username">
           <input name="first_name"><input type="password" name="password"><input type="password" name="password_confirm">
           <input type="checkbox" name="accept_terms"><input type="checkbox" name="newsletter">
           <input name="captcha_answer"><select name="country"><option>US</option></select>
           <select name="topic"><option>a</option></select><input type="radio" name="kind" value="a"></form>"#,
    );
    let roles = field_roles(&signup, classify_form(&signup));
    let want = [
        ("email", "email"),
        ("username", "username"),
        ("first_name", "first name"),
        ("password", "password"),
        ("password_confirm", "password confirmation"),
        ("accept_terms", "terms acceptance"),
        ("newsletter", "newsletter opt-in"),
        ("captcha_answer", "captcha"),
        ("country", "country"),
        ("topic", "choice"),
        ("kind", "choice"),
    ];
    for (name, role) in want {
        assert_eq!(roles[name], role, "{name}");
    }

    let search = form(r#"<form action="/s" method="get"><input name="q"></form>"#);
    assert_eq!(field_roles(&search, "search")["q"], "search query");
    let contact = form(
        r#"<form method="post"><textarea name="body"></textarea><input type="file" name="att"><input name="odd"></form>"#,
    );
    let roles = field_roles(&contact, "contact");
    assert_eq!(
        (
            roles["body"].as_str(),
            roles["att"].as_str(),
            roles["odd"].as_str()
        ),
        ("message", "file", "other")
    );
}

// ------------------------------------------------------------ record

#[test]
fn knowledge_base_serializes_reference_keys_and_omits_empties() {
    let login = form(
        r#"<form action="/login" method="post"><input name="username"><input type="password" name="password"></form>"#,
    );
    let finding = secrets::detect(&[3u8; 32], &[], concat!("AKIA", "ABCDEFGHIJKLMNOP")).remove(0);
    let endpoint = KbEndpoint::new(&url("/graphql"), "POST", None, "", None).unwrap();
    let kb = KnowledgeBase::new(
        Some(PageType::Login),
        std::slice::from_ref(&login),
        vec![KbSecret::new(finding.clone(), Some(Validity::Invalid))],
        vec![endpoint],
    );
    assert!(!kb.is_empty());
    let v = serde_json::to_value(&kb).unwrap();
    assert_eq!(v["PageType"], "login");
    assert_eq!(v["Forms"][0]["type"], "login");
    assert_eq!(v["Forms"][0]["fields"]["username"], "username or email");
    assert_eq!(v["secrets"][0]["kind"], "aws_access_key_id"); // detection-data
    assert_eq!(v["secrets"][0]["validation"], "invalid");
    assert!(
        v["secrets"][0].get("value").is_none(),
        "no part of the credential is recorded"
    );
    assert_eq!(v["endpoints"][0]["class"], "graphql");
    let back: KnowledgeBase = serde_json::from_value(v).unwrap();
    assert_eq!(back, kb);

    let unvalidated = serde_json::to_value(KbSecret::new(finding, None)).unwrap();
    assert!(unvalidated.get("validation").is_none());

    let empty = KnowledgeBase::new(None, &[], Vec::new(), Vec::new());
    assert!(empty.is_empty());
    assert_eq!(serde_json::to_string(&empty).unwrap(), "{}");
    let only_type = KnowledgeBase::new(Some(PageType::Error), &[], Vec::new(), Vec::new());
    assert_eq!(
        serde_json::to_string(&only_type).unwrap(),
        r#"{"PageType":"error"}"#
    );
}
