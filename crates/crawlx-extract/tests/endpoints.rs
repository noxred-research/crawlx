#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Golden tests for the katana-derived endpoint extractor: one snippet per parser
//! construct, header cases, srcset, form body synthesis, htmx, JS regex mining and the
//! textual guard.

use crawlx_core::config::JavascriptMode;
use crawlx_extract::endpoints::{
    self, body, headers, Confidence, DiscoveredEndpoint, DiscoveryInput, DiscoveryOptions,
};
use crawlx_extract::{ExtractOptions, Extractor};
use http::Method;
use url::Url;

const PAGE: &str = "https://security-crawl-maze.app/test/";

fn page() -> Url {
    Url::parse(PAGE).unwrap()
}

fn run(html: &str) -> Vec<DiscoveredEndpoint> {
    run_with(html, Some("text/html; charset=utf-8"), &[])
}

fn run_with(body: &str, content_type: Option<&str>, headers: &[(&str, &str)]) -> Vec<DiscoveredEndpoint> {
    let headers: Vec<(String, String)> = headers
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect();
    let url = page();
    endpoints::discover(&DiscoveryInput {
        url: &url,
        status: 200,
        headers: &headers,
        content_type,
        body: body.as_bytes(),
        depth: 0,
    })
    .unwrap()
}

fn urls(found: &[DiscoveredEndpoint]) -> Vec<String> {
    found.iter().map(|e| e.url.to_string()).collect()
}

fn find<'a>(found: &'a [DiscoveredEndpoint], path: &str) -> &'a DiscoveredEndpoint {
    let want = format!("https://security-crawl-maze.app{path}");
    found
        .iter()
        .find(|e| e.url.as_str() == want)
        .unwrap_or_else(|| panic!("{want} not found in {:?}", urls(found)))
}

/// `(html, expected path, source)` — one row per katana parser construct.
const CONSTRUCTS: &[(&str, &str, endpoints::EndpointSource)] = &[
    (
        r#"<a href="/test/html/body/a/href.found">x</a>"#,
        "/test/html/body/a/href.found",
        body::A_HREF,
    ),
    (
        r##"<a ping="/test/html/body/a/ping.found" href="#">x</a>"##,
        "/test/html/body/a/ping.found",
        body::A_PING,
    ),
    (
        r#"<link rel="stylesheet" href="/test/html/head/link/href.found">"#,
        "/test/html/head/link/href.found",
        body::LINK_HREF,
    ),
    (
        r#"<embed src="/test/html/body/embed/src.found">"#,
        "/test/html/body/embed/src.found",
        body::EMBED_SRC,
    ),
    (
        r#"<frameset><frame src="/test/html/body/frameset/frame/src.found"></frameset>"#,
        "/test/html/body/frameset/frame/src.found",
        body::FRAME_SRC,
    ),
    (
        r#"<iframe src="/test/html/body/iframe/src.found"></iframe>"#,
        "/test/html/body/iframe/src.found",
        body::IFRAME_SRC,
    ),
    (
        r#"<iframe srcdoc="&lt;a href='/test/html/body/iframe/srcdoc.html'&gt;x&lt;/a&gt;"></iframe>"#,
        "/test/html/body/iframe/srcdoc.html",
        body::IFRAME_SRCDOC,
    ),
    (
        r#"<input type="IMAGE" src="/test/html/body/input/src.found">"#,
        "/test/html/body/input/src.found",
        body::INPUT_IMAGE_SRC,
    ),
    (
        r#"<isindex action="/test/html/body/isindex/action.found">"#,
        "/test/html/body/isindex/action.found",
        body::ISINDEX_ACTION,
    ),
    (
        r#"<script src="/test/html/body/script/src.found"></script>"#,
        "/test/html/body/script/src.found",
        body::SCRIPT_SRC,
    ),
    (
        r#"<body background="/test/html/body/background.found"></body>"#,
        "/test/html/body/background.found",
        body::BODY_BACKGROUND,
    ),
    (
        r#"<audio src="/test/html/body/audio/src.found"></audio>"#,
        "/test/html/body/audio/src.found",
        body::AUDIO_SRC,
    ),
    (
        r#"<audio controls><source src="/test/html/body/audio/source/src.found" type="audio/mpeg"></audio>"#,
        "/test/html/body/audio/source/src.found",
        body::AUDIO_SOURCE,
    ),
    (
        r#"<applet archive="/test/html/body/applet/archive.found"></applet>"#,
        "/test/html/body/applet/archive.found",
        body::APPLET_ARCHIVE,
    ),
    (
        r#"<applet codebase="/test/html/body/applet/codebase.found"></applet>"#,
        "/test/html/body/applet/codebase.found",
        body::APPLET_CODEBASE,
    ),
    (
        r#"<img dynsrc="/test/html/body/img/dynsrc.found">"#,
        "/test/html/body/img/dynsrc.found",
        body::IMG_DYNSRC,
    ),
    (
        r##"<img alt="" src="#" longdesc="/test/html/body/img/longdesc.found">"##,
        "/test/html/body/img/longdesc.found",
        body::IMG_LONGDESC,
    ),
    (
        r#"<img lowsrc="/test/html/body/img/lowsrc.found">"#,
        "/test/html/body/img/lowsrc.found",
        body::IMG_LOWSRC,
    ),
    (
        r#"<img src="/test/html/body/img/src.found">"#,
        "/test/html/body/img/src.found",
        body::IMG_SRC,
    ),
    (
        r#"<object data="/test/html/body/object/data.found"></object>"#,
        "/test/html/body/object/data.found",
        body::OBJECT_DATA,
    ),
    (
        r#"<object codebase="/test/html/body/object/codebase.found"></object>"#,
        "/test/html/body/object/codebase.found",
        body::OBJECT_CODEBASE,
    ),
    (
        r#"<object classid="clsid:6BF52A52"><param name="ref" value="/test/html/body/object/param/value.found"></object>"#,
        "/test/html/body/object/param/value.found",
        body::OBJECT_PARAM_VALUE,
    ),
    (
        r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="/test/html/body/svg/image/xlink.found"/></svg>"#,
        "/test/html/body/svg/image/xlink.found",
        body::SVG_IMAGE_HREF,
    ),
    (
        r#"<svg xmlns="http://www.w3.org/2000/svg"><image href="/test/html/body/svg/image/href.found"/></svg>"#,
        "/test/html/body/svg/image/href.found",
        body::SVG_IMAGE_HREF,
    ),
    (
        r#"<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><script xlink:href="/test/html/body/svg/script/xlink.found"></script></svg>"#,
        "/test/html/body/svg/script/xlink.found",
        body::SVG_SCRIPT_HREF,
    ),
    (
        r#"<table background="/test/html/body/table/background.found"></table>"#,
        "/test/html/body/table/background.found",
        body::TABLE_BACKGROUND,
    ),
    (
        r#"<table><tr><td background="/test/html/body/table/td/background.found"></td></tr></table>"#,
        "/test/html/body/table/td/background.found",
        body::TABLE_TD_BACKGROUND,
    ),
    (
        r#"<video src="/test/html/body/video/src.found"></video>"#,
        "/test/html/body/video/src.found",
        body::VIDEO_SRC,
    ),
    (
        r#"<video poster="/test/html/body/video/poster.found"></video>"#,
        "/test/html/body/video/poster.found",
        body::VIDEO_POSTER,
    ),
    (
        r#"<video><track src="/test/html/body/video/track/src.found"></video>"#,
        "/test/html/body/video/track/src.found",
        body::VIDEO_TRACK_SRC,
    ),
    (
        r#"<video><source src="/test/html/body/video/source/src.found"></video>"#,
        "/test/html/body/video/source/src.found",
        body::SOURCE_SRC,
    ),
    (
        r#"<blockquote cite="/test/html/body/blockquote/cite.found"></blockquote>"#,
        "/test/html/body/blockquote/cite.found",
        body::BLOCKQUOTE_CITE,
    ),
    (
        r#"<q cite="/test/html/body/q/cite.found"></q>"#,
        "/test/html/body/q/cite.found",
        body::Q_CITE,
    ),
    (
        r#"<del cite="/test/html/body/del/cite.found"></del>"#,
        "/test/html/body/del/cite.found",
        body::DEL_CITE,
    ),
    (
        r#"<ins cite="/test/html/body/ins/cite.found"></ins>"#,
        "/test/html/body/ins/cite.found",
        body::INS_CITE,
    ),
    (
        r#"<map name="m"><area shape="rect" coords="0,0,1,1" href="/test/html/body/map/area/href.found"></map>"#,
        "/test/html/body/map/area/href.found",
        body::AREA_HREF,
    ),
    (
        r##"<map name="m"><area ping="/test/html/body/map/area/ping.found" href="#"></map>"##,
        "/test/html/body/map/area/ping.found",
        body::AREA_PING,
    ),
    (
        r#"<import implementation="/test/html/body/import/implementation.found">"#,
        "/test/html/body/import/implementation.found",
        body::IMPORT_IMPLEMENTATION,
    ),
    (
        r#"<form><button formaction="/test/html/body/button/formaction.found">go</button></form>"#,
        "/test/html/body/button/formaction.found",
        body::BUTTON_FORMACTION,
    ),
    (
        r#"<html manifest="/test/html/manifest.found"><body></body></html>"#,
        "/test/html/manifest.found",
        body::HTML_MANIFEST,
    ),
    (
        r#"<meta http-equiv="refresh" content="0; url=/test/html/head/meta/refresh.found">"#,
        "/test/html/head/meta/refresh.found",
        body::META_REFRESH,
    ),
    (
        r#"<meta name="description" content="see /test/html/head/meta/content.html now">"#,
        "/test/html/head/meta/content.html",
        body::META_CONTENT,
    ),
    (
        r#"<div hx-get="/test/html/body/htmx/get.found"></div>"#,
        "/test/html/body/htmx/get.found",
        body::HTMX_GET,
    ),
    (
        r#"<script>fetch("/test/javascript/inline/fetch.json");</script>"#,
        "/test/javascript/inline/fetch.json",
        INLINE_SCRIPT_SOURCE,
    ),
];

/// Inline script text: the AST pass reads the `fetch` site when built; the
/// regex pass is the fallback.
const INLINE_SCRIPT_SOURCE: endpoints::EndpointSource = if cfg!(feature = "js-ast") {
    body::JS_FETCH
} else {
    body::SCRIPT_TEXT
};

/// Script-file strings: AST catch-all when built, regex otherwise.
const SCRIPT_FILE_SOURCE: endpoints::EndpointSource = if cfg!(feature = "js-ast") {
    body::JS_STRING
} else {
    body::JS_REGEX
};

const SCRIPT_CONFIDENCE: Confidence = if cfg!(feature = "js-ast") {
    Confidence::Structural
} else {
    Confidence::Regex
};

#[test]
fn every_parser_construct_is_found() {
    assert!(CONSTRUCTS.len() >= 30);
    for (html, path, source) in CONSTRUCTS {
        let found = run(html);
        let ep = find(&found, path);
        assert_eq!(ep.source, *source, "source of {path} in {html}");
        assert_eq!(ep.method, Method::GET);
        assert_eq!(ep.depth, 1);
        let expected_confidence = match source.attribute {
            "srcdoc" | "text" | "content" | "regex" => Confidence::Regex,
            _ => Confidence::Structural,
        };
        assert_eq!(ep.confidence, expected_confidence, "{path}");
    }
}

#[test]
fn doctype_system_id() {
    let found = run(r#"<!DOCTYPE html SYSTEM "/test/html/doctype.found"><html></html>"#);
    assert_eq!(
        find(&found, "/test/html/doctype.found").source,
        body::HTML_DOCTYPE
    );
}

#[test]
fn srcset_candidates_img_and_audio_source() {
    let found = run(r#"<img srcset="/test/html/body/img/srcset1x.found 1x,
            /test/html/body/img/srcset2x.found 2x">
        <audio controls><source srcset="/test/html/body/audio/source/srcset1x.found 1x, /test/html/body/audio/source/srcset2x.found 2x"></audio>
        <picture><source srcset="/test/html/body/picture/source/srcset.found 100w"></picture>"#);
    for p in [
        "/test/html/body/img/srcset1x.found",
        "/test/html/body/img/srcset2x.found",
    ] {
        assert_eq!(find(&found, p).source, body::IMG_SRCSET);
    }
    for p in [
        "/test/html/body/audio/source/srcset1x.found",
        "/test/html/body/audio/source/srcset2x.found",
    ] {
        assert_eq!(find(&found, p).source, body::AUDIO_SOURCE_SRCSET);
    }
    assert_eq!(
        find(&found, "/test/html/body/picture/source/srcset.found").source,
        body::SOURCE_SRCSET
    );
}

#[test]
fn base_href_is_honoured_and_recorded() {
    let found = run(r#"<base href="https://security-crawl-maze.app/base/dir/"><a href="rel.found">x</a>"#);
    assert_eq!(find(&found, "/base/dir/").source, body::BASE_HREF);
    assert_eq!(find(&found, "/base/dir/rel.found").source, body::A_HREF);
}

#[test]
fn get_form_becomes_query_string() {
    let found = run(
        r#"<form action="/test/html/body/form/action-get.found" method="get">
            <input name="q" placeholder="search here">
            <input type="hidden" name="csrf" value="tok">
            <input type="radio" name="r" value="1"><input type="radio" name="r" value="2">
            <input type="checkbox" name="c" value="on">
            <select name="s"><option value="a">A</option><option value="b" selected>B</option></select>
            <textarea name="t"></textarea>
            <input type="email" name="e"><input type="number" name="n" min="5" max="9" step="2">
            <input name="">
        </form>"#,
    );
    let f = found.iter().find(|e| e.source == body::FORM_ACTION).unwrap();
    assert_eq!(f.method, Method::GET);
    assert_eq!(
        f.url.as_str(),
        "https://security-crawl-maze.app/test/html/body/form/action-get.found?q=search+here&csrf=tok&r=1&c=on&s=b&t=crawlx&e=crawlx%40example.org&n=7"
    );
    assert!(f.body.is_none());
    assert!(f.content_type.is_none());
}

#[test]
fn post_form_urlencoded_body_and_content_type() {
    let found = run(
        r#"<form action="/test/html/body/form/action-post.found" method="POST">
            <input name="user" value="alice"><input type="password" name="pass">
        </form>"#,
    );
    let f = find(&found, "/test/html/body/form/action-post.found");
    assert_eq!(f.method, Method::POST);
    assert_eq!(f.body.as_deref(), Some("user=alice&pass=crawlxP%40ssw0rd1"));
    assert_eq!(
        f.content_type.as_deref(),
        Some("application/x-www-form-urlencoded")
    );
}

#[test]
fn post_form_multipart_body() {
    let found = run(
        r#"<form action="/upload" method="post" enctype="multipart/form-data">
            <input name="title" value="t"><input type="file" name="f">
        </form>"#,
    );
    let f = find(&found, "/upload");
    assert_eq!(
        f.content_type.as_deref(),
        Some(&*format!(
            "multipart/form-data; boundary={}",
            body::MULTIPART_BOUNDARY
        ))
    );
    let b = f.body.as_deref().unwrap();
    assert!(
        b.starts_with(&format!(
            "--{}\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nt\r\n",
            body::MULTIPART_BOUNDARY
        )),
        "{b}"
    );
    assert!(b.contains("name=\"f\"\r\n\r\ncrawlx\r\n"), "{b}");
    assert!(
        b.ends_with(&format!("--{}--\r\n", body::MULTIPART_BOUNDARY)),
        "{b}"
    );
}

#[test]
fn form_without_action_targets_the_page_and_other_methods_have_no_body() {
    let found = run(r#"<form method="put"><input name="a" value="1"></form>"#);
    let f = found.iter().find(|e| e.source == body::FORM_ACTION).unwrap();
    assert_eq!(f.url.as_str(), PAGE);
    assert_eq!(f.method, Method::PUT);
    assert!(f.body.is_none());
}

#[test]
fn htmx_methods_and_delete_exclusion() {
    let found = run(r#"<button hx-post="/api/items">a</button>
           <div hx-put="/api/items/1" hx-patch="/api/items/1/name"></div>
           <span hx-delete="/api/items/2"></span>
           <a hx-get="/api/list" href="/html/list">l</a>"#);
    assert_eq!(find(&found, "/api/items").method, Method::POST);
    let put = found.iter().find(|e| e.source == body::HTMX_PUT).unwrap();
    assert_eq!(
        (put.method.clone(), put.url.path()),
        (Method::PUT, "/api/items/1")
    );
    let patch = found.iter().find(|e| e.source == body::HTMX_PATCH).unwrap();
    assert_eq!(
        (patch.method.clone(), patch.url.path()),
        (Method::PATCH, "/api/items/1/name")
    );
    assert_eq!(find(&found, "/api/list").source, body::HTMX_GET);
    assert!(!urls(&found).iter().any(|u| u.contains("/api/items/2")));
}

#[test]
fn header_parsers() {
    let found = run_with(
        "",
        Some("text/html"),
        &[
            ("Content-Location", "/test/headers/content-location.found"),
            ("Link", "</test/headers/link.found>; rel=preload; as=style, <https://security-crawl-maze.app/test/headers/link2.found>; rel=\"next\""),
            ("Location", "/test/headers/location.found"),
            ("Refresh", "999; url=/test/headers/refresh.found"),
            ("X-Other", "/ignored"),
        ],
    );
    assert_eq!(
        find(&found, "/test/headers/content-location.found").source,
        headers::CONTENT_LOCATION
    );
    assert_eq!(find(&found, "/test/headers/link.found").source, headers::LINK);
    assert_eq!(find(&found, "/test/headers/link2.found").source, headers::LINK);
    assert_eq!(
        find(&found, "/test/headers/location.found").source,
        headers::LOCATION
    );
    assert_eq!(
        find(&found, "/test/headers/refresh.found").source,
        headers::REFRESH
    );
    assert_eq!(found.len(), 5);
}

#[test]
fn javascript_file_is_mined() {
    let js = r#"const api = "/test/javascript/file/api.json"; load('./javascript/file/rel.js'); x = "https://security-crawl-maze.app/test/javascript/file/abs.php";
// only the regex pass reads comments: "/test/javascript/file/comment.js""#;
    let found = run_with(js, Some("application/javascript"), &[]);
    for p in [
        "/test/javascript/file/api.json",
        "/test/javascript/file/rel.js",
        "/test/javascript/file/abs.php",
    ] {
        let ep = find(&found, p);
        assert_eq!(ep.source, SCRIPT_FILE_SOURCE, "{p}");
        assert_eq!(ep.confidence, SCRIPT_CONFIDENCE, "{p}");
    }
    let ep = find(&found, "/test/javascript/file/comment.js");
    assert_eq!(ep.source, body::JS_REGEX);
    assert_eq!(ep.confidence, Confidence::Regex);
}

/// The AST pass through the public API: request sites with method, body
/// keys and header names from a script file, an inline script and an
/// event-handler attribute; a script that does not parse falls back to the
/// regex pass; `JavascriptMode::Off` disables both.
#[cfg(feature = "js-ast")]
#[test]
fn javascript_ast_pass() {
    let js = r#"
        const root = '/test/javascript/ast';
        fetch(root + '/items', {method: 'POST', headers: {'Content-Type': 'application/json', Authorization: tok},
              body: JSON.stringify({name: n})});
        axios.put(`${root}/items/${id}`, {done: true});
        history.pushState({}, '', root + '/route');
        new WebSocket('wss://security-crawl-maze.app/test/javascript/ast/socket');
    "#;
    let found = run_with(js, Some("text/javascript"), &[]);
    let post = find(&found, "/test/javascript/ast/items");
    assert_eq!(post.method, Method::POST);
    assert_eq!(post.source, body::JS_FETCH);
    assert_eq!(post.confidence, Confidence::Structural);
    assert_eq!(post.body.as_deref(), Some(r#"{"name":"crawlx"}"#));
    assert_eq!(post.content_type.as_deref(), Some("application/json"));
    assert_eq!(post.headers, vec!["authorization", "content-type"]);
    assert!(
        !found
            .iter()
            .any(|e| e.url.path() == "/test/javascript/ast/items" && e.method == Method::GET),
        "a POST site must not also yield a GET: {:?}",
        urls(&found)
    );
    let put = find(&found, "/test/javascript/ast/items/:id");
    assert_eq!(put.method, Method::PUT);
    assert_eq!(put.source, body::JS_AXIOS);
    assert_eq!(put.body.as_deref(), Some(r#"{"done":"crawlx"}"#));
    assert_eq!(
        find(&found, "/test/javascript/ast/route").source,
        body::JS_HISTORY
    );
    let ws = find(&found, "/test/javascript/ast/socket");
    assert_eq!(ws.source, body::JS_WEBSOCKET);
    assert_eq!(ws.url.scheme(), "https");

    // inline script and event-handler attribute in a page
    let html = r#"<button onclick="fetch('/test/javascript/ast/attr.found', {method: 'DELETE'})">x</button>
        <script>document.querySelector('a').addEventListener('click', function () { fetch('/test/javascript/ast/inline.found'); });</script>"#;
    let found = run(html);
    let attr = find(&found, "/test/javascript/ast/attr.found");
    assert_eq!(attr.method, Method::DELETE);
    assert_eq!(attr.source, body::JS_FETCH);
    let inline = find(&found, "/test/javascript/ast/inline.found");
    assert_eq!(inline.source, body::JS_FETCH);
    assert_eq!(inline.confidence, Confidence::Structural);

    // syntax error: the regex pass still mines the quoted path
    let broken = r#"<script>fetch("/test/javascript/ast/broken.js", { ; </script>"#;
    let found = run(broken);
    assert_eq!(
        find(&found, "/test/javascript/ast/broken.js").source,
        body::SCRIPT_TEXT
    );

    // the switch covers both passes
    let url = page();
    let off = endpoints::discover_with(
        &DiscoveryInput {
            url: &url,
            status: 200,
            headers: &[],
            content_type: Some("text/html"),
            body: html.as_bytes(),
            depth: 0,
        },
        &DiscoveryOptions {
            javascript_mode: JavascriptMode::Off,
            ..DiscoveryOptions::default()
        },
    )
    .unwrap();
    assert!(off.is_empty(), "{:?}", urls(&off));
}

#[test]
fn page_body_regex_runs_on_textual_bodies_only() {
    let text = "plain notes: ./misc/relative/path and /misc/known/page.html end";
    let found = run_with(text, Some("text/plain"), &[]);
    assert_eq!(find(&found, "/test/misc/relative/path").source, body::HTML_REGEX);
    assert_eq!(find(&found, "/misc/known/page.html").source, body::HTML_REGEX);

    // The same text with no declared type is sniffed as text and mined.
    let untyped = run_with(text, None, &[]);
    assert!(untyped.iter().any(|e| e.url.path() == "/misc/known/page.html"));
    let octet = run_with(text, Some("application/octet-stream"), &[]);
    assert!(octet.iter().any(|e| e.url.path() == "/misc/known/page.html"));
}

#[test]
fn png_body_yields_zero_endpoints() {
    let mut png = b"\x89PNG\r\n\x1a\n".to_vec();
    png.extend_from_slice(b"\0\0\0\rIHDR./6 ./a/b.html <a href=\"/laundered.found\">");
    let url = page();
    let input = DiscoveryInput {
        url: &url,
        status: 200,
        headers: &[],
        content_type: None,
        body: &png,
        depth: 0,
    };
    assert!(endpoints::discover(&input).unwrap().is_empty());
    let typed = DiscoveryInput {
        content_type: Some("image/png"),
        ..input
    };
    assert!(endpoints::discover(&typed).unwrap().is_empty());
}

#[test]
fn skipped_schemes_fragments_and_dedupe() {
    let found = run(
        r##"<a href="javascript:void(0)">j</a><a href="mailto:a@b.c">m</a><a href="data:text/plain,x">d</a>
           <a href="#top">f</a><a href="/dup.found">1</a><a href="/dup.found#x">2</a><img src="data:image/png;base64,AAAA">"##,
    );
    assert_eq!(urls(&found), vec!["https://security-crawl-maze.app/dup.found"]);
}

#[test]
fn result_cap_and_body_cap() {
    let mut html = String::new();
    for i in 0..50 {
        html.push_str(&format!(r#"<a href="/n/{i}">x</a>"#));
    }
    let url = page();
    let input = DiscoveryInput {
        url: &url,
        status: 200,
        headers: &[],
        content_type: Some("text/html"),
        body: html.as_bytes(),
        depth: 3,
    };
    let capped = endpoints::discover_with(
        &input,
        &DiscoveryOptions {
            max_results: 7,
            ..DiscoveryOptions::default()
        },
    )
    .unwrap();
    assert_eq!(capped.len(), 7);
    assert!(capped.iter().all(|e| e.depth == 4));
    let truncated = endpoints::discover_with(
        &input,
        &DiscoveryOptions {
            max_body_bytes: 40,
            ..DiscoveryOptions::default()
        },
    )
    .unwrap();
    assert!(truncated.len() <= 2, "{:?}", urls(&truncated));
}

#[test]
fn mining_can_be_disabled() {
    let html = r#"<script>fetch("/inline.json")</script><a href="/structural">s</a>"#;
    let url = page();
    let input = DiscoveryInput {
        url: &url,
        status: 200,
        headers: &[],
        content_type: Some("text/html"),
        body: html.as_bytes(),
        depth: 0,
    };
    let found = endpoints::discover_with(
        &input,
        &DiscoveryOptions {
            javascript_mode: JavascriptMode::Off,
            ..DiscoveryOptions::default()
        },
    )
    .unwrap();
    assert_eq!(urls(&found), vec!["https://security-crawl-maze.app/structural"]);
}

#[test]
fn extractor_fills_discovered_endpoints_when_enabled() {
    let html = r#"<html><body><a href="/a.found">a</a><form action="/f" method="post"><input name="x" value="1"></form></body></html>"#;
    let off = Extractor::extract(html, &page(), &ExtractOptions::default()).unwrap();
    assert!(off.discovered_endpoints.is_empty());
    let opts = ExtractOptions {
        discover_endpoints: true,
        headers: vec![("Link".to_owned(), "</pre.css>; rel=preload".to_owned())],
        content_type: Some("text/html".to_owned()),
        depth: 2,
        ..ExtractOptions::default()
    };
    let on = Extractor::extract(html, &page(), &opts).unwrap();
    let paths: Vec<&str> = on.discovered_endpoints.iter().map(|e| e.url.path()).collect();
    assert_eq!(paths, vec!["/pre.css", "/a.found", "/f"]);
    assert!(on.discovered_endpoints.iter().all(|e| e.depth == 3));
    let f = &on.discovered_endpoints[2];
    assert_eq!(f.method, Method::POST);
    assert_eq!(f.body.as_deref(), Some("x=1"));
    // Round-trips through serde (Method and EndpointSource have custom impls).
    let json = serde_json::to_string(&on).unwrap();
    let back: crawlx_extract::Document = serde_json::from_str(&json).unwrap();
    assert_eq!(back.discovered_endpoints, on.discovered_endpoints);
}
