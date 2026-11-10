//! Fixture `g32`: a reproduction of a public security crawl-maze blueprint.
//!
//! The ground truth is the `expectedResults` list of a scoring tool ported from an
//! MIT-licensed upstream; see THIRD_PARTY_NOTICES.md. It mirrors the blueprint's
//! `expected-results.json` (an Apache-2.0 blueprint). The pages are
//! re-implemented from that list, one construct per page, not copied. Two list entries
//! carry a stray `/test` prefix (`multi-step-request-event-listener-div{,-dom}`); they are
//! normalized to the blueprint form here.
//!
//! Layout: the entry page `/g32/` (embedded `fixtures/g32/index.html`) links the five
//! category indexes `/g32/<category>/`; each index links its test pages; every expected
//! endpoint lives under [`TEST_PREFIX`] (`/g32/test/<path>`), answers `200 text/plain` and
//! is recorded by the gym ledger as an `op` row like every other request. Known-files
//! targets are reached through the origin's `robots.txt` (`Allow:` + `Sitemap:`), which the
//! gym serves for this fixture once a test calls `GymHandle::claim_origin("g32")`.
//!
//! Two deviations from the blueprint are deliberate: absolute URLs (`http://host:port/…`)
//! are used where a construct is mined by the scoring tool's quoted-endpoint regex, because the gym
//! runs on a random port and the ported regexes resolve dotted last segments only in the
//! absolute form; and the automatic POST fires after 300 ms instead of 5 s.

use std::fmt::Write as _;

use crate::gym::manifest::MazePlane;

/// Path prefix of every expected endpoint (`/g32/test/html/body/a/href.found`).
pub const TEST_PREFIX: &str = "/g32/test";

/// Fixture id.
pub const ID: &str = "g32";

/// Blueprint categories, in index order.
pub const CATEGORIES: [&str; 5] = ["css", "headers", "html", "javascript", "misc"];

/// A generated `g32` response.
#[derive(Clone, Debug)]
pub struct MazeResponse {
    /// HTTP status (`200`, `201` for the `Content-Location` case, `301` for `Location`).
    pub status: u16,
    /// `Content-Type` header value.
    pub content_type: &'static str,
    /// Extra response headers (the `headers/*` cases).
    pub headers: Vec<(&'static str, String)>,
    /// Body.
    pub body: String,
}

/// One test page of the fixture.
#[derive(Clone, Copy, Debug)]
pub struct MazePage {
    /// Path below `/g32/` (`html/body/a/href.html`).
    pub path: &'static str,
    /// Plane expected to request the page's targets.
    pub plane: MazePlane,
    /// Expected endpoints this page references (blueprint form, no `/test` prefix).
    pub targets: &'static [&'static str],
    /// One-line description shown on the page and in the category index.
    pub title: &'static str,
    render: fn(&Env<'_>) -> MazeResponse,
}

impl MazePage {
    /// Blueprint category: the first path segment.
    #[must_use]
    pub fn category(&self) -> &'static str {
        self.path.split('/').next().unwrap_or(self.path)
    }

    /// Render the page for request host `host`.
    #[must_use]
    pub fn render(&self, host: &str) -> MazeResponse {
        (self.render)(&Env { host })
    }
}

/// Request-scoped rendering context.
struct Env<'a> {
    host: &'a str,
}

impl Env<'_> {
    /// `http://host:port/g32/test<target>`.
    fn abs(&self, target: &str) -> String {
        format!("http://{}{TEST_PREFIX}{target}", self.host)
    }
}

/// Root-relative `/g32/test<target>`.
fn rel(target: &str) -> String {
    format!("{TEST_PREFIX}{target}")
}

const HTML: &str = "text/html; charset=utf-8";
const TEXT: &str = "text/plain; charset=utf-8";

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
}

fn page(title: &str, head: &str, body: &str) -> MazeResponse {
    MazeResponse {
        status: 200,
        content_type: HTML,
        headers: Vec::new(),
        body: format!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>crawl-maze: {t}</title>{head}</head>\n\
             <body><h1>{t}</h1>\n{body}\n</body></html>\n",
            t = escape(title)
        ),
    }
}

fn body_only(title: &str, body: &str) -> MazeResponse {
    page(title, "", body)
}

fn raw(content_type: &'static str, body: String) -> MazeResponse {
    MazeResponse {
        status: 200,
        content_type,
        headers: Vec::new(),
        body,
    }
}

/// Inline script that binds `fetch(target, {method})` to `#id` on click (interactive cases).
fn click_fetch(id: &str, target: &str, method: &str) -> String {
    format!(
        "<script>document.getElementById('{id}').addEventListener('click', function () {{ fetch('{}', {{method: '{method}'}}); }});</script>",
        rel(target)
    )
}

// ---- css -------------------------------------------------------------------------------------

fn css_font_face_html(_: &Env<'_>) -> MazeResponse {
    page(
        "css font-face",
        "<link rel=\"stylesheet\" href=\"/g32/css/font-face.css\">",
        "<p class=\"maze\">The linked stylesheet declares a font face whose source must be found.</p>",
    )
}

fn css_font_face_css(e: &Env<'_>) -> MazeResponse {
    raw(
        "text/css; charset=utf-8",
        format!(
            "@font-face {{\n  font-family: \"maze\";\n  src: url(\"{}\");\n}}\n.maze {{ font-family: \"maze\", sans-serif; }}\n",
            e.abs("/css/font-face.found")
        ),
    )
}

// ---- headers ---------------------------------------------------------------------------------

fn headers_content_location(_: &Env<'_>) -> MazeResponse {
    let mut r = body_only(
        "headers Content-Location",
        "<p>The response carries a <code>Content-Location</code> header.</p>",
    );
    r.status = 201;
    r.headers
        .push(("content-location", rel("/headers/content-location.found")));
    r
}

fn headers_link(_: &Env<'_>) -> MazeResponse {
    let mut r = body_only(
        "headers Link",
        "<p>The response carries a <code>Link</code> header with <code>rel=preload</code>.</p>",
    );
    r.headers.push((
        "link",
        format!("<{}>; rel=\"preload\"", rel("/headers/link.found")),
    ));
    r
}

fn headers_location(_: &Env<'_>) -> MazeResponse {
    MazeResponse {
        status: 301,
        content_type: TEXT,
        headers: vec![("location", rel("/headers/location.found"))],
        body: "moved\n".to_owned(),
    }
}

fn headers_refresh(_: &Env<'_>) -> MazeResponse {
    let mut r = body_only(
        "headers Refresh",
        "<p>The response carries a <code>Refresh</code> header with a long delay.</p>",
    );
    r.headers
        .push(("refresh", format!("999; url={}", rel("/headers/refresh.found"))));
    r
}

// ---- html ------------------------------------------------------------------------------------

fn html_doctype(_: &Env<'_>) -> MazeResponse {
    raw(
        HTML,
        format!(
            "<!DOCTYPE html SYSTEM \"{}\">\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>crawl-maze: html doctype</title></head>\n\
             <body><h1>html doctype</h1><p>The doctype names a system identifier.</p></body></html>\n",
            rel("/html/doctype.found")
        ),
    )
}

fn html_manifest(_: &Env<'_>) -> MazeResponse {
    raw(
        HTML,
        format!(
            "<!doctype html>\n<html lang=\"en\" manifest=\"{}\"><head><meta charset=\"utf-8\"><title>crawl-maze: html manifest</title></head>\n\
             <body><h1>html manifest</h1><p>The html element names an application-cache manifest.</p></body></html>\n",
            rel("/html/manifest.found")
        ),
    )
}

fn body_background(_: &Env<'_>) -> MazeResponse {
    raw(
        HTML,
        format!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>crawl-maze: body background</title></head>\n\
             <body background=\"{}\"><h1>body background</h1><p>The body element names a background image.</p></body></html>\n",
            rel("/html/body/background.found")
        ),
    )
}

fn a_href(_: &Env<'_>) -> MazeResponse {
    body_only(
        "a href",
        &format!(
            "<p><a href=\"{}\">a plain link</a></p>",
            rel("/html/body/a/href.found")
        ),
    )
}

fn a_ping(_: &Env<'_>) -> MazeResponse {
    body_only(
        "a ping",
        &format!(
            "<p><a href=\"#\" ping=\"{}\">a link whose ping attribute names an auditing URL</a></p>",
            rel("/html/body/a/ping.found")
        ),
    )
}

fn audio_src(_: &Env<'_>) -> MazeResponse {
    body_only(
        "audio src",
        &format!(
            "<audio controls src=\"{}\"></audio>",
            rel("/html/body/audio/src.found")
        ),
    )
}

fn audio_source_src(_: &Env<'_>) -> MazeResponse {
    body_only(
        "audio source src",
        &format!(
            "<audio controls><source src=\"{}\" type=\"audio/ogg\"></audio>",
            rel("/html/body/audio/source/src.found")
        ),
    )
}

fn audio_source_srcset(_: &Env<'_>) -> MazeResponse {
    body_only(
        "audio source srcset",
        &format!(
            "<audio controls><source srcset=\"{} 1x, {} 2x\"></audio>",
            rel("/html/body/audio/source/srcset1x.found"),
            rel("/html/body/audio/source/srcset2x.found")
        ),
    )
}

fn applet_archive(_: &Env<'_>) -> MazeResponse {
    body_only(
        "applet archive",
        &format!(
            "<applet code=\"Maze.class\" archive=\"{}\" width=\"10\" height=\"10\"></applet>",
            rel("/html/body/applet/archive.found")
        ),
    )
}

fn applet_codebase(_: &Env<'_>) -> MazeResponse {
    body_only(
        "applet codebase",
        &format!(
            "<applet code=\"Maze.class\" codebase=\"{}\" width=\"10\" height=\"10\"></applet>",
            rel("/html/body/applet/codebase.found")
        ),
    )
}

fn blockquote_cite(_: &Env<'_>) -> MazeResponse {
    body_only(
        "blockquote cite",
        &format!(
            "<blockquote cite=\"{}\">A quotation whose source is cited.</blockquote>",
            rel("/html/body/blockquote/cite.found")
        ),
    )
}

fn embed_src(_: &Env<'_>) -> MazeResponse {
    body_only(
        "embed src",
        &format!(
            "<embed src=\"{}\" type=\"application/x-maze\" width=\"10\" height=\"10\">",
            rel("/html/body/embed/src.found")
        ),
    )
}

fn form_action_get(_: &Env<'_>) -> MazeResponse {
    body_only(
        "form action (GET)",
        &format!(
            "<form action=\"{}\" method=\"get\"><label>Query <input type=\"text\" name=\"q\" value=\"maze\"></label> <button type=\"submit\">Search</button></form>",
            rel("/html/body/form/action-get.found")
        ),
    )
}

fn form_action_post(_: &Env<'_>) -> MazeResponse {
    body_only(
        "form action (POST)",
        &format!(
            "<form action=\"{}\" method=\"post\"><label>Name <input type=\"text\" name=\"name\" value=\"maze\"></label> <button type=\"submit\">Send</button></form>",
            rel("/html/body/form/action-post.found")
        ),
    )
}

fn button_formaction(_: &Env<'_>) -> MazeResponse {
    body_only(
        "form button formaction",
        &format!(
            "<form action=\"/g32/html/body/form/button/\" method=\"get\"><button type=\"submit\" formaction=\"{}\">Submit elsewhere</button></form>",
            rel("/html/body/form/button/formaction.found")
        ),
    )
}

fn frameset_frame_src(_: &Env<'_>) -> MazeResponse {
    raw(
        HTML,
        format!(
            "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>crawl-maze: frameset frame src</title></head>\n\
             <frameset cols=\"*\"><frame src=\"{}\" name=\"maze\"></frameset></html>\n",
            rel("/html/body/frameset/frame/src.found")
        ),
    )
}

fn iframe_src(_: &Env<'_>) -> MazeResponse {
    body_only(
        "iframe src",
        &format!(
            "<iframe src=\"{}\" title=\"maze\" width=\"10\" height=\"10\"></iframe>",
            rel("/html/body/iframe/src.found")
        ),
    )
}

fn iframe_srcdoc(e: &Env<'_>) -> MazeResponse {
    body_only(
        "iframe srcdoc",
        &format!(
            "<iframe srcdoc=\"<p><a href='{}'>inline document link</a></p>\" title=\"maze\" width=\"100\" height=\"40\"></iframe>",
            e.abs("/html/body/iframe/srcdoc.found")
        ),
    )
}

fn img_dynsrc(_: &Env<'_>) -> MazeResponse {
    body_only(
        "img dynsrc",
        &format!(
            "<img dynsrc=\"{}\" alt=\"dynamic source\">",
            rel("/html/body/img/dynsrc.found")
        ),
    )
}

fn img_lowsrc(_: &Env<'_>) -> MazeResponse {
    body_only(
        "img lowsrc",
        &format!(
            "<img lowsrc=\"{}\" alt=\"low-resolution source\">",
            rel("/html/body/img/lowsrc.found")
        ),
    )
}

fn img_longdesc(_: &Env<'_>) -> MazeResponse {
    body_only(
        "img longdesc",
        &format!(
            "<img src=\"data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==\" longdesc=\"{}\" alt=\"long description\">",
            rel("/html/body/img/longdesc.found")
        ),
    )
}

fn img_src_data(_: &Env<'_>) -> MazeResponse {
    body_only(
        "img src (data: SVG with an inner image)",
        &format!(
            "<img src=\"data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' xmlns:xlink='http://www.w3.org/1999/xlink'><image xlink:href='{}'/></svg>\" alt=\"data image\">",
            rel("/html/body/img/src-data.found")
        ),
    )
}

fn img_src(_: &Env<'_>) -> MazeResponse {
    body_only(
        "img src",
        &format!("<img src=\"{}\" alt=\"image\">", rel("/html/body/img/src.found")),
    )
}

fn img_srcset(_: &Env<'_>) -> MazeResponse {
    body_only(
        "img srcset",
        &format!(
            "<img srcset=\"{} 1x, {} 2x\" alt=\"responsive image\">",
            rel("/html/body/img/srcset1x.found"),
            rel("/html/body/img/srcset2x.found")
        ),
    )
}

fn input_src(_: &Env<'_>) -> MazeResponse {
    body_only(
        "input image src",
        &format!(
            "<form action=\"/g32/html/body/input/\"><input type=\"image\" src=\"{}\" alt=\"submit image\"></form>",
            rel("/html/body/input/src.found")
        ),
    )
}

fn isindex_action(_: &Env<'_>) -> MazeResponse {
    body_only(
        "isindex action",
        &format!(
            "<isindex action=\"{}\" prompt=\"Search the maze\">",
            rel("/html/body/isindex/action.found")
        ),
    )
}

fn area_ping(_: &Env<'_>) -> MazeResponse {
    body_only(
        "map area ping",
        &format!(
            "<img src=\"data:image/gif;base64,R0lGODlhAQABAAAAACH5BAEKAAEALAAAAAABAAEAAAICTAEAOw==\" usemap=\"#maze\" alt=\"map\" width=\"10\" height=\"10\">\
             <map name=\"maze\"><area shape=\"rect\" coords=\"0,0,10,10\" href=\"#\" ping=\"{}\" alt=\"area\"></map>",
            rel("/html/body/map/area/ping.found")
        ),
    )
}

fn object_data(_: &Env<'_>) -> MazeResponse {
    body_only(
        "object data",
        &format!(
            "<object data=\"{}\" type=\"application/x-maze\" width=\"10\" height=\"10\"></object>",
            rel("/html/body/object/data.found")
        ),
    )
}

fn object_codebase(_: &Env<'_>) -> MazeResponse {
    body_only(
        "object codebase",
        &format!(
            "<object codebase=\"{}\" classid=\"clsid:maze\" width=\"10\" height=\"10\"></object>",
            rel("/html/body/object/codebase.found")
        ),
    )
}

fn object_param_value(_: &Env<'_>) -> MazeResponse {
    body_only(
        "object param value",
        &format!(
            "<object type=\"application/x-maze\" width=\"10\" height=\"10\"><param name=\"movie\" value=\"{}\"></object>",
            rel("/html/body/object/param/value.found")
        ),
    )
}

fn script_src(_: &Env<'_>) -> MazeResponse {
    page(
        "script src",
        &format!("<script src=\"{}\"></script>", rel("/html/body/script/src.found")),
        "<p>The head loads an external script.</p>",
    )
}

fn svg_image_xlink(_: &Env<'_>) -> MazeResponse {
    body_only(
        "svg image xlink:href",
        &format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" width=\"10\" height=\"10\"><image xlink:href=\"{}\" width=\"10\" height=\"10\"/></svg>",
            rel("/html/body/svg/image/xlink.found")
        ),
    )
}

fn svg_script_xlink(_: &Env<'_>) -> MazeResponse {
    body_only(
        "svg script xlink:href",
        &format!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" xmlns:xlink=\"http://www.w3.org/1999/xlink\" width=\"10\" height=\"10\"><script xlink:href=\"{}\"></script></svg>",
            rel("/html/body/svg/script/xlink.found")
        ),
    )
}

fn table_background(_: &Env<'_>) -> MazeResponse {
    body_only(
        "table background",
        &format!(
            "<table background=\"{}\"><tr><td>cell</td></tr></table>",
            rel("/html/body/table/background.found")
        ),
    )
}

fn td_background(_: &Env<'_>) -> MazeResponse {
    body_only(
        "table td background",
        &format!(
            "<table><tr><td background=\"{}\">cell</td></tr></table>",
            rel("/html/body/table/td/background.found")
        ),
    )
}

fn video_src(_: &Env<'_>) -> MazeResponse {
    body_only(
        "video src",
        &format!(
            "<video controls src=\"{}\"></video>",
            rel("/html/body/video/src.found")
        ),
    )
}

fn video_track_src(_: &Env<'_>) -> MazeResponse {
    body_only(
        "video track src",
        &format!(
            "<video controls><track kind=\"subtitles\" srclang=\"en\" src=\"{}\"></video>",
            rel("/html/body/video/track/src.found")
        ),
    )
}

fn video_poster(_: &Env<'_>) -> MazeResponse {
    body_only(
        "video poster",
        &format!(
            "<video controls poster=\"{}\"></video>",
            rel("/html/body/video/poster.found")
        ),
    )
}

fn head_profile(_: &Env<'_>) -> MazeResponse {
    raw(
        HTML,
        format!(
            "<!doctype html>\n<html lang=\"en\"><head profile=\"{}\"><meta charset=\"utf-8\"><title>crawl-maze: head profile</title></head>\n\
             <body><h1>head profile</h1><p>The head element names a metadata profile (HTML 4).</p></body></html>\n",
            rel("/html/head/profile.found")
        ),
    )
}

fn base_href(_: &Env<'_>) -> MazeResponse {
    page(
        "head base href",
        &format!("<base href=\"{}\">", rel("/html/head/base/")),
        "<p><a href=\"href.found\">a link relative to the document base</a></p>",
    )
}

fn comment_conditional(_: &Env<'_>) -> MazeResponse {
    page(
        "head conditional comment",
        &format!(
            "<!--[if IE]>\n<link rel=\"stylesheet\" href=\"{}\">\n<![endif]-->",
            rel("/html/head/comment-conditional.found")
        ),
        "<p>A stylesheet inside a conditional comment that only old Internet Explorer evaluated.</p>",
    )
}

fn import_implementation(_: &Env<'_>) -> MazeResponse {
    page(
        "head import implementation",
        &format!(
            "<import implementation=\"{}\">",
            rel("/html/head/import/implementation.found")
        ),
        "<p>An HTML Components (HTC) import element.</p>",
    )
}

fn link_href(_: &Env<'_>) -> MazeResponse {
    page(
        "head link href",
        &format!(
            "<link rel=\"stylesheet\" href=\"{}\">",
            rel("/html/head/link/href.found")
        ),
        "<p>The head links a stylesheet.</p>",
    )
}

fn meta_content_csp(e: &Env<'_>) -> MazeResponse {
    page(
        "head meta Content-Security-Policy",
        &format!(
            "<meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'self' ; report-uri {} ;\">",
            e.abs("/html/head/meta/content-csp.found")
        ),
        "<p>A CSP meta element whose <code>report-uri</code> names a reporting endpoint.</p>",
    )
}

fn meta_content_pinned(_: &Env<'_>) -> MazeResponse {
    page(
        "head meta msapplication-config",
        &format!(
            "<meta name=\"msapplication-config\" content=\"{}\">",
            rel("/html/head/meta/content-pinned-websites.found")
        ),
        "<p>A pinned-sites browser configuration file.</p>",
    )
}

fn meta_content_reading_view(_: &Env<'_>) -> MazeResponse {
    page(
        "head meta reading view",
        &format!(
            "<meta name=\"reading-view\" content=\"{}\">",
            rel("/html/head/meta/content-reading-view.found")
        ),
        "<p>A reading-view resource named by a meta element.</p>",
    )
}

fn meta_content_redirect(_: &Env<'_>) -> MazeResponse {
    page(
        "head meta refresh",
        &format!(
            "<meta http-equiv=\"refresh\" content=\"999; url={}\">",
            rel("/html/head/meta/content-redirect.found")
        ),
        "<p>A meta refresh with a long delay.</p>",
    )
}

fn url_full(e: &Env<'_>) -> MazeResponse {
    body_only(
        "misc full URL",
        &format!(
            "<p><a href=\"{}\">an absolute link including scheme and host</a></p>",
            e.abs("/html/misc/url/full-url.found")
        ),
    )
}

fn url_path_relative(_: &Env<'_>) -> MazeResponse {
    body_only(
        "misc path-relative URL",
        "<p><a href=\"../../../test/html/misc/url/path-relative-url.found\">a link relative to this page's directory</a></p>",
    )
}

fn url_protocol_relative(e: &Env<'_>) -> MazeResponse {
    body_only(
        "misc protocol-relative URL",
        &format!(
            "<p><a href=\"//{}{}\">a link without a scheme</a></p>",
            e.host,
            rel("/html/misc/url/protocol-relative-url.found")
        ),
    )
}

fn url_root_relative(_: &Env<'_>) -> MazeResponse {
    body_only(
        "misc root-relative URL",
        &format!(
            "<p><a href=\"{}\">a link relative to the origin root</a></p>",
            rel("/html/misc/url/root-relative-url.found")
        ),
    )
}

fn string_dot_dot_slash(_: &Env<'_>) -> MazeResponse {
    body_only(
        "misc inline string with ../ prefix",
        "<p>An inline string, not a link: ../../../test/html/misc/string/dot-dot-slash-prefix.found</p>",
    )
}

fn string_dot_slash(_: &Env<'_>) -> MazeResponse {
    body_only(
        "misc inline string with ./ prefix",
        "<p>An inline string, not a link: ./../../../test/html/misc/string/dot-slash-prefix.found</p>",
    )
}

fn string_url(e: &Env<'_>) -> MazeResponse {
    body_only(
        "misc inline URL string",
        &format!(
            "<p>An inline absolute URL, not a link: {}</p>",
            e.abs("/html/misc/string/url-string.found")
        ),
    )
}

fn string_known_extension(_: &Env<'_>) -> MazeResponse {
    body_only(
        "misc inline string with a known extension",
        "<p>An inline string with a document extension, not a link: /g32/test/html/misc/string/string-known-extension.pdf</p>",
    )
}

// ---- javascript ------------------------------------------------------------------------------

fn js_automatic_post(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript automatic POST",
        &format!(
            "<p>A POST request is sent shortly after the page opens.</p>\n<script>setTimeout(function () {{ fetch('{}', {{method: 'POST'}}); }}, 300);</script>",
            rel("/javascript/misc/automatic-post.found")
        ),
    )
}

fn js_comment_html(_: &Env<'_>) -> MazeResponse {
    page(
        "javascript comment",
        "<script src=\"/g32/javascript/misc/comment.js\"></script>",
        "<p>The external script mentions a URL in a comment.</p>",
    )
}

fn js_comment_js(e: &Env<'_>) -> MazeResponse {
    raw(
        "text/javascript; charset=utf-8",
        format!(
            "// crawl-maze: the endpoint below is only mentioned in this comment\n// {}\nvar mazeComment = true;\n",
            e.abs("/javascript/misc/comment.found")
        ),
    )
}

fn js_string_variable_html(_: &Env<'_>) -> MazeResponse {
    page(
        "javascript string variable",
        "<script src=\"/g32/javascript/misc/string-variable.js\"></script>",
        "<p>The external script stores a URL in a variable and never uses it.</p>",
    )
}

fn js_string_variable_js(e: &Env<'_>) -> MazeResponse {
    raw(
        "text/javascript; charset=utf-8",
        format!(
            "var mazeUrl = \"{}\";\n",
            e.abs("/javascript/misc/string-variable.found")
        ),
    )
}

fn js_string_concat_html(_: &Env<'_>) -> MazeResponse {
    page(
        "javascript concatenated string variable",
        "<script src=\"/g32/javascript/misc/string-concat-variable.js\"></script>",
        "<p>The external script builds a URL from two string variables and never uses it.</p>",
    )
}

fn js_string_concat_js(e: &Env<'_>) -> MazeResponse {
    raw(
        "text/javascript; charset=utf-8",
        format!(
            "var mazeDomain = \"http://{}/\";\nvar mazePath = \"g32/test/javascript/misc/string-concat-variable.found\";\nvar mazeFull = mazeDomain + mazePath;\n",
            e.host
        ),
    )
}

fn fw_angular_event_handler(_: &Env<'_>) -> MazeResponse {
    body_only(
        "framework event binding (Angular-style)",
        &format!(
            "<p>A template event binding (<code>(click)</code>) is wired by the framework at bootstrap, not by an attribute or a visible listener.</p>\n\
             <button type=\"button\" data-maze-click=\"load\">Load component</button>\n\
             <script>\n(function bootstrap() {{\n  var handlers = {{ load: function () {{ fetch('{}'); }} }};\n  document.querySelectorAll('[data-maze-click]').forEach(function (el) {{\n    el.addEventListener('click', handlers[el.getAttribute('data-maze-click')]);\n  }});\n}})();\n</script>",
            rel("/javascript/frameworks/angular/event-handler.found")
        ),
    )
}

fn fw_angular_router_outlet(_: &Env<'_>) -> MazeResponse {
    body_only(
        "framework router outlet (Angular-style)",
        &format!(
            "<p>A router link pushes a client-side route and the outlet loads the route's view.</p>\n\
             <nav><a href=\"/g32/javascript/frameworks/angular/router-outlet.html#/detail\" data-route=\"/detail\">Detail route</a></nav>\n<div id=\"outlet\"></div>\n\
             <script>\ndocument.querySelector('[data-route]').addEventListener('click', function (ev) {{\n  ev.preventDefault();\n  history.pushState({{}}, '', '#/detail');\n  fetch('{}').then(function () {{ document.getElementById('outlet').textContent = 'detail'; }});\n}});\n</script>",
            rel("/javascript/frameworks/angular/router-outlet.found")
        ),
    )
}

fn fw_angularjs_ng_href(_: &Env<'_>) -> MazeResponse {
    body_only(
        "framework computed href (AngularJS ng-href)",
        &format!(
            "<p>The link's <code>href</code> is bound from a model value after the page runs; the markup carries only the binding.</p>\n\
             <a data-ng-href=\"{{{{ detailUrl }}}}\">Detail (bound)</a>\n\
             <script>\n(function digest() {{\n  var model = {{ detailUrl: '{}' }};\n  var a = document.querySelector('[data-ng-href]');\n  a.setAttribute('href', model[a.getAttribute('data-ng-href').replace(/[{{}} ]/g, '')]);\n}})();\n</script>",
            rel("/javascript/frameworks/angularjs/ng-href.found")
        ),
    )
}

fn fw_polymer_event_handler(_: &Env<'_>) -> MazeResponse {
    body_only(
        "framework custom element handler (Polymer-style)",
        &format!(
            "<p>A custom element with a shadow root handles clicks inside its template.</p>\n<maze-button></maze-button>\n\
             <script>\ncustomElements.define('maze-button', class extends HTMLElement {{\n  connectedCallback() {{\n    var root = this.attachShadow({{mode: 'open'}});\n    root.innerHTML = '<button type=\"button\">Shadow action</button>';\n    root.querySelector('button').addEventListener('click', function () {{ fetch('{}'); }});\n  }}\n}});\n</script>",
            rel("/javascript/frameworks/polymer/event-handler.found")
        ),
    )
}

fn fw_polymer_router(_: &Env<'_>) -> MazeResponse {
    body_only(
        "framework hash router (Polymer-style)",
        &format!(
            "<p>A hash route change loads the route's data.</p>\n<a href=\"#/items\">Items route</a>\n<div id=\"view\"></div>\n\
             <script>\nwindow.addEventListener('hashchange', function () {{\n  if (location.hash === '#/items') {{ fetch('{}').then(function () {{ document.getElementById('view').textContent = 'items'; }}); }}\n}});\n</script>",
            rel("/javascript/frameworks/polymer/polymer-router.found")
        ),
    )
}

fn fw_react_route_path(_: &Env<'_>) -> MazeResponse {
    body_only(
        "framework route path (React Router-style)",
        &format!(
            "<p>A client-side route whose component fetches its data when matched.</p>\n\
             <a href=\"/g32/javascript/frameworks/react/route-path.html?route=profile\" data-link>Profile route</a>\n<div id=\"app\"></div>\n\
             <script>\ndocument.querySelector('[data-link]').addEventListener('click', function (ev) {{\n  ev.preventDefault();\n  history.pushState({{}}, '', '?route=profile');\n  fetch('{}').then(function () {{ document.getElementById('app').textContent = 'profile'; }});\n}});\n</script>",
            rel("/javascript/frameworks/react/route-path.found")
        ),
    )
}

fn fw_react_search(_: &Env<'_>) -> MazeResponse {
    body_only(
        "framework controlled search form (React-style)",
        &format!(
            "<p>A controlled form whose submit handler queries an API instead of navigating.</p>\n\
             <form id=\"search\"><label>Search <input type=\"search\" name=\"q\" value=\"maze\"></label> <button type=\"submit\">Go</button></form>\n<ul id=\"results\"></ul>\n\
             <script>\ndocument.getElementById('search').addEventListener('submit', function (ev) {{\n  ev.preventDefault();\n  var q = encodeURIComponent(ev.target.elements.q.value);\n  fetch('{}?q=' + q).then(function () {{ document.getElementById('results').textContent = 'results'; }});\n}});\n</script>",
            rel("/javascript/frameworks/react/index.html/search.found")
        ),
    )
}

fn js_delete(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript DELETE on click",
        &format!(
            "<p>Clicking the button sends a DELETE request.</p>\n<button type=\"button\" id=\"btn\">Delete item</button>\n{}",
            click_fetch("btn", "/javascript/interactive/js-delete.found", "DELETE")
        ),
    )
}

fn js_post(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript POST on click (event attribute)",
        &format!(
            "<p>Clicking the button sends a POST request from an <code>onclick</code> attribute.</p>\n<button type=\"button\" onclick=\"fetch('{}', {{method: 'POST'}})\">Post item</button>",
            rel("/javascript/interactive/js-post.found")
        ),
    )
}

fn js_post_event_listener(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript POST on click (event listener)",
        &format!(
            "<p>Clicking the button sends a POST request from a listener added with <code>addEventListener</code>.</p>\n<button type=\"button\" id=\"btn\">Post item</button>\n{}",
            click_fetch("btn", "/javascript/interactive/js-post-event-listener.found", "POST")
        ),
    )
}

fn js_put(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript PUT on click",
        &format!(
            "<p>Clicking the button sends a PUT request.</p>\n<button type=\"button\" id=\"btn\">Put item</button>\n{}",
            click_fetch("btn", "/javascript/interactive/js-put.found", "PUT")
        ),
    )
}

fn js_listener_and_attribute(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript listener and event attribute on one button",
        &format!(
            "<p>One button fires two requests: one from its <code>onclick</code> attribute, one from a listener.</p>\n\
             <button type=\"button\" id=\"btn\" onclick=\"fetch('{}')\">Fire both</button>\n{}",
            rel("/javascript/interactive/listener-and-event-attribute-first.found"),
            click_fetch(
                "btn",
                "/javascript/interactive/listener-and-event-attribute-second.found",
                "GET"
            )
        ),
    )
}

fn js_multi_step_event_attribute(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript multi-step request (event attribute)",
        &format!(
            "<p>The first click creates a second button whose <code>onclick</code> attribute sends the request.</p>\n\
             <button type=\"button\" id=\"reveal\">Show secret button</button>\n<div id=\"slot\"></div>\n\
             <script>\ndocument.getElementById('reveal').addEventListener('click', function () {{\n  if (document.getElementById('secret')) return;\n  var b = document.createElement('button');\n  b.type = 'button'; b.id = 'secret'; b.textContent = 'Secret request';\n  b.setAttribute('onclick', \"fetch('{}')\");\n  document.getElementById('slot').appendChild(b);\n}});\n</script>",
            rel("/javascript/interactive/multi-step-request-event-attribute.found")
        ),
    )
}

fn multi_step_listener(target: &str, element: &str, listener_before_dom: bool) -> String {
    let (create, attach) = if listener_before_dom {
        (
            format!(
                "var el = document.createElement('{element}');\n  el.id = 'secret'; el.textContent = 'Secret request'; el.tabIndex = 0;{}\n  el.addEventListener('click', function () {{ fetch('{}'); }});\n  document.getElementById('slot').appendChild(el);",
                if element == "button" { " el.type = 'button';" } else { " el.setAttribute('role', 'button');" },
                rel(target)
            ),
            String::new(),
        )
    } else {
        (
            format!(
                "var el = document.createElement('{element}');\n  el.id = 'secret'; el.textContent = 'Secret request'; el.tabIndex = 0;{}\n  document.getElementById('slot').appendChild(el);",
                if element == "button" { " el.type = 'button';" } else { " el.setAttribute('role', 'button');" }
            ),
            format!(
                "\n  document.getElementById('secret').addEventListener('click', function () {{ fetch('{}'); }});",
                rel(target)
            ),
        )
    };
    format!(
        "<p>The first click creates a second control; a listener on it sends the request.</p>\n\
         <button type=\"button\" id=\"reveal\">Show secret control</button>\n<div id=\"slot\"></div>\n\
         <script>\ndocument.getElementById('reveal').addEventListener('click', function () {{\n  if (document.getElementById('secret')) return;\n  {create}{attach}\n}});\n</script>"
    )
}

fn js_multi_step_listener_div_dom(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript multi-step request (div, listener before DOM insertion)",
        &multi_step_listener(
            "/javascript/interactive/multi-step-request-event-listener-div-dom.found",
            "div",
            true,
        ),
    )
}

fn js_multi_step_listener_div(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript multi-step request (div, listener after DOM insertion)",
        &multi_step_listener(
            "/javascript/interactive/multi-step-request-event-listener-div.found",
            "div",
            false,
        ),
    )
}

fn js_multi_step_listener_dom(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript multi-step request (button, listener before DOM insertion)",
        &multi_step_listener(
            "/javascript/interactive/multi-step-request-event-listener-dom.found",
            "button",
            true,
        ),
    )
}

fn js_multi_step_listener(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript multi-step request (button, listener after DOM insertion)",
        &multi_step_listener(
            "/javascript/interactive/multi-step-request-event-listener.found",
            "button",
            false,
        ),
    )
}

fn js_multi_step_redefine(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript multi-step request (redefined event attribute)",
        &format!(
            "<p>The first click replaces the button's <code>onclick</code>; the second click sends the request.</p>\n\
             <button type=\"button\" id=\"btn\" onclick=\"this.setAttribute('onclick', &quot;fetch('{}')&quot;); this.textContent = 'Send request';\">Arm button</button>",
            rel("/javascript/interactive/multi-step-request-redefine-event-attribute.found")
        ),
    )
}

fn js_multi_step_remove_button(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript multi-step request (button replaced)",
        &format!(
            "<p>The first click removes the button and inserts a different one that sends the request.</p>\n\
             <div id=\"slot\"><button type=\"button\" id=\"first\">Replace me</button></div>\n\
             <script>\ndocument.getElementById('first').addEventListener('click', function () {{\n  var b = document.createElement('button');\n  b.type = 'button'; b.id = 'second'; b.textContent = 'Send request';\n  b.addEventListener('click', function () {{ fetch('{}'); }});\n  var slot = document.getElementById('slot');\n  slot.removeChild(this);\n  slot.appendChild(b);\n}});\n</script>",
            rel("/javascript/interactive/multi-step-request-remove-button.found")
        ),
    )
}

fn js_multi_step_remove_listener(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript multi-step request (listener swapped)",
        &format!(
            "<p>The first click removes the arming listener and installs the one that sends the request.</p>\n\
             <button type=\"button\" id=\"btn\">Arm</button>\n\
             <script>\nvar btn = document.getElementById('btn');\nfunction arm() {{\n  btn.removeEventListener('click', arm);\n  btn.textContent = 'Send request';\n  btn.addEventListener('click', function () {{ fetch('{}'); }});\n}}\nbtn.addEventListener('click', arm);\n</script>",
            rel("/javascript/interactive/multi-step-request-remove-event-listener.found")
        ),
    )
}

fn js_two_listeners(_: &Env<'_>) -> MazeResponse {
    body_only(
        "javascript two listeners on one button",
        &format!(
            "<p>One click fires two POST requests from two listeners on the same button.</p>\n<button type=\"button\" id=\"btn\">Fire both</button>\n{}\n{}",
            click_fetch("btn", "/javascript/interactive/two-listeners-first.found", "POST"),
            click_fetch("btn", "/javascript/interactive/two-listeners-second.found", "POST")
        ),
    )
}

// ---- misc ------------------------------------------------------------------------------------

fn misc_robots(_: &Env<'_>) -> MazeResponse {
    body_only(
        "misc known file robots.txt",
        "<p>The origin's <code>/robots.txt</code> lists an <code>Allow:</code> path that only a crawler reading robots can find.</p>",
    )
}

fn misc_sitemap(_: &Env<'_>) -> MazeResponse {
    body_only(
        "misc known file sitemap.xml",
        "<p>The origin's <code>/robots.txt</code> names <code>/g32/sitemap.xml</code>, which lists a page nothing links to.</p>",
    )
}

// ---- table -----------------------------------------------------------------------------------

use MazePlane::{Browser, Deferred, Static};

macro_rules! p {
    ($path:literal, $plane:ident, $title:literal, $render:ident, [$($t:literal),* $(,)?]) => {
        MazePage { path: $path, plane: $plane, title: $title, targets: &[$($t),*], render: $render }
    };
}

/// Every test page, in index order.
pub const PAGES: &[MazePage] = &[
    p!(
        "css/font-face.html",
        Static,
        "font-face source in a linked stylesheet",
        css_font_face_html,
        []
    ),
    p!(
        "css/font-face.css",
        Static,
        "stylesheet declaring the font face",
        css_font_face_css,
        ["/css/font-face.found"]
    ),
    p!(
        "headers/content-location.html",
        Static,
        "Content-Location header",
        headers_content_location,
        ["/headers/content-location.found"]
    ),
    p!(
        "headers/link.html",
        Static,
        "Link header",
        headers_link,
        ["/headers/link.found"]
    ),
    p!(
        "headers/location.html",
        Static,
        "Location header (301)",
        headers_location,
        ["/headers/location.found"]
    ),
    p!(
        "headers/refresh.html",
        Static,
        "Refresh header",
        headers_refresh,
        ["/headers/refresh.found"]
    ),
    p!(
        "html/doctype.html",
        Static,
        "doctype system identifier",
        html_doctype,
        ["/html/doctype.found"]
    ),
    p!(
        "html/manifest.html",
        Static,
        "html manifest",
        html_manifest,
        ["/html/manifest.found"]
    ),
    p!(
        "html/body/background.html",
        Static,
        "body background",
        body_background,
        ["/html/body/background.found"]
    ),
    p!(
        "html/body/a/href.html",
        Static,
        "a href",
        a_href,
        ["/html/body/a/href.found"]
    ),
    p!(
        "html/body/a/ping.html",
        Static,
        "a ping",
        a_ping,
        ["/html/body/a/ping.found"]
    ),
    p!(
        "html/body/audio/src.html",
        Static,
        "audio src",
        audio_src,
        ["/html/body/audio/src.found"]
    ),
    p!(
        "html/body/audio/source/src.html",
        Static,
        "audio source src",
        audio_source_src,
        ["/html/body/audio/source/src.found"]
    ),
    p!(
        "html/body/audio/source/srcset.html",
        Static,
        "audio source srcset",
        audio_source_srcset,
        [
            "/html/body/audio/source/srcset1x.found",
            "/html/body/audio/source/srcset2x.found"
        ]
    ),
    p!(
        "html/body/applet/archive.html",
        Static,
        "applet archive",
        applet_archive,
        ["/html/body/applet/archive.found"]
    ),
    p!(
        "html/body/applet/codebase.html",
        Static,
        "applet codebase",
        applet_codebase,
        ["/html/body/applet/codebase.found"]
    ),
    p!(
        "html/body/blockquote/cite.html",
        Static,
        "blockquote cite",
        blockquote_cite,
        ["/html/body/blockquote/cite.found"]
    ),
    p!(
        "html/body/embed/src.html",
        Static,
        "embed src",
        embed_src,
        ["/html/body/embed/src.found"]
    ),
    p!(
        "html/body/form/action-get.html",
        Static,
        "form action GET",
        form_action_get,
        ["/html/body/form/action-get.found"]
    ),
    p!(
        "html/body/form/action-post.html",
        Browser,
        "form action POST",
        form_action_post,
        ["/html/body/form/action-post.found"]
    ),
    p!(
        "html/body/form/button/formaction.html",
        Static,
        "button formaction",
        button_formaction,
        ["/html/body/form/button/formaction.found"]
    ),
    p!(
        "html/body/frameset/frame/src.html",
        Static,
        "frameset frame src",
        frameset_frame_src,
        ["/html/body/frameset/frame/src.found"]
    ),
    p!(
        "html/body/iframe/src.html",
        Static,
        "iframe src",
        iframe_src,
        ["/html/body/iframe/src.found"]
    ),
    p!(
        "html/body/iframe/srcdoc.html",
        Static,
        "iframe srcdoc",
        iframe_srcdoc,
        ["/html/body/iframe/srcdoc.found"]
    ),
    p!(
        "html/body/img/dynsrc.html",
        Static,
        "img dynsrc",
        img_dynsrc,
        ["/html/body/img/dynsrc.found"]
    ),
    p!(
        "html/body/img/lowsrc.html",
        Static,
        "img lowsrc",
        img_lowsrc,
        ["/html/body/img/lowsrc.found"]
    ),
    p!(
        "html/body/img/longdesc.html",
        Static,
        "img longdesc",
        img_longdesc,
        ["/html/body/img/longdesc.found"]
    ),
    p!(
        "html/body/img/src-data.html",
        Deferred,
        "img src data: URI with an inner image",
        img_src_data,
        ["/html/body/img/src-data.found"]
    ),
    p!(
        "html/body/img/src.html",
        Static,
        "img src",
        img_src,
        ["/html/body/img/src.found"]
    ),
    p!(
        "html/body/img/srcset.html",
        Static,
        "img srcset",
        img_srcset,
        ["/html/body/img/srcset1x.found", "/html/body/img/srcset2x.found"]
    ),
    p!(
        "html/body/input/src.html",
        Static,
        "input type=image src",
        input_src,
        ["/html/body/input/src.found"]
    ),
    p!(
        "html/body/isindex/action.html",
        Static,
        "isindex action",
        isindex_action,
        ["/html/body/isindex/action.found"]
    ),
    p!(
        "html/body/map/area/ping.html",
        Static,
        "map area ping",
        area_ping,
        ["/html/body/map/area/ping.found"]
    ),
    p!(
        "html/body/object/data.html",
        Static,
        "object data",
        object_data,
        ["/html/body/object/data.found"]
    ),
    p!(
        "html/body/object/codebase.html",
        Static,
        "object codebase",
        object_codebase,
        ["/html/body/object/codebase.found"]
    ),
    p!(
        "html/body/object/param/value.html",
        Static,
        "object param value",
        object_param_value,
        ["/html/body/object/param/value.found"]
    ),
    p!(
        "html/body/script/src.html",
        Static,
        "script src",
        script_src,
        ["/html/body/script/src.found"]
    ),
    p!(
        "html/body/svg/image/xlink.html",
        Static,
        "svg image xlink:href",
        svg_image_xlink,
        ["/html/body/svg/image/xlink.found"]
    ),
    p!(
        "html/body/svg/script/xlink.html",
        Static,
        "svg script xlink:href",
        svg_script_xlink,
        ["/html/body/svg/script/xlink.found"]
    ),
    p!(
        "html/body/table/background.html",
        Static,
        "table background",
        table_background,
        ["/html/body/table/background.found"]
    ),
    p!(
        "html/body/table/td/background.html",
        Static,
        "td background",
        td_background,
        ["/html/body/table/td/background.found"]
    ),
    p!(
        "html/body/video/src.html",
        Static,
        "video src",
        video_src,
        ["/html/body/video/src.found"]
    ),
    p!(
        "html/body/video/track/src.html",
        Static,
        "video track src",
        video_track_src,
        ["/html/body/video/track/src.found"]
    ),
    p!(
        "html/body/video/poster.html",
        Static,
        "video poster",
        video_poster,
        ["/html/body/video/poster.found"]
    ),
    p!(
        "html/head/profile.html",
        Deferred,
        "head profile",
        head_profile,
        ["/html/head/profile.found"]
    ),
    p!(
        "html/head/base/href.html",
        Static,
        "base href with a relative link",
        base_href,
        ["/html/head/base/href.found"]
    ),
    p!(
        "html/head/comment-conditional.html",
        Deferred,
        "conditional comment",
        comment_conditional,
        ["/html/head/comment-conditional.found"]
    ),
    p!(
        "html/head/import/implementation.html",
        Static,
        "import implementation",
        import_implementation,
        ["/html/head/import/implementation.found"]
    ),
    p!(
        "html/head/link/href.html",
        Static,
        "link href",
        link_href,
        ["/html/head/link/href.found"]
    ),
    p!(
        "html/head/meta/content-csp.html",
        Static,
        "meta Content-Security-Policy report-uri",
        meta_content_csp,
        ["/html/head/meta/content-csp.found"]
    ),
    p!(
        "html/head/meta/content-pinned-websites.html",
        Deferred,
        "meta msapplication-config",
        meta_content_pinned,
        ["/html/head/meta/content-pinned-websites.found"]
    ),
    p!(
        "html/head/meta/content-reading-view.html",
        Deferred,
        "meta reading view",
        meta_content_reading_view,
        ["/html/head/meta/content-reading-view.found"]
    ),
    p!(
        "html/head/meta/content-redirect.html",
        Static,
        "meta refresh",
        meta_content_redirect,
        ["/html/head/meta/content-redirect.found"]
    ),
    p!(
        "html/misc/url/full-url.html",
        Static,
        "full URL",
        url_full,
        ["/html/misc/url/full-url.found"]
    ),
    p!(
        "html/misc/url/path-relative-url.html",
        Static,
        "path-relative URL",
        url_path_relative,
        ["/html/misc/url/path-relative-url.found"]
    ),
    p!(
        "html/misc/url/protocol-relative-url.html",
        Static,
        "protocol-relative URL",
        url_protocol_relative,
        ["/html/misc/url/protocol-relative-url.found"]
    ),
    p!(
        "html/misc/url/root-relative-url.html",
        Static,
        "root-relative URL",
        url_root_relative,
        ["/html/misc/url/root-relative-url.found"]
    ),
    p!(
        "html/misc/string/dot-dot-slash-prefix.html",
        Static,
        "inline string with ../ prefix",
        string_dot_dot_slash,
        ["/html/misc/string/dot-dot-slash-prefix.found"]
    ),
    p!(
        "html/misc/string/dot-slash-prefix.html",
        Static,
        "inline string with ./ prefix",
        string_dot_slash,
        ["/html/misc/string/dot-slash-prefix.found"]
    ),
    p!(
        "html/misc/string/url-string.html",
        Static,
        "inline absolute URL string",
        string_url,
        ["/html/misc/string/url-string.found"]
    ),
    p!(
        "html/misc/string/string-known-extension.html",
        Static,
        "inline string with a known extension",
        string_known_extension,
        ["/html/misc/string/string-known-extension.pdf"]
    ),
    p!(
        "javascript/misc/automatic-post.html",
        Browser,
        "automatic POST after load",
        js_automatic_post,
        ["/javascript/misc/automatic-post.found"]
    ),
    p!(
        "javascript/misc/comment.html",
        Static,
        "URL in a script comment",
        js_comment_html,
        []
    ),
    p!(
        "javascript/misc/comment.js",
        Static,
        "script with the URL in a comment",
        js_comment_js,
        ["/javascript/misc/comment.found"]
    ),
    p!(
        "javascript/misc/string-variable.html",
        Static,
        "URL in a string variable",
        js_string_variable_html,
        []
    ),
    p!(
        "javascript/misc/string-variable.js",
        Static,
        "script with the URL in a variable",
        js_string_variable_js,
        ["/javascript/misc/string-variable.found"]
    ),
    p!(
        "javascript/misc/string-concat-variable.html",
        Static,
        "URL built by string concatenation",
        js_string_concat_html,
        []
    ),
    p!(
        "javascript/misc/string-concat-variable.js",
        Static,
        "script concatenating two string variables (AST pass inlines both constants)",
        js_string_concat_js,
        ["/javascript/misc/string-concat-variable.found"]
    ),
    p!(
        "javascript/frameworks/angular/event-handler.html",
        Browser,
        "framework event binding",
        fw_angular_event_handler,
        ["/javascript/frameworks/angular/event-handler.found"]
    ),
    p!(
        "javascript/frameworks/angular/router-outlet.html",
        Browser,
        "framework router outlet",
        fw_angular_router_outlet,
        ["/javascript/frameworks/angular/router-outlet.found"]
    ),
    p!(
        "javascript/frameworks/angularjs/ng-href.html",
        Browser,
        "framework computed href",
        fw_angularjs_ng_href,
        ["/javascript/frameworks/angularjs/ng-href.found"]
    ),
    p!(
        "javascript/frameworks/polymer/event-handler.html",
        Browser,
        "custom element handler in a shadow root",
        fw_polymer_event_handler,
        ["/javascript/frameworks/polymer/event-handler.found"]
    ),
    p!(
        "javascript/frameworks/polymer/polymer-router.html",
        Browser,
        "hash router",
        fw_polymer_router,
        ["/javascript/frameworks/polymer/polymer-router.found"]
    ),
    p!(
        "javascript/frameworks/react/route-path.html",
        Browser,
        "client-side route path",
        fw_react_route_path,
        ["/javascript/frameworks/react/route-path.found"]
    ),
    p!(
        "javascript/frameworks/react/search.html",
        Browser,
        "controlled search form",
        fw_react_search,
        ["/javascript/frameworks/react/index.html/search.found"]
    ),
    p!(
        "javascript/interactive/js-delete.html",
        Browser,
        "DELETE on click",
        js_delete,
        ["/javascript/interactive/js-delete.found"]
    ),
    p!(
        "javascript/interactive/js-post.html",
        Browser,
        "POST on click (event attribute)",
        js_post,
        ["/javascript/interactive/js-post.found"]
    ),
    p!(
        "javascript/interactive/js-post-event-listener.html",
        Browser,
        "POST on click (event listener)",
        js_post_event_listener,
        ["/javascript/interactive/js-post-event-listener.found"]
    ),
    p!(
        "javascript/interactive/js-put.html",
        Browser,
        "PUT on click",
        js_put,
        ["/javascript/interactive/js-put.found"]
    ),
    p!(
        "javascript/interactive/listener-and-event-attribute.html",
        Browser,
        "listener and event attribute on one button",
        js_listener_and_attribute,
        [
            "/javascript/interactive/listener-and-event-attribute-first.found",
            "/javascript/interactive/listener-and-event-attribute-second.found"
        ]
    ),
    p!(
        "javascript/interactive/multi-step-request-event-attribute.html",
        Browser,
        "multi-step: created button with onclick",
        js_multi_step_event_attribute,
        ["/javascript/interactive/multi-step-request-event-attribute.found"]
    ),
    p!(
        "javascript/interactive/multi-step-request-event-listener-div-dom.html",
        Browser,
        "multi-step: created div, listener before insertion",
        js_multi_step_listener_div_dom,
        ["/javascript/interactive/multi-step-request-event-listener-div-dom.found"]
    ),
    p!(
        "javascript/interactive/multi-step-request-event-listener-div.html",
        Browser,
        "multi-step: created div, listener after insertion",
        js_multi_step_listener_div,
        ["/javascript/interactive/multi-step-request-event-listener-div.found"]
    ),
    p!(
        "javascript/interactive/multi-step-request-event-listener-dom.html",
        Browser,
        "multi-step: created button, listener before insertion",
        js_multi_step_listener_dom,
        ["/javascript/interactive/multi-step-request-event-listener-dom.found"]
    ),
    p!(
        "javascript/interactive/multi-step-request-event-listener.html",
        Browser,
        "multi-step: created button, listener after insertion",
        js_multi_step_listener,
        ["/javascript/interactive/multi-step-request-event-listener.found"]
    ),
    p!(
        "javascript/interactive/multi-step-request-redefine-event-attribute.html",
        Browser,
        "multi-step: redefined onclick",
        js_multi_step_redefine,
        ["/javascript/interactive/multi-step-request-redefine-event-attribute.found"]
    ),
    p!(
        "javascript/interactive/multi-step-request-remove-button.html",
        Browser,
        "multi-step: button replaced",
        js_multi_step_remove_button,
        ["/javascript/interactive/multi-step-request-remove-button.found"]
    ),
    p!(
        "javascript/interactive/multi-step-request-remove-event-listener.html",
        Browser,
        "multi-step: listener swapped",
        js_multi_step_remove_listener,
        ["/javascript/interactive/multi-step-request-remove-event-listener.found"]
    ),
    p!(
        "javascript/interactive/two-listeners.html",
        Browser,
        "two listeners on one button",
        js_two_listeners,
        [
            "/javascript/interactive/two-listeners-first.found",
            "/javascript/interactive/two-listeners-second.found"
        ]
    ),
    p!(
        "misc/known-files/robots.txt.html",
        Static,
        "robots.txt Allow path",
        misc_robots,
        ["/misc/known-files/robots.txt.found"]
    ),
    p!(
        "misc/known-files/sitemap.xml.html",
        Static,
        "sitemap.xml entry",
        misc_sitemap,
        ["/misc/known-files/sitemap.xml.found"]
    ),
];

/// The page at `path` (below `/g32/`).
#[must_use]
pub fn page_at(path: &str) -> Option<&'static MazePage> {
    PAGES.iter().find(|p| p.path == path)
}

/// Every expected endpoint (blueprint form), in page order; 91 entries.
#[must_use]
pub fn expected_paths() -> Vec<&'static str> {
    PAGES.iter().flat_map(|p| p.targets.iter().copied()).collect()
}

/// The page whose construct references `target`.
#[must_use]
pub fn page_for(target: &str) -> Option<&'static MazePage> {
    PAGES.iter().find(|p| p.targets.contains(&target))
}

/// `robots.txt` of the gym origin while this fixture owns it: the known-files `Allow:` path
/// and the fixture sitemap.
#[must_use]
pub fn robots_txt(host: &str) -> String {
    format!(
        "User-agent: *\nAllow: {}\nCrawl-delay: 0\n\nSitemap: http://{host}/g32/sitemap.xml\n",
        rel("/misc/known-files/robots.txt.found")
    )
}

fn sitemap_xml(host: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n  <url><loc>http://{host}{}</loc></url>\n</urlset>\n",
        rel("/misc/known-files/sitemap.xml.found")
    )
}

fn category_index(category: &str) -> MazeResponse {
    let mut body = String::from("<ul>\n");
    for p in PAGES
        .iter()
        .filter(|p| p.category() == category && !p.path.ends_with(".js") && !p.path.ends_with(".css"))
    {
        let _ = writeln!(
            body,
            "<li><a href=\"/g32/{}\">{}</a> — {}</li>",
            p.path,
            escape(p.path),
            escape(p.title)
        );
    }
    body.push_str("</ul>");
    page(&format!("{category} cases"), "", &body)
}

/// Serve `rest` (the path below `/g32/`, no leading slash) for request host `host`; `None`
/// for the entry page (served from the embedded `index.html`) and unknown paths.
#[must_use]
pub fn serve(rest: &str, host: &str) -> Option<MazeResponse> {
    let key = rest.trim_start_matches('/');
    if key.is_empty() || key == "index.html" {
        return None;
    }
    if key == "sitemap.xml" {
        return Some(raw("application/xml", sitemap_xml(host)));
    }
    if let Some(target) = key.strip_prefix("test/") {
        let target = format!("/{target}");
        return page_for(&target).map(|_| raw(TEXT, format!("found {target}\n")));
    }
    let trimmed = key.trim_end_matches('/');
    if CATEGORIES.contains(&trimmed) {
        return Some(category_index(trimmed));
    }
    page_at(key).map(|p| p.render(host))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn ninety_one_unique_targets_each_under_its_category() {
        let all = expected_paths();
        assert_eq!(all.len(), 91);
        let set: BTreeSet<_> = all.iter().collect();
        assert_eq!(set.len(), 91);
        for p in PAGES {
            for t in p.targets {
                assert!(t.starts_with(&format!("/{}/", p.category())), "{t} vs {}", p.path);
            }
        }
        let mut cats: BTreeSet<&str> = BTreeSet::new();
        cats.extend(PAGES.iter().map(MazePage::category));
        assert_eq!(cats.into_iter().collect::<Vec<_>>(), CATEGORIES);
    }

    #[test]
    fn every_page_category_index_and_target_serves() {
        for p in PAGES {
            let r = serve(p.path, "h:1").unwrap();
            assert!(
                r.status == 200 || r.status == 201 || r.status == 301,
                "{}",
                p.path
            );
            for t in p.targets {
                let f = serve(&format!("test{t}"), "h:1").unwrap();
                assert_eq!(f.status, 200);
            }
        }
        for c in CATEGORIES {
            let idx = serve(&format!("{c}/"), "h:1").unwrap();
            assert!(idx.body.contains(&format!("/g32/{c}/")), "{c}");
        }
        assert!(serve("", "h:1").is_none());
        assert!(serve("test/nope.found", "h:1").is_none());
        assert!(serve("html/body/nope.html", "h:1").is_none());
        assert!(robots_txt("h:1").contains("Allow: /g32/test/misc/known-files/robots.txt.found"));
        assert!(serve("sitemap.xml", "h:1")
            .unwrap()
            .body
            .contains("/g32/test/misc/known-files/sitemap.xml.found"));
    }
}
