//! HTML body parsers: every construct of katana's parser table plus inline
//! script text and event-handler attributes.
//!
//! Ported from projectdiscovery/katana `pkg/engine/parser/parser.go`
//! (`body*TagParser`, `bodyFormTagParser`, `bodyHtmxAttrParser`,
//! `scriptContentRegexParser`) at commit 9662cd7 (MIT). The tree is walked
//! once; each element is dispatched on its tag name. Form bodies are
//! synthesized with deterministic placeholder values (no random fillers).

use crawlx_core::config::JavascriptMode;
use http::Method;
use scraper::{ElementRef, Html};
use url::Url;

use super::headers::parse_refresh;
use super::script::extract_relative_endpoints;
use super::{Confidence, DiscoveredEndpoint, EndpointSource};
use crate::dom::{srcset_urls, walk};

const fn src(tag: &'static str, attribute: &'static str) -> EndpointSource {
    EndpointSource { tag, attribute }
}

/// `a href`.
pub const A_HREF: EndpointSource = src("a", "href");
/// `a ping`.
pub const A_PING: EndpointSource = src("a", "ping");
/// `link href`.
pub const LINK_HREF: EndpointSource = src("link", "href");
/// `embed src`.
pub const EMBED_SRC: EndpointSource = src("embed", "src");
/// `frame src`.
pub const FRAME_SRC: EndpointSource = src("frame", "src");
/// `iframe src`.
pub const IFRAME_SRC: EndpointSource = src("iframe", "src");
/// Endpoints mined from `iframe srcdoc`.
pub const IFRAME_SRCDOC: EndpointSource = src("iframe", "srcdoc");
/// `input[type=image] src`.
pub const INPUT_IMAGE_SRC: EndpointSource = src("input-image", "src");
/// `isindex action`.
pub const ISINDEX_ACTION: EndpointSource = src("isindex", "action");
/// `script src`.
pub const SCRIPT_SRC: EndpointSource = src("script", "src");
/// Endpoints mined from inline `<script>` text.
pub const SCRIPT_TEXT: EndpointSource = src("script", "text");
/// `body background`.
pub const BODY_BACKGROUND: EndpointSource = src("body", "background");
/// `audio src`.
pub const AUDIO_SRC: EndpointSource = src("audio", "src");
/// `audio > source src`.
pub const AUDIO_SOURCE: EndpointSource = src("audio", "source");
/// `audio > source srcset`.
pub const AUDIO_SOURCE_SRCSET: EndpointSource = src("audio", "sourcesrcset");
/// `applet archive`.
pub const APPLET_ARCHIVE: EndpointSource = src("applet", "archive");
/// `applet codebase`.
pub const APPLET_CODEBASE: EndpointSource = src("applet", "codebase");
/// `img dynsrc`.
pub const IMG_DYNSRC: EndpointSource = src("img", "dynsrc");
/// `img longdesc`.
pub const IMG_LONGDESC: EndpointSource = src("img", "longdesc");
/// `img lowsrc`.
pub const IMG_LOWSRC: EndpointSource = src("img", "lowsrc");
/// `img src`.
pub const IMG_SRC: EndpointSource = src("img", "src");
/// `img srcset` candidates.
pub const IMG_SRCSET: EndpointSource = src("img", "srcset");
/// `object data`.
pub const OBJECT_DATA: EndpointSource = src("object", "data");
/// `object codebase`.
pub const OBJECT_CODEBASE: EndpointSource = src("object", "codebase");
/// `object > param value`.
pub const OBJECT_PARAM_VALUE: EndpointSource = src("object", "param-value");
/// `svg image href` / `xlink:href`.
pub const SVG_IMAGE_HREF: EndpointSource = src("svg", "image-href");
/// `svg script href` / `xlink:href`.
pub const SVG_SCRIPT_HREF: EndpointSource = src("svg", "script-href");
/// `table background`.
pub const TABLE_BACKGROUND: EndpointSource = src("table", "background");
/// `td background`.
pub const TABLE_TD_BACKGROUND: EndpointSource = src("table", "td-background");
/// `video src`.
pub const VIDEO_SRC: EndpointSource = src("video", "src");
/// `video poster`.
pub const VIDEO_POSTER: EndpointSource = src("video", "poster");
/// `video > track src`.
pub const VIDEO_TRACK_SRC: EndpointSource = src("video", "track-src");
/// `source src` outside `audio`.
pub const SOURCE_SRC: EndpointSource = src("source", "src");
/// `source srcset` outside `audio`.
pub const SOURCE_SRCSET: EndpointSource = src("source", "srcset");
/// `track src` outside `video`.
pub const TRACK_SRC: EndpointSource = src("track", "src");
/// `blockquote cite`.
pub const BLOCKQUOTE_CITE: EndpointSource = src("blockquote", "cite");
/// `q cite`.
pub const Q_CITE: EndpointSource = src("q", "cite");
/// `del cite`.
pub const DEL_CITE: EndpointSource = src("del", "cite");
/// `ins cite`.
pub const INS_CITE: EndpointSource = src("ins", "cite");
/// `area href`.
pub const AREA_HREF: EndpointSource = src("area", "href");
/// `area ping`.
pub const AREA_PING: EndpointSource = src("area", "ping");
/// `base href`.
pub const BASE_HREF: EndpointSource = src("base", "href");
/// `import implementation`.
pub const IMPORT_IMPLEMENTATION: EndpointSource = src("import", "implementation");
/// `button formaction`.
pub const BUTTON_FORMACTION: EndpointSource = src("button", "formaction");
/// `html manifest`.
pub const HTML_MANIFEST: EndpointSource = src("html", "manifest");
/// Doctype system identifier.
pub const HTML_DOCTYPE: EndpointSource = src("html", "doctype");
/// `form action` (method, enctype and body attached).
pub const FORM_ACTION: EndpointSource = src("form", "action");
/// `meta http-equiv=refresh content="…; url=…"`.
pub const META_REFRESH: EndpointSource = src("meta", "refresh");
/// Endpoints mined from any `meta content`.
pub const META_CONTENT: EndpointSource = src("meta", "content");
/// `hx-get`.
pub const HTMX_GET: EndpointSource = src("htmx", "hx-get");
/// `hx-post`.
pub const HTMX_POST: EndpointSource = src("htmx", "hx-post");
/// `hx-put`.
pub const HTMX_PUT: EndpointSource = src("htmx", "hx-put");
/// `hx-patch`.
pub const HTMX_PATCH: EndpointSource = src("htmx", "hx-patch");
/// Endpoints mined from a script/stylesheet response body.
pub const JS_REGEX: EndpointSource = src("js", "regex");
/// Endpoints mined from a textual page body.
pub const HTML_REGEX: EndpointSource = src("html", "regex");
/// AST pass (`js-ast`): `fetch(url, opts)` / `new Request(url, opts)`.
pub const JS_FETCH: EndpointSource = src("js", "fetch");
/// AST pass: `axios(...)`, `axios.<method>(...)`.
pub const JS_AXIOS: EndpointSource = src("js", "axios");
/// AST pass: generic `<client>.get/post/put/patch/delete(url, …)`.
pub const JS_HTTP: EndpointSource = src("js", "http");
/// AST pass: `xhr.open(method, url)`.
pub const JS_XHR: EndpointSource = src("js", "xhr");
/// AST pass: `$.ajax`, `$.get`, `$.post`, `$.getJSON`.
pub const JS_AJAX: EndpointSource = src("js", "ajax");
/// AST pass: `navigator.sendBeacon(url, data)`.
pub const JS_BEACON: EndpointSource = src("js", "sendbeacon");
/// AST pass: `new URL(path, base?)`.
pub const JS_URL: EndpointSource = src("js", "url");
/// AST pass: `location.assign/replace(url)`, `location[.href] = url`.
pub const JS_LOCATION: EndpointSource = src("js", "location");
/// AST pass: `window.open(url)`.
pub const JS_OPEN: EndpointSource = src("js", "open");
/// AST pass: `history.pushState/replaceState(_, _, url)`.
pub const JS_HISTORY: EndpointSource = src("js", "history");
/// AST pass: `new WebSocket(url)`.
pub const JS_WEBSOCKET: EndpointSource = src("js", "websocket");
/// AST pass: `new EventSource(url)`.
pub const JS_EVENTSOURCE: EndpointSource = src("js", "eventsource");
/// AST pass: a string, template or concatenation that looks like a URL.
pub const JS_STRING: EndpointSource = src("js", "string");

/// Deterministic form-fill placeholders (katana's `DefaultFormFillData`
/// without the random e-mail; `rand_*` fillers are not adopted).
pub(super) mod fill {
    pub const EMAIL: &str = "crawlx@example.org";
    pub const COLOR: &str = "#e66465";
    pub const PASSWORD: &str = "crawlxP@ssw0rd1";
    pub const PHONE: &str = "2124567890";
    pub const PLACEHOLDER: &str = "crawlx";
}

/// Fixed multipart boundary (katana uses a random one; crawlx output is deterministic).
pub const MULTIPART_BOUNDARY: &str = "crawlx-form-boundary";

struct Ctx<'a> {
    base: &'a Url,
    depth: u32,
    javascript_mode: JavascriptMode,
    out: &'a mut Vec<DiscoveredEndpoint>,
}

impl Ctx<'_> {
    fn get(&mut self, raw: &str, source: EndpointSource) {
        self.out.extend(DiscoveredEndpoint::get(
            self.base,
            raw,
            source,
            Confidence::Structural,
            self.depth,
        ));
    }

    fn attr(&mut self, el: ElementRef<'_>, name: &str, source: EndpointSource) {
        if let Some(v) = attr_local(el, name) {
            self.get(v, source);
        }
    }

    fn srcset(&mut self, el: ElementRef<'_>, source: EndpointSource) {
        if let Some(v) = el.value().attr("srcset") {
            for u in srcset_urls(v) {
                self.get(u, source);
            }
        }
    }

    /// Run exactly the selected miners. Only `both` retains regex fallback
    /// when an AST parse fails or exceeds the parser's size bound.
    fn script(&mut self, text: &str, source: EndpointSource) {
        #[cfg(feature = "js-ast")]
        if self.javascript_mode.ast() {
            self.out.extend(super::ast::discover(text, self.base, self.depth));
        }
        self.regex(text, source);
    }

    fn regex(&mut self, text: &str, source: EndpointSource) {
        if !self.javascript_mode.regex() {
            return;
        }
        for raw in extract_relative_endpoints(text) {
            self.out.extend(DiscoveredEndpoint::get(
                self.base,
                raw,
                source,
                Confidence::Regex,
                self.depth,
            ));
        }
    }

    /// Event-handler attributes (`onclick="fetch('/x')"`) go through the AST
    /// pass only: the regex pass never mined them (katana parity).
    #[cfg(feature = "js-ast")]
    fn event_handlers(&mut self, el: ElementRef<'_>) {
        if !self.javascript_mode.ast() {
            return;
        }
        for (name, value) in &el.value().attrs {
            let local = &*name.local;
            if local.len() > 2 && local.starts_with("on") && !value.is_empty() {
                self.out
                    .extend(super::ast::discover(value, self.base, self.depth));
            }
        }
    }

    fn method(&mut self, el: ElementRef<'_>, attr: &str, method: Method, source: EndpointSource) {
        if let Some(raw) = el.value().attr(attr).filter(|v| !v.is_empty()) {
            if let Some(url) = super::resolve(self.base, raw) {
                self.out.push(DiscoveredEndpoint {
                    url,
                    method,
                    source,
                    body: None,
                    content_type: None,
                    confidence: Confidence::Structural,
                    depth: self.depth.saturating_add(1),
                    headers: Vec::new(),
                });
            }
        }
    }
}

/// Non-empty attribute value matched by local name in any namespace, so
/// `xlink:href` on SVG children is found like plain `href` (goquery semantics).
fn attr_local<'a>(el: ElementRef<'a>, name: &str) -> Option<&'a str> {
    el.value()
        .attrs
        .iter()
        .find(|(k, _)| &*k.local == name)
        .map(|(_, v)| &**v)
        .filter(|v| !v.is_empty())
}

fn parent_tag(el: ElementRef<'_>) -> Option<&str> {
    el.parent().and_then(ElementRef::wrap).map(|p| p.value().name())
}

fn in_svg(el: ElementRef<'_>) -> bool {
    el.value().name.ns.as_ref() == "http://www.w3.org/2000/svg"
}

/// Run every body parser over `doc`, resolving against `base`.
pub(super) fn parse(
    doc: &Html,
    base: &Url,
    depth: u32,
    javascript_mode: JavascriptMode,
    out: &mut Vec<DiscoveredEndpoint>,
) {
    let mut cx = Ctx {
        base,
        depth,
        javascript_mode,
        out,
    };
    doctype(doc, &mut cx);
    walk(doc.tree.root(), |el| {
        element(el, &mut cx);
        true
    });
}

fn doctype(doc: &Html, cx: &mut Ctx<'_>) {
    for n in doc.tree.root().children() {
        if let scraper::Node::Doctype(d) = n.value() {
            let system = d.system_id.trim();
            if !system.is_empty() {
                cx.get(system, HTML_DOCTYPE);
            }
            return;
        }
    }
}

fn element(el: ElementRef<'_>, cx: &mut Ctx<'_>) {
    let v = el.value();
    match v.name() {
        "a" => {
            cx.attr(el, "href", A_HREF);
            cx.attr(el, "ping", A_PING);
        }
        "area" => {
            cx.attr(el, "href", AREA_HREF);
            cx.attr(el, "ping", AREA_PING);
        }
        "link" => cx.attr(el, "href", LINK_HREF),
        "embed" => cx.attr(el, "src", EMBED_SRC),
        "frame" => cx.attr(el, "src", FRAME_SRC),
        "iframe" => {
            cx.attr(el, "src", IFRAME_SRC);
            if let Some(doc) = v.attr("srcdoc").filter(|s| !s.is_empty()) {
                cx.regex(doc, IFRAME_SRCDOC);
            }
        }
        "input" => {
            if v.attr("type").is_some_and(|t| t.eq_ignore_ascii_case("image")) {
                cx.attr(el, "src", INPUT_IMAGE_SRC);
            }
        }
        "isindex" => cx.attr(el, "action", ISINDEX_ACTION),
        "script" => {
            if in_svg(el) {
                cx.attr(el, "href", SVG_SCRIPT_HREF);
            }
            cx.attr(el, "src", SCRIPT_SRC);
            if v.attr("src").is_none() && cx.javascript_mode != JavascriptMode::Off {
                let text: String = el.text().collect();
                if !text.is_empty() {
                    cx.script(&text, SCRIPT_TEXT);
                }
            }
        }
        "body" => cx.attr(el, "background", BODY_BACKGROUND),
        "audio" => cx.attr(el, "src", AUDIO_SRC),
        "source" => {
            if parent_tag(el) == Some("audio") {
                cx.attr(el, "src", AUDIO_SOURCE);
                cx.srcset(el, AUDIO_SOURCE_SRCSET);
            } else {
                cx.attr(el, "src", SOURCE_SRC);
                cx.srcset(el, SOURCE_SRCSET);
            }
        }
        "applet" => {
            cx.attr(el, "archive", APPLET_ARCHIVE);
            cx.attr(el, "codebase", APPLET_CODEBASE);
        }
        "img" => {
            cx.attr(el, "dynsrc", IMG_DYNSRC);
            cx.attr(el, "longdesc", IMG_LONGDESC);
            cx.attr(el, "lowsrc", IMG_LOWSRC);
            if let Some(s) = v.attr("src").filter(|s| !s.is_empty() && *s != "#") {
                if !s.starts_with("data:") {
                    cx.get(s, IMG_SRC);
                }
            }
            cx.srcset(el, IMG_SRCSET);
        }
        "object" => {
            cx.attr(el, "data", OBJECT_DATA);
            cx.attr(el, "codebase", OBJECT_CODEBASE);
        }
        "param" => {
            if parent_tag(el) == Some("object") {
                cx.attr(el, "value", OBJECT_PARAM_VALUE);
            }
        }
        "image" => {
            if in_svg(el) {
                cx.attr(el, "href", SVG_IMAGE_HREF);
            }
        }
        "table" => cx.attr(el, "background", TABLE_BACKGROUND),
        "td" => cx.attr(el, "background", TABLE_TD_BACKGROUND),
        "video" => {
            cx.attr(el, "src", VIDEO_SRC);
            cx.attr(el, "poster", VIDEO_POSTER);
        }
        "track" => {
            if parent_tag(el) == Some("video") {
                cx.attr(el, "src", VIDEO_TRACK_SRC);
            } else {
                cx.attr(el, "src", TRACK_SRC);
            }
        }
        "blockquote" => cx.attr(el, "cite", BLOCKQUOTE_CITE),
        "q" => cx.attr(el, "cite", Q_CITE),
        "del" => cx.attr(el, "cite", DEL_CITE),
        "ins" => cx.attr(el, "cite", INS_CITE),
        "base" => cx.attr(el, "href", BASE_HREF),
        "import" => cx.attr(el, "implementation", IMPORT_IMPLEMENTATION),
        "button" => cx.attr(el, "formaction", BUTTON_FORMACTION),
        "html" => cx.attr(el, "manifest", HTML_MANIFEST),
        "form" => form(el, cx),
        "meta" => meta(el, cx),
        _ => {}
    }
    htmx(el, cx);
    #[cfg(feature = "js-ast")]
    cx.event_handlers(el);
}

fn meta(el: ElementRef<'_>, cx: &mut Ctx<'_>) {
    let v = el.value();
    let Some(content) = v.attr("content").filter(|c| !c.is_empty()) else {
        return;
    };
    if v.attr("http-equiv")
        .is_some_and(|h| h.eq_ignore_ascii_case("refresh"))
    {
        if let Some(raw) = parse_refresh(content) {
            cx.get(raw, META_REFRESH);
        }
    }
    cx.regex(content, META_CONTENT);
}

fn htmx(el: ElementRef<'_>, cx: &mut Ctx<'_>) {
    // `hx-delete` is deliberately excluded (katana does the same).
    cx.method(el, "hx-get", Method::GET, HTMX_GET);
    cx.method(el, "hx-post", Method::POST, HTMX_POST);
    cx.method(el, "hx-put", Method::PUT, HTMX_PUT);
    cx.method(el, "hx-patch", Method::PATCH, HTMX_PATCH);
}

/// Insertion-ordered `name → value` with set-overwrites-in-place semantics
/// (katana's `OrderedMap`).
#[derive(Default)]
struct Fields(Vec<(String, String)>);

impl Fields {
    fn has(&self, k: &str) -> bool {
        self.0.iter().any(|(n, _)| n == k)
    }
    fn set(&mut self, k: &str, v: &str) {
        if k.is_empty() {
            return;
        }
        match self.0.iter_mut().find(|(n, _)| n == k) {
            Some(slot) => slot.1 = v.to_owned(),
            None => self.0.push((k.to_owned(), v.to_owned())),
        }
    }
}

fn int_attr(el: ElementRef<'_>, key: &str, default: i64) -> i64 {
    el.value()
        .attr(key)
        .and_then(|v| v.trim().parse::<i64>().ok())
        .unwrap_or(default)
}

/// Deterministic value for one form control (`FormInputFillSuggestions`,
/// `FormSelectFill`, `FormTextAreaFill` without random data).
fn fill_control(el: ElementRef<'_>, fields: &mut Fields) {
    let v = el.value();
    let Some(name) = v.attr("name").filter(|n| !n.is_empty()) else {
        return;
    };
    match v.name() {
        "input" => {
            let ty = v.attr("type").unwrap_or("text").trim().to_ascii_lowercase();
            let value = v.attr("value").unwrap_or("");
            match ty.as_str() {
                "radio" => {
                    if !fields.has(name) {
                        fields.set(name, value);
                    }
                }
                "checkbox" => fields.set(name, value),
                _ => {
                    if !value.is_empty() {
                        fields.set(name, value);
                    } else if let Some(p) = v.attr("placeholder").filter(|p| !p.is_empty()) {
                        fields.set(name, p);
                    } else {
                        let filled = match ty.as_str() {
                            "email" => fill::EMAIL.to_owned(),
                            "color" => fill::COLOR.to_owned(),
                            "number" | "range" => {
                                let min = int_attr(el, "min", 1);
                                let max = int_attr(el, "max", 10);
                                let step = int_attr(el, "step", 1);
                                let mut val = min.saturating_add(step);
                                if val > max {
                                    val = max.saturating_sub(step);
                                }
                                val.to_string()
                            }
                            "password" => fill::PASSWORD.to_owned(),
                            "tel" => fill::PHONE.to_owned(),
                            _ => fill::PLACEHOLDER.to_owned(),
                        };
                        fields.set(name, &filled);
                    }
                }
            }
        }
        "select" => {
            let mut options: Vec<ElementRef<'_>> = Vec::new();
            walk(*el, |o| {
                if o.value().name() == "option" {
                    options.push(o);
                }
                true
            });
            let selected = options
                .iter()
                .find(|o| o.value().attr("selected").is_some())
                .or_else(|| options.first());
            if let Some(o) = selected {
                let val = o
                    .value()
                    .attr("value")
                    .map_or_else(|| o.text().collect::<String>().trim().to_owned(), str::to_owned);
                fields.set(name, &val);
            }
        }
        "textarea" => fields.set(name, fill::PLACEHOLDER),
        _ => {}
    }
}

fn urlencode(fields: &Fields) -> String {
    let mut ser = url::form_urlencoded::Serializer::new(String::new());
    for (k, v) in &fields.0 {
        ser.append_pair(k, v);
    }
    ser.finish()
}

fn multipart(fields: &Fields) -> String {
    let mut s = String::new();
    for (k, v) in &fields.0 {
        s.push_str("--");
        s.push_str(MULTIPART_BOUNDARY);
        s.push_str("\r\nContent-Disposition: form-data; name=\"");
        s.push_str(&k.replace('"', "%22"));
        s.push_str("\"\r\n\r\n");
        s.push_str(v);
        s.push_str("\r\n");
    }
    s.push_str("--");
    s.push_str(MULTIPART_BOUNDARY);
    s.push_str("--\r\n");
    s
}

fn form(el: ElementRef<'_>, cx: &mut Ctx<'_>) {
    let v = el.value();
    let action = v.attr("action").unwrap_or("");
    let enctype = v
        .attr("enctype")
        .filter(|e| !e.is_empty())
        .unwrap_or("application/x-www-form-urlencoded");
    let method_raw = v.attr("method").filter(|m| !m.is_empty()).unwrap_or("GET");
    let Ok(method) = Method::from_bytes(method_raw.trim().to_ascii_uppercase().as_bytes()) else {
        return;
    };
    let Ok(mut url) = cx.base.join(action.trim()) else {
        return;
    };
    if !matches!(url.scheme(), "http" | "https") {
        return;
    }
    url.set_fragment(None);

    let mut fields = Fields::default();
    walk(*el, |c| {
        if c != el && matches!(c.value().name(), "input" | "select" | "textarea") {
            fill_control(c, &mut fields);
        }
        true
    });

    let is_multipart = enctype.to_ascii_lowercase().starts_with("multipart/");
    let (body, content_type) = match method {
        Method::GET => {
            if !fields.0.is_empty() {
                let mut q = url.query_pairs_mut();
                for (k, val) in &fields.0 {
                    q.append_pair(k, val);
                }
            }
            (None, None)
        }
        Method::POST => {
            if is_multipart {
                (
                    Some(multipart(&fields)),
                    Some(format!("multipart/form-data; boundary={MULTIPART_BOUNDARY}")),
                )
            } else {
                (Some(urlencode(&fields)), Some(enctype.to_owned()))
            }
        }
        _ => (None, None),
    };
    cx.out.push(DiscoveredEndpoint {
        url,
        method,
        source: FORM_ACTION,
        body,
        content_type,
        confidence: Confidence::Structural,
        depth: cx.depth.saturating_add(1),
        headers: Vec::new(),
    });
}
