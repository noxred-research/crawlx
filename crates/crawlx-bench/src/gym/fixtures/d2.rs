//! Fixture `d2`: "differential site 2", the own-authored site of the Firecrawl differential
//! harness.
//!
//! Five sections under `/d2/`, all procedural and independent of the request host (every
//! page is served for every [`HOSTS`] alias and for the bare gym address):
//!
//! * `scope/`: subdomain, look-alike-suffix, external and non-HTTP link targets;
//! * `redir/`: 301/302/303/307/308 responses, a three-hop and a thirteen-hop chain, a loop,
//!   a relative and a cross-host `Location`, a robots-blocked target, a meta refresh and a
//!   redirect to a missing page;
//! * `robots/`: pages named after the rules of [`robots`] (prefix, `Allow` override,
//!   `*.pdf$`, a bare-prefix `tmp`, a user-agent specific group);
//! * `tiny/`: four fast pages;
//! * `slow/`: forty pages that answer after [`SLOW_DELAY_MS`].
//!
//! Absolute links name the alias hosts with the port of the request's `Host` header, so the
//! page graph is the same whichever address the crawler reached the gym under. The module is
//! pure: the gym server applies [`D2Response::delay_ms`] and [`D2Response::headers`].
//! `robots.txt` depends on the request host ([`robots`]); the origin serves it once a test or
//! `gym-server --claim-origin d2` makes this fixture the origin owner.

use std::fmt::Write as _;
use std::sync::LazyLock;

/// Fixture id.
pub const ID: &str = "d2";

/// Every host name the fixture uses; the harness maps all of them to the gym (compose
/// `extra_hosts`, `StaticResolver`).
pub const HOSTS: [&str; 11] = [
    "gym.test",
    "app.gym.test",
    "deep.app.gym.test",
    "www.gym.test",
    "notgym.test",
    "other.test",
    "big.gym.test",
    "e404.gym.test",
    "e403.gym.test",
    "e503.gym.test",
    "ua.gym.test",
];

/// Delay of every `slow/p/N` page.
const SLOW_DELAY_MS: u64 = 500;

/// Number of pages `slow/p/1` ..= `slow/p/SLOW_PAGES`.
const SLOW_PAGES: u32 = 40;

/// Hops of the `redir/long/N` chain (`N` in `1..=LONG_HOPS`).
const LONG_HOPS: u32 = 12;

/// Byte offset after which the `big.gym.test` robots file puts its last rule (the common
/// crawler cut-off is 500 KiB = 512 000 bytes).
const BIG_ROBOTS_LATE_OFFSET: usize = 520_000;

/// Filler of one `# padding` line of the big robots file (the line is 65 bytes long).
const PADDING: &str = "0123456789abcdef0123456789abcdef0123456789abcdef";

const HTML: &str = "text/html; charset=utf-8";
const TEXT: &str = "text/plain; charset=utf-8";

/// Pages of `robots/`, named after the rule that applies to them.
const ROBOTS_PAGES: [&str; 19] = [
    "open",
    "private/x",
    "private/open/y",
    "file.pdf",
    "docs/file.pdf",
    "docs/file.pdf.html",
    "export.dat",
    "docs/export.dat",
    "docs/export.dat.html",
    "tmp1",
    "tmp/z",
    "search",
    "early-blocked",
    "late-blocked",
    "ua-star",
    "fc-only",
    "cx-only",
    "ok/a",
    "ok/b",
];

/// Rules of `gym.test`.
const MAIN_ROBOTS: &str = "User-agent: *\n\
Disallow: /d2/robots/private/\n\
Allow: /d2/robots/private/open/\n\
Disallow: /d2/robots/*.pdf$\n\
Disallow: /d2/robots/*.dat$\n\
Disallow: /d2/robots/tmp\n\
Disallow: /d2/redir/private\n\
Crawl-delay: 0\n";

/// Rules of `ua.gym.test`: one group per user agent.
const UA_ROBOTS: &str = "User-agent: *\n\
Disallow: /d2/robots/ua-star\n\
\n\
User-agent: FirecrawlAgent\n\
Disallow: /d2/robots/fc-only\n\
\n\
User-agent: crawlx\n\
Disallow: /d2/robots/cx-only\n";

/// Rules of every host without a rule set of its own: everything allowed.
const OPEN_ROBOTS: &str = "User-agent: *\nDisallow:\n";

/// Rules of `big.gym.test`: `early-blocked` in the first 50 bytes, `late-blocked` after
/// [`BIG_ROBOTS_LATE_OFFSET`] bytes of comments.
static BIG_ROBOTS: LazyLock<String> = LazyLock::new(|| {
    let mut s = String::from("User-agent: *\nDisallow: /d2/robots/early-blocked\n");
    let mut n = 0_u32;
    while s.len() <= BIG_ROBOTS_LATE_OFFSET {
        n = n.saturating_add(1);
        let _ = writeln!(s, "# padding {n:05} {PADDING}");
    }
    s.push_str("Disallow: /d2/robots/late-blocked\n");
    s
});

/// A generated `d2` response, ready to be written to the socket.
#[derive(Clone, Debug)]
pub struct D2Response {
    /// HTTP status code (200, or one of the redirect statuses of `redir/go/`).
    pub status: u16,
    /// MIME type sent as the `Content-Type` header.
    pub content_type: &'static str,
    /// Response body (HTML, or a short text for redirects).
    pub body: String,
    /// Extra response headers (`Location` of the redirects).
    pub headers: Vec<(String, String)>,
    /// Time the server waits before answering (`slow/p/N`); `0` for every other page.
    pub delay_ms: u64,
}

type Link = (String, String);

fn l(href: impl Into<String>, text: &str) -> Link {
    (href.into(), text.to_owned())
}

/// `http://{alias}{port}{path}`; `port` is empty or `:N` (see [`port_suffix`]).
fn abs(alias: &str, port: &str, path: &str) -> String {
    format!("http://{alias}{port}{path}")
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// Split a `Host` header into its name and port. Bracketed IPv6 literals are understood; an
/// unparsable port counts as absent.
fn split_host(host: &str) -> (&str, Option<u16>) {
    let host = host.trim();
    let (name, port) = match host.strip_prefix('[') {
        Some(inner) => match inner.split_once(']') {
            Some((name, rest)) => (name, rest.strip_prefix(':')),
            None => (inner, None),
        },
        None => match host.rsplit_once(':') {
            Some((name, port)) => (name, Some(port)),
            None => (host, None),
        },
    };
    (name, port.and_then(|p| p.parse().ok()))
}

/// `:N` for a `Host` header that carries a port, else the empty string.
fn port_suffix(host: &str) -> String {
    split_host(host)
        .1
        .map_or_else(String::new, |port| format!(":{port}"))
}

/// An HTML page in the shape of `s1` (the crawlx extractor keeps link lists only inside
/// `<main>`): a header with the one `<h1>`, then `<main>` holding a two-sentence paragraph
/// and the `<ul>` of anchors. `head` is extra markup for `<head>`.
fn render(title: &str, head: &str, links: &[Link]) -> String {
    let mut items = String::new();
    for (href, text) in links {
        let _ = writeln!(
            items,
            "<li><a href=\"{}\">{}</a></li>",
            escape(href),
            escape(text)
        );
    }
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>{t}</title>{head}</head>\n\
         <body><header><h1>{t}</h1></header>\n<main><p>{t} is a page of the CrawlerGym d2 site. \
         Its links are the ground truth of the differential crawl.</p>\n<ul>\n{items}</ul></main></body></html>\n",
        t = escape(title)
    )
}

fn html(title: &str, links: &[Link]) -> D2Response {
    D2Response {
        status: 200,
        content_type: HTML,
        body: render(title, "", links),
        headers: Vec::new(),
        delay_ms: 0,
    }
}

fn redirect(status: u16, location: String) -> D2Response {
    D2Response {
        status,
        content_type: TEXT,
        body: format!("{status} redirect to {location}\n"),
        headers: vec![("Location".to_owned(), location)],
        delay_ms: 0,
    }
}

/// `s` as a number in `1..=max` written without a sign or leading zero.
fn counter(s: &str, max: u32) -> Option<u32> {
    if s.starts_with('0') || !s.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    s.parse().ok().filter(|n| (1..=max).contains(n))
}

/// `path` as words only (`docs/file.pdf.html` becomes `docs file pdf html`): headings and
/// anchor texts never look like a URL path a text-based extractor could resolve.
fn words(path: &str) -> String {
    path.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { ' ' })
        .collect()
}

fn title_of(section: &str, tail: &str) -> String {
    if tail.is_empty() {
        format!("d2 {section}: index")
    } else {
        format!("d2 {section}: {}", words(tail))
    }
}

fn index() -> D2Response {
    html(
        "d2 differential site",
        &[
            l("/d2/scope/", "Scope"),
            l("/d2/redir/", "Redirects"),
            l("/d2/robots/", "Robots"),
            l("/d2/tiny/", "Tiny"),
            l("/d2/slow/", "Slow"),
        ],
    )
}

fn scope(tail: &str, port: &str) -> Option<D2Response> {
    let links: Vec<Link> = match tail {
        "" => vec![
            l("a", "Relative a"),
            l("b/", "Relative b"),
            l(abs("app.gym.test", port, "/d2/scope/sub"), "Subdomain"),
            l(abs("deep.app.gym.test", port, "/d2/scope/deep"), "Deep subdomain"),
            l(abs("www.gym.test", port, "/d2/scope/www"), "www"),
            l(
                abs("notgym.test", port, "/d2/scope/lookalike"),
                "Look-alike suffix",
            ),
            l(abs("other.test", port, "/d2/scope/ext"), "External"),
            l(
                format!("//other.test{port}/d2/scope/ext-proto"),
                "External, protocol-relative",
            ),
            l("mailto:ops@gym.test", "Mail"),
            l("tel:+100", "Phone"),
            l("javascript:void(0)", "Script"),
            l("#frag", "Fragment"),
            l("ftp://gym.test/file", "FTP"),
        ],
        "a" => vec![l("/d2/scope/", "Index"), l("/d2/scope/a/deeper", "Deeper")],
        "a/deeper" | "b" => vec![l("/d2/scope/", "Index")],
        "sub" => vec![
            l(abs("gym.test", port, "/d2/scope/back-from-sub"), "Apex"),
            l(abs("app.gym.test", port, "/d2/scope/sub2"), "Sibling"),
        ],
        "deep" => vec![l(abs("deep.app.gym.test", port, "/d2/scope/deep2"), "Deeper")],
        "www" => vec![l("/d2/scope/www2", "Second")],
        "ext" => vec![
            l(abs("other.test", port, "/d2/scope/ext2"), "Second external"),
            l(abs("gym.test", port, "/d2/scope/back-from-ext"), "Back"),
        ],
        "sub2" | "back-from-sub" | "deep2" | "www2" | "lookalike" | "ext2" | "ext-proto"
        | "back-from-ext" => Vec::new(),
        _ => return None,
    };
    Some(html(&title_of("scope", tail), &links))
}

/// `redir/go/<name>`: the entry points of the redirect cases.
fn go(name: &str, port: &str) -> Option<D2Response> {
    const TARGET: &str = "/d2/redir/target";
    Some(match name {
        "301" => redirect(301, TARGET.to_owned()),
        "302chain" => redirect(302, "/d2/redir/hop/1".to_owned()),
        "long" => redirect(302, "/d2/redir/long/1".to_owned()),
        "loop-a" => redirect(302, "/d2/redir/go/loop-b".to_owned()),
        "loop-b" => redirect(302, "/d2/redir/go/loop-a".to_owned()),
        "rel" => redirect(302, "../target".to_owned()),
        "cross" => redirect(302, abs("other.test", port, "/d2/redir/cross-target")),
        "blocked" => redirect(302, "/d2/redir/private/blocked-target".to_owned()),
        "missing" => redirect(302, "/d2/redir/nope".to_owned()),
        "303" => redirect(303, TARGET.to_owned()),
        "307" => redirect(307, TARGET.to_owned()),
        "308" => redirect(308, TARGET.to_owned()),
        "meta" => D2Response {
            status: 200,
            content_type: HTML,
            body: render(
                "d2 redir: meta refresh",
                "<meta http-equiv=\"refresh\" content=\"0; url=/d2/redir/target-meta\">",
                &[],
            ),
            headers: Vec::new(),
            delay_ms: 0,
        },
        _ => return None,
    })
}

fn redir(tail: &str, port: &str) -> Option<D2Response> {
    if let Some(name) = tail.strip_prefix("go/") {
        return go(name, port);
    }
    if let Some(n) = tail.strip_prefix("hop/").and_then(|n| counter(n, 2)) {
        let to = if n == 1 {
            "/d2/redir/hop/2"
        } else {
            "/d2/redir/target"
        };
        return Some(redirect(302, to.to_owned()));
    }
    if let Some(n) = tail.strip_prefix("long/").and_then(|n| counter(n, LONG_HOPS)) {
        let to = if n == LONG_HOPS {
            "/d2/redir/target-long".to_owned()
        } else {
            format!("/d2/redir/long/{}", n.saturating_add(1))
        };
        return Some(redirect(302, to));
    }
    let links: Vec<Link> = match tail {
        "" => [
            "go/301",
            "go/302chain",
            "go/long",
            "go/loop-a",
            "go/rel",
            "go/cross",
            "go/blocked",
            "go/meta",
            "go/missing",
            "go/303",
            "go/307",
            "go/308",
            "target",
        ]
        .iter()
        .map(|p| l(format!("/d2/redir/{p}"), &format!("Redirect case {}", words(p))))
        .collect(),
        "target" => vec![l("/d2/redir/", "Index")],
        "target-long" | "target-meta" | "cross-target" | "private/blocked-target" => Vec::new(),
        _ => return None,
    };
    Some(html(&title_of("redir", tail), &links))
}

fn robots_page(tail: &str) -> Option<D2Response> {
    let case = |p: &str| l(format!("/d2/robots/{p}"), &format!("Robots case {}", words(p)));
    let links: Vec<Link> = if tail.is_empty() {
        let mut links: Vec<Link> = ROBOTS_PAGES.iter().copied().map(case).collect();
        links.push(case("search?q=1"));
        links
    } else if matches!(tail, "docs/file.pdf" | "docs/file.pdf.html") {
        vec![case("docs/export.dat"), case("docs/export.dat.html")]
    } else if ROBOTS_PAGES.contains(&tail) {
        Vec::new()
    } else {
        return None;
    };
    Some(html(&title_of("robots", tail), &links))
}

fn tiny(tail: &str) -> Option<D2Response> {
    let links: Vec<Link> = match tail {
        "" => vec![l("/d2/tiny/a", "A"), l("/d2/tiny/b", "B")],
        "a" => vec![l("/d2/tiny/c", "C")],
        "b" | "c" => vec![l("/d2/tiny/", "Index")],
        _ => return None,
    };
    Some(html(&title_of("tiny", tail), &links))
}

fn slow(tail: &str) -> Option<D2Response> {
    if tail.is_empty() {
        let links: Vec<Link> = (1..=SLOW_PAGES)
            .map(|n| l(format!("/d2/slow/p/{n}"), &format!("Page {n}")))
            .collect();
        return Some(html("d2 slow: index", &links));
    }
    let n = tail.strip_prefix("p/").and_then(|n| counter(n, SLOW_PAGES))?;
    let mut resp = html(&format!("d2 slow: page {n}"), &[l("/d2/slow/", "Index")]);
    resp.delay_ms = SLOW_DELAY_MS;
    Some(resp)
}

/// Serve `rest` (the path below `/d2/`, no leading slash, no query). `host` is the request's
/// `Host` header (it may carry a `:port`); `None` for paths the fixture does not know, which
/// the gym answers with 404. A trailing slash is optional.
#[must_use]
pub fn serve(rest: &str, host: &str) -> Option<D2Response> {
    let key = rest.trim_matches('/');
    let (section, tail) = key.split_once('/').unwrap_or((key, ""));
    match section {
        "" => Some(index()),
        "scope" => scope(tail, &port_suffix(host)),
        "redir" => redir(tail, &port_suffix(host)),
        "robots" => robots_page(tail),
        "tiny" => tiny(tail),
        "slow" => slow(tail),
        _ => None,
    }
}

/// Status and body of `/robots.txt` for the request `Host` header; the port is ignored and the
/// name compared case-insensitively. Hosts without a rule set of their own allow everything.
#[must_use]
pub fn robots(host: &str) -> (u16, String) {
    match split_host(host).0.to_ascii_lowercase().as_str() {
        "gym.test" => (200, MAIN_ROBOTS.to_owned()),
        "big.gym.test" => (200, BIG_ROBOTS.clone()),
        "e404.gym.test" => (404, "not found\n".to_owned()),
        "e403.gym.test" => (403, "forbidden\n".to_owned()),
        "e503.gym.test" => (503, "unavailable\n".to_owned()),
        "ua.gym.test" => (200, UA_ROBOTS.to_owned()),
        _ => (200, OPEN_ROBOTS.to_owned()),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::collections::BTreeSet;
    use url::Url;

    const HOST: &str = "127.0.0.1:41233";

    fn get(path: &str) -> Option<D2Response> {
        serve(path.strip_prefix("/d2/").unwrap(), HOST)
    }

    fn location(r: &D2Response) -> Option<&str> {
        r.headers
            .iter()
            .find(|(n, _)| n == "Location")
            .map(|(_, v)| v.as_str())
    }

    /// Every `href="..."` of `html`, in document order.
    fn hrefs(html: &str) -> Vec<String> {
        html.split("href=\"")
            .skip(1)
            .map(|rest| rest.split('"').next().unwrap().replace("&amp;", "&"))
            .collect()
    }

    /// Everything a walk from `/d2/` observed.
    #[derive(Default)]
    struct Walk {
        served: BTreeSet<String>,
        dead: BTreeSet<String>,
        schemes: BTreeSet<String>,
        hosts: BTreeSet<String>,
    }

    /// Walk the page graph breadth-first from `/d2/`: links of 200 pages, `Location` of
    /// redirects and the meta refresh target. Every http(s) target must name an alias host
    /// and the port of the request `Host`.
    fn walk() -> Walk {
        let mut out = Walk::default();
        let mut seen = BTreeSet::new();
        let mut queue = vec![Url::parse(&format!("http://{HOST}/d2/")).unwrap()];
        while let Some(url) = queue.pop() {
            if !seen.insert(url.path().to_owned()) {
                continue;
            }
            let host = format!("{}:{}", url.host_str().unwrap(), url.port().unwrap());
            let Some(r) = serve(url.path().strip_prefix("/d2/").unwrap(), &host) else {
                out.dead.insert(url.path().to_owned());
                continue;
            };
            out.served.insert(url.path().to_owned());
            let mut targets = hrefs(&r.body);
            targets.extend(location(&r).map(str::to_owned));
            if let Some((_, after)) = r.body.split_once("http-equiv=\"refresh\" content=\"0; url=") {
                targets.push(after.split('"').next().unwrap().to_owned());
            }
            for t in targets {
                let next = url.join(&t).unwrap();
                if matches!(next.scheme(), "http" | "https") {
                    let name = next.host_str().unwrap();
                    if name != "127.0.0.1" {
                        assert!(HOSTS.contains(&name), "{t} names {name}");
                        assert_eq!(next.port(), Some(41233), "{t}");
                        out.hosts.insert(name.to_owned());
                    }
                    queue.push(next);
                } else {
                    out.schemes.insert(next.scheme().to_owned());
                }
            }
        }
        out
    }

    /// `(status, path)` of every response of the redirect chain started at `start`, and how it
    /// ended.
    fn follow(start: &str) -> (Vec<(u16, String)>, &'static str) {
        let mut url = Url::parse(&format!("http://{HOST}{start}")).unwrap();
        let mut trail: Vec<(u16, String)> = Vec::new();
        loop {
            if trail.iter().any(|(_, p)| p == url.path()) {
                return (trail, "loop");
            }
            let host = format!("{}:{}", url.host_str().unwrap(), url.port().unwrap());
            let Some(r) = serve(url.path().strip_prefix("/d2/").unwrap(), &host) else {
                trail.push((404, url.path().to_owned()));
                return (trail, "missing");
            };
            trail.push((r.status, url.path().to_owned()));
            match location(&r) {
                Some(loc) => url = url.join(loc).unwrap(),
                None => return (trail, "ok"),
            }
        }
    }

    #[test]
    fn index_links_the_five_sections_in_order() {
        let r = get("/d2/").unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type, "text/html; charset=utf-8");
        assert_eq!(
            hrefs(&r.body),
            [
                "/d2/scope/",
                "/d2/redir/",
                "/d2/robots/",
                "/d2/tiny/",
                "/d2/slow/"
            ]
        );
        assert_eq!(serve("", HOST).unwrap().body, r.body);
    }

    #[test]
    fn every_page_is_small_html_with_title_heading_paragraph_and_list() {
        for path in walk().served {
            let r = get(&path).unwrap();
            if r.status != 200 {
                continue;
            }
            assert!(r.body.len() < 8_000, "{path}: {} bytes", r.body.len());
            assert_eq!(r.body.matches("<title>").count(), 1, "{path}");
            assert_eq!(r.body.matches("<h1>").count(), 1, "{path}");
            assert_eq!(r.body.matches("<p>").count(), 1, "{path}");
            assert_eq!(r.body.matches("<ul>").count(), 1, "{path}");
            // s1 shape: the heading in a header, paragraph and list inside <main>
            assert!(r.body.contains("<body><header><h1>"), "{path}");
            assert!(r.body.contains("</h1></header>\n<main><p>"), "{path}");
            assert!(r.body.contains("</p>\n<ul>\n"), "{path}");
            assert!(r.body.ends_with("</ul></main></body></html>\n"), "{path}");
            // two sentences
            assert!(
                r.body.contains(" is a page of the CrawlerGym d2 site. Its links are the ground truth of the differential crawl.</p>"),
                "{path}"
            );
        }
    }

    #[test]
    fn the_walk_reaches_every_page_and_every_link_resolves() {
        let w = walk();
        // 1 index + 16 scope + 33 redir (13 go/, 2 hop, 12 long, target, target-long,
        // cross-target, private/blocked-target, target-meta, index) + 20 robots (index and
        // 19 pages) + 4 tiny + 41 slow
        assert_eq!(w.served.len(), 115, "{:?}", w.served);
        // the only dead end is the deliberate redirect to a missing page
        assert_eq!(w.dead, BTreeSet::from(["/d2/redir/nope".to_owned()]));
        assert_eq!(
            w.schemes,
            BTreeSet::from(["ftp", "javascript", "mailto", "tel"].map(str::to_owned))
        );
        for host in [
            "app.gym.test",
            "deep.app.gym.test",
            "www.gym.test",
            "notgym.test",
            "other.test",
            "gym.test",
        ] {
            assert!(w.hosts.contains(host), "{host} never linked: {:?}", w.hosts);
        }
        for path in [
            "/d2/redir/target-long",
            "/d2/redir/target-meta",
            "/d2/redir/cross-target",
        ] {
            assert!(w.served.contains(path), "{path}");
        }
        assert!(w.served.contains("/d2/redir/private/blocked-target"));
    }

    #[test]
    fn scope_index_lists_its_links_in_order_with_the_request_port() {
        let body = serve("scope/", "app.gym.test:4101").unwrap().body;
        assert_eq!(
            hrefs(&body),
            [
                "a",
                "b/",
                "http://app.gym.test:4101/d2/scope/sub",
                "http://deep.app.gym.test:4101/d2/scope/deep",
                "http://www.gym.test:4101/d2/scope/www",
                "http://notgym.test:4101/d2/scope/lookalike",
                "http://other.test:4101/d2/scope/ext",
                "//other.test:4101/d2/scope/ext-proto",
                "mailto:ops@gym.test",
                "tel:+100",
                "javascript:void(0)",
                "#frag",
                "ftp://gym.test/file",
            ]
        );
        // the host name of the request does not matter, only its port
        assert_eq!(serve("scope", "127.0.0.1:4101").unwrap().body, body);
        // no port in `Host`: none in the links
        let bare = serve("scope/", "gym.test").unwrap().body;
        assert!(
            bare.contains("href=\"http://app.gym.test/d2/scope/sub\""),
            "{bare}"
        );
        assert!(
            bare.contains("href=\"//other.test/d2/scope/ext-proto\""),
            "{bare}"
        );
        assert!(!bare.contains("gym.test:"), "{bare}");
    }

    #[test]
    fn scope_pages_link_as_specified() {
        let h = |rest: &str| hrefs(&serve(rest, "h:7").unwrap().body);
        assert_eq!(h("scope/a"), ["/d2/scope/", "/d2/scope/a/deeper"]);
        assert_eq!(h("scope/a/deeper"), ["/d2/scope/"]);
        assert_eq!(h("scope/b/"), ["/d2/scope/"]);
        assert_eq!(
            h("scope/sub"),
            [
                "http://gym.test:7/d2/scope/back-from-sub",
                "http://app.gym.test:7/d2/scope/sub2"
            ]
        );
        assert_eq!(h("scope/deep"), ["http://deep.app.gym.test:7/d2/scope/deep2"]);
        assert_eq!(h("scope/www"), ["/d2/scope/www2"]);
        assert_eq!(
            h("scope/ext"),
            [
                "http://other.test:7/d2/scope/ext2",
                "http://gym.test:7/d2/scope/back-from-ext"
            ]
        );
        for leaf in [
            "sub2",
            "back-from-sub",
            "deep2",
            "www2",
            "lookalike",
            "ext2",
            "ext-proto",
            "back-from-ext",
        ] {
            assert_eq!(
                serve(&format!("scope/{leaf}"), "h:7").unwrap().status,
                200,
                "{leaf}"
            );
        }
    }

    #[test]
    fn redirect_chains_terminate_and_the_loop_loops() {
        let statuses = |t: &[(u16, String)]| t.iter().map(|(s, _)| *s).collect::<Vec<_>>();
        let paths = |t: &[(u16, String)]| t.iter().map(|(_, p)| p.clone()).collect::<Vec<_>>();

        let (t, end) = follow("/d2/redir/go/301");
        assert_eq!((statuses(&t), end), (vec![301, 200], "ok"));
        assert_eq!(paths(&t)[1], "/d2/redir/target");

        let (t, end) = follow("/d2/redir/go/302chain");
        assert_eq!((statuses(&t), end), (vec![302, 302, 302, 200], "ok"));
        assert_eq!(
            paths(&t),
            [
                "/d2/redir/go/302chain",
                "/d2/redir/hop/1",
                "/d2/redir/hop/2",
                "/d2/redir/target"
            ]
        );

        let (t, end) = follow("/d2/redir/go/long");
        assert_eq!(end, "ok");
        // go/long plus long/1 ..= long/12, then the 200
        assert_eq!(t.len(), 1 + 12 + 1);
        assert!(t[..13].iter().all(|(s, _)| *s == 302));
        assert_eq!(t[1].1, "/d2/redir/long/1");
        assert_eq!(t[12].1, "/d2/redir/long/12");
        assert_eq!(t[13], (200, "/d2/redir/target-long".to_owned()));
        assert!(get("/d2/redir/long/13").is_none());
        assert!(get("/d2/redir/long/0").is_none());
        assert!(get("/d2/redir/long/01").is_none());

        let (t, end) = follow("/d2/redir/go/loop-a");
        assert_eq!(end, "loop");
        assert_eq!(paths(&t), ["/d2/redir/go/loop-a", "/d2/redir/go/loop-b"]);
        let (_, end) = follow("/d2/redir/go/loop-b");
        assert_eq!(end, "loop");
    }

    #[test]
    fn redirect_cases_carry_their_status_and_location() {
        let loc = |name: &str| {
            let r = serve(&format!("redir/go/{name}"), "h:9").unwrap();
            assert_eq!(r.content_type, "text/plain; charset=utf-8");
            assert!(!r.body.is_empty() && r.body.len() < 200, "{name}: {}", r.body);
            assert_eq!(r.delay_ms, 0);
            (r.status, location(&r).unwrap().to_owned())
        };
        assert_eq!(loc("301"), (301, "/d2/redir/target".to_owned()));
        assert_eq!(loc("303"), (303, "/d2/redir/target".to_owned()));
        assert_eq!(loc("307"), (307, "/d2/redir/target".to_owned()));
        assert_eq!(loc("308"), (308, "/d2/redir/target".to_owned()));
        assert_eq!(
            loc("blocked"),
            (302, "/d2/redir/private/blocked-target".to_owned())
        );
        assert_eq!(loc("missing"), (302, "/d2/redir/nope".to_owned()));
        assert_eq!(loc("loop-a"), (302, "/d2/redir/go/loop-b".to_owned()));
        assert_eq!(loc("loop-b"), (302, "/d2/redir/go/loop-a".to_owned()));
        // relative Location: resolves against /d2/redir/go/rel to the target
        let (status, rel) = loc("rel");
        assert_eq!((status, rel.as_str()), (302, "../target"));
        let base = Url::parse("http://h:9/d2/redir/go/rel").unwrap();
        assert_eq!(base.join(&rel).unwrap().path(), "/d2/redir/target");
        // cross-host Location carries the port of the request
        assert_eq!(
            loc("cross"),
            (302, "http://other.test:9/d2/redir/cross-target".to_owned())
        );
        let bare = serve("redir/go/cross", "gym.test").unwrap();
        assert_eq!(location(&bare), Some("http://other.test/d2/redir/cross-target"));
        assert!(serve("redir/go/nope", "h").is_none());
    }

    #[test]
    fn meta_refresh_page_is_200_html_without_a_link_to_its_target() {
        let r = serve("redir/go/meta", HOST).unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(r.content_type, "text/html; charset=utf-8");
        assert!(r
            .body
            .contains("<meta http-equiv=\"refresh\" content=\"0; url=/d2/redir/target-meta\">"));
        assert!(hrefs(&r.body).is_empty());
        assert_eq!(serve("redir/target-meta", HOST).unwrap().status, 200);
        assert_eq!(hrefs(&serve("redir/target", HOST).unwrap().body), ["/d2/redir/"]);
    }

    #[test]
    fn redirect_index_and_robots_index_list_every_case() {
        assert_eq!(
            hrefs(&serve("redir/", HOST).unwrap().body),
            [
                "/d2/redir/go/301",
                "/d2/redir/go/302chain",
                "/d2/redir/go/long",
                "/d2/redir/go/loop-a",
                "/d2/redir/go/rel",
                "/d2/redir/go/cross",
                "/d2/redir/go/blocked",
                "/d2/redir/go/meta",
                "/d2/redir/go/missing",
                "/d2/redir/go/303",
                "/d2/redir/go/307",
                "/d2/redir/go/308",
                "/d2/redir/target",
            ]
        );
        let links = hrefs(&serve("robots/", HOST).unwrap().body);
        assert_eq!(links.len(), 20, "19 pages and search?q=1");
        for p in ROBOTS_PAGES {
            assert!(links.contains(&format!("/d2/robots/{p}")), "{p}");
            let r = serve(&format!("robots/{p}"), HOST).unwrap();
            assert_eq!(r.status, 200, "{p}");
            assert!(r.body.len() < 1_000, "{p}");
        }
        assert!(links.contains(&"/d2/robots/search?q=1".to_owned()));
        assert!(serve("robots/search", HOST).is_some());
        assert!(serve("robots/nope", HOST).is_none());
    }

    #[test]
    fn docs_pages_link_the_dat_pages_and_every_anchor_is_root_relative() {
        for p in ["export.dat", "docs/export.dat", "docs/export.dat.html"] {
            let r = serve(&format!("robots/{p}"), HOST).unwrap();
            assert_eq!(
                (r.status, r.content_type),
                (200, "text/html; charset=utf-8"),
                "{p}"
            );
        }
        for docs in ["docs/file.pdf", "docs/file.pdf.html"] {
            assert_eq!(
                hrefs(&serve(&format!("robots/{docs}"), HOST).unwrap().body),
                ["/d2/robots/docs/export.dat", "/d2/robots/docs/export.dat.html"],
                "{docs}"
            );
        }
        // the only relative anchors of the site are `a` and `b/` of the scope index
        for path in walk().served {
            let body = get(&path).unwrap().body;
            for href in hrefs(&body) {
                if path == "/d2/scope/" && (href == "a" || href == "b/") {
                    continue;
                }
                let rooted = href.starts_with("/d2/");
                let other = href.contains("://")
                    || href.starts_with("//")
                    || ["mailto:", "tel:", "javascript:", "#"]
                        .iter()
                        .any(|s| href.starts_with(s));
                assert!(rooted || other, "{path}: relative anchor {href}");
                if !path.starts_with("/d2/scope/") {
                    assert!(rooted, "{path}: {href}");
                }
            }
        }
        // anchor texts and headings are words, never path-like
        let body = serve("robots/", HOST).unwrap().body;
        assert!(body.contains(">Robots case docs file pdf html</a>"), "{body}");
        assert!(body.contains("<h1>d2 robots: index</h1>"), "{body}");
        let page = serve("robots/docs/file.pdf.html", HOST).unwrap().body;
        assert!(page.contains("<h1>d2 robots: docs file pdf html</h1>"), "{page}");
    }

    #[test]
    fn robots_rule_sets_follow_the_host_without_its_port() {
        let (status, body) = robots("gym.test:4101");
        assert_eq!(status, 200);
        assert_eq!(
            body,
            "User-agent: *\n\
             Disallow: /d2/robots/private/\n\
             Allow: /d2/robots/private/open/\n\
             Disallow: /d2/robots/*.pdf$\n\
             Disallow: /d2/robots/*.dat$\n\
             Disallow: /d2/robots/tmp\n\
             Disallow: /d2/redir/private\n\
             Crawl-delay: 0\n"
        );
        assert_eq!(robots("GYM.test"), robots("gym.test:1"));
        assert_eq!(robots("e404.gym.test:5"), (404, "not found\n".to_owned()));
        assert_eq!(robots("e403.gym.test"), (403, "forbidden\n".to_owned()));
        assert_eq!(robots("E503.GYM.TEST:80"), (503, "unavailable\n".to_owned()));
        let (status, ua) = robots("ua.gym.test:9");
        assert_eq!(status, 200);
        assert_eq!(
            ua.lines().filter(|l| !l.is_empty()).collect::<Vec<_>>(),
            [
                "User-agent: *",
                "Disallow: /d2/robots/ua-star",
                "User-agent: FirecrawlAgent",
                "Disallow: /d2/robots/fc-only",
                "User-agent: crawlx",
                "Disallow: /d2/robots/cx-only",
            ]
        );
        let open = (200, "User-agent: *\nDisallow:\n".to_owned());
        for host in [
            "127.0.0.1:4101",
            "127.0.0.1",
            "[::1]:4101",
            "app.gym.test:4101",
            "deep.app.gym.test",
            "www.gym.test",
            "notgym.test",
            "other.test:4101",
            "",
        ] {
            assert_eq!(robots(host), open, "{host}");
        }
    }

    #[test]
    fn big_robots_puts_the_late_rule_after_500_kib() {
        let (status, body) = robots("big.gym.test:4101");
        assert_eq!(status, 200);
        assert!(body.len() > 520_000 && body.len() < 600_000, "{}", body.len());
        assert!(body.starts_with("User-agent: *\nDisallow: /d2/robots/early-blocked\n"));
        let early = body.find("early-blocked").unwrap();
        assert!(early < 100, "{early}");
        let late = body.find("Disallow: /d2/robots/late-blocked").unwrap();
        assert!(late > 520_000, "{late}");
        assert!(body.ends_with("Disallow: /d2/robots/late-blocked\n"));
        assert_eq!(body.matches("late-blocked").count(), 1);
        assert!(body[49..late].lines().all(|l| l.starts_with("# padding ")));
        assert!(body.is_ascii());
        assert_eq!(robots("big.gym.test").1, body, "deterministic");
    }

    #[test]
    fn slow_pages_answer_after_500_ms_and_the_index_at_once() {
        assert_eq!(serve("slow/", HOST).unwrap().delay_ms, 0);
        let index = hrefs(&serve("slow", HOST).unwrap().body);
        assert_eq!(index.len(), 40);
        assert_eq!(index[0], "/d2/slow/p/1");
        assert_eq!(index[39], "/d2/slow/p/40");
        for n in 1..=40 {
            let r = serve(&format!("slow/p/{n}"), HOST).unwrap();
            assert_eq!((r.status, r.delay_ms), (200, 500), "p/{n}");
            assert_eq!(hrefs(&r.body), ["/d2/slow/"]);
        }
        assert!(serve("slow/p/0", HOST).is_none());
        assert!(serve("slow/p/41", HOST).is_none());
        assert!(serve("slow/p/", HOST).is_none());
        assert!(serve("slow/p/x", HOST).is_none());
    }

    #[test]
    fn tiny_pages_form_a_small_graph() {
        assert_eq!(
            hrefs(&serve("tiny/", HOST).unwrap().body),
            ["/d2/tiny/a", "/d2/tiny/b"]
        );
        assert_eq!(hrefs(&serve("tiny/a", HOST).unwrap().body), ["/d2/tiny/c"]);
        assert_eq!(hrefs(&serve("tiny/b", HOST).unwrap().body), ["/d2/tiny/"]);
        assert_eq!(hrefs(&serve("tiny/c", HOST).unwrap().body), ["/d2/tiny/"]);
        assert!(serve("tiny/d", HOST).is_none());
    }

    #[test]
    fn unknown_paths_are_not_served() {
        for rest in [
            "nope",
            "scope/nope",
            "redir/hop/3",
            "redir/hop/0",
            "redir/nope",
            "index.html",
            "robots.txt",
        ] {
            assert!(serve(rest, HOST).is_none(), "{rest}");
        }
    }

    #[test]
    fn host_header_parsing() {
        assert_eq!(split_host("app.gym.test:4101"), ("app.gym.test", Some(4101)));
        assert_eq!(split_host("app.gym.test"), ("app.gym.test", None));
        assert_eq!(split_host("[::1]:80"), ("::1", Some(80)));
        assert_eq!(split_host("[::1]"), ("::1", None));
        assert_eq!(split_host("h:notaport"), ("h", None));
        assert_eq!(port_suffix("h:65535"), ":65535");
        assert_eq!(port_suffix("h:65536"), "");
        assert_eq!(port_suffix("h"), "");
    }
}
