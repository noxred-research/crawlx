//! Fixture `s1`: the static site.
//!
//! 28 linked pages, tracking-parameter, trailing-slash and fragment duplicates,
//! `/s1/private/` paths blocked by `/robots.txt`, external and out-of-scope links, a sitemap
//! with five pages nothing links to, one 404 and one 500. The link graph is data, so the
//! expected URL-plane counters in `fixtures/s1/manifest.json` are a property of this file.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::LazyLock;

/// Fixture id.
pub const ID: &str = "s1";

/// A generated `s1` response, ready to be written to the socket.
#[derive(Clone, Debug)]
pub struct S1Response {
    /// HTTP status code (200, or the deliberate 404/500 pages of the site).
    pub status: u16,
    /// MIME type sent as the `Content-Type` header.
    pub content_type: &'static str,
    /// Response body (HTML, XML or plain text).
    pub body: String,
}

struct PageDef {
    title: String,
    links: Vec<(String, String)>,
}

fn l(href: &str, text: &str) -> (String, String) {
    (href.to_owned(), text.to_owned())
}

fn insert(m: &mut BTreeMap<String, PageDef>, key: &str, title: &str, links: Vec<(String, String)>) {
    m.insert(
        key.to_owned(),
        PageDef {
            title: title.to_owned(),
            links,
        },
    );
}

#[allow(clippy::too_many_lines)]
fn build() -> BTreeMap<String, PageDef> {
    let mut m = BTreeMap::new();
    insert(
        &mut m,
        "",
        "Gym Static Site",
        vec![
            l("/s1/about/", "About"),
            l("/s1/contact/", "Contact"),
            l("/s1/team/", "Team"),
            l("/s1/careers/", "Careers"),
            l("/s1/pricing/", "Pricing"),
            l("/s1/blog/", "Blog"),
            l("/s1/docs/", "Docs"),
            l("/s1/products/", "Products"),
            // duplicates: tracking parameter, trailing slash, tracking + trailing slash
            l("/s1/about?utm_source=newsletter", "About (newsletter)"),
            l("/s1/blog", "Blog (no slash)"),
            l(
                "/s1/docs/?utm_medium=email&utm_campaign=spring",
                "Docs (campaign)",
            ),
            // external hosts and an out-of-scope path on the same origin
            l("https://external.example/partner", "Partner"),
            l("https://www.example.org/", "Example"),
            l("/d1/", "Single page app"),
            // robots-blocked and failing pages
            l("/s1/private/", "Private area"),
            l("/s1/missing", "Missing page"),
            l("/s1/error", "Broken page"),
        ],
    );
    insert(
        &mut m,
        "about",
        "About",
        vec![l("/s1/", "Home"), l("/s1/team/", "Team")],
    );
    insert(
        &mut m,
        "contact",
        "Contact",
        vec![
            l("/s1/", "Home"),
            l("/s1/about/#team", "About our team"),
            l("mailto:hello@gym.test", "Email us"),
        ],
    );
    insert(
        &mut m,
        "team",
        "Team",
        vec![l("/s1/", "Home"), l("/s1/careers/", "Careers")],
    );
    insert(&mut m, "careers", "Careers", vec![l("/s1/", "Home")]);
    insert(
        &mut m,
        "pricing",
        "Pricing",
        vec![l("/s1/", "Home"), l("/s1/products/", "Products")],
    );

    let mut blog = vec![l("/s1/", "Home")];
    for n in 1..=6 {
        blog.push(l(&format!("/s1/blog/post-{n}/"), &format!("Post {n}")));
    }
    insert(&mut m, "blog", "Blog", blog);
    for n in 1..=6 {
        let mut links = vec![l("/s1/blog/", "Back to the blog")];
        if n < 6 {
            links.push(l(&format!("/s1/blog/post-{}/", n + 1), "Next post"));
        }
        links.push(l("/s1/", "Home"));
        if n == 3 {
            links.push(l("/s1/private/secret", "Leaked draft"));
        }
        insert(&mut m, &format!("blog/post-{n}"), &format!("Post {n}"), links);
    }

    insert(
        &mut m,
        "docs",
        "Documentation",
        vec![
            l("/s1/", "Home"),
            l("/s1/docs/intro/", "Introduction"),
            l("/s1/docs/guide/", "Guide"),
            l("/s1/docs/api/", "API"),
            l("/s1/docs/faq/", "FAQ"),
        ],
    );
    for (key, title) in [
        ("intro", "Introduction"),
        ("guide", "Guide"),
        ("api", "API"),
        ("faq", "FAQ"),
    ] {
        let mut links = vec![l("/s1/docs/", "Docs index"), l("/s1/", "Home")];
        if key == "api" {
            links.push(l("/s1/docs/guide/?utm_source=api", "Guide (from API)"));
        }
        insert(&mut m, &format!("docs/{key}"), title, links);
    }

    insert(
        &mut m,
        "products",
        "Products",
        vec![
            l("/s1/", "Home"),
            l("/s1/products/alpha/", "Alpha"),
            l("/s1/products/beta/", "Beta"),
            l("/s1/products/gamma/", "Gamma"),
            l("/s1/products/delta/", "Delta"),
        ],
    );
    for key in ["alpha", "beta", "gamma", "delta"] {
        let mut links = vec![l("/s1/products/", "All products"), l("/s1/", "Home")];
        if key == "alpha" {
            links.push(l("/s1/products/beta/?utm_source=cross", "Beta (cross-sell)"));
        }
        insert(&mut m, &format!("products/{key}"), key, links);
    }

    // Reachable only through the sitemap.
    for n in 1..=5 {
        insert(
            &mut m,
            &format!("archive/y{n}"),
            &format!("Archive {n}"),
            vec![l("/s1/", "Home")],
        );
    }
    // Robots-blocked area: exists, so a rude crawler can fetch (and be caught by the ledger).
    insert(&mut m, "private", "Private", vec![l("/s1/", "Home")]);
    insert(&mut m, "private/secret", "Secret", vec![l("/s1/", "Home")]);
    m
}

static SITE: LazyLock<BTreeMap<String, PageDef>> = LazyLock::new(build);

fn site() -> &'static BTreeMap<String, PageDef> {
    &SITE
}

fn escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('"', "&quot;")
}

fn render_page(def: &PageDef) -> String {
    let mut body = String::new();
    for (href, text) in &def.links {
        let _ = writeln!(body, "<li><a href=\"{}\">{}</a></li>", escape(href), escape(text));
    }
    format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>{t}</title></head>\n\
         <body><header><h1>{t}</h1></header>\n<main><p>{t}: a static page of the CrawlerGym s1 site.</p>\n\
         <ul>\n{body}</ul></main></body></html>\n",
        t = escape(&def.title)
    )
}

/// The pages of the site as `(path, html)`, for tests that need the link graph.
#[must_use]
pub fn page_paths() -> Vec<String> {
    site()
        .keys()
        .map(|k| {
            if k.is_empty() {
                "/s1/".to_owned()
            } else {
                format!("/s1/{k}/")
            }
        })
        .collect()
}

/// Paths listed in `/s1/sitemap.xml` (no page links to them).
#[must_use]
pub fn sitemap_paths() -> Vec<String> {
    (1..=5).map(|n| format!("/s1/archive/y{n}/")).collect()
}

/// `robots.txt` of the gym origin for request host `host` (e.g. `127.0.0.1:41233`).
#[must_use]
pub fn robots_txt(host: &str) -> String {
    format!("User-agent: *\nDisallow: /s1/private\nCrawl-delay: 0\n\nSitemap: http://{host}/s1/sitemap.xml\n")
}

fn sitemap_xml(host: &str) -> String {
    let mut s = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n",
    );
    for p in sitemap_paths() {
        let _ = writeln!(
            s,
            "  <url><loc>http://{host}{p}</loc><lastmod>2026-01-01</lastmod><priority>0.4</priority></url>"
        );
    }
    s.push_str("</urlset>\n");
    s
}

/// Serve `rest` (the path below `/s1/`, no leading slash). `host` is the request's `Host`.
#[must_use]
pub fn serve(rest: &str, host: &str) -> Option<S1Response> {
    let html = "text/html; charset=utf-8";
    let key = rest.trim_matches('/');
    match key {
        "sitemap.xml" => {
            return Some(S1Response {
                status: 200,
                content_type: "application/xml",
                body: sitemap_xml(host),
            })
        }
        "missing" => {
            return Some(S1Response {
                status: 404,
                content_type: html,
                body: "<!doctype html><title>Not found</title><h1>Not found</h1>".to_owned(),
            })
        }
        "error" => {
            return Some(S1Response {
                status: 500,
                content_type: html,
                body: "<!doctype html><title>Server error</title><h1>Server error</h1>".to_owned(),
            })
        }
        _ => {}
    }
    site().get(key).map(|def| S1Response {
        status: 200,
        content_type: html,
        body: render_page(def),
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn site_has_more_than_twenty_linked_pages_and_special_statuses() {
        assert!(page_paths().len() >= 28);
        assert_eq!(serve("missing", "h").unwrap().status, 404);
        assert_eq!(serve("error/", "h").unwrap().status, 500);
        assert!(serve("nope", "h").is_none());
        assert!(serve("about/", "h").unwrap().body.contains("href=\"/s1/team/\""));
        assert!(serve("", "h").unwrap().body.contains("utm_source=newsletter"));
    }

    #[test]
    fn robots_and_sitemap_name_the_host() {
        assert!(robots_txt("h:1").contains("Disallow: /s1/private\n"));
        assert!(robots_txt("h:1").contains("Sitemap: http://h:1/s1/sitemap.xml"));
        let x = serve("sitemap.xml", "h:1").unwrap().body;
        assert_eq!(x.matches("<url>").count(), 5);
        assert!(x.contains("http://h:1/s1/archive/y3/"));
    }
}
