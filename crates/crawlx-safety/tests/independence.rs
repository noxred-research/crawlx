//! The kernel depends only on `crawlx-core`, `crawlx-url`
//! and `crawlx-policy`. (CI additionally checks `cargo metadata`; this test
//! catches the edge in the crate's own manifest.)
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[test]
fn manifest_has_no_forbidden_crawlx_dependencies() {
    let manifest = include_str!("../Cargo.toml");
    let deps: Vec<&str> = manifest
        .lines()
        .map(str::trim)
        .filter_map(|l| l.split(['=', ' ']).next())
        .filter(|name| name.starts_with("crawlx-"))
        .collect();
    for name in deps {
        assert!(
            matches!(name, "crawlx-core" | "crawlx-policy" | "crawlx-url"),
            "forbidden dependency on {name}"
        );
    }
    for forbidden in [
        "crawlx-model",
        "crawlx-strategies",
        "crawlx-graph",
        "crawlx-browser",
    ] {
        assert!(
            !manifest.contains(forbidden),
            "{forbidden} must not appear in crawlx-safety/Cargo.toml"
        );
    }
}
