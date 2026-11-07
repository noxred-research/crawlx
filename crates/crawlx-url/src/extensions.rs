//! File-extension filter for the frontier
//! (`scope.extensionMatch|extensionFilter|noDefaultExtensionFilter`).
//!
//! Ported from projectdiscovery/katana `pkg/utils/extensions/extensions.go`
//! at commit 9662cd7 (MIT).
//! Path classification follows `path.Ext` in the v1.8.0 validator at commit
//! `35267ac5c8ff1db9694a319d0eb466ed97b0969f`.
//!
//! A non-empty match list is an allow list (only those extensions pass); the
//! filter list is a deny list, seeded with [`DEFAULT_EXTENSION_FILTER`] unless
//! disabled. The pseudo-extension `none` names URLs without an extension.

use std::collections::BTreeSet;

use url::Url;

/// Katana's default deny list (images, fonts, archives, media, office
/// documents, binaries), without the leading dot.
pub const DEFAULT_EXTENSION_FILTER: &[&str] = &[
    "3g2", "3gp", "7z", "apk", "arj", "avi", "axd", "bmp", "csv", "deb", "dll", "doc", "drv", "eot", "exe",
    "flv", "gif", "gifv", "gz", "h264", "ico", "iso", "jar", "jpeg", "jpg", "lock", "m4a", "m4v", "map",
    "mkv", "mov", "mp3", "mp4", "mpeg", "mpg", "msi", "ogg", "ogm", "ogv", "otf", "pdf", "pkg", "png", "ppt",
    "psd", "rar", "rm", "rpm", "svg", "swf", "sys", "tar.gz", "tar", "tif", "tiff", "ttf", "txt", "vob",
    "wav", "webm", "webp", "wmv", "woff", "woff2", "xcf", "xls", "xlsx", "zip",
];

/// Pseudo-extension naming URLs whose path has no extension.
pub const NONE_EXTENSION: &str = "none";

/// Normalized form: lowercase, no leading dot; `none` becomes the empty string.
/// A literal `.` names a trailing-dot extension, distinct from no extension.
fn normalize(ext: &str) -> String {
    let ext = ext.trim();
    let extension = if ext == "." {
        ext
    } else {
        ext.trim_start_matches('.')
    };
    let e = extension.to_ascii_lowercase();
    if e == NONE_EXTENSION {
        String::new()
    } else {
        e
    }
}

/// Extension of a URL path (lowercase, no leading dot; empty when none).
/// Only the last path segment counts. A leading dot starts an extension,
/// and a trailing dot yields `.` rather than no extension, as in Go's `path.Ext`.
#[must_use]
pub fn path_extension(path: &str) -> String {
    let last = path.rsplit('/').next().unwrap_or("");
    match last.rsplit_once('.') {
        Some((_, "")) => ".".to_owned(),
        Some((_, ext)) => ext.to_ascii_lowercase(),
        None => String::new(),
    }
}

/// Compiled allow/deny extension sets.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExtensionFilter {
    matches: BTreeSet<String>,
    filtered: BTreeSet<String>,
}

impl ExtensionFilter {
    /// Build from `extensionMatch`, `extensionFilter` and `noDefaultExtensionFilter`.
    #[must_use]
    pub fn new<S: AsRef<str>>(matches: &[S], filter: &[S], no_default_filter: bool) -> Self {
        let mut out = Self::default();
        out.matches.extend(matches.iter().map(|e| normalize(e.as_ref())));
        if !no_default_filter {
            out.filtered
                .extend(DEFAULT_EXTENSION_FILTER.iter().map(|e| (*e).to_owned()));
        }
        out.filtered.extend(filter.iter().map(|e| normalize(e.as_ref())));
        out
    }

    /// Katana's defaults: no allow list, the default deny list.
    #[must_use]
    pub fn defaults() -> Self {
        Self::new::<&str>(&[], &[], false)
    }

    /// Does the filter pass every URL (no allow list, empty deny list)?
    #[must_use]
    pub fn is_permissive(&self) -> bool {
        self.matches.is_empty() && self.filtered.is_empty()
    }

    /// Is a path with `extension` (lowercase, no leading dot; `.` for a trailing dot,
    /// empty for none) allowed?
    #[must_use]
    pub fn allows_extension(&self, extension: &str) -> bool {
        if !self.matches.is_empty() {
            return self.matches.contains(extension);
        }
        !self.filtered.contains(extension)
    }

    /// Is `url` allowed?
    #[must_use]
    pub fn allows(&self, url: &Url) -> bool {
        self.allows_extension(&path_extension(url.path()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn ok(f: &ExtensionFilter, u: &str) -> bool {
        f.allows(&Url::parse(u).unwrap())
    }

    #[test]
    fn katana_validator_cases() {
        let f = ExtensionFilter::new(&[".go"], &[], false);
        assert!(ok(&f, "https://e.test/main.go"));
        assert!(!ok(&f, "https://e.test/main.php"));
        let f = ExtensionFilter::new(&[], &[".php"], false);
        assert!(!ok(&f, "https://e.test/main.php"));
        assert!(ok(&f, "https://e.test/main.go"));
        let f = ExtensionFilter::new(&["png"], &[], false);
        assert!(
            ok(&f, "https://e.test/main.png"),
            "match list bypasses the default deny list"
        );
        let f = ExtensionFilter::new::<&str>(&[], &[], true);
        assert!(ok(&f, "https://e.test/main.png"));
        assert!(f.is_permissive());
        let f = ExtensionFilter::new(&[], &["png"], true);
        assert!(!ok(&f, "https://e.test/main.png"));
    }

    #[test]
    fn defaults_deny_binary_media_and_documents() {
        let f = ExtensionFilter::defaults();
        for u in [
            "https://e.test/a.PNG",
            "https://e.test/a/b.jpg",
            "https://e.test/font.woff2",
            "https://e.test/doc.pdf",
            "https://e.test/x.tar.gz",
            "https://e.test/data.csv?x=1",
        ] {
            assert!(!ok(&f, u), "{u}");
        }
        for u in [
            "https://e.test/",
            "https://e.test/page",
            "https://e.test/page.html",
            "https://e.test/app.js",
            "https://e.test/api/v1.2/users",
            "https://e.test/.well-known/x",
            "https://e.test/png/",
        ] {
            assert!(ok(&f, u), "{u}");
        }
        assert!(!f.is_permissive());
    }

    #[test]
    fn none_pseudo_extension() {
        let f = ExtensionFilter::new(&["css", "js"], &[], false);
        assert!(ok(&f, "https://e.test/style.css"));
        assert!(!ok(&f, "https://e.test/page"));
        assert!(!ok(&f, "https://e.test/"));
        let f = ExtensionFilter::new(&["css", "js", "none"], &[], false);
        assert!(ok(&f, "https://e.test/page"));
        assert!(ok(&f, "https://e.test/"));
        assert!(!ok(&f, "https://e.test/image.png"));
        let f = ExtensionFilter::new(&["NONE"], &[], false);
        assert!(ok(&f, "https://e.test/page"));
        assert!(!ok(&f, "https://e.test/app.js"));
        let f = ExtensionFilter::new(&[], &["none"], false);
        assert!(!ok(&f, "https://e.test/page"));
        assert!(ok(&f, "https://e.test/app.js"));
    }

    #[test]
    fn pinned_dotfile_and_trailing_dot_filter_cases() {
        let filters = [
            ExtensionFilter::defaults(),
            ExtensionFilter::new(&["png"], &[], false),
            ExtensionFilter::new(&["none"], &[], false),
            ExtensionFilter::new(&["."], &[], false),
            ExtensionFilter::new::<&str>(&[], &[], true),
        ];
        for (url, expected) in [
            ("https://e.test/", [true, false, true, false, true]),
            ("https://e.test/page", [true, false, true, false, true]),
            ("https://e.test/.png", [false, true, false, false, true]),
            ("https://e.test/.PNG?name=.php", [false, true, false, false, true]),
            ("https://e.test/image.png", [false, true, false, false, true]),
            ("https://e.test/file.", [true, false, false, true, true]),
            ("https://e.test/.hidden", [true, false, false, false, true]),
            ("https://e.test/dir.png/leaf", [true, false, true, false, true]),
            ("https://e.test/dir.png/", [true, false, true, false, true]),
        ] {
            for (filter, expected) in filters.iter().zip(expected) {
                assert_eq!(ok(filter, url), expected, "{url}: {filter:?}");
            }
        }
        let deny_dot = ExtensionFilter::new(&[], &["."], true);
        assert!(!ok(&deny_dot, "https://e.test/file."));
        assert!(ok(&deny_dot, "https://e.test/page"));
        let deny_none = ExtensionFilter::new(&[], &["none"], true);
        assert!(ok(&deny_none, "https://e.test/file."));
        assert!(!ok(&deny_none, "https://e.test/page"));
    }

    #[test]
    fn extension_of_path() {
        assert_eq!(path_extension("/a/b.JPG"), "jpg");
        assert_eq!(path_extension("/a.b/c"), "");
        assert_eq!(path_extension("/.hidden"), "hidden");
        assert_eq!(path_extension("/x."), ".");
        assert_eq!(path_extension("/"), "");
        assert_eq!(path_extension("/x.tar.gz"), "gz");
    }
}
