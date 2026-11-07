//! Katana output fields: `url`, `path`, `fqdn`, `rdn`, `rurl`, `qurl`, `qpath`, `file`,
//! `ufile`, `key`, `value`, `kv`, `dir`, `udir` plus custom regex fields.
//!
//! Semantics ported from katana `pkg/output/fields.go` (`formatField`) at commit
//! `9662cd7b60ba1bc3a88232433ddefc4f48a65bfe` (MIT). Deviations: `qpath` keeps the query in
//! its original order (katana re-encodes it sorted; the README table shows the original
//! order), and `rdn` yields nothing instead of an empty string when the host has no
//! registrable domain (IP addresses, single labels).

use crawlx_core::repo::PageRecord;
use serde_json::Value;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use url::Url;

/// Maximum length of a custom field name (`crawlx_extract::custom_fields`).
const MAX_NAME_LEN: usize = 64;

/// A field name that is neither built in nor a valid custom field name.
#[derive(Clone, Debug, PartialEq, Eq, Error)]
#[error("invalid output field name `{name}`")]
pub struct FieldError {
    /// Offending name.
    pub name: String,
}

/// One output field (katana `-field`).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Field {
    /// The full URL.
    Url,
    /// The URL path.
    Path,
    /// The host name.
    Fqdn,
    /// The registrable domain (public suffix list).
    Rdn,
    /// `scheme://host[:port]`.
    Rurl,
    /// The full URL, only when it has a query.
    Qurl,
    /// `path?query`, only when the URL has a query.
    Qpath,
    /// The last path segment, only when it has an extension.
    File,
    /// The full URL, only when the last path segment has an extension.
    Ufile,
    /// Every query key.
    Key,
    /// Every query value.
    Value,
    /// Every `key=value` pair.
    Kv,
    /// The directory of the path (ends with `/`), only when the path has one.
    Dir,
    /// `rurl` + `dir`.
    Udir,
    /// A custom regex field (`extract.customFields[].name`) read from
    /// `metadata.custom_fields`.
    Custom(String),
}

impl Field {
    /// Built-in field names in katana's order.
    pub const NAMES: [&'static str; 14] = [
        "url", "path", "fqdn", "rdn", "rurl", "qurl", "qpath", "file", "ufile", "key", "value", "kv", "dir",
        "udir",
    ];

    /// Built-in fields in katana's order.
    pub const ALL: [Self; 14] = [
        Self::Url,
        Self::Path,
        Self::Fqdn,
        Self::Rdn,
        Self::Rurl,
        Self::Qurl,
        Self::Qpath,
        Self::File,
        Self::Ufile,
        Self::Key,
        Self::Value,
        Self::Kv,
        Self::Dir,
        Self::Udir,
    ];

    /// The field name as written on the command line.
    #[must_use]
    pub fn as_str(&self) -> &str {
        match self {
            Self::Url => "url",
            Self::Path => "path",
            Self::Fqdn => "fqdn",
            Self::Rdn => "rdn",
            Self::Rurl => "rurl",
            Self::Qurl => "qurl",
            Self::Qpath => "qpath",
            Self::File => "file",
            Self::Ufile => "ufile",
            Self::Key => "key",
            Self::Value => "value",
            Self::Kv => "kv",
            Self::Dir => "dir",
            Self::Udir => "udir",
            Self::Custom(name) => name,
        }
    }

    /// Is this a custom (regex) field?
    #[must_use]
    pub const fn is_custom(&self) -> bool {
        matches!(self, Self::Custom(_))
    }
}

impl Field {
    /// Parse a comma-separated `-f` list (`url,path,email`): every part is a built-in field or
    /// a valid custom field name ([`FromStr`]); blank parts are skipped and a field named twice
    /// is kept once, at its first position.
    ///
    /// # Errors
    /// [`FieldError`] for the first part that is not a valid field name.
    pub fn parse_list(list: &str) -> Result<Vec<Self>, FieldError> {
        let mut out: Vec<Self> = Vec::new();
        for part in list.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let field: Self = part.parse()?;
            if !out.contains(&field) {
                out.push(field);
            }
        }
        Ok(out)
    }
}

impl fmt::Display for Field {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

fn valid_custom_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl FromStr for Field {
    type Err = FieldError;

    /// Built-in names map to their variant; any other name that is a valid custom field
    /// name (`[A-Za-z0-9_-]{1,64}`) becomes [`Field::Custom`].
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let s = s.trim();
        if let Some(i) = Self::NAMES.iter().position(|n| *n == s) {
            return Ok(Self::ALL[i].clone());
        }
        if valid_custom_name(s) {
            return Ok(Self::Custom(s.to_owned()));
        }
        Err(FieldError { name: s.to_owned() })
    }
}

/// `scheme://host[:port]`.
fn root_url(url: &Url) -> String {
    let mut s = format!("{}://", url.scheme());
    if let Some(host) = url.host_str() {
        s.push_str(host);
    }
    if let Some(port) = url.port() {
        s.push(':');
        s.push_str(&port.to_string());
    }
    s
}

/// Go `path.Base` for a non-empty path: trailing slashes removed, last element.
fn base_name(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    trimmed.rsplit('/').next().unwrap_or(trimmed)
}

/// The directory prefix of `path` up to and including its last `/`, when the path has a
/// slash after its leading one (katana `dir`).
fn directory(path: &str) -> Option<&str> {
    if path.is_empty() || path == "/" {
        return None;
    }
    let rest = path.get(1..)?;
    let last = rest.rfind('/')?;
    path.get(..last.checked_add(2)?)
}

/// Last path segment when it has an extension (katana `file`).
fn file_name(path: &str) -> Option<&str> {
    if path.is_empty() || path == "/" {
        return None;
    }
    let base = base_name(path);
    base.contains('.').then_some(base)
}

/// Values of `field` for `url`; custom fields read `metadata.custom_fields[name]`.
///
/// Multi-valued fields (`key`, `value`, `kv`, custom) return one entry per value; fields
/// without a value for this URL return an empty vector.
#[must_use]
pub fn extract(field: &Field, url: &Url, metadata: &Value) -> Vec<String> {
    let path = url.path();
    let one = |v: String| vec![v];
    match field {
        Field::Url => one(url.to_string()),
        Field::Path => {
            if path.is_empty() {
                Vec::new()
            } else {
                one(path.to_owned())
            }
        }
        Field::Fqdn => url.host_str().map(str::to_owned).into_iter().collect(),
        Field::Rdn => url
            .host_str()
            .and_then(crawlx_policy::scope::registrable_domain)
            .into_iter()
            .collect(),
        Field::Rurl => one(root_url(url)),
        Field::Qurl => url.query().map(|_| url.to_string()).into_iter().collect(),
        Field::Qpath => url.query().map(|q| format!("{path}?{q}")).into_iter().collect(),
        Field::File => file_name(path).map(str::to_owned).into_iter().collect(),
        Field::Ufile => file_name(path).map(|_| url.to_string()).into_iter().collect(),
        Field::Key => url.query_pairs().map(|(k, _)| k.into_owned()).collect(),
        Field::Value => url.query_pairs().map(|(_, v)| v.into_owned()).collect(),
        Field::Kv => url.query_pairs().map(|(k, v)| format!("{k}={v}")).collect(),
        Field::Dir => directory(path).map(str::to_owned).into_iter().collect(),
        Field::Udir => directory(path)
            .map(|d| format!("{}{d}", root_url(url)))
            .into_iter()
            .collect(),
        Field::Custom(name) => metadata
            .get("custom_fields")
            .and_then(|m| m.get(name))
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default(),
    }
}

/// [`extract`] over a stored page.
#[must_use]
pub fn extract_page(field: &Field, page: &PageRecord) -> Vec<String> {
    extract(field, &page.url.url, &page.metadata)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    fn values(field: &str, url: &str) -> Vec<String> {
        extract(&field.parse().unwrap(), &Url::parse(url).unwrap(), &Value::Null)
    }

    /// Every row of the katana README "Field" table (`/tmp/katana/README.md`, section
    /// "Field"), with the URL each row's example implies. Multi-valued rows are joined with
    /// the separator the README shows. The README's `path` example prints a full URL, which
    /// contradicts katana's `formatField` (`parsed.Path`); the code is followed.
    #[test]
    fn readme_field_table_reproduces() {
        let q = "https://admin.projectdiscovery.io/admin/login?user=admin&password=admin";
        let php = "https://admin.projectdiscovery.io/admin/login.php?user=admin&password=admin";
        let rows: [(&str, &str, &str, &str); 14] = [
            ("url", q, ",", q),
            ("qurl", php, ",", php),
            (
                "qpath",
                "https://admin.projectdiscovery.io/login?user=admin&password=admin",
                ",",
                "/login?user=admin&password=admin",
            ),
            ("path", q, ",", "/admin/login"),
            ("fqdn", q, ",", "admin.projectdiscovery.io"),
            ("rdn", q, ",", "projectdiscovery.io"),
            ("rurl", q, ",", "https://admin.projectdiscovery.io"),
            (
                "ufile",
                "https://admin.projectdiscovery.io/login.js",
                ",",
                "https://admin.projectdiscovery.io/login.js",
            ),
            ("file", php, ",", "login.php"),
            ("key", q, ",", "user,password"),
            ("value", q, ",", "admin,admin"),
            ("kv", q, "&", "user=admin&password=admin"),
            ("dir", q, ",", "/admin/"),
            ("udir", q, ",", "https://admin.projectdiscovery.io/admin/"),
        ];
        for (field, url, sep, expected) in rows {
            assert_eq!(values(field, url).join(sep), expected, "field `{field}`");
        }
    }

    #[test]
    fn api_example_url_fields() {
        let u = "https://example.com/api/v1/users?id=1&q=x";
        let expect: [(&str, &[&str]); 14] = [
            ("url", &[u]),
            ("path", &["/api/v1/users"]),
            ("fqdn", &["example.com"]),
            ("rdn", &["example.com"]),
            ("rurl", &["https://example.com"]),
            ("qurl", &[u]),
            ("qpath", &["/api/v1/users?id=1&q=x"]),
            ("file", &[]),
            ("ufile", &[]),
            ("key", &["id", "q"]),
            ("value", &["1", "x"]),
            ("kv", &["id=1", "q=x"]),
            ("dir", &["/api/v1/"]),
            ("udir", &["https://example.com/api/v1/"]),
        ];
        for (field, want) in expect {
            assert_eq!(values(field, u), want, "field `{field}`");
        }
        assert_eq!(
            Field::ALL.map(|f| f.as_str().to_owned()),
            Field::NAMES.map(str::to_owned)
        );
    }

    #[test]
    fn query_less_and_root_urls_yield_nothing_for_conditional_fields() {
        for f in [
            "qurl", "qpath", "key", "value", "kv", "file", "ufile", "dir", "udir",
        ] {
            assert!(values(f, "https://example.com/").is_empty(), "{f}");
        }
        assert_eq!(values("path", "https://example.com"), ["/"]);
        assert!(values("dir", "https://example.com/a").is_empty());
        assert_eq!(values("dir", "https://example.com/a/"), ["/a/"]);
        assert_eq!(values("file", "https://example.com/x.d/"), ["x.d"]);
        assert_eq!(
            values("rurl", "http://127.0.0.1:8080/a?b=c"),
            ["http://127.0.0.1:8080"]
        );
        assert_eq!(values("fqdn", "http://127.0.0.1:8080/a"), ["127.0.0.1"]);
        assert!(values("rdn", "http://127.0.0.1:8080/a").is_empty());
        assert_eq!(values("rdn", "https://a.b.co.uk/"), ["b.co.uk"]);
    }

    #[test]
    fn custom_fields_read_metadata_and_names_are_validated() {
        let meta = json!({"custom_fields": {"email": ["a@x.io", "b@x.io"], "n": [1]}});
        let url = Url::parse("https://example.com/").unwrap();
        assert_eq!(
            extract(&Field::Custom("email".to_owned()), &url, &meta),
            ["a@x.io", "b@x.io"]
        );
        assert!(extract(&Field::Custom("n".to_owned()), &url, &meta).is_empty());
        assert!(extract(&Field::Custom("missing".to_owned()), &url, &meta).is_empty());
        assert_eq!(
            "email".parse::<Field>().unwrap(),
            Field::Custom("email".to_owned())
        );
        assert_eq!(" kv ".parse::<Field>().unwrap(), Field::Kv);
        assert!("".parse::<Field>().is_err());
        assert!("a b".parse::<Field>().is_err());
        assert!("x".repeat(65).parse::<Field>().is_err());
        assert_eq!(Field::Udir.to_string(), "udir");
    }

    #[test]
    fn parse_list_splits_on_commas_and_dedupes() {
        assert_eq!(
            Field::parse_list("url, path,email,url,,").unwrap(),
            [Field::Url, Field::Path, Field::Custom("email".to_owned())]
        );
        assert_eq!(Field::parse_list("kv").unwrap(), [Field::Kv]);
        assert!(Field::parse_list("").unwrap().is_empty());
        let err = Field::parse_list("url,a b").unwrap_err();
        assert_eq!(err.name, "a b");
    }
}
