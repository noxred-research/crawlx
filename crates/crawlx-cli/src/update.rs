//! Release check (compatibility `-update`, `-disable-update-check`).
//!
//! crawlx never downloads or replaces its own binary. `--update` asks the release endpoint
//! once and prints whether a newer version exists; with `CRAWLX_UPDATE_CHECK=1` the same
//! question is asked once at the start of a crawl, unless `--disable-update-check` is given.
//! The endpoint is `CRAWLX_RELEASE_URL` (default: the project's GitHub "latest release" API).

use anyhow::{anyhow, bail, Context as _};
use std::cmp::Ordering;
use std::time::Duration;

/// Environment variable overriding [`DEFAULT_RELEASE_URL`].
pub const RELEASE_URL_ENV: &str = "CRAWLX_RELEASE_URL";
/// Environment variable that turns the automatic check on (`1`, `true`, `yes`).
pub const UPDATE_CHECK_ENV: &str = "CRAWLX_UPDATE_CHECK";
/// The project's "latest release" endpoint.
pub const DEFAULT_RELEASE_URL: &str = "https://api.github.com/repos/noxred-research/crawlx/releases/latest";

const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);

/// What the release endpoint says about the running version.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UpdateStatus {
    /// The running version is the latest release.
    UpToDate {
        /// Running version.
        current: String,
    },
    /// A newer release exists.
    Available {
        /// Running version.
        current: String,
        /// Latest release version.
        latest: String,
        /// Where the release is described, when the endpoint says.
        url: Option<String>,
    },
    /// The running version is newer than the latest release (a development build).
    Ahead {
        /// Running version.
        current: String,
        /// Latest release version.
        latest: String,
    },
}

impl UpdateStatus {
    /// The one-line message printed for this status.
    #[must_use]
    pub fn message(&self) -> String {
        match self {
            Self::UpToDate { current } => format!("crawlx {current} is up to date"),
            Self::Available { current, latest, url } => {
                let more = url.as_deref().map(|u| format!(": {u}")).unwrap_or_default();
                format!("a newer crawlx is available: {latest} (running {current}){more}")
            }
            Self::Ahead { current, latest } => {
                format!("crawlx {current} is newer than the latest release {latest}")
            }
        }
    }
}

/// The endpoint to ask: `CRAWLX_RELEASE_URL` when set and non-empty, else the default.
#[must_use]
pub fn release_url(getenv: &dyn Fn(&str) -> Option<String>) -> String {
    getenv(RELEASE_URL_ENV)
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| DEFAULT_RELEASE_URL.to_owned())
}

/// Whether the automatic check runs: `CRAWLX_UPDATE_CHECK` is on and `--disable-update-check`
/// was not given.
#[must_use]
pub fn auto_check_enabled(getenv: &dyn Fn(&str) -> Option<String>, disabled: bool) -> bool {
    !disabled && getenv(UPDATE_CHECK_ENV).is_some_and(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes"))
}

/// GET `url` once and compare the `tag_name` of the answer with `current`.
///
/// # Errors
/// The request fails, answers with a non-success status or a body without a semantic
/// `tag_name`.
pub async fn check(url: &str, current: &str) -> anyhow::Result<UpdateStatus> {
    let client = reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .user_agent(format!("crawlx/{current}"))
        .build()
        .context("building the release-check client")?;
    let response = client
        .get(url)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .send()
        .await
        .with_context(|| format!("release check: GET {url}"))?;
    let status = response.status();
    if !status.is_success() {
        bail!("release check: {url} answered {status}");
    }
    let body: serde_json::Value = response
        .json()
        .await
        .with_context(|| format!("release check: {url} did not answer JSON"))?;
    let tag = body
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| anyhow!("release check: {url} answered no `tag_name`"))?;
    let latest = tag.trim().trim_start_matches('v').to_owned();
    let release_page = body
        .get("html_url")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    compare(current, &latest, release_page)
}

fn compare(current: &str, latest: &str, url: Option<String>) -> anyhow::Result<UpdateStatus> {
    let have =
        Semver::parse(current).ok_or_else(|| anyhow!("running version {current:?} is not semantic"))?;
    let want =
        Semver::parse(latest).ok_or_else(|| anyhow!("release tag {latest:?} is not a semantic version"))?;
    Ok(match want.cmp(&have) {
        Ordering::Greater => UpdateStatus::Available {
            current: current.to_owned(),
            latest: latest.to_owned(),
            url,
        },
        Ordering::Equal => UpdateStatus::UpToDate {
            current: current.to_owned(),
        },
        Ordering::Less => UpdateStatus::Ahead {
            current: current.to_owned(),
            latest: latest.to_owned(),
        },
    })
}

/// Semantic-version precedence (<https://semver.org/#spec-item-11>); build metadata is ignored.
#[derive(Debug, PartialEq, Eq)]
struct Semver {
    core: [u64; 3],
    pre: Vec<String>,
}

impl Semver {
    fn parse(text: &str) -> Option<Self> {
        let text = text.split('+').next()?;
        let (core, pre) = match text.split_once('-') {
            Some((core, pre)) => (core, pre.split('.').map(str::to_owned).collect()),
            None => (text, Vec::new()),
        };
        let mut parts = core.split('.');
        let mut out = [0u64; 3];
        for slot in &mut out {
            *slot = parts.next()?.parse().ok()?;
        }
        if parts.next().is_some() || pre.iter().any(String::is_empty) {
            return None;
        }
        Some(Self { core: out, pre })
    }
}

impl Ord for Semver {
    fn cmp(&self, other: &Self) -> Ordering {
        self.core
            .cmp(&other.core)
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => cmp_pre(&self.pre, &other.pre),
            })
    }
}

impl PartialOrd for Semver {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn cmp_pre(a: &[String], b: &[String]) -> Ordering {
    for (x, y) in a.iter().zip(b) {
        let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
            (Ok(x), Ok(y)) => x.cmp(&y),
            (Ok(_), Err(_)) => Ordering::Less,
            (Err(_), Ok(_)) => Ordering::Greater,
            (Err(_), Err(_)) => x.cmp(y),
        };
        if ord != Ordering::Equal {
            return ord;
        }
    }
    a.len().cmp(&b.len())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn precedence_follows_semver() {
        let v = |s: &str| Semver::parse(s).unwrap();
        assert!(v("1.2.3") < v("1.10.0"));
        assert!(v("1.0.0-rc.1") < v("1.0.0"));
        assert!(v("1.0.0-alpha") < v("1.0.0-alpha.1"));
        assert!(v("1.0.0-alpha.2") < v("1.0.0-alpha.10"));
        assert!(v("1.0.0-1") < v("1.0.0-alpha"));
        assert_eq!(v("1.0.0+build5"), v("1.0.0"));
        assert!(Semver::parse("1.0").is_none());
        assert!(Semver::parse("one").is_none());
        assert!(Semver::parse("1.0.0-").is_none());
    }

    #[test]
    fn status_messages_say_what_to_do() {
        let a = compare("0.1.0", "0.2.0", Some("https://r/0.2.0".to_owned())).unwrap();
        assert_eq!(
            a.message(),
            "a newer crawlx is available: 0.2.0 (running 0.1.0): https://r/0.2.0"
        );
        assert_eq!(
            compare("0.1.0", "0.1.0", None).unwrap().message(),
            "crawlx 0.1.0 is up to date"
        );
        assert_eq!(
            compare("0.3.0", "0.2.0", None).unwrap().message(),
            "crawlx 0.3.0 is newer than the latest release 0.2.0"
        );
        assert!(compare("0.1.0", "nightly", None).is_err());
    }

    #[test]
    fn the_check_is_off_unless_the_env_enables_it_and_the_flag_does_not_disable_it() {
        let on = |k: &str| (k == UPDATE_CHECK_ENV).then(|| "1".to_owned());
        let off = |_: &str| None;
        assert!(auto_check_enabled(&on, false));
        assert!(!auto_check_enabled(&on, true));
        assert!(!auto_check_enabled(&off, false));
        let custom = |k: &str| (k == RELEASE_URL_ENV).then(|| " http://x/y ".to_owned());
        assert_eq!(release_url(&custom), "http://x/y");
        assert_eq!(release_url(&off), DEFAULT_RELEASE_URL);
    }
}
