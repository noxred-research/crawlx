//! Operator-only encrypted DNS configuration shared by worker startup and config checking.

use crate::config_check::{egress_source, load_from, Loaded, ProxyUrl, CONFIG_ENV};
use anyhow::{anyhow, Context as _};
use crawlx_fetch::{HttpsResolver, HttpsResolverConfig};
use crawlx_policy::{EgressPolicy, SharedEgressLists};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

pub(crate) const ENV: &[&str] = &[
    "CRAWLX_FETCH__RESOLVER_HTTPS__ENDPOINT",
    "CRAWLX_FETCH__RESOLVER_HTTPS__BOOTSTRAP_PINS",
    "CRAWLX_FETCH__RESOLVER_HTTPS__DEADLINE_MS",
    "CRAWLX_FETCH__RESOLVER_HTTPS__MAX_RESPONSE_BYTES",
    "CRAWLX_FETCH__RESOLVER_HTTPS__MAX_RECORDS",
    "CRAWLX_FETCH__RESOLVER_HTTPS__MAX_CNAME_DEPTH",
];

/// Deployment `[fetch.resolver_https]` settings. Absent settings preserve system DNS.
///
/// An endpoint activates encrypted DNS. Pins are mandatory and never resolved through the
/// adapter. Tenant request fields cannot supply or override any setting in this section.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
#[non_exhaustive]
pub struct ResolverHttpsSettings {
    /// HTTPS wire-format POST endpoint; serialized output redacts the entire URL.
    pub endpoint: Option<ProxyUrl>,
    /// Approved endpoint IP addresses, at most 16. No implicit bootstrap resolver exists.
    pub bootstrap_pins: Vec<IpAddr>,
    /// Total lookup deadline in milliseconds, 1..=60,000.
    pub deadline_ms: u64,
    /// Maximum DNS response bytes, 12..=65,535.
    pub max_response_bytes: u32,
    /// Maximum records per response, 1..=1,024.
    pub max_records: u16,
    /// Maximum alias transitions per address family, 1..=16.
    pub max_cname_depth: u8,
}

impl Default for ResolverHttpsSettings {
    fn default() -> Self {
        Self {
            endpoint: None,
            bootstrap_pins: Vec::new(),
            deadline_ms: 5000,
            max_response_bytes: 16_384,
            max_records: 128,
            max_cname_depth: 8,
        }
    }
}

impl ResolverHttpsSettings {
    fn config(&self) -> anyhow::Result<HttpsResolverConfig> {
        let endpoint = self
            .endpoint
            .as_ref()
            .ok_or_else(|| anyhow!("encrypted DNS settings require an endpoint"))?;
        let endpoint = url::Url::parse(&endpoint.0).context("invalid encrypted DNS endpoint URL")?;
        let mut config = HttpsResolverConfig::new(endpoint, self.bootstrap_pins.clone());
        config.deadline = Duration::from_millis(self.deadline_ms);
        config.max_response_bytes = usize::try_from(self.max_response_bytes)
            .context("encrypted DNS byte limit is not representable")?;
        config.max_records = usize::from(self.max_records);
        config.max_cname_depth = usize::from(self.max_cname_depth);
        Ok(config)
    }
}

fn policies(
    config: &HttpsResolverConfig,
    lists: SharedEgressLists,
) -> (Arc<EgressPolicy>, Arc<EgressPolicy>) {
    let mut answers = EgressPolicy::default().with_lists(lists);
    // Only explicit deployment allowlist ranges can exempt private addresses. The run's
    // checked resolution still applies its independent authorization and egress policy.
    answers.deployment_exempt = true;
    let endpoint = answers.clone().with_seed_port(&config.endpoint);
    (Arc::new(endpoint), Arc::new(answers))
}

/// Validate the exact deployment settings and endpoint policy without opening sockets.
pub(crate) fn check(loaded: &Loaded) -> anyhow::Result<()> {
    let Some(settings) = &loaded.config.fetch.resolver_https else {
        return Ok(());
    };
    let config = settings.config()?;
    let lists = egress_source(loaded)?.load_blocking()?;
    let (endpoint, _) = policies(&config, SharedEgressLists::new(lists));
    config.validate(&endpoint).context("encrypted DNS configuration")
}

/// Load only encrypted DNS environment overrides; unrelated command settings remain untouched.
pub(crate) fn from_env(
    getenv: &dyn Fn(&str) -> Option<String>,
    lists: SharedEgressLists,
    cancel: CancellationToken,
) -> anyhow::Result<Option<Arc<HttpsResolver>>> {
    let vars = ENV
        .iter()
        .filter_map(|name| getenv(name).map(|value| ((*name).to_owned(), value)))
        .collect::<Vec<_>>();
    let file = getenv(CONFIG_ENV)
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from);
    let Some(settings) = load_from(file.as_deref(), &vars)?.config.fetch.resolver_https else {
        return Ok(None);
    };
    let config = settings.config()?;
    let (endpoint, answers) = policies(&config, lists);
    HttpsResolver::new(config, endpoint, answers, cancel)
        .map(Arc::new)
        .map(Some)
        .context("encrypted DNS configuration")
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::config_check::{validate, Source};
    use crawlx_fetch::Resolver;

    fn empty_lists() -> SharedEgressLists {
        SharedEgressLists::new(crawlx_policy::EgressLists::default())
    }

    #[tokio::test]
    async fn file_and_environment_select_real_adapter_and_keep_tenant_override_disabled() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("operator.toml");
        std::fs::write(&file, "[fetch.resolver_https]\nendpoint='https://resolver.test/dns-query'\nbootstrap_pins=['93.184.216.34']\ndeadline_ms=4000\n").unwrap();
        let variables = vec![
            (CONFIG_ENV.to_owned(), file.display().to_string()),
            (ENV[2].to_owned(), "2500".to_owned()),
            (ENV[3].to_owned(), "4096".to_owned()),
        ];
        let getenv = |name: &str| {
            variables
                .iter()
                .find(|(key, _)| key == name)
                .map(|(_, value)| value.clone())
        };
        let loaded = load_from(Some(&file), &variables).unwrap();
        let settings = loaded.config.fetch.resolver_https.as_ref().unwrap();
        assert_eq!(settings.deadline_ms, 2500);
        assert_eq!(settings.max_response_bytes, 4096);
        assert_eq!(loaded.sources["fetch.resolver_https.deadline_ms"], Source::Env);
        assert!(!validate(&loaded)
            .0
            .iter()
            .any(|finding| finding.key == "fetch.resolver_https"));
        let resolver = from_env(&getenv, empty_lists(), CancellationToken::new())
            .unwrap()
            .unwrap();
        let expected: Arc<dyn Resolver> = resolver.clone();
        let egress = crawlx_worker::EgressConfig {
            resolver_https: Some(resolver),
            ..crawlx_worker::EgressConfig::default()
        };
        let mut request = crawlx_core::CreateCrawl::new("https://owned.test/".parse().unwrap());
        request.fetch.resolvers = vec!["not-an-address".to_owned()];
        let selected = egress.resolver_for(&request).unwrap();
        assert!(Arc::ptr_eq(&selected, &expected));
        // A literal exercises the selected adapter without external traffic.
        assert!(matches!(
            selected.resolve("127.0.0.1").await,
            Err(crawlx_fetch::FetchError::EgressDenied(_))
        ));
    }

    #[test]
    fn runtime_and_config_check_reject_missing_pins_http_and_unbounded_limits() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("operator.toml");
        std::fs::write(&file, "environment='dev'\n").unwrap();
        for override_value in [
            (ENV[0], "http://resolver.test/dns-query"),
            (
                ENV[0],
                "https://resolver.test/dns-query?key=operator-dns-secret-canary",
            ),
            (ENV[1], "[]"),
            (ENV[1], "['169.254.169.254']"),
            (ENV[2], "0"),
            (ENV[2], "60001"),
            (ENV[3], "65536"),
            (ENV[4], "1025"),
            (ENV[5], "17"),
        ] {
            let mut variables = vec![
                (CONFIG_ENV.to_owned(), file.display().to_string()),
                (ENV[0].to_owned(), "https://resolver.test/dns-query".to_owned()),
                (ENV[1].to_owned(), "['93.184.216.34']".to_owned()),
            ];
            variables.retain(|(name, _)| name != override_value.0);
            variables.push((override_value.0.to_owned(), override_value.1.to_owned()));
            let lookup = |name: &str| {
                variables
                    .iter()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.clone())
            };
            let loaded = load_from(Some(&file), &variables).unwrap();
            let findings = validate(&loaded).0;
            assert!(findings
                .iter()
                .any(|finding| finding.error && finding.key == "fetch.resolver_https"));
            assert!(!format!("{findings:?}").contains("operator-dns-secret-canary"));
            let error = from_env(&lookup, empty_lists(), CancellationToken::new()).unwrap_err();
            assert!(!format!("{error:#}").contains("operator-dns-secret-canary"));
            assert!(!format!("{error:?}").contains("operator-dns-secret-canary"));
        }
        let variables = [(ENV[0].to_owned(), "https://resolver.test/dns-query".to_owned())];
        let loaded = load_from(Some(&file), &variables).unwrap();
        assert!(check(&loaded).is_err());
        std::fs::write(&file, "[fetch.resolver_https]\n").unwrap();
        let loaded = load_from(Some(&file), &[]).unwrap();
        assert!(check(&loaded).is_err());
        let lookup = |name: &str| (name == CONFIG_ENV).then(|| file.display().to_string());
        assert!(from_env(&lookup, empty_lists(), CancellationToken::new()).is_err());
    }

    #[test]
    fn disabled_settings_stay_disabled_and_endpoint_output_is_redacted() {
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("operator.toml");
        std::fs::write(&file, "").unwrap();
        let lookup = |name: &str| (name == CONFIG_ENV).then(|| file.display().to_string());
        assert!(from_env(&lookup, empty_lists(), CancellationToken::new())
            .unwrap()
            .is_none());
        let loaded = load_from(
            Some(&file),
            &[(
                ENV[0].to_owned(),
                "https://secret-user:secret-password@resolver.test/dns-query?secret-token".to_owned(),
            )],
        )
        .unwrap();
        let output = serde_json::to_string(&loaded.config).unwrap();
        assert!(!output.contains("secret-"));
        assert!(!format!("{:?}", loaded.config).contains("secret-"));
        assert!(check(&loaded).is_err());
    }

    #[tokio::test]
    async fn deployed_adapter_observes_live_endpoint_blocklist_before_connecting() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("operator.toml");
        std::fs::write(
            &file,
            format!(
                "[fetch.resolver_https]\nendpoint='https://resolver.test:{port}/dns-query'\n\
             bootstrap_pins=['127.0.0.1']\n\
             [egress]\ndeployment_allowlist=['127.0.0.1/32']\n"
            ),
        )
        .unwrap();
        let loaded = load_from(Some(&file), &[]).unwrap();
        assert!(check(&loaded).is_ok());
        let lists = SharedEgressLists::new(egress_source(&loaded).unwrap().load_blocking().unwrap());
        let lookup = |name: &str| (name == CONFIG_ENV).then(|| file.display().to_string());
        let resolver = from_env(&lookup, lists.clone(), CancellationToken::new())
            .unwrap()
            .unwrap();
        lists.replace(
            crawlx_policy::EgressLists::new(Some(vec!["127.0.0.1/32".parse().unwrap()]), ["resolver.test"])
                .unwrap(),
        );
        assert!(matches!(
            resolver.resolve("owned.test").await,
            Err(crawlx_fetch::FetchError::EgressDenied(_))
        ));
    }
}
