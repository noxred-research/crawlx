//! ProxyX pool gateway configuration: `[fetch.proxyx]`, its flags and environment variables.
//!
//! ```toml
//! [fetch.proxyx]
//! gateway_url = "http://pool-gateway.internal:8080"   # CONNECT listener
//! control_url = "http://pool-gateway.internal:8081"   # optional: block-signal feedback
//! org_key     = "env://PROXYX_POOL_ORG_KEY"           # env://NAME, file:///path or the key itself
//!
//! [fetch.proxyx.basic]        # a table (even an empty one) routes the basic tier through the pool
//! kind = "rotating"
//! country = "fr"
//!
//! [fetch.proxyx.enhanced]
//! kind = "static"
//! ```
//!
//! Precedence per field: flag, then environment, then file. A tier is routed through the pool
//! when its selector is present; it must not also have a plain proxy URL. The org key and the
//! gateway are shared by both tiers. Debug and serialized output show `<redacted>` for the key
//! and the URLs.

use crate::config_check::{proxy_url_arg, ProxyUrl};
use anyhow::{anyhow, bail, Context as _};
use clap::Args;
use crawlx_core::secret::SecretOr;
use crawlx_fetch::proxyx::{PoolSelector, ProxyxRoute};
use crawlx_fetch::ProxyRoutes;
use serde::{Deserialize, Serialize};
use std::io::Read as _;
use std::path::Path;

/// Environment variable overriding `fetch.proxyx.gateway_url`.
pub const GATEWAY_URL_ENV: &str = "CRAWLX_FETCH_PROXYX_GATEWAY_URL";
/// Environment variable overriding `fetch.proxyx.control_url`.
pub const CONTROL_URL_ENV: &str = "CRAWLX_FETCH_PROXYX_CONTROL_URL";
/// Environment variable overriding `fetch.proxyx.org_key`.
pub const ORG_KEY_ENV: &str = "CRAWLX_FETCH_PROXYX_ORG_KEY";
/// Environment variable overriding `fetch.proxyx.basic` with the compact selector form
/// (`kind=rotating,cc=fr`); the empty value selects the pool with the org's policy.
pub const BASIC_ENV: &str = "CRAWLX_FETCH_PROXYX_BASIC";
/// Environment variable overriding `fetch.proxyx.enhanced`, like [`BASIC_ENV`].
pub const ENHANCED_ENV: &str = "CRAWLX_FETCH_PROXYX_ENHANCED";
/// The flat variables, with the configuration key each overrides (the selectors are not plain
/// keys and are read by [`apply`]).
pub(crate) const FLAT_KEY_ENV: &[(&str, &str)] = &[
    (GATEWAY_URL_ENV, "gateway_url"),
    (CONTROL_URL_ENV, "control_url"),
    (ORG_KEY_ENV, "org_key"),
];
/// Variables reported, not rejected, by the strict reader.
pub(crate) const SELECTOR_ENV: &[&str] = &[BASIC_ENV, ENHANCED_ENV];

/// Every variable [`crate::config_check::ProxyArgs::routes`] reads into the configuration: the
/// flat keys and the nested `CRAWLX_FETCH__PROXYX__<KEY>` forms, selector tables included.
pub(crate) fn env_names() -> Vec<String> {
    let mut names: Vec<String> = FLAT_KEY_ENV.iter().map(|(name, _)| (*name).to_owned()).collect();
    for key in ["GATEWAY_URL", "CONTROL_URL", "ORG_KEY"] {
        names.push(format!("CRAWLX_FETCH__PROXYX__{key}"));
    }
    for tier in ["BASIC", "ENHANCED"] {
        for field in ["KIND", "COUNTRY", "CITY", "PROVIDER", "TTL", "ROTATION"] {
            names.push(format!("CRAWLX_FETCH__PROXYX__{tier}__{field}"));
        }
    }
    names
}

/// Largest file `file://` may name.
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;

/// The org key as configured: the key itself, `env://NAME` or `file:///absolute/path`.
/// Serialization and debug output never expose it.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(transparent)]
pub struct ProxyxKey(String);

impl std::fmt::Debug for ProxyxKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

impl Serialize for ProxyxKey {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str("<redacted>")
    }
}

fn key_arg(value: &str) -> Result<ProxyxKey, std::convert::Infallible> {
    Ok(ProxyxKey(value.to_owned()))
}

impl ProxyxKey {
    /// Check the shape without touching the environment or the file system.
    fn check_shape(&self) -> anyhow::Result<()> {
        let raw = self.0.trim();
        if raw.is_empty() {
            bail!("the org key is empty");
        }
        if let Some((scheme, rest)) = raw.split_once("://") {
            match scheme {
                "env" if !rest.is_empty() => {}
                "file" if rest.starts_with('/') => {}
                "env" | "file" => {
                    bail!("the credential reference is malformed (env://NAME or file:///absolute/path)")
                }
                _ => bail!(
                    "unsupported credential reference scheme; use env:// or file:// (or the key itself)"
                ),
            }
        }
        Ok(())
    }

    /// The key itself: the literal, the environment variable named by `env://NAME` (read through
    /// `getenv`) or the contents of the file named by `file:///path`. A file must be a regular
    /// file of at most 64 KiB that is not world-readable; one trailing newline is dropped.
    fn resolve(&self, getenv: &dyn Fn(&str) -> Option<String>) -> anyhow::Result<SecretOr<String>> {
        self.check_shape()?;
        let raw = self.0.trim();
        let value = if let Some(name) = raw.strip_prefix("env://") {
            getenv(name).ok_or_else(|| {
                anyhow!("the environment variable {name} named by the org key reference is not set")
            })?
        } else if let Some(path) = raw.strip_prefix("file://") {
            read_key_file(Path::new(path))?
        } else {
            raw.to_owned()
        };
        let value = value.trim_end_matches(['\r', '\n']).to_owned();
        if value.is_empty() {
            bail!("the org key resolved to an empty value");
        }
        Ok(SecretOr::secret(value))
    }
}

fn read_key_file(path: &Path) -> anyhow::Result<String> {
    let file = std::fs::File::open(path).with_context(|| format!("reading {}", path.display()))?;
    let meta = file
        .metadata()
        .with_context(|| format!("reading {}", path.display()))?;
    if !meta.is_file() || meta.len() > MAX_KEY_FILE_BYTES {
        bail!("{} must be a regular file of at most 64 KiB", path.display());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if meta.permissions().mode() & 0o004 != 0 {
            bail!("{} is world-readable; restrict its mode", path.display());
        }
    }
    let mut text = String::new();
    file.take(MAX_KEY_FILE_BYTES + 1)
        .read_to_string(&mut text)
        .with_context(|| format!("reading {}", path.display()))?;
    Ok(text)
}

/// `[fetch.proxyx]`.
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug, Default)]
#[serde(deny_unknown_fields, default)]
pub struct Proxyx {
    /// The pool gateway's `CONNECT` listener (`http://host[:8080]`), without credentials.
    pub gateway_url: Option<ProxyUrl>,
    /// The pool's control API (`http://host[:8081]`); enables block-signal feedback.
    pub control_url: Option<ProxyUrl>,
    /// The org key: the key itself, `env://NAME` or `file:///absolute/path`.
    pub org_key: Option<ProxyxKey>,
    /// Route the basic tier through the pool with this selector.
    pub basic: Option<PoolSelector>,
    /// Route the enhanced tier through the pool with this selector.
    pub enhanced: Option<PoolSelector>,
}

/// Flags of the pool route, flattened next to the plain proxy flags.
#[derive(Args, Clone, Debug, Default)]
pub struct ProxyxArgs {
    /// ProxyX pool gateway URL; overrides CRAWLX_FETCH_PROXYX_GATEWAY_URL and [fetch.proxyx].gateway_url.
    #[arg(long, value_name = "URL", value_parser = proxy_url_arg, help_heading = "Deployment")]
    pub fetch_proxyx_gateway_url: Option<ProxyUrl>,
    /// ProxyX control API URL for block feedback; overrides CRAWLX_FETCH_PROXYX_CONTROL_URL.
    #[arg(long, value_name = "URL", value_parser = proxy_url_arg, help_heading = "Deployment")]
    pub fetch_proxyx_control_url: Option<ProxyUrl>,
    /// Reference to the ProxyX org key (env://NAME or file:///path); overrides CRAWLX_FETCH_PROXYX_ORG_KEY.
    /// A reference, never the key: a flag shows in the process list.
    #[arg(long, value_name = "REF", value_parser = key_arg, help_heading = "Deployment")]
    pub fetch_proxyx_org_key_ref: Option<ProxyxKey>,
    /// Route the basic tier through the pool, for example `kind=rotating,cc=fr` (empty: the org's
    /// policy); overrides CRAWLX_FETCH_PROXYX_BASIC and [fetch.proxyx.basic].
    #[arg(long, value_name = "SELECTOR", help_heading = "Deployment")]
    pub fetch_proxyx_basic: Option<String>,
    /// Route the enhanced tier through the pool; like --fetch-proxyx-basic.
    #[arg(long, value_name = "SELECTOR", help_heading = "Deployment")]
    pub fetch_proxyx_enhanced: Option<String>,
}

impl ProxyxArgs {
    /// Fill fields this level left unset from `lower` (a request-file level below the flags).
    pub(crate) fn fill_from(&mut self, lower: Self) {
        let Self {
            fetch_proxyx_gateway_url,
            fetch_proxyx_control_url,
            fetch_proxyx_org_key_ref,
            fetch_proxyx_basic,
            fetch_proxyx_enhanced,
        } = lower;
        for (slot, value) in [
            (&mut self.fetch_proxyx_gateway_url, fetch_proxyx_gateway_url),
            (&mut self.fetch_proxyx_control_url, fetch_proxyx_control_url),
        ] {
            if slot.is_none() {
                *slot = value;
            }
        }
        if self.fetch_proxyx_org_key_ref.is_none() {
            self.fetch_proxyx_org_key_ref = fetch_proxyx_org_key_ref;
        }
        for (slot, value) in [
            (&mut self.fetch_proxyx_basic, fetch_proxyx_basic),
            (&mut self.fetch_proxyx_enhanced, fetch_proxyx_enhanced),
        ] {
            if slot.is_none() {
                *slot = value;
            }
        }
    }
}

/// The selector of one tier: flag, else environment, else the file's table.
fn tier(
    name: &str,
    flag: Option<&str>,
    env: Option<String>,
    file: Option<&PoolSelector>,
) -> anyhow::Result<Option<PoolSelector>> {
    let from_spec = |spec: &str| PoolSelector::from_spec(spec).map_err(|e| anyhow!("{name}: {e}"));
    if let Some(spec) = flag {
        return from_spec(spec).map(Some);
    }
    if let Some(spec) = env {
        return from_spec(&spec).map(Some);
    }
    file.map(|selector| {
        selector.validate().map_err(|e| anyhow!("{name}: {e}"))?;
        Ok(selector.clone())
    })
    .transpose()
}

/// Build the pool routes of `section` under `args` and `getenv`, and install them in `routes`.
///
/// # Errors
/// Fails when a tier is routed through the pool but the gateway or the org key is missing, when
/// a tier also has a plain proxy URL, or when a URL, selector or key is invalid. Errors name the
/// configuration key and never contain a URL or the key.
pub(crate) fn apply(
    section: &Proxyx,
    args: &ProxyxArgs,
    getenv: &dyn Fn(&str) -> Option<String>,
    routes: &mut ProxyRoutes,
) -> anyhow::Result<()> {
    let basic = tier(
        "fetch.proxyx.basic",
        args.fetch_proxyx_basic.as_deref(),
        getenv(BASIC_ENV),
        section.basic.as_ref(),
    )?;
    let enhanced = tier(
        "fetch.proxyx.enhanced",
        args.fetch_proxyx_enhanced.as_deref(),
        getenv(ENHANCED_ENV),
        section.enhanced.as_ref(),
    )?;
    let gateway = args
        .fetch_proxyx_gateway_url
        .as_ref()
        .or(section.gateway_url.as_ref());
    let control = args
        .fetch_proxyx_control_url
        .as_ref()
        .or(section.control_url.as_ref());
    let key = args
        .fetch_proxyx_org_key_ref
        .as_ref()
        .or(section.org_key.as_ref());
    if basic.is_none() && enhanced.is_none() {
        if gateway.is_some() || control.is_some() || key.is_some() {
            bail!(
                "fetch.proxyx sets a gateway, control URL or org key but no tier: \
                 set fetch.proxyx.basic and/or fetch.proxyx.enhanced"
            );
        }
        return Ok(());
    }
    for (selected, plain, tier_name) in [
        (basic.is_some(), routes.basic.is_some(), "basic"),
        (enhanced.is_some(), routes.enhanced.is_some(), "enhanced"),
    ] {
        if selected && plain {
            bail!(
                "fetch.proxyx.{tier_name} and fetch.{tier_name}_proxy_url both route the {tier_name} tier; \
                 configure one"
            );
        }
    }
    let gateway = gateway
        .ok_or_else(|| anyhow!("fetch.proxyx.gateway_url is required when a pool tier is configured"))?
        .parse()
        .context("fetch.proxyx.gateway_url")?;
    let control = control
        .map(ProxyUrl::parse)
        .transpose()
        .context("fetch.proxyx.control_url")?;
    let key = key
        .ok_or_else(|| anyhow!("fetch.proxyx.org_key is required when a pool tier is configured"))?
        .resolve(getenv)
        .context("fetch.proxyx.org_key")?;
    for (selector, slot, name) in [
        (basic, &mut routes.basic_pool, "fetch.proxyx.basic"),
        (enhanced, &mut routes.enhanced_pool, "fetch.proxyx.enhanced"),
    ] {
        if let Some(selector) = selector {
            *slot = Some(
                ProxyxRoute::new(&gateway, control.as_ref(), key.clone(), selector)
                    .map_err(|e| anyhow!("{name}: {e}"))?,
            );
        }
    }
    Ok(())
}

/// Findings of `config check` for `section`, as `(key, message)`; every one is an error. Checks
/// shape only: it reads neither the environment nor files.
pub(crate) fn check(
    section: &Proxyx,
    plain_basic: bool,
    plain_enhanced: bool,
) -> Vec<(&'static str, String)> {
    let mut findings = Vec::new();
    for (key, selector) in [
        ("fetch.proxyx.basic", section.basic.as_ref()),
        ("fetch.proxyx.enhanced", section.enhanced.as_ref()),
    ] {
        if let Some(Err(error)) = selector.map(PoolSelector::validate) {
            findings.push((key, error.to_string()));
        }
    }
    for (key, url) in [
        ("fetch.proxyx.gateway_url", section.gateway_url.as_ref()),
        ("fetch.proxyx.control_url", section.control_url.as_ref()),
    ] {
        if let Some(url) = url {
            match url.parse() {
                Err(error) => findings.push((key, format!("{error:#}"))),
                Ok(parsed) => {
                    if !matches!(parsed.scheme(), "http" | "https")
                        || !parsed.username().is_empty()
                        || parsed.password().is_some()
                    {
                        findings.push((key, "must be an http(s) URL without credentials".to_owned()));
                    }
                }
            }
        }
    }
    if let Some(key) = &section.org_key {
        if let Err(error) = key.check_shape() {
            findings.push(("fetch.proxyx.org_key", error.to_string()));
        }
    }
    let tiers = section.basic.is_some() || section.enhanced.is_some();
    if tiers && section.gateway_url.is_none() {
        findings.push((
            "fetch.proxyx.gateway_url",
            "required when a pool tier is configured".to_owned(),
        ));
    }
    if tiers && section.org_key.is_none() {
        findings.push((
            "fetch.proxyx.org_key",
            "required when a pool tier is configured".to_owned(),
        ));
    }
    if !tiers && (section.gateway_url.is_some() || section.control_url.is_some() || section.org_key.is_some())
    {
        findings.push((
            "fetch.proxyx",
            "a gateway, control URL or org key is set but neither fetch.proxyx.basic nor fetch.proxyx.enhanced".to_owned(),
        ));
    }
    if section.basic.is_some() && plain_basic {
        findings.push((
            "fetch.proxyx.basic",
            "also set fetch.basic_proxy_url; configure one route for the tier".to_owned(),
        ));
    }
    if section.enhanced.is_some() && plain_enhanced {
        findings.push((
            "fetch.proxyx.enhanced",
            "also set fetch.enhanced_proxy_url; configure one route for the tier".to_owned(),
        ));
    }
    findings
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    const KEY: &str = "ak_secret-key-value_0123456789abcdefghijklmnopqrstuv";

    fn env<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |name| {
            pairs
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| (*v).to_owned())
        }
    }

    fn section(toml: &str) -> Proxyx {
        toml::from_str(toml).unwrap()
    }

    fn build(
        section: &Proxyx,
        args: &ProxyxArgs,
        getenv: &dyn Fn(&str) -> Option<String>,
    ) -> anyhow::Result<ProxyRoutes> {
        let mut routes = ProxyRoutes::default();
        apply(section, args, getenv, &mut routes)?;
        Ok(routes)
    }

    #[test]
    fn a_table_routes_the_tier_through_the_pool() {
        let s = section(
            "gateway_url = 'http://pool.test'\ncontrol_url = 'http://pool.test'\norg_key = 'env://K'\n\
             [basic]\nkind = 'rotating'\ncountry = 'fr'\n[enhanced]\n",
        );
        let routes = build(&s, &ProxyxArgs::default(), &env(&[("K", KEY)])).unwrap();
        let basic = routes.basic_pool.unwrap();
        assert_eq!(basic.selector().to_string(), "kind=rotating,cc=fr");
        assert_eq!(basic.gateway().as_str(), "http://pool.test:8080/");
        assert_eq!(basic.control().unwrap().as_str(), "http://pool.test:8081/");
        assert_eq!(routes.enhanced_pool.unwrap().selector().to_string(), "");
        assert!(routes.basic.is_none() && routes.enhanced.is_none());
    }

    #[test]
    fn nothing_configured_is_no_pool() {
        let routes = build(&Proxyx::default(), &ProxyxArgs::default(), &env(&[])).unwrap();
        assert!(routes.basic_pool.is_none() && routes.enhanced_pool.is_none());
    }

    #[test]
    fn flag_beats_environment_beats_file_per_field() {
        let s = section(
            "gateway_url = 'http://file.test'\norg_key = 'file-key-0123456789'\n[basic]\ncountry = 'fr'\n",
        );
        let getenv = env(&[(BASIC_ENV, "cc=de"), (ENHANCED_ENV, "kind=static")]);
        let routes = build(&s, &ProxyxArgs::default(), &getenv).unwrap();
        assert_eq!(
            routes.basic_pool.as_ref().unwrap().selector().to_string(),
            "cc=de"
        );
        assert_eq!(
            routes.enhanced_pool.as_ref().unwrap().selector().to_string(),
            "kind=static"
        );
        let args = ProxyxArgs {
            fetch_proxyx_basic: Some("cc=us".to_owned()),
            fetch_proxyx_gateway_url: Some(ProxyUrl("http://flag.test:9000".to_owned())),
            ..ProxyxArgs::default()
        };
        let routes = build(&s, &args, &getenv).unwrap();
        assert_eq!(
            routes.basic_pool.as_ref().unwrap().selector().to_string(),
            "cc=us"
        );
        assert_eq!(
            routes.basic_pool.unwrap().gateway().as_str(),
            "http://flag.test:9000/"
        );
    }

    #[test]
    fn a_tier_cannot_have_two_routes_and_a_pool_needs_its_parts() {
        let mut routes = ProxyRoutes::default();
        routes.basic = Some("http://plain.test:3128".parse().unwrap());
        let s = section("gateway_url = 'http://pool.test'\norg_key = 'k0123456789'\n[basic]\n");
        let error = apply(&s, &ProxyxArgs::default(), &env(&[]), &mut routes).unwrap_err();
        assert!(
            format!("{error:#}").contains("both route the basic tier"),
            "{error:#}"
        );
        let no_gateway = section("org_key = 'k0123456789'\n[basic]\n");
        let error = build(&no_gateway, &ProxyxArgs::default(), &env(&[])).unwrap_err();
        assert!(format!("{error:#}").contains("gateway_url is required"));
        let no_key = section("gateway_url = 'http://pool.test'\n[basic]\n");
        let error = build(&no_key, &ProxyxArgs::default(), &env(&[])).unwrap_err();
        assert!(format!("{error:#}").contains("org_key is required"));
        let orphan = section("gateway_url = 'http://pool.test'\n");
        let error = build(&orphan, &ProxyxArgs::default(), &env(&[])).unwrap_err();
        assert!(format!("{error:#}").contains("no tier"));
    }

    #[test]
    fn invalid_values_fail_without_echoing_secrets() {
        let secret_url = "http://secret-user:secret-pass@secret-host.test";
        for toml in [
            format!("gateway_url = '{secret_url}'\norg_key = 'k0123456789'\n[basic]\n"),
            "gateway_url = 'socks5://secret-host.test'\norg_key = 'k0123456789'\n[basic]\n".to_owned(),
            "gateway_url = 'http://pool.test'\norg_key = 'secret key with spaces'\n[basic]\n".to_owned(),
            "gateway_url = 'http://pool.test'\norg_key = 'vault://secret/path#k'\n[basic]\n".to_owned(),
            "gateway_url = 'http://pool.test'\norg_key = 'k0123456789'\n[basic]\ncountry = 'secret'\n"
                .to_owned(),
        ] {
            let error = format!(
                "{:#}",
                build(&section(&toml), &ProxyxArgs::default(), &env(&[])).unwrap_err()
            );
            for secret in [
                "secret-user",
                "secret-pass",
                "secret-host",
                "secret key",
                "secret/path",
            ] {
                assert!(!error.contains(secret), "{error}");
            }
        }
        let bad_spec = ProxyxArgs {
            fetch_proxyx_basic: Some("cc=secret-value".to_owned()),
            ..ProxyxArgs::default()
        };
        let s = section("gateway_url = 'http://pool.test'\norg_key = 'k0123456789'\n");
        let error = format!("{:#}", build(&s, &bad_spec, &env(&[])).unwrap_err());
        assert!(
            error.contains("fetch.proxyx.basic") && !error.contains("secret-value"),
            "{error}"
        );
    }

    #[test]
    fn debug_and_serialization_redact_key_and_urls() {
        let s = section(&format!(
            "gateway_url = 'http://secret-host.test'\norg_key = '{KEY}'\ncontrol_url = 'http://ctl.test'\n[basic]\n"
        ));
        for output in [
            format!("{s:?}"),
            toml::to_string_pretty(&s).unwrap(),
            serde_json::to_string(&s).unwrap(),
            format!(
                "{:?}",
                ProxyxArgs {
                    fetch_proxyx_org_key_ref: Some(ProxyxKey(KEY.to_owned())),
                    ..ProxyxArgs::default()
                }
            ),
        ] {
            assert!(
                !output.contains(KEY) && !output.contains("secret-host"),
                "{output}"
            );
        }
    }

    #[test]
    fn key_references_resolve_through_env_and_files() {
        let getenv = env(&[("K", KEY), ("EMPTY", "")]);
        let resolve = |raw: &str| ProxyxKey(raw.to_owned()).resolve(&getenv);
        assert_eq!(resolve("env://K").unwrap().expose(), KEY);
        assert_eq!(resolve(KEY).unwrap().expose(), KEY);
        assert!(resolve("env://MISSING").is_err());
        assert!(resolve("env://EMPTY").is_err());
        assert!(resolve("env://").is_err());
        assert!(resolve("").is_err());
        assert!(resolve("vault://kv/pool#key").is_err());
        assert!(resolve("file://relative/key").is_err());

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("org-key");
        std::fs::write(&path, format!("{KEY}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            resolve(&format!("file://{}", path.display())).unwrap().expose(),
            KEY
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let error = format!(
            "{:#}",
            resolve(&format!("file://{}", path.display())).unwrap_err()
        );
        assert!(
            error.contains("world-readable") && !error.contains(KEY),
            "{error}"
        );
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "\n").unwrap();
        std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(resolve(&format!("file://{}", empty.display())).is_err());
        assert!(resolve(&format!("file://{}", dir.path().display())).is_err());
    }

    #[test]
    fn check_reports_shape_problems_by_key() {
        let s = section(
            "gateway_url = 'http://u:p@pool.test'\norg_key = 'vault://x'\n[basic]\ncountry = 'fra'\n",
        );
        let keys: Vec<_> = check(&s, true, false).into_iter().map(|(k, _)| k).collect();
        for expected in [
            "fetch.proxyx.basic",
            "fetch.proxyx.gateway_url",
            "fetch.proxyx.org_key",
        ] {
            assert!(keys.contains(&expected), "{keys:?}");
        }
        assert!(check(&Proxyx::default(), true, true).is_empty());
        let ok =
            section("gateway_url = 'http://pool.test'\norg_key = 'env://K'\n[enhanced]\nkind = 'static'\n");
        assert!(check(&ok, true, false).is_empty());
        assert_eq!(check(&ok, false, true).len(), 1);
    }

    #[test]
    fn unknown_fields_are_rejected() {
        assert!(toml::from_str::<Proxyx>("speed = 'fast'").is_err());
        assert!(toml::from_str::<Proxyx>("[basic]\ncolor = 'red'").is_err());
    }
}
