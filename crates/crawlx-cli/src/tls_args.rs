//! URL-engine synthetic TLS randomization flags.

use clap::Args;
use crawlx_core::config::Fetch;
use crawlx_core::tls::TlsImpersonation;

/// Opt-in synthetic ClientHello randomization; never browser impersonation.
#[derive(Args, Debug, Clone, Default)]
pub struct TlsArgs {
    /// Randomize URL-only TLS ClientHello profiles using --seed; not browser fingerprints.
    #[arg(
        long,
        visible_alias = "tlsi",
        env = "CRAWLX_TLS_IMPERSONATE",
        action = clap::ArgAction::Set,
        num_args = 0..=1,
        require_equals = true,
        default_missing_value = "true",
        value_name = "BOOL",
        help_heading = "Fetch"
    )]
    pub tls_impersonate: Option<bool>,
}

impl TlsArgs {
    /// Fill an absent flag from a lower-priority configuration layer.
    pub(crate) fn fill_from(&mut self, lower: Self) {
        crate::merge::fill(&mut self.tls_impersonate, lower.tls_impersonate);
    }

    /// Apply an explicit on/off choice without changing certificate verification.
    pub(crate) fn apply(&self, fetch: &mut Fetch) {
        if let Some(enabled) = self.tls_impersonate {
            fetch.tls_impersonation = if enabled {
                TlsImpersonation::Randomized
            } else {
                TlsImpersonation::Off
            };
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use clap::{FromArgMatches as _, Parser as _};

    fn parsed(values: &[&str]) -> crate::CrawlArgs {
        let mut argv = vec!["crawlx", "crawl", "https://example.test/", "--mode", "static"];
        argv.extend_from_slice(values);
        let cli = crate::Cli::try_parse_from(crate::normalize_args(argv)).unwrap();
        let crate::Command::Crawl(args) = cli.command else {
            panic!("crawl command");
        };
        *args
    }

    #[test]
    fn all_spellings_enable_randomization_without_disabling_verification() {
        for flag in ["--tls-impersonate", "--tlsi", "-tlsi", "-tls-impersonate"] {
            let request = crate::crawl::build_request(&parsed(&[flag, "--seed", "42"])).unwrap();
            assert_eq!(request.fetch.tls_impersonation, TlsImpersonation::Randomized);
            assert_eq!(request.seed, Some(42));
            assert!(!request.fetch.skip_tls_verification);
            assert_eq!(
                serde_json::to_value(request.redacted()).unwrap()["fetch"]["tlsImpersonation"],
                "randomized"
            );
        }
    }

    #[test]
    fn defaults_off_and_rejects_unknown_flag_values() {
        let request = crate::crawl::build_request(&parsed(&[])).unwrap();
        assert_eq!(request.fetch.tls_impersonation, TlsImpersonation::Off);
        assert!(crate::Cli::try_parse_from([
            "crawlx",
            "crawl",
            "https://example.test/",
            "--tls-impersonate=chrome"
        ])
        .is_err());
    }

    #[test]
    fn explicit_false_beats_lower_priority_flags() {
        let mut args = TlsArgs {
            tls_impersonate: Some(false),
        };
        args.fill_from(TlsArgs {
            tls_impersonate: Some(true),
        });
        let mut fetch = Fetch {
            tls_impersonation: TlsImpersonation::Randomized,
            ..Default::default()
        };
        args.apply(&mut fetch);
        assert_eq!(fetch.tls_impersonation, TlsImpersonation::Off);
    }

    #[test]
    fn flag_has_boolean_environment_binding() {
        let command = TlsArgs::augment_args(clap::Command::new("tls"));
        let arg = command
            .get_arguments()
            .find(|arg| arg.get_id() == "tls_impersonate")
            .unwrap();
        assert_eq!(
            arg.get_env(),
            Some(std::ffi::OsStr::new("CRAWLX_TLS_IMPERSONATE"))
        );
        let matches = command
            .try_get_matches_from(["tls", "--tls-impersonate=false"])
            .unwrap();
        let args = TlsArgs::from_arg_matches(&matches).unwrap();
        assert_eq!(args.tls_impersonate, Some(false));
    }

    #[test]
    fn environment_values_and_cli_precedence_are_isolated() {
        const EXPECTED: &str = "CRAWLX_TLS_TEST_EXPECTED";
        if let Ok(expected) = std::env::var(EXPECTED) {
            let flags = if expected == "override" {
                vec!["--tls-impersonate=false"]
            } else {
                Vec::new()
            };
            let request = crate::crawl::build_request(&parsed(&flags)).unwrap();
            let mode = if expected == "randomized" {
                TlsImpersonation::Randomized
            } else {
                TlsImpersonation::Off
            };
            assert_eq!(request.fetch.tls_impersonation, mode);
            return;
        }
        for (value, expected) in [("true", "randomized"), ("false", "off"), ("true", "override")] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tls_args::tests::environment_values_and_cli_precedence_are_isolated",
                ])
                .env("CRAWLX_TLS_IMPERSONATE", value)
                .env(EXPECTED, expected)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn browser_modes_are_rejected_by_request_validation() {
        for mode in ["dynamic", "hybrid"] {
            let cli = crate::Cli::try_parse_from([
                "crawlx",
                "crawl",
                "https://example.test/",
                "--mode",
                mode,
                "--tls-impersonate",
            ])
            .unwrap();
            let crate::Command::Crawl(args) = cli.command else {
                panic!("crawl command");
            };
            let mut request = crate::crawl::build_request(&args).unwrap();
            assert!(request.normalize().unwrap_err().iter().any(|error| matches!(
                error,
                crawlx_core::CoreError::Conflict {
                    a: "fetch.tlsImpersonation",
                    ..
                }
            )));
        }
    }

    #[test]
    fn config_body_is_typed_and_cli_choice_wins() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tls.json");
        std::fs::write(
            &path,
            r#"{"mode":"static","fetch":{"tlsImpersonation":"randomized"}}"#,
        )
        .unwrap();
        let args = parsed(&["--config", path.to_str().unwrap(), "--tls-impersonate=false"]);
        let request = crate::crawl::build_request(&args).unwrap();
        assert_eq!(request.fetch.tls_impersonation, TlsImpersonation::Off);
        std::fs::write(&path, r#"{"fetch":{"tlsImpersonation":"chrome"}}"#).unwrap();
        assert!(crate::crawl::build_request(&args).is_err());
    }

    #[test]
    fn yaml_long_name_and_alias_are_recognized() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tls.yaml");
        for key in ["tls-impersonate", "tlsi"] {
            std::fs::write(&path, format!("{key}: true\n")).unwrap();
            let args = parsed(&["--config", path.to_str().unwrap()]);
            let request = crate::crawl::build_request(&args).unwrap();
            assert_eq!(request.fetch.tls_impersonation, TlsImpersonation::Randomized);
        }
    }
}
