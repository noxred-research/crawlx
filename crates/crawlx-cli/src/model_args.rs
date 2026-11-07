//! Flags that attach the System 1 model and the LLM planner (`crawl` and `worker`).

use anyhow::{bail, Result};
use clap::{Args, ValueEnum};
use crawlx_core::config::{LlmPlannerMode, StrategyName, System1Mode};
use crawlx_core::CreateCrawl;
use crawlx_worker::{EngineConfig, ModelConfig, PlannerConfig};

/// Per-call time budget of the model and planner endpoints.
const REMOTE_TIMEOUT_MS: u64 = 1500;

/// `--system1-mode`: how much the model may influence selection. `active` is not offered; it is
/// rejected until gate G3 has passed.
#[derive(Clone, Copy, Debug, ValueEnum)]
pub enum System1ModeArg {
    /// The model never runs.
    #[value(name = "off")]
    Off,
    /// The model runs and is recorded in `model_decisions`; selection is unchanged.
    #[value(name = "shadow")]
    Shadow,
    /// The model's confident choice reorders the safe shortlist.
    #[value(name = "advisory")]
    Advisory,
}

impl From<System1ModeArg> for System1Mode {
    fn from(m: System1ModeArg) -> Self {
        match m {
            System1ModeArg::Off => Self::Off,
            System1ModeArg::Shadow => Self::Shadow,
            System1ModeArg::Advisory => Self::Advisory,
        }
    }
}

/// Model-related flags shared by `crawl` and `worker`.
#[derive(Args, Debug, Clone, Default)]
pub struct ModelArgs {
    /// Typed-decision service endpoint for System 1; needs `--system1-mode shadow|advisory`.
    #[arg(long, value_name = "URL")]
    pub model_endpoint: Option<String>,
    /// Environment variable holding the bearer key of `--model-endpoint` (the key is never a flag).
    #[arg(long, value_name = "VAR", requires = "model_endpoint")]
    pub model_api_key_env: Option<String>,
    /// System 1 mode. For `crawl` it overrides the request and lists `system1` among the
    /// strategies; for `worker` it is the most any run may let the model influence selection.
    #[arg(long, value_enum)]
    pub system1_mode: Option<System1ModeArg>,
    /// LLM planner endpoint. For `crawl`, a request that left `dynamic.llmPlanner` off gets
    /// `stalled_only`.
    #[arg(long, value_name = "URL")]
    pub planner_endpoint: Option<String>,
    /// Environment variable holding the bearer key of `--planner-endpoint`.
    #[arg(long, value_name = "VAR", requires = "planner_endpoint")]
    pub planner_api_key_env: Option<String>,
}

impl ModelArgs {
    /// Fill unset flags from `lower` (a `--config` flag layer).
    pub(crate) fn fill_from(&mut self, lower: Self) {
        crate::merge::fill_fields!(
            self,
            lower,
            ModelArgs {
                model_endpoint,
                model_api_key_env,
                system1_mode,
                planner_endpoint,
                planner_api_key_env,
            }
        );
    }

    /// Fold the flags into the request of a `crawl`.
    pub fn apply(&self, crawl: &mut CreateCrawl) {
        if let Some(mode) = self.system1_mode {
            let mode = System1Mode::from(mode);
            crawl.dynamic.system1_mode = mode;
            if mode != System1Mode::Off && !crawl.dynamic.strategies.contains(&StrategyName::System1) {
                crawl.dynamic.strategies.push(StrategyName::System1);
            }
        }
        if self.planner_endpoint.is_some() && crawl.dynamic.llm_planner == LlmPlannerMode::Off {
            crawl.dynamic.llm_planner = LlmPlannerMode::StalledOnly;
        }
    }

    /// The worker-side settings for `ceiling`, the most System 1 may influence selection.
    ///
    /// # Errors
    /// When `--model-endpoint` is given with mode `off`, or a mode other than `off` is asked
    /// for without an endpoint: either is a misconfiguration that would silently do nothing.
    pub fn settings(&self, ceiling: System1Mode) -> Result<(Option<ModelConfig>, Option<PlannerConfig>)> {
        let model = match (&self.model_endpoint, ceiling) {
            (Some(_), System1Mode::Off) => {
                bail!("--model-endpoint needs --system1-mode shadow or advisory (the mode is off)")
            }
            (None, System1Mode::Shadow | System1Mode::Advisory) if self.system1_mode.is_some() => {
                bail!("--system1-mode {ceiling:?} needs --model-endpoint")
            }
            (Some(url), mode) => Some(ModelConfig {
                engine: EngineConfig::DecisionHttp {
                    base_url: url.clone(),
                    api_key_env: self.model_api_key_env.clone(),
                    timeout_ms: REMOTE_TIMEOUT_MS,
                },
                mode,
            }),
            (None, _) => None,
        };
        let planner = self.planner_endpoint.as_ref().map(|url| PlannerConfig {
            base_url: url.clone(),
            api_key_env: self.planner_api_key_env.clone(),
            timeout_ms: REMOTE_TIMEOUT_MS,
        });
        Ok((model, planner))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn crawl() -> CreateCrawl {
        CreateCrawl::new(url::Url::parse("https://example.test/").unwrap())
    }

    #[test]
    fn a_mode_flag_overrides_the_request_and_lists_the_strategy_once() {
        let args = ModelArgs {
            system1_mode: Some(System1ModeArg::Shadow),
            ..ModelArgs::default()
        };
        let mut c = crawl();
        args.apply(&mut c);
        args.apply(&mut c);
        assert_eq!(c.dynamic.system1_mode, System1Mode::Shadow);
        assert_eq!(
            c.dynamic
                .strategies
                .iter()
                .filter(|s| **s == StrategyName::System1)
                .count(),
            1
        );
    }

    #[test]
    fn off_adds_no_strategy_and_the_planner_flag_enables_the_planner() {
        let args = ModelArgs {
            system1_mode: Some(System1ModeArg::Off),
            planner_endpoint: Some("http://planner.test/".to_owned()),
            ..ModelArgs::default()
        };
        let mut c = crawl();
        args.apply(&mut c);
        assert!(!c.dynamic.strategies.contains(&StrategyName::System1));
        assert_eq!(c.dynamic.llm_planner, LlmPlannerMode::StalledOnly);
        // an explicit request value is kept
        let mut c = crawl();
        c.dynamic.llm_planner = LlmPlannerMode::Enabled;
        args.apply(&mut c);
        assert_eq!(c.dynamic.llm_planner, LlmPlannerMode::Enabled);
    }

    #[test]
    fn settings_pair_the_endpoint_with_the_mode() {
        let args = ModelArgs {
            model_endpoint: Some("http://decision.test/".to_owned()),
            model_api_key_env: Some("DECISION_KEY".to_owned()),
            system1_mode: Some(System1ModeArg::Advisory),
            ..ModelArgs::default()
        };
        let (model, planner) = args.settings(System1Mode::Advisory).unwrap();
        let model = model.unwrap();
        assert_eq!(model.mode, System1Mode::Advisory);
        assert_eq!(
            model.engine,
            EngineConfig::DecisionHttp {
                base_url: "http://decision.test/".to_owned(),
                api_key_env: Some("DECISION_KEY".to_owned()),
                timeout_ms: REMOTE_TIMEOUT_MS,
            }
        );
        assert!(planner.is_none());
        assert!(
            args.settings(System1Mode::Off).is_err(),
            "an endpoint with mode off does nothing"
        );
    }

    #[test]
    fn a_mode_without_an_endpoint_is_refused_but_no_flags_is_fine() {
        let args = ModelArgs {
            system1_mode: Some(System1ModeArg::Shadow),
            ..ModelArgs::default()
        };
        assert!(args.settings(System1Mode::Shadow).is_err());
        let (model, planner) = ModelArgs::default().settings(System1Mode::Off).unwrap();
        assert!(model.is_none() && planner.is_none());
        // a request-level mode without an endpoint is the worker's decision: no model, no error
        assert!(ModelArgs::default()
            .settings(System1Mode::Shadow)
            .unwrap()
            .0
            .is_none());
    }
}
