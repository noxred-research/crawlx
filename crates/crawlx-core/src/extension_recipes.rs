//! Immutable declarative start, parse, item, actor and discovery recipes.
//!
//! Recipes contain proposals only. Compilation never grants action, network, scope,
//! robots, storage or budget authority. Unknown fields and executable inputs fail closed.

use crate::{
    archive_behaviors::{RecipeStepV1, RecipeV1},
    extensions::{json_size, ExtensionError, ExtensionPipelineV1, MAX_EXTENSION_BYTES},
    hash::Digest,
    request::{RequestEnvelopeV1, RequestError, MAX_REQUEST_BATCH},
    scrape::{ScrapeAction, ScrollDirection},
    selectors::SelectorV1,
};
use serde::{Deserialize, Serialize};

/// Maximum ordered discovery rules in one recipe.
pub const MAX_RECIPE_RULES: usize = 32;

mod script;
pub use script::{
    compile_script, ScriptError, MAX_SCRIPT_BYTES, MAX_SCRIPT_DEPTH, MAX_SCRIPT_EVALUATIONS,
    MAX_SCRIPT_REPEAT, MAX_SCRIPT_VALUE, MAX_SCRIPT_VARIABLES,
};

/// A closed actor vocabulary, compiled into existing governed native actions.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub enum ActorActionV1 {
    /// Wait a bounded duration, without expressions or scripts.
    Wait {
        /// Duration charged to the existing action allowance.
        milliseconds: u32,
    },
    /// Click the first freshly resolved CSS target; never an unbounded collection.
    Click {
        /// Static CSS selector, not a browser handle.
        selector: String,
    },
    /// Fill a freshly resolved target through governed native input.
    Fill {
        /// Static CSS selector.
        selector: String,
        /// Sensitive input; never included in debug output or dispositions.
        text: String,
    },
    /// Press one native key through the action journal and safety kernel.
    Press {
        /// Native key name.
        key: String,
    },
    /// Scroll the page or one static target.
    Scroll {
        /// Existing native scroll direction.
        direction: ScrollDirection,
        /// Static CSS target, or the page when absent.
        selector: Option<String>,
    },
    /// Type text into the focused element through governed native input.
    Write {
        /// Sensitive input; never included in debug output or dispositions.
        text: String,
    },
}

impl ActorActionV1 {
    fn native(&self) -> ScrapeAction {
        match self {
            Self::Wait { milliseconds } => ScrapeAction::Wait {
                milliseconds: Some(*milliseconds),
                selector: None,
                state: crate::page_op::SelectorState::Attached,
            },
            Self::Click { selector } => ScrapeAction::Click {
                selector: selector.clone(),
                all: false,
            },
            Self::Fill { selector, text } => ScrapeAction::Fill {
                selector: selector.clone(),
                text: text.clone(),
            },
            Self::Press { key } => ScrapeAction::Press { key: key.clone() },
            Self::Write { text } => ScrapeAction::Write { text: text.clone() },
            Self::Scroll { direction, selector } => ScrapeAction::Scroll {
                direction: *direction,
                selector: selector.clone(),
            },
        }
    }
}

impl std::fmt::Debug for ActorActionV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Wait { .. } => "Wait",
            Self::Click { .. } => "Click",
            Self::Fill { .. } => "Fill",
            Self::Press { .. } => "Press",
            Self::Scroll { .. } => "Scroll",
            Self::Write { .. } => "Write",
        })
    }
}

/// Source for first-match handler selection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecipeSourceV1 {
    /// Links selected from stored HTML.
    Html,
    /// Page locations and optional language alternates from a sitemap.
    Sitemap,
}

/// One immutable discovery rule. List position is execution order.
///
/// All deny predicates are hard denials across every source and rule, even when
/// an earlier allow predicate matches. Selectors restrict HTML occurrences only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct DiscoveryRuleV1 {
    /// HTML or sitemap selection.
    pub source: RecipeSourceV1,
    /// Exact key in the recipe pipeline's routes, never an implicit fallback.
    pub route: String,
    /// Union of bounded CSS/XPath regions; empty selects the whole HTML document.
    #[serde(default)]
    pub selectors: Vec<SelectorV1>,
    /// Absolute-URL regular expressions; empty imposes no allow restriction.
    #[serde(default)]
    pub allow: Vec<String>,
    /// Absolute-URL hard-deny expressions, evaluated before any allow.
    #[serde(default)]
    pub deny: Vec<String>,
    /// Allowed hosts and subdomains; empty imposes no domain restriction.
    #[serde(default)]
    pub allow_domains: Vec<String>,
    /// Hard-denied hosts and subdomains.
    #[serde(default)]
    pub deny_domains: Vec<String>,
    /// Allowed final path extensions, without a dot; empty allows all extensions.
    #[serde(default)]
    pub allow_extensions: Vec<String>,
    /// Hard-denied final path extensions, decoded once and compared case-insensitively.
    #[serde(default)]
    pub deny_extensions: Vec<String>,
}

impl DiscoveryRuleV1 {
    /// Create an unrestricted rule for one source and an exact handler label.
    #[must_use]
    pub fn new(source: RecipeSourceV1, route: String) -> Self {
        Self {
            source,
            route,
            selectors: Vec::new(),
            allow: Vec::new(),
            deny: Vec::new(),
            allow_domains: Vec::new(),
            deny_domains: Vec::new(),
            allow_extensions: Vec::new(),
            deny_extensions: Vec::new(),
        }
    }
}

/// Versioned finite recipe. Runtime compilation takes an owned immutable snapshot.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtensionRecipeV1 {
    /// Contract version, exactly one.
    pub schema_version: u16,
    /// Stable operator-chosen identifier.
    pub id: String,
    /// Immutable configuration revision, greater than zero.
    pub revision: u32,
    /// Complete seed proposals, preserving method and request metadata.
    #[serde(default)]
    pub start_requests: Vec<RequestEnvelopeV1>,
    /// Existing reviewed request, parse and item pipeline.
    pub pipeline: ExtensionPipelineV1,
    /// Finite safe native actor actions; still require ordinary action admission.
    #[serde(default)]
    pub actor_actions: Vec<ActorActionV1>,
    /// Bounded actor script (see [`compile_script`]) that unrolls into the same flat actions;
    /// exclusive with `actor_actions`. It adds no authority: the result passes the same
    /// native allowlist, registry approval and action admission.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor_script: Option<String>,
    /// Discovery rules in stable first-match order.
    #[serde(default)]
    pub rules: Vec<DiscoveryRuleV1>,
    /// Whether nested sitemap references may become source proposals.
    #[serde(default)]
    pub follow_sitemaps: bool,
    /// Whether namespace-checked language alternates become page proposals.
    #[serde(default)]
    pub sitemap_alternates: bool,
    /// Maximum nested sitemap depth; zero permits the root only.
    pub max_sitemap_depth: u16,
    /// Largest stored source document accepted for local evaluation.
    pub max_input_bytes: usize,
    /// Largest serialized proposal batch; overflow rejects the entire batch.
    pub max_output_bytes: usize,
    /// Maximum proposals per evaluation, including nested sources and alternates.
    pub max_candidates: usize,
}

impl std::fmt::Debug for ExtensionRecipeV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtensionRecipeV1")
            .field("id", &self.id)
            .field("revision", &self.revision)
            .field("start_count", &self.start_requests.len())
            .field("action_count", &self.actor_actions.len())
            .field("scripted", &self.actor_script.is_some())
            .field("rule_count", &self.rules.len())
            .finish_non_exhaustive()
    }
}

impl ExtensionRecipeV1 {
    /// Create a finite recipe using the existing default document handler.
    #[must_use]
    pub fn new(id: String, revision: u32) -> Self {
        Self {
            schema_version: 1,
            id,
            revision,
            start_requests: Vec::new(),
            pipeline: ExtensionPipelineV1::default(),
            actor_actions: Vec::new(),
            actor_script: None,
            rules: Vec::new(),
            follow_sitemaps: false,
            sitemap_alternates: false,
            max_sitemap_depth: 5,
            max_input_bytes: MAX_EXTENSION_BYTES,
            max_output_bytes: MAX_EXTENSION_BYTES,
            max_candidates: MAX_REQUEST_BATCH,
        }
    }

    /// Validate finite shape, exact handlers and the native action allowlist.
    ///
    /// # Errors
    /// Rejects unknown versions, unsafe actions, invalid requests and excess bounds.
    pub fn validate(&self) -> Result<(), ExtensionRecipeError> {
        if self.schema_version != 1
            || !crate::request::safe_id(&self.id)
            || self.revision == 0
            || self.rules.len() > MAX_RECIPE_RULES
            || self.actor_actions.len() > crate::archive_behaviors::MAX_RECIPE_STEPS
            || self.start_requests.len() > self.max_candidates
            || !(1..=MAX_REQUEST_BATCH).contains(&self.max_candidates)
            || !(1..=MAX_EXTENSION_BYTES).contains(&self.max_input_bytes)
            || !(1..=MAX_EXTENSION_BYTES).contains(&self.max_output_bytes)
            || self.max_sitemap_depth > 16
        {
            return Err(ExtensionRecipeError::Invalid);
        }
        self.pipeline.validate()?;
        if self.follow_sitemaps
            && self.pipeline.routes.get("default") != Some(&crate::extensions::HandlerV1::DocumentItem)
        {
            return Err(ExtensionRecipeError::Handler);
        }
        for request in &self.start_requests {
            request.validate()?;
            if !matches!(request.method.as_str(), "GET" | "HEAD")
                || request.body.is_some()
                || !matches!(request.url.url.scheme(), "http" | "https")
                || !request.url.url.username().is_empty()
                || request.url.url.password().is_some()
            {
                return Err(ExtensionRecipeError::Invalid);
            }
            if !self.pipeline.routes.contains_key(&request.route) {
                return Err(ExtensionRecipeError::Handler);
            }
        }
        for rule in &self.rules {
            if !self.pipeline.routes.contains_key(&rule.route)
                || rule.selectors.len() > 64
                || (rule.source == RecipeSourceV1::Sitemap && !rule.selectors.is_empty())
                || rule
                    .selectors
                    .iter()
                    .any(|s| s.expression().is_empty() || s.expression().len() > 4096)
            {
                return Err(ExtensionRecipeError::Handler);
            }
            for list in [
                &rule.allow,
                &rule.deny,
                &rule.allow_domains,
                &rule.deny_domains,
                &rule.allow_extensions,
                &rule.deny_extensions,
            ] {
                if list.len() > 64 || list.iter().any(|s| s.is_empty() || s.len() > 512) {
                    return Err(ExtensionRecipeError::Invalid);
                }
            }
            if rule
                .allow_extensions
                .iter()
                .chain(&rule.deny_extensions)
                .any(|s| s.len() > 32 || !s.bytes().all(|b| b.is_ascii_alphanumeric()))
            {
                return Err(ExtensionRecipeError::Invalid);
            }
        }
        self.compile_actor()?;
        if json_size(self)? > MAX_EXTENSION_BYTES {
            return Err(ExtensionRecipeError::Limit);
        }
        Ok(())
    }

    /// Compile into the existing finite native action recipe, not another executor. A bounded
    /// `actor_script` is unrolled here, before any run exists, into the same flat action list.
    ///
    /// # Errors
    /// Rejects unsafe actions, excessive action counts and unbounded waits or text, a script
    /// that does not compile (loops over their cap, `EVAL`, unbound variables) and a recipe
    /// that holds both `actor_actions` and `actor_script`.
    pub fn compile_actor(&self) -> Result<RecipeV1, ExtensionRecipeError> {
        let scripted;
        let actions: &[ActorActionV1] = match &self.actor_script {
            Some(source) => {
                if !self.actor_actions.is_empty() {
                    return Err(ExtensionRecipeError::Invalid);
                }
                scripted = compile_script(source)?;
                &scripted
            }
            None => &self.actor_actions,
        };
        if actions.len() > crate::archive_behaviors::MAX_RECIPE_STEPS {
            return Err(ExtensionRecipeError::Limit);
        }
        let mut recipe = RecipeV1::new(self.id.clone(), self.revision);
        for (index, action) in actions.iter().enumerate() {
            let index = u32::try_from(index).map_err(|_| ExtensionRecipeError::Limit)?;
            recipe.steps.push(RecipeStepV1::new(index, action.native()));
        }
        recipe.validate()?;
        Ok(recipe)
    }

    /// Compute the configuration pin after validation, including rule list order.
    ///
    /// # Errors
    /// Rejects invalid recipes and serialization failures.
    pub fn pin(&self) -> Result<ExtensionRecipePinV1, ExtensionRecipeError> {
        self.validate()?;
        Ok(ExtensionRecipePinV1 {
            id: self.id.clone(),
            revision: self.revision,
            digest: Digest::of_value("crawlx/extension-recipe/v1", self)?,
        })
    }
}

/// Exact immutable configuration identity, suitable for run/checkpoint binding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct ExtensionRecipePinV1 {
    /// Stable recipe identifier.
    pub id: String,
    /// Immutable revision.
    pub revision: u32,
    /// Digest of all typed configuration, including ordered rules and actor actions.
    pub digest: Digest,
}

/// Value-free recipe failure; underlying errors remain available through `source()`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ExtensionRecipeError {
    /// Invalid schema version, configuration or finite bound.
    #[error("invalid extension recipe")]
    Invalid,
    /// Exact handler label is absent or selector source is incompatible.
    #[error("invalid recipe handler or selector source")]
    Handler,
    /// Input, output or candidate ceiling exceeded.
    #[error("extension recipe limit exceeded")]
    Limit,
    /// Request schema failed.
    #[error("invalid recipe request")]
    Request(#[from] RequestError),
    /// Existing extension validation or transformation failed.
    #[error("recipe pipeline failed")]
    Extension(#[from] ExtensionError),
    /// Existing actor action allowlist rejected the compiled proposal.
    #[error("recipe action denied")]
    Action(#[from] crate::archive_behaviors::RecipeError),
    /// Configuration serialization failed.
    #[error("recipe serialization failed")]
    Serialization(#[from] serde_json::Error),
    /// Canonical digest serialization failed.
    #[error("recipe canonical serialization failed")]
    CanonicalSerialization(#[from] ciborium::ser::Error<std::io::Error>),
    /// Exact immutable revision was changed or the digest did not match.
    #[error("recipe configuration pin mismatch")]
    Pin,
    /// Run cancellation won before completion; no partial result is returned.
    #[error("recipe cancelled")]
    Cancelled,
    /// The bounded actor script did not compile.
    #[error("recipe actor script refused")]
    Script(#[from] ScriptError),
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn rejects_unknown_schema_and_raw_action_vocabulary() {
        let mut recipe = ExtensionRecipeV1::new("fixture".into(), 1);
        recipe.schema_version = 2;
        assert!(recipe.validate().is_err());
        for action in [
            serde_json::json!({"type":"executeJavascript","script":"fetch('/')"}),
            serde_json::json!({"type":"click","selector":"a","callback":"code"}),
            serde_json::json!({"type":"click","selector":"a","all":true}),
            serde_json::json!({"type":"eval","source":"code"}),
            serde_json::json!({"type":"fill","selector":"input","text":"x","handle":"raw"}),
        ] {
            assert!(serde_json::from_value::<ActorActionV1>(action).is_err());
        }
        let mut value = serde_json::to_value(ExtensionRecipeV1::new("fixture".into(), 1)).unwrap();
        value["callback"] = serde_json::json!("not executable");
        assert!(serde_json::from_value::<ExtensionRecipeV1>(value).is_err());
    }

    #[test]
    fn action_bounds_and_exact_handlers_fail_closed() {
        let mut recipe = ExtensionRecipeV1::new("fixture".into(), 1);
        recipe.actor_actions.push(ActorActionV1::Wait {
            milliseconds: u32::MAX,
        });
        assert!(recipe.validate().is_err());
        recipe.actor_actions.clear();
        recipe.pipeline.default_handler = Some(crate::extensions::HandlerV1::DocumentItem);
        recipe
            .rules
            .push(DiscoveryRuleV1::new(RecipeSourceV1::Html, "unknown".into()));
        assert!(matches!(recipe.validate(), Err(ExtensionRecipeError::Handler)));
    }

    #[test]
    fn native_compilation_and_pin_cover_exact_actions_and_rule_order() {
        let mut recipe = ExtensionRecipeV1::new("fixture".into(), 7);
        recipe.actor_actions.push(ActorActionV1::Click {
            selector: "a.next".into(),
        });
        let compiled = recipe.compile_actor().unwrap();
        assert!(matches!(
            &compiled.steps[0].action,
            ScrapeAction::Click { all: false, .. }
        ));
        let first = recipe.pin().unwrap();
        recipe.actor_actions.push(ActorActionV1::Fill {
            selector: "input".into(),
            text: "private-fixture".into(),
        });
        assert_ne!(first.digest, recipe.pin().unwrap().digest);
        assert!(!format!("{recipe:?}").contains("private-fixture"));
        let mut a = DiscoveryRuleV1::new(RecipeSourceV1::Html, "default".into());
        a.allow.push("/first".into());
        recipe.rules.push(a);
        recipe
            .rules
            .push(DiscoveryRuleV1::new(RecipeSourceV1::Sitemap, "default".into()));
        let ordered = recipe.pin().unwrap();
        recipe.rules.reverse();
        assert_ne!(ordered.digest, recipe.pin().unwrap().digest);
    }

    #[test]
    fn scripts_compile_before_any_run_and_keep_the_native_allowlist() {
        let mut recipe = ExtensionRecipeV1::new("scripted".into(), 1);
        recipe.actor_script = Some(
            "LET name = \"fixture\"\nREPEAT 2 AS n\nCLICK `li:nth-child(${n})`\nFILL `input` \"${name}\"\nEND\nTYPE \"done\"\nPRESS Enter"
                .into(),
        );
        recipe.validate().unwrap();
        let compiled = recipe.compile_actor().unwrap();
        let kinds: Vec<&str> = compiled.steps.iter().map(|s| s.action.name()).collect();
        assert_eq!(kinds, ["click", "fill", "click", "fill", "write", "press"]);
        assert!(compiled
            .steps
            .windows(2)
            .all(|pair| pair[0].source_index < pair[1].source_index));
        let first = recipe.pin().unwrap();
        assert_eq!(first, recipe.pin().unwrap(), "the pin is stable");
        assert!(!format!("{recipe:?}").contains("li:nth-child"));
        recipe.actor_script = recipe.actor_script.take().map(|s| s.replace("fixture", "other"));
        assert_ne!(first.digest, recipe.pin().unwrap().digest);
        let wire = serde_json::to_value(&recipe).unwrap();
        assert!(wire["actorScript"].is_string());
        assert_eq!(serde_json::from_value::<ExtensionRecipeV1>(wire).unwrap(), recipe);
        let plain = serde_json::to_value(ExtensionRecipeV1::new("plain".into(), 1)).unwrap();
        assert!(plain.get("actorScript").is_none(), "existing pins do not change");
    }

    #[test]
    fn refused_scripts_fail_validation_and_cannot_mix_with_actions() {
        let mut recipe = ExtensionRecipeV1::new("scripted".into(), 1);
        for source in [
            "EVAL `window.name`",
            "REPEAT 21\nCLICK `a`\nEND",
            "REPEAT 20\nREPEAT 3\nCLICK `a`\nEND\nEND",
            "SET `input` \"x\"",
            "WAIT 60000\nWAIT 1",
        ] {
            recipe.actor_script = Some(source.into());
            assert!(recipe.validate().is_err(), "{source}");
            assert!(recipe.pin().is_err(), "{source}");
        }
        recipe.actor_script = Some("EVAL `x`".into());
        assert!(matches!(
            recipe.validate(),
            Err(ExtensionRecipeError::Script(ScriptError::Eval { line: 1 }))
        ));
        recipe.actor_script = Some("CLICK `a`".into());
        recipe
            .actor_actions
            .push(ActorActionV1::Click { selector: "b".into() });
        assert!(matches!(recipe.validate(), Err(ExtensionRecipeError::Invalid)));
    }
}
