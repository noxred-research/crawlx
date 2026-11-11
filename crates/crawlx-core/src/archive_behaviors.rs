//! Bounded operator-approved declarative browser recipes. No executable sources are accepted.

use crate::{
    hash::Digest,
    scrape::{ScrapeAction, ScreenshotViewport},
};
use serde::{Deserialize, Serialize};

/// Largest canonical recipe, in bytes.
pub const MAX_RECIPE_BYTES: usize = 65_536;
/// Largest recipe step count.
pub const MAX_RECIPE_STEPS: usize = 50;

/// Requested execution timing; initialization hooks are deliberately unsupported.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecipePhaseV1 {
    /// Requires a native initialization capability, not post-navigation input.
    BeforePageScripts,
    /// Initial emulation only; input cannot execute here.
    BeforeInitialNavigation,
    /// Native input after the initial checked navigation.
    PostNavigation,
}

/// Tenant selection of an immutable operator registration, never recipe contents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RecipeReferenceV1 {
    /// Operator-owned stable identifier.
    pub id: String,
    /// Exact immutable recipe revision.
    pub version: u32,
    /// Domain-separated digest of the canonical recipe JSON.
    pub digest: Digest,
    /// Required timing; cannot be silently weakened.
    pub phase: RecipePhaseV1,
}

impl RecipeReferenceV1 {
    /// Construct a reference from an already validated recipe.
    ///
    /// # Errors
    /// Rejects invalid or unbounded recipes.
    pub fn for_recipe(recipe: &RecipeV1) -> Result<Self, RecipeError> {
        Ok(Self {
            id: recipe.id.clone(),
            version: recipe.version,
            digest: recipe.digest()?,
            phase: recipe.phase,
        })
    }

    /// Check the bounded reference vocabulary.
    ///
    /// # Errors
    /// Rejects malformed identifiers, revision zero and unsupported execution phases.
    pub fn validate(&self) -> Result<(), RecipeError> {
        if !valid_id(&self.id) || self.version == 0 {
            return Err(RecipeError::Invalid);
        }
        if self.phase != RecipePhaseV1::PostNavigation {
            return Err(RecipeError::Timing);
        }
        Ok(())
    }
}

/// Secret-free source provenance retained across offline conversion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RecipeSourceV1 {
    /// Digest of the original bounded flow bytes, never their contents.
    pub digest: Digest,
    /// Version of the offline translation contract.
    pub importer_version: u16,
    /// Number of required source steps, including initial navigation and emulation.
    pub step_count: u32,
    /// Source position mapped to the initial checked navigation.
    pub initial_navigation_index: Option<u32>,
    /// Source position mapped to initial viewport emulation, if supplied.
    pub initial_viewport_index: Option<u32>,
}

impl RecipeSourceV1 {
    /// Record the digest of bounded source bytes without retaining their contents.
    #[must_use]
    pub const fn new(digest: Digest) -> Self {
        Self {
            digest,
            importer_version: 1,
            step_count: 0,
            initial_navigation_index: None,
            initial_viewport_index: None,
        }
    }
}

/// One native action, with its position in the recorded source.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RecipeStepV1 {
    /// Original source step position; strictly increasing.
    pub source_index: u32,
    /// Existing native action vocabulary, restricted by recipe validation.
    pub action: ScrapeAction,
}
impl std::fmt::Debug for RecipeStepV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipeStepV1")
            .field("source_index", &self.source_index)
            .field("kind", &self.action.name())
            .finish_non_exhaustive()
    }
}

impl RecipeStepV1 {
    /// Bind a native action to its original source position.
    #[must_use]
    pub const fn new(source_index: u32, action: ScrapeAction) -> Self {
        Self { source_index, action }
    }
}

/// Declarative recipe bytes supplied only through an operator registry.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
#[non_exhaustive]
pub struct RecipeV1 {
    /// Contract version, exactly one.
    pub schema_version: u16,
    /// Stable operator identifier, not an address or executable source.
    pub id: String,
    /// Immutable revision, greater than zero.
    pub version: u32,
    /// Actual input execution phase.
    pub phase: RecipePhaseV1,
    /// Exact initial navigation required by a translated flow, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry_url: Option<url::Url>,
    /// Initial desktop viewport applied before initial navigation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initial_viewport: Option<ScreenshotViewport>,
    /// Optional source provenance; values never enter dispositions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<RecipeSourceV1>,
    /// Bounded, ordered, required native steps. No retries, loops or optional drops.
    pub steps: Vec<RecipeStepV1>,
}

impl std::fmt::Debug for RecipeV1 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RecipeV1")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("phase", &self.phase)
            .field("steps", &self.steps)
            .finish_non_exhaustive()
    }
}

impl RecipeV1 {
    /// Construct an empty native recipe for offline conversion or operator assembly.
    #[must_use]
    pub fn new(id: String, version: u32) -> Self {
        Self {
            schema_version: 1,
            id,
            version,
            phase: RecipePhaseV1::PostNavigation,
            entry_url: None,
            initial_viewport: None,
            source: None,
            steps: Vec::new(),
        }
    }

    /// Check bounds, exact timing and the non-executable action allowlist.
    ///
    /// # Errors
    /// Rejects scripts, captures, collection engines, invalid waits and oversized fields.
    pub fn validate(&self) -> Result<(), RecipeError> {
        if self.schema_version != 1
            || !valid_id(&self.id)
            || self.version == 0
            || self.steps.len() > MAX_RECIPE_STEPS
        {
            return Err(RecipeError::Invalid);
        }
        if self.phase != RecipePhaseV1::PostNavigation {
            return Err(RecipeError::Timing);
        }
        if self.entry_url.as_ref().is_some_and(|url| {
            !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
                || url.as_str().len() > 8_192
        }) {
            return Err(RecipeError::Invalid);
        }
        if self
            .initial_viewport
            .is_some_and(|v| !(1..=8_192).contains(&v.width) || !(1..=8_192).contains(&v.height))
        {
            return Err(RecipeError::Invalid);
        }
        if self
            .source
            .as_ref()
            .is_some_and(|source| source.importer_version != 1)
            || self
                .steps
                .windows(2)
                .any(|pair| pair[0].source_index >= pair[1].source_index)
        {
            return Err(RecipeError::Invalid);
        }
        if let Some(source) = &self.source {
            if source.step_count > 52
                || source.initial_navigation_index.is_none()
                || self.entry_url.is_none()
                || source.initial_viewport_index.is_some() != self.initial_viewport.is_some()
            {
                return Err(RecipeError::Invalid);
            }
            let mut seen = 0_u64;
            for index in self
                .steps
                .iter()
                .map(|step| step.source_index)
                .chain(source.initial_navigation_index)
                .chain(source.initial_viewport_index)
            {
                if index >= source.step_count {
                    return Err(RecipeError::Invalid);
                }
                let bit = 1_u64.checked_shl(index).ok_or(RecipeError::Invalid)?;
                if seen & bit != 0 {
                    return Err(RecipeError::Invalid);
                }
                seen |= bit;
            }
            if seen.count_ones() != source.step_count
                || source
                    .initial_navigation_index
                    .zip(self.steps.first())
                    .is_some_and(|(navigation, step)| navigation >= step.source_index)
                || source
                    .initial_viewport_index
                    .zip(source.initial_navigation_index)
                    .is_some_and(|(viewport, navigation)| viewport >= navigation)
            {
                return Err(RecipeError::Invalid);
            }
        }
        let mut waited = 0_u64;
        for step in &self.steps {
            let bounded = |s: &str| !s.is_empty() && s.len() <= 4_096;
            match &step.action {
                ScrapeAction::Click { selector, all: false } if bounded(selector) => {}
                ScrapeAction::Write { text } if bounded(text) => {}
                ScrapeAction::Fill { selector, text } if bounded(selector) && text.len() <= 4_096 => {}
                ScrapeAction::Press { key } if bounded(key) && key.len() <= 64 => {}
                ScrapeAction::Scroll { selector, .. } if selector.as_deref().is_none_or(bounded) => {}
                ScrapeAction::Wait {
                    milliseconds: Some(ms),
                    selector: None,
                    state,
                } if *state == crate::page_op::SelectorState::Attached => {
                    waited += u64::from(*ms);
                }
                ScrapeAction::Wait {
                    milliseconds: None,
                    selector: Some(selector),
                    ..
                } if bounded(selector) => {}
                _ => return Err(RecipeError::UnsafeStep),
            }
        }
        if waited > u64::from(crate::scrape::MAX_WAIT_MS) {
            return Err(RecipeError::Invalid);
        }
        Ok(())
    }

    /// Digest canonical JSON after validation. Map order is fixed by typed fields.
    ///
    /// # Errors
    /// Rejects invalid recipes, serialization failure and the canonical byte cap.
    pub fn digest(&self) -> Result<Digest, RecipeError> {
        self.validate()?;
        let bytes = serde_json::to_vec(self).map_err(|_| RecipeError::Invalid)?;
        if bytes.len() > MAX_RECIPE_BYTES {
            return Err(RecipeError::Invalid);
        }
        Ok(Digest::of("crawlx/archive-recipe/v1", &bytes))
    }
}

/// A value-free outcome for one required source step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum RecipeStepDispositionV1 {
    /// Step completed through the existing action path.
    Completed,
    /// First failed step; subsequent steps did not run.
    Failed,
    /// Step was in flight when cancellation stopped the run.
    Cancelled,
    /// Step never started because an earlier step failed or cancellation arrived.
    NotRun,
}

/// Stable, value-free recipe refusal.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[non_exhaustive]
pub enum RecipeError {
    /// A schema or bound failed.
    #[error("invalid bounded recipe")]
    Invalid,
    /// Requested initialization timing cannot be honored.
    #[error("unsupported recipe timing")]
    Timing,
    /// Action cannot safely execute as an approved declarative recipe.
    #[error("unsupported or unsafe recipe step")]
    UnsafeStep,
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn pin_changes_with_values_but_debug_never_contains_them() {
        let mut recipe = RecipeV1::new("fixture".into(), 1);
        recipe.steps.push(RecipeStepV1 {
            source_index: 0,
            action: ScrapeAction::Write {
                text: "private-input-marker".into(),
            },
        });
        let pin = recipe.digest().unwrap();
        assert!(!format!("{recipe:?}").contains("private-input-marker"));
        recipe.steps[0].action = ScrapeAction::Write {
            text: "changed".into(),
        };
        assert_ne!(pin, recipe.digest().unwrap());
    }

    #[test]
    fn unsafe_steps_and_initialization_never_validate() {
        let mut recipe = RecipeV1::new("fixture".into(), 1);
        recipe.steps.push(RecipeStepV1 {
            source_index: 0,
            action: ScrapeAction::ExecuteJavascript {
                script: "private-script".into(),
            },
        });
        assert_eq!(recipe.validate(), Err(RecipeError::UnsafeStep));
        recipe.steps.clear();
        recipe.phase = RecipePhaseV1::BeforePageScripts;
        assert_eq!(recipe.validate(), Err(RecipeError::Timing));
    }

    #[test]
    fn zero_data_retention_refuses_content_bearing_recipe_provenance_at_admission() {
        let recipe = RecipeV1::new("fixture".into(), 1);
        let options = crate::scrape::ScrapeOptions {
            archive_behavior: Some(RecipeReferenceV1::for_recipe(&recipe).unwrap()),
            ..crate::scrape::ScrapeOptions::default()
        };
        let mut crawl = crate::CreateCrawl::new("https://fixture.test/".parse().unwrap());
        crawl.scrape = Some(crate::scrape::ScrapeJob::new(
            crate::scrape::JobKind::Scrape,
            options,
        ));
        crawl.retention.mode = crate::config::RetentionMode::Zdr;
        let errors = crawl.normalize().unwrap_err();
        assert!(errors.iter().any(|error| matches!(
            error,
            crate::CoreError::Invalid {
                field: "scrape.options.archiveBehavior",
                ..
            }
        )));
    }

    #[test]
    fn recorded_source_indices_must_cover_every_required_step_without_holes() {
        let mut recipe = RecipeV1::new("fixture".into(), 1);
        let mut source = RecipeSourceV1::new(Digest::of("fixture", b"source"));
        source.step_count = 2;
        source.initial_navigation_index = Some(0);
        recipe.entry_url = Some("https://fixture.test/".parse().unwrap());
        recipe.source = Some(source);
        assert_eq!(recipe.validate(), Err(RecipeError::Invalid));
        recipe.steps.push(RecipeStepV1::new(
            1,
            ScrapeAction::Click {
                selector: "#button".into(),
                all: false,
            },
        ));
        assert!(recipe.validate().is_ok());
        recipe.steps[0].source_index = 0;
        assert_eq!(recipe.validate(), Err(RecipeError::Invalid));
    }
}
