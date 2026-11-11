//! Offline recorded-flow inspection and exact-subset conversion. Never executes source code.
//!
//! The additional neutral wire contract is `dialect: "declarative-flow"`,
//! `dialectVersion: 1`. Navigation and initial desktop viewport use the recorder
//! fields below. Native input uses `click {selector}`, `fill {selector,text}`,
//! `write {text}`, `press {key}`, `scroll {direction,selector?}`, and
//! `wait {milliseconds}` or `wait {selector,state?}`. Scroll means one current
//! viewport-height relative vertical movement, including for an element target;
//! it never means absolute coordinates or arbitrary pixel deltas. Keys are
//! complete chords, not separate down/up events. Selector waits use the native
//! first-match attached/visible/hidden/detached contract and native deadline.
//! Repeated literal entries remain separate required source steps. Retries,
//! loops, run-once scheduling, scripts and executable callbacks are not inferred.
//! This is a native neutral interchange, not a claim of upstream runtime parity.

use anyhow::{bail, Context};
use clap::{Args, Subcommand};
use crawlx_core::{
    archive_behaviors::{RecipeReferenceV1, RecipeSourceV1, RecipeStepV1, RecipeV1},
    hash::Digest,
    page_op::SelectorState,
    scrape::{ScrapeAction, ScreenshotViewport, ScrollDirection, MAX_WAIT_MS},
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::{io::Write, path::PathBuf, process::ExitCode};
use tokio::io::AsyncReadExt;

const MAX_FLOW_BYTES: usize = 1_048_576;
const MAX_SOURCE_STEPS: usize = 52;
const MAX_FLOW_DEPTH: usize = 16;

/// Inspect or convert a local recorded JSON flow without browser or network access.
#[derive(Debug, Args)]
pub struct FlowImportArgs {
    /// Offline operation.
    #[command(subcommand)]
    pub command: FlowImportCommand,
}
/// Offline flow operations, never execution or operator approval.
#[derive(Debug, Subcommand)]
pub enum FlowImportCommand {
    /// Emit one value-free disposition per source step; exit two if any step cannot map exactly.
    Inspect(FlowArgs),
    /// Emit a digest-pinned recipe candidate only when every source step maps exactly.
    Convert(FlowArgs),
    /// Sign a complete operator registry offline; approval keys never enter output.
    SignRegistry(RegistrySignArgs),
}
/// Explicit bounded local input and immutable recipe identity.
#[derive(Debug, Args)]
pub struct FlowArgs {
    /// Regular JSON file, at most one MiB. Symlinks and special files are refused.
    pub flow: PathBuf,
    /// Operator recipe identifier; conversion does not grant approval.
    #[arg(long)]
    pub id: String,
    /// Exact immutable revision, greater than zero.
    #[arg(long)]
    pub version: u32,
}

/// Offline operator approval, separate from tenant flow selection.
#[derive(Debug, Args)]
pub struct RegistrySignArgs {
    /// Complete unsigned operator registry JSON, at most one MiB.
    pub registry: PathBuf,
    /// Operator-only env:// or file:// key reference, not a raw key.
    #[arg(long)]
    pub key_ref: String,
}

/// One source step outcome, without selectors, URLs, values or source error text.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowDispositionV1 {
    /// Original zero-based step position.
    pub source_index: u32,
    /// Recognized source wire type, or a fixed unsupported marker.
    pub source_type: &'static str,
    /// translated or unsupported; steps are never silently dropped.
    pub state: &'static str,
    /// Exact native route when supported.
    pub target: Option<&'static str>,
    /// Fixed, value-free explanation.
    pub reason: &'static str,
}
/// Complete value-free inspection output.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FlowReportV1 {
    /// Offline import contract revision.
    pub schema_version: u16,
    /// Source bytes digest, never source contents.
    pub source_digest: Digest,
    /// One entry per original source step.
    pub dispositions: Vec<FlowDispositionV1>,
    /// Fixed reasons for unsupported top-level behavior; field names are not echoed.
    pub source_refusals: Vec<&'static str>,
    /// Every required step and top-level behavioral option mapped exactly.
    pub convertible: bool,
    /// Conversion is not execution approval. An operator must register this exact digest.
    pub operator_approval_required: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConvertedFlow {
    report: FlowReportV1,
    recipe: RecipeV1,
    digest: Digest,
    reference: RecipeReferenceV1,
}

/// Inspect all source steps and build a candidate only for a fully supported flow.
///
/// # Errors
/// Refuses malformed JSON, non-object roots, absent steps and input/count bounds.
/// Individual unsupported semantics remain explicit dispositions, not parser errors.
pub fn inspect(bytes: &[u8], id: String, version: u32) -> anyhow::Result<(FlowReportV1, Option<RecipeV1>)> {
    if bytes.len() > MAX_FLOW_BYTES {
        bail!("recorded flow exceeds byte cap");
    }
    check_depth(bytes)?;
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid recorded flow JSON"))?;
    let root = value.as_object().context("recorded flow must be an object")?;
    let steps = root
        .get("steps")
        .and_then(Value::as_array)
        .context("recorded flow needs steps array")?;
    if steps.len() > MAX_SOURCE_STEPS {
        bail!("recorded flow exceeds step cap");
    }
    let source_digest = Digest::of("crawlx/recorded-flow-source/v1", bytes);
    let mut recipe = RecipeV1::new(id, version);
    recipe.source = Some(RecipeSourceV1::new(source_digest));
    if let Some(source) = &mut recipe.source {
        source.step_count = u32::try_from(steps.len())?;
    }
    let mut report = FlowReportV1 {
        schema_version: 1,
        source_digest,
        dispositions: Vec::with_capacity(steps.len()),
        source_refusals: Vec::new(),
        convertible: true,
        operator_approval_required: true,
    };
    let neutral = is_neutral_dialect(root, &mut report.source_refusals);
    for key in root.keys() {
        if !matches!(key.as_str(), "title" | "steps" | "dialect" | "dialectVersion") {
            report
                .source_refusals
                .push("unsupported top-level behavior, initialization, timing or driver configuration");
        }
    }
    if root.get("title").is_some_and(|value| !value.is_string()) {
        report.source_refusals.push("title must be inert text metadata");
    }
    let mut navigated = false;
    let mut viewport_seen = false;
    for (index, step) in steps.iter().enumerate() {
        let source_index = u32::try_from(index)?;
        let source_type = source_type(step.get("type").and_then(Value::as_str));
        let mapped = match step.as_object() {
            Some(step) => translate_step(
                step,
                &mut recipe,
                source_index,
                neutral,
                &mut navigated,
                &mut viewport_seen,
            ),
            None => Err("source step must be an object"),
        };
        let (state, target, reason) = match mapped {
            Ok(target) => ("translated", Some(target), "exact bounded native operation"),
            Err(reason) => ("unsupported", None, reason),
        };
        report.dispositions.push(FlowDispositionV1 {
            source_index,
            source_type,
            state,
            target,
            reason,
        });
    }
    if !navigated {
        report
            .source_refusals
            .push("exact initial navigation is required");
    }
    if recipe.digest().is_err() {
        report
            .source_refusals
            .push("native recipe identity, action or byte bounds failed");
    }
    report.convertible = report.source_refusals.is_empty()
        && report.dispositions.iter().all(|step| step.state == "translated");
    let candidate = report.convertible.then_some(recipe);
    Ok((report, candidate))
}

fn is_neutral_dialect(root: &Map<String, Value>, source_refusals: &mut Vec<&'static str>) -> bool {
    let neutral = root.get("dialect").and_then(Value::as_str) == Some("declarative-flow")
        && root.get("dialectVersion").and_then(Value::as_u64) == Some(1);
    if (root.contains_key("dialect") || root.contains_key("dialectVersion")) && !neutral {
        source_refusals.push("unsupported or incomplete flow dialect pin");
    }
    neutral
}

fn translate_step(
    step: &Map<String, Value>,
    recipe: &mut RecipeV1,
    index: u32,
    neutral: bool,
    navigated: &mut bool,
    viewport_seen: &mut bool,
) -> Result<&'static str, &'static str> {
    let result = if neutral {
        translate_neutral(step, recipe, index, *navigated)
    } else {
        None
    };
    result.unwrap_or_else(|| translate(step, recipe, index, navigated, viewport_seen))
}

fn translate(
    step: &Map<String, Value>,
    recipe: &mut RecipeV1,
    index: u32,
    navigated: &mut bool,
    viewport_seen: &mut bool,
) -> Result<&'static str, &'static str> {
    if step
        .get("target")
        .is_some_and(|target| target.as_str() != Some("main"))
        || step
            .get("frame")
            .is_some_and(|frame| frame.as_array().is_none_or(|frame| !frame.is_empty()))
    {
        return Err("frame and alternate-target semantics are unsupported");
    }
    if step
        .get("assertedEvents")
        .is_some_and(|events| events.as_array().is_none_or(|events| !events.is_empty()))
    {
        return Err("event assertions require unsupported timing semantics");
    }
    // These source type spellings are retained only for recorded-flow wire compatibility.
    match step.get("type").and_then(Value::as_str) {
        Some("setViewport") => {
            fields(
                step,
                &[
                    "type",
                    "width",
                    "height",
                    "deviceScaleFactor",
                    "isMobile",
                    "hasTouch",
                    "isLandscape",
                ],
            )?;
            if *navigated || *viewport_seen || !recipe.steps.is_empty() {
                return Err("mid-flow or repeated viewport changes are unsupported");
            }
            if step.get("deviceScaleFactor").and_then(Value::as_f64) != Some(1.0)
                || ["isMobile", "hasTouch", "isLandscape"]
                    .iter()
                    .any(|key| step.get(*key).and_then(Value::as_bool) != Some(false))
            {
                return Err("only exact desktop scale-one non-touch initial emulation is supported");
            }
            let width = dimension(step.get("width"))?;
            let height = dimension(step.get("height"))?;
            recipe.initial_viewport = Some(ScreenshotViewport { width, height });
            if let Some(source) = &mut recipe.source {
                source.initial_viewport_index = Some(index);
            }
            *viewport_seen = true;
            Ok("initialEmulation.viewport")
        }
        Some("navigate") => {
            fields(step, &["type", "url", "target", "frame", "assertedEvents"])?;
            if *navigated || !recipe.steps.is_empty() {
                return Err("mid-flow navigation is unsupported");
            }
            let url: url::Url = step
                .get("url")
                .and_then(Value::as_str)
                .ok_or("navigation URL is required")?
                .parse()
                .map_err(|_| "navigation URL is invalid")?;
            if url.as_str().len() > 8_192 {
                return Err("navigation URL exceeds native bound");
            }
            if !matches!(url.scheme(), "http" | "https")
                || url.host_str().is_none()
                || !url.username().is_empty()
                || url.password().is_some()
            {
                return Err("navigation requires a checked credential-free HTTP URL");
            }
            let canonical = crawlx_url::Canonicalizer::canonicalize_url(&url, &Default::default())
                .map_err(|_| "navigation URL cannot use the checked native request path")?;
            if canonical.url != url {
                return Err("native URL normalization would change required navigation semantics");
            }
            recipe.entry_url = Some(url);
            if let Some(source) = &mut recipe.source {
                source.initial_navigation_index = Some(index);
            }
            *navigated = true;
            Ok("SessionActor.initialNavigation")
        }
        Some("change") => {
            fields(
                step,
                &["type", "selectors", "value", "target", "frame", "assertedEvents"],
            )?;
            if !*navigated {
                return Err("input before initial navigation is unsupported");
            }
            let selector = selector(step)?;
            let text = step
                .get("value")
                .and_then(Value::as_str)
                .ok_or("change needs a literal string value")?;
            if text.len() > 4_096 {
                return Err("change value exceeds native bound");
            }
            recipe.steps.push(RecipeStepV1::new(
                index,
                ScrapeAction::Fill {
                    selector,
                    text: text.to_owned(),
                },
            ));
            Ok("ScrapeAction.fill")
        }
        Some("click") => {
            fields(
                step,
                &["type", "selectors", "button", "target", "frame", "assertedEvents"],
            )?;
            if !*navigated {
                return Err("input before initial navigation is unsupported");
            }
            if step
                .get("button")
                .is_some_and(|button| button.as_str() != Some("primary"))
            {
                return Err("only a single primary click is equivalent");
            }
            recipe.steps.push(RecipeStepV1::new(
                index,
                ScrapeAction::Click {
                    selector: selector(step)?,
                    all: false,
                },
            ));
            Ok("ScrapeAction.click")
        }
        Some("scroll") => Err("source absolute scroll coordinates are not native relative deltas"),
        Some("keyDown" | "keyUp") => {
            Err("separate key-down/up events are not equivalent to a native key chord")
        }
        Some("waitForElement") => {
            Err("source element-count and visibility assertions lack an exact native equivalent")
        }
        Some("waitForExpression") => Err("source script expressions are forbidden"),
        Some("customStep") => Err("custom executable steps are forbidden"),
        _ => Err("unsupported source step or executable initialization"),
    }
}

/// Reject excessive structure before allocating the JSON value tree.
fn check_depth(bytes: &[u8]) -> anyhow::Result<()> {
    let mut depth = 0_usize;
    let mut quoted = false;
    let mut escaped = false;
    for byte in bytes {
        if quoted {
            if escaped {
                escaped = false;
            } else if *byte == b'\\' {
                escaped = true;
            } else if *byte == b'"' {
                quoted = false;
            }
        } else {
            match byte {
                b'"' => quoted = true,
                b'{' | b'[' => {
                    depth += 1;
                    if depth > MAX_FLOW_DEPTH {
                        bail!("recorded flow exceeds nesting cap");
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}

/// Only explicit neutral types use this path; recorder types keep their refusals.
fn translate_neutral(
    step: &Map<String, Value>,
    recipe: &mut RecipeV1,
    index: u32,
    navigated: bool,
) -> Option<Result<&'static str, &'static str>> {
    let kind = step.get("type").and_then(Value::as_str)?;
    if !matches!(kind, "click" | "fill" | "write" | "press" | "scroll" | "wait") {
        return None;
    }
    Some((|| {
        if !navigated {
            return Err("native input and waits require initial navigation");
        }
        if recipe.steps.len() >= crawlx_core::archive_behaviors::MAX_RECIPE_STEPS {
            return Err("native action count exceeds bound");
        }
        let action = match kind {
            "click" => {
                fields(step, &["type", "selector"])?;
                ScrapeAction::Click {
                    selector: neutral_selector(step)?,
                    all: false,
                }
            }
            "fill" => {
                fields(step, &["type", "selector", "text"])?;
                ScrapeAction::Fill {
                    selector: neutral_selector(step)?,
                    text: literal(step, "text", true)?,
                }
            }
            "write" => {
                fields(step, &["type", "text"])?;
                ScrapeAction::Write {
                    text: literal(step, "text", false)?,
                }
            }
            "press" => {
                fields(step, &["type", "key"])?;
                let key = literal(step, "key", false)?;
                if !neutral_key(&key) {
                    return Err("key chord is outside the pinned native key subset");
                }
                ScrapeAction::Press { key }
            }
            "scroll" => {
                fields(step, &["type", "direction", "selector"])?;
                let direction = match step.get("direction").and_then(Value::as_str) {
                    Some("up") => ScrollDirection::Up,
                    Some("down") => ScrollDirection::Down,
                    _ => return Err("relative viewport scroll needs an explicit vertical direction"),
                };
                let selector = if step.contains_key("selector") {
                    Some(neutral_selector(step)?)
                } else {
                    None
                };
                ScrapeAction::Scroll { direction, selector }
            }
            "wait" => {
                fields(step, &["type", "milliseconds", "selector", "state"])?;
                if step.contains_key("milliseconds") {
                    if step.contains_key("selector") || step.contains_key("state") {
                        return Err("fixed wait cannot contain selector or state semantics");
                    }
                    let milliseconds = step["milliseconds"]
                        .as_u64()
                        .and_then(|value| u32::try_from(value).ok())
                        .filter(|value| *value <= MAX_WAIT_MS)
                        .ok_or("fixed wait exceeds native bound")?;
                    let waited: u64 = recipe
                        .steps
                        .iter()
                        .filter_map(|step| match &step.action {
                            ScrapeAction::Wait {
                                milliseconds: Some(ms),
                                ..
                            } => Some(u64::from(*ms)),
                            _ => None,
                        })
                        .sum();
                    if waited + u64::from(milliseconds) > u64::from(MAX_WAIT_MS) {
                        return Err("total fixed wait exceeds native bound");
                    }
                    ScrapeAction::Wait {
                        milliseconds: Some(milliseconds),
                        selector: None,
                        state: SelectorState::Attached,
                    }
                } else {
                    let state = match step.get("state").and_then(Value::as_str) {
                        None if !step.contains_key("state") => SelectorState::Attached,
                        Some("attached") => SelectorState::Attached,
                        Some("visible") => SelectorState::Visible,
                        Some("hidden") => SelectorState::Hidden,
                        Some("detached") => SelectorState::Detached,
                        _ => return Err("unknown native selector wait state"),
                    };
                    ScrapeAction::Wait {
                        milliseconds: None,
                        selector: Some(neutral_selector(step)?),
                        state,
                    }
                }
            }
            _ => return Err("unsupported neutral action"),
        };
        let target = match &action {
            ScrapeAction::Click { .. } => "ScrapeAction.click",
            ScrapeAction::Fill { .. } => "ScrapeAction.fill",
            ScrapeAction::Write { .. } => "ScrapeAction.write",
            ScrapeAction::Press { .. } => "ScrapeAction.press",
            ScrapeAction::Scroll { .. } => "ScrapeAction.scroll",
            ScrapeAction::Wait { .. } => "ScrapeAction.wait",
            _ => return Err("unsupported neutral action"),
        };
        recipe.steps.push(RecipeStepV1::new(index, action));
        Ok(target)
    })())
}

fn literal(step: &Map<String, Value>, field: &str, empty: bool) -> Result<String, &'static str> {
    step.get(field)
        .and_then(Value::as_str)
        .filter(|value| (empty || !value.is_empty()) && value.len() <= 4_096)
        .map(str::to_owned)
        .ok_or("native literal is absent, invalid or exceeds bound")
}

fn neutral_selector(step: &Map<String, Value>) -> Result<String, &'static str> {
    let selector = literal(step, "selector", false)?;
    if selector.contains(" >> ")
        || ["aria/", "text/", "xpath/", "pierce/"]
            .iter()
            .any(|prefix| selector.starts_with(prefix))
    {
        return Err("native selector must be one CSS selector");
    }
    Ok(selector)
}

/// Deliberately narrower than the actor parser: canonical names and unique modifiers.
fn neutral_key(chord: &str) -> bool {
    if chord.len() > 64 {
        return false;
    }
    if chord == "+" {
        return true;
    }
    let mut parts = chord.rsplit('+');
    let Some(key) = parts.next() else {
        return false;
    };
    let character = key.chars().count() == 1 && !key.chars().any(char::is_whitespace);
    if !character
        && !matches!(
            key,
            "Enter"
                | "Escape"
                | "Tab"
                | "Backspace"
                | "Delete"
                | "Insert"
                | "ArrowUp"
                | "ArrowDown"
                | "ArrowLeft"
                | "ArrowRight"
                | "Home"
                | "End"
                | "PageUp"
                | "PageDown"
                | "Space"
                | "F1"
                | "F2"
                | "F3"
                | "F4"
                | "F5"
                | "F6"
                | "F7"
                | "F8"
                | "F9"
                | "F10"
                | "F11"
                | "F12"
        )
    {
        return false;
    }
    let mut seen = 0_u8;
    for modifier in parts {
        let bit = match modifier {
            "Control" => 1,
            "Alt" => 2,
            "Shift" => 4,
            "Meta" => 8,
            _ => return false,
        };
        if seen & bit != 0 {
            return false;
        }
        seen |= bit;
    }
    true
}

fn fields(step: &Map<String, Value>, allowed: &[&str]) -> Result<(), &'static str> {
    if step.keys().any(|key| !allowed.contains(&key.as_str())) {
        Err("unsupported step field, timing, script, driver argument or input semantics")
    } else {
        Ok(())
    }
}
fn dimension(value: Option<&Value>) -> Result<u32, &'static str> {
    value
        .and_then(Value::as_u64)
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| (1..=8_192).contains(value))
        .ok_or("viewport dimension exceeds native bound")
}
fn selector(step: &Map<String, Value>) -> Result<String, &'static str> {
    let alternatives = step
        .get("selectors")
        .and_then(Value::as_array)
        .ok_or("one exact CSS selector is required")?;
    if alternatives.len() != 1 {
        return Err("selector alternatives cannot be silently dropped");
    }
    let chain = alternatives[0]
        .as_array()
        .ok_or("selector chain must be an array")?;
    if chain.len() != 1 {
        return Err("shadow or nested selector chains are unsupported");
    }
    let selector = chain[0].as_str().ok_or("selector must be CSS text")?;
    if selector.is_empty()
        || selector.len() > 4_096
        || selector.contains(" >> ")
        || ["aria/", "text/", "xpath/", "pierce/"]
            .iter()
            .any(|prefix| selector.starts_with(prefix))
    {
        return Err("non-CSS or oversized selector is unsupported");
    }
    Ok(selector.to_owned())
}
fn source_type(kind: Option<&str>) -> &'static str {
    // Exact recorded-flow wire vocabulary only; unknown caller text never enters reports.
    match kind {
        Some("setViewport") => "setViewport",
        Some("navigate") => "navigate",
        Some("change") => "change",
        Some("click") => "click",
        Some("fill") => "fill",
        Some("write") => "write",
        Some("press") => "press",
        Some("wait") => "wait",
        Some("scroll") => "scroll",
        Some("keyDown") => "keyDown",
        Some("keyUp") => "keyUp",
        Some("waitForElement") => "waitForElement",
        Some("waitForExpression") => "waitForExpression",
        Some("customStep") => "customStep",
        _ => "unsupported",
    }
}

/// Run offline inspection or conversion without logging, network setup or browser launch.
///
/// # Errors
/// Refuses unreadable/nonregular/oversized inputs, invalid JSON and output failures.
/// Unsupported semantics print the complete report and return exit code two.
pub async fn run(args: FlowImportArgs, out: &mut dyn Write) -> anyhow::Result<ExitCode> {
    let (args, convert) = match args.command {
        FlowImportCommand::Inspect(args) => (args, false),
        FlowImportCommand::Convert(args) => (args, true),
        FlowImportCommand::SignRegistry(args) => {
            let metadata = tokio::fs::symlink_metadata(&args.registry)
                .await
                .context("reading registry metadata")?;
            if !metadata.file_type().is_file() || metadata.len() > 1_048_576 {
                bail!("recipe registry must be a bounded regular file");
            }
            let mut bytes = Vec::new();
            tokio::fs::File::open(&args.registry)
                .await
                .context("opening recipe registry")?
                .take(1_048_577)
                .read_to_end(&mut bytes)
                .await
                .context("reading recipe registry")?;
            let key = crawlx_worker::archive_behaviors::load_approval_key(
                &crawlx_core::secret::CredentialRef(args.key_ref),
            )
            .await?;
            let signed =
                crawlx_worker::archive_behaviors::sign_registry_bytes(&bytes, key.expose().as_bytes())?;
            out.write_all(&signed)?;
            writeln!(out)?;
            return Ok(ExitCode::SUCCESS);
        }
    };
    let metadata = tokio::fs::symlink_metadata(&args.flow)
        .await
        .context("reading recorded flow metadata")?;
    if !metadata.file_type().is_file() || metadata.len() > 1_048_576 {
        bail!("recorded flow must be a bounded regular file");
    }
    let mut bytes = Vec::new();
    tokio::fs::File::open(&args.flow)
        .await
        .context("opening recorded flow")?
        .take(1_048_577)
        .read_to_end(&mut bytes)
        .await
        .context("reading recorded flow")?;
    let (report, recipe) = inspect(&bytes, args.id, args.version)?;
    let success = report.convertible;
    if convert {
        if let Some(recipe) = recipe {
            let reference = RecipeReferenceV1::for_recipe(&recipe)?;
            let digest = reference.digest;
            serde_json::to_writer_pretty(
                &mut *out,
                &ConvertedFlow {
                    report,
                    recipe,
                    digest,
                    reference,
                },
            )?;
        } else {
            serde_json::to_writer_pretty(&mut *out, &report)?;
        }
    } else {
        serde_json::to_writer_pretty(&mut *out, &report)?;
    }
    writeln!(out)?;
    Ok(if success {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn pinned_key_chords_match_native_complete_press_grammar_without_down_up_inference() {
        for key in ["+", "é", "Control+é", "Shift+Tab", "F12", "Alt+Insert"] {
            assert!(neutral_key(key));
        }
        for key in [
            "",
            " ",
            "Control+",
            "Control++",
            "Control+Control+A",
            "Shift+private-secret",
            "private-modifier+A",
            "F13",
            " Enter",
        ] {
            assert!(!neutral_key(key));
        }
    }

    #[tokio::test]
    async fn pinned_neutral_commands_emit_valid_recipe_or_complete_value_free_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("neutral.json");
        tokio::fs::write(
            &path,
            br#"{
            "dialect":"declarative-flow","dialectVersion":1,"steps":[
            {"type":"navigate","url":"https://fixture.test/"},
            {"type":"scroll","direction":"down"},
            {"type":"press","key":"Enter"},
            {"type":"wait","selector":"body","state":"attached"}]}"#,
        )
        .await
        .unwrap();
        let args = || FlowArgs {
            flow: path.clone(),
            id: "fixture".into(),
            version: 1,
        };
        let mut output = Vec::new();
        assert_eq!(
            run(
                FlowImportArgs {
                    command: FlowImportCommand::Convert(args())
                },
                &mut output
            )
            .await
            .unwrap(),
            ExitCode::SUCCESS
        );
        let converted: Value = serde_json::from_slice(&output).unwrap();
        let recipe: RecipeV1 = serde_json::from_value(converted["recipe"].clone()).unwrap();
        assert_eq!(
            converted["digest"],
            serde_json::to_value(recipe.digest().unwrap()).unwrap()
        );
        assert_eq!(converted["reference"]["digest"], converted["digest"]);
        tokio::fs::write(
            &path,
            br#"{
            "dialect":"declarative-flow","dialectVersion":1,"steps":[
            {"type":"navigate","url":"https://fixture.test/"},
            {"type":"press","key":"Enter","callback":"private-secret"}]}"#,
        )
        .await
        .unwrap();
        for command in [
            FlowImportCommand::Inspect(args()),
            FlowImportCommand::Convert(args()),
        ] {
            output.clear();
            assert_eq!(
                run(FlowImportArgs { command }, &mut output).await.unwrap(),
                ExitCode::from(2)
            );
            let report: Value = serde_json::from_slice(&output).unwrap();
            assert_eq!(report["dispositions"].as_array().unwrap().len(), 2);
            assert_eq!(report["dispositions"][1]["state"], "unsupported");
            assert!(report.get("recipe").is_none());
            assert!(!String::from_utf8(output.clone())
                .unwrap()
                .contains("private-secret"));
        }
    }

    #[test]
    fn pinned_neutral_flow_preserves_every_native_action_and_repeated_literal_entry() {
        let bytes = br##"{"dialect":"declarative-flow","dialectVersion":1,"steps":[
            {"type":"setViewport","width":800,"height":600,"deviceScaleFactor":1,"isMobile":false,"hasTouch":false,"isLandscape":false},
            {"type":"navigate","url":"https://fixture.test/"},
            {"type":"click","selector":"#open"},
            {"type":"fill","selector":"#input","text":"value"},
            {"type":"fill","selector":"#input","text":"value"},
            {"type":"write","text":"suffix"},
            {"type":"press","key":"Control+Shift+A"},
            {"type":"scroll","direction":"down"},
            {"type":"scroll","direction":"up","selector":"#list"},
            {"type":"wait","milliseconds":25},
            {"type":"wait","selector":"#present"},
            {"type":"wait","selector":"#visible","state":"visible"},
            {"type":"wait","selector":"#hidden","state":"hidden"},
            {"type":"wait","selector":"#gone","state":"detached"}]}"##;
        let (report, candidate) = inspect(bytes, "fixture".into(), 1).unwrap();
        assert!(report.convertible);
        assert_eq!(report.dispositions.len(), 14);
        let recipe = candidate.unwrap();
        assert_eq!(recipe.source.as_ref().unwrap().step_count, 14);
        assert_eq!(recipe.steps.len(), 12);
        for (index, step) in recipe.steps.iter().enumerate() {
            assert_eq!(step.source_index, u32::try_from(index + 2).unwrap());
        }
        assert_eq!(recipe.steps[1].action, recipe.steps[2].action);
        assert!(matches!(&recipe.steps[4].action, ScrapeAction::Press { key } if key == "Control+Shift+A"));
        assert!(matches!(
            &recipe.steps[5].action,
            ScrapeAction::Scroll {
                direction: ScrollDirection::Down,
                selector: None
            }
        ));
        assert!(matches!(&recipe.steps[6].action,
            ScrapeAction::Scroll { direction: ScrollDirection::Up, selector: Some(selector) } if selector == "#list"));
        assert!(matches!(
            &recipe.steps[8].action,
            ScrapeAction::Wait {
                state: SelectorState::Attached,
                ..
            }
        ));
        assert!(matches!(
            &recipe.steps[9].action,
            ScrapeAction::Wait {
                state: SelectorState::Visible,
                ..
            }
        ));
        assert!(matches!(
            &recipe.steps[10].action,
            ScrapeAction::Wait {
                state: SelectorState::Hidden,
                ..
            }
        ));
        assert!(matches!(
            &recipe.steps[11].action,
            ScrapeAction::Wait {
                state: SelectorState::Detached,
                ..
            }
        ));
        let roundtrip: RecipeV1 = serde_json::from_slice(&serde_json::to_vec(&recipe).unwrap()).unwrap();
        assert_eq!(recipe.digest().unwrap(), roundtrip.digest().unwrap());
    }

    #[test]
    fn neutral_dialect_requires_exact_pin_and_never_reinterprets_recorder_events() {
        for pin in [
            "",
            r#""dialect":"declarative-flow","#,
            r#""dialectVersion":1,"#,
            r#""dialect":"declarative-flow","dialectVersion":2,"#,
            r#""dialect":"private-unknown","dialectVersion":1,"#,
        ] {
            let bytes = format!(
                r#"{{{pin}"steps":[
                {{"type":"navigate","url":"https://fixture.test/"}},
                {{"type":"press","key":"Enter"}}]}}"#
            );
            let (report, candidate) = inspect(bytes.as_bytes(), "fixture".into(), 1).unwrap();
            assert!(!report.convertible);
            assert!(candidate.is_none());
            assert!(!serde_json::to_string(&report).unwrap().contains("private-"));
        }
        for pin in ["", r#""dialect":"declarative-flow","dialectVersion":1,"#] {
            let bytes = format!(
                r#"{{{pin}"steps":[
                {{"type":"navigate","url":"https://fixture.test/"}},
                {{"type":"scroll","x":0,"y":100}},
                {{"type":"keyDown","key":"Enter"}},
                {{"type":"keyUp","key":"Enter"}},
                {{"type":"waitForElement","selectors":[["body"]],"count":1}}]}}"#
            );
            let (report, candidate) = inspect(bytes.as_bytes(), "fixture".into(), 1).unwrap();
            assert!(candidate.is_none());
            assert_eq!(report.dispositions.len(), 5);
            assert!(report.dispositions[1..]
                .iter()
                .all(|step| step.state == "unsupported"));
        }
    }

    #[test]
    fn neutral_malicious_unknown_and_inexact_fields_get_complete_secret_free_refusals() {
        let bytes = br##"{"dialect":"declarative-flow","dialectVersion":1,
            "runOnce":true,"retries":3,"private-field":"private-root","steps":[
            {"type":"navigate","url":"https://fixture.test/private-url"},
            {"type":"click","selector":"#private-selector","callback":"private-script"},
            {"type":"fill","selector":"#private-selector","text":"private-value","repeat":2},
            {"type":"press","key":"private-key"},
            {"type":"press","key":"Control+Control+A"},
            {"type":"scroll","direction":"down","dy":100},
            {"type":"wait","selector":"#private-selector","state":"private-state"},
            {"type":"wait","milliseconds":1,"selector":"#private-selector"},
            {"type":"wait","selector":"body","timeout":100},
            {"type":"customStep","script":"private-script"},
            {"type":"waitForExpression","expression":"private-expression"},
            {"type":"private-type","private-field":"private-secret"},
            {"type":"executeJavascript","script":"private-script"},
            {"type":"click","selector":"body","frame":[0]},
            null,
            {"type":"press","key":"Enter"}]}"##;
        let (report, candidate) = inspect(bytes, "fixture".into(), 1).unwrap();
        assert!(candidate.is_none());
        assert_eq!(report.dispositions.len(), 16);
        assert_eq!(report.source_refusals.len(), 4);
        assert_eq!(
            report.source_refusals.last(),
            Some(&"native recipe identity, action or byte bounds failed")
        );
        assert_eq!(report.dispositions[0].state, "translated");
        assert_eq!(report.dispositions[15].state, "translated");
        assert!(report.dispositions[1..15]
            .iter()
            .all(|step| step.state == "unsupported"));
        assert!(!serde_json::to_string(&report).unwrap().contains("private-"));
        assert!(!format!("{report:?}").contains("private-"));
    }

    #[test]
    fn neutral_wait_limits_refuse_each_bad_step_without_dropping_later_entries() {
        let bytes = br##"{"dialect":"declarative-flow","dialectVersion":1,"steps":[
            {"type":"navigate","url":"https://fixture.test/"},
            {"type":"wait","milliseconds":60000},
            {"type":"wait","milliseconds":1},
            {"type":"wait","milliseconds":-1},
            {"type":"wait","milliseconds":1.5},
            {"type":"wait","milliseconds":4294967296},
            {"type":"wait","selector":null},
            {"type":"wait","selector":"body","state":null},
            {"type":"wait","milliseconds":0},
            {"type":"press","key":"Shift+Tab"}]}"##;
        let (report, candidate) = inspect(bytes, "fixture".into(), 1).unwrap();
        assert!(candidate.is_none());
        assert_eq!(report.dispositions.len(), 10);
        assert!(report.dispositions[2..8]
            .iter()
            .all(|step| step.state == "unsupported"));
        assert!(report.dispositions[8..]
            .iter()
            .all(|step| step.state == "translated"));
    }

    #[test]
    fn flow_byte_depth_and_step_caps_refuse_without_source_error_values() {
        let oversize = vec![b' '; MAX_FLOW_BYTES + 1];
        assert_eq!(
            inspect(&oversize, "fixture".into(), 1).unwrap_err().to_string(),
            "recorded flow exceeds byte cap"
        );
        let deep = format!(
            r#"{{"private-field":{}"private-secret"{},"steps":[]}}"#,
            "[".repeat(MAX_FLOW_DEPTH),
            "]".repeat(MAX_FLOW_DEPTH)
        );
        assert_eq!(
            inspect(deep.as_bytes(), "fixture".into(), 1)
                .unwrap_err()
                .to_string(),
            "recorded flow exceeds nesting cap"
        );
        let steps = vec![serde_json::json!({"type":"private-type"}); MAX_SOURCE_STEPS + 1];
        let bytes = serde_json::to_vec(&serde_json::json!({"steps":steps})).unwrap();
        assert_eq!(
            inspect(&bytes, "fixture".into(), 1).unwrap_err().to_string(),
            "recorded flow exceeds step cap"
        );
        let malformed = br#"{"private-secret": private-source-error}"#;
        assert_eq!(
            inspect(malformed, "fixture".into(), 1).unwrap_err().to_string(),
            "invalid recorded flow JSON"
        );
        let quoted = serde_json::to_vec(&serde_json::json!({
            "title": format!("{}\\\"{}", "[".repeat(100), "]".repeat(100)),
            "steps": [{"type":"navigate","url":"https://fixture.test/"}]
        }))
        .unwrap();
        assert!(inspect(&quoted, "fixture".into(), 1).unwrap().0.convertible);
    }

    #[test]
    fn neutral_action_count_and_literal_bounds_refuse_before_candidate_output() {
        let mut steps = vec![serde_json::json!({"type":"navigate","url":"https://fixture.test/"})];
        steps.extend((0..51).map(|_| serde_json::json!({"type":"press","key":"Enter"})));
        let bytes = serde_json::to_vec(&serde_json::json!({
            "dialect":"declarative-flow","dialectVersion":1,"steps":steps
        }))
        .unwrap();
        let (report, candidate) = inspect(&bytes, "fixture".into(), 1).unwrap();
        assert!(candidate.is_none());
        assert_eq!(report.dispositions.len(), 52);
        assert_eq!(report.dispositions[51].state, "unsupported");
        for action in [
            serde_json::json!({"type":"fill","selector":"body","text":"x".repeat(4097)}),
            serde_json::json!({"type":"write","text":""}),
            serde_json::json!({"type":"click","selector":"x".repeat(4097)}),
            serde_json::json!({"type":"click","selector":"xpath/private-secret"}),
        ] {
            let bytes = serde_json::to_vec(&serde_json::json!({
                "dialect":"declarative-flow","dialectVersion":1,
                "steps":[{"type":"navigate","url":"https://fixture.test/"},action]
            }))
            .unwrap();
            let (report, candidate) = inspect(&bytes, "fixture".into(), 1).unwrap();
            assert!(candidate.is_none());
            assert_eq!(report.dispositions[1].state, "unsupported");
            assert!(!serde_json::to_string(&report).unwrap().contains("private-secret"));
        }
    }

    #[test]
    fn exact_flow_converts_without_dropping_source_steps_or_leaking_report_values() {
        let bytes = br##"{"title":"private-title","steps":[
            {"type":"setViewport","width":800,"height":600,"deviceScaleFactor":1,"isMobile":false,"hasTouch":false,"isLandscape":false},
            {"type":"navigate","url":"https://fixture.test/private-url"},
            {"type":"change","selectors":[["#private-selector"]],"value":"private-value"}] }"##;
        let (report, recipe) = inspect(bytes, "fixture".into(), 1).unwrap();
        assert!(report.convertible);
        assert_eq!(report.dispositions.len(), 3);
        let recipe = recipe.unwrap();
        assert!(matches!(&recipe.steps[0].action, ScrapeAction::Fill { .. }));
        let report = serde_json::to_string(&report).unwrap();
        for marker in [
            "private-title",
            "private-url",
            "private-selector",
            "private-value",
        ] {
            assert!(!report.contains(marker));
        }
    }

    #[test]
    fn every_unsafe_or_inexact_source_step_gets_a_disposition_and_blocks_conversion() {
        let bytes = br##"{"driverArguments":["private-flag"],"steps":[
            {"type":"navigate","url":"https://fixture.test/"},
            {"type":"setViewport","width":800,"height":600},
            {"type":"customStep","script":"private-script"},
            {"type":"keyDown","key":"private-key"},
            {"type":"private-unknown-type"},
            {"type":"click","selectors":[["#a"],["#b"]]}]}"##;
        let (report, recipe) = inspect(bytes, "fixture".into(), 1).unwrap();
        assert!(!report.convertible);
        assert!(recipe.is_none());
        assert_eq!(report.dispositions.len(), 6);
        assert_eq!(
            report
                .dispositions
                .iter()
                .filter(|step| step.state == "unsupported")
                .count(),
            5
        );
        assert!(!serde_json::to_string(&report).unwrap().contains("private-"));
    }

    #[tokio::test]
    async fn commands_emit_real_inspection_and_pinned_conversion_without_network() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("flow.json");
        tokio::fs::write(
            &path,
            br#"{"steps":[{"type":"navigate","url":"https://fixture.test/"}]}"#,
        )
        .await
        .unwrap();
        let args = || FlowArgs {
            flow: path.clone(),
            id: "fixture".into(),
            version: 1,
        };
        let mut inspected = Vec::new();
        let exit = run(
            FlowImportArgs {
                command: FlowImportCommand::Inspect(args()),
            },
            &mut inspected,
        )
        .await
        .unwrap();
        assert_eq!(exit, ExitCode::SUCCESS);
        let report: Value = serde_json::from_slice(&inspected).unwrap();
        assert_eq!(report["dispositions"].as_array().unwrap().len(), 1);
        assert_eq!(report["convertible"], true);
        assert!(report.get("recipe").is_none());
        let mut converted = Vec::new();
        let exit = run(
            FlowImportArgs {
                command: FlowImportCommand::Convert(args()),
            },
            &mut converted,
        )
        .await
        .unwrap();
        assert_eq!(exit, ExitCode::SUCCESS);
        let output: Value = serde_json::from_slice(&converted).unwrap();
        let recipe: RecipeV1 = serde_json::from_value(output["recipe"].clone()).unwrap();
        assert_eq!(
            output["digest"],
            serde_json::to_value(recipe.digest().unwrap()).unwrap()
        );
        assert_eq!(output["reference"]["digest"], output["digest"]);
        assert_eq!(output["report"]["operatorApprovalRequired"], true);
        tokio::fs::write(
            &path,
            br#"{"steps":[{"type":"customStep","script":"private-code"}]}"#,
        )
        .await
        .unwrap();
        converted.clear();
        let exit = run(
            FlowImportArgs {
                command: FlowImportCommand::Convert(args()),
            },
            &mut converted,
        )
        .await
        .unwrap();
        assert_eq!(exit, ExitCode::from(2));
        let refused: Value = serde_json::from_slice(&converted).unwrap();
        assert_eq!(refused["dispositions"][0]["state"], "unsupported");
        assert!(refused.get("recipe").is_none());
        assert!(!String::from_utf8(converted).unwrap().contains("private-code"));
    }

    #[tokio::test]
    async fn offline_registry_signing_uses_private_key_reference_and_verifies_before_output() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("approval-key");
        let key = format!("private-operator-{}", "0123456789".repeat(4));
        tokio::fs::write(&key_path, &key).await.unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            tokio::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
                .await
                .unwrap();
        }
        let recipe = RecipeV1::new("fixture".into(), 1);
        let path = dir.path().join("registry.json");
        let unsigned = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 1, "recipes": [{
                "digest": recipe.digest().unwrap(), "recipe": recipe,
                "approvedTenants": [crawlx_core::TenantId::new()],
                "approvalId": "fixture", "legalReviewApproved": true
            }]
        }))
        .unwrap();
        tokio::fs::write(&path, unsigned).await.unwrap();
        let mut output = Vec::new();
        let exit = run(
            FlowImportArgs {
                command: FlowImportCommand::SignRegistry(RegistrySignArgs {
                    registry: path,
                    key_ref: format!("file://{}", key_path.display()),
                }),
            },
            &mut output,
        )
        .await
        .unwrap();
        assert_eq!(exit, ExitCode::SUCCESS);
        assert!(
            crawlx_worker::archive_behaviors::RecipeRegistry::from_bytes(&output, key.as_bytes()).is_ok()
        );
        assert!(!String::from_utf8(output).unwrap().contains(&key));
    }
}
