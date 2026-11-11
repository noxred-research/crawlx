//! Offline recorded-flow inspection and exact-subset conversion. Never executes source code.

use anyhow::{bail, Context};
use clap::{Args, Subcommand};
use crawlx_core::{
    archive_behaviors::{RecipeReferenceV1, RecipeSourceV1, RecipeStepV1, RecipeV1},
    hash::Digest,
    scrape::{ScrapeAction, ScreenshotViewport},
};
use serde::Serialize;
use serde_json::{Map, Value};
use std::{io::Write, path::PathBuf, process::ExitCode};
use tokio::io::AsyncReadExt;

const MAX_FLOW_BYTES: usize = 1_048_576;
const MAX_SOURCE_STEPS: usize = 52;

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
    for key in root.keys() {
        if !matches!(key.as_str(), "title" | "steps") {
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
            Some(step) => translate(
                step,
                &mut recipe,
                source_index,
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
        let key = "private-operator-key-0123456789012345678901";
        tokio::fs::write(&key_path, key).await.unwrap();
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
        assert!(!String::from_utf8(output).unwrap().contains(key));
    }
}
