//! What `crawlx crawl` writes: the output directory, the result streams and the printed
//! counter block.

use crate::output_args::OutputPlan;
use crate::style::Style;
use anyhow::{anyhow, bail, Context as _};
use crawlx_core::config::CrawlMode;
use crawlx_core::counters::{Counters, RunStatus};
use crawlx_core::CreateCrawl;
use crawlx_worker::output::{ExportStats, Exporter, PageText, TextFile};
use crawlx_worker::RunReport;
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use url::Url;

/// One finished seed.
pub(crate) struct SeedRun {
    /// The seed URL.
    pub seed: Url,
    /// The admitted request the run executed.
    pub request: CreateCrawl,
    /// What the run reported.
    pub report: RunReport,
    /// The directory this seed's files go to.
    pub dir: PathBuf,
}

/// Indices of `report.pages` sorted by URL, so every output is deterministic.
pub(crate) fn page_order(report: &RunReport) -> Vec<usize> {
    let mut order: Vec<usize> = (0..report.pages.len()).collect();
    order.sort_by(|a, b| {
        report.pages[*a]
            .url
            .url
            .as_str()
            .cmp(report.pages[*b].url.url.as_str())
    });
    order
}

fn slug(url: &Url) -> String {
    let mut raw = String::new();
    raw.push_str(url.host_str().unwrap_or("host"));
    if let Some(p) = url.port() {
        raw.push_str(&format!("-{p}"));
    }
    raw.push_str(url.path());
    if let Some(q) = url.query() {
        raw.push('-');
        raw.push_str(q);
    }
    let mut s = String::with_capacity(raw.len());
    let mut dash = true;
    for c in raw.chars() {
        if c.is_ascii_alphanumeric() {
            s.push(c.to_ascii_lowercase());
            dash = false;
        } else if !dash {
            s.push('-');
            dash = true;
        }
    }
    let s = s.trim_matches('-');
    let s: String = s.chars().take(120).collect();
    if s.is_empty() {
        "index".to_owned()
    } else {
        s
    }
}

/// The directory a seed's files go to: the output directory itself for one seed, a
/// subdirectory named after the seed for several.
pub(crate) fn seed_dir(output: &Path, seed: &Url, seeds: usize) -> PathBuf {
    if seeds <= 1 {
        output.to_owned()
    } else {
        output.join(slug(seed))
    }
}

/// Write `pages/*.md`, `metadata.json`, `links.json` and `report.json`; returns the page files
/// written. The request in `report.json` has its header and cookie values redacted.
pub(crate) fn write_outputs(dir: &Path, request: &CreateCrawl, report: &RunReport) -> anyhow::Result<usize> {
    let pages_dir = dir.join("pages");
    std::fs::create_dir_all(&pages_dir).with_context(|| format!("creating {}", pages_dir.display()))?;
    let order = page_order(report);
    let mut used: BTreeMap<String, u32> = BTreeMap::new();
    let mut metadata = Vec::new();
    let mut links = serde_json::Map::new();
    let mut written = 0usize;
    for i in order {
        let page = &report.pages[i];
        let base = slug(&page.url.url);
        let n = used.entry(base.clone()).or_insert(0);
        *n += 1;
        let name = if *n == 1 { base } else { format!("{base}-{n}") };
        let mut file = None;
        if let Some(md) = report.page_contents.get(i).and_then(|c| c.markdown.as_ref()) {
            let rel = format!("pages/{name}.md");
            std::fs::write(dir.join(&rel), md).with_context(|| format!("writing {rel}"))?;
            written += 1;
            file = Some(rel);
        }
        metadata.push(serde_json::json!({
            "url": page.url.url.as_str(),
            "status": page.status,
            "contentType": page.content_type,
            "title": page.title,
            "file": file,
            "metadata": page.metadata,
            "fetchedAt": page.fetched_at,
        }));
        links.insert(page.url.url.to_string(), serde_json::json!(page.links));
    }
    std::fs::write(dir.join("metadata.json"), serde_json::to_vec_pretty(&metadata)?)?;
    std::fs::write(dir.join("links.json"), serde_json::to_vec_pretty(&links)?)?;
    let mut value = serde_json::to_value(report)?;
    if let Some(obj) = value.as_object_mut() {
        obj.insert("request".to_owned(), serde_json::to_value(request.redacted())?);
    }
    std::fs::write(dir.join("report.json"), serde_json::to_vec_pretty(&value)?)?;
    Ok(written)
}

/// Body and raw text of every page of `run`, by URL (a URL seen twice keeps its first entry).
fn page_texts(run: &SeedRun) -> BTreeMap<&str, PageText> {
    let mut texts = BTreeMap::new();
    for (page, content) in run.report.pages.iter().zip(&run.report.page_contents) {
        texts.entry(page.url.url.as_str()).or_insert_with(|| {
            let mut text = PageText::default();
            if let Some(body) = &content.html {
                text = text.with_body(body.clone());
            }
            if let Some(raw) = &content.raw {
                text = text.with_raw(raw.clone());
            }
            text
        });
    }
    texts
}

/// Feed every seed's pages (URL order, seeds in order) to `exporter`, writing to `dest`.
fn export_runs(exporter: &Exporter, runs: &[SeedRun], dest: &mut dyn Write) -> anyhow::Result<ExportStats> {
    let mut total = ExportStats::default();
    for run in runs {
        let texts = page_texts(run);
        let pages = page_order(&run.report).into_iter().map(|i| &run.report.pages[i]);
        let stats = exporter
            .export_pages_with(
                pages,
                |p| texts.get(p.url.url.as_str()).cloned().unwrap_or_default(),
                dest,
            )
            .map_err(|e| anyhow!("output failed: {e}"))?;
        total.pages = total.pages.saturating_add(stats.pages);
        total.lines = total.lines.saturating_add(stats.lines);
        total.filtered = total.filtered.saturating_add(stats.filtered);
        total.stored = total.stored.saturating_add(stats.stored);
    }
    dest.flush()?;
    Ok(total)
}

/// Write the JSONL and text result streams of every seed. Text goes to `out` unless `-o`
/// redirects it; a text exporter that only feeds wordlists (no field, template or `-o`) writes
/// nothing to `out`.
///
/// # Errors
/// A file that cannot be created or written, or an export failure.
pub(crate) fn emit_streams(plan: &OutputPlan, runs: &[SeedRun], out: &mut dyn Write) -> anyhow::Result<()> {
    if let (Some(exporter), Some(path)) = (&plan.jsonl, &plan.jsonl_file) {
        let mut file = TextFile::create(path, plan.no_clobber && plan.jsonl_to_user_file)
            .with_context(|| format!("creating {}", path.display()))?;
        export_runs(exporter, runs, &mut file)?;
        file.finish()
            .with_context(|| format!("writing {}", path.display()))?;
    }
    if let Some(exporter) = &plan.text {
        if let Some(path) = &plan.text_file {
            let mut file = TextFile::create(path, plan.no_clobber)
                .with_context(|| format!("creating {}", path.display()))?;
            export_runs(exporter, runs, &mut file)?;
            file.finish()
                .with_context(|| format!("writing {}", path.display()))?;
        } else if exporter.template.is_some() || !exporter.fields.is_empty() {
            export_runs(exporter, runs, out)?;
        } else {
            export_runs(exporter, runs, &mut std::io::sink())?;
        }
    }
    Ok(())
}

fn line(out: &mut dyn Write, name: &str, value: u64, width: usize) -> std::io::Result<()> {
    writeln!(out, "{name:<width$}{value:>3}")
}

/// `width` is the name column: 20 for the `urls.*` block, wider for longer prefixes.
fn block(
    out: &mut dyn Write,
    prefix: &str,
    c: &Counters,
    unknown_bare: bool,
    width: usize,
) -> std::io::Result<()> {
    line(out, &format!("{prefix}.discovered"), c.discovered, width)?;
    line(out, &format!("{prefix}.admitted"), c.admitted, width)?;
    line(out, &format!("{prefix}.deduplicated"), c.deduplicated, width)?;
    line(out, &format!("{prefix}.policy_blocked"), c.policy_blocked, width)?;
    line(out, &format!("{prefix}.robots_blocked"), c.robots_blocked, width)?;
    line(out, &format!("{prefix}.attempted"), c.attempted, width)?;
    line(out, &format!("{prefix}.succeeded"), c.succeeded, width)?;
    line(out, &format!("{prefix}.failed"), c.failed, width)?;
    if c.abandoned > 0 {
        line(out, &format!("{prefix}.abandoned"), c.abandoned, width)?;
    }
    if c.unreachable > 0 {
        line(out, &format!("{prefix}.unreachable"), c.unreachable, width)?;
    }
    let unknown = if unknown_bare {
        "unknown_outcome".to_owned()
    } else {
        format!("{prefix}.unknown_outcome")
    };
    line(out, &unknown, c.unknown_outcome, width)
}

fn mode_str(m: CrawlMode) -> &'static str {
    match m {
        CrawlMode::Static => "static",
        CrawlMode::Dynamic => "dynamic",
        CrawlMode::Hybrid => "hybrid",
    }
}

/// The counters block (`urls.* … unknown_outcome`, `pages written: N`).
///
/// # Errors
/// Writing failed, or the run failed (the block is printed first).
pub(crate) fn print_summary(
    out: &mut dyn Write,
    style: Style,
    mode: CrawlMode,
    report: &RunReport,
    dir: &Path,
    pages_written: usize,
) -> anyhow::Result<()> {
    let reason = report
        .terminal_reason
        .map_or("none", crawlx_core::counters::TerminalReason::as_str);
    let shown_reason = if report.status == RunStatus::Failed {
        style.bad(reason)
    } else if reason == "frontier_exhausted" {
        style.good(reason)
    } else {
        style.warn(reason)
    };
    writeln!(
        out,
        "crawl {} mode={} terminal_reason={shown_reason}",
        report.run_id,
        mode_str(mode)
    )?;
    if mode != CrawlMode::Dynamic {
        block(out, "urls", &report.counters.urls, true, 20)?;
        writeln!(
            out,
            "pages written: {pages_written}  -> {}/pages/*.md  (+ metadata.json, links.json)",
            dir.display()
        )?;
    }
    if mode != CrawlMode::Static {
        block(out, "interactions", &report.counters.interactions, false, 30)?;
        block(out, "states", &report.counters.states, false, 30)?;
        writeln!(
            out,
            "states recorded: {}  actions recorded: {}  -> {}/report.json",
            report.states.len(),
            report.actions.len(),
            dir.display()
        )?;
    }
    if report.status == RunStatus::Failed {
        bail!("run failed ({reason})");
    }
    Ok(())
}

/// Per-session browser diagnostics (`--enable-diagnostics`), one JSON line per session.
///
/// # Errors
/// Writing or serializing failed.
pub(crate) fn print_diagnostics(out: &mut dyn Write, report: &RunReport) -> anyhow::Result<()> {
    if report.diagnostics.is_empty() {
        return Ok(());
    }
    writeln!(out, "diagnostics: {} session(s)", report.diagnostics.len())?;
    for session in &report.diagnostics {
        writeln!(out, "{}", serde_json::to_string(session)?)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn one_seed_writes_to_the_output_directory_and_several_to_subdirectories() {
        let a = Url::parse("https://a.test/docs?x=1").unwrap();
        let out = Path::new("out");
        assert_eq!(seed_dir(out, &a, 1), Path::new("out"));
        assert_eq!(seed_dir(out, &a, 2), Path::new("out/a-test-docs-x-1"));
        assert_eq!(slug(&Url::parse("https://a.test/").unwrap()), "a-test");
    }
}
