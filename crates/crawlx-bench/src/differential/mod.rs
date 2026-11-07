//! Data-only differential comparison of a Firecrawl crawl export and a crawlx run.
//!
//! Both sides enter as data: [`FirecrawlExport`] (the v2 status and errors bodies) and
//! [`CrawlxRun`] (a worker report, a CLI output directory or its own JSON). The
//! [`DifferentialRunner`] reduces both to origin-independent URL keys, compares admission
//! (C1), normalized markdown, links and metadata per common page (C2) and counters/status
//! (C3), and consults the divergence [`Ledger`] for every difference. Undocumented admission
//! differences are blocking; everything else undocumented is a warning. The [`Report`]
//! renders a markdown scorecard and an exit code.

pub mod access;
pub mod crawlx;
pub mod firecrawl;
pub mod ledger;
pub mod normalize;
pub mod wire;
pub use access::{AccessEntry, AccessLog};
pub use crawlx::{apply_firecrawl_request, CrawlxFrontierRow, CrawlxPage, CrawlxRun, FixtureRun};
pub use firecrawl::{FirecrawlDocument, FirecrawlError, FirecrawlErrors, FirecrawlExport, FirecrawlMetadata};
pub use ledger::{Divergence, DivergenceClass, DivergenceKind, Ledger, Side};
pub use normalize::{
    block_f1, line_diff, markdown_blocks, normalize_markdown, ordered_subsequence_ratio, token_jaccard,
    url_key, LineDiff,
};

use crawlx_core::repo::FrontierStatus;
use normalize::set_jaccard;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use url::Url;

/// Planning-default thresholds.
#[derive(Clone, Copy, Debug, PartialEq)]
#[non_exhaustive]
pub struct Thresholds {
    /// Markdown normalized-token similarity per page.
    pub markdown_page: f64,
    /// Markdown similarity, corpus mean.
    pub markdown_corpus: f64,
    /// Link-set Jaccard per page.
    pub links: f64,
    /// Metadata field equality over the corpus.
    pub metadata: f64,
    /// Block-level F1 per page (an addition for the messy corpus;
    /// informational for the corpus mean).
    pub block_f1: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            markdown_page: 0.97,
            markdown_corpus: 0.98,
            links: 0.98,
            metadata: 0.99,
            block_f1: 0.80,
        }
    }
}

/// A page as the comparator sees it, from either side.
#[derive(Clone, Debug, Default, PartialEq)]
struct PageView {
    url: String,
    status: Option<u16>,
    title: Option<String>,
    description: Option<String>,
    language: Option<String>,
    content_type: Option<String>,
    markdown: Option<String>,
    links: BTreeSet<String>,
}

/// One side reduced to sets keyed by [`url_key`].
#[derive(Clone, Debug, Default)]
struct Observed {
    status: String,
    total: u64,
    completed: u64,
    attempted: BTreeSet<String>,
    robots_blocked: BTreeSet<String>,
    pages: BTreeMap<String, PageView>,
    /// Page requests the fixture server saw (`URL key -> count`), when its access log was
    /// recorded for this side.
    requested: Option<BTreeMap<String, u32>>,
}

fn http_only(raw: &str) -> bool {
    let t = raw.trim_start();
    t.starts_with("http://") || t.starts_with("https://")
}

fn link_keys<'a>(links: impl IntoIterator<Item = &'a str>, origin: &Url) -> BTreeSet<String> {
    links
        .into_iter()
        .filter(|l| http_only(l))
        .map(|l| url_key(l, origin, false))
        .collect()
}

impl Observed {
    fn firecrawl(export: &FirecrawlExport, origin: &Url, keep_query: bool) -> Self {
        let mut o = Self {
            status: export.status.clone(),
            total: export.total,
            completed: export.completed,
            ..Self::default()
        };
        for d in &export.data {
            let key = url_key(&d.metadata.source_url, origin, keep_query);
            o.attempted.insert(key.clone());
            if d.metadata.status_code.is_some_and(|s| s >= 400) {
                continue;
            }
            o.pages.entry(key).or_insert_with(|| PageView {
                url: d.metadata.source_url.clone(),
                status: d.metadata.status_code,
                title: d.metadata.title.clone(),
                description: d.metadata.description.clone(),
                language: d.metadata.language.clone(),
                content_type: d.metadata.content_type.clone(),
                markdown: d.markdown.clone(),
                links: link_keys(d.links.iter().map(String::as_str), origin),
            });
        }
        for e in &export.errors.errors {
            o.attempted.insert(url_key(&e.url, origin, keep_query));
        }
        for r in &export.errors.robots_blocked {
            o.robots_blocked.insert(url_key(r, origin, keep_query));
        }
        o.requested = export
            .access_log
            .as_ref()
            .map(|l| l.requested(origin, keep_query));
        o
    }

    fn crawlx(run: &CrawlxRun, origin: &Url, keep_query: bool) -> Self {
        let mut o = Self {
            status: facade_status(&run.status),
            // Firecrawl's `total` is the number of scrape jobs it ran; crawlx's `attempted`
            // has that meaning (`admitted` can shrink after fetch when the URL plane
            // re-attributes exact/similar content duplicates to `deduplicated`).
            total: run.counters.attempted,
            completed: run.counters.succeeded,
            ..Self::default()
        };
        for p in &run.pages {
            let key = url_key(&p.url, origin, keep_query);
            o.attempted.insert(key.clone());
            o.pages.entry(key).or_insert_with(|| PageView {
                url: p.url.clone(),
                status: Some(p.status),
                title: p.title.clone(),
                description: p.description.clone(),
                language: p.language.clone(),
                content_type: p.content_type.clone(),
                markdown: p.markdown.clone(),
                links: link_keys(p.links.iter().map(String::as_str), origin),
            });
        }
        for status in [
            FrontierStatus::Succeeded,
            FrontierStatus::Failed,
            FrontierStatus::Unreachable,
        ] {
            for r in run.frontier_with(status) {
                o.attempted.insert(url_key(&r.url, origin, keep_query));
            }
        }
        // the entry URL that `includePaths` refused as a page is still fetched for its links
        // (Firecrawl lists it in `errors[]` as CRAWL_DENIAL, so its attempted set holds it)
        for r in run.frontier.iter().filter(|r| r.is_fetched_entry_denial()) {
            o.attempted.insert(url_key(&r.url, origin, keep_query));
        }
        for r in run.frontier_with(FrontierStatus::RobotsBlocked) {
            o.robots_blocked.insert(url_key(&r.url, origin, keep_query));
        }
        o.requested = run.access_log.as_ref().map(|l| l.requested(origin, keep_query));
        o
    }
}

/// Native status → the compat facade's Firecrawl status.
fn facade_status(native: &str) -> String {
    match native {
        "completed" | "failed" | "cancelled" => native.to_owned(),
        _ => "scraping".to_owned(),
    }
}

/// How serious a finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum Severity {
    /// Documented in the ledger; informational.
    Documented,
    /// Undocumented content, metadata or counter difference.
    Warning,
    /// Undocumented admission or robots difference.
    Blocking,
}

/// One difference, flattened for the scorecard and the verdict.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Finding {
    /// Severity.
    pub severity: Severity,
    /// Comparison.
    pub kind: DivergenceKind,
    /// URL key or counter field.
    pub subject: String,
    /// What differs.
    pub detail: String,
    /// Ledger id when documented.
    pub documented: Option<String>,
}

/// A URL in one system's set only.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct SetDiff {
    /// `admission` or `robots`.
    pub kind: DivergenceKind,
    /// Side.
    pub side: Side,
    /// URL key.
    pub key: String,
    /// Ledger id when documented.
    pub documented: Option<String>,
}

/// A metadata field that differs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct FieldDiff {
    /// Field name (`title`, `description`, `language`, `statusCode`, `contentType`).
    pub field: &'static str,
    /// Firecrawl value.
    pub firecrawl: String,
    /// crawlx value.
    pub crawlx: String,
    /// Ledger id when documented.
    pub documented: Option<String>,
}

/// Comparison of one page present on both sides.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct PageComparison {
    /// URL key.
    pub key: String,
    /// Normalized-token similarity; `None` when either side has no markdown.
    pub markdown_similarity: Option<f64>,
    /// Ledger id when a below-threshold similarity is documented.
    pub markdown_documented: Option<String>,
    /// Line diff of the normalized markdown (Firecrawl → crawlx).
    pub diff: LineDiff,
    /// Link-set Jaccard.
    pub links_jaccard: f64,
    /// Ledger id when a below-threshold link set is documented.
    pub links_documented: Option<String>,
    /// Differing metadata fields.
    pub metadata: Vec<FieldDiff>,
    /// Block-level F1 of the normalized markdown; `None` when either side has
    /// no markdown.
    pub block_f1: Option<f64>,
    /// Ordered-subsequence ratio of the markdown blocks; `None` without markdown or when the
    /// alignment budget is exceeded.
    pub ordered_ratio: Option<f64>,
    /// Ledger id when a below-threshold block F1 is documented.
    pub block_documented: Option<String>,
}

/// A counter or status that differs.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub struct CounterDiff {
    /// Field (`status`, `total`, `completed`, `attempted`, `robotsBlocked`).
    pub field: &'static str,
    /// Firecrawl value.
    pub firecrawl: String,
    /// crawlx value.
    pub crawlx: String,
    /// Ledger id when documented.
    pub documented: Option<String>,
}

/// Overall verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Verdict {
    /// No undocumented difference.
    Pass,
    /// Undocumented content/metadata/counter differences only.
    Warn,
    /// Undocumented admission or robots differences.
    Block,
}

/// The comparison result.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub struct Report {
    /// Label of the run (fixture id or free text).
    pub label: String,
    /// Thresholds applied.
    pub thresholds: Thresholds,
    /// Firecrawl status, crawlx facade status.
    pub status: (String, String),
    /// Attempted URL counts (Firecrawl, crawlx).
    pub attempted: (usize, usize),
    /// Succeeded page counts (Firecrawl, crawlx).
    pub pages_count: (usize, usize),
    /// Pages present on both sides.
    pub common_pages: usize,
    /// Admission and robots set differences.
    pub set_diffs: Vec<SetDiff>,
    /// Per-page comparisons, keyed order.
    pub pages: Vec<PageComparison>,
    /// Counter and status differences.
    pub counters: Vec<CounterDiff>,
    /// Corpus mean of the markdown similarity over compared pages.
    pub corpus_mean: Option<f64>,
    /// Metadata field equality rate over compared pages.
    pub metadata_rate: Option<f64>,
    /// Every finding, blocking first.
    pub findings: Vec<Finding>,
    /// Ledger entries no finding matched.
    pub unused_entries: Vec<String>,
    /// The admission sets were not compared (a `limit` below the site size makes the chosen
    /// subset order-dependent): only the cardinalities are.
    pub cardinality_only: bool,
    /// Distinct page URLs the fixture server saw requested (Firecrawl, crawlx); `None` when
    /// either side has no access log (a capture taken before it was recorded).
    pub requested: Option<(usize, usize)>,
    /// Total page requests the fixture server saw (Firecrawl, crawlx), with the access log.
    pub request_totals: Option<(u32, u32)>,
    /// Differences of the requested sets (C1).
    pub requested_diffs: Vec<SetDiff>,
    /// URLs both systems requested a different number of times (Firecrawl, crawlx), by key.
    pub request_count_diffs: Vec<(String, u32, u32)>,
    /// Corpus mean of the block-level F1 over compared pages (informational).
    pub block_corpus_mean: Option<f64>,
}

impl Report {
    /// The verdict.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        match self.findings.iter().map(|f| f.severity).max() {
            Some(Severity::Blocking) => Verdict::Block,
            Some(Severity::Warning) => Verdict::Warn,
            _ => Verdict::Pass,
        }
    }

    /// Process exit code: `0` pass (or warn unless `fail_on_warning`), `1` block, `3` warn
    /// with `fail_on_warning`.
    #[must_use]
    pub fn exit_code(&self, fail_on_warning: bool) -> u8 {
        match self.verdict() {
            Verdict::Pass => 0,
            Verdict::Warn if fail_on_warning => 3,
            Verdict::Warn => 0,
            Verdict::Block => 1,
        }
    }

    fn count(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }

    /// The markdown scorecard.
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn to_markdown(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# Differential scorecard: {}\n", self.label);
        let _ = writeln!(
            out,
            "Verdict: **{:?}** ({} blocking, {} warnings, {} documented)\n",
            self.verdict(),
            self.count(Severity::Blocking),
            self.count(Severity::Warning),
            self.count(Severity::Documented)
        );
        let _ = writeln!(out, "| Metric | Firecrawl | crawlx | Threshold |");
        let _ = writeln!(out, "|---|---:|---:|---:|");
        let _ = writeln!(out, "| status | {} | {} | equal |", self.status.0, self.status.1);
        let _ = writeln!(
            out,
            "| attempted URLs | {} | {} | equal |",
            self.attempted.0, self.attempted.1
        );
        let _ = writeln!(
            out,
            "| succeeded pages | {} | {} | equal |",
            self.pages_count.0, self.pages_count.1
        );
        let _ = writeln!(
            out,
            "| pages compared | {} | {} | |",
            self.common_pages, self.common_pages
        );
        let _ = writeln!(
            out,
            "| markdown similarity, corpus mean | {} | | ≥ {:.2} |",
            self.corpus_mean.map_or("n/a".to_owned(), |m| format!("{m:.4}")),
            self.thresholds.markdown_corpus
        );
        let _ = writeln!(
            out,
            "| metadata field equality | {} | | ≥ {:.2} |",
            self.metadata_rate.map_or("n/a".to_owned(), |m| format!("{m:.4}")),
            self.thresholds.metadata
        );
        let _ = writeln!(
            out,
            "| block F1, corpus mean (informational) | {} | | per page ≥ {:.2} |",
            self.block_corpus_mean
                .map_or("n/a".to_owned(), |m| format!("{m:.4}")),
            self.thresholds.block_f1
        );

        let _ = writeln!(out, "\n## C1 admission\n");
        if self.cardinality_only {
            let _ = writeln!(
                out,
                "Admission sets are not compared (`limit` below the site size); the attempted cardinalities are compared above and as the `total` counter. Robots-blocked sets are compared.\n"
            );
        }
        if self.set_diffs.is_empty() {
            let _ = writeln!(
                out,
                "{}",
                if self.cardinality_only {
                    "Robots-blocked sets are equal."
                } else {
                    "Attempted and robots-blocked sets are equal."
                }
            );
        } else {
            let _ = writeln!(out, "| Set | Only in | URL | Ledger |");
            let _ = writeln!(out, "|---|---|---|---|");
            for d in &self.set_diffs {
                let _ = writeln!(
                    out,
                    "| {} | {} | `{}` | {} |",
                    kind_name(d.kind),
                    side_name(d.side),
                    d.key,
                    d.documented.as_deref().unwrap_or("**undocumented**")
                );
            }
        }

        let _ = writeln!(out, "\n## C1 requested set (fixture access log)\n");
        match (self.requested, self.request_totals) {
            (Some((a, b)), Some((ta, tb))) => {
                let _ = writeln!(
                    out,
                    "| | Firecrawl | crawlx |\n|---|---:|---:|\n| distinct page URLs requested | {a} | {b} |\n| page requests | {ta} | {tb} |\n"
                );
                if self.cardinality_only {
                    let _ = writeln!(
                        out,
                        "Requested sets are not compared (`limit` below the site size)."
                    );
                } else if self.requested_diffs.is_empty() {
                    let _ = writeln!(out, "Requested sets are equal.");
                } else {
                    let _ = writeln!(out, "| Only in | URL | Ledger |\n|---|---|---|");
                    for d in &self.requested_diffs {
                        let _ = writeln!(
                            out,
                            "| {} | `{}` | {} |",
                            side_name(d.side),
                            d.key,
                            d.documented.as_deref().unwrap_or("**undocumented**")
                        );
                    }
                }
                if !self.request_count_diffs.is_empty() {
                    let _ = writeln!(
                        out,
                        "\nURLs requested a different number of times (informational):\n"
                    );
                    let _ = writeln!(out, "| URL | Firecrawl | crawlx |\n|---|---:|---:|");
                    for (key, a, b) in &self.request_count_diffs {
                        let _ = writeln!(out, "| `{key}` | {a} | {b} |");
                    }
                }
            }
            _ => {
                let _ = writeln!(out, "Not recorded for this pair (a side has no access log).");
            }
        }

        let _ = writeln!(out, "\n## C2 content\n");
        let _ = writeln!(out, "| URL | Markdown | Block F1 | Links | Metadata | Ledger |");
        let _ = writeln!(out, "|---|---:|---:|---:|---|---|");
        for p in &self.pages {
            let md = p
                .markdown_similarity
                .map_or("n/a".to_owned(), |s| format!("{s:.4}"));
            let blocks = p.block_f1.map_or("n/a".to_owned(), |s| format!("{s:.4}"));
            let meta = if p.metadata.is_empty() {
                "ok".to_owned()
            } else {
                p.metadata.iter().map(|f| f.field).collect::<Vec<_>>().join(", ")
            };
            let mut ledger: Vec<&str> = p
                .markdown_documented
                .iter()
                .chain(p.block_documented.iter())
                .chain(p.links_documented.iter())
                .chain(p.metadata.iter().filter_map(|f| f.documented.as_ref()))
                .map(String::as_str)
                .collect();
            ledger.dedup();
            let _ = writeln!(
                out,
                "| `{}` | {md} | {blocks} | {:.4} | {meta} | {} |",
                p.key,
                p.links_jaccard,
                ledger.join(", ")
            );
        }
        let below: Vec<&PageComparison> = self
            .pages
            .iter()
            .filter(|p| {
                p.markdown_similarity
                    .is_some_and(|s| s < self.thresholds.markdown_page)
                    || p.block_f1.is_some_and(|b| b < self.thresholds.block_f1)
                    || !p.metadata.is_empty()
            })
            .collect();
        if !below.is_empty() {
            let _ = writeln!(out, "\n### Differences\n");
            for p in below {
                let _ = writeln!(out, "#### `{}`\n", p.key);
                for f in &p.metadata {
                    let _ = writeln!(
                        out,
                        "- metadata `{}`: firecrawl `{}` vs crawlx `{}`{}",
                        f.field,
                        f.firecrawl,
                        f.crawlx,
                        f.documented
                            .as_deref()
                            .map_or(String::new(), |d| format!(" ({d})"))
                    );
                }
                if !p.diff.is_empty() {
                    let _ = writeln!(out, "\n```diff");
                    for l in p.diff.removed.iter().take(20) {
                        let _ = writeln!(out, "- {l}");
                    }
                    for l in p.diff.added.iter().take(20) {
                        let _ = writeln!(out, "+ {l}");
                    }
                    if p.diff.removed.len() > 20 || p.diff.added.len() > 20 {
                        let _ = writeln!(
                            out,
                            "… {} removed, {} added in total",
                            p.diff.removed.len(),
                            p.diff.added.len()
                        );
                    }
                    let _ = writeln!(out, "```");
                }
                out.push('\n');
            }
        }

        let _ = writeln!(out, "\n## C3 counters\n");
        if self.counters.is_empty() {
            let _ = writeln!(out, "Status and counters agree.");
        } else {
            let _ = writeln!(out, "| Field | Firecrawl | crawlx | Ledger |");
            let _ = writeln!(out, "|---|---:|---:|---|");
            for c in &self.counters {
                let _ = writeln!(
                    out,
                    "| {} | {} | {} | {} |",
                    c.field,
                    c.firecrawl,
                    c.crawlx,
                    c.documented.as_deref().unwrap_or("undocumented")
                );
            }
        }

        let _ = writeln!(out, "\n## Findings\n");
        if self.findings.is_empty() {
            let _ = writeln!(out, "None.");
        }
        for f in &self.findings {
            let _ = writeln!(
                out,
                "- {:?} {} `{}`: {}{}",
                f.severity,
                kind_name(f.kind),
                f.subject,
                f.detail,
                f.documented
                    .as_deref()
                    .map_or(String::new(), |d| format!(" [{d}]"))
            );
        }
        if !self.unused_entries.is_empty() {
            let _ = writeln!(
                out,
                "\nLedger entries not exercised: {}",
                self.unused_entries.join(", ")
            );
        }
        out
    }
}

const fn kind_name(k: DivergenceKind) -> &'static str {
    match k {
        DivergenceKind::Admission => "admission",
        DivergenceKind::Robots => "robots",
        DivergenceKind::Markdown => "markdown",
        DivergenceKind::Links => "links",
        DivergenceKind::Metadata => "metadata",
        DivergenceKind::Counter => "counter",
        DivergenceKind::Requested => "requested",
        DivergenceKind::Behavior => "behavior",
    }
}

const fn side_name(s: Side) -> &'static str {
    match s {
        Side::FirecrawlOnly => "firecrawl",
        Side::CrawlxOnly => "crawlx",
    }
}

/// Compares one Firecrawl export with one crawlx run under a ledger and thresholds.
#[derive(Clone, Debug)]
#[must_use]
pub struct DifferentialRunner {
    /// The whole ledger.
    all: Ledger,
    /// The entries that apply to `label` (those without a `families` list and those naming it).
    ledger: Ledger,
    thresholds: Thresholds,
    keep_query: bool,
    cardinality_only: bool,
    label: String,
}

impl DifferentialRunner {
    /// A runner over `ledger` with plan-default thresholds, comparing URLs with their full
    /// query (`keep_all`).
    pub fn new(ledger: Ledger) -> Self {
        let label = "differential".to_owned();
        Self {
            ledger: ledger.for_family(&label),
            all: ledger,
            thresholds: Thresholds::default(),
            keep_query: true,
            cardinality_only: false,
            label,
        }
    }

    /// Override thresholds.
    pub fn with_thresholds(mut self, thresholds: Thresholds) -> Self {
        self.thresholds = thresholds;
        self
    }

    /// Strip tracking parameters from URL keys before comparing admission (use when the crawlx
    /// run was made with `classify`).
    pub fn with_keep_query(mut self, keep_query: bool) -> Self {
        self.keep_query = keep_query;
        self
    }

    /// Compare only the cardinality of the attempted sets (`limit` below the site size: which
    /// subset a crawler keeps depends on its traversal order).
    pub fn with_cardinality_only(mut self, cardinality_only: bool) -> Self {
        self.cardinality_only = cardinality_only;
        self
    }

    /// Label printed in the scorecard. It is also the family id: ledger entries that list
    /// `families` apply only when the label is one of them.
    pub fn with_label(mut self, label: impl Into<String>) -> Self {
        self.label = label.into();
        self.ledger = self.all.for_family(&self.label);
        self
    }

    /// Compare. `firecrawl_origin` and `crawlx_origin` are the origins each system crawled
    /// (they differ when the fixture ran on two hosts or ports).
    #[must_use]
    #[allow(clippy::too_many_lines)]
    pub fn compare(
        &self,
        firecrawl: &FirecrawlExport,
        firecrawl_origin: &Url,
        crawlx: &CrawlxRun,
        crawlx_origin: &Url,
    ) -> Report {
        let fc = Observed::firecrawl(firecrawl, firecrawl_origin, self.keep_query);
        let cx = Observed::crawlx(crawlx, crawlx_origin, self.keep_query);
        let mut findings = Vec::new();
        let mut used: BTreeSet<String> = BTreeSet::new();

        // C1
        let mut set_diffs = Vec::new();
        for (kind, a, b) in [
            (DivergenceKind::Admission, &fc.attempted, &cx.attempted),
            (DivergenceKind::Robots, &fc.robots_blocked, &cx.robots_blocked),
        ] {
            if kind == DivergenceKind::Admission && self.cardinality_only {
                continue;
            }
            for (side, keys) in [
                (Side::FirecrawlOnly, a.difference(b)),
                (Side::CrawlxOnly, b.difference(a)),
            ] {
                for key in keys {
                    let documented = self.ledger.admission(kind, side, key).map(|d| d.id.clone());
                    if let Some(id) = &documented {
                        used.insert(id.clone());
                    }
                    findings.push(Finding {
                        severity: if documented.is_some() {
                            Severity::Documented
                        } else {
                            Severity::Blocking
                        },
                        kind,
                        subject: key.clone(),
                        detail: format!("only {} attempted it", side_name(side)),
                        documented: documented.clone(),
                    });
                    set_diffs.push(SetDiff {
                        kind,
                        side,
                        key: key.clone(),
                        documented,
                    });
                }
            }
        }

        // C1, requested set: what the fixture server saw, when both sides recorded it. Skipped
        // with the admission sets under `cardinality_only` (a kept subset is order-dependent).
        let mut requested_diffs = Vec::new();
        let mut request_count_diffs = Vec::new();
        if let (Some(a), Some(b)) = (&fc.requested, &cx.requested) {
            if !self.cardinality_only {
                let only_fc: Vec<&String> = a.keys().filter(|k| !b.contains_key(*k)).collect();
                let only_cx: Vec<&String> = b.keys().filter(|k| !a.contains_key(*k)).collect();
                for (side, keys) in [(Side::FirecrawlOnly, only_fc), (Side::CrawlxOnly, only_cx)] {
                    for key in keys {
                        // an admission entry documents the same URL difference in the requested set
                        let documented = self
                            .ledger
                            .admission(DivergenceKind::Requested, side, key)
                            .or_else(|| self.ledger.admission(DivergenceKind::Admission, side, key))
                            .map(|d| d.id.clone());
                        if let Some(id) = &documented {
                            used.insert(id.clone());
                        }
                        findings.push(Finding {
                            severity: if documented.is_some() {
                                Severity::Documented
                            } else {
                                Severity::Blocking
                            },
                            kind: DivergenceKind::Requested,
                            subject: key.clone(),
                            detail: format!("only {} requested it (fixture access log)", side_name(side)),
                            documented: documented.clone(),
                        });
                        requested_diffs.push(SetDiff {
                            kind: DivergenceKind::Requested,
                            side,
                            key: key.clone(),
                            documented,
                        });
                    }
                }
                for (key, n) in a {
                    if let Some(m) = b.get(key) {
                        if n != m {
                            request_count_diffs.push((key.clone(), *n, *m));
                        }
                    }
                }
            }
        }

        // C2
        let mut pages = Vec::new();
        let mut sims = Vec::new();
        let mut block_sims = Vec::new();
        let mut fields_total = 0usize;
        let mut fields_equal = 0usize;
        for (key, f) in &fc.pages {
            let Some(c) = cx.pages.get(key) else { continue };
            let page_f = Url::parse(&f.url).unwrap_or_else(|_| firecrawl_origin.clone());
            let page_c = Url::parse(&c.url).unwrap_or_else(|_| crawlx_origin.clone());
            let (markdown_similarity, diff, blocks) = match (&f.markdown, &c.markdown) {
                (Some(a), Some(b)) => {
                    let na = normalize_markdown(a, &page_f, firecrawl_origin);
                    let nb = normalize_markdown(b, &page_c, crawlx_origin);
                    let (ba, bb) = (markdown_blocks(&na), markdown_blocks(&nb));
                    (
                        Some(token_jaccard(&na, &nb)),
                        line_diff(&na, &nb),
                        Some((block_f1(&ba, &bb), ordered_subsequence_ratio(&ba, &bb))),
                    )
                }
                _ => (None, LineDiff::default(), None),
            };
            let mut markdown_documented = None;
            if let Some(s) = markdown_similarity {
                sims.push(s);
                if s < self.thresholds.markdown_page {
                    markdown_documented = self
                        .ledger
                        .page(DivergenceKind::Markdown, key, None)
                        .map(|d| d.id.clone());
                    push_page_finding(
                        &mut findings,
                        &mut used,
                        DivergenceKind::Markdown,
                        key,
                        format!(
                            "similarity {s:.4} below {:.2} ({} lines removed, {} added)",
                            self.thresholds.markdown_page,
                            diff.removed.len(),
                            diff.added.len()
                        ),
                        markdown_documented.clone(),
                    );
                }
            }
            let (block_f1_value, ordered_ratio) =
                blocks.map_or((None, None), |(bf, ordered)| (Some(bf), ordered));
            let mut block_documented = None;
            if let Some(bf) = block_f1_value {
                block_sims.push(bf);
                if bf < self.thresholds.block_f1 {
                    block_documented = self
                        .ledger
                        .page(DivergenceKind::Markdown, key, None)
                        .map(|d| d.id.clone());
                    push_page_finding(
                        &mut findings,
                        &mut used,
                        DivergenceKind::Markdown,
                        key,
                        format!(
                            "block F1 {bf:.4} below {:.2} (ordered-subsequence ratio {})",
                            self.thresholds.block_f1,
                            ordered_ratio.map_or("n/a".to_owned(), |r| format!("{r:.4}"))
                        ),
                        block_documented.clone(),
                    );
                }
            }
            let links_jaccard = set_jaccard(&f.links, &c.links);
            let mut links_documented = None;
            if links_jaccard < self.thresholds.links {
                links_documented = self
                    .ledger
                    .page(DivergenceKind::Links, key, None)
                    .map(|d| d.id.clone());
                let only_f: Vec<&String> = f.links.difference(&c.links).collect();
                let only_c: Vec<&String> = c.links.difference(&f.links).collect();
                push_page_finding(
                    &mut findings,
                    &mut used,
                    DivergenceKind::Links,
                    key,
                    format!(
                        "link jaccard {links_jaccard:.4} below {:.2}; firecrawl-only {only_f:?}, crawlx-only {only_c:?}",
                        self.thresholds.links
                    ),
                    links_documented.clone(),
                );
            }
            let mut metadata = Vec::new();
            let fields: [(&'static str, Option<String>, Option<String>); 5] = [
                ("title", f.title.clone(), c.title.clone()),
                ("description", f.description.clone(), c.description.clone()),
                ("language", f.language.clone(), c.language.clone()),
                (
                    "statusCode",
                    f.status.map(|s| s.to_string()),
                    c.status.map(|s| s.to_string()),
                ),
                ("contentType", f.content_type.clone(), c.content_type.clone()),
            ];
            for (field, a, b) in fields {
                fields_total += 1;
                if a == b {
                    fields_equal += 1;
                    continue;
                }
                let documented = self
                    .ledger
                    .page(DivergenceKind::Metadata, key, Some(field))
                    .map(|d| d.id.clone());
                let (fa, fb) = (a.unwrap_or_default(), b.unwrap_or_default());
                push_page_finding(
                    &mut findings,
                    &mut used,
                    DivergenceKind::Metadata,
                    key,
                    format!("{field}: firecrawl `{fa}` vs crawlx `{fb}`"),
                    documented.clone(),
                );
                metadata.push(FieldDiff {
                    field,
                    firecrawl: fa,
                    crawlx: fb,
                    documented,
                });
            }
            pages.push(PageComparison {
                key: key.clone(),
                markdown_similarity,
                markdown_documented,
                diff,
                links_jaccard,
                links_documented,
                metadata,
                block_f1: block_f1_value,
                ordered_ratio,
                block_documented,
            });
        }
        let corpus_mean = mean(&sims);
        let block_corpus_mean = mean(&block_sims);
        if let Some(m) = corpus_mean {
            if m < self.thresholds.markdown_corpus {
                let documented = self.ledger.counter("markdown_corpus_mean").map(|d| d.id.clone());
                push_page_finding(
                    &mut findings,
                    &mut used,
                    DivergenceKind::Counter,
                    "markdown_corpus_mean",
                    format!("{m:.4} below {:.2}", self.thresholds.markdown_corpus),
                    documented,
                );
            }
        }
        let metadata_rate = (fields_total > 0).then(|| ratio(fields_equal, fields_total));
        if let Some(r) = metadata_rate {
            if r < self.thresholds.metadata {
                let documented = self.ledger.counter("metadata_rate").map(|d| d.id.clone());
                push_page_finding(
                    &mut findings,
                    &mut used,
                    DivergenceKind::Counter,
                    "metadata_rate",
                    format!("{r:.4} below {:.2}", self.thresholds.metadata),
                    documented,
                );
            }
        }

        // C3 (attempted and robots cardinalities are covered by the C1 set differences). A
        // `total`/`completed` delta that equals the net count of documented admission
        // differences is explained by those entries.
        let mut counters = Vec::new();
        let (mut total_delta, mut completed_delta): (i64, i64) = (0, 0);
        let mut explaining: BTreeSet<&str> = BTreeSet::new();
        for d in set_diffs.iter().filter(|d| d.kind == DivergenceKind::Admission) {
            let Some(id) = d.documented.as_deref() else {
                continue;
            };
            let (sign, pages) = match d.side {
                Side::FirecrawlOnly => (1, &fc.pages),
                Side::CrawlxOnly => (-1, &cx.pages),
            };
            explaining.insert(id);
            total_delta += sign;
            if pages.contains_key(&d.key) {
                completed_delta += sign;
            }
        }
        let explained_by = explaining.into_iter().collect::<Vec<_>>().join(", ");
        let signed = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
        let pairs: [(&'static str, String, String, i64); 3] = [
            ("status", fc.status.clone(), cx.status.clone(), 0),
            (
                "total",
                fc.total.to_string(),
                cx.total.to_string(),
                signed(fc.total) - signed(cx.total),
            ),
            (
                "completed",
                fc.completed.to_string(),
                cx.completed.to_string(),
                signed(fc.completed) - signed(cx.completed),
            ),
        ];
        for (field, a, b, delta) in pairs {
            if a == b {
                continue;
            }
            let expected = match field {
                "total" => total_delta,
                "completed" => completed_delta,
                _ => 0,
            };
            let documented = if expected != 0 && delta == expected {
                Some(explained_by.clone())
            } else {
                self.ledger.counter(field).map(|d| d.id.clone())
            };
            push_page_finding(
                &mut findings,
                &mut used,
                DivergenceKind::Counter,
                field,
                format!("firecrawl {a} vs crawlx {b}"),
                documented.clone(),
            );
            counters.push(CounterDiff {
                field,
                firecrawl: a,
                crawlx: b,
                documented,
            });
        }

        findings.sort_by(|a, b| {
            b.severity
                .cmp(&a.severity)
                .then_with(|| a.subject.cmp(&b.subject))
        });
        let unused_entries = self
            .ledger
            .entries
            .iter()
            .filter(|e| !used.contains(&e.id))
            .map(|e| e.id.clone())
            .collect();
        Report {
            label: self.label.clone(),
            thresholds: self.thresholds,
            status: (fc.status, cx.status),
            attempted: (fc.attempted.len(), cx.attempted.len()),
            pages_count: (fc.pages.len(), cx.pages.len()),
            common_pages: pages.len(),
            set_diffs,
            pages,
            counters,
            corpus_mean,
            metadata_rate,
            findings,
            unused_entries,
            cardinality_only: self.cardinality_only,
            requested: fc
                .requested
                .as_ref()
                .zip(cx.requested.as_ref())
                .map(|(a, b)| (a.len(), b.len())),
            request_totals: fc
                .requested
                .as_ref()
                .zip(cx.requested.as_ref())
                .map(|(a, b)| (a.values().sum(), b.values().sum())),
            requested_diffs,
            request_count_diffs,
            block_corpus_mean,
        }
    }
}

fn push_page_finding(
    findings: &mut Vec<Finding>,
    used: &mut BTreeSet<String>,
    kind: DivergenceKind,
    subject: &str,
    detail: String,
    documented: Option<String>,
) {
    if let Some(id) = &documented {
        used.insert(id.clone());
    }
    findings.push(Finding {
        severity: if documented.is_some() {
            Severity::Documented
        } else {
            Severity::Warning
        },
        kind,
        subject: subject.to_owned(),
        detail,
        documented,
    });
}

fn ratio(num: usize, den: usize) -> f64 {
    // page and field counts; exact in f64
    #[allow(clippy::cast_precision_loss)]
    {
        num as f64 / den as f64
    }
}

fn mean(xs: &[f64]) -> Option<f64> {
    if xs.is_empty() {
        None
    } else {
        #[allow(clippy::cast_precision_loss)]
        Some(xs.iter().sum::<f64>() / xs.len() as f64)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn doc(url: &str, md: &str, links: &[&str]) -> FirecrawlDocument {
        FirecrawlDocument {
            markdown: Some(md.to_owned()),
            links: links.iter().map(|s| (*s).to_owned()).collect(),
            metadata: FirecrawlMetadata {
                source_url: url.to_owned(),
                status_code: Some(200),
                title: Some("T".to_owned()),
                language: Some("en".to_owned()),
                content_type: Some("text/html; charset=utf-8".to_owned()),
                ..FirecrawlMetadata::default()
            },
        }
    }

    fn page(url: &str, md: &str, links: &[&str]) -> CrawlxPage {
        CrawlxPage {
            url: url.to_owned(),
            status: 200,
            title: Some("T".to_owned()),
            language: Some("en".to_owned()),
            content_type: Some("text/html; charset=utf-8".to_owned()),
            markdown: Some(md.to_owned()),
            links: links.iter().map(|s| (*s).to_owned()).collect(),
            ..CrawlxPage::default()
        }
    }

    fn row(url: &str, status: &str) -> CrawlxFrontierRow {
        CrawlxFrontierRow {
            url: url.to_owned(),
            status: status.to_owned(),
            reason: None,
            depth: None,
        }
    }

    #[test]
    fn equal_runs_pass_across_origins() {
        let fc = FirecrawlExport {
            status: "completed".to_owned(),
            total: 2,
            completed: 1,
            data: vec![doc(
                "http://a.test/s/",
                "# Hi\n\n* [x](/s/x/)",
                &["http://a.test/s/x/"],
            )],
            errors: FirecrawlErrors {
                errors: vec![FirecrawlError {
                    url: "http://a.test/s/x/".to_owned(),
                    code: "404".to_owned(),
                    ..FirecrawlError::default()
                }],
                robots_blocked: vec!["http://a.test/s/p".to_owned()],
            },
            ..FirecrawlExport::default()
        };
        let mut cx = CrawlxRun {
            status: "completed".to_owned(),
            pages: vec![page(
                "http://127.0.0.1:9/s",
                "Hi\n==\n\n- [x](http://127.0.0.1:9/s/x)",
                &["http://127.0.0.1:9/s/x"],
            )],
            frontier: vec![
                row("http://127.0.0.1:9/s", "succeeded"),
                row("http://127.0.0.1:9/s/x", "failed"),
                row("http://127.0.0.1:9/s/p", "robots_blocked"),
            ],
            ..CrawlxRun::default()
        };
        cx.counters.admitted = 2;
        cx.counters.attempted = 2;
        cx.counters.succeeded = 1;
        let r = DifferentialRunner::new(Ledger::default()).compare(
            &fc,
            &Url::parse("http://a.test").unwrap(),
            &cx,
            &Url::parse("http://127.0.0.1:9").unwrap(),
        );
        assert_eq!(r.verdict(), Verdict::Pass, "{}", r.to_markdown());
        assert_eq!(r.common_pages, 1);
        assert!((r.corpus_mean.unwrap() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn undocumented_admission_blocks_and_documented_passes() {
        let fc = FirecrawlExport {
            status: "completed".to_owned(),
            data: vec![
                doc("http://a.test/s/", "x", &[]),
                doc("http://a.test/s/?utm_source=n", "x", &[]),
            ],
            ..FirecrawlExport::default()
        };
        let cx = CrawlxRun {
            status: "completed".to_owned(),
            pages: vec![page("http://a.test/s", "x", &[])],
            ..CrawlxRun::default()
        };
        let o = Url::parse("http://a.test").unwrap();
        let r = DifferentialRunner::new(Ledger::default()).compare(&fc, &o, &cx, &o);
        assert_eq!(r.verdict(), Verdict::Block);
        assert_eq!(r.exit_code(false), 1);
        let ledger = Ledger::parse(
            r#"
[[divergence]]
id = "QRY-001"
family = "QRY"
level = "C1"
kind = "admission"
side = "firecrawl_only"
match = "*?utm_*"
class = "intentional_correctness"
source = "adr:0018"
rationale = "r"
user_visible = "u"
"#,
        )
        .unwrap();
        let r = DifferentialRunner::new(ledger).compare(&fc, &o, &cx, &o);
        assert_eq!(r.verdict(), Verdict::Pass, "{}", r.to_markdown());
        assert_eq!(r.findings[0].documented.as_deref(), Some("QRY-001"));
        assert!(r.unused_entries.is_empty());
    }

    #[test]
    fn a_fetched_include_denied_seed_is_attempted_like_firecrawls_crawl_denial() {
        let fc = FirecrawlExport {
            status: "completed".to_owned(),
            total: 1,
            completed: 1,
            data: vec![doc("http://a.test/s/docs", "x", &[])],
            errors: FirecrawlErrors {
                errors: vec![FirecrawlError {
                    url: "http://a.test/s/".to_owned(),
                    code: "CRAWL_DENIAL".to_owned(),
                    ..FirecrawlError::default()
                }],
                robots_blocked: Vec::new(),
            },
            ..FirecrawlExport::default()
        };
        let denied = |depth| CrawlxFrontierRow {
            reason: Some("not_included".to_owned()),
            depth,
            ..row("http://a.test/s", "policy_blocked")
        };
        let mut cx = CrawlxRun {
            status: "completed".to_owned(),
            pages: vec![page("http://a.test/s/docs", "x", &[])],
            frontier: vec![row("http://a.test/s/docs", "succeeded"), denied(Some(0))],
            ..CrawlxRun::default()
        };
        cx.counters.attempted = 1;
        cx.counters.succeeded = 1;
        let o = Url::parse("http://a.test").unwrap();
        let r = DifferentialRunner::new(Ledger::default()).compare(&fc, &o, &cx, &o);
        assert_eq!(r.verdict(), Verdict::Pass, "{}", r.to_markdown());
        assert_eq!(r.attempted, (2, 2));
        // a link refused deeper in the tree (or a row of unknown depth) was never fetched
        for depth in [Some(1), None] {
            cx.frontier[1] = denied(depth);
            let r = DifferentialRunner::new(Ledger::default()).compare(&fc, &o, &cx, &o);
            assert_eq!(r.verdict(), Verdict::Block, "{depth:?}");
        }
    }

    #[test]
    fn content_below_threshold_warns_only() {
        let fc = FirecrawlExport {
            status: "completed".to_owned(),
            data: vec![doc(
                "http://a.test/s/",
                "one two three four five six seven eight nine ten",
                &[],
            )],
            ..FirecrawlExport::default()
        };
        let cx = CrawlxRun {
            status: "completed".to_owned(),
            pages: vec![page(
                "http://a.test/s",
                "one two three four five six seven eight nine",
                &[],
            )],
            ..CrawlxRun::default()
        };
        let o = Url::parse("http://a.test").unwrap();
        let r = DifferentialRunner::new(Ledger::default()).compare(&fc, &o, &cx, &o);
        assert_eq!(r.verdict(), Verdict::Warn);
        assert_eq!(r.exit_code(false), 0);
        assert_eq!(r.exit_code(true), 3);
        assert!(r.to_markdown().contains("```diff"));
    }

    fn entry(path: &str, host: &str) -> AccessEntry {
        AccessEntry {
            method: "GET".to_owned(),
            path: path.to_owned(),
            host: Some(host.to_owned()),
            ..AccessEntry::default()
        }
    }

    #[test]
    fn the_requested_set_is_compared_documented_and_counted() {
        let fc = FirecrawlExport {
            status: "completed".to_owned(),
            data: vec![doc("http://a.test:4101/s/", "x", &[])],
            access_log: Some(AccessLog {
                entries: vec![
                    entry("/robots.txt", "a.test:4101"),
                    entry("/s/", "a.test:4101"),
                    entry("/s/hidden", "a.test:4101"),
                    entry("/s/twice", "a.test:4101"),
                    entry("/s/twice", "a.test:4101"),
                    entry("/s/sub", "app.a.test:4101"),
                ],
            }),
            ..FirecrawlExport::default()
        };
        let cx = CrawlxRun {
            status: "completed".to_owned(),
            pages: vec![page("http://a.test:9/s", "x", &[])],
            access_log: Some(AccessLog {
                entries: vec![
                    entry("/robots.txt", "a.test:9"),
                    entry("/s/", "a.test:9"),
                    entry("/s/twice", "a.test:9"),
                    entry("/s/sub", "app.a.test:9"),
                    entry("/s/extra", "a.test:9"),
                ],
            }),
            ..CrawlxRun::default()
        };
        let fo = Url::parse("http://a.test:4101").unwrap();
        let co = Url::parse("http://a.test:9").unwrap();
        let r = DifferentialRunner::new(Ledger::default()).compare(&fc, &fo, &cx, &co);
        assert_eq!(r.verdict(), Verdict::Block, "{}", r.to_markdown());
        assert_eq!(r.requested, Some((4, 4)));
        assert_eq!(r.request_totals, Some((5, 4)));
        let diffs: Vec<(&str, Side)> = r
            .requested_diffs
            .iter()
            .map(|d| (d.key.as_str(), d.side))
            .collect();
        assert_eq!(
            diffs,
            vec![
                ("{origin}/s/hidden", Side::FirecrawlOnly),
                ("{origin}/s/extra", Side::CrawlxOnly)
            ]
        );
        // the URL requested twice by one side only is informational, not a finding
        assert_eq!(r.request_count_diffs, vec![("{origin}/s/twice".to_owned(), 2, 1)]);
        assert!(r.to_markdown().contains("## C1 requested set"));

        // an admission entry documents the same URL in the requested set; a `requested` entry too
        let ledger = Ledger::parse(
            r#"
[[divergence]]
id = "T-1"
family = "T"
level = "C1"
kind = "admission"
side = "firecrawl_only"
match = "*/s/hidden"
class = "intentional_correctness"
source = "s"
rationale = "r"
user_visible = "u"
[[divergence]]
id = "T-2"
family = "T"
level = "C1"
kind = "requested"
side = "crawlx_only"
match = "*/s/extra"
class = "unsupported_feature"
source = "s"
rationale = "r"
"#,
        )
        .unwrap();
        let r = DifferentialRunner::new(ledger).compare(&fc, &fo, &cx, &co);
        assert_eq!(r.verdict(), Verdict::Pass, "{}", r.to_markdown());
        assert!(r.requested_diffs.iter().all(|d| d.documented.is_some()));
        assert!(r.unused_entries.is_empty(), "{:?}", r.unused_entries);

        // a side without a log leaves the comparison out
        let mut no_log = cx.clone();
        no_log.access_log = None;
        let r = DifferentialRunner::new(Ledger::default()).compare(&fc, &fo, &no_log, &co);
        assert_eq!(r.requested, None);
        assert!(r.to_markdown().contains("Not recorded for this pair"));
    }

    #[test]
    fn block_f1_warns_where_the_token_similarity_is_perfect() {
        let fc = FirecrawlExport {
            status: "completed".to_owned(),
            data: vec![doc("http://a.test/s/", "# T\n\none two\n\nthree four", &[])],
            ..FirecrawlExport::default()
        };
        let cx = CrawlxRun {
            status: "completed".to_owned(),
            pages: vec![page("http://a.test/s", "# T\n\none two three four", &[])],
            ..CrawlxRun::default()
        };
        let o = Url::parse("http://a.test").unwrap();
        let r = DifferentialRunner::new(Ledger::default()).compare(&fc, &o, &cx, &o);
        let p = &r.pages[0];
        assert!((p.markdown_similarity.unwrap() - 1.0).abs() < f64::EPSILON);
        assert!((p.block_f1.unwrap() - 0.4).abs() < 1e-9);
        assert!(p.ordered_ratio.is_some());
        assert_eq!(r.verdict(), Verdict::Warn, "{}", r.to_markdown());
        assert!(r.to_markdown().contains("block F1 0.4000 below 0.80"));
        // a markdown entry for the page documents the block finding too
        let ledger = Ledger::parse(
            r#"
[[divergence]]
id = "T-3"
family = "T"
level = "C2"
kind = "markdown"
match = "*/s"
class = "intentional_correctness"
source = "s"
rationale = "r"
user_visible = "u"
"#,
        )
        .unwrap();
        let r = DifferentialRunner::new(ledger).compare(&fc, &o, &cx, &o);
        assert_eq!(r.verdict(), Verdict::Pass, "{}", r.to_markdown());
        assert_eq!(r.pages[0].block_documented.as_deref(), Some("T-3"));
        // identical pages have block F1 1 and the corpus mean says so
        let same = CrawlxRun {
            pages: vec![page("http://a.test/s", "# T\n\none two\n\nthree four", &[])],
            ..cx
        };
        let r = DifferentialRunner::new(Ledger::default()).compare(&fc, &o, &same, &o);
        assert_eq!(r.verdict(), Verdict::Pass);
        assert!((r.block_corpus_mean.unwrap() - 1.0).abs() < f64::EPSILON);
    }
}
