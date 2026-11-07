//! Full-text search over a directory of Markdown documents (`docs/` of the repository or the
//! operator's `intel.docsDir`), behind `/support/docs-search` and `/support/ask`.
//!
//! Files are split into chunks at Markdown headings; chunks are ranked with BM25
//! (`k1 = 1.2`, `b = 0.75`) over lowercase alphanumeric tokens. The index is built once per
//! process, off the async runtime.

use crate::state::AppState;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Markdown files indexed at most.
pub const MAX_FILES: usize = 2_000;
/// Largest file read, bytes.
pub const MAX_FILE_BYTES: u64 = 1_048_576;
/// Chunks longer than this are split at paragraph boundaries, characters.
const MAX_CHUNK_CHARS: usize = 2_400;

/// One searchable passage.
#[derive(Clone, Debug)]
pub struct Chunk {
    /// File path relative to the docs root (`integrations.md`).
    pub path: String,
    /// Nearest heading above the passage (empty before the first heading).
    pub heading: String,
    /// Passage text.
    pub text: String,
    terms: BTreeMap<String, u32>,
    len: u32,
}

/// A ranked passage.
#[derive(Clone, PartialEq, Debug)]
pub struct Hit {
    /// File path relative to the docs root.
    pub path: String,
    /// Heading of the passage.
    pub heading: String,
    /// Passage text.
    pub text: String,
    /// BM25 score (higher is better).
    pub score: f64,
}

/// The searchable index.
#[derive(Debug, Default)]
pub struct DocsIndex {
    chunks: Vec<Chunk>,
    df: BTreeMap<String, u32>,
    total_len: u64,
}

fn tokenize(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .filter(|t| t.chars().count() >= 2)
        .map(str::to_lowercase)
        .collect()
}

fn collect_files(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    let mut entries: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    entries.sort();
    for p in entries {
        if out.len() >= MAX_FILES {
            return;
        }
        if p.is_dir() {
            collect_files(&p, out);
        } else if p
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("md") || e.eq_ignore_ascii_case("markdown"))
            && p.metadata().is_ok_and(|m| m.len() <= MAX_FILE_BYTES)
        {
            out.push(p);
        }
    }
}

/// Split `text` at headings into `(heading, body)` pieces, further cut at paragraph boundaries.
fn split(text: &str) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = Vec::new();
    let mut heading = String::new();
    let mut body = String::new();
    let mut in_fence = false;
    let flush = |heading: &str, body: &mut String, out: &mut Vec<(String, String)>| {
        let t = body.trim();
        if t.len() >= 20 {
            let mut cur = String::new();
            for para in t.split("\n\n") {
                if !cur.is_empty() && cur.len() + para.len() > MAX_CHUNK_CHARS {
                    out.push((heading.to_owned(), std::mem::take(&mut cur)));
                }
                if !cur.is_empty() {
                    cur.push_str("\n\n");
                }
                cur.push_str(para);
            }
            if !cur.trim().is_empty() {
                out.push((heading.to_owned(), cur));
            }
        }
        body.clear();
    };
    for line in text.lines() {
        if line.trim_start().starts_with("```") {
            in_fence = !in_fence;
        }
        if !in_fence && line.starts_with('#') {
            flush(&heading, &mut body, &mut out);
            heading = line.trim_start_matches('#').trim().to_owned();
        } else {
            body.push_str(line);
            body.push('\n');
        }
    }
    flush(&heading, &mut body, &mut out);
    out
}

impl DocsIndex {
    /// Index every Markdown file below `root` (an unreadable or missing root yields an empty index).
    #[must_use]
    pub fn load(root: &Path) -> Self {
        let mut files = Vec::new();
        collect_files(root, &mut files);
        let mut idx = Self::default();
        for f in files {
            let Ok(text) = std::fs::read_to_string(&f) else {
                continue;
            };
            let rel = f
                .strip_prefix(root)
                .unwrap_or(&f)
                .to_string_lossy()
                .replace('\\', "/");
            for (heading, body) in split(&text) {
                let mut terms: BTreeMap<String, u32> = BTreeMap::new();
                for t in tokenize(&format!("{heading} {body}")) {
                    *terms.entry(t).or_insert(0) += 1;
                }
                let len = terms.values().sum::<u32>();
                for t in terms.keys() {
                    *idx.df.entry(t.clone()).or_insert(0) += 1;
                }
                idx.total_len += u64::from(len);
                idx.chunks.push(Chunk {
                    path: rel.clone(),
                    heading,
                    text: body,
                    terms,
                    len,
                });
            }
        }
        idx
    }

    /// Number of indexed passages.
    #[must_use]
    pub fn len(&self) -> usize {
        self.chunks.len()
    }

    /// Whether nothing is indexed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    /// The `k` best passages for `query`, best first; ties keep file order.
    #[must_use]
    pub fn search(&self, query: &str, k: usize) -> Vec<Hit> {
        let terms: std::collections::BTreeSet<String> = tokenize(query).into_iter().collect();
        if terms.is_empty() || self.chunks.is_empty() {
            return Vec::new();
        }
        let n = f64::from(u32::try_from(self.chunks.len()).unwrap_or(u32::MAX));
        let avg = (self.total_len as f64 / n).max(1.0);
        let mut scored: Vec<(usize, f64)> = Vec::new();
        for (i, c) in self.chunks.iter().enumerate() {
            let mut s = 0.0_f64;
            for t in &terms {
                let Some(tf) = c.terms.get(t) else {
                    continue;
                };
                let df = f64::from(self.df.get(t).copied().unwrap_or(1));
                let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
                let tf = f64::from(*tf);
                let norm = 1.2 * (1.0 - 0.75 + 0.75 * f64::from(c.len) / avg);
                s += idf * (tf * 2.2) / (tf + norm);
            }
            if s > 0.0 {
                scored.push((i, s));
            }
        }
        scored.sort_by(|a, b| b.1.total_cmp(&a.1).then(a.0.cmp(&b.0)));
        scored
            .into_iter()
            .take(k)
            .map(|(i, score)| {
                let c = &self.chunks[i];
                Hit {
                    path: c.path.clone(),
                    heading: c.heading.clone(),
                    text: c.text.clone(),
                    score,
                }
            })
            .collect()
    }
}

/// The process-wide index of the operator's documentation directory (`intel.docsDir`, default
/// `./docs`), built on first use off the async runtime. Empty when the directory is missing.
pub async fn index_for(state: &AppState) -> Arc<DocsIndex> {
    state
        .docs_index
        .get_or_init(|| async {
            let root = state
                .config
                .intel
                .docs_dir
                .clone()
                .unwrap_or_else(|| PathBuf::from("docs"));
            match tokio::task::spawn_blocking(move || DocsIndex::load(&root)).await {
                Ok(idx) => Arc::new(idx),
                Err(e) => {
                    tracing::warn!(error = %e, "documentation index build failed");
                    Arc::new(DocsIndex::default())
                }
            }
        })
        .await
        .clone()
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn indexes_markdown_and_ranks_by_bm25() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("sub")).unwrap();
        std::fs::write(
            dir.path().join("a.md"),
            "# Webhooks\n\nWebhook deliveries are signed with an HMAC signature header for every event.\n\n# Crawl\n\nCrawls follow links from the seed URL within scope limits and budgets.\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("sub/b.md"),
            "# Signatures\n\nVerify the signature of a webhook by recomputing the HMAC over the raw body.\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("c.txt"), "webhook webhook webhook not markdown").unwrap();
        let idx = DocsIndex::load(dir.path());
        assert_eq!(idx.len(), 3);
        let hits = idx.search("verify webhook signature hmac", 2);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].path, "sub/b.md");
        assert!(hits[0].score >= hits[1].score);
        assert!(idx.search("zzzz", 3).is_empty());
        assert!(idx.search("   ", 3).is_empty());
        assert!(DocsIndex::load(Path::new("/definitely/not/here")).is_empty());
    }

    #[test]
    fn headings_in_code_fences_do_not_split() {
        let parts = split(
            "# T\n\ntext text text text text text\n\n```\n# not a heading\n```\n\nmore text here to pad\n",
        );
        assert_eq!(parts.len(), 1);
        assert!(parts[0].1.contains("# not a heading"));
    }
}
