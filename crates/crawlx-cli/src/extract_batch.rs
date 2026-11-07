//! Bounded deterministic source tree traversal through descriptor-rooted corpus admission.

use anyhow::{bail, Context};
use crawlx_fetch::protocol::file::FileCorpus;
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio_util::sync::CancellationToken;
use url::Url;

pub(super) struct Batch {
    corpus: FileCorpus,
    canonical_root: PathBuf,
    pending: BTreeMap<String, Option<Url>>,
    entries: usize,
    files: usize,
    bytes_left: u32,
    max_entries: usize,
    max_files: usize,
    max_depth: usize,
    max_file_bytes: u32,
}

pub(super) enum Entry {
    Document { source: String, bytes: bytes::Bytes },
    Refused { source: String, reason: &'static str },
}

fn relative(url: &Url) -> anyhow::Result<String> {
    let path = url
        .to_file_path()
        .map_err(|()| anyhow::anyhow!("invalid root-relative corpus URL"))?;
    Ok(path
        .to_str()
        .context("source path must be UTF-8")?
        .trim_start_matches('/')
        .to_owned())
}

impl Batch {
    pub(super) fn open(root: &Path, args: &super::ExtractArgs) -> anyhow::Result<Self> {
        // Pin the original root atomically before deriving any display/containment path.
        // Reopening canonicalize(root) would permit a root-to-symlink replacement race.
        let corpus = FileCorpus::open(root, usize::from(args.max_entries))?;
        let canonical_root = corpus.canonical_root()?;
        let mut pending = BTreeMap::new();
        pending.insert(String::new(), Some(FileCorpus::parse_url("file:///")?));
        Ok(Self {
            corpus,
            canonical_root,
            pending,
            entries: 0,
            files: 0,
            bytes_left: args.max_total_bytes,
            max_entries: usize::from(args.max_entries),
            max_files: usize::from(args.max_files),
            max_depth: usize::from(args.max_depth),
            max_file_bytes: args.max_file_bytes,
        })
    }

    pub(super) fn canonical_root(&self) -> &Path {
        &self.canonical_root
    }

    pub(super) async fn next(&mut self, cancel: &CancellationToken) -> anyhow::Result<Option<Entry>> {
        while let Some((source, url)) = self.pending.pop_first() {
            if cancel.is_cancelled() {
                bail!("offline extraction cancelled");
            }
            let Some(url) = url else {
                return Ok(Some(Entry::Refused {
                    source,
                    reason: "symlink_or_special_file",
                }));
            };
            let directory = url.path().ends_with('/');
            if !directory {
                self.files = self.files.saturating_add(1);
                if self.files > self.max_files {
                    return Ok(Some(Entry::Refused {
                        source,
                        reason: "file_count_limit",
                    }));
                }
                if self.bytes_left == 0 {
                    return Ok(Some(Entry::Refused {
                        source,
                        reason: "total_byte_limit",
                    }));
                }
            }
            let depth = source
                .trim_end_matches('/')
                .split('/')
                .filter(|part| !part.is_empty())
                .count();
            if directory && depth > self.max_depth {
                return Ok(Some(Entry::Refused {
                    source,
                    reason: "directory_depth_limit",
                }));
            }
            let limit = self.max_file_bytes.min(self.bytes_left).max(1);
            let acquired = self
                .corpus
                .acquire(&url, limit, Duration::from_secs(30), cancel)
                .await;
            let resource = match acquired {
                Ok(value) => value,
                Err(_) if cancel.is_cancelled() => bail!("offline extraction cancelled"),
                Err(_) => {
                    // A racing grow/read failure may already consume the reserved bytes.
                    if !directory {
                        self.bytes_left = self.bytes_left.saturating_sub(limit);
                    }
                    return Ok(Some(Entry::Refused {
                        source,
                        reason: "input_refused_or_limit",
                    }));
                }
            };
            if directory {
                let count = resource
                    .children
                    .len()
                    .saturating_add(resource.denied_children.len());
                self.entries = self.entries.saturating_add(count);
                if self.entries > self.max_entries {
                    bail!("offline source tree entry limit exceeded");
                }
                for child in resource.children {
                    self.pending.insert(relative(&child)?, Some(child));
                }
                for child in resource.denied_children {
                    self.pending.insert(relative(&child)?, None);
                }
                continue;
            }
            self.bytes_left = self
                .bytes_left
                .checked_sub(u32::try_from(resource.body.len())?)
                .context("offline source tree byte limit exceeded")?;
            return Ok(Some(Entry::Document {
                source,
                bytes: resource.body,
            }));
        }
        Ok(None)
    }
}
