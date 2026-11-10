//! The `--resume FILE` of an in-memory crawl (compatibility `-resume`).
//!
//! One seed: the file is that run's [`ResumeState`] JSON, byte for byte what
//! [`ResumeState::to_json`] writes. Several seeds: an envelope
//! `{"version":1,"completed":[seed..],"runs":{seed: ResumeState}}`, so a rerun skips the seeds
//! that finished and continues the ones that stopped. A run that left no URL pending removes
//! its entry; when nothing is pending anywhere the file is deleted.

use anyhow::{bail, Context as _};
use crawlx_worker::surface::resume::{ResumeState, RESUME_VERSION};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use url::Url;

/// What the previous invocation left for one seed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Progress {
    /// The seed has no entry: crawl it from scratch.
    Fresh,
    /// The seed finished last time: skip it.
    Completed,
    /// The seed stopped with URLs left: continue it.
    Continue(ResumeState),
}

/// How a seed ended in this invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Outcome {
    /// The frontier ran dry (or the seed was skipped as completed).
    Done,
    /// The run stopped early; this is its state.
    Stopped(ResumeState),
}

#[derive(Serialize, Deserialize)]
struct Envelope {
    version: u32,
    #[serde(default)]
    completed: BTreeSet<String>,
    #[serde(default)]
    runs: BTreeMap<String, ResumeState>,
}

/// The parsed contents of a resume file.
#[derive(Debug, Default)]
pub(crate) struct ResumeFile {
    single: Option<ResumeState>,
    envelope: Option<Envelope>,
}

impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("completed", &self.completed.len())
            .field("runs", &self.runs.len())
            .finish()
    }
}

impl ResumeFile {
    /// Read `path`; a missing file is an empty one.
    ///
    /// # Errors
    /// An unreadable file, malformed JSON or an unsupported version.
    pub(crate) fn load(path: &Path) -> anyhow::Result<Self> {
        let text = match std::fs::read_to_string(path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Self::default()),
            Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
        };
        let value: serde_json::Value =
            serde_json::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        if value.get("runs").is_some() {
            let envelope: Envelope =
                serde_json::from_value(value).with_context(|| format!("parsing {}", path.display()))?;
            if envelope.version != RESUME_VERSION {
                bail!(
                    "{}: resume file version {} is not supported (expected {RESUME_VERSION})",
                    path.display(),
                    envelope.version
                );
            }
            return Ok(Self {
                single: None,
                envelope: Some(envelope),
            });
        }
        let state = ResumeState::from_json(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(Self {
            single: Some(state),
            envelope: None,
        })
    }

    /// What the file says about `seed`, given the number of seeds of this invocation.
    ///
    /// # Errors
    /// A single-seed file used with several seeds: it cannot tell which seed it belongs to.
    pub(crate) fn progress(&self, seed: &Url, seeds_in_run: usize) -> anyhow::Result<Progress> {
        if let Some(state) = &self.single {
            if seeds_in_run != 1 {
                bail!("the resume file holds the state of a single-seed run, but this run has {seeds_in_run} seeds");
            }
            return Ok(Progress::Continue(state.clone()));
        }
        let Some(envelope) = &self.envelope else {
            return Ok(Progress::Fresh);
        };
        let key = seed.as_str();
        Ok(if let Some(state) = envelope.runs.get(key) {
            Progress::Continue(state.clone())
        } else if envelope.completed.contains(key) {
            Progress::Completed
        } else {
            Progress::Fresh
        })
    }

    /// Persist the outcomes of this invocation: delete the file when nothing is pending, write
    /// the bare state for one seed, the envelope for several.
    ///
    /// # Errors
    /// A file that cannot be written or removed.
    pub(crate) fn save(path: &Path, outcomes: &[(Url, Outcome)]) -> anyhow::Result<()> {
        let stopped = outcomes
            .iter()
            .filter(|(_, o)| matches!(o, Outcome::Stopped(_)))
            .count();
        if stopped == 0 {
            return match std::fs::remove_file(path) {
                Ok(()) => Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
                Err(e) => Err(e).with_context(|| format!("removing {}", path.display())),
            };
        }
        let json = if let [(_, Outcome::Stopped(state))] = outcomes {
            state.to_json().context("encoding the resume state")?
        } else {
            let mut envelope = Envelope {
                version: RESUME_VERSION,
                completed: BTreeSet::new(),
                runs: BTreeMap::new(),
            };
            for (seed, outcome) in outcomes {
                match outcome {
                    Outcome::Done => {
                        envelope.completed.insert(seed.as_str().to_owned());
                    }
                    Outcome::Stopped(state) => {
                        envelope.runs.insert(seed.as_str().to_owned(), state.clone());
                    }
                }
            }
            serde_json::to_string_pretty(&envelope).context("encoding the resume state")?
        };
        std::fs::write(path, json).with_context(|| format!("writing {}", path.display()))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crawlx_worker::surface::resume::ResumeEntry;

    fn state(url: &str) -> ResumeState {
        ResumeState::new(
            ["https://a.test/".to_owned()],
            [ResumeEntry::new(url.to_owned(), 1)],
        )
    }

    #[test]
    fn one_seed_round_trips_as_a_bare_state_and_a_finished_run_deletes_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resume.json");
        let seed = Url::parse("https://a.test/").unwrap();
        let st = state("https://a.test/next");
        ResumeFile::save(&path, &[(seed.clone(), Outcome::Stopped(st.clone()))]).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), st.to_json().unwrap());
        let loaded = ResumeFile::load(&path).unwrap();
        assert_eq!(loaded.progress(&seed, 1).unwrap(), Progress::Continue(st));
        assert!(loaded.progress(&seed, 2).is_err());
        ResumeFile::save(&path, &[(seed, Outcome::Done)]).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn several_seeds_keep_completed_and_stopped_runs_apart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("resume.json");
        let a = Url::parse("https://a.test/").unwrap();
        let b = Url::parse("https://b.test/").unwrap();
        let c = Url::parse("https://c.test/").unwrap();
        let st = state("https://b.test/next");
        ResumeFile::save(
            &path,
            &[
                (a.clone(), Outcome::Done),
                (b.clone(), Outcome::Stopped(st.clone())),
            ],
        )
        .unwrap();
        let loaded = ResumeFile::load(&path).unwrap();
        assert_eq!(loaded.progress(&a, 3).unwrap(), Progress::Completed);
        assert_eq!(loaded.progress(&b, 3).unwrap(), Progress::Continue(st));
        assert_eq!(loaded.progress(&c, 3).unwrap(), Progress::Fresh);
    }

    #[test]
    fn a_missing_file_is_empty_and_garbage_is_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let seed = Url::parse("https://a.test/").unwrap();
        let none = ResumeFile::load(&dir.path().join("absent.json")).unwrap();
        assert_eq!(none.progress(&seed, 1).unwrap(), Progress::Fresh);
        let bad = dir.path().join("bad.json");
        std::fs::write(&bad, "not json").unwrap();
        assert!(ResumeFile::load(&bad).is_err());
    }
}
