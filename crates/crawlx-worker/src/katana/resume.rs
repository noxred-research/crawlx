//! Resumable crawls (katana `-resume`): the URL plane's progress as a small, deterministic
//! JSON document.
//!
//! A run that stops before its frontier is exhausted (`limits.urls`, the deadline, a
//! cancellation) reports a [`ResumeState`]: the canonical URLs it already fetched
//! (`visited`) and the admitted URLs it never got to (`pending`, with their discovery
//! depth). A later run seeded with it ([`crate::UrlPlaneRunner::seed_resume`]) never
//! refetches a visited URL and starts its frontier from `pending`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Version written to and required from the JSON form.
pub const RESUME_VERSION: u32 = 1;

/// Why a [`ResumeState`] could not be encoded or decoded.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ResumeError {
    /// The document is not valid JSON of the expected shape.
    #[error("resume state is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),
    /// The document was written by an incompatible version.
    #[error("resume state version {found} is not supported (expected {RESUME_VERSION})")]
    Version {
        /// Version found in the document.
        found: u32,
    },
}

/// A URL admitted but not yet fetched when the run stopped.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResumeEntry {
    /// Canonical URL.
    pub url: String,
    /// Discovery depth the URL had in the stopped run.
    pub depth: u16,
}

impl ResumeEntry {
    /// An entry for `url` found at `depth`.
    #[must_use]
    pub fn new(url: impl Into<String>, depth: u16) -> Self {
        Self {
            url: url.into(),
            depth,
        }
    }
}

/// Progress of a stopped URL-plane run; both lists are sorted and free of duplicates.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ResumeState {
    /// Format version, [`RESUME_VERSION`].
    pub version: u32,
    /// Canonical URLs the stopped run fetched (a success, a failure or an unreachable host).
    pub visited: Vec<String>,
    /// Admitted URLs the stopped run did not fetch, ordered by `(depth, url)`.
    pub pending: Vec<ResumeEntry>,
}

impl ResumeState {
    /// Build a state from unordered parts: lists are sorted and deduplicated, and a pending
    /// URL that is also visited is dropped.
    #[must_use]
    pub fn new(
        visited: impl IntoIterator<Item = String>,
        pending: impl IntoIterator<Item = ResumeEntry>,
    ) -> Self {
        let visited: BTreeSet<String> = visited.into_iter().collect();
        let mut seen = BTreeSet::new();
        let mut pending: Vec<ResumeEntry> = pending
            .into_iter()
            .filter(|e| !visited.contains(&e.url) && seen.insert(e.url.clone()))
            .collect();
        pending.sort_by(|a, b| (a.depth, &a.url).cmp(&(b.depth, &b.url)));
        Self {
            version: RESUME_VERSION,
            visited: visited.into_iter().collect(),
            pending,
        }
    }

    /// `true` when there is nothing left to do: no pending URL.
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.pending.is_empty()
    }

    /// The deterministic JSON form: the same state always yields the same bytes.
    ///
    /// # Errors
    /// [`ResumeError::Json`] when serialization fails (it cannot for this type; the error is
    /// kept so callers never have to assume that).
    pub fn to_json(&self) -> Result<String, ResumeError> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Parse the JSON form; lists are re-sorted so a hand-edited file behaves like a
    /// generated one.
    ///
    /// # Errors
    /// [`ResumeError::Json`] for malformed input, [`ResumeError::Version`] when the
    /// document's `version` is not [`RESUME_VERSION`].
    pub fn from_json(json: &str) -> Result<Self, ResumeError> {
        let raw: Self = serde_json::from_str(json)?;
        if raw.version != RESUME_VERSION {
            return Err(ResumeError::Version { found: raw.version });
        }
        Ok(Self::new(raw.visited, raw.pending))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn json_is_sorted_deduplicated_and_stable() {
        let a = ResumeState::new(
            [
                "http://h/b".to_owned(),
                "http://h/a".to_owned(),
                "http://h/a".to_owned(),
            ],
            [
                ResumeEntry::new("http://h/z", 2),
                ResumeEntry::new("http://h/y", 1),
                ResumeEntry::new("http://h/z", 3),
                ResumeEntry::new("http://h/a", 1),
            ],
        );
        assert_eq!(a.visited, ["http://h/a", "http://h/b"]);
        assert_eq!(
            a.pending,
            [
                ResumeEntry::new("http://h/y", 1),
                ResumeEntry::new("http://h/z", 2)
            ]
        );
        let json = a.to_json().unwrap();
        let b = ResumeState::from_json(&json).unwrap();
        assert_eq!(a, b);
        assert_eq!(json, b.to_json().unwrap());
    }

    #[test]
    fn from_json_rejects_foreign_versions_and_resorts_hand_edits() {
        let err = ResumeState::from_json(r#"{"version":2,"visited":[],"pending":[]}"#).unwrap_err();
        assert!(matches!(err, ResumeError::Version { found: 2 }), "{err}");
        let edited = ResumeState::from_json(
            r#"{"version":1,"visited":["b","a"],"pending":[{"url":"q","depth":3},{"url":"p","depth":1}]}"#,
        )
        .unwrap();
        assert_eq!(edited.visited, ["a", "b"]);
        assert_eq!(edited.pending[0], ResumeEntry::new("p", 1));
        assert!(ResumeState::from_json("not json").is_err());
    }
}
