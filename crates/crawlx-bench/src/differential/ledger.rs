//! The divergence ledger `bench/differential/divergences.toml`:
//! every documented difference between Firecrawl and crawlx, with its class, provenance and
//! the match rule the runner applies. A difference without a matching entry fails the run.

use crate::error::BenchError;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Why a divergence exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DivergenceClass {
    /// crawlx is deliberately stricter (SSRF, TLS, politeness).
    IntentionalSecurity,
    /// crawlx is deliberately different for correctness or explainability.
    IntentionalCorrectness,
    /// Firecrawl's behavior is the defect.
    FirecrawlBug,
    /// A Firecrawl feature crawlx does not provide.
    UnsupportedFeature,
    /// The behavior cannot be exercised on the Firecrawl self-host as the harness runs it
    /// (no LLM provider, no team flags, no database): the reference answered with a refusal or
    /// a degraded behavior that says nothing about the feature itself.
    ReferenceUnavailable,
}

/// Which comparison the entry documents.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum DivergenceKind {
    /// A URL attempted by one system only (C1).
    Admission,
    /// A URL in one system's robots-blocked set only (C1).
    Robots,
    /// Markdown similarity below the threshold (C2).
    Markdown,
    /// Link-set Jaccard below the threshold (C2).
    Links,
    /// A metadata field differs (C2).
    Metadata,
    /// A counter or status differs (C3).
    Counter,
    /// A URL requested from the fixture server by one system only (C1, the gym access log).
    /// An `admission` entry with the same side and match documents the same URL here too.
    Requested,
    /// An observable of a wire-level scenario differs (C0/C3: request validation, clamping,
    /// precedence, persistence, cancel, resume, webhooks, zero data retention).
    Behavior,
}

/// Which side a set difference is on.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Side {
    /// Present on the Firecrawl side only.
    FirecrawlOnly,
    /// Present on the crawlx side only.
    CrawlxOnly,
}

/// One ledger entry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Divergence {
    /// Stable id (`QRY-001`).
    pub id: String,
    /// Test family.
    pub family: String,
    /// Compatibility level (`C1`, `C2`, `C3`).
    pub level: String,
    /// Families (ids of `families.json`, the runner label) the entry applies to; empty means
    /// every run. An entry that is specific to a family must not tolerate the same difference
    /// in another one.
    #[serde(default)]
    pub families: Vec<String>,
    /// Comparison the entry applies to.
    pub kind: DivergenceKind,
    /// Required for `admission` and `robots`.
    #[serde(default)]
    pub side: Option<Side>,
    /// Glob over the normalized URL key (`*` matches any run of characters); `None` matches
    /// every URL. For `counter` entries this is the field name instead.
    #[serde(default, rename = "match")]
    pub pattern: Option<String>,
    /// For `metadata`: the field name (`title`, `description`, `language`, `statusCode`,
    /// `contentType`); `None` matches every field.
    #[serde(default)]
    pub field: Option<String>,
    /// Class.
    pub class: DivergenceClass,
    /// Provenance (R3): documentation URL, black-box run id, SDK type, RFC or ADR section.
    pub source: String,
    /// Why.
    pub rationale: String,
    /// What a migrating user sees; required for intentional classes.
    #[serde(default)]
    pub user_visible: Option<String>,
}

/// The ledger file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub struct Ledger {
    /// Format version (1).
    #[serde(default = "one")]
    pub version: u32,
    /// Entries.
    #[serde(default, rename = "divergence")]
    pub entries: Vec<Divergence>,
}

const fn one() -> u32 {
    1
}

/// Glob match with `*` as the only wildcard.
#[must_use]
pub fn glob_matches(pattern: &str, text: &str) -> bool {
    fn go(p: &[u8], t: &[u8]) -> bool {
        match p.first() {
            None => t.is_empty(),
            Some(b'*') => (0..=t.len()).any(|i| go(&p[1..], &t[i..])),
            Some(c) => t.first() == Some(c) && go(&p[1..], &t[1..]),
        }
    }
    go(pattern.as_bytes(), text.as_bytes())
}

/// [`glob_matches`] over `|`-separated alternatives: `a/*|b/*` matches what either side does.
#[must_use]
pub fn any_glob_matches(pattern: &str, text: &str) -> bool {
    pattern.split('|').any(|p| glob_matches(p, text))
}

impl Ledger {
    /// Parse ledger TOML.
    ///
    /// # Errors
    /// [`BenchError::Manifest`] when the TOML does not parse or an entry violates a rule
    /// (duplicate id; `admission`/`robots` without `side`; intentional class without
    /// `user_visible`).
    pub fn parse(text: &str) -> Result<Self, BenchError> {
        let ledger: Self =
            toml::from_str(text).map_err(|e| BenchError::manifest("divergences.toml", e.to_string()))?;
        ledger.validate()?;
        Ok(ledger)
    }

    /// Load a ledger file.
    ///
    /// # Errors
    /// [`BenchError::Io`] when the file cannot be read; see [`Ledger::parse`].
    pub fn load(path: &Path) -> Result<Self, BenchError> {
        let text = std::fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;
        Self::parse(&text)
    }

    fn validate(&self) -> Result<(), BenchError> {
        let mut ids = std::collections::BTreeSet::new();
        for e in &self.entries {
            if !ids.insert(e.id.as_str()) {
                return Err(BenchError::manifest(
                    "divergences.toml",
                    format!("duplicate id `{}`", e.id),
                ));
            }
            if matches!(
                e.kind,
                DivergenceKind::Admission | DivergenceKind::Robots | DivergenceKind::Requested
            ) && e.side.is_none()
            {
                return Err(BenchError::manifest(
                    "divergences.toml",
                    format!("`{}`: {:?} entries need `side`", e.id, e.kind),
                ));
            }
            if matches!(
                e.class,
                DivergenceClass::IntentionalSecurity | DivergenceClass::IntentionalCorrectness
            ) && e.user_visible.as_deref().is_none_or(str::is_empty)
            {
                return Err(BenchError::manifest(
                    "divergences.toml",
                    format!("`{}`: intentional divergences need `user_visible`", e.id),
                ));
            }
        }
        Ok(())
    }

    /// The entries that apply to a run labelled `label`.
    #[must_use]
    pub fn for_family(&self, label: &str) -> Self {
        Self {
            version: self.version,
            entries: self
                .entries
                .iter()
                .filter(|e| e.families.is_empty() || e.families.iter().any(|f| f == label))
                .cloned()
                .collect(),
        }
    }

    /// The first entry documenting a set difference of `kind` on `side` for URL `key`.
    #[must_use]
    pub fn admission(&self, kind: DivergenceKind, side: Side, key: &str) -> Option<&Divergence> {
        self.entries.iter().find(|e| {
            e.kind == kind
                && e.side == Some(side)
                && e.pattern.as_deref().is_none_or(|p| any_glob_matches(p, key))
        })
    }

    /// The first entry documenting a per-page difference of `kind` for URL `key` (and
    /// metadata `field` when given).
    #[must_use]
    pub fn page(&self, kind: DivergenceKind, key: &str, field: Option<&str>) -> Option<&Divergence> {
        self.entries.iter().find(|e| {
            e.kind == kind
                && e.pattern.as_deref().is_none_or(|p| any_glob_matches(p, key))
                && (field.is_none() || e.field.is_none() || e.field.as_deref() == field)
        })
    }

    /// The first entry documenting a counter or status difference on `field`.
    #[must_use]
    pub fn counter(&self, field: &str) -> Option<&Divergence> {
        self.entries
            .iter()
            .find(|e| e.kind == DivergenceKind::Counter && e.pattern.as_deref().is_none_or(|p| p == field))
    }

    /// The first entry documenting a behavior difference (`kind = "behavior"`: the wire-level
    /// families VAL, CLAMP, PREC, PERSIST, CANCEL, RESUME, WH, ZDR) on `subject`, the string
    /// `scenario/observation` the comparison names (`*` globs in the entry's `match`).
    #[must_use]
    pub fn behavior(&self, subject: &str) -> Option<&Divergence> {
        self.entries.iter().find(|e| {
            e.kind == DivergenceKind::Behavior
                && e.pattern.as_deref().is_none_or(|p| any_glob_matches(p, subject))
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    const SAMPLE: &str = r#"
version = 1
[[divergence]]
id = "QRY-001"
family = "QRY"
level = "C1"
kind = "admission"
side = "firecrawl_only"
match = "*?utm_*"
class = "intentional_correctness"
source = "adr:0018"
rationale = "crawlx classifies query parameters"
user_visible = "tracking-parameter variants are one page"
"#;

    #[test]
    fn glob_star_only() {
        assert!(glob_matches("*?utm_*", "{origin}/s1/about?utm_source=x"));
        assert!(!glob_matches("*?utm_*", "{origin}/s1/about"));
        assert!(glob_matches("{origin}/s1/*", "{origin}/s1/a/b"));
        assert!(glob_matches("*", ""));
        assert!(!glob_matches("a", "ab"));
    }

    #[test]
    fn parses_and_matches() {
        let l = Ledger::parse(SAMPLE).unwrap();
        assert_eq!(l.entries.len(), 1);
        assert!(l
            .admission(
                DivergenceKind::Admission,
                Side::FirecrawlOnly,
                "{origin}/s1/about?utm_source=x"
            )
            .is_some());
        assert!(l
            .admission(
                DivergenceKind::Admission,
                Side::CrawlxOnly,
                "{origin}/s1/about?utm_source=x"
            )
            .is_none());
        assert!(l
            .admission(DivergenceKind::Admission, Side::FirecrawlOnly, "{origin}/s1/x")
            .is_none());
    }

    #[test]
    fn validation_rejects_bad_entries() {
        let no_side = SAMPLE.replace("side = \"firecrawl_only\"\n", "");
        assert!(Ledger::parse(&no_side).is_err());
        let dup = format!("{SAMPLE}{}", &SAMPLE[SAMPLE.find("[[divergence]]").unwrap()..]);
        assert!(Ledger::parse(&dup).is_err());
        let no_user = SAMPLE.replace(
            "user_visible = \"tracking-parameter variants are one page\"\n",
            "",
        );
        assert!(Ledger::parse(&no_user).is_err());
    }

    #[test]
    fn entries_with_families_apply_only_to_those_families() {
        let scoped = SAMPLE.replace("level = \"C1\"", "families = [\"s1\", \"g12\"]\nlevel = \"C1\"");
        let l = Ledger::parse(&scoped).unwrap();
        assert_eq!(l.for_family("s1").entries.len(), 1);
        assert_eq!(l.for_family("g12").entries.len(), 1);
        assert!(l.for_family("d1").entries.is_empty());
        let everywhere = Ledger::parse(SAMPLE).unwrap();
        assert_eq!(
            everywhere.for_family("d1").entries.len(),
            1,
            "no `families` list: every run"
        );
    }
}
