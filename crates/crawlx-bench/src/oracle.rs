//! Interface to `bench/browser-oracle`.
//!
//! * [`OracleManifest`] is the input `runner.mjs --manifest` expects:
//!   `{ url, controls: [{ id, selector, expected }] }`.
//! * [`OracleReport`] is the result file the runner writes; it records the driver and its
//!   package version.
//! * [`merge`] and [`compare`] mirror `compare.mjs`: result files from different drivers are
//!   never merged, and `compare` reports false-actionable controls (blocking, zero tolerated),
//!   false-non-actionable controls (at most 2 percent, non-blocking) and oracle gaps.
//! * [`discovery`] is the AX-recall differential over `runner.mjs --discover`:
//!   [`discovery::compare_discovery`] joins crawlx's candidates with the oracle's
//!   role-locator elements.

pub mod discovery;

use crate::error::BenchError;
use crate::gym::manifest::{ExpectedClass, FixtureManifest};
use crawlx_core::observation::Revalidation;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

/// Drivers `runner.mjs` accepts (`ORACLE_DRIVER`).
pub const DRIVERS: [&str; 2] = ["playwright", "patchright"];

/// One control in the runner's manifest.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct OracleControl {
    /// Ground-truth control id from the fixture manifest.
    pub id: String,
    /// CSS selector the driver resolves on the page to find the control.
    pub selector: String,
    /// The verdict the driver is expected to reach.
    pub expected: ExpectedClass,
}

/// Input of `runner.mjs --manifest`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct OracleManifest {
    /// Absolute URL of the fixture entry page the driver navigates to.
    pub url: String,
    /// Controls to trial, in manifest order.
    pub controls: Vec<OracleControl>,
}

/// Build the runner manifest for `manifest` served under `base_url`, expecting `driver`'s verdicts.
///
/// # Errors
/// [`BenchError::Oracle`] when `driver` is not a known oracle driver.
pub fn oracle_manifest(
    manifest: &FixtureManifest,
    base_url: &str,
    driver: &str,
) -> Result<OracleManifest, BenchError> {
    if !DRIVERS.contains(&driver) {
        return Err(BenchError::Oracle(format!(
            "ORACLE_DRIVER must be one of {}, got {driver}",
            DRIVERS.join("|")
        )));
    }
    Ok(OracleManifest {
        url: manifest.entry_url(base_url),
        controls: manifest
            .controls
            .iter()
            .map(|c| OracleControl {
                id: c.id.clone(),
                selector: c.selector.clone(),
                expected: c.oracle_expected(driver),
            })
            .collect(),
    })
}

/// Write the runner manifest as JSON to `path` (creating parent directories).
///
/// # Errors
/// I/O failures, or an unknown driver.
pub fn write_manifest(
    manifest: &FixtureManifest,
    base_url: &str,
    driver: &str,
    path: &Path,
) -> Result<(), BenchError> {
    let m = oracle_manifest(manifest, base_url, driver)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir).map_err(|e| BenchError::io(dir, e))?;
    }
    let json = serde_json::to_string_pretty(&m)?;
    std::fs::write(path, json).map_err(|e| BenchError::io(path, e))
}

/// One control's oracle result.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct OracleResult {
    /// Ground-truth control id the verdict belongs to.
    pub id: String,
    /// CSS selector the driver used.
    pub selector: String,
    /// Verdict the manifest expected from this driver, recorded by the runner; `None` when it recorded none.
    #[serde(default)]
    pub expected: Option<ExpectedClass>,
    /// What the driver concluded.
    pub verdict: ExpectedClass,
    /// Why the driver reached the verdict (`obscured`, `not_visible`, `disabled`, `unstable`, `locator_unresolved`, or a truncated error message); `None` for actionable controls.
    #[serde(default)]
    pub reason: Option<String>,
}

/// A result file written by `runner.mjs`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct OracleReport {
    /// Oracle driver that produced the report (one of [`DRIVERS`]).
    pub driver: String,
    /// Installed package version of the driver; results of different versions are never merged.
    pub driver_version: String,
    /// Whether the driver captured console output (`false` for Patchright, which disables the Console domain).
    #[serde(default)]
    pub console_capture: bool,
    /// Entry URL of the manifest the runner executed.
    #[serde(default)]
    pub manifest_url: String,
    /// ISO-8601 timestamp at which the runner started; empty when absent.
    #[serde(default)]
    pub started: String,
    /// ISO-8601 timestamp at which the runner finished; empty when absent.
    #[serde(default)]
    pub finished: String,
    /// One result per control of the runner manifest.
    pub results: Vec<OracleResult>,
}

impl OracleReport {
    /// Parse and validate a result file.
    ///
    /// # Errors
    /// [`BenchError::Json`] for malformed JSON or an unknown verdict, [`BenchError::Oracle`] for an
    /// unknown driver.
    pub fn parse(json: &str) -> Result<Self, BenchError> {
        let r: Self = serde_json::from_str(json)?;
        if !DRIVERS.contains(&r.driver.as_str()) {
            return Err(BenchError::Oracle(format!(
                "unknown oracle driver `{}`",
                r.driver
            )));
        }
        Ok(r)
    }

    /// Load a result file from disk.
    ///
    /// # Errors
    /// I/O or parse failures.
    pub fn load(path: &Path) -> Result<Self, BenchError> {
        let text = std::fs::read_to_string(path).map_err(|e| BenchError::io(path, e))?;
        Self::parse(&text)
    }

    /// Controls whose verdict differs from the expectation recorded by the runner.
    #[must_use]
    pub fn unexpected(&self) -> Vec<&OracleResult> {
        self.results
            .iter()
            .filter(|r| r.expected.is_some_and(|e| e != r.verdict))
            .collect()
    }
}

/// Results of one driver, merged by control id (later files win).
#[derive(Clone, PartialEq, Eq, Debug)]
#[non_exhaustive]
pub struct MergedOracle {
    /// Driver all merged reports came from.
    pub driver: String,
    /// Driver version all merged reports came from.
    pub driver_version: String,
    /// Results keyed by control id; the last report containing an id wins.
    pub results: BTreeMap<String, OracleResult>,
}

/// Merge result files of one driver build.
///
/// # Errors
/// [`BenchError::Oracle`] when `reports` is empty or mixes `driver@version` pairs: results of
/// different drivers are separate series.
pub fn merge(reports: &[OracleReport]) -> Result<MergedOracle, BenchError> {
    let drivers: BTreeSet<String> = reports
        .iter()
        .map(|r| format!("{}@{}", r.driver, r.driver_version))
        .collect();
    if drivers.len() > 1 {
        return Err(BenchError::Oracle(format!(
            "refusing to merge results from different drivers: {}",
            drivers.into_iter().collect::<Vec<_>>().join(", ")
        )));
    }
    let Some(first) = reports.first() else {
        return Err(BenchError::Oracle("no oracle result files to merge".to_owned()));
    };
    let mut results = BTreeMap::new();
    for r in reports {
        for x in &r.results {
            results.insert(x.id.clone(), x.clone());
        }
    }
    Ok(MergedOracle {
        driver: first.driver.clone(),
        driver_version: first.driver_version.clone(),
        results,
    })
}

/// crawlx's own verdict for a control, from `BrowserContext::revalidate`.
#[must_use]
pub const fn verdict_of(r: &Revalidation) -> ExpectedClass {
    match r {
        Revalidation::Actionable { .. } => ExpectedClass::Actionable,
        _ => ExpectedClass::NotActionable,
    }
}

/// The crawlx side of a comparison: `{ "verdicts": { "<control id>": "actionable" | "not_actionable" } }`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug, Default)]
pub struct CrawlxVerdicts {
    /// crawlx's verdict per control id.
    pub verdicts: BTreeMap<String, ExpectedClass>,
}

impl CrawlxVerdicts {
    /// Parse the crawlx revalidate file.
    ///
    /// # Errors
    /// [`BenchError::Json`] for malformed JSON.
    pub fn parse(json: &str) -> Result<Self, BenchError> {
        Ok(serde_json::from_str(json)?)
    }
}

/// A control crawlx called actionable although the oracle says it is not.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize, Debug)]
pub struct FalseActionable {
    /// Id of the control crawlx called actionable.
    pub id: String,
    /// Oracle's reason for the non-actionable verdict, when it gave one.
    pub reason: Option<String>,
}

/// Outcome of [`compare`] (shape of `compare.mjs` output).
#[derive(Clone, PartialEq, Serialize, Deserialize, Debug)]
#[non_exhaustive]
pub struct Comparison {
    /// Oracle driver the comparison used.
    pub driver: String,
    /// Controls crawlx called actionable but the oracle did not; zero are tolerated (blocking).
    pub false_actionable: Vec<FalseActionable>,
    /// Controls crawlx called non-actionable but the oracle did; at most 2 percent are tolerated (non-blocking).
    pub false_non_actionable: Vec<String>,
    /// `false_non_actionable` over the number of oracle results, in `[0, 1]`.
    pub false_non_actionable_rate: f64,
    /// Controls the oracle could not decide (`oracle_gap`); excluded from both error lists.
    pub oracle_gaps: Vec<String>,
    /// `true` when `false_actionable` is non-empty.
    pub blocking: bool,
}

/// Compare oracle verdicts with crawlx `revalidate` verdicts.
#[must_use]
pub fn compare(oracle: &MergedOracle, crawlx: &BTreeMap<String, ExpectedClass>) -> Comparison {
    let mut false_actionable = Vec::new();
    let mut false_non_actionable = Vec::new();
    let mut oracle_gaps = Vec::new();
    for (id, o) in &oracle.results {
        let Some(c) = crawlx.get(id).copied() else {
            continue;
        };
        use ExpectedClass::{Actionable, NotActionable, OracleGap};
        if o.verdict == OracleGap {
            oracle_gaps.push(id.clone());
        } else if c == Actionable && o.verdict == NotActionable {
            false_actionable.push(FalseActionable {
                id: id.clone(),
                reason: o.reason.clone(),
            });
        } else if c == NotActionable && o.verdict == Actionable {
            false_non_actionable.push(id.clone());
        }
    }
    let total = oracle.results.len().max(1);
    Comparison {
        driver: oracle.driver.clone(),
        blocking: !false_actionable.is_empty(),
        false_non_actionable_rate: false_non_actionable.len() as f64 / total as f64,
        false_actionable,
        false_non_actionable,
        oracle_gaps,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    fn manifest() -> FixtureManifest {
        FixtureManifest::from_json(
            r##"{"id":"g31","url_path":"/g31/","controls":[
              {"id":"c1","selector":"#c1","role":"button","oracle":{"playwright":"oracle_gap"}},
              {"id":"c2","selector":"#c2","role":"button","expected":"not_actionable"}]}"##,
        )
        .unwrap()
    }

    fn report(driver: &str, version: &str, results: &[(&str, ExpectedClass)]) -> OracleReport {
        OracleReport {
            driver: driver.to_owned(),
            driver_version: version.to_owned(),
            console_capture: driver == "playwright",
            manifest_url: "http://h/g31/".to_owned(),
            started: String::new(),
            finished: String::new(),
            results: results
                .iter()
                .map(|(id, v)| OracleResult {
                    id: (*id).to_owned(),
                    selector: format!("#{id}"),
                    expected: None,
                    verdict: *v,
                    reason: Some("r".to_owned()),
                })
                .collect(),
        }
    }

    #[test]
    fn manifest_has_the_runner_shape_and_per_driver_expectations() {
        let m = oracle_manifest(&manifest(), "http://127.0.0.1:9/", "playwright").unwrap();
        assert_eq!(m.url, "http://127.0.0.1:9/g31/");
        let json = serde_json::to_value(&m).unwrap();
        assert_eq!(json["controls"][0]["expected"], "oracle_gap");
        assert_eq!(json["controls"][1]["expected"], "not_actionable");
        assert_eq!(json["controls"][1]["selector"], "#c2");
        let p = oracle_manifest(&manifest(), "http://127.0.0.1:9", "patchright").unwrap();
        assert_eq!(p.controls[0].expected, ExpectedClass::Actionable);
        assert!(oracle_manifest(&manifest(), "http://h", "selenium").is_err());
    }

    #[test]
    fn manifest_round_trips_through_a_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nested/g31.json");
        write_manifest(&manifest(), "http://h:1", "patchright", &path).unwrap();
        let back: OracleManifest = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(
            back,
            oracle_manifest(&manifest(), "http://h:1", "patchright").unwrap()
        );
    }

    #[test]
    fn report_parse_validates_driver_and_verdicts() {
        let ok = serde_json::to_string(&report(
            "playwright",
            "1.56.1",
            &[("c1", ExpectedClass::OracleGap)],
        ))
        .unwrap();
        assert_eq!(OracleReport::parse(&ok).unwrap().results.len(), 1);
        let bad_driver = ok.replace("playwright", "selenium");
        assert!(OracleReport::parse(&bad_driver).is_err());
        let bad_verdict = ok.replace("oracle_gap", "maybe");
        assert!(OracleReport::parse(&bad_verdict).is_err());
    }

    #[test]
    fn merge_refuses_mixed_drivers_and_versions() {
        let a = report("playwright", "1.56.1", &[("c1", ExpectedClass::Actionable)]);
        let b = report("patchright", "1.56.2", &[("c2", ExpectedClass::Actionable)]);
        let err = merge(&[a.clone(), b]).unwrap_err().to_string();
        assert!(
            err.contains("refusing to merge results from different drivers"),
            "{err}"
        );
        assert!(
            err.contains("patchright@1.56.2") && err.contains("playwright@1.56.1"),
            "{err}"
        );
        let c = report("playwright", "1.57.0", &[("c2", ExpectedClass::Actionable)]);
        assert!(merge(&[a.clone(), c]).is_err());
        let a2 = report(
            "playwright",
            "1.56.1",
            &[
                ("c1", ExpectedClass::NotActionable),
                ("c2", ExpectedClass::Actionable),
            ],
        );
        let merged = merge(&[a, a2]).unwrap();
        assert_eq!(
            merged.results["c1"].verdict,
            ExpectedClass::NotActionable,
            "later file wins"
        );
        assert_eq!(merged.results.len(), 2);
        assert!(merge(&[]).is_err());
    }

    #[test]
    fn compare_mirrors_compare_mjs() {
        let oracle = merge(&[report(
            "patchright",
            "1.56.2",
            &[
                ("a", ExpectedClass::NotActionable),
                ("b", ExpectedClass::Actionable),
                ("c", ExpectedClass::OracleGap),
                ("d", ExpectedClass::Actionable),
                ("e", ExpectedClass::NotActionable),
            ],
        )])
        .unwrap();
        let crawlx: BTreeMap<String, ExpectedClass> = [
            ("a", ExpectedClass::Actionable),    // false actionable: blocking
            ("b", ExpectedClass::NotActionable), // false non-actionable
            ("c", ExpectedClass::Actionable),    // gap
            ("d", ExpectedClass::Actionable),    // agree
                                                 // e missing from crawlx: skipped
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v))
        .collect();
        let c = compare(&oracle, &crawlx);
        assert_eq!(
            c.false_actionable,
            [FalseActionable {
                id: "a".into(),
                reason: Some("r".into())
            }]
        );
        assert_eq!(c.false_non_actionable, ["b"]);
        assert_eq!(c.oracle_gaps, ["c"]);
        assert!((c.false_non_actionable_rate - 0.2).abs() < 1e-12);
        assert!(c.blocking);
        let clean = compare(
            &oracle,
            &BTreeMap::from([("d".to_owned(), ExpectedClass::Actionable)]),
        );
        assert!(!clean.blocking);
    }

    #[test]
    fn crawlx_verdict_file_and_revalidation_mapping() {
        let v = CrawlxVerdicts::parse(r#"{"verdicts":{"a":"actionable"}}"#).unwrap();
        assert_eq!(v.verdicts["a"], ExpectedClass::Actionable);
        assert_eq!(verdict_of(&Revalidation::Detached), ExpectedClass::NotActionable);
        assert_eq!(verdict_of(&Revalidation::Disabled), ExpectedClass::NotActionable);
    }
}
