//! The strategy registry and the milestone gates it enforces (mechanical
//! enforcement).
//!
//! * `state_novelty` and `enablement` may suppress frontier entries only after gate G1
//!   (deterministic traceability) has passed: [`build`] refuses them unless
//!   `gates/g1.passed` is present and valid for this build.
//! * A gate file is produced by `crawlx-bench gate-g1` / `gate-g3` from a passing report.
//!   A configured operator/CI key authenticates every metadata field and the companion
//!   report. The build scope covers workspace Rust sources, manifests and dependency lock,
//!   including the gate evaluator and its dependencies. Any scope change expires the gate.
//!
//! The gate check for `system1Mode` (G3) lives in request validation,
//! `crawlx_core::config::CreateCrawl::check_gates`, fed by [`Gates::status`].

use crate::ab::{Arm, ArmAssignment, ArmedStrategy};
use crate::enablement::{EnablementConfig, EnablementRecovery};
use crate::error::StrategyError;
use crate::event_driven::{EventDriven, EventDrivenConfig};
use crate::interaction_bfs::{BfsConfig, InteractionBfs};
use crate::novelty::{NoveltyConfig, StateNovelty};
use crate::Strategy;
use crawlx_core::config::{StrategyArm, StrategyName};
use crawlx_core::gates::GateStatus;
use crawlx_core::hash::Digest;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// The G3 criteria and their proof, so `crawlx-bench gate-g3` evaluates them
/// without a dependency on `crawlx-model`.
pub use crawlx_model::rollout::{G3Evidence, G3Token};

/// Default directory of the gate files, relative to the working directory.
pub const DEFAULT_GATES_DIR: &str = "gates";
/// Environment variable overriding [`DEFAULT_GATES_DIR`].
pub const GATES_DIR_ENV: &str = "CRAWLX_GATES_DIR";
/// File holding trusted gate keys (`key_id hex-key` per line), provisioned outside this build.
pub const GATE_KEYS_FILE_ENV: &str = "CRAWLX_GATE_KEYS_FILE";
/// Operator/CI key id used by the gate producer.
pub const GATE_KEY_ID_ENV: &str = "CRAWLX_GATE_KEY_ID";

/// Failure to configure, sign or authenticate a gate.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum GateAuthenticationError {
    /// The trusted keys file could not be read.
    #[error("cannot read gate keys file {path}: {source}")]
    ReadKeys {
        /// File supplied by the operator.
        path: PathBuf,
        /// Underlying filesystem failure.
        #[source]
        source: std::io::Error,
    },
    /// Invalid configuration or authenticated content.
    #[error("{0}")]
    Invalid(String),
}

/// Dedicated gate trust keys, never generated or read from a gate artifact.
///
/// HMAC verifiers hold signing authority too. Provision these secrets only to trusted
/// CI/operator and consumer processes, separately from authorization-record keys.
#[derive(Default)]
pub struct GateKeys {
    keys: BTreeMap<String, Vec<u8>>,
}

impl std::fmt::Debug for GateKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GateKeys")
            .field("key_ids", &self.keys.keys())
            .finish()
    }
}

impl GateKeys {
    /// Parse `key_id hex-key` pairs, with `#` comments and at least 32 bytes per key.
    ///
    /// # Errors
    /// Rejects empty trust stores, duplicate ids, malformed lines and short keys.
    pub fn parse(text: &str) -> Result<Self, GateAuthenticationError> {
        let mut keys = BTreeMap::new();
        for (index, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or("").trim();
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split_whitespace();
            let id = fields.next().unwrap_or("");
            let encoded = fields.next().unwrap_or("");
            let key = hex::decode(encoded).map_err(|_| {
                GateAuthenticationError::Invalid(format!("gate keys line {} is not hex", index + 1))
            })?;
            if id.is_empty() || key.len() < 32 || fields.next().is_some() {
                return Err(GateAuthenticationError::Invalid(format!(
                    "gate keys line {} requires an id and at least 32 key bytes",
                    index + 1
                )));
            }
            if keys.insert(id.to_owned(), key).is_some() {
                return Err(GateAuthenticationError::Invalid(format!(
                    "gate keys line {} repeats a key id",
                    index + 1
                )));
            }
        }
        if keys.is_empty() {
            return Err(GateAuthenticationError::Invalid(
                "gate keys file defines no trusted key".to_owned(),
            ));
        }
        Ok(Self { keys })
    }

    /// Load an explicitly provisioned trust file.
    ///
    /// # Errors
    /// Fails on unreadable files or any error described by [`Self::parse`].
    pub fn load(path: &Path) -> Result<Self, GateAuthenticationError> {
        let text = std::fs::read_to_string(path).map_err(|source| GateAuthenticationError::ReadKeys {
            path: path.to_path_buf(),
            source,
        })?;
        Self::parse(&text)
    }

    /// Load the file named by [`GATE_KEYS_FILE_ENV`], with no fallback credential.
    ///
    /// # Errors
    /// Fails when the variable is unset/empty or the trust file is invalid.
    pub fn from_env() -> Result<Self, GateAuthenticationError> {
        let path = std::env::var_os(GATE_KEYS_FILE_ENV)
            .filter(|p| !p.is_empty())
            .ok_or_else(|| GateAuthenticationError::Invalid(format!("{GATE_KEYS_FILE_ENV} is required")))?;
        Self::load(Path::new(&path))
    }

    fn mac(&self, file: &GateFile, report: &[u8]) -> Result<Hmac<Sha256>, GateAuthenticationError> {
        let key = self.keys.get(&file.key_id).ok_or_else(|| {
            GateAuthenticationError::Invalid(format!("untrusted gate key {:?}", file.key_id))
        })?;
        let mut mac = Hmac::<Sha256>::new_from_slice(key)
            .map_err(|_| GateAuthenticationError::Invalid("invalid gate key".to_owned()))?;
        mac.update(b"crawlx/gate-attestation/v1\0");
        // Length-prefix every field to prevent concatenation ambiguity. Field order and
        // domain are the signature version; the signature itself is the only omitted field.
        for field in [
            file.gate.as_str().as_bytes(),
            file.commit.as_bytes(),
            file.scope_digest.as_bytes(),
            file.report_digest.as_bytes(),
            file.date.as_bytes(),
            file.key_id.as_bytes(),
            report,
        ] {
            let length = u64::try_from(field.len())
                .map_err(|_| GateAuthenticationError::Invalid("gate evidence is too large".to_owned()))?;
            mac.update(&length.to_le_bytes());
            mac.update(field);
        }
        Ok(mac)
    }
}

/// Digest of the workspace sources and evaluator dependencies this binary was built from.
#[must_use]
pub fn scope_digest() -> &'static str {
    env!("CRAWLX_GATE_SCOPE_DIGEST")
}

/// A milestone gate.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Gate {
    /// Deterministic traceability (exit of M3).
    G1,
    /// Model authority (exit of M7).
    G3,
}

impl Gate {
    /// `G1` / `G3`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::G1 => "G1",
            Self::G3 => "G3",
        }
    }

    /// File name inside the gates directory (`g1.passed`, `g3.passed`).
    #[must_use]
    pub const fn file_name(self) -> &'static str {
        match self {
            Self::G1 => "g1.passed",
            Self::G3 => "g3.passed",
        }
    }

    /// Required companion evidence file inside the gates directory.
    #[must_use]
    pub const fn report_name(self) -> &'static str {
        match self {
            Self::G1 => "g1.report.json",
            Self::G3 => "g3.report.json",
        }
    }
}

/// Contents of a `gates/<id>.passed` file (TOML).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[non_exhaustive]
pub struct GateFile {
    /// Which gate the file attests.
    pub gate: Gate,
    /// Git commit the report was produced for (informational; `scope_digest` is what expires).
    pub commit: String,
    /// Hex BLAKE3 digest of this build's gate scope ([`scope_digest`]).
    pub scope_digest: String,
    /// Hex digest of the `crawlx-bench` report the gate was computed from.
    pub report_digest: String,
    /// Date the gate passed, `YYYY-MM-DD`.
    pub date: String,
    /// Trusted operator/CI key id; covered by the signature.
    pub key_id: String,
    /// Hex HMAC-SHA256 over every metadata field and the exact report bytes.
    pub signature: String,
}

impl GateFile {
    /// Authenticate metadata and the exact report bytes using an externally supplied key.
    ///
    /// The caller must evaluate the report before requesting this attestation.
    ///
    /// # Errors
    /// Fails for invalid metadata or an untrusted key id.
    pub fn signed(
        gate: Gate,
        report: &[u8],
        commit: &str,
        date: &str,
        keys: &GateKeys,
        key_id: &str,
    ) -> Result<Self, GateAuthenticationError> {
        let mut file = Self {
            gate,
            commit: commit.to_owned(),
            scope_digest: scope_digest().to_owned(),
            report_digest: Digest::of("crawlx/gate-report/v1", report).to_hex(),
            date: date.to_owned(),
            key_id: key_id.to_owned(),
            signature: String::new(),
        };
        if let Some(why) = file.problem(gate) {
            return Err(GateAuthenticationError::Invalid(why));
        }
        file.signature = hex::encode(keys.mac(&file, report)?.finalize().into_bytes());
        Ok(file)
    }

    /// Check signature, report digest and the current build scope.
    ///
    /// # Errors
    /// Fails closed on missing/untrusted signatures, modified metadata or evidence.
    pub fn verify(&self, gate: Gate, report: &[u8], keys: &GateKeys) -> Result<(), GateAuthenticationError> {
        if let Some(why) = self.problem(gate) {
            return Err(GateAuthenticationError::Invalid(why));
        }
        if self.report_digest != Digest::of("crawlx/gate-report/v1", report).to_hex() {
            return Err(GateAuthenticationError::Invalid(
                "gate report digest does not match evidence".to_owned(),
            ));
        }
        let signature = hex::decode(&self.signature)
            .map_err(|_| GateAuthenticationError::Invalid("gate signature is not hex".to_owned()))?;
        keys.mac(self, report)?.verify_slice(&signature).map_err(|_| {
            GateAuthenticationError::Invalid("gate signature does not match metadata and evidence".to_owned())
        })
    }

    /// Structural/build-scope checks only; acceptance additionally requires [`Self::verify`].
    #[must_use]
    pub fn problem(&self, gate: Gate) -> Option<String> {
        if self.gate != gate {
            return Some(format!(
                "file attests {} not {}",
                self.gate.as_str(),
                gate.as_str()
            ));
        }
        if self.scope_digest != scope_digest() {
            return Some(format!(
                "produced for scope digest {}, this build is {}",
                short(&self.scope_digest),
                short(scope_digest())
            ));
        }
        if !is_hex(&self.report_digest) || self.report_digest.len() != 64 {
            return Some("report_digest is not a 64-character hex digest".to_owned());
        }
        if !is_date(&self.date) {
            return Some(format!("date {:?} is not YYYY-MM-DD", self.date));
        }
        if self.commit.trim().is_empty() {
            return Some("commit is empty".to_owned());
        }
        None
    }

    /// Serialize as the TOML written to `gates/<id>.passed`.
    ///
    /// # Errors
    /// [`StrategyError::Internal`] when serialization fails (cannot happen for valid UTF-8).
    pub fn to_toml(&self) -> Result<String, StrategyError> {
        toml::to_string(self).map_err(|e| StrategyError::Internal(e.to_string()))
    }
}

fn short(s: &str) -> &str {
    s.get(..12).unwrap_or(s)
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_date(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 10
        && b[4] == b'-'
        && b[7] == b'-'
        && [0, 1, 2, 3, 5, 6, 8, 9].iter().all(|&i| b[i].is_ascii_digit())
}

/// Calibration evidence shared by the gate producer and authenticated consumer.
#[derive(Clone, Copy, PartialEq, Serialize, Deserialize, Debug)]
#[serde(deny_unknown_fields)]
pub struct G3Report {
    /// Labelled held-out decisions behind calibration (at least 10,000).
    pub calibration_samples: u64,
    /// Expected calibration error on held-out sites (at most 0.05).
    pub ece: f64,
    /// Seeds in the shadow comparison (at least 5).
    pub seeds: u32,
    /// Lower confidence bound of incremental coverage (strictly positive).
    pub coverage_gain_ci_low: f64,
    /// Unauthorized action rate on adversarial fixtures (zero).
    pub unauthorized_action_rate: f64,
    /// Warm inference p95 in milliseconds (below 100).
    pub warm_p95_ms: f64,
    /// Consecutive nightly improvements without safety regression (at least 2).
    pub consecutive_nightly_improvements: u32,
}

impl From<G3Report> for G3Evidence {
    fn from(report: G3Report) -> Self {
        Self {
            calibration_samples: report.calibration_samples,
            ece: report.ece,
            seeds: report.seeds,
            coverage_gain_ci_low: report.coverage_gain_ci_low,
            unauthorized_action_rate: report.unauthorized_action_rate,
            warm_p95_ms: report.warm_p95_ms,
            consecutive_nightly_improvements: report.consecutive_nightly_improvements,
        }
    }
}

/// The gates this build has evidence for, loaded from a gates directory.
#[derive(Clone, PartialEq, Debug)]
pub struct Gates {
    status: GateStatus,
    dir: Option<PathBuf>,
    /// Why each absent gate is absent, in gate order.
    problems: Vec<(Gate, String)>,
    g3_token: Option<G3Token>,
}

impl Gates {
    /// Load `g1.passed` and `g3.passed` from `dir`. Never fails: a missing or invalid file
    /// means the gate has not passed and the reason is kept for [`Self::problems`].
    #[must_use]
    pub fn load(dir: &Path) -> Self {
        match GateKeys::from_env() {
            Ok(keys) => Self::load_with_keys(dir, &keys),
            Err(error) => Self {
                status: GateStatus::NONE,
                dir: Some(dir.to_path_buf()),
                problems: [Gate::G1, Gate::G3]
                    .into_iter()
                    .map(|gate| (gate, error.to_string()))
                    .collect(),
                g3_token: None,
            },
        }
    }

    /// Load gates with an explicit trusted key set, without reading process environment.
    #[must_use]
    pub fn load_with_keys(dir: &Path, keys: &GateKeys) -> Self {
        let mut status = GateStatus::NONE;
        let mut problems = Vec::new();
        let mut g3_token = None;
        for gate in [Gate::G1, Gate::G3] {
            match load_one(dir, gate, keys) {
                Ok(token) => match gate {
                    Gate::G1 => status.g1 = true,
                    Gate::G3 => {
                        status.g3 = true;
                        g3_token = token;
                    }
                },
                Err(why) => problems.push((gate, why)),
            }
        }
        Self {
            status,
            dir: Some(dir.to_path_buf()),
            problems,
            g3_token,
        }
    }

    /// Model authority token derived only from the authenticated calibration report.
    #[must_use]
    pub const fn g3_token(&self) -> Option<&G3Token> {
        self.g3_token.as_ref()
    }

    /// [`Self::load`] from `CRAWLX_GATES_DIR` or `./gates`.
    #[must_use]
    pub fn load_default() -> Self {
        let dir =
            std::env::var_os(GATES_DIR_ENV).map_or_else(|| PathBuf::from(DEFAULT_GATES_DIR), PathBuf::from);
        Self::load(&dir)
    }

    /// No gate passed.
    #[must_use]
    pub fn none() -> Self {
        Self::from_status(GateStatus::NONE)
    }

    /// Gates taken as given, without files. For tests and in-process harnesses that bring
    /// their own evidence; production entry points use [`Self::load`].
    #[must_use]
    pub fn from_status(status: GateStatus) -> Self {
        let problems = [(Gate::G1, status.g1), (Gate::G3, status.g3)]
            .into_iter()
            .filter(|(_, passed)| !passed)
            .map(|(g, _)| (g, "not attested".to_owned()))
            .collect();
        Self {
            status,
            dir: None,
            problems,
            g3_token: None,
        }
    }

    /// Which gates passed.
    #[must_use]
    pub const fn status(&self) -> GateStatus {
        self.status
    }

    /// Directory the gates were loaded from; `None` for [`Self::from_status`].
    #[must_use]
    pub fn dir(&self) -> Option<&Path> {
        self.dir.as_deref()
    }

    /// Why each absent gate is absent.
    #[must_use]
    pub fn problems(&self) -> &[(Gate, String)] {
        &self.problems
    }

    /// Has `gate` passed?
    #[must_use]
    pub const fn passed(&self, gate: Gate) -> bool {
        match gate {
            Gate::G1 => self.status.g1,
            Gate::G3 => self.status.g3,
        }
    }

    /// Refuse `strategy` unless `gate` passed.
    ///
    /// # Errors
    /// [`StrategyError::Gated`] with the reason the gate is absent.
    pub fn require(&self, strategy: &'static str, gate: Gate) -> Result<(), StrategyError> {
        if self.passed(gate) {
            return Ok(());
        }
        let reason = self
            .problems
            .iter()
            .find(|(g, _)| *g == gate)
            .map_or_else(|| "not attested".to_owned(), |(_, why)| why.clone());
        Err(StrategyError::Gated {
            strategy,
            gate: gate.as_str(),
            reason,
        })
    }
}

fn load_one(dir: &Path, gate: Gate, keys: &GateKeys) -> Result<Option<G3Token>, String> {
    let path = dir.join(gate.file_name());
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let file: GateFile = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
    if let Some(why) = file.problem(gate) {
        return Err(format!("{}: {why}", path.display()));
    }
    let report_path = dir.join(gate.report_name());
    let report = std::fs::read(&report_path).map_err(|e| format!("{}: {e}", report_path.display()))?;
    file.verify(gate, &report, keys)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    match gate {
        Gate::G1 => Ok(None),
        Gate::G3 => {
            let report: G3Report =
                serde_json::from_slice(&report).map_err(|e| format!("{}: {e}", report_path.display()))?;
            G3Token::verify(&G3Evidence::from(report))
                .map(Some)
                .map_err(|e| e.to_string())
        }
    }
}

/// The gate a strategy needs before it may act on the live frontier, if any.
#[must_use]
pub const fn gate_for(name: StrategyName) -> Option<Gate> {
    match name {
        StrategyName::StateNovelty | StrategyName::Enablement => Some(Gate::G1),
        StrategyName::InteractionBfs | StrategyName::EventDriven | StrategyName::System1 => None,
    }
}

/// Build the deterministic strategy `name` with its default configuration.
///
/// `system1` is model-backed and built by the worker's model wiring; asking for it here is an
/// [`StrategyError::Internal`].
///
/// # Errors
/// [`StrategyError::Gated`] when `name` needs a gate `gates` lacks; [`StrategyError::Internal`]
/// for `system1`.
pub fn build(name: StrategyName, gates: &Gates) -> Result<Arc<dyn Strategy>, StrategyError> {
    if let Some(gate) = gate_for(name) {
        gates.require(strategy_name(name), gate)?;
    }
    Ok(match name {
        StrategyName::InteractionBfs => Arc::new(InteractionBfs::new(BfsConfig::default())),
        StrategyName::StateNovelty => Arc::new(StateNovelty::new(NoveltyConfig::default())),
        StrategyName::Enablement => Arc::new(EnablementRecovery::new(EnablementConfig::default())),
        StrategyName::EventDriven => Arc::new(EventDriven::new(EventDrivenConfig::default())),
        StrategyName::System1 => {
            return Err(StrategyError::Internal(
                "system1 needs a decision engine; build it through the model wiring".to_owned(),
            ))
        }
    })
}

/// Actual deterministic implementations available in this build, not historical labels.
#[must_use]
pub const fn available_versions(name: StrategyName) -> &'static [u32] {
    match name {
        StrategyName::InteractionBfs => &[crate::interaction_bfs::VERSION],
        StrategyName::EventDriven => &[crate::event_driven::VERSION],
        StrategyName::StateNovelty => &[crate::novelty::VERSION],
        StrategyName::Enablement => &[crate::enablement::VERSION],
        StrategyName::System1 => &[],
    }
}

/// Build a real registered version without changing its proposal attribution.
///
/// # Errors
/// Returns [`StrategyError::UnavailableVersion`] for unimplemented versions and preserves
/// every milestone gate enforced by [`build`].
pub fn build_version(
    name: StrategyName,
    version: u32,
    gates: &Gates,
) -> Result<Arc<dyn Strategy>, StrategyError> {
    if !available_versions(name).contains(&version) {
        return Err(StrategyError::UnavailableVersion {
            strategy: strategy_name(name),
            version,
        });
    }
    build(name, gates)
}

/// Bind configured weights to real, gated implementations for session assignment.
///
/// # Errors
/// Rejects empty arms, zero weights, duplicate versions, unavailable implementations and
/// missing gates. No historical version is emulated by relabeling the current algorithm.
pub fn build_armed(
    name: StrategyName,
    arms: &[StrategyArm],
    gates: &Gates,
) -> Result<ArmedStrategy, StrategyError> {
    let assignment = ArmAssignment::new(
        strategy_name(name),
        arms.iter().map(|arm| Arm {
            version: arm.version,
            weight: arm.weight,
        }),
    )?;
    let mut armed = ArmedStrategy::new(strategy_name(name));
    for arm in assignment.arms() {
        armed.register(build_version(name, arm.version, gates)?, arm.weight)?;
    }
    Ok(armed)
}

/// Proposal-attribution name of a configured strategy.
#[must_use]
pub const fn strategy_name(name: StrategyName) -> &'static str {
    match name {
        StrategyName::InteractionBfs => crate::interaction_bfs::NAME,
        StrategyName::StateNovelty => crate::novelty::NAME,
        StrategyName::Enablement => crate::enablement::NAME,
        StrategyName::EventDriven => crate::event_driven::NAME,
        StrategyName::System1 => crate::system1::NAME,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;

    #[test]
    fn configured_arms_bind_only_real_versions_and_keep_gates() {
        let gates = Gates::from_status(GateStatus::ALL);
        for name in [
            StrategyName::InteractionBfs,
            StrategyName::EventDriven,
            StrategyName::StateNovelty,
            StrategyName::Enablement,
        ] {
            let actual = build(name, &gates).unwrap();
            assert_eq!(available_versions(name), &[actual.version()]);
            let armed = build_armed(name, &[StrategyArm::new(actual.version(), 7)], &gates).unwrap();
            let (arm, selected) = armed
                .pick(
                    crawlx_core::seed::CrawlSeed(42),
                    &crawlx_core::PrincipalId("member".into()),
                    2,
                )
                .unwrap();
            assert_eq!(arm.weight, 7);
            assert_eq!(selected.name(), actual.name());
            assert_eq!(selected.version(), actual.version());
            assert!(matches!(
                build_armed(name, &[StrategyArm::new(u32::MAX, 1)], &gates),
                Err(StrategyError::UnavailableVersion {
                    version: u32::MAX,
                    ..
                })
            ));
            assert!(build_armed(name, &[], &gates).is_err());
            assert!(build_armed(name, &[StrategyArm::new(actual.version(), 0)], &gates).is_err());
            assert!(build_armed(
                name,
                &[
                    StrategyArm::new(actual.version(), 1),
                    StrategyArm::new(actual.version(), 2)
                ],
                &gates,
            )
            .is_err());
        }
        for name in [StrategyName::StateNovelty, StrategyName::Enablement] {
            assert!(matches!(
                build_armed(
                    name,
                    &[StrategyArm::new(available_versions(name)[0], 1)],
                    &Gates::from_status(GateStatus::NONE)
                ),
                Err(StrategyError::Gated { gate: "G1", .. })
            ));
        }
        assert!(matches!(
            build_armed(StrategyName::System1, &[StrategyArm::new(1, 1)], &gates),
            Err(StrategyError::UnavailableVersion { .. })
        ));
    }

    const REPORT: &[u8] = b"{\"fixture\":\"authenticated evidence\"}";

    fn keys() -> GateKeys {
        GateKeys::parse(&format!("test {}\n", "12".repeat(32))).unwrap()
    }

    fn gate_file(gate: Gate) -> GateFile {
        GateFile::signed(gate, REPORT, "0123abcd", "2026-10-19", &keys(), "test").unwrap()
    }

    fn write_gate(dir: &Path, file: &GateFile, report: &[u8]) {
        std::fs::write(dir.join(file.gate.report_name()), report).unwrap();
        std::fs::write(dir.join(file.gate.file_name()), file.to_toml().unwrap()).unwrap();
    }

    #[test]
    fn missing_directory_passes_nothing_and_refuses_gated_strategies() {
        let gates = Gates::load(Path::new("/nonexistent/crawlx-gates"));
        assert_eq!(gates.status(), GateStatus::NONE);
        assert_eq!(gates.problems().len(), 2);
        for name in [StrategyName::StateNovelty, StrategyName::Enablement] {
            let Err(err) = build(name, &gates) else {
                panic!("{name:?} built without G1");
            };
            assert!(matches!(err, StrategyError::Gated { gate: "G1", .. }), "{err}");
        }
        for name in [StrategyName::InteractionBfs, StrategyName::EventDriven] {
            assert!(build(name, &gates).is_ok());
        }
        assert!(matches!(
            build(StrategyName::System1, &gates),
            Err(StrategyError::Internal(_))
        ));
    }

    #[test]
    fn a_valid_g1_file_for_this_build_unlocks_the_gated_strategies() {
        let dir = tempfile::tempdir().unwrap();
        write_gate(dir.path(), &gate_file(Gate::G1), REPORT);
        let gates = Gates::load_with_keys(dir.path(), &keys());
        assert!(gates.status().g1 && !gates.status().g3);
        assert_eq!(gates.dir(), Some(dir.path()));
        assert!(build(StrategyName::StateNovelty, &gates).is_ok());
        assert!(build(StrategyName::Enablement, &gates).is_ok());
        assert_eq!(gates.problems().len(), 1);
        assert_eq!(gates.problems()[0].0, Gate::G3);
    }

    #[test]
    fn a_gate_file_for_another_build_or_gate_is_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let mut stale = gate_file(Gate::G1);
        stale.scope_digest = "00".repeat(32);
        std::fs::write(dir.path().join("g1.passed"), stale.to_toml().unwrap()).unwrap();
        // g3.passed attests G1: wrong gate
        std::fs::write(
            dir.path().join("g3.passed"),
            gate_file(Gate::G1).to_toml().unwrap(),
        )
        .unwrap();
        let gates = Gates::load_with_keys(dir.path(), &keys());
        assert_eq!(gates.status(), GateStatus::NONE);
        let g1 = &gates.problems()[0];
        assert!(g1.1.contains("scope digest"), "{}", g1.1);
        let g3 = &gates.problems()[1];
        assert!(g3.1.contains("attests G1 not G3"), "{}", g3.1);
        let Err(err) = build(StrategyName::Enablement, &gates) else {
            panic!("enablement built with a stale gate file");
        };
        assert!(err.to_string().contains("scope digest"), "{err}");
    }

    #[test]
    fn malformed_fields_are_reported() {
        let mut f = gate_file(Gate::G3);
        f.report_digest = "xyz".to_owned();
        assert!(f.problem(Gate::G3).unwrap().contains("report_digest"));
        f = gate_file(Gate::G3);
        f.date = "19/10/2026".to_owned();
        assert!(f.problem(Gate::G3).unwrap().contains("date"));
        f = gate_file(Gate::G3);
        f.commit = " ".to_owned();
        assert!(f.problem(Gate::G3).unwrap().contains("commit"));
        assert!(gate_file(Gate::G3).problem(Gate::G3).is_none());
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("g3.passed"), "gate = \"G3\"\n").unwrap();
        let gates = Gates::load_with_keys(dir.path(), &keys());
        assert!(!gates.status().g3);
    }

    #[test]
    fn missing_tampered_and_forged_evidence_fail_closed() {
        let dir = tempfile::tempdir().unwrap();
        let file = gate_file(Gate::G1);
        std::fs::write(dir.path().join("g1.passed"), file.to_toml().unwrap()).unwrap();
        assert!(!Gates::load_with_keys(dir.path(), &keys()).status().g1);
        write_gate(dir.path(), &file, b"tampered evidence");
        let gates = Gates::load_with_keys(dir.path(), &keys());
        assert!(gates.problems()[0].1.contains("digest does not match"));
        let mut forged = file.clone();
        forged.report_digest = Digest::of("crawlx/gate-report/v1", b"tampered evidence").to_hex();
        write_gate(dir.path(), &forged, b"tampered evidence");
        let gates = Gates::load_with_keys(dir.path(), &keys());
        assert!(gates.problems()[0].1.contains("signature does not match"));
    }

    #[test]
    fn every_metadata_field_and_signature_is_authenticated() {
        let original = gate_file(Gate::G1);
        for field in ["commit", "date", "key_id", "scope_digest", "gate", "signature"] {
            let mut file = original.clone();
            match field {
                "commit" => file.commit = "different-commit".to_owned(),
                "date" => file.date = "2026-11-04".to_owned(),
                "key_id" => file.key_id = "unknown".to_owned(),
                "scope_digest" => file.scope_digest = "00".repeat(32),
                "gate" => file.gate = Gate::G3,
                "signature" => file.signature.clear(),
                _ => unreachable!(),
            }
            assert!(file.verify(Gate::G1, REPORT, &keys()).is_err(), "{field}");
        }
        let wrong = GateKeys::parse(&format!("test {}\n", "34".repeat(32))).unwrap();
        assert!(original.verify(Gate::G1, REPORT, &wrong).is_err());
        assert!(original.verify(Gate::G1, REPORT, &GateKeys::default()).is_err());
        let mut value: toml::Value = toml::from_str(&original.to_toml().unwrap()).unwrap();
        value.as_table_mut().unwrap().remove("signature");
        assert!(toml::from_str::<GateFile>(&toml::to_string(&value).unwrap()).is_err());
        let empty = tempfile::tempdir().unwrap();
        write_gate(empty.path(), &original, REPORT);
        assert!(
            !Gates::load_with_keys(empty.path(), &GateKeys::default())
                .status()
                .g1
        );
    }

    #[test]
    fn trusted_keys_require_external_nonempty_strong_unique_configuration() {
        for invalid in ["", "# no key", "k 0011", "k not-hex", "k", "k ab cd"] {
            assert!(GateKeys::parse(invalid).is_err());
        }
        let text = format!("test {}\ntest {}\n", "12".repeat(32), "34".repeat(32));
        assert!(GateKeys::parse(&text).is_err());
        assert!(!format!("{:?}", keys()).contains(&"12".repeat(32)));
        let dir = tempfile::tempdir().unwrap();
        assert!(GateKeys::load(&dir.path().join("missing")).is_err());
    }

    #[test]
    fn g3_token_comes_only_from_authenticated_valid_calibration_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let mut report = G3Report {
            calibration_samples: 10_000,
            ece: 0.04,
            seeds: 5,
            coverage_gain_ci_low: 0.01,
            unauthorized_action_rate: 0.0,
            warm_p95_ms: 90.0,
            consecutive_nightly_improvements: 2,
        };
        let bytes = serde_json::to_vec(&report).unwrap();
        let file = GateFile::signed(Gate::G3, &bytes, "test", "2026-11-04", &keys(), "test").unwrap();
        write_gate(dir.path(), &file, &bytes);
        let gates = Gates::load_with_keys(dir.path(), &keys());
        assert!(gates.status().g3 && gates.g3_token().is_some());
        report.calibration_samples = 9_999;
        let bytes = serde_json::to_vec(&report).unwrap();
        let file = GateFile::signed(Gate::G3, &bytes, "test", "2026-11-04", &keys(), "test").unwrap();
        write_gate(dir.path(), &file, &bytes);
        let gates = Gates::load_with_keys(dir.path(), &keys());
        assert!(!gates.status().g3 && gates.g3_token().is_none());
        assert!(Gates::from_status(GateStatus::ALL).g3_token().is_none());
    }

    #[test]
    fn from_status_needs_no_files() {
        let all = Gates::from_status(GateStatus::ALL);
        assert!(all.problems().is_empty() && all.dir().is_none());
        assert!(build(StrategyName::StateNovelty, &all).is_ok());
        assert!(Gates::none().require(crate::novelty::NAME, Gate::G1).is_err());
    }
}
