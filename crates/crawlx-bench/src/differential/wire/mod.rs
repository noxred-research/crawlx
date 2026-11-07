//! Wire-level differential (families VAL, PREC, CLAMP, PERSIST, CANCEL, RESUME, LEASE, WH,
//! ZDR): scenarios over the Firecrawl v2 HTTP surface, run against any API that speaks it.
//!
//! The crawl families of the parent module compare *what was crawled*; these compare *what the
//! API does*: whether a request body is accepted, how a crawl ends after a cancel or a restart,
//! which webhook events a sink receives. A [`WireSpec`] (`bench/differential/wire-scenarios.json`)
//! names the scenarios; [`driver::run_family`] executes one family against a [`Target`] (the
//! unmodified Firecrawl self-host, or the crawlx compat facade) and returns a [`WireCapture`] of
//! raw exchanges; [`compare::compare`] derives observations from two captures and judges them
//! under the divergence ledger. Captures of the real Firecrawl are committed data
//! (`bench/differential/captures/<family>.json`), so the comparison replays offline.

pub mod cli;
pub mod compare;
pub mod driver;
pub mod sink;

use super::access::AccessLog;
use crate::error::BenchError;
use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::path::Path;

pub use compare::{compare, Observation, WireReport};
pub use driver::{run_family, Target};
pub use sink::{Sink, SinkEvent};

/// The scenario file: families of wire scenarios.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct WireSpec {
    /// Format version (1).
    #[serde(default)]
    pub version: u32,
    /// The families.
    pub families: Vec<WireFamily>,
}

/// One family: a list of scenarios sharing a fixture seed and an expected verdict.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct WireFamily {
    /// Family id (the runner label and the `families` key of ledger entries).
    pub id: String,
    /// Families the scenarios belong to (`VAL`, `CLAMP`, ...).
    #[serde(default)]
    pub plan_families: Vec<String>,
    /// Seed path below the gym origin that `{seed}` expands to.
    #[serde(default)]
    pub seed_path: String,
    /// Verdict a committed capture pair must reach (`pass`, `warn`, `block`).
    #[serde(default)]
    pub expect: Option<String>,
    /// Why a `block` family stays open: the known gap it documents.
    #[serde(default)]
    pub open: Option<String>,
    /// Scenarios in execution order.
    pub scenarios: Vec<Scenario>,
}

/// How a scenario ends the crawl it started.
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(tag = "mode", rename_all = "snake_case")]
#[non_exhaustive]
pub enum Settle {
    /// Leave the crawl alone (lookups, rejected requests).
    None,
    /// Cancel it right after the request was accepted (an accepted validation case must not
    /// keep crawling).
    #[default]
    Cancel,
    /// Poll until the crawl is terminal.
    Terminal {
        /// Give up after this many seconds.
        #[serde(default = "default_timeout")]
        timeout_s: u64,
    },
    /// Poll until `completed` reaches a count, then cancel, then poll until terminal.
    CancelAfter {
        /// Completed documents that trigger the cancel.
        completed: u64,
        /// Give up waiting for the trigger after this many seconds.
        #[serde(default = "default_timeout")]
        timeout_s: u64,
    },
}

const fn default_timeout() -> u64 {
    180
}

/// An action on the system under test while a crawl runs.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[non_exhaustive]
pub struct HookSpec {
    /// Run the hook once `completed` reaches this count (`0`: right after the request).
    #[serde(default)]
    pub after_completed: u64,
    /// Give up waiting for the trigger after this many seconds.
    #[serde(default = "default_timeout")]
    pub timeout_s: u64,
    /// Poll until terminal for this many seconds after the hook ran.
    #[serde(default = "default_timeout")]
    pub then_timeout_s: u64,
}

/// A webhook the request carries, delivered to the runner's sink.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct WebhookSpec {
    /// Sink label (the path `/hook/{label}` the webhook URL names).
    pub label: String,
    /// Custom headers the delivery must carry.
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Metadata the events must echo.
    #[serde(default)]
    pub metadata: Option<Value>,
    /// Event filter (`started`, `page`, `completed`, `failed`); `None` leaves it out.
    #[serde(default)]
    pub events: Option<Vec<String>>,
    /// The sink answers the first this-many deliveries with `fail_status` (retry behavior).
    #[serde(default)]
    pub fail_first: u32,
    /// Status the failing deliveries get.
    #[serde(default = "default_fail_status")]
    pub fail_status: u16,
}

const fn default_fail_status() -> u16 {
    500
}

/// A request issued after the crawl settled; `{id}` expands to the crawl id.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct AfterStep {
    /// Label (`after:<label>` in the capture).
    pub label: String,
    /// HTTP method.
    #[serde(default = "get")]
    pub method: String,
    /// Path below the API root.
    pub path: String,
    /// JSON body.
    #[serde(default)]
    pub body: Option<Value>,
}

fn get() -> String {
    "GET".to_owned()
}

fn post() -> String {
    "POST".to_owned()
}

fn crawl_path() -> String {
    "/v2/crawl".to_owned()
}

/// One scenario: a request, how the crawl it starts is settled, and what is recorded.
#[derive(Clone, Debug, Deserialize)]
#[non_exhaustive]
pub struct Scenario {
    /// Scenario id; ledger entries match `<id>/<observation>`.
    pub id: String,
    /// What the scenario probes.
    #[serde(default)]
    pub description: String,
    /// HTTP method of the request.
    #[serde(default = "post")]
    pub method: String,
    /// Path below the API root.
    #[serde(default = "crawl_path")]
    pub path: String,
    /// JSON body; strings may contain `{seed}`, `{origin}` and `{sink}` placeholders.
    #[serde(default)]
    pub body: Option<Value>,
    /// Raw request body sent as is with a JSON content type (malformed JSON); wins over `body`.
    #[serde(default)]
    pub raw_body: Option<String>,
    /// Seed path override for `{seed}`.
    #[serde(default)]
    pub seed_path: Option<String>,
    /// How the started crawl ends.
    #[serde(default)]
    pub settle: Settle,
    /// Webhook the request carries.
    #[serde(default)]
    pub webhook: Option<WebhookSpec>,
    /// Action while the crawl runs (restart of the API and its workers).
    #[serde(default)]
    pub hook: Option<HookSpec>,
    /// Requests issued after the settle.
    #[serde(default)]
    pub after: Vec<AfterStep>,
    /// After the settle, watch the gym for this long and record how many page requests it saw
    /// (a cancelled crawl must go quiet).
    #[serde(default)]
    pub quiet_ms: u64,
    /// After the settle, wait this long for webhook deliveries before reading the sink.
    #[serde(default)]
    pub sink_grace_ms: u64,
}

impl WireSpec {
    /// Load the scenario file.
    ///
    /// # Errors
    /// [`BenchError::Io`] when the file cannot be read, [`BenchError::Json`] when it does not
    /// parse.
    pub fn load(path: &Path) -> Result<Self, BenchError> {
        let bytes = std::fs::read(path).map_err(|e| BenchError::io(path, e))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// The family `id`.
    #[must_use]
    pub fn family(&self, id: &str) -> Option<&WireFamily> {
        self.families.iter().find(|f| f.id == id)
    }
}

/// Where a capture came from.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct WireProvenance {
    /// `black_box_run` (the real Firecrawl) or `crawlx_facade`.
    pub provenance: String,
    /// System name (`firecrawl`, `crawlx`).
    pub system: String,
    /// Pinned upstream commit, for the real Firecrawl.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_commit: Option<String>,
    /// API root the requests went to.
    pub api_root: String,
    /// Origin the system reached the gym on (URL keys are rebased against it).
    pub origin: String,
}

/// One HTTP exchange of a scenario.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct Exchange {
    /// Step label: `request`, `trigger`, `settle`, `final`, `after:<label>`.
    pub step: String,
    /// HTTP method.
    pub method: String,
    /// Path below the API root.
    pub path: String,
    /// JSON request body.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request: Option<Value>,
    /// HTTP status; `0` when no response arrived.
    pub status: u16,
    /// JSON response body, with documents reduced to `sourceURL` and `statusCode`; a body that
    /// is not JSON is `{"_text": "..."}`, a transport error `{"_error": "..."}`.
    pub response: Value,
    /// Wall time of the exchange in milliseconds (informational, never compared).
    #[serde(default)]
    pub elapsed_ms: u64,
}

/// What one scenario recorded.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[non_exhaustive]
pub struct ScenarioCapture {
    /// Scenario id.
    pub id: String,
    /// The exchanges in order.
    pub exchanges: Vec<Exchange>,
    /// Facts the driver recorded outside HTTP exchanges: `quiet_requests`, `sink_events`,
    /// `hook` outcome.
    #[serde(default)]
    pub notes: BTreeMap<String, Value>,
}

impl ScenarioCapture {
    /// The first exchange labelled `step`.
    #[must_use]
    pub fn exchange(&self, step: &str) -> Option<&Exchange> {
        self.exchanges.iter().find(|e| e.step == step)
    }
}

/// The capture of one family on one system.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
#[non_exhaustive]
pub struct WireCapture {
    /// Where it came from.
    pub wire_sample: WireProvenance,
    /// Family id.
    pub family: String,
    /// Scenarios in spec order.
    pub scenarios: Vec<ScenarioCapture>,
    /// The gym's access log over the whole family, when the gym was fresh for it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_log: Option<AccessLog>,
}

impl WireCapture {
    /// Load a capture file.
    ///
    /// # Errors
    /// [`BenchError::Io`] / [`BenchError::Json`].
    pub fn load(path: &Path) -> Result<Self, BenchError> {
        let bytes = std::fs::read(path).map_err(|e| BenchError::io(path, e))?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    /// Write the capture as pretty JSON with sorted keys.
    ///
    /// # Errors
    /// [`BenchError::Json`] / [`BenchError::Io`].
    pub fn save(&self, path: &Path) -> Result<(), BenchError> {
        let mut bytes = serde_json::to_vec_pretty(self)?;
        bytes.push(b'\n');
        std::fs::write(path, bytes).map_err(|e| BenchError::io(path, e))
    }

    /// The scenario `id`.
    #[must_use]
    pub fn scenario(&self, id: &str) -> Option<&ScenarioCapture> {
        self.scenarios.iter().find(|s| s.id == id)
    }
}

/// Actions on the system under test that a scenario's [`HookSpec`] triggers.
#[async_trait]
pub trait Hooks: Send + Sync {
    /// Restart the API and every worker of the system, killing in-flight work.
    ///
    /// # Errors
    /// A message when the restart could not be carried out.
    async fn restart(&self) -> Result<(), String>;
}

/// [`Hooks`] that run a shell command (`docker compose ... restart api` for the Firecrawl stack).
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct ShellHooks {
    /// The command, run with `sh -c`.
    pub restart: String,
}

#[async_trait]
impl Hooks for ShellHooks {
    async fn restart(&self) -> Result<(), String> {
        let out = tokio::process::Command::new("sh")
            .arg("-c")
            .arg(&self.restart)
            .output()
            .await
            .map_err(|e| format!("restart command: {e}"))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "restart command exited with {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }
}

/// Expand `{seed}`, `{origin}` and `{sink}` in every string of `value`.
#[must_use]
pub fn substitute(value: &Value, vars: &BTreeMap<&str, String>) -> Value {
    match value {
        Value::String(s) => {
            let mut out = s.clone();
            for (k, v) in vars {
                out = out.replace(&format!("{{{k}}}"), v);
            }
            Value::String(out)
        }
        Value::Array(a) => Value::Array(a.iter().map(|v| substitute(v, vars)).collect()),
        Value::Object(m) => Value::Object(m.iter().map(|(k, v)| (k.clone(), substitute(v, vars))).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use serde_json::json;

    #[test]
    fn placeholders_expand_in_nested_strings_only() {
        let vars = BTreeMap::from([("seed", "http://gym.test:1/d2/tiny/".to_owned())]);
        let v = substitute(
            &json!({"url": "{seed}", "n": 3, "a": ["x{seed}", {"b": "{seed}"}]}),
            &vars,
        );
        assert_eq!(v["url"], "http://gym.test:1/d2/tiny/");
        assert_eq!(v["n"], 3);
        assert_eq!(v["a"][0], "xhttp://gym.test:1/d2/tiny/");
        assert_eq!(v["a"][1]["b"], "http://gym.test:1/d2/tiny/");
    }

    #[test]
    fn scenarios_default_to_a_cancelled_crawl_request() {
        let s: Scenario = serde_json::from_value(json!({"id": "x", "body": {"url": "{seed}"}})).unwrap();
        assert_eq!(s.method, "POST");
        assert_eq!(s.path, "/v2/crawl");
        assert_eq!(s.settle, Settle::Cancel);
        let t: Scenario = serde_json::from_value(
            json!({"id": "y", "settle": {"mode": "terminal", "timeout_s": 9}, "hook": {"after_completed": 2}}),
        )
        .unwrap();
        assert_eq!(t.settle, Settle::Terminal { timeout_s: 9 });
        assert_eq!(t.hook.unwrap().after_completed, 2);
    }
}
