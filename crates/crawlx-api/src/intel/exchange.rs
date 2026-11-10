//! The exchange seam of the agent (`exchange` request member): third-party data providers the
//! agent may call besides the web. the reference service offers them as hosted providers; crawlx has no hosted
//! catalogue, so the operator plugs one in through [`ExchangeProvider`] (production wiring is the
//! coordinator's job; [`MockExchange`] serves hermetic tests).
//!
//! A provider is a *toolkit* (`slug`, such as `apollo`) with named *capabilities*. A capability
//! is `paid` when a call costs credits (and then waits for approval under
//! `exchange.requireApproval`), and may support zero data retention. A toolkit whose data terms
//! the tenant has not accepted is never called.

use async_trait::async_trait;
use crawlx_core::TenantId;
use parking_lot::Mutex;
use serde_json::Value;
use std::collections::BTreeMap;

/// One thing a toolkit can do.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Capability {
    /// Name within the toolkit (`people/search`).
    pub name: String,
    /// What the capability returns, shown to the agent.
    pub description: String,
    /// Whether a call costs credits and needs approval under `requireApproval`.
    pub paid: bool,
    /// Credits a call is expected to cost, when known.
    pub credits_estimate: Option<u64>,
    /// Whether the capability may run in a zero-data-retention agent run.
    pub supports_zdr: bool,
}

/// Data terms a toolkit needs the tenant to accept before it may be called.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Terms {
    /// Terms version.
    pub version: String,
    /// Terms digest, when the catalogue published one.
    pub digest: Option<String>,
    /// Where a person accepts the terms.
    pub url: String,
    /// Whether the tenant has accepted this version.
    pub accepted: bool,
}

/// A provider of data the agent may call.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Toolkit {
    /// Slug used in `exchange.toolkits`.
    pub slug: String,
    /// Display name.
    pub name: String,
    /// What the toolkit offers.
    pub capabilities: Vec<Capability>,
    /// Terms gating the toolkit, when it has any.
    pub terms: Option<Terms>,
}

/// One call to a toolkit capability.
#[derive(Clone, PartialEq, Debug)]
pub struct ExchangeCall {
    /// Toolkit slug.
    pub toolkit: String,
    /// Capability name.
    pub capability: String,
    /// Capability input.
    pub input: Value,
}

/// What a call returned.
#[derive(Clone, PartialEq, Debug)]
pub struct ExchangeOutput {
    /// Provider data.
    pub output: Value,
    /// Credits the call cost.
    pub credits: u64,
}

/// Failure of a provider call.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ExchangeError {
    /// The toolkit or capability does not exist.
    #[error("unknown provider capability: {0}")]
    Unknown(String),
    /// The provider could not serve the call.
    #[error("{0}")]
    Failed(String),
}

/// A catalogue of data providers. Object-safe.
#[async_trait]
pub trait ExchangeProvider: Send + Sync {
    /// Toolkits `tenant` may use.
    async fn toolkits(&self, tenant: TenantId) -> Vec<Toolkit>;

    /// Run `call` for `tenant`.
    ///
    /// # Errors
    /// [`ExchangeError::Unknown`] for an unknown toolkit or capability, [`ExchangeError::Failed`]
    /// when the provider fails.
    async fn call(&self, tenant: TenantId, call: &ExchangeCall) -> Result<ExchangeOutput, ExchangeError>;
}

type Outputs = BTreeMap<(String, String), Result<ExchangeOutput, ExchangeError>>;

/// An [`ExchangeProvider`] with canned toolkits and outputs that records the calls it served.
#[derive(Debug, Default)]
pub struct MockExchange {
    toolkits: Mutex<Vec<Toolkit>>,
    outputs: Mutex<Outputs>,
    calls: Mutex<Vec<ExchangeCall>>,
}

impl MockExchange {
    /// A mock offering `toolkits`; every call fails until [`Self::set_output`] answers it.
    #[must_use]
    pub fn new(toolkits: Vec<Toolkit>) -> Self {
        Self {
            toolkits: Mutex::new(toolkits),
            ..Self::default()
        }
    }

    /// Answer calls of `toolkit`/`capability` with `output` costing `credits`.
    pub fn set_output(&self, toolkit: &str, capability: &str, output: Value, credits: u64) {
        self.outputs.lock().insert(
            (toolkit.to_owned(), capability.to_owned()),
            Ok(ExchangeOutput { output, credits }),
        );
    }

    /// Make calls of `toolkit`/`capability` fail with `error`.
    pub fn set_failure(&self, toolkit: &str, capability: &str, error: ExchangeError) {
        self.outputs
            .lock()
            .insert((toolkit.to_owned(), capability.to_owned()), Err(error));
    }

    /// Change whether the terms of `toolkit` are accepted.
    pub fn accept_terms(&self, toolkit: &str, accepted: bool) {
        for t in self.toolkits.lock().iter_mut().filter(|t| t.slug == toolkit) {
            if let Some(terms) = t.terms.as_mut() {
                terms.accepted = accepted;
            }
        }
    }

    /// Every call served so far, oldest first.
    #[must_use]
    pub fn calls(&self) -> Vec<ExchangeCall> {
        self.calls.lock().clone()
    }
}

#[async_trait]
impl ExchangeProvider for MockExchange {
    async fn toolkits(&self, _tenant: TenantId) -> Vec<Toolkit> {
        self.toolkits.lock().clone()
    }

    async fn call(&self, _tenant: TenantId, call: &ExchangeCall) -> Result<ExchangeOutput, ExchangeError> {
        self.calls.lock().push(call.clone());
        self.outputs
            .lock()
            .get(&(call.toolkit.clone(), call.capability.clone()))
            .cloned()
            .unwrap_or_else(|| {
                Err(ExchangeError::Unknown(format!(
                    "{}/{}",
                    call.toolkit, call.capability
                )))
            })
    }
}
