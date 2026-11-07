//! crawlx-core: shared IDs, value types, configuration, typed errors and the
//! repository/service traits every other crate implements or consumes.
//!
//! This crate depends on no other crawlx crate. A type lives
//! here only if at least two crates need it and it performs no I/O.

pub mod acquisition;
pub mod action;
pub mod archive;
pub mod archive_catalog;
pub mod article_language;
pub mod browser;
pub mod cache;
pub mod captcha;
pub mod checkpoint_crypto;
pub mod config;
pub mod counters;
pub mod custody;
pub mod data_capabilities;
pub mod dataset;
pub mod discovery;
pub mod dom_ops;
pub mod epoch;
pub mod error;
pub mod extensions;
pub mod extraction;
pub mod extraction_import;
pub mod gates;
pub mod hash;
pub mod identity;
pub mod ids;
pub mod observation;
pub mod orchestration;
pub mod origin;
pub mod page_op;
pub mod priority;
pub mod proposal;
pub mod protocol;
pub mod repo;
pub mod request;
pub mod request_controls;
pub mod runtime_admission;
pub mod safety;
pub mod scrape;
pub mod secret;
pub mod seed;
pub mod selectors;
pub mod session_binding;
pub mod state;
pub mod time;
pub mod tls;
pub mod traffic;
pub mod url;

pub use action::{BrowserAction, KeyChord, Modifiers, OptionKey, PointerButton, ScrollDelta};
pub use browser::{
    BlockedNavigation, BrowserBackend, BrowserContext, BrowserError, ContextConfig, NavigationGuard,
    NavigationVerdict,
};
pub use config::{CrawlMode, CreateCrawl, LaunchProfile, SafetyProfile};
pub use epoch::ObservationEpoch;
pub use error::{Classify, CoreError, ErrorClass, StoreError};
pub use identity::{
    ActionContextKey, ActionKind, ElementIdentityHash, ElementIdentityV1, InputClass, ResourceContext,
};
pub use ids::*;
pub use proposal::{ActionProposal, ProposalClass};
pub use safety::{RiskClass, SafetyVerdict};
pub use secret::{SecretOr, SecretResolver};
pub use time::{Clock, SystemClock, Timestamp};
pub use traffic::{Fidelity, TrustLane};
pub use url::{CanonicalUrl, ParamClass, RouteKey, RouteTemplate};
