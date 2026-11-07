//! crawlx-worker: lease loop, browser pool, Session Actors, exploration drivers, the
//! static-plane runner and the local in-process run.
//!
//! * [`actor`] – [`SessionActor`] / [`SessionHandle`]: the single writer of a browser context,
//!   the per-action protocol (epoch check → revalidate → confirm → T1 → perform → settle →
//!   observe → T2), reconciliation and checkpoints.
//! * [`recovery`] – the recovery ladder; [`checkpoint`] – checkpoint artifacts and restore.
//! * [`pool`] – [`BrowserPool`]: lazily launched Chromium processes, context semaphores.
//! * [`supervisor`] – [`Supervisor`]: panics become typed [`SessionFailure`] events.
//! * [`login`] – `builtin:form` login with a [`crawlx_core::SecretResolver`].
//! * [`secrets`] – [`ChainResolver`]: `env://`, `file://`, `vault://`, `aws-sm://`, `totp://`.
//! * [`driver`] – [`ExplorationDriver`]: strategies, arbiter, safety kernel, switching policy.
//! * [`model`] – [`ModelServices`]: System 1 engine and LLM planner clients and their strategies.
//! * [`url_plane`] – [`UrlPlaneRunner`]: robots, sitemap, frontier, fetch, extract, pages.
//! * [`scrape`] – [`ScrapeEngine`]: Firecrawl scrape documents (cache, formats, change
//!   tracking, LLM formats, browser rendering) for the pages of scrape runs.
//! * [`authorization`] – [`AuthorizationGuard`]: the run's authorization record,
//!   its target as a hard bound on every request and its revocation or expiry as a run stop.
//! * [`lease_loop`] – [`run`]: the worker process.
//! * [`run`](mod@run) – [`run::run_local`]: create and execute a run in-process.

#![warn(missing_docs)]

pub mod acquisition;
pub mod action_trace;
pub mod actor;
pub mod analysis;
pub mod archive_qa;
pub(crate) mod archive_recorder;
pub mod archive_replay;
pub mod authorization;
pub mod capture;
pub mod chaos;
pub mod checkpoint;
pub mod config;
pub mod counters;
pub mod delivery;
pub mod diagnostics;
pub(crate) mod driven;
pub mod driver;
pub mod error;
pub mod extensions;
pub mod fixture_evaluation;
pub mod katana;
pub mod lease_loop;
pub mod login;
pub mod media_probe;
pub mod model;
pub mod output;
mod pacing;
pub mod pool;
pub(crate) mod profile_lifecycle;
pub mod protocol;
pub mod recovery;
pub mod replay;
pub(crate) mod replay_queue;
pub mod robots_gate;
pub(crate) mod role_budget;
pub mod routes;
pub mod run;
pub mod runtime;
pub mod runtime_admission;
pub mod scrape;
pub mod secrets;
pub mod stores;
pub mod supervisor;
pub mod url_plane;
pub mod xhr;

pub use actor::{
    ActionOutcome, DropReason, RestoreReport, SessionActor, SessionCommand, SessionConfig, SessionHandle,
    SessionServices, SessionState, SessionStats, ShutdownReason,
};
pub use analysis::{Analyzed, RunClusters, StateAnalyzer};
pub use authorization::{
    AuthorizationGuard, AuthorizationSource, AuthorizationStop, AuthorizationWatch, PgAuthorizationSource,
    StaticAuthorizationSource, DEFAULT_RECHECK_INTERVAL,
};
pub use checkpoint::{CheckpointPayload, Checkpointer};
pub use config::{EgressConfig, RetainedProfilePolicy, WorkerConfig};
pub use counters::{Attempt, Plane, RunCounters};
pub use crawlx_browser::{pin as chromium_pin, ChromiumPin};
pub use crawlx_strategies::Gates;
pub use diagnostics::{DiagnosticsSink, SessionDiagnostics};
pub use driver::{
    build_strategies, build_strategies_gated, build_strategy_set, DriverConfig, DriverEnd, ExplorationDriver,
    ShortlistRecording,
};
pub use error::{SessionError, WorkerError};
pub use lease_loop::run;
pub use login::{LoginCredential, LoginMaterial, MAX_LOGIN_ATTEMPTS};
pub use model::{
    EngineConfig, ModelConfig, ModelOverlay, ModelServices, PlannerConfig, ProvidedEngine, StrategySet,
};
pub use output::{
    expand_patterns, field_names, write_error_log, Dsl, DslError, ExportFormat, ExportStats, Exporter, Field,
    OutputError, OutputFilters, PageText, Record, StoreFields, StoredResponses, Template, TextFile,
};
pub use pool::{BrowserPool, PoolConfig, PooledContext};
pub use recovery::RecoveryRung;
pub use replay::{ReplayMode, ReplayPlan, ReplayReport, ReplayRunner, StepResult, StepVerdict};
pub use robots_gate::RobotsGate;
pub use routes::{LearnedRoutes, RouteLearner, ROUTE_TEMPLATES_EVENT};
pub use run::{
    run_local, run_local_with, CaptureReport, EgressCapture, LocalRun, RunContext, RunReport, UrlFailure,
};
pub use runtime::{build_runtime, CpuPool, RuntimeConfig, RuntimeConfigError, PARSE_MEMORY_ENV};
pub use scrape::{FailReason, Outcome, PageRenderer, ScrapeEngine, ScrapeFailure, Scraped};
pub use secrets::{
    AwsSecretsManagerResolver, ChainResolver, EnvSecretResolver, FileSecretResolver, SecretError,
    TotpResolver, VaultResolver,
};
pub use stores::Stores;
pub use supervisor::{SessionFailure, Supervisor};
pub use url_plane::{UrlPlaneDeps, UrlPlaneOutcome, UrlPlaneRunner};
pub use xhr::XhrSink;
