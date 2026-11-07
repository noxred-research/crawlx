//! crawlx-model: System-1 typed decision engines, calibration, circuit breaker,
//! rollout gating and the constrained LLM planner DSL.
//!
//! Model confidence is not safety confidence: nothing in this crate can
//! authorize an action. Engines return calibrated probabilities over a
//! crawler-built candidate list; the safety kernel (`crawlx-safety`, which this
//! crate does not depend on) still adjudicates every proposal.
//!
//! Modules: [`typed`] (request/response types, [`DecisionEngine`]),
//! [`provenance`] (untrusted-data tags, instruction/data split), [`calibration`]
//! (temperature scaling, ECE, Brier, confidence gate), [`breaker`] and [`guard`]
//! (circuit breaker, concurrency cap, time budget), [`rollout`] (modes, G3
//! token, rollout share), [`decision_http`] (HTTP adapter), [`bundle`] (model artifact
//! bundle: manifest, digests, calibration), [`onnx_ranker`] (ONNX adapter),
//! [`llm`] (`ActionPlan` DSL and planner client) and [`llm_cache`] (record, replay
//! and call cap around any `LlmExtractor`).

pub mod article_language;
pub mod breaker;
pub mod bundle;
pub mod calibration;
pub mod decision_http;
pub mod error;
pub mod guard;
pub mod llm;
pub mod llm_cache;
pub mod mock;
pub mod onnx_ranker;
pub mod planner_http;
pub mod provenance;
pub mod rollout;
pub mod typed;

pub use breaker::{BreakerConfig, BreakerState, CircuitBreaker};
pub use bundle::ModelBundle;
pub use calibration::{Gate, GateDecision, TemperatureScaler};
pub use error::ModelError;
pub use guard::{CallGuard, GuardConfig};
pub use mock::MockEngine;
pub use planner_http::{HttpPlanner, HttpPlannerConfig};
pub use provenance::{Instruction, Provenance, ProvenanceTagged, Untrusted};
pub use rollout::{G3Token, Rollout};
pub use typed::{
    CandidateRef, DecisionEngine, ModelId, StateView, TypedAnswer, TypedDecision, TypedDecisionRequest,
    TypedQuestion,
};
