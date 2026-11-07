#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, dead_code)]
//! Shared request builders for the integration tests.

use crawlx_model::provenance::{Instruction, Provenance, ProvenanceTagged};
use crawlx_model::typed::{CandidateView, RegionSummary};
use crawlx_model::{CandidateRef, ModelId, StateView, TypedDecisionRequest, TypedQuestion};

pub fn model_id() -> ModelId {
    ModelId::new("decision-http", "typed-ranker", "b3:0123abcd", "cal-v1")
}

pub fn request(n: u32) -> TypedDecisionRequest {
    TypedDecisionRequest {
        goal: Instruction::from_static("Pick the next control to exercise."),
        state: ProvenanceTagged::new(
            Provenance::PageText,
            StateView {
                route_template: "/projects/:id".to_owned(),
                regions: vec![RegionSummary {
                    name: "main".into(),
                    summary: "project list".into(),
                }],
                candidates: (0..n)
                    .map(|i| CandidateView::new("button", &format!("Action {i}"), Some("main")))
                    .collect(),
            },
        ),
        questions: vec![
            TypedQuestion::Choice {
                id: "next_action".into(),
                options: (0..n).map(CandidateRef).collect(),
            },
            TypedQuestion::Score {
                id: "risk".into(),
                criteria: vec!["none".into(), "low".into(), "high".into()],
            },
            TypedQuestion::Noul {
                id: "modal_blocking".into(),
                question: "Is a modal dialog blocking the page?".into(),
            },
        ],
    }
}
