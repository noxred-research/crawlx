//! A deterministic [`DecisionEngine`] for demos, the `engine: mock` worker setting and tests.
//!
//! It needs no network and no checkpoint: every `Choice` question is answered with a fixed share
//! of the probability on one favoured option and the rest spread evenly, so runs are
//! reproducible. It is not a model and must never stand in for one in a measurement.

use crate::calibration::Gate;
use crate::error::ModelError;
use crate::typed::{
    choice_answer, CandidateRef, DecisionEngine, ModelId, TypedAnswer, TypedDecision, TypedDecisionRequest,
    TypedQuestion,
};
use std::time::Instant;

/// Probability mass the mock keeps for "none of these".
const NONE_P: f32 = 0.05;

/// Answers every choice with `top_p` on the favoured option.
#[derive(Clone, Debug)]
pub struct MockEngine {
    model: ModelId,
    favoured: CandidateRef,
    top_p: f32,
    gate: Gate,
}

impl MockEngine {
    /// An engine that puts `top_p` (clamped to `[0, 0.95]`) on option `favoured` of every choice
    /// question; when the question does not offer that option, on its first option.
    #[must_use]
    pub fn new(favoured: u32, top_p: f32) -> Self {
        Self {
            model: ModelId::new("mock", "mock-v1", "", "none"),
            favoured: CandidateRef(favoured),
            top_p: top_p.clamp(0.0, 1.0 - NONE_P),
            gate: Gate::default(),
        }
    }

    /// Replace the confidence gate applied to choice answers.
    #[must_use]
    pub const fn with_gate(mut self, gate: Gate) -> Self {
        self.gate = gate;
        self
    }
}

impl Default for MockEngine {
    /// Favours the first option with `0.85`: above the default gate, so advisory mode acts.
    fn default() -> Self {
        Self::new(0, 0.85)
    }
}

#[async_trait::async_trait]
impl DecisionEngine for MockEngine {
    async fn decide(&self, req: TypedDecisionRequest) -> Result<TypedDecision, ModelError> {
        req.validate()?;
        let started = Instant::now();
        let mut answers = Vec::with_capacity(req.questions.len());
        let mut abstained = Vec::new();
        for q in &req.questions {
            match q {
                TypedQuestion::Choice { id, options } => {
                    let favoured = options.iter().position(|o| *o == self.favoured).unwrap_or(0);
                    let others = options.len().saturating_sub(1);
                    let (top, rest) = if others == 0 {
                        (1.0 - NONE_P, 0.0)
                    } else {
                        let spread = (1.0 - NONE_P - self.top_p)
                            / f32::from(u16::try_from(others).unwrap_or(u16::MAX));
                        (self.top_p, spread)
                    };
                    let probs: Vec<f32> = (0..options.len())
                        .map(|i| if i == favoured { top } else { rest })
                        .collect();
                    let (answer, did_abstain) = choice_answer(id, options, &probs, NONE_P, &self.gate);
                    if did_abstain {
                        abstained.push(id.clone());
                    }
                    answers.push(answer);
                }
                TypedQuestion::Score { id, criteria } => {
                    let n = f32::from(u16::try_from(criteria.len()).unwrap_or(u16::MAX));
                    answers.push(TypedAnswer::Score {
                        id: id.clone(),
                        distribution: vec![1.0 / n; criteria.len()],
                        level: 0,
                    });
                }
                TypedQuestion::Noul { id, .. } => answers.push(TypedAnswer::Noul {
                    id: id.clone(),
                    p_yes: 0.5,
                }),
            }
        }
        Ok(TypedDecision {
            answers,
            abstained,
            latency_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
            model: self.model.clone(),
        })
    }

    fn id(&self) -> &ModelId {
        &self.model
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    use super::*;
    use crate::provenance::{Instruction, Provenance, ProvenanceTagged};
    use crate::typed::{CandidateView, StateView};

    fn request(n: u32) -> TypedDecisionRequest {
        TypedDecisionRequest {
            goal: Instruction::from_static("Pick."),
            state: ProvenanceTagged::new(
                Provenance::PageText,
                StateView {
                    route_template: "/".to_owned(),
                    regions: Vec::new(),
                    candidates: (0..n)
                        .map(|i| CandidateView::new("button", &format!("B{i}"), None))
                        .collect(),
                },
            ),
            questions: vec![TypedQuestion::Choice {
                id: "next_action".to_owned(),
                options: (0..n).map(CandidateRef).collect(),
            }],
        }
    }

    #[tokio::test]
    async fn favours_the_configured_option_and_probabilities_sum_to_one() {
        let d = MockEngine::new(2, 0.8).decide(request(4)).await.unwrap();
        let Some(TypedAnswer::Choice {
            probs,
            none_p,
            selected,
            ..
        }) = d.answer("next_action")
        else {
            panic!("a choice answer");
        };
        assert_eq!(*selected, Some(CandidateRef(2)));
        assert!((probs.iter().map(|(_, p)| p).sum::<f32>() + none_p - 1.0).abs() < 1e-5);
        assert!(d.abstained.is_empty());
    }

    #[tokio::test]
    async fn an_option_that_is_not_offered_falls_back_to_the_first() {
        let d = MockEngine::new(9, 0.8).decide(request(3)).await.unwrap();
        assert_eq!(d.selected("next_action"), Some(CandidateRef(0)));
    }

    #[tokio::test]
    async fn a_low_share_abstains_at_the_gate() {
        let d = MockEngine::new(0, 0.3).decide(request(3)).await.unwrap();
        assert_eq!(d.selected("next_action"), None);
        assert_eq!(d.abstained, vec!["next_action".to_owned()]);
    }

    #[tokio::test]
    async fn invalid_requests_are_refused() {
        let mut r = request(2);
        r.questions.clear();
        assert!(matches!(
            MockEngine::default().decide(r).await,
            Err(ModelError::InvalidRequest(_))
        ));
    }
}
