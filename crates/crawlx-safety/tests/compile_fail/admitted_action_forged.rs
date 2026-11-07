//! `AdmittedAction` has private fields and a private seal, so a
//! strategy or model adapter cannot build one; `SafetyKernel::adjudicate` is the only source.
use crawlx_safety::{AdmittedAction, Adjudication};

fn forge() -> AdmittedAction {
    AdmittedAction { _seal: () }
}

fn forge_verdict(a: Adjudication) -> AdmittedAction {
    match a {
        Adjudication::Allow(admitted) => admitted,
        Adjudication::Deny(verdict) | Adjudication::ApprovalRequired(verdict, _) => AdmittedAction { verdict },
    }
}

fn main() {}
