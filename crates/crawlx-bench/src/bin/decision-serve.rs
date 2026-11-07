//! `decision-serve`: serve a model bundle through the typed-decision endpoint.
//!
//! ```text
//! decision-serve --bundle DIR [--bind ADDR] [--ep cpu|cuda[:N]]
//! ```
//!
//! Needs the ONNX Runtime shared library: `ORT_DYLIB_PATH` names it (a GPU build for
//! `--ep cuda`). The process prints `listening <endpoint>` on stdout once the model answered a
//! warm-up request, then serves until interrupted. Point the worker at the printed URL with
//! `crawl --model-endpoint URL --system1-mode shadow`.

use clap::Parser;
use crawlx_bench::decision_serve::start;
use crawlx_bench::error::chain;
use crawlx_model::onnx_ranker::{ExecutionProvider, OnnxRankerEngine};
use crawlx_model::provenance::{Instruction, Provenance, ProvenanceTagged};
use crawlx_model::typed::CandidateView;
use crawlx_model::{
    CandidateRef, DecisionEngine, GuardConfig, StateView, TypedDecisionRequest, TypedQuestion,
};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

#[derive(Parser, Debug)]
#[command(
    name = "decision-serve",
    version,
    about = "Serve a model bundle through the typed-decision endpoint"
)]
struct Cli {
    /// Model bundle directory (`manifest.json`, `model.onnx`, `tokenizer.json`, `calibration.json`).
    #[arg(long)]
    bundle: PathBuf,
    /// Address to listen on; port 0 picks a free one.
    #[arg(long, default_value = "127.0.0.1:0")]
    bind: SocketAddr,
    /// Execution provider: `cpu`, `cuda` or `cuda:<device>`.
    #[arg(long, default_value = "cpu")]
    ep: String,
}

/// A 16-candidate request: loads the CUDA context and fills the provider's caches before the
/// first real request, which would otherwise exceed the call budget.
fn warm_up_request() -> TypedDecisionRequest {
    TypedDecisionRequest {
        goal: Instruction::from_static(
            "Pick the control most likely to reach functionality that has not been exercised yet.",
        ),
        state: ProvenanceTagged::new(
            Provenance::PageText,
            StateView {
                route_template: "/warm-up".to_owned(),
                regions: Vec::new(),
                candidates: (0..16)
                    .map(|i| CandidateView::new("button", &format!("warm {i}"), Some("main")))
                    .collect(),
            },
        ),
        questions: vec![TypedQuestion::Choice {
            id: "next_action".to_owned(),
            options: (0..16).map(CandidateRef).collect(),
        }],
    }
}

async fn run(cli: Cli) -> Result<(), String> {
    let provider = ExecutionProvider::parse(&cli.ep).map_err(|e| e.to_string())?;
    let engine = Arc::new(
        OnnxRankerEngine::from_bundle_with(&cli.bundle, GuardConfig::local(), provider)
            .map_err(|e| format!("load {}: {e}", cli.bundle.display()))?,
    );
    for _ in 0..3 {
        // the first calls pay for context creation; later ones are the warm path
        let _ = engine.decide(warm_up_request()).await;
    }
    let handle = start(engine, cli.bind).await.map_err(|e| chain(&e))?;
    println!("listening {}", handle.endpoint);
    tokio::signal::ctrl_c()
        .await
        .map_err(|e| format!("signal: {e}"))?;
    handle.shutdown().await;
    Ok(())
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match tokio::runtime::Runtime::new() {
        Ok(rt) => match rt.block_on(run(cli)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(msg) => {
                eprintln!("decision-serve: {msg}");
                ExitCode::from(1)
            }
        },
        Err(e) => {
            eprintln!("decision-serve: runtime: {e}");
            ExitCode::from(2)
        }
    }
}
