//! crawlx-bench: CrawlerGym fixtures, replay harness, scorecards.
//!
//! * [`gym`]: the fixture server, ground-truth manifests and the server-side ledger.
//! * [`urlplane`]: a URL-plane crawl of the static fixture (ablation A0).
//! * [`scorecard`]: the scorecard metrics computed from run rows plus the ledger.
//! * [`policy`], [`driver`]: the layered-queue policy and a self-contained exploration driver.
//! * [`replay`]: recorded-trace replay through a decision function.
//! * [`ablation`]: the A0–A12 variant matrix and its runner.
//! * [`oracle`]: manifests and result comparison for `bench/browser-oracle`.
//! * [`golden`]: golden traces (signature, identity and action-outcome sequence) of a fixture on
//!   the pinned Chromium, compared on a pin bump.
//! * [`stats`]: paired bootstrap, Wilcoxon, pilot variance analysis and the committed seed sets.
//! * [`differential`]: the Firecrawl differential runner over data exports.
//! * [`trail`]: the trail verifier (`verify-trail`), run after every fixture crawl.
//! * [`gates`]: G1/G3 gate evaluation and `gates/*.passed` emission (`gate-g1`, `gate-g3`).
//! * [`crawl_maze`]: the security-crawl-maze scorer over the gym ledger or a run artifact (G32).
//! * [`soak`], [`load`], [`netfault`]: the soak harness, the open-loop API load
//!   generator and the in-process TCP fault proxy (toxiproxy stand-in).
//! * [`decision_dataset`], [`decision_eval`], [`decision_rig`], [`decision_report`], `decision_serve`: the System 1
//!   model evaluation: dataset collection, offline and shadow metrics, the
//!   model-in-the-loop rig over a served bundle and the assembly of the G3 evidence.
//! * [`crawl_bench`]: the `crawl-bench` harness (katana `cmd/tools/crawl-bench` equivalent):
//!   crawl gym fixtures or operator-run applications behind a recording proxy under a named
//!   profile (`static`, `katana-defaults`, `crawlx-defaults`), report pages, discovered
//!   endpoints, recall against the fixture's known endpoint list, requests/s, wall time and
//!   page latency percentiles, and compare against a baseline:
//!
//!   ```text
//!   cargo run -p crawlx-bench --release --bin crawl-bench -- \
//!       --target gym:s1 --target gym:g32 --target gym:hybrid-mix \
//!       --profile static --profile katana-defaults --profile crawlx-defaults \
//!       --repeat 3 --json bench/out/crawl-bench.json \
//!       --baseline bench/baselines/crawl-bench.json \
//!       --max-regress 0 --gate-metrics pages,endpoints,recall
//!   ```
//!
//!   `--target https://host:port/` crawls an application the operator runs (DVWA, Juice
//!   Shop); see [`crawl_bench`] for the metrics, profiles and the baseline rules.

pub mod ablation;
pub mod crawl_bench;
pub mod crawl_maze;
pub mod decision_dataset;
pub mod decision_eval;
pub mod decision_report;
pub mod decision_rig;
#[cfg(feature = "onnx")]
pub mod decision_serve;
pub mod differential;
pub mod driver;
pub mod error;
pub mod gates;
pub mod golden;
pub mod gym;
pub mod load;
pub mod netfault;
pub mod oracle;
pub mod policy;
pub mod replay;
pub mod scorecard;
pub mod soak;
pub mod stats;
pub mod strategy_replay;
pub mod trail;
pub mod urlplane;
pub mod worker_exec;

pub use error::BenchError;
