//! Chromium-corpus quality gates.
//!
//! One integration binary, one module per gate family. Chromium-backed tests skip (with a
//! message) when no executable is installed; every other test is deterministic and offline.
//!
//! * [`identity`] — 20-reload identity run over G02/G06 on real Chromium.
//! * [`states`] — G26 corpus report, `feed-and-clock` explosion guard.
//! * [`fixtures`] — per-row scorecard gates for every fixture without a
//!   behavioural test; `hybrid-mix` hybrid > max(static, dynamic).
//! * [`graph`] — enablement replay ≥ 0.9 on G11/G13, A7-vs-A8 efficiency.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod fixtures;
mod graph;
mod identity;
mod states;
