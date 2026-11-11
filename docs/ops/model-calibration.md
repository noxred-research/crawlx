# Model calibration

A System 1 model gives each option on its shortlist a calibrated probability, and the confidence
gate accepts an option only when that probability is high enough and clear of the runner-up. The
release gate checks calibration once, on held-out data: expected calibration error (ECE) at most
0.05. A model in service can drift away from that: a model update, a change in the sites crawled
or a shift in the data makes its confidence stop matching how often it is right. Then the gate
lets weak candidates through, or abstains far too often. This page covers the in-service monitor,
the metrics and the alert.

Safety never depends on model confidence. A drifting model cannot authorize an action: its
proposals still pass the arbiter and the safety kernel, and a model that abstains falls back to the
deterministic ranking.

## What is measured

The worker keeps, for each provider and model, two rolling windows of the last 1000 entries
(`crawlx_model::calibration::DriftMonitor`):

- **Graded outcomes.** Each entry is the calibrated probability the model gave its top option and
  whether that option turned out right. The window's ECE uses the same ten equal-width bins as the
  release gate, so the two numbers compare directly.
- **Gate decisions.** Each entry says whether the confidence gate accepted or abstained. Every
  System 1 record the worker flushes adds one.

A window starts empty and never reads a clock. A model with a new calibration version starts new
windows, so a refit is judged on its own outcomes and the previous fit's number is retired.

Only an observed outcome is a graded outcome. Agreement with the deterministic ranking is not one,
and an abstention is never graded. Feed outcomes with
`crawlx_worker::model::record_calibration_outcome(model, confidence, correct)` from whatever
establishes ground truth for a decision (for example a shadow run whose chosen action is later
verified). A confidence outside `0..=1` is refused and changes nothing.

## Metrics

| Metric | Meaning |
| --- | --- |
| `crawlx_model_calibration_ece{provider,model}` | ECE of the graded window. Exported only once the window holds 200 outcomes; fewer outcomes are not a reading. |
| `crawlx_model_calibration_samples{provider,model}` | Graded outcomes in the window (at most 1000). |
| `crawlx_model_abstention_rate{provider,model}` | Share of the last 1000 decisions on which the gate abstained. |

## Alert: `CrawlxModelCalibrationDrift`

Severity `ticket`. It fires when the window's ECE stays above 0.05 for 15 minutes with at least 200
graded outcomes. The rule and its promtool cases are in `deploy/alerts/crawlx-rules.yaml` and
`deploy/alerts/crawlx-rules.test.yaml` (`promtool test rules deploy/alerts/crawlx-rules.test.yaml`);
the cases cover a drifting model, a healthy one, a young window with a high ECE and a model that
recovers.

There is no alert on the abstention rate, because the right baseline depends on the model and the
crawl. Watch `crawlx_model_abstention_rate` next to the ECE: a rate that climbs while ECE stays low
usually means the gate thresholds no longer fit the model, and a rate that falls while ECE climbs
means the model is overconfident.

### Response

1. Open the alert's `provider` and `model` series. Check `crawlx_model_calibration_samples`: a
   window that only just reached 200 outcomes is noisy, so wait for it to fill before acting.
2. Compare the model's calibration version in `model_decisions` (`calibration_version`) with the one
   it was released with. A recent change points at the update; no change points at the data.
3. Re-run the calibration (`crawlx-model` temperature fit) on fresh held-out logits. If the new fit
   passes the release gate (ECE at most 0.05), ship it: the new version starts a clean window and
   the alert resolves once the 15 minute `for` has passed without a mature window above the ceiling.
4. If no fit passes, set `dynamic.system1Mode` to `shadow` (or `off`) for the affected model. The
   deterministic ranking carries the crawl meanwhile. Do not raise the ECE threshold.

## Limits

The monitor is only as good as its outcomes. Real readings need real graded outcomes from shadow
runs; until a deployment records them, the ECE gauge stays absent and the alert cannot fire. The
synthetic cases in the unit tests and in the promtool file show that the monitor and the rule
behave, not how a particular model performs.
