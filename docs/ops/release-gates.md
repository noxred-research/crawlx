# Release gates

A release candidate ships only when the release-gate checklist passes. The checklist is not
filled in by hand: `release-gate` (`crates/crawlx-bench/src/release_gate.rs`) computes it from
machine-readable evidence files and repository files, prints it as markdown, writes a JSON
report and exits 1 unless every applicable item passes.

```sh
ci/release-gate.sh                       # evidence in bench/out, report next to it
ci/release-gate.sh --model-tier-changed  # the model tier changes in this release
```

which runs

```sh
cargo run -p crawlx-bench --bin release-gate -- check \
  --evidence bench/out \
  --out bench/out/release-checklist.json \
  --markdown bench/out/release-checklist.md
```

| Exit | Meaning |
|---|---|
| 0 | every applicable item is `pass` or `waived` |
| 1 | the release is blocked: at least one item is `fail` or `unmeasured` |
| 2 | usage error, or a malformed waiver |

Options of `check`: `--evidence DIR` (default `bench/out`), `--repo DIR` (default `.`),
`--out FILE` (default `DIR/release-checklist.json`), `--markdown FILE`, `--waivers FILE`
(default `bench/baselines/release-waivers.json` when it exists), `--today YYYY-MM-DD` (default:
today, UTC; the only clock read, and only by the binary) and `--model-tier-changed`.

## States

| State | Meaning |
|---|---|
| `pass` | evidence present and within the threshold |
| `fail` | evidence present and outside the threshold, or present and unreadable |
| `unmeasured` | no evidence, or not enough of it (a soak shorter than 24 h, a flake window shorter than 30 days). Blocks the release exactly like `fail`; no item defaults to a pass |
| `waived` | a `fail` or `unmeasured` performance row covered by a valid waiver |
| `not_applicable` | the model item when the model tier does not change |

## Evidence

Every path is relative to the evidence directory unless it says *repository*. Nothing needs a
caller-supplied pass flag: verdicts are recomputed from counts, exit codes and metrics.

| File | Producer | Read by |
|---|---|---|
| `scorecards/*.json` | one `Scorecard` JSON per gym run (`Scorecard::to_json`, the scorecard of `crawlx_bench::scorecard`); runs are matched to checklist rows by fixture id (`G19` is `g25`, `G21` is `a2`, `G10` is `g19`, `G11` is `g21`, `G25` is `stale-rerender`; see `crawlx_bench::gym::fixtures::CATALOG_ROWS`) and deduplicated by fixture, seed, variant and profile | the safety, correctness and run-to-run items |
| `g1-report.json` | `g1-report` (the `G1Report`: scorecards, run evidence and the captured chaos suites); its scorecards count like `scorecards/*.json` | `worker_kill_reconciled`, `chaos_suite` and the scorecard items |
| `suites/<id>.json` | `release-gate record --id ID [--tool] -- COMMAND...`, see below | one item per suite id |
| `mutants-safety/outcomes.json` | `outcomes.json` of `cargo mutants -p crawlx-safety --output mutants-safety` (the file `ci/mutants-gate.sh` reads) | `mutants_safety` |
| `findings.json` | the security-finding tracker export: `{"open_s1": 0, "open_s2": 0}` | `security_findings` |
| `run-to-run.json` | `{"different_seed_jaccard": 0.91, "previous_release_different_seed_jaccard": 0.90}` | `different_seed_jaccard` |
| `coverage-paired.json` | a `PairedComparison` (`crawlx_bench::stats`) of a higher-is-better `coverage.*` metric, baseline = previous release, candidate = this one | `action_context_coverage` |
| `soak-report.json` | `soak --out DIR` | `soak_invariants` |
| `flake-report.json` | `flake-report report`: `{"window_days": 30, "runs": 12480, "flaky_runs": 3}` (see [`flaky-tests.md`](flaky-tests.md)) | `flake_rate` |
| `restore-drill.json` | `{"completed_on": "YYYY-MM-DD"}` written when a restore drill completes | `restore_drill` |
| `g3-report.json` | the `G3Report` JSON given to `gate g3 --report` | `model_tier` |
| *repository* `chromium-pin.toml` | the pin | `chromium_pin` |
| *repository* `bench/baselines/release-base.json` | the previous release: `{"release": "...", "chromium_pin": {"version": "...", "sha256": "..."}}` | `chromium_pin` |
| *repository* `deploy/alerts/crawlx-rules.yaml`, `docs/ops/runbooks.md` | the shipped alert rules and runbooks | `runbook_catalog`, checked against the telemetry metric catalog (`crawlx_telemetry::metrics::catalog`) |

Items whose evidence has no producer yet (`findings.json`, `run-to-run.json`,
`coverage-paired.json`, `restore-drill.json`, `bench/baselines/release-base.json`, and the
scorecards of fixtures nobody has run) are `unmeasured` until a producer writes the file.

### Recording suite results

`release-gate record` runs a command, forwards its output, and stores the exit status and the
libtest summary in `suites/<id>.json`. It exits 0 whenever the result was recorded; the verdict
is computed later by `check`:

```sh
cargo run -p crawlx-bench --bin release-gate -- record --id secret_canary_zdr \
  -- cargo test -p crawlx-bench --test canary
cargo run -p crawlx-bench --bin release-gate -- record --id cargo_deny --tool \
  -- cargo deny --locked check licenses advisories bans sources
cargo run -p crawlx-bench --bin release-gate -- record --id criterion_gates --tool \
  -- ci/bench-gate.sh
```

A suite passes when the process exited 0, no test failed, no output line starts with `skipped:`
(the tests' marker for a missing PostgreSQL or Chromium) and, for a libtest run, at least one
test ran and none was ignored. `--tool` is for commands that are not libtest runs (`cargo deny`,
`ci/bench-gate.sh`): the exit status alone decides.

| Suite id | Item | For example |
|---|---|---|
| `ssrf_matrix` | SSRF matrix on both planes, rebinding and redirect-chain rows, the browser SSRF lab | the egress and admission suites of `crawlx-policy` plus the browser-plane lab run |
| `scope_escape` | scope-escape suite, every profile | the scope suites of `crawlx-policy` and `crawlx-safety` |
| `secret_canary_zdr` | secret canary and ZDR leak checks | `cargo test -p crawlx-bench --test canary` and the ZDR suites |
| `cargo_deny` | `cargo-deny` clean | `cargo deny --locked check licenses advisories bans sources` (`--tool`) |
| `stale_proposal_executions` | stale-proposal executions = 0 (G25) | the `stale-rerender` browser test of `crawlx-bench` |
| `differential_extraction` | differential extraction and URL-filter suites | `cargo test -p crawlx-bench --test differential --test oracle_differential` |
| `snapshots_unchanged` | CrawlerGym, extraction and API schema snapshots unchanged | the snapshot suites and `ci/schema-snapshot.sh` (`--tool`) |
| `criterion_gates` | every Criterion gate within target; **waivable** | `ci/bench-gate.sh` (`--tool`) |
| `chaos_slo` | DB failover and lease-expiry SLO checks | the lease and failover suites of the weekly chaos job |
| `model_breaker_outage` | model breaker outage test (model item) | the model-outage suites of `crawlx-model` |
| `migrations_tested` | migrations tested up and down on production-shaped data | the migration test run |
| `chromium_upgrade` | Chromium-upgrade suite, read only when the pin changed | the pin-bump procedure's suite |

## Checklist items

Thresholds are the planning defaults; each is a named constant in `release_gate.rs`.

**Safety and security (hard blockers)**

| Item | Rule | Evidence |
|---|---|---|
| `unauthorized_action_rate` | 0 unauthorized actions on G19 and G21 under every safety profile (`read_only`, `test_environment`, `authorized_security_test`); a missing fixture/profile run is `unmeasured` | scorecards |
| `ssrf_matrix` | suite passes | `suites/ssrf_matrix.json` |
| `scope_escape` | suite passes | `suites/scope_escape.json` |
| `secret_canary_zdr` | suite passes (zero leaks) | `suites/secret_canary_zdr.json` |
| `mutants_safety` | at least `MUTANTS_MIN_PERCENT` = 95 % of the viable `crawlx-safety` mutants caught (timeouts count as caught, unviable mutants are excluded) | `mutants-safety/outcomes.json` |
| `cargo_deny` | clean | `suites/cargo_deny.json` |
| `security_findings` | no open S1 or S2 finding | `findings.json` |
| `repeated_non_idempotent` | 0 repeated non-idempotent executions in the scorecards that carry unknown-outcome metrics (the chaos and soak gym runs); none carrying them is `unmeasured` | scorecards |

**Correctness**

| Item | Rule | Evidence |
|---|---|---|
| `worker_kill_reconciled` | the chaos suites of `g1-report.json` passed for this build (`ChaosEvidence::passed`), every unknown outcome ended reconciled, no repeated effect | `g1-report.json`, scorecards |
| `state_false_merges` | on G26: 0 merges hiding a reachable action, false-split rate at most `STATE_FALSE_SPLIT_MAX` = 0.05 | scorecards |
| `identity_stability` | on G02 and G06: collision rate at most `IDENTITY_COLLISION_MAX` = 0.005 (exactly 0.5 % passes), split rate at most `IDENTITY_SPLIT_MAX` = 0.02 | scorecards |
| `interactive_targets` | AX-mechanism recall and precision, pooled over all scorecards, at least `TARGET_RECALL_MIN` = `TARGET_PRECISION_MIN` = 0.95 | scorecards |
| `enablement` | replay success on G11 at least `ENABLEMENT_REPLAY_MIN` = 0.9; false-edge rate on G09 and G10 at most `FALSE_ENABLEMENT_EDGE_MAX` = 0.10 | scorecards |
| `stale_proposal_executions` | suite passes (G25) | `suites/stale_proposal_executions.json` |
| `quiescence_timeout_rate` | every scorecard of a non-adversarial fixture at most `QUIESCENCE_TIMEOUT_MAX` = 0.02; rows `QUIESCENCE_EXEMPT_ROWS` (G07, G08, G21) are excluded | scorecards |
| `trusted_lane_share` | every scorecard with lane counts at least `TRUSTED_LANE_SHARE_MIN` = 0.99 | scorecards |
| `same_seed_jaccard` | every scorecard with a same-seed Jaccard has exactly 1.0 | scorecards |
| `different_seed_jaccard` | not lower than the previous release by more than `DIFFERENT_SEED_JACCARD_MAX_DROP` = 0.03 | `run-to-run.json` |
| `action_context_coverage` | the lower end of the paired bootstrap interval of the candidate-minus-previous difference is not below 0, i.e. the interval excludes a decrease | `coverage-paired.json` |

**Compatibility**

| Item | Rule | Evidence |
|---|---|---|
| `differential_extraction` | suite passes | `suites/differential_extraction.json` |
| `snapshots_unchanged` | suite passes | `suites/snapshots_unchanged.json` |

**Performance and reliability**

| Item | Rule | Evidence |
|---|---|---|
| `criterion_gates` | `ci/bench-gate.sh` exited 0 (its median-regression and absolute p95 gates are not recomputed); waivable | `suites/criterion_gates.json` |
| `soak_invariants` | a soak of at least `SOAK_MIN_SECONDS` = 24 h on PostgreSQL with scheduled faults, verdict not `fail`, no failed cycle, no stuck `intended` row, no unreconciled `unknown` action, at least one journaled action; a shorter, memory-backed or fault-free soak is `unmeasured` | `soak-report.json` |
| `chaos_suite` | completed worker and CLI chaos suite artifacts of the current build | `g1-report.json` |
| `chaos_slo` | suite passes | `suites/chaos_slo.json` |
| `flake_rate` | window of at least `FLAKE_WINDOW_DAYS` = 30 days, rate strictly below `FLAKE_RATE_LIMIT_PERCENT` = 1 %; absent report is `unmeasured` | `flake-report.json` |

**Model (only when the model tier changes, `--model-tier-changed`)**

| Item | Rule | Evidence |
|---|---|---|
| `model_tier` | the calibration gate (`evaluate_g3`: samples, ECE at most 0.05, seeds, coverage gain, zero unauthorized actions, warm p95, consecutive nightly improvements) passes and the breaker outage suite passes | `g3-report.json`, `suites/model_breaker_outage.json` |

**Operations**

| Item | Rule | Evidence |
|---|---|---|
| `chromium_pin` | `chromium-pin.toml` (version and sha256) equals the previous release's, or `suites/chromium_upgrade.json` passed | repository pin, `release-base.json` |
| `migrations_tested` | suite passes | `suites/migrations_tested.json` |
| `restore_drill` | completed at most `RESTORE_DRILL_MAX_AGE_DAYS` = 90 days before the evaluation date and not in the future | `restore-drill.json` |
| `runbook_catalog` | every `crawlx_*` metric in an alert expression exists in the telemetry catalog (histogram series included), every `runbook` annotation points at an existing anchor of `docs/ops/runbooks.md`, and every alert has its alert card heading | repository files, catalog |

## CI evidence transfer

The `release-checklist` job of `ci.yml` runs on manual dispatch and the weekly schedule.
Dispatch evaluations block on failed or unmeasured items; weekly evaluations publish the same
results without treating a report as release approval. `v*` release tags run the separate
`release-checklist.yml` workflow, which blocks the same way. It has no producer jobs and no
caches (a tag trigger makes cached steps a cache-poisoning surface), so it never finds
same-run evidence and every producer-supplied item stays unmeasured until supplied.

The job waits for its producers and downloads this run's `release-evidence-*` artifacts.
`ci/release-evidence.py` copies the available G1 report to `bench/out/g1-report.json`,
mutation outcomes to `bench/out/mutants-safety/outcomes.json`, and unit/browser flake histories
to separate `bench/out/flake-history-*.json` files. It records producer results, source hashes
and missing-input reasons in `bench/out/release-evidence.json` and `.md`, uploaded beside the
checklist.

Missing evidence stays blocking:

- G1 signing runs only on scheduled/default-branch dispatch events. Signing credentials are
  not exposed to release-tag jobs, so a tag without an approved G1 artifact remains unmeasured.
- Direct test-job success is not a recorded suite result with test counts and skip detection.
  The full fixture/profile/seed matrix and recorded safety, correctness and migration suites
  must still be supplied.
- Raw mutation outcomes are usable evidence; raw unit/browser flake histories are not a merged,
  complete 30-day execution window. No passing flake report is synthesized.
- Shared-runner samples cannot replace reference-runner performance measurements. No connected
  producer supplies previous-release paired comparisons, the staging soak, a completed restore
  drill, severity-classified security findings or release model calibration.
- The previous-release pin baseline must come from an actual release, not a copy of the current
  pin. A candidate-browser canary report does not establish the complete Chromium upgrade suite.
- Same-seed G1 traces do not depend on how many proposals go stale. A proposal dropped before it
  runs (`stale_epoch`, identity change, not actionable) is not journaled, so it no longer
  advances the seeded decision stream the arbiter's tie-break draws from; two runs that journal
  the same actions draw identically. The `d1` fixture's ticker and status line advance once per
  recorded interaction instead of on wall-clock timers; `/d1/?live=1` keeps the 250 ms / 1 s
  timers for volatile-region tests. `g1-report` prints the stale-dropped proposal count after
  each run.

The generated transfer report lists the exact missing producer for every expected evidence
path. It creates no suite results, passing metrics or waivers.

## Waivers

A waiver turns a `fail` or `unmeasured` row into `waived`. Only performance rows are waivable;
today that is `criterion_gates` (a recorded waiver is the escape hatch of the Criterion rows).
`bench/baselines/release-waivers.json` (or `--waivers FILE`):

```json
{
  "waivers": [
    {
      "item": "criterion_gates",
      "owner": "perf-team",
      "reason": "shared-runner noise on the lease benches; re-measured on the reference runner",
      "expires": "2026-12-15"
    }
  ]
}
```

- `owner`, `reason` and `expires` (`YYYY-MM-DD`) are all required; an unknown field is refused.
- A waiver applies through its `expires` date inclusive and not after: an expired waiver changes
  nothing and is listed under "Waiver notes" in the report.
- A waiver for an item that does not exist or is not waivable, or one with an empty owner or
  reason or a bad date, aborts the run with exit code 2 instead of being ignored.
- A waiver on a passing item changes nothing and is listed as unused.

## Network-fault harness

The in-process TCP fault proxy of `crawlx_bench::netfault` is a standard tool for load and
chaos runs, with a schedule that turns faults on and off at fixed offsets.

Schedule text: comma-separated `fault[=ARG]@START[..END]`:

```text
latency=50ms@0s..10s,blackhole@12s..15s,reset@20s,refuse@25s..27s
```

| Fault | Effect |
|---|---|
| `latency=D@A..B` | every forwarded chunk waits `D`, both directions |
| `blackhole@A..B` | bytes are swallowed; when the window ends the stranded connections are reset, so a client waits out the window and not its own timeout |
| `refuse@A..B` | new connections are reset at once |
| `reset@T` | every live connection is reset at `T` |

Spans are `<n>ms`, `<n>s`, `<n>m`, `<n>h` or a concatenation (`1m30s`). Windows of one kind must
not overlap; different kinds may. A schedule can also be generated from a seed
(`FaultSchedule::generate(seed, horizon, count)`): one fault per equal slot of the horizon, never
overlapping, a pure function of the arguments. `Proxy::run_schedule` drives a schedule and sleeps
only; it reads no clock.

**`netfault`** forwards TCP and prints the applied faults and the proxy counters as JSON on exit:

```sh
cargo run -p crawlx-bench --bin netfault -- --listen 127.0.0.1:15432 --upstream db.internal:5432 \
  --schedule 'latency=50ms@0s..10s,blackhole@12s..15s,reset@20s,refuse@25s..27s'
cargo run -p crawlx-bench --bin netfault -- --listen 127.0.0.1:15432 --upstream db.internal:5432 \
  --seed 42 --duration 60s --faults 6 --exit-after-schedule
```

It runs until SIGINT or SIGTERM, or with `--exit-after-schedule` until the schedule ends.
`--schedule` and `--seed` are exclusive.

**`load --fault`** starts the proxy in front of `--base` (an `http://` URL), runs the load through
it while the schedule runs from the first request (the run pool is created before, without
faults), and adds a `fault` section to the JSON report: the schedule, the faults applied, the
proxy counters, and every route's statistics split into requests that overlapped a fault window
(plus a 1 s tail for requests that were in flight when it ended) and requests that did not:

```sh
cargo run -p crawlx-bench --release --bin load -- --base http://127.0.0.1:8080 --key "$KEY" \
  --rps 100 --duration 60s --fault 'latency=25ms@0s..20s,blackhole@30s..35s' --allow-errors-during-fault
cargo run -p crawlx-bench --release --bin load -- ... --fault random:6 --fault-seed 42
```

Exit rules:

| Schedule | p99 gate (`--max-p99-ms`) | errors |
|---|---|---|
| none | every route | none allowed |
| latency only | every route, in-fault requests included | none allowed, with or without the flag |
| with `blackhole`, `refuse` or `reset` | requests outside every fault window | none allowed by default; with `--allow-errors-during-fault`, allowed for requests that overlapped a blackhole, refuse or reset window (plus tail) and none outside them |

A latency window that pushes the in-window p99 above the gate therefore fails a latency-only
run: pick a latency the gate can absorb.

## Runtime resource proof

An opt-in ten-minute workload exercises real PostgreSQL, Chromium, the session actor, the CPU
pool, the HTTP API at 200 requests per second and a stalled remote model behind a bounded
guard. It fails on any slow actor poll, any API error, or a mean resident memory in the last
30 seconds more than 2 MiB above the first 30 seconds. Before the baseline it saturates the
database pool and then asserts that the pool size stays fixed through the window, so pool
growth cannot read as a leak. Run it alone on an idle host, in a fresh process:

```sh
RUSTFLAGS='--cfg tokio_unstable' CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER='env RUST_MIN_STACK=1048576' \
  cargo test --release -p crawlx-bench --features runtime-diagnostics --test runtime_proof \
  resource_stalled_model_backpressure_rss_ten_minutes -- --ignored --exact --nocapture --test-threads=1
```

The log prints the evidence line (worst worker mean poll, slow actor polls, mailbox peak,
completed operations), the per-route latency table and the resident-memory series as
30-second means. A recorded run on the current tree: 600 s, 1,750,909 operations, worst worker
mean poll 54 µs, no slow actor polls, no API errors, resident memory 57.3–58.6 MiB with the last
30-second mean below the first.
