# Milestone gate files

This directory holds authenticated evidence that a milestone gate passed for the **current
build**. A gate file is only ever produced by an operator or CI pipeline holding a trusted
signing key; nothing in this repository ships a passing gate. The files are consumed at run time:

| Attestation | Required companion report | Gate | What it unlocks |
|---|---|---|---|
| `g1.passed` | `g1.report.json` | G1 deterministic traceability | `state_novelty` and `enablement` strategies (opt-in: not in the default `dynamic.strategies`) |
| `g3.passed` | `g3.report.json` | G3 model authority | `dynamic.system1Mode` above `shadow`; Active also needs the verified calibration token |

Defaults run without any gate file or key: `dynamic.strategies` defaults to `interaction_bfs`
and `event_driven`, and `dynamic.system1Mode` to `off`. A request that explicitly lists
`state_novelty` or `enablement` without authenticated G1, or asks for `system1Mode`
`advisory`/`active` without authenticated G3, is rejected at admission (CLI `crawl`, API,
and again by the worker) with `profile_conflict` naming the gate; no run is created.

`crawlx crawl` and `crawlx worker` read `--gates-dir` / `CRAWLX_GATES_DIR` (default
`./gates`). Consumers require a trusted key file configured by `CRAWLX_GATE_KEYS_FILE`.
Missing keys, unknown key ids, unsigned metadata, absent reports, changed report bytes,
metadata tampering and stale build scopes all leave the gate **closed**. Legacy unsigned
`.passed` files are historical evidence, not runtime authority.

Active requests normalize normally, but API/CLI admission and both `RunContext` builders
require G3. Model-service construction also requires the authenticated report's G3 token;
a boolean status override cannot grant Active authority. Normalization alone is not admission.
`WorkerConfig::default` grants no gates. An Active worker request also requires a configured
Active model engine; missing or lower-ceiling engines fail explicitly instead of silently
turning the request Off or Shadow. Dynamic integration fixtures opt into test-only status.

## Operator/CI credentials

Provision a dedicated random secret of at least **32 bytes** through your operator/CI
secret manager. There is no generated, checked-in or local default key. Keep gate keys
separate from `CRAWLX_AUTHZ_OPERATOR_KEYS_FILE` authorization-record keys.

The trusted file contains one `key_id hex-key` pair per line; `#` starts a comment. Hex
encoding needs at least 64 characters. Blank files, duplicate ids and short keys are rejected.
Do not use the illustrative metadata below as a key or a passing attestation.

- Producer: set `CRAWLX_GATE_KEYS_FILE` to the provisioned file and
  `CRAWLX_GATE_KEY_ID` to the selected id, or pass `--keys-file FILE --key-id ID`.
- Consumer: mount the trusted file read-only outside the downloaded artifact and set
  `CRAWLX_GATE_KEYS_FILE` to its path. No signing-id variable is needed for consumption.
- Rotate keys by adding the new id to consumer trust stores, issuing new attestations,
  then removing the retired id. An artifact cannot supply its own trust store.
- HMAC-SHA256 is symmetric: every verifier holding the secret can also sign. Only trusted
  CI/operator and deployment processes may read the file. Use secret-file permissions
  such as owner-read-only; do not expose it to benchmark target sites or upload it.

For GitHub Actions, configure protected secret `CRAWLX_GATE_KEYS` with the full keys-file
contents and protected variable `CRAWLX_GATE_KEY_ID` with the selected id. The signing step
writes the secret under `$RUNNER_TEMP` with `umask 077`, exports `CRAWLX_GATE_KEYS_FILE`,
and invokes `gate`. Missing configuration fails issuance; no job creates a fallback key.
The workflow artifact contains only attestations and evidence, never the key file.

## File format and expiry

Illustrative TOML (ellipses are not valid digest/signature values):

```toml
gate = "G1"
commit = "0123abcd…"
scope_digest = "c90bfebc…"
report_digest = "ff00be43…"
date = "2026-11-04"
key_id = "gate-ci"
signature = "64 lowercase hex characters…"
```

The signature is domain-separated HMAC-SHA256 over length-prefixed `gate`, `commit`,
`scope_digest`, `report_digest`, `date`, `key_id` and the exact companion report bytes.
The consumer also recomputes the report's domain-separated BLAKE3 digest and compares
`scope_digest` with the digest embedded in its build. Signature checks use constant-time
MAC verification. Unknown TOML fields and missing required fields are rejected.

`crates/crawlx-strategies/build.rs` hashes workspace crate Rust, TOML, JSON and SQL inputs
plus executable fixture assets (HTML, JS, CSS, images, WASM, text and ONNX inputs).
It also hashes workspace `Cargo.toml`, `Cargo.lock`, the toolchain file,
`chromium-pin.toml` and layering configuration.
This deliberately includes the evaluator, report producer/schema, validation code and their
workspace dependencies. Changes to those inputs expire every gate. Collection/read errors
fail the build rather than silently omitting inputs. Source paths are workspace-relative.
The recorded commit is authenticated provenance; the content scope determines expiry.

## Producing a gate

Both commands print every criterion, exit `1` when a criterion fails, and issue an
attestation only on a pass. `--check` evaluates without credentials and writes nothing.
Issuance requires the external credential setup above.

```bash
# G1: collect real chaos evidence, then run Chromium D1 and replay every recorded path.
cargo run -p crawlx-bench --bin chaos-report -- --out bench/out/chaos-report.json
cargo run -p crawlx-bench --bin g1-report -- --out bench/out/g1-report.json --chaos-report bench/out/chaos-report.json
cargo run -p crawlx-bench --bin gate -- g1 --report bench/out/g1-report.json

# G3: evaluate real calibration/shadow evidence; no passing G3 artifact is synthesized.
cargo run -p crawlx-bench --bin gate -- g3 --report bench/out/calibration.json
```

`g1-report` requires real Chromium (`CRAWLX_CHROMIUM_PATH`). It crawls each D1 fixture
twice with the same seed and compares complete ordered semantic action identities and digests
of the actual nonsecret parameters sent to the browser. Control-set Jaccard remains a separate
coverage check, not determinism evidence. Secret values and runtime handles are never recorded;
unverifiable parameters refuse the gate.

Every performed path, including paths ending in failed actions, must be replayed in verify
mode. The report carries recorded, attempted and matched counts for each scorecard. Missing
paths refuse the gate. `--replay-paths N` is an explicitly informational cap and never produces
passing gate evidence, even when the cap happens to include every current path.

`chaos-report` launches the fixed worker failpoint and CLI SIGKILL suites. It requires
`CRAWLX_TEST_DATABASE_URL` and Chromium, retains process exit codes and raw test output,
and checks complete, unfiltered, nonempty success summaries without ignored or skipped tests.
The G1 report embeds this current-scope artifact. A caller-provided boolean is not evidence.

The producer copies exactly the evaluated report bytes into `g1.report.json` or
`g3.report.json` beside the selected `--out` file. The commit defaults to `GITHUB_SHA`,
then `git rev-parse HEAD`; the date defaults to today (UTC).

## Pre-promotion controlled experiments

`decision-eval ablation|shadow|safety` is the planned isolated fixture evaluation path, not
production promotion. It starts an owned ephemeral Gym listener and issues a nonserializable,
single-use `FixtureEvaluationPermit` for each normalized Off/Shadow/Advisory request.
No request field, environment switch, queued job or production CLI flag grants this permit.
Active has no evaluation exception, and no G3 status or token is synthesized.

The permit binds the real retained listener, fixture, request digest (including budgets),
tenant, run and freshly admitted authorization body. The real socket stays reserved while
any capability exists, so a stopped server's port cannot be recycled into another service.
Shutdown, task exit and owner drop revoke the permit and cancel its run. Every browser/fetch
resource and redirect is restricted to that exact HTTP loopback origin; another local port,
external destination, custom backend, browser attach or CONNECT tunnel is refused.

Experiments allow only `read_only` or `test_environment`, at most 3,600 seconds and
10,000 interactions/URLs/states per run. Mutable requests, widened targets, credential
references, persistent profiles, upstream proxies and auxiliary external services are refused.
The local model transport uses literal `http://127.0.0.1`, follows no redirects and ignores
environment proxies. Safety, authorization, approvals, sinks and journaling remain unchanged.
G1-gated deterministic strategies still require authentic signed G1; boolean overrides do not suffice.

With real G1 evidence and the existing database/Chromium prerequisites configured:

```bash
cargo run -p crawlx-bench --bin decision-eval -- ablation \
  --endpoint http://127.0.0.1:PORT/v1/decide --fixtures g01,g03 \
  --suite nightly --night 1 --out bench/out/decision/ablation/night1.json
cargo run -p crawlx-bench --bin decision-eval -- shadow \
  --endpoint http://127.0.0.1:PORT/v1/decide --fixtures g01,g03 \
  --seeds 1,2,3,4,5 --shard shadow1 --out bench/out/decision/shadow
```

These commands collect genuine experimental outcomes without requiring G3 first. The worker
records `fixture_evaluation` with `promotion: false`, and captures include `evaluation_origin`.
Off baselines construct no model engine; Shadow remains non-authoritative. Issuing production
G3 still requires the unchanged real measured thresholds and authenticated report workflow.


## Deployment and CI artifacts

Gate files are **not committed**. The `gate-g1` job in `.github/workflows/ci.yml` runs the
real evidence producers on pinned Chromium, signs with the protected CI credential, and
uploads `gates/g1.passed`, `gates/g1.report.json` and the original report/evidence outputs.
Deploy both the `.passed` file and its companion report from the exact build being shipped.
Mount the independently provisioned trusted keys file and set `CRAWLX_GATE_KEYS_FILE`.
Copying only `.passed`, or trusting an artifact-supplied key file, is not sufficient.

G1 keeps its measured thresholds: per-scorecard complete reconciliation and lane
evidence, no repeated non-idempotent actions, completed successful chaos suites, repeat-run
Jaccard `== 1.0`, identical ordered action/value traces, zero diagnostic-lane actions, trusted
share `>= 0.99` and replay match rate `>= 0.95` on every scorecard, every recorded path
attempted, and zero unauthorized actions. G3 requires real calibration/shadow metrics accepted by
`G3Token::verify`: at least 10,000 calibration samples, ECE at most 0.05, at least 5 seeds,
positive coverage-gain confidence bound, no unauthorized action, warm p95 below 100 ms,
and at least 2 consecutive nightly improvements without safety regression.

The authenticated G3 consumer parses the same `G3Report` schema as the producer and
revalidates its real metrics before exposing a model-authority token. In-process harness
status overrides do not create such a token.
