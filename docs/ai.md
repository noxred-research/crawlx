# AI-native features

CrawlX can use language models around a crawl, always as an advisor. The rules below hold for every
feature on this page:

- **Models advise and never authorize.** A model can propose a configuration, a plan, a claim or a
  paragraph. Operator capabilities, verified target scope, authorization records, retention policy,
  rate limits and the hard safety kernel stay deterministic and decide what happens.
- **Page content is untrusted.** Retained pages, traffic, schemas, tool descriptions, earlier model
  answers and validation diagnostics are data. They reach a model only inside a fenced, typed envelope
  and never in the instruction channel.
- **Off by default.** No model call is made until the operator enables external processing and
  approves a provider for a purpose. Features that have a deterministic core keep working without a model.
- **Passive.** None of these endpoints fetches a page, enqueues a request or acts on a target. Evidence
  comes from what a run already retained.
- **Auditable.** Every model call writes a digest-only audit row (`model.processed`): provider, model
  revision, purpose, policy, input and output digests and token usage, never content.

The operations are also available as tools of the native [MCP surface](mcp.md).

## Model-processing policy

Everything model-assisted goes through one governor. The operator configures it in the `[intel.policy]`
section of `crawlx.toml` (the file named by `CRAWLX_CONFIG`, else `./crawlx.toml`), which `crawlx serve`
reads at start-up; nothing in it can be set by a request, a page or a model. The keys are the API's
camelCase configuration keys, and the section is read from the file only: there is no flag or environment
override for it. Unknown keys fail `serve` and `crawlx config check`.

```toml
[intel.policy]
externalProcessing = true
maxInputBytes = 131072
maxOutputTokens = 2048
maxResponseBytes = 1048576
maxRunCalls = 16
maxRunTokens = 200000
deadlineMs = 60000
proposalTtlSecs = 900
allowSelfApproval = false

[intel.policy.providers.analysis]
endpoint = "https://models.internal.example/v1"
model = "reviewer-1"
apiKeyRef = "env:POLICY_PROVIDER_KEY"   # env:NAME or file:/path, never the key itself
revision = "2026-11"
retentionCapability = "none"
allowedPurposes = ["crawl_spec", "agent_plan", "evidence_extraction", "surface_triage", "run_summary"]
```

A provider that omits `endpoint`, `model` and `apiKeyRef` uses the default model endpoint, which is set by the
environment (`CRAWLX_LLM_BASE_URL`, `CRAWLX_LLM_MODEL`, `CRAWLX_LLM_API_KEY`). Provider keys are only ever
referenced: a key reference that is not `env:` or `file:`, and an endpoint carrying user info, a query or a
fragment, are refused. Without an `[intel.policy]` section, or with `externalProcessing = false`, every
model call of these endpoints answers `403 external_processing_disabled`.

`crawlx config check` validates the section (a provider that cannot be built, a key reference that does not
resolve, a switch that disagrees with the approved providers) and reports it under `intel.policy` with
endpoints stripped of user info and each key reference shown with whether it resolves, never the key.

| Key | Meaning |
|---|---|
| `externalProcessing` | Master switch, `false` by default. While off, every model call of these endpoints is refused with `403 external_processing_disabled` before any provider I/O. |
| `providers.<id>` | An approved provider (`a-z0-9_-`, at most 32 characters). `endpoint`, `model`, `apiKeyRef` and `timeoutMs` default to the `intel.llm` endpoint; a credential is inherited only together with the endpoint it belongs to. |
| `revision` | Operator label of the model revision. It is part of every cache key and audit digest. |
| `retentionCapability` | `none` (default) or `zdr`. Content of a zero-data-retention run reaches only providers marked `zdr`; any other provider receives zero requests. |
| `allowedPurposes` | Purposes the provider may serve: `crawl_spec`, `agent_plan`, `evidence_extraction`, `surface_triage`, `run_summary`. Empty approves none. |
| Budgets | Rendered input ceiling (never silently cut), provider-enforced completion tokens, decoded response bytes, calls and tokens per run, and a per-call deadline. Calls that belong to no run yet (spec compiling, plan proposals) are budgeted per API key and hour. Budgets are held in memory and restart with the process. |
| `proposalTtlSecs` | How long a compiled spec, agent plan or approval stays valid (default 900, at most 86400). |
| `allowSelfApproval` | Whether the key that created a spec or plan may also approve it (default `false`). |

How a call is prepared and checked:

1. **Envelope.** A static instruction compiled into the binary, the caller's task text (a request, never a
   permission) and typed source records, each with a provenance tag, a stable id and a digest. Delimiters
   inside sources are neutralized. Fencing is defense in depth; it is not what authorizes anything.
2. **Projection.** Registered secrets, credential shapes and secret-named values are masked in every
   prompt and in every reply. The digests describe exactly what was sent.
3. **Bounds.** Caller JSON Schemas are limited to 32 KiB, twelve levels and 512 nodes, and may contain only
   local `#` references; no document is ever fetched. Oversize input, an exhausted run budget, a missing
   token count, a truncated reply and a deadline all fail explicitly.
4. **Reply.** The parsed reply is marked `generated_unverified`. Each feature validates it
   deterministically before any part is used.
5. **Cache.** Replies are cached in memory, keyed by tenant, provider, model revision, prompt and schema
   version, policy digest and source digests. Another tenant, another model revision or another source
   never hits another entry, and zero-data-retention calls are never cached.

`GET /v1/capabilities/ai` shows the policy in force: the switch, provider ids with model, revision,
retention capability and purposes, budgets and the model-assisted and deterministic operations. It never
shows endpoints, keys or prompts.

Refusals use stable codes: `external_processing_disabled`, `purpose_not_allowed`, `zdr_incompatible`
(all `403`), `ai_not_configured` (`503`), `input_too_large` (`413`), `ai_budget_exhausted` (`429`),
`ai_timeout` (`504`) and `ai_invalid_output` (`502`).

Scope of the policy: it governs the native endpoints below, including the model calls of an approved
agent plan (see below). The compatibility `json` format and `/compat/v2/extract` keep their page-level
source attribution; field-level evidence is the native extraction endpoint. Other compatibility products
(`/compat/v2/agent` started directly, scrape formats) keep their own controls (fenced inputs, bounded
content strategy with explicit consent, zero-data-retention handling).

Run budgets and the reply cache are held in this process's memory: they restart with the process and are
not shared between API replicas, so a deployment with several replicas allows up to that many times the
configured per-run budget. The run-budget ledger is bounded per tenant (1024 scopes, oldest evicted), so one
tenant cannot push another tenant's budgets out.

## Natural-language specifications

`POST /v1/crawl-specs/validate` dry-runs the native create validation and admission for a body shaped
like `POST /v1/crawls`. Nothing is created and no target is contacted. Supply `seed` for a reproducible digest.

`POST /v1/crawl-specs/compile` turns an engagement description into a native configuration:

```json
{
  "baseConfig": { "seedUrl": "https://app.example.test/", "limits": { "urls": 500 } },
  "prompt": "Crawl only the app lightly, skip logout, never submit forms.",
  "authorizationId": "…"
}
```

Give exactly one of `prompt` (a model compiles it) and `intent` (an operator-typed `CrawlIntentV1`, no
model needed). The model returns a bounded intent: goals, prohibitions, methods, path prefixes, depth,
page and duration budgets, a minimum delay and a list of things it could not express. A deterministic
compiler applies it to `baseConfig`:

- An intent can only **narrow**. Budgets take the smaller value, exclusions add, inclusions fill an empty
  list, and a request to widen is refused with a `widening_refused` warning.
- Prohibitions are enforced or the compile fails: `form_submission` forces the read-only profile,
  `destructive_actions` and `external_communication` force deny, `external_links` and `subdomains` turn
  those scopes off. A goal that contradicts a prohibition fails with `conflicting_intent`; the compiler
  never guesses.
- Path prefixes are compiled to anchored patterns by the server. A model never supplies a regular
  expression.
- What the compiler cannot represent (state-changing methods, form submission, free-text wishes) is
  listed under `unsupportedIntents`; nothing is silently dropped.
- The intent has no field for credentials, authorization, safety-profile ceilings, egress, robots
  policy, provider endpoints or the target. A reply with any other field is rejected (`ai_invalid_output`).

The compiled configuration goes through the same admission code as `POST /v1/crawls` (including the
extraction-option validation), so an invalid configuration is a `400` or `422` with the usual details.
The configuration shown, diffed and digested is a **redacted view**: fetch headers and cookies, the form
password, scrape header maps and secret-named or credential-shaped values read `[redacted]`. The real
configuration is kept server-side only, is never returned (also not by `GET /v1/crawl-specs/{id}` or the MCP
tools), and must still match the redacted view at creation. The response carries `config`, `diff` against the base
configuration, `warnings`, `unsupportedIntents`, `requiredCapabilities`, `configDigest`,
`authorizationDigest` and `policyDigest`, and `targetIo: false`.

Starting a crawl needs an operator:

1. `POST /v1/crawl-specs/{specId}/approve` with `approvals:decide` returns a single-use `approvalToken`
   bound to the spec digest. It is shown once. By default the proposing key cannot approve its own spec.
2. `POST /v1/crawl-specs/{specId}/create` with `crawls:write` and `{"approvalToken": "…"}` re-runs
   admission, refuses with `409 spec_stale` when the admission or model policy or the authorization
   record changed since the preview, and then starts the crawl through normal admission. An expired or
   revoked authorization therefore refuses the start. The token is spent by the first successful create.

Specs and approvals expire after `proposalTtlSecs`. Approving and spending are atomic claims: of any number
of concurrent approvals or spends of one token exactly one succeeds (the rest get `409`), and a plan cannot
be both cancelled and executed. Each API key may hold at most 32 live proposals of a kind (`429
proposal_quota`); expired, spent and cancelled ones are evicted oldest first beyond 64 per tenant and kind,
live ones never. A spec whose stored body was altered no longer
matches its digest and its token is refused.

## Plan-first research agent

For the research agent (`/compat/v2/agent`), plan-first mode puts an operator between the model's idea and
its execution.

1. `POST /v1/agent-plans` with `{"prompt" (at most 3000 characters), "urls" (at most 20, 300 characters each), "schema"?, "effort"?, "maxCredits"?}` proposes a plan.
   The operator supplies the URLs; a model (when approved) proposes at most `effort` steps using only
   `map`, `scrape` and `extract` on those hosts and path prefixes. Every step is validated
   deterministically: steps with another tool, host, port or path are dropped and listed in `findings`.
   With no usable model the plan is one `scrape` step per URL and says `planner: "deterministic"`.
   Nothing is fetched.
2. `POST /v1/agent-plans/{planId}/approve` (`approvals:decide`, a different key than the proposer)
   returns a single-use token bound to the plan digest.
3. `POST /v1/agent-plans/{planId}/execute` (`crawls:write`, `{"approvalToken"}`) first requires a provider
   approved for `agent_plan` (and for zero-data-retention content when the tenant forces it); otherwise it
   is refused with `403` before the token is spent. It then starts an agent job, whose model calls go through
   the governor (projection, bounds, budget scope `plan:<id>`, audit rows `model.processed`), with
   `strictConstrainToURLs`, no exchange tools, the plan's effort and credit ceiling, and a binding to the
   plan's tool set. A call outside the plan is refused, and the refusal is recorded as a deviation on the
   job result (`plan.digest`, `plan.deviations`) and on the plan record. Page text can fill data inside
   approved steps but cannot add a tool, a host or a step.

`GET /v1/agent-plans/{planId}` shows the plan, its digest, approval state and deviations;
`POST …/cancel` withdraws an unexecuted plan. The job itself is read at `/compat/v2/agent/{id}`.

## Schema extraction with exact evidence

`POST /v1/crawls/{id}/extractions` extracts fields from retained renditions (by `artifacts` ids or page
`urls`; never fetched) against a JSON Schema (at most 6000 bytes here) or a versioned `preset`:
`endpoint_inventory`, `forms`, `auth_mechanisms`, `api_parameters` or `response_metadata`
(`schemaVersion` in the result names the version used). A model returns claims: a JSON
pointer, a scalar value, a verbatim quote and the id of the chunk the quote came from. CrawlX verifies
each claim itself:

| Status | Meaning |
|---|---|
| `observed` | The quote occurs in the cited chunk (whitespace-insensitive), the byte span was computed by CrawlX, and the value literally occurs in the quote (short scalars must match as whole tokens). |
| `inferred` | The quote is real but the value is only implied by it. Excluded from `data` unless `includeInferred` is set. |
| `conflicting` | Verified claims disagree; no value is chosen, the candidates are listed. |
| `rejected` | The claim failed verification (`ungrounded_quote`, `unknown_source`, `invalid_path`, `non_scalar`, `missing_value`, `missing_quote`). |
| `unknown` | The schema requires the field and nothing supports it. |

`data` holds only observed fields. Spans (`start`, `end`) are byte offsets into the projected text the
model saw; `projected: true` on a source says projection changed it. Sources carry their artifact id and
digest, and `expectedDigests` makes a changed rendition fail with `409 stale_source`. Verified values that
violate the schema get one repair call; a second mismatch is a `422 schema_mismatch`. Large sources are
cut into overlapping chunks; chunks beyond the cap are reported as `status: "partial"`.

## Surface triage

`POST /v1/crawls/{id}/triage` groups retained pages (and the static forms in retained HTML) and observed
traffic into surfaces: one per host, method and route template, with values dropped and parameter names kept.
Rules produce labels (`auth`, `role_boundary`, `upload`, `search_input`, `object_reference`, `admin`,
`export`, `state_change`) only from observable facts, each fact with the evidence ids it came from
(`artifact:<id>`, `traffic:<id>`). A route name alone (`/admin-guide`) produces a **hypothesis**, never a
label. Role-specific responses, `GET` versus `POST` on the same route, refused (`401`/`403`) access and
form encodings are facts. Confidence is `high`, `medium`, `low` or `none`, and a surface the rules cannot
classify abstains.

`{"mode": "advisory"}` additionally asks an approved model for a short explanation and one of a closed set
of manual verification categories per surface. An explanation is kept only when it cites evidence of that
surface and carries no payload-like text; it never changes labels, facts or review status. When the model
is unavailable the deterministic result is returned with `model.status = "unavailable"`. The latest triage
is stored and read with `GET /v1/crawls/{id}/triage`.

## Grounded summaries and reviewed findings

`POST /v1/crawls/{id}/summaries` (`kind`: `run` or `findings`) first builds numbered facts from counters,
coverage, retained pages, the stored triage and reviewed findings, then renders sections and Markdown
from those facts alone. Every claim cites fact or evidence ids. Without a model the report is the
same, deterministic one. With a model (`useModel`, default on when approved), narrative claims are kept
only when every cited id exists, every number appears in a cited fact, the status is allowed and the text
asserts nothing the evidence cannot carry (CVSS scores, exploitability, completeness). Rejected claims are
returned in `rejectedClaims` with the reason. Missing, expired and partially read evidence is stated in
the `limitations` section.

A model can never promote a hypothesis. Only an operator-reviewed finding can be `confirmed`:
`PUT /v1/crawls/{id}/findings/{findingId}` (`approvals:decide`) records a title, a status
(`confirmed`, `dismissed`, `needs_review`), a severity label (`info` to `critical`; no scores) and
retained evidence ids that must resolve in the run; a confirmed finding needs evidence. `GET …/findings`
lists them.

Derived records of zero-data-retention runs (extractions, triage, summaries) are returned but never stored.
The stored records of a run (extractions, triage, findings, summaries) are deleted with the run, by
`DELETE /v1/crawls/{id}` and by the retention sweeper.

## Scopes

| Operation | Scope |
|---|---|
| Validate, compile, read a spec; propose, read a plan; extract, triage, summarize, list results, list findings, AI capabilities | `crawls:read` |
| Create a crawl from an approved spec; execute or cancel a plan | `crawls:write` |
| Approve a spec or plan; review a finding | `approvals:decide` |

## Model qualification and roadmap

Model qualification is unchanged by this page. The typed-decision engines and the ONNX ranker stay behind
the promotion gates described in [model calibration](ops/model-calibration.md) and
[release gates](ops/release-gates.md); the diagnostic ranker may collect shadow data and has no authority.
The following are **documented roadmap, not implemented**:

- **Coverage-aware guided exploration.** Agent proposals over the live driver's candidate handles,
  compiled into the existing constrained action plan and executed one step per actor epoch through the
  arbiter and safety kernel.
- **Cross-page semantic grouping and retrieval.** A run-scoped semantic index over approved text and
  surface records that never merges away method-, role-, parameter- or trust-lane-specific evidence.
- **Browser-session and proxy-exchange interoperability.** Negotiated, tenant- and run-bound handles to
  external browser sessions and captured exchanges, with a single mutating owner per session.
- **Schema induction.** A model proposes selectors once, a deterministic validator checks them on held-out
  pages, and later runs extract with no model call.
- **Session capability ledger and signed scope grants.** Per-engagement flags for untrusted input, sensitive
  context and consequential capability, and operator-signed grants over origin sets and approved plans.
- **Model qualification workbench.** Read-only model status, decision and evaluation tools over
  provenance-complete outcome data, with signed operator promotion outside any agent surface.
