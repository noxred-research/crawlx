# Safety model

CrawlX can click, type and submit in real web applications and can fetch arbitrary URLs. Its safety
model has several independent layers, each of which fails closed. Use CrawlX only against systems
you own or are authorized to test; nothing here verifies legal permission to crawl a target.

| Layer | Where | Decides |
|---|---|---|
| Admission | `crawlx-policy` (`AdmissionPolicy`) | Whether a request may start at all: scope, profile, authorization, limits |
| Egress policy | `crawlx-policy` (`EgressPolicy`), enforced by `crawlx-fetch` | Which network addresses any request may reach |
| Robots and politeness | `crawlx-policy`, `crawlx-fetch`, `crawlx-worker` | Which URLs and how fast |
| Hard safety kernel | `crawlx-safety` | Whether each browser action may run |
| Independent auditor | `crawlx-storage`, `crawlx admin safety-audit` | Whether recorded actions respected the above, checked from outside the worker |

Models and strategies are **advisory**. `crawlx-model` does not depend on `crawlx-safety`, a model
confidence is never a safety confidence, and a model hint can only raise the severity of a kernel
decision.

## Safety profiles

A run has one safety profile. The default is `read_only`.

| Profile | Intent | Needs an authorization record |
|---|---|---|
| `read_only` | Observe and navigate. Reversible local preferences only. Nothing that changes server state. | No |
| `test_environment` | Interact with a controlled test target: own-account writes, test sinks, fixture uploads. | No (but deployment egress exemptions apply to private ranges inside the deployment allowlist) |
| `authorized_security_test` | Broader probing of an authorized target, including cross-principal probes. | Yes |

Every action is classified into one of eleven risk classes: `navigation_reveal`,
`reversible_local_preference`, `persistent_write_own`, `persistent_write_other_principal`,
`external_communication`, `financial_transaction`, `destructive`, `security_change`, `file_upload`,
`out_of_scope` and `unclassified`. The decision for each class under each profile is a fixed table.
It is generated from the code and published as the [risk matrix](safety-matrix.md); do not edit it by
hand.

Request options can only **narrow** the table:

- `destructive` actions that the profile would send to approval are denied unless
  `safety.destructiveActions=approval`.
- `external_communication` is denied unless the destination is a verified test sink.
- `file_upload` is allowed only for upload actions using fixture files.
- An authorization record can restrict further: a class missing from its `permittedRiskClasses` is
  denied and a class in its `approvalRequired` turns `allow` into `approval_required`.

`out_of_scope` is denied under every profile. `financial_transaction` and `security_change` are
denied outside `authorized_security_test`, and need approval inside it.

## The hard safety kernel

`crawlx-safety` depends only on `crawlx-core`, `crawlx-policy` and `crawlx-url`. It is the only code
that can mint an `AdmittedAction`, the sealed type the Session Actor requires in order to perform
anything. A compile-fail test pins that property.

**Classification.** Structural evidence (role, tag, ARIA state, input type, form method and action,
observed request methods, scope of a link target, resource context for cross-principal writes)
decides navigation and preference classes; a name alone never does. Multilingual keyword lexicons
(Latin-script English, German, French, Spanish and Turkish, plus Japanese, Chinese, Korean and
Russian substring matches) can only *raise* risk, never lower it. With no evidence the action is
`unclassified`. When several classes apply, the strictest decision wins.

**Adjudication.** `adjudicate` returns `Allow(AdmittedAction)`, `Deny` or `ApprovalRequired`.
The audit entry is written before `Allow` is returned. Failure of the classifier, a rule hook, the
audit sink or the approval store yields `Deny` (`failclosed.*` rules); there is no allow-by-default
path.

**Live confirmation.** Immediately before performing, the Session Actor calls `confirm` with
facts read from the live page. It re-checks the identity digest, that the current URL is still in
scope, and re-runs classification: a higher risk or a stricter decision rejects the action even
though it was admitted earlier.

**Approvals.** An approval is bound to the action key, risk class and a digest of the action
parameters, is single-use (consumption is atomic) and expires after 24 hours or at the run deadline,
whichever is earlier.

**Test sinks.** `external_communication` (email, SMS, webhook) is allowed only when the destination
exactly equals an approved, verified sink recorded in the run's authorization record.

**Provenance.** Text that came from the page, an accessible name, hidden text, a network body or a
model is wrapped in `Untrusted<T>`, which prints no payload in `Debug`. Audit summaries keep at most
24 characters of such text plus a hash.

**Audit and the journal.** Each verdict is recorded in `safety_decisions`. In the database,
`actions.safety_decision_id` is `NOT NULL` and references that table, so no action exists without a
decision row. The worker additionally counts a hard-deny breach or an action reaching `perform`
without `allow` as an invariant violation (`crawlx_safety_invariant_violations_total`), which
alerts at SEV-1 in the [runbooks](../ops/runbooks.md).

## Authorization records

An authorization record is an immutable, versioned JSON document written by the operator that
states what a run may touch. It is *evidence of the operator's stated authorization*; CrawlX does
not check that the operator has the legal right to test the target.

Contents: the tenant, a named authorizer who attests ownership or control, explicit origins or URL
prefixes (no wildcards, host-exact, no implied subdomains), excluded paths, authorized private
networks, a validity window of at most 90 days, the most privileged profile the record permits
(`profileCap`), permitted and approval-required risk classes, test accounts (credential references
only), test sinks, optional politeness ceilings, an evidence reference and an emergency contact.

A record is required for:

- `profile = authorized_security_test`;
- `allowPrivateNetworks` (which also needs non-empty `authorizedNetworks`, and an operator-signature
  ownership proof for them);
- `respectRobotsTxt = false` (which also needs `robotsOverrideAcknowledged`);
- role credentials (a matching test account) and test sinks under `authorized_security_test`.

Lifecycle, over the API (`/v1/authorizations`, scopes `authorizations:read` and
`authorizations:write`) or `crawlx authz create|show|revoke|verify`:

- **Create.** Ownership of the target is proven by a DNS TXT record at `_crawlx-authz.<host>`, a file
  at `/.well-known/crawlx-authorization`, or an operator signature (HMAC-SHA256 under keys from
  `CRAWLX_AUTHZ_OPERATOR_KEYS_FILE`; `crawlx authz sign` and `challenge` work offline). The API
  refuses to start a run under a record without `verifiedAt`.
- **Amend.** A new version or a new record; existing ones are never mutated. Status is
  `active`, `not_yet_valid`, `expired` or `revoked`.
- **Bind.** Admission stores the record id, version and body digest on the run.
- **Re-check while running.** A guard re-reads the record at least every 60 seconds. Revocation,
  expiry or loss stops the run with the terminal reason `authorization_revoked`; a failed read is
  retried, not treated as revocation.
- **Every request.** The record's scope is part of the egress policy, so it bounds each fetch hop,
  not just the seed. The browser proxy applies it at host level (it cannot see paths inside
  `CONNECT`); browser-discovered URLs are bounded by the scope policy with the record scope.

## Admission

`AdmissionPolicy::admit` runs for every request, in the API and the CLI, before anything is created:

- normalizes the request and forces zero-data-retention for tenants that enforce it;
- checks the milestone gates (see [crawl model](crawl-model.md#gates));
- clamps limits to tenant ceilings and reports every clamp (URLs, interactions, states, duration,
  discovery depth, tabs, per-origin in-flight, minimum delay);
- validates the authorization record: tenant match, validity window, profile at most `profileCap`,
  record covers the seed;
- builds the egress policy and checks the seed, each role `replicaBaseUrl` and the webhook URL
  (the webhook with a strict policy that no exemption can relax) against it;
- checks robots-override and test-sink preconditions.

Refusals are typed (`authorization_required`, `profile_conflict`, `mode_conflict`, `url_denied`) and
no run is created.

## Egress and SSRF

`EgressPolicy` is a deny-first table applied by both planes. Rules (`DenyRule`): unspecified,
loopback, private, link-local, CGNAT, unique-local, multicast, reserved, broadcast, documentation,
cloud metadata, IPv6 transition, hostname, scheme, port, userinfo, configured, authorization scope and
blocklist.

- **Addresses.** IANA special-purpose ranges for IPv4 and IPv6, including the cloud metadata
  endpoints (`169.254.169.254`, `100.100.100.200`, `192.0.0.192`, `fd00:ec2::254`). IPv4 embedded
  in mapped, compatible, NAT64, 6to4 and Teredo addresses is extracted and judged by its own rule.
  Legacy literal forms (decimal, octal, hex) are normalized first.
- **Exemptions.** Only `private`, `cgnat`, `unique_local` and `loopback` can be exempted, and only
  by an authorization record or the deployment allowlist. Metadata, link-local, multicast, reserved
  and transition ranges are never exemptable.
- **Hostnames and ports.** `metadata.google.internal`, `metadata.goog` and `instance-data` are
  denied; `.localhost`, `.internal` and `.local` are denied unless private ranges are exempt. Only
  http and https; credentials in URLs are refused; ports are limited to 80, 443 and the seed's port.
- **Resolve, check, pin.** The fetcher resolves the name, checks the name and *all* addresses, and
  connects only to a pinned checked address. Redirects are manual (at most 10), and each hop is
  re-resolved and re-checked; credentials are stripped on a cross-origin hop.
- **Deployment lists.** `egress.deployment_allowlist` bounds which private networks any record may
  open (unset means unbounded; set but empty means none). `egress.operator_blocklist` refuses hosts
  (with subdomains), addresses and CIDRs. Either can come from a file
  (`CRAWLX_EGRESS_DEPLOYMENT_ALLOWLIST_FILE`, `CRAWLX_EGRESS_OPERATOR_BLOCKLIST_FILE`), re-read on
  `SIGHUP` and every 60 seconds; a malformed file keeps the previous snapshot rather than emptying
  the list.
- **Browser plane.** Chromium is launched with `--proxy-server` pointing at a loopback proxy in
  `crawlx-fetch`, `--host-resolver-rules="MAP * ~NOTFOUND , EXCLUDE 127.0.0.1"` so every name is
  resolved inside the proxy, and a WebRTC policy that blocks non-proxied UDP. The proxy resolves,
  checks and pins each target, tunnels `CONNECT` only to checked addresses, and answers denials with
  `403` and an `x-crawlx-egress-denied` header. Launch profiles may not override these flags.
  Denials are counted by plane and reason. An operator upstream proxy (`http`, `https`, `socks5`,
  `socks5h`) can be chained; the upstream proxy host is itself egress-checked. A ProxyX pool gateway
  is such an upstream (`CONNECT` only): the gateway host and the control API host of its block
  feedback are checked and pinned like any proxy, the gateway's own destination denylist is a second
  layer rather than a substitute, and the org key travels only in `Proxy-Authorization` and the
  control API's Basic password.
- **Defense in depth.** Run workers with a deny-by-default network policy (see `deploy/k8s`);
  the in-process checks are not a substitute for network-level controls. WebSocket upgrades travel
  through the same vetted tunnel.

## Robots

`robots.txt` is implemented per RFC 9309: product-token group with `*` fallback, longest match wins,
`Allow` wins ties, `*` and `$` wildcards, 500 KiB size cap. One cache is shared by both planes:
24-hour TTL (from `Cache-Control` within 60 s to 24 h), 4xx and over-long redirect chains mean allow,
5xx or unreachable means disallow (`robots_unavailable`); the cache applies exponential backoff and
a 24-hour give-up, but the worker never refetches within a run, so such an origin stays blocked for
the rest of the run. The default product token is `crawlx`.

The browser plane checks robots for its own navigations and for page-initiated **main-frame**
document requests (paused through the CDP `Fetch` domain, with a 30-second guard timeout). It does
not check subresources or embedded frames.

Overriding robots requires an authorization record with `robotsOverrideAcknowledged`.
`Crawl-delay` (capped at 10 seconds) raises the origin's minimum spacing for a run that obeys robots,
once the robots.txt answer is recorded and on every allowed URL; see
[rate limits](#rate-limits-and-politeness). A run that overrides robots does not apply it itself.

## Rate limits and politeness

One `OriginGovernor` is shared by both planes, so browser sessions and the fetcher on the same origin
share a budget.

- **Defaults.** One request in flight per origin, at least 250 ms between starts (floor 50 ms),
  global concurrency 10, a process-wide per-origin cap, optional global and per-host requests per
  second or minute.
- **Robots `Crawl-delay`.** For an obeying run the origin's spacing never drops below
  `max(politeness.delayMs, Crawl-delay)`. Only an explicit `Crawl-delay` value (including `0`)
  changes the floor, setting it to `max(politeness.delayMs, hint)`; an adapted spacing then decays
  toward it. A robots.txt answer or refetch without the directive (any `4xx`, including `429` and
  `403`, is allow-all with no hint) keeps the floor learned earlier in the run. A hint learned while
  a start is already admitted (spacing already read) applies from the next start, not that one. Only
  the first robots.txt request of an origin is paced by the base delay; refetches are paced by the
  floor.
  Back-off, success decay and latency feedback all respect that floor. Discovery fetches that bypass
  the gate (sitemaps, known files) are paced only on the origin whose robots.txt was recorded; a
  sitemap host on another origin gets its own floor only once its robots.txt has been read. The floor
  is not shared across workers: the process-wide cap and deployment admission (keyed by origin only)
  hold back only the start that directly follows a floored start, including one from a run that
  overrides robots, while a worker that has not learned the delay can space its own consecutive
  starts at its own `delayMs`.
- **Adaptive back-off.** `429` and `503` double the origin's spacing with ±20 % seeded jitter up to
  60 s (never below the `Crawl-delay` floor); `Retry-After` is a floor and is never shortened; after
  ten consecutive successes the spacing halves down to the floor. The cool-down is shared across
  workers.
- **Retries.** Three retries on `429` and `503` with exponential back-off from 500 ms (cap 30 s); a
  `Retry-After` longer than 60 s is not waited out.
- **Ceilings.** Tenant ceilings raise the minimum delay and lower the in-flight limit; an
  authorization record can only tighten politeness further.
- **Violations.** `crawlx.fetch.politeness_violations` counts permits issued sooner than the
  origin's spacing floor or above the in-flight cap. It should stay at zero.
- **API limits.** A per-tenant token bucket (default 6000 requests per minute; `0` disables it)
  with `RateLimit-*` headers; at most 50 SSE streams per tenant and 5 per run.

## Independent safety auditor

`crawlx admin safety-audit` re-checks recorded actions from outside the worker. It connects with two
database logins that have no other privilege (`crawlx_safety_reader`, which can read a cross-tenant
view of action, run and tenant identifiers and violation reasons; `crawlx_safety_pauser`, which can
only pause a violating run and append to the audit chain). The client refuses superuser, `BYPASSRLS`,
role-creation, write or DDL privileges and refuses a connection that holds both roles. It reads in a
`REPEATABLE READ, READ ONLY` snapshot and flags, among others: an intent without a decision, a
decision that does not match the action, a denied or hard-deny action that was intended, an invalid
or insufficient authorization at intent time, a missing verified sink, and a missing approval.
Violating runs are paused automatically. A one-minute CronJob is in `deploy/k8s/safety-auditor.yaml`.
Setup is in the [runbooks](../ops/runbooks.md#independent-safety-auditor).

## Captcha solving

Opt-in only (`crawl.captcha`, a provider and a key reference), and only with the browser plane
enabled. Callback delivery is classified as an `unclassified` action, so the default `read_only`
profile refuses it; use `test_environment` for controlled targets you are authorized to test.
Configuring a solver never bypasses action admission. See the README for the flags.

## API authentication and isolation

API keys (`cx_live_` plus 26 base32 characters) are stored as BLAKE3 hashes and carry scopes such as
`crawls:read`, `crawls:write`, `approvals:decide`, `artifacts:read_sensitive`, `authorizations:*`.
Prefixed `fc-` keys are accepted only on `/compat/*` routes and only when enabled. Tenant
isolation is enforced by PostgreSQL row-level security and a restricted API database role; see
[data and secrets](data-and-secrets.md#tenant-isolation).

## Current limitations

- Approvals: the kernel enforces the approval protocol, but its approval store is in-process. The
  API has an approval-decision route, but a decision made through it does not yet reach the kernel's
  store, so treat `approval_required` as `deny` in practice.
- The kernel does not run without an audit sink attached; the in-process worker attaches an
  in-memory log, and the durable record is the `safety_decisions` row.
- Robots is not consulted for browser subresources and frames.
- `Crawl-delay`: the URL plane processes a leased batch sequentially, so a row on an origin with a
  `Crawl-delay` floor waits for it in process (up to the 10 s cap) and the rows behind it in the
  batch wait too. A `429` behaves differently: it publishes a cooldown, and later rows of that
  origin are deferred instead of waited on. The acquisition budget (default 60 s
  `max_elapsed_ms`) includes these pacing waits: a continuation makes at most `max_attempts`
  requests, and on a 10 s floor at most about six within the 60 s deadline. A durable fix
  (per-origin deferral without frontier churn) is open on
  [#35](https://github.com/noxred-research/crawlx/issues/35).
