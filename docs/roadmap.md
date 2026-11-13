# Roadmap

What is open in CrawlX 0.1.0. This list is intent, not a commitment or a schedule; items move when
someone picks them up. The [changelog](../CHANGELOG.md) records what has shipped, and
[CONTRIBUTING.md](../CONTRIBUTING.md) explains how to propose a change. Open an issue before starting
anything large.

## Qualify for production use

CrawlX is pre-1.0. Before it is recommended for public services or sensitive authenticated sessions the
integration, soak and operational checks that gate the first stable release need to be closed.

## Distribution

Releases are source archives with a SBOM and checksums. Prebuilt binaries, published container images and
crates.io packages are not part of the initial distribution.

## Safety and policy

- **Durable approvals.** API reviewer decisions bind the original parked action and current
  session fence; kernel reclassification and live confirmation remain mandatory.
- **Browser robots boundary.** Robots applies to main-frame document navigations and redirects,
  not every subresource or embedded frame. Egress authorization and private-address checks
  apply independently to mediated traffic. CONNECT cannot inspect encrypted URL paths.
- **Network isolation deployment.** The worker supports verified namespace launch and fails
  closed without its privileged helper. Host namespace/CNI deployment proof remains external.

## Data and secrets

- **Retention operations.** `crawlx admin sweep-retention --every 5m` runs the built-in scheduled
  sweeper; monitor its failures and overdue artifacts ([operations](ops/README.md#scheduled-retention-sweeper)).
- **Secret authority renewal.** Fenced renewable use windows preserve the original absolute
  retention ceiling; Redis secret TTL never extends.
- **Retained browser profiles.** Structured encrypted cookie/web-storage custody is available
  under explicit operator approval; arbitrary browser directories remain unavailable.
- **Parser internals.** The parsed tree is built fallibly under the parse-memory budget; the HTML
  parser's own token and stack buffers are still bounded by a measured allowance, not by individually
  fallible allocation.

## Browser plane

- **Zero-attempt background isolation.** The pinned Chromium attempts unsolicited background requests that
  the egress policy denies and logs. A patched build exists under `ci/chromium-patches/`; validating it
  and making it the pinned browser would remove the attempts.

## AI-native work

The shipped AI features are described in [AI-native features](ai.md) and the native [MCP surface](mcp.md).
Open items:

- **Coverage-aware guided exploration.** Agent proposals over the live driver's candidate handles, compiled
  into the existing constrained action plan and executed one step per actor epoch through the arbiter and
  safety kernel; progress reported as uncovered, blocked, attempted, verified or unknown outcome.
- **Cross-page semantic grouping and retrieval.** A run-scoped index over approved text and surface records
  whose grouping is reversible advisory metadata and never suppresses distinct methods, roles, parameters
  or trust-lane evidence.
- **Browser-session and proxy-exchange interoperability.** Negotiated, tenant- and run-bound handles to
  external browser sessions and captured exchanges, with one mutating owner per session and a fenced handoff.
- **Schema induction.** A model proposes selectors once, a deterministic validator checks them on held-out
  pages, and later runs extract with no model call.
- **Session capability ledger and signed scope grants.** Per-engagement flags for untrusted input, sensitive
  context and consequential capability, and operator-signed grants over origin sets and approved plans. Today
  approval is a server-side, single-use, digest-bound token and plan execution is confined to the approved
  tools and URLs.
- **Model qualification workbench.** Read-only model status, decision and evaluation views over
  provenance-complete outcome data, evaluated against the unchanged promotion criteria; promotion stays a
  signed operator workflow and is never an agent tool.

## Good places to start

Documentation fixes, tests for a documented behavior, a new fixture for the CrawlerGym server, and
clarifying error messages are always welcome. Look at the open items above for larger work.
