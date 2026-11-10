<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img alt="crawlx" src="assets/logo-light.svg" width="260">
  </picture>
</p>

# crawlx documentation

crawlx is a next-generation AI/LLM-native crawler for **authorized security research**: it maps the attack
surface of dynamic web applications with a URL plane and a browser-interaction plane (accessibility-tree
discovery, semantic element identity, a probabilistic enablement graph, reversible state clustering), under a
hard safety kernel. Optional typed-decision, ONNX-ranker and LLM guidance advises and never authorizes.

crawlx is built and intended for testing systems you own or have written authorization to test. It is not for
unauthorized scraping, credential attacks, evading a site's protections or any other abuse. See
[Responsible use](../README.md#responsible-use) and the [safety model](design/safety-model.md).

crawlx is pre-1.0. Production qualification is in progress; see the
[README](../README.md#release-status) and the [changelog](../CHANGELOG.md) for known limitations.

## Design

| Page | Covers |
|---|---|
| [Architecture](design/architecture.md) | Workspace crates and their layering, processes, data flow, the Session Actor, scheduling, storage and telemetry |
| [Crawl model](design/crawl-model.md) | URL plane, browser plane, element identity, observation epochs, state clustering, enablement graph, strategies, the intent journal and the gates |
| [Safety model](design/safety-model.md) | Safety profiles, the hard safety kernel, authorization records, egress and SSRF policy, robots, rate limits |
| [Safety risk matrix](design/safety-matrix.md) | Generated table of what each profile allows per action class |
| [Data and secrets](design/data-and-secrets.md) | Retention modes, zero data retention, secret boundaries, encrypted artifact custody, parse-memory budget, Chromium background traffic |

## Integrations and operations

| Page | Covers |
|---|---|
| [Reference](reference.md) | Source discovery, response cache and replay, adaptive extraction, MCP, compatibility flags, JavaScript endpoint mining, wordlists, captcha solving |
| [Walkthrough](walkthrough.md) | An end-to-end local run against the CrawlerGym fixture with PostgreSQL and Chromium, including a sample authorization record |
| [Compatibility clients and integrations](integrations.md) | Pointing client libraries, command-line clients and third-party integrations at the compatibility API, the endpoints served, operator protocol and acquisition-service boundary |
| [Operations](ops/README.md) | Provisioning and validation of optional operator capabilities |
| [Operator runbooks](ops/runbooks.md) | Runbooks RB-01 to RB-12, alert cards, the `crawlx admin` command table, backup, restore and rollback |

## Project

- [README](../README.md): what crawlx is, quick start and configuration pointers
- [Roadmap](roadmap.md): open work
- [CONTRIBUTING](../CONTRIBUTING.md): coding standards, checks and contribution flow
- [SECURITY](../SECURITY.md): private vulnerability reporting, response times and safe harbor
- [CODE_OF_CONDUCT](../CODE_OF_CONDUCT.md)
- [CHANGELOG](../CHANGELOG.md) and [THIRD_PARTY_NOTICES](../THIRD_PARTY_NOTICES.md)
- Deployment files: [`docker/`](../docker/), [`deploy/helm/crawlx/`](../deploy/helm/crawlx/Chart.yaml),
  [`deploy/k8s/`](../deploy/k8s/README.md), [`deploy/systemd/`](../deploy/systemd/)
- Gate mechanism for milestone-gated strategies: [`gates/README.md`](../gates/README.md)

## Fixed vocabulary

These terms are used consistently across the code and the documentation:
`ActionContextKey`, `ElementIdentityV1`, `ObservedDescriptor`, `RuntimeLocator`,
`ObservationEpoch`, `StateSignature`, Session Actor, safety kernel, trust lanes
(`trusted_ui` / `diagnostic`), `QuiescencePolicy`, intent journal, safety profiles
(`read_only` / `test_environment` / `authorized_security_test`), query-parameter classes
(`RESOURCE_ID` / `NAVIGATION` / `FILTER` / `TRACKING` / `SESSION` / `ACTION_BEARING`), value
partitions, and round-robin role runs.

## Crate map

`crawlx-core`, `crawlx-api`, `crawlx-policy`, `crawlx-url`, `crawlx-fetch`, `crawlx-extract`,
`crawlx-browser`, `crawlx-observe`, `crawlx-elements`, `crawlx-state`, `crawlx-graph`,
`crawlx-strategies`, `crawlx-forms`, `crawlx-model`, `crawlx-safety`, `crawlx-storage`,
`crawlx-scheduler`, `crawlx-telemetry`, `crawlx-worker`, `crawlx-bench`, `crawlx-cli`.
Responsibilities are in the [architecture page](design/architecture.md).
