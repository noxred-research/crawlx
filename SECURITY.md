# Security policy

We take the security of crawlx and of the people who run it seriously. This page says which versions are
supported, how to report a vulnerability, what you can expect from us, and what is in and out of scope.

> **Intended use.** crawlx is built and intended for security research and authorized testing only: testing
> systems you own or have written authorization to test. It is not for unauthorized scraping, credential
> attacks, evading a site's protections or any other abuse. See [Responsible use](#responsible-use).

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Earlier than 0.1.0 | No |

crawlx is pre-1.0. Only the latest 0.1.x release receives security fixes. The distribution is the source
repository and tagged source releases; no binaries, container images, hosted service or crates.io packages
are published, so there are no other artifacts to patch.

Production qualification is still in progress. The [README](README.md#release-status), the
[changelog](CHANGELOG.md) and the [roadmap](docs/roadmap.md) list the open items. Do not deploy a checkout
as a public service or use it for sensitive authenticated sessions until those are closed.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion for a suspected vulnerability.** Report it privately
through GitHub private vulnerability reporting for `noxred-research/crawlx`:

1. Open <https://github.com/noxred-research/crawlx/security/advisories/new>, or go to the repository's
   **Security** tab and choose **Report a vulnerability**.
2. Describe the affected component and version or commit, the impact, and steps or a proof of concept that
   reproduce the problem. A minimal reproduction against a local fixture is ideal.
3. Do not include live credentials, real personal data or captured third-party content in the report.

If the private reporting option is not offered on the repository, open a public issue that asks for a
private channel and contains no technical details.

## What to expect

These are commitments for good-faith reports of issues in scope. Times are in business days.

| Step | Target |
| --- | --- |
| Acknowledge receipt | within 3 days |
| Initial assessment: confirmed, needs more information, or not a vulnerability | within 10 days |
| Status updates while the report is open | at least every 14 days |
| Fix or mitigation, and a coordinated disclosure date | within 90 days of the initial assessment; sooner for actively exploited issues |

We will keep you informed, agree on a disclosure date with you, and credit you in the published advisory
unless you ask to remain anonymous. This project does not run a bug bounty. If we cannot meet a target we
will tell you why.

## Safe harbor

We consider security research carried out in good faith under this policy to be authorized, and we will not
pursue or support legal action against you for it. Good faith means that you:

- test only against your own deployment of crawlx or a local fixture, never against someone else's
  systems or data, and never against production data you do not own;
- make a reasonable effort to avoid privacy violations, data destruction and interruption or degradation of
  services;
- access only as much data as needed to demonstrate the issue, and stop and report if you encounter
  personal data or credentials;
- give us a reasonable time to fix the issue before you disclose it, and do not disclose it publicly
  until we have agreed a date or the 90-day target has passed without a response;
- do not use social engineering, physical attacks, denial of service or spam.

This safe harbor covers the crawlx project only. It does not authorize testing of third-party systems
that crawlx may be pointed at, of the services of GitHub or other providers, or of anyone else's
deployment; those have their own terms. If you are unsure whether an activity is covered, ask first,
privately.

## Scope

**In scope:** code in this repository, its build and CI configuration, and the deployment files under
`docker/` and `deploy/`. Findings that bypass a control described below are in scope even when they need a
particular configuration. Examples:

- a path that performs a privileged action without a valid, unrevoked, in-scope authorization record;
- a bypass of the egress (SSRF) policy, the safety kernel, robots enforcement or the politeness limits;
- cross-tenant data access, or leakage of secrets, cookies or sensitive page content into logs, prompts,
  telemetry, artifacts or durable storage;
- a zero-data-retention run that persists page content;
- a way to read sealed artifacts without the key, or to publish content that bypasses custody checks;
- authentication, scope or idempotency flaws in the API and the Firecrawl-compatible facade;
- supply-chain weaknesses in the build, release or workflow configuration.

**Out of scope:**

- vulnerabilities in third-party dependencies that have no crawlx-specific exploit path (report those
  upstream; dependency advisories are checked by `cargo deny`);
- the behavior of crawled sites, and content a crawled site serves to crawlx;
- findings that require an operator to deliberately grant an authorization, a profile or a secret to an
  attacker;
- denial of service by volume against a deployment without the rate limits and resource limits the
  documentation tells operators to configure;
- the background requests that the pinned stock Chromium attempts, which the egress policy denies and logs
  (see [data and secrets](docs/design/data-and-secrets.md#chromium-background-traffic));
- missing hardening that is documented as a known limitation in the [changelog](CHANGELOG.md);
- reports from automated scanners without a demonstrated impact, and social engineering of maintainers;
- reports that depend on running crawlx against a system you do not own and are not authorized to test.
  Research on crawlx itself must use your own deployment or a local fixture (see [Safe harbor](#safe-harbor));
- abuse of crawlx by third parties against systems you operate. We cannot act on deployments we do not run;
  report that activity to the operator or hosting provider concerned, and tell us if you believe a safety
  control in crawlx failed to stop it, which is in scope.

### Authorization records

crawlx refuses requests that need elevated authority unless an authorization record covers them. The safety
profiles `test_environment` and `authorized_security_test`, private-network access
(`--allow-private-networks`) and the robots override all require a record created by the operator. The
record is evidence of the operator's stated authorization; crawlx does not verify legal permission to crawl a
target. A path that performs one of those actions without a valid, unrevoked, in-scope record is a
vulnerability. See the [safety model](docs/design/safety-model.md#authorization-records) for what is
enforced and where.

### Zero data retention and secret boundaries

Zero-data-retention (ZDR) mode and the handling of credentials, cookies, API keys and other secrets are
described in the [data and secrets design](docs/design/data-and-secrets.md). Secrets and sensitive page
content must stay out of prompts, logs, snapshots, artifacts, telemetry and durable storage, and ZDR runs
must not create durable copies of page content. A leak across those boundaries, or a ZDR path that persists
content, is a vulnerability.

### Egress and safety kernel

The egress filter (SSRF protection) and the independent safety kernel (see the
[safety model](docs/design/safety-model.md)) are security controls. Bypassing either is a vulnerability.

## Responsible use

crawlx is built and intended for **security research and authorized testing only**: testing systems you own,
or systems you have written authorization to test. Do not use it for unauthorized scraping, credential
attacks, evading a site's protections or any other abuse. This is the project's intended-use policy and a
condition of support and community participation; the [AGPL-3.0-only](LICENSE) license itself is unchanged.

The project enforces this in code: privileged modes need an
[authorization record](docs/design/safety-model.md#authorization-records), the default `read_only` profile
cannot change server state, a hard safety kernel adjudicates every browser action, and a deny-first egress
policy bounds every request. An authorization record states what you are authorized to do; it does not
verify that you are. Misuse of crawlx against systems you are not authorized to test is not covered by this
policy, is not covered by the safe harbor above, and is your responsibility.

## Verifying a release

A `vX.Y.Z` tag triggers a gated workflow that re-verifies the tagged tree and creates a **draft** release
containing a deterministic source archive `crawlx-X.Y.Z-source.tar.gz`, a CycloneDX SBOM
`crawlx-X.Y.Z-source.cdx.json` and `SHA256SUMS`. A maintainer publishes the draft. No binaries, images or
crates are published by CI. Release tags are protected and published releases are immutable.

```
sha256sum --check SHA256SUMS
gh attestation verify crawlx-X.Y.Z-source.tar.gz --repo noxred-research/crawlx
```

Once the repository is public, each release file carries a build provenance attestation and the archive an
SBOM attestation (`--predicate-type https://cyclonedx.org/bom` selects it).

## Disclosure

After a fix is released, the advisory is published through GitHub Security Advisories with credit to the
reporter unless the reporter asks to remain anonymous.
