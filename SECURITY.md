# Security policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Earlier than 0.1.0 | No |

crawlx is pre-1.0. Only the latest 0.1.x release receives security fixes. The first
public distribution is the source repository and tagged source releases; no
binaries, container images, hosted service or crates.io packages are published, so
there are no other artifacts to patch.

Production qualification is still in progress. The [README](README.md#release-status)
and the [changelog](CHANGELOG.md) list the open items. Do not deploy a checkout as a
public service or use it for sensitive authenticated sessions until those are closed.

## Reporting a vulnerability

Report vulnerabilities privately through GitHub private vulnerability reporting for
`noxred-research/crawlx`:

1. Open <https://github.com/noxred-research/crawlx/security/advisories/new>, or go to the
   repository's **Security** tab and choose **Report a vulnerability**.
2. Describe the affected component and version or commit, the impact, and steps or a
   proof of concept that reproduce the problem.
3. Do not include live credentials, real personal data or captured third-party content
   in the report.

Do not open a public issue or pull request for a suspected vulnerability. If the
private reporting option is not offered on the repository, open a public issue that
asks for a private channel and contains no technical details.

Reports are handled by the maintainer on a best-effort basis. This project does not
publish a response-time commitment or a bug bounty.

## Scope

In scope: code in this repository, its build and CI configuration, and the
deployment files under `docker/` and `deploy/`. Findings that bypass a control
described below are in scope even when they need a particular configuration.

Out of scope: vulnerabilities in third-party dependencies that have no crawlx-specific
exploit path (report those upstream; dependency advisories are checked by
`cargo deny`), the behavior of crawled sites, and findings that require an operator to
grant an authorization or secret deliberately.

### Authorization records

crawlx refuses requests that need elevated authority unless an authorization record
covers them. The safety profiles `test_environment` and `authorized_security_test`,
private-network access (`--allow-private-networks`) and the robots override all require
a record created by the operator. The record is evidence of the operator's stated
authorization; crawlx does not verify legal permission to crawl a target. A path that
performs one of those actions without a valid, unrevoked, in-scope record is a
vulnerability. See the [safety model](docs/design/safety-model.md#authorization-records)
for what is enforced and where.

Use crawlx only against systems you own or are authorized to test.

### Zero data retention and secret boundaries

Zero-data-retention (ZDR) mode and the handling of credentials, cookies, API keys and
other secrets are described in the
[data and secrets design](docs/design/data-and-secrets.md). Secrets and sensitive page
content must stay out of prompts, logs, snapshots, artifacts, telemetry and durable
storage, and ZDR runs must not create durable copies of page content. A leak across
those boundaries, or a ZDR path that persists content, is a vulnerability. The
release-specific restrictions listed in the changelog are known limitations, not new
findings.

### Egress and safety kernel

The egress filter (SSRF protection) and the independent safety kernel
(see the [safety model](docs/design/safety-model.md)) are security controls.
Bypassing either is a vulnerability.

## Disclosure

After a fix is released, the advisory is published through GitHub Security Advisories
with credit to the reporter unless the reporter asks to remain anonymous.
