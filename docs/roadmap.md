# Roadmap

What is open in crawlx 0.1.0. This list is intent, not a commitment or a schedule; items move when
someone picks them up. The [changelog](../CHANGELOG.md) records what has shipped, and
[CONTRIBUTING.md](../CONTRIBUTING.md) explains how to propose a change. Open an issue before starting
anything large.

## Qualify for production use

crawlx is pre-1.0. Before it is recommended for public services or sensitive authenticated sessions the
integration, soak and operational checks that gate the first stable release need to be closed.

## Distribution

Releases are source archives with a SBOM and checksums. Prebuilt binaries, published container images and
crates.io packages are not part of the initial distribution.

## Safety and policy

- **Approvals end to end.** The kernel enforces single-use, parameter-bound approvals, but its approval
  store is in-process and a decision made through the API route does not reach it, so `approval_required`
  behaves as `deny`. Connect the two.
- **Browser robots coverage.** Robots is checked for main-frame navigations but not for subresources and
  embedded frames. Decide and document the boundary, or extend it.
- **Network-namespace egress mode.** The configuration enum and a deployment example exist; the worker
  does not implement the mode.

## Data and secrets

- **Retention sweeper loop.** `crawlx admin sweep-retention` runs one pass and must be scheduled by the
  operator. A built-in scheduled loop would remove that step.
- **Secret authority renewal.** The run-wide secret registry lives at most 24 hours with no mid-run renewal;
  after expiry, durable content writes of that run fail closed.
- **Retained browser profiles.** Unavailable while encrypted artifact custody is enabled; bring profiles
  under custody.
- **Fallible HTML parsing.** Parse memory is bounded by a measured ceiling and a process budget rather
  than by fully fallible allocation.

## Browser plane

- **Zero-attempt background isolation.** The pinned Chromium attempts unsolicited background requests that
  the egress policy denies and logs. A patched build exists under `ci/chromium-patches/`; validating it
  and making it the pinned browser would remove the attempts.

## Good places to start

Documentation fixes, tests for a documented behavior, a new fixture for the CrawlerGym server, and
clarifying error messages are always welcome. Look at the open items above for larger work.
