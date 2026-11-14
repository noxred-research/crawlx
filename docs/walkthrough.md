# Walkthrough: CrawlerGym, PostgreSQL and Chromium

An end-to-end local run against the bundled CrawlerGym fixture server, with a PostgreSQL store and the
pinned Chromium. Everything stays on loopback. Build with `cargo build --workspace` and put `target/debug`
on your `PATH` (it holds `crawlx` and `gym-server`); see the [README](../README.md#install) for fetching
Chromium.

## The authorization record

The gym listens on loopback, so the run needs an [authorization record](design/safety-model.md#authorization-records).
For a local run you are the authorizer and no ownership proof is needed. Save this as `authz.local.json`
(replace the UUIDs and keep the window under 90 days):

```json
{
  "id": "00000000-0000-4000-8000-000000000001",
  "tenant": "00000000-0000-4000-8000-000000000002",
  "version": 1,
  "title": "local CrawlerGym",
  "authorizer": {
    "name": "Your Name",
    "role": "owner",
    "organization": "Your Org",
    "contact": "you@example.org",
    "attestsOwnershipOrControl": true
  },
  "origins": ["http://127.0.0.1:34635"],
  "authorizedNetworks": ["127.0.0.0/8"],
  "validFrom": "2026-11-01T00:00:00Z",
  "validTo": "2026-12-01T00:00:00Z",
  "profileCap": "read_only",
  "permittedRiskClasses": [],
  "approvalRequired": [],
  "testAccounts": [],
  "emergencyContact": "you@example.org",
  "evidence": { "kind": "local_fixture", "digest": "0000000000000000000000000000000000000000000000000000000000000000" }
}
```

## Run

```
gym-server --bind 127.0.0.1:34635                      # 14 fixtures under /<id>/
export DB=postgres://crawlx@127.0.0.1:54329/crawlx CRAWLX_ALLOW_UNPINNED=1
crawlx migrate --database-url $DB
# Every PostgreSQL crawl (including the local CLI) needs encrypted artifact custody:
# use a protected regular file containing 64 hexadecimal characters, and a persistence-free registry.
export CRAWLX_ARTIFACT_KEY_FILE=/absolute/path/to/artifact-key
export CRAWLX_SECRET_REDIS_URL=redis://127.0.0.1:6390
# Browser runs additionally need a checkpoint key provider: a cloud KMS key identifier
#   export CRAWLX_CHECKPOINT_KMS_KEY_ID=<checkpoint-key-id>
# or, with no cloud service, a local key-encryption-key file (mode 0600, lines of <key-id>:<64 hex>):
export CRAWLX_CHECKPOINT_KEK_FILE=/absolute/path/to/checkpoint-keks
# See docs/design/data-and-secrets.md for key provisioning and registry requirements.
# static plane: prints discovered 90 / admitted 30 / deduplicated 55 /
# policy_blocked 3 / robots_blocked 2 / succeeded 28 / failed 2 and writes 28 pages.
crawlx crawl http://127.0.0.1:34635/s1/ --mode static --authorization-record authz.local.json \
  --allow-private-networks --seed 20261019 --trailing-slash strip --database-url $DB --output ./out/static
# observe only: one state with an AX artifact; the metadata-address request is blocked.
crawlx crawl http://127.0.0.1:34635/d1/ --mode dynamic --observe-only --authorization-record authz.local.json \
  --allow-private-networks --seed 20261019 --database-url $DB --output ./out/observe
crawlx inspect states <run-id> --database-url $DB; crawlx inspect epochs <run-id> --database-url $DB
# read_only interaction. kill -9 mid-action, then:
crawlx worker --recover --database-url $DB             # intended -> unknown -> reconciled, never re-executed
crawlx inspect actions <run-id> --status reconciled --database-url $DB
# API: serve + worker use filesystem artifact storage and must share --artifacts-dir. A PostgreSQL worker also
# needs an artifact key provider (CRAWLX_ARTIFACT_KEY_FILE or CRAWLX_ARTIFACT_KMS_KEY_ID) and CRAWLX_SECRET_REDIS_URL;
# the API needs the key provider (see docs/design/data-and-secrets.md).
# Provision a restricted API login first (docker/provision-api-role.sql), then set
# CRAWLX_API_DATABASE_URL or CRAWLX_API_DATABASE_URL_FILE to its connection string.
# Example key below uses exactly 26 characters from lowercase a-z and digits 2-7; replace it.
crawlx serve --bind 127.0.0.1:38080 --database-url $DB --artifacts-dir ./crawlx-artifacts --api-key 00000000-0000-4000-8000-000000000002=cx_live_abcdefghijklmnopqrstuvwxyz
crawlx worker --database-url $DB --artifacts-dir ./crawlx-artifacts
```

The authorization record covers the gym origin and `127.0.0.0/8`, and every request of the run stays inside it.
