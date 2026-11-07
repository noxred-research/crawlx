# Firecrawl differential harness

Firecrawl is a black box that produces data; crawlx
is compared against that data. Nothing here links, vendors or translates Firecrawl source.

## Pieces

| Path | What |
|---|---|
| `crates/crawlx-bench/src/differential/` | the runner library: export shapes, crawlx run reduction, normalization (incl. block-level F1), the gym access log (`access.rs`), ledger, comparator, scorecard, and the wire-level scenarios (`wire/`: driver, webhook sink, comparator) |
| `crates/crawlx-bench/src/bin/crawlx-differential.rs` | the CLI (`cargo run -p crawlx-bench --bin crawlx-differential -- --help`; `... -- wire --help` for the wire subcommands) |
| `divergences.toml` | the divergence ledger; schema in the file header; entries may be scoped to families |
| `families.json` | the crawl families: fixture, host, seed path, Firecrawl request, comparison mode, expected verdict, recorded residuals |
| `wire-scenarios.json` | the wire families (VAL, PREC, CLAMP, PERSIST, CANCEL, RESUME/LEASE, WH, ZDR): scenarios, how each crawl is settled, the expected verdict |
| `captures/<family>.json` | the black-box Firecrawl captures (`provenance: black_box_run`, pinned commit): a v2 export for a crawl family, the raw exchanges of the scenarios for a `wire-*` family; `s1.authored.json` is the authored sample of 2026-10-20, kept for diffing only |
| `docker-compose.firecrawl.yaml`, `firecrawl.env` | the override file and the compose environment for the unmodified pinned Firecrawl self-host (upstream's own `docker-compose.yaml` is the first `-f` file) |
| `firecrawl_export.py` | crawl one family through a running Firecrawl v2 API and write the export, with the gym's access log (stdlib only) |
| `run.sh`, `run-wire.sh` | start the stack, run every crawl family (resp. wire family) against Firecrawl and crawlx, score; `all` or one family |
| `sdk_shape_capture.py`, `sdk_shape_diff.py`, `tests/` | the SDK-in-the-loop shape diff (below): the official `firecrawl-py` calls captured against one API, the field-by-field diff of two captures, and its offline unit tests |

## Export format

The Firecrawl side is the `GET /v2/crawl/{id}` body with every `next` page merged into `data[]`
and the `GET /v2/crawl/{id}/errors` body stored under `errors`:

```json
{
  "status": "completed", "total": 34, "completed": 32, "creditsUsed": 34, "next": null,
  "data": [{"markdown": "…", "links": ["…"], "metadata": {"sourceURL": "…", "statusCode": 200, "title": "…", "language": "en", "contentType": "…"}}],
  "errors": {"errors": [{"url": "…", "code": "…", "error": "…"}], "robotsBlocked": ["…"]}
}
```

Unknown fields are ignored. The crawlx side is the JSON `--save-crawlx` writes (status, URL-plane
counters, succeeded pages with markdown and links, every frontier row with its outcome) or the
directory `crawlx crawl --out DIR` writes (no frontier, so admission is judged on succeeded pages
only).

## What is compared

- **C1 admission.** The set of URLs each system attempted (documents plus error entries on the
  Firecrawl side; `succeeded`, `failed` and `unreachable` frontier rows plus the entry URL an
  include filter refused as a page but crawlx fetched for its links, a depth-0 `policy_blocked` row
  `not_included`/`url_not_included`, on the crawlx side; Firecrawl lists that URL in `errors[]` as
  `CRAWL_DENIAL`) and the
  robots-blocked sets. URLs are reduced to origin-independent keys (`{origin}/path?query`, fragment
  dropped, trailing slash removed), so the two systems may crawl the fixture on different hosts or
  ports. A difference without a ledger entry is **blocking** (exit 1).
- **C1 requested set.** The fixture server's access log (`/__gym/ledger`: method, path, query and `Host` of
  every request; a fresh gym serves one system) gives the set of page URLs each system *requested*, excluding
  `robots.txt`, sitemaps, gym beacons and favicons. It is compared like the attempted set
  (a URL requested by one side only is **blocking**); an `admission` entry of the same URL and side
  documents it too, a `requested` entry covers requested-only differences (a redirect hop, a fetch the system
  does not report). URLs requested a different number of times are listed, not judged. Requests to another
  host name of the same gym are keyed `http://<host>:{port}/path`.
- **C2 content.** For each page present on both sides: normalized-markdown token Jaccard with a
  line diff (threshold 0.97 per page, 0.98 corpus mean), block-level F1 (each heading,
  list item, table row, code span and paragraph is a block; threshold 0.80 per page, informational for the
  corpus mean) with the ordered-subsequence ratio, link-set Jaccard (0.98) and equality of
  `title`, `description`, `language`, `statusCode`, `contentType` (0.99 over the corpus). Below a
  threshold without a ledger entry is a **warning** (exit 0, or 3 with `--fail-on-warning`).
- **C3 counters.** `status` (crawlx mapped through the compat facade's status table), `total`
  versus `admitted`, `completed` versus `succeeded`, attempted and robots-blocked cardinalities.
  Warnings.
- **Wire families (C0/C3).** `wire-*` families compare behavior over HTTP (`run-wire.sh`): per scenario the
  observations `request.decision` (accept 2xx, reject 4xx), `final.status`, `final.urls`, `cancel`/`after:*`
  decisions, `quiet` (does a cancelled crawl stop requesting pages), `resumed_within_slo`, the webhook
  `types` sequence, metadata and header echo, redelivery after a failed delivery are **hard** (an undocumented
  difference blocks); HTTP and error codes, counters and envelope keys are **soft** (warning). Ledger entries
  of kind `behavior` match `<scenario>/<observation>` (`|` separates alternatives).

Normalization (both sides): NFC, line endings, trailing whitespace, entity
decoding, setext → ATX headings, `*`/`+` → `-` list markers, `__` → `**`, link targets resolved
against the page URL with tracking parameters stripped and the origin rebased, canonical table
rows, blank-line runs collapsed.

## Capture provenance

`captures/<family>.json` are real exports (`crawlxSample.provenance: black_box_run`, with the pinned
`upstreamCommit`, the job id, the request and the status-page count) of Firecrawl
`c31e88c07afe941bfd8aebde61684eeba042abb5` crawling a CrawlerGym fixture (the 13 families of 2026-10-28; the `d2` families and the wire families of
2026-10-29). A crawl capture of 2026-10-29 also
carries `accessLog`, the gym's rows of that crawl. `rawHtml` is stored as its SHA-256 and byte
length, not as bytes. A `wire-*` capture (`wireSample.provenance: black_box_run`) holds the raw HTTP
exchanges of every scenario (documents reduced to `sourceURL` and `statusCode`), the webhook sink's
deliveries and the quiet-window request counts. `captures/s1.authored.json` was written from the `s1` fixture semantics and is
**not** a capture; it differs from the real one (HTTP-error pages are documents upstream), the runner
tests still use it as a synthetic export. Firecrawl's own fixtures are not used (R7).

The captures pin the upstream commit and request, but do not record a digest of the authored gym
source. The gym snapshot digest covers the seed, not the fixture files. Historical input therefore
must not be inferred from either value. G12's captured entry used
`/g12/invoice?id=3&sessionid=abc123`; the current entry deliberately uses the distinctive
`g12_session_canary_7d91e8c4` token for the privacy acceptance test.

The Rust offline replay restores only G12's historical `index.html`, preserved from source revision
`300ba24` at `fixtures/2026-10-28/g12/index.html`. It checks domain-separated BLAKE3 source digests
(`crawlx/bench/differential/fixture-source/v1`, followed by a zero byte, then the exact source bytes):

| Authored entry version | Source digest |
| --- | --- |
| Historical `300ba24`, used by the 2026-10-28 capture | `3f38c50ca2e80e8b24bf106e690e7324dcf05f9632f78c4d33839abfe5c0f570` |
| Current privacy canary | `f612587c73c3cc75beb305e4a84c0ce894533fd99e1868af206c340a221ff667` |

Before selecting that immutable, listener-local file override, replay verifies the current source
and checks that replacing only the known canary with `abc123` exactly reproduces the historical
entry. Future source changes require an explicit provenance review, not automatic token
normalization. All other files, resource-identifying queries, admission comparisons, ledger entries
and thresholds remain unchanged. The historical file is authored input, not a new upstream
measurement; `captures/g12.json` remains untouched. Ordinary gym listeners, including the G12
privacy test, retain the current canary. The command-line gym and `SKIP_FIRECRAWL=1` shell runner
still use the current catalog; unlike the Rust replay, their G12 comparison is not a like-for-like
replay of this historical entry.

## Running

```sh
# offline replay of the committed captures against in-process crawlx runs (what the tests do)
cargo test -p crawlx-bench --test differential
SKIP_FIRECRAWL=1 GYM_PORT=4101 bench/differential/run.sh all /tmp/replay

# one capture by hand
cargo run -p crawlx-bench --bin crawlx-differential -- --firecrawl bench/differential/captures/s1.json \
  --firecrawl-origin http://gym.test:4101 --fixture s1 --request @bench/differential/captures/s1.json \
  --trailing-slash keep --label s1 --out /tmp/scorecard.md

# a real run: Firecrawl at the pin, built from a checkout outside the repository
FIRECRAWL_SRC=$HOME/.cache/firecrawl-upstream FIRECRAWL_PORT=3102 GYM_PORT=4101 PROMOTE=1 \
  bench/differential/run.sh all bench/differential/out
FIRECRAWL_URL=http://127.0.0.1:3102 bench/differential/run.sh s1   # an already running stack
```

`run.sh` checks the pinned commit out (default `.firecrawl-src/`, git-ignored; `FIRECRAWL_SRC` for another
path), builds and starts only `api` and its dependencies with
`docker compose -p crawlx-differential --env-file firecrawl.env -f <checkout>/docker-compose.yaml -f docker-compose.firecrawl.yaml`,
starts a fresh gym on `0.0.0.0:$GYM_PORT` per family (its `robots.txt` belongs to the fixture that claims the origin:
`claim_origin` in `families.json`), posts the family's request with `maxConcurrency: 1` and formats `markdown`,
`links`, `rawHtml`, follows `next`, fetches `/errors` and the gym's access log (`/__gym/ledger`), and scores with
`--trailing-slash keep` (the facade's workers). It exits 1 when a family misses its
`expect`ed verdict in `families.json`. Known quirks of the database-less self-host: it must not be sent
`x-idempotency-key` (the API process exits), and it fetches the gym only because `ALLOW_LOCAL_WEBHOOKS=true` is set on the API container.

The `d2` families fetch the gym under several host names (`fixture_hosts` in `families.json`, mapped to the host
gateway by `docker-compose.firecrawl.yaml` and to 127.0.0.1 by the crawlx run's resolver).

```sh
# the wire families: scenarios against the real Firecrawl, the same scenarios against the in-process facade
FIRECRAWL_URL=http://127.0.0.1:3102 FIRECRAWL_SRC=$HOME/.cache/firecrawl-upstream FIRECRAWL_PORT=3102 \
  GYM_PORT=4101 PROMOTE=1 bench/differential/run-wire.sh all bench/differential/out
SKIP_FIRECRAWL=1 bench/differential/run-wire.sh all /tmp/wire   # offline: committed captures vs the facade
cargo test -p crawlx-bench --test wire_facade                  # the same, as tests
```

`run-wire.sh` restarts the Firecrawl API container (`RESTART_CMD`) for the PERSIST and RESUME scenarios and runs
a webhook sink on a free port, addressed from the containers as `http://gym.test:<port>/hook/<label>`.

## CI

`ci.yml` job `differential-nightly` runs `run.sh` on the schedule only; `run-wire.sh` is run by hand and is not wired into CI yet. The runner tests (`cargo test -p crawlx-bench --test differential --test wire_facade`)
run on every PR without Firecrawl.

## SDK shape diff

The question is what the official SDK sees from the real Firecrawl and from the crawlx compat facade
for the same calls on the same fixture. `sdk_shape_capture.py` runs `scrape` (the entry page, a 404, a
500, a robots-disallowed page), `map`, `start_crawl` + `get_crawl_status` + `get_crawl_errors`, the
`crawl` waiter and `cancel_crawl` through `firecrawl-py`, records each typed result and the raw wire
exchange of the same request, and `sdk_shape_diff.py` flattens both wires to JSON path to type and
writes the markdown report (paths only upstream, only crawlx, type and presence differences, stable
values, response headers). The gated test `crates/crawlx-cli/tests/sdk_upstream_shape.rs` runs both
captures (the facade in-process through `support/sdk_rig.rs`, the real Firecrawl at
`CRAWLX_UPSTREAM_FIRECRAWL_URL`) and the diff; without the variable it prints `skipping: ...`.
The report and the raw captures are written to `bench/out/sdk-shape/` (git-ignored) unless the test is
given another output directory.

```sh
python3 -B -m unittest discover -s bench/differential/tests   # offline
CRAWLX_UPSTREAM_FIRECRAWL_URL=http://127.0.0.1:3102 cargo test -p crawlx-cli --test sdk_upstream_shape -- --nocapture
```
