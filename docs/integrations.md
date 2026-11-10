# Compatibility clients and integrations

CrawlX serves a compatibility API with v2 scrape, crawl, map, search, extract, agent and parse routes under
`/compat/v2` (`crates/crawlx-api/src/routes/mod.rs`, `routes/compat_*.rs`). This page says how to point
existing client libraries, command-line clients and third-party integrations at it, which endpoints each
kind of client calls, which of those CrawlX serves, and what is exercised by tests. Every statement is marked
**run** (executed by `cargo test -p crawlx-cli --test sdk_python`), **read** (read from the package or source
file in question, not executed) or **documented-only**.

Clients examined: the official Python and Node client libraries (v2 API generation) and the command-line
client built on the Node library; the document loaders of two popular LLM-application frameworks (one
maintained by the framework, one in its community package); a workflow-automation platform with an official and
a community node; an LLM-application builder; a low-code flow builder. Package names and versions are not
listed: the rules below follow from how each client builds its URLs and which routes it calls.

## 1. Run the compatibility API for a client

```sh
export CRAWLX_DATABASE_URL=postgres://crawlx:...@db/crawlx
export CRAWLX_API_DATABASE_URL=postgres://crawlx_api:...@db/crawlx # restricted non-owner role
FC_KEY="fc-$(openssl rand -hex 16)"            # fc- + 32 hex characters
crawlx serve  --bind 0.0.0.0:8080 --compat-keys --api-key "acme=$FC_KEY"
crawlx worker                                   # executes the runs the compatibility API creates
```

Provision the restricted API login and its tenant-table grants before starting
(`docker/provision-api-role.sql`; see [tenant isolation](design/data-and-secrets.md#tenant-isolation)).
Deployments should use `CRAWLX_DATABASE_URL_FILE` and `CRAWLX_API_DATABASE_URL_FILE`
with secret-manager files instead of environment values containing credentials.

* **The worker is required.** `scrape`, `crawl`, `batch/scrape`, `map` and the pages `extract` reads
  are CrawlX runs; `crawlx worker` leases them from PostgreSQL (`crates/crawlx-cli/src/ops.rs`,
  `worker`). `crawlx serve` without `--database-url` keeps its runs in the process, where no worker
  can see them.
* **Enable `fc-` keys.** An `fc-` key is accepted only when `compat.prefixedKeys` is on:
  `crawlx serve --compat-keys` or the environment variable `CRAWLX_COMPAT_KEYS=1`
  (`1`, `true`, `yes` or `on`; `CompatConfig::from_lookup`, `crates/crawlx-api/src/config.rs`). In a
  library the setting is `ApiConfig.compat.prefixed_keys`. **Run**: the bootstrap test starts the `crawlx` binary with the flag
  and with the variable, calls `GET /compat/v2/team/credit-usage` with the key (200) and
  checks that an unknown `fc-` key and the same key on `/v1/crawls/{id}` get 401.
* **Without the switch** a bootstrap `fc-` key is refused at startup (`bootstrap_keys`,
  `crates/crawlx-api/src/lib.rs`): `API key for tenant "acme" must look like cx_live_<26 base32
  characters>` (same test, third phase: the process exits non-zero with that message).
* **Key shape.** `fc-` followed by 16 to 64 ASCII alphanumerics (`parse_compat_key`,
  `crates/crawlx-api/src/auth.rs`). An `fc-` key authenticates only on `/compat/...` routes and
  never opens a native `/v1/...` route (`auth_layer`); a `cx_live_` key works on both.
* **LLM and search backends** (needed by `/extract`, `/search`, the `json`, `summary`,
  `question`, `highlights` and `query` formats) come from these variables:
  `CRAWLX_LLM_BASE_URL` (a chat-completions compatible endpoint; `CRAWLX_LOCAL_LLM_BASE_URL` for a local model server), `CRAWLX_LLM_MODEL`, `CRAWLX_LLM_API_KEY`, `CRAWLX_SEARCH_ENDPOINT` (a metasearch JSON API),
  `CRAWLX_SEARCH_ENGINES`, `CRAWLX_SEARCH_CATEGORIES`, `CRAWLX_SEARCH_API_KEY`, `CRAWLX_SEARCH_API_ENGINE` (a hosted search-results API)
  (`IntelConfig::from_lookup`, `crates/crawlx-api/src/config.rs`). `crawlx serve` reads all of them;
  `crawlx worker` reads the LLM ones for the scrape formats. Without a backend the endpoint answers 503.

## 2. Which base URL a client needs

The compatibility API lives at `http://HOST:8080/compat`; compatible clients append `/v2/...` to the base URL
they are given. Clients differ in how they join the two, and one of them throws the prefix away:

| client | how it builds the URL | base URL to configure | status |
|---|---|---|---|
| Python client library (v2) | `urljoin(api_url + "/", "/v2/scrape")`: a rooted path **replaces** the path of `api_url` | the origin of a proxy that maps `/v2/*` to `/compat/v2/*` (section 3) | **run**: with `api_url=http://HOST/compat` the request goes to `/v2/scrape` and the API answers `404 route not found` (row `scrape@prefix_base_url`); through the rewrite every method works |
| Node client library | HTTP client `baseURL` + `/v2/scrape`: the prefix is kept | `http://HOST:8080/compat` | **run** (the Node rows); a logging server also saw `POST /compat/v2/scrape` and `POST /compat/v2/map` |
| command-line client (built on the Node library) | the Node library, plus `${apiUrl}${path}` for `status`/`parse`/`feedback` | `--api-url http://HOST:8080/compat` (or its API-URL environment variable) | **run** (the CLI rows) |
| framework document loaders (Python) | build a Python-library client from `(api_key, api_url)` | as the Python client library | **run** for one loader (the loader rows); the other **read** |
| LLM-application builder | `base_url.rstrip('/') + '/' + 'v2/scrape'`: the prefix is kept | `http://HOST:8080/compat` | **read** |
| workflow platform, official node | credential `Base URL` (default: the hosted v2 endpoint) + relative `/scrape`, `/crawl`, ... | `http://HOST:8080/compat/v2` (the `/v2` is part of the value) | **read** |
| workflow platform, community node (third party) | credential `Base URL` default is a hosted v1 endpoint + `/scrape`, `/map`, `/crawl`, `/crawl/{id}`, `/crawl/webhook`, `/crawl/websocket` | `http://HOST:8080/compat/v2` | **read** |
| low-code flow builder, document loader | `this.apiUrl + '/v1/scrape'` and `/v1/crawl`, `/v1/extract`, `/v1/search`, `/v1/crawl/{id}`, `/v1/extract/{id}` | none works: the paths are v1 | **read** |
| no-code automation tools, any HTTP client | whatever URL you type | `http://HOST:8080/compat/v2/<endpoint>` | **documented-only** |

### 3. The `/v2/*` rewrite the Python client library needs

Put a reverse proxy in front of the API that maps `/v2/...` to `/compat/v2/...`, and give
the Python client the proxy's origin as `api_url`. The compatibility API writes absolute links into its answers (the
`url` of a started crawl, the `next` link of a paged status; `base_url`,
`crates/crawlx-api/src/scrape_service.rs`) from the `Host` and `X-Forwarded-Proto` headers and names the
`/compat/v2/...` path, which the client follows on the `api_url` origin: forward both headers, and let `/compat/` pass through too.

```
# reverse-proxy configuration, not executed here: the same mapping as the rewrite used by the test
location /v2/ {
    proxy_pass http://crawlx:8080/compat/v2/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
location /compat/ {
    proxy_pass http://crawlx:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

The **run** evidence uses an in-process rewrite (`rewrite_v2` in `crates/crawlx-cli/tests/support/sdk_rig.rs`)
instead of a reverse proxy. The API does not serve `/v2/...` at the root by itself.

## 4. Endpoints the compatibility API serves

Mounted by `crates/crawlx-api/src/routes/mod.rs` behind the key check, all under `/compat`:

| family | routes |
|---|---|
| scrape | `POST /v2/scrape`, `GET /v2/scrape/{jobId}` |
| batch scrape | `POST /v2/batch/scrape`, `GET`/`DELETE /v2/batch/scrape/{id}`, `GET /v2/batch/scrape/{id}/errors`, `GET /v2/batch/scrape/{id}/ws` |
| crawl | `POST /v2/crawl`, `GET`/`DELETE /v2/crawl/{id}`, `GET /v2/crawl/{id}/errors`, `GET /v2/crawl/{id}/ws`, `GET /v2/crawl/active`, `POST /v2/crawl/params-preview` |
| map | `POST /v2/map` |
| search | `POST /v2/search`, `POST /v2/search/{jobId}/feedback`, `GET`/`POST /v2/search/developer`, `GET`/`POST /v2/search/gov`, `GET /v2/search/research/papers[/{paperId}[/similar]]` |
| extract | `POST /v2/extract`, `GET /v2/extract/{id}` |
| agent | `GET`/`POST /v2/agent`, `GET`/`DELETE /v2/agent/{jobId}`, `GET /v2/agent/{jobId}/trace` |
| parse | `POST /v2/parse`, `GET /v2/parse/formats` |
| monitor | `POST`/`GET /v2/monitor`, `/v2/monitor/{id}`, `/run`, `/checks` |
| team | `GET /v2/team/credit-usage[/historical]`, `/token-usage[/historical]`, `/queue-status`, `/activity`; `POST /v2/feedback`, `/v2/support/ask`, `/v2/support/docs-search` |
| probes (no key) | `GET /v0/health/readiness`, `/v0/health/liveness` |

Not served, by design or because they are hosted-only:
every `/v1/...` route, `/v2/scrape/{jobId}/interact`, `/v2/browser...` and `/v2/team/threat-protection`.

## 5. Per client

### Python client library (official) - run

`tests/sdk/test_sdk.py` drives the real package (installed with `pip install --target` from
`tests/sdk/requirements.txt`) against the in-process compatibility API with a real worker, a fixture site, a mock LLM
and a metasearch stand-in. Results (`crates/crawlx-cli/tests/sdk_python.rs`, the Python test):

| client call | endpoint | result |
|---|---|---|
| `scrape(url, formats=[markdown, links, html])` | `POST /v2/scrape` | pass: markdown, links, html, metadata |
| `scrape` with a `json` format + schema | `POST /v2/scrape` | pass: `json` is the mock LLM's answer |
| `start_crawl` + `get_crawl_status` polling | `POST /v2/crawl`, `GET /v2/crawl/{id}` | pass: `scraping` then `completed`, 3 pages with markdown |
| `crawl` (waiter) | same | pass |
| `get_crawl_errors`, `cancel_crawl` (finished crawl), `get_active_crawls` | `/v2/crawl/{id}/errors`, `DELETE /v2/crawl/{id}`, `/v2/crawl/active` | pass (`cancel_crawl` returns `False`: the API answers 409) |
| `map` | `POST /v2/map` | pass |
| `search`, `search(scrape_options=...)` | `POST /v2/search` | pass: hits from the metasearch stand-in, with markdown when scraped |
| `extract`, `start_extract` + `get_extract_status` | `POST /v2/extract`, `GET /v2/extract/{id}` | pass: `completed`, data = the mock LLM's answer for the client's schema |
| `batch_scrape` | `POST /v2/batch/scrape`, `GET /v2/batch/scrape/{id}` | pass |
| `get_credit_usage`, `get_token_usage` | `/v2/team/credit-usage`, `/v2/team/token-usage` | pass (`-1`: no balance) |
| `scrape` with `api_url=http://HOST/compat` | `POST /v2/scrape` on the host | **expected fail, 404**: the client drops the prefix (section 2) |
| the legacy v1 methods (`.v1.scrape_url`, `.v1.crawl_url`, `.v1.check_crawl_status`, `.v1.map_url`; the default client is the v2 one, the v1 methods hang off its `.v1` attribute) | `/compat/v1/...` | **expected fail, 404 `route not found`**: `/v1` is not served by design |

### Node client library and its command-line client (official) - run

`tests/sdk/test_node.mjs` (installed with `npm ci` from `tests/sdk/package-lock.json`; the Node and CLI test)
with `apiUrl = http://HOST/compat`, no rewrite:
`scrape`, `startCrawl` + `getCrawlStatus`, `crawl`, `map`, `search`, `extract`, `batchScrape` all pass; the CLI
passes `scrape --format markdown,links --json`, `map --json`, `search --json`, `crawl --wait` and
`credit-usage --json` with `--api-url`/`--api-key`. The CLI's `search` also asks for a hosted-only
source; the API ignores it and says so in `warning`.

### Agent-skill installers - partly run

The command-line client's `init` command installs skill files into the detected coding agents and
logs in; it does not talk to the compatibility API. The skills tell the agent to run the command-line client, which does:
tell the CLI about the API with `config --api-url http://HOST:8080/compat --api-key fc-...`
or its API-URL and API-key environment variables (the client's "self-hosted" mode; a custom API URL skips
the browser login). **Run**: the CLI commands above. **Not run**: `init` itself, which writes to the agents' home
directory and downloads a skill catalog from a hosted service. CLI commands that need hosted features
(`interact`, `browser` and hosted-only tools) are not served.

### Document loaders for LLM-application frameworks - run (one loader), read (the other)

The first-party loader of the framework's partner package builds a Python-library client from `(api_key, api_url)` and calls `scrape` (`POST /v2/scrape`),
`crawl` (`POST /v2/crawl`, `GET /v2/crawl/{id}`), `map` (`POST /v2/map`), `extract` (`POST /v2/extract`,
`GET /v2/extract/{id}`) and `search` (`POST /v2/search`) with an `integration` field in the body. **Run**: the loader rows `scrape`, `crawl`, `map`,
`search`, `extract` pass against the API through the `/v2/*` rewrite, so the extra `integration` body
field is accepted. The same framework's community-package loader makes the same client calls: **read**,
not executed. A second framework's web reader makes the same calls (`scrape`, `crawl`, `map`, `search`, `extract` with its own
`integration` value) under the same URL rule as the Python client library: **read**, not executed (the package pulls a long
dependency tree). Use `api_url=<rewrite origin>` for all of them.

### Workflow-automation platform - read

The official node posts `{..., "integration": "<platform>"}` to `/scrape`, `/crawl`,
`/map`, `/search`, `/extract`, `/batch/scrape`, `/agent` and reads `/crawl/{id}`, `/crawl/{id}/errors`,
`/crawl/active`, `/extract/{id}`, `/batch/scrape/{id}[/errors]`, `/agent/{id}`, `/team/credit-usage`,
`/team/queue-status`, `/team/token-usage[/historical]`, `/team/credit-usage/historical` (relative to the credential
`Base URL`). Set the credential `Base URL` to
`http://HOST:8080/compat/v2` and the API key to the `fc-` key; the API serves all of those. Its
`interact` and `browser` operations (`/scrape/{id}/interact`, `/browser`) are not served. The credential test
calls `GET /team/credit-usage`. The community node is a v1 node: with its `Base URL`
set to the v2 base, `scrape`, `map`, `crawl` and the crawl status call routes the API serves; `crawl/webhook`
and `crawl/websocket` are routes of that node's own API that CrawlX does not have; its request
bodies were not compared with the compatibility API. **HTTP request node fallback**: any workflow can call the API
with the platform's generic HTTP request node and an `Authorization: Bearer fc-...` header (section 6).

### LLM-application builder - read

Its web-extractor client posts `v2/scrape`, `v2/crawl`, `v2/map` and
`v2/search` (the last two with an `"integration"` field) and reads `v2/crawl/{id}` plus the `next` links of
paged results, all relative to the configured base URL. The API serves all five. The credential check and the
data-source flow of current releases live in plugins that were not read (the earlier auth service no
longer exists on the main branch), so whether the builder's "authorize" step accepts a self-hosted URL is unknown here.

### Low-code flow builder - read: does not work

Its document loader calls `/v1/scrape`, `/v1/crawl`, `/v1/extract`, `/v1/search`, `/v1/crawl/{id}` and
`/v1/extract/{id}`. The compatibility API serves none
of them (the same 404 as the legacy v1 rows above), so that loader cannot use CrawlX. The builder's other
loaders (static HTML, headless browser, ...) do not involve the compatibility API.

### No-code automation tools and agent frameworks - documented-only

The generic webhook or custom-request action of an automation tool sends plain HTTP: use
the URL, headers and bodies of section 6. Dedicated apps, app-builder connectors and agent-framework tools were
not examined (closed or not read); if they take only an API key and cannot be given a base URL, they cannot reach
a self-hosted compatibility API at all.

## 6. Plain HTTP (curl, workflow HTTP request nodes, automation tools)

```sh
BASE=http://HOST:8080/compat/v2
AUTH="Authorization: Bearer $FC_KEY"

# one page
curl -s $BASE/scrape -H "$AUTH" -H 'content-type: application/json' \
  -d '{"url":"https://example.com","formats":["markdown","links"]}'

# a crawl: start, then poll until "status" is "completed" (statuses: scraping, completed, failed, cancelled)
curl -s $BASE/crawl -H "$AUTH" -H 'content-type: application/json' \
  -d '{"url":"https://example.com","limit":10,"scrapeOptions":{"formats":["markdown"]}}'   # {"success":true,"id":"...","url":"..."}
curl -s $BASE/crawl/<id> -H "$AUTH"                                                         # follow "next" while it is not null
```

The request and response shapes are the ones the client rows above exercise.

## 7. Caveats

* **The Python client library and its dependents (the framework loaders) need the `/v2/*` rewrite** (section 3); without it
  they get 404 for every call. Everything that builds URLs by concatenation (Node library, CLI, the app builder, the workflow platform) takes the
  `/compat` prefix as is.
* **No `/v1`.** Clients and integrations that call `/v1/...` (the low-code flow builder, the v1 methods of both client libraries, the community workflow node's
  default base URL) fail with 404.
* **Hosted-only features** answer 404 or a warning: `interact`, browser sandbox, hosted-only search sources, threat protection.
* **`extract` and `search` URLs** keep their own port (a fixed bug: `/extract` used to answer 422 `no valid URLs`
  for `http://host:8080/...`, found by this test).
* **The test installs from PyPI and npm.** It prints `skipping: <reason>` and returns when `python3`/`pip`,
  `node`/`npm` or the registry is unavailable. `CRAWLX_SDK_PYTHONPATH` and `CRAWLX_SDK_NODE_DIR` point it at an
  existing install.

## 8. Operator protocol and acquisition-service boundary

Native HTTP and Session Actor browser acquisition remain the default. `protocol.schemaVersion: 1`
adds at most 32 ordered routes. Each route names an operator registry key, never an endpoint,
script, CDP URL, credential value or storage location. The first matching scheme/origin/path/
scheduler-fact selector wins. HTTP(S) without a match retains the existing native classifier.
Path expressions compile at admission under 2 KiB pattern and 64 KiB compiled-program limits.
An explicit HTTP route disables later dynamic promotion. Explicit browser routes use the existing
native browser renderer and its shared acquisition allowance. Route body and elapsed ceilings only
lower the parent allowance; they do not mint fresh retries, requests or bytes.

Scheduler selectors currently expose these worker-produced facts: `request_class=stateless_get`,
`source_kind=url_plane` and `media_class=unclassified`. Page/extractor metadata never populates
this map. Unknown selector keys fail admission. Public request normalization rejects file routes
and wildcard scheme routes. File roots cannot be configured through the HTTP API.

### Local corpus

`crawlx corpus --root /operator/corpus --url file:///articles/ --max-entries 64 --max-bytes 16777216`
reads only root-relative resources and writes native extraction JSONL to stdout. It initializes no
network transport or artifact store. Raw authority/traversal admission happens before URL normalization.
The root is an operator-held directory descriptor. Linux component opens use `O_PATH|O_NOFOLLOW`,
then classify the pinned inode before opening regular-file content. Directories enumerate bounded,
sorted direct children; the invocation also bounds total entries, bytes and elapsed time.
Directory URLs require a trailing slash; regular-file URLs must not have one. The low-level
reader separates refused entries into `denied_children`, never into authorized discovery.
The corpus command refuses a directory with any denied entry. HTML uses the native article
serializer; other supported file types use native format detection and bounded document parsers.
Unavailable formats, including images without an OCR backend, fail explicitly.
Symlinks, devices, FIFOs, host components and parent traversal fail closed. Reads require Linux
descriptor reopening through `/proc/self/fd` and a supported local kernel filesystem
(ext-family, XFS, Btrfs, tmpfs or overlayfs); network/FUSE filesystems are unavailable.

### Approved isolated services

Set `CRAWLX_PROTOCOL_REGISTRY` to an operator-controlled JSON file, limited to 64 KiB:

```json
{
  "schemaVersion": 1,
  "approvedTenants": ["00000000-0000-0000-0000-000000000001"],
  "services": {}
}
```

An empty registry advertises no remote capability. Each `services` entry must contain:

* A fixed HTTPS `endpoint`, fixed `audience`, 64-hex `approvalDigest` and a scoped
  `credentialRef` such as `env://CRAWLX_ACQUISITION_TOKEN` or a mounted `file:///run/secrets/...`.
  The worker resolves only this explicit
  operator reference. Target credentials use `targetCredentialRefs`, keyed by exact canonical origin
  (for example `sftp://approved.example`, not merely a host shared with HTTPS),
  and resolve inside the isolated service. Storage credentials are never part of this contract.
* An approved `capabilities` contract: version, schemes, capability IDs, byte cap, body streaming,
  redirect behavior, subresource enforcement, cancellation/deadline enforcement, checked egress,
  identity isolation, zero-retention behavior and immutable build digest. These are operator
  conformance approvals, not trusted assertions downloaded from a provider.
  `read_only_effects` and `secret_free_response` are mandatory capability IDs. The request always
  sends `allowBrowserWrites=false`; service-side automatic and explicit write effects must remain
  blocked. Responses echo `redactionPolicyDigest`, matching the approved policy, before content
  may enter native retention sinks. Locally known service credentials are also removed defensively.
* `policyDigests` containing the exact permitted policy references. A route's `policyRevision`
  must name one of these approvals; the service must already enforce that policy for document,
  redirect, iframe, subresource, popup, worker, download and protocol control/data traffic.
* `originAdmissionRef` naming an approved shared network broker policy, and capability
  `shared_origin_admission`. The isolated service must integrate this broker for every redirected
  or subordinate effect, not create a separate unpaced network path. The locally held initial
  origin permit does not establish pacing for arbitrary remote subresources. An unintegrated
  generic browser, FTP or CDP service is therefore unavailable, even if it returns matching JSON.
* `sftpHostKeys` for exact-host SSH key pins and `whoisRegistries` for approved referral authorities.
  SFTP requires `sftp_key_pinned` and target credential references. FTP requires
  `ftp_passive_pinned`; active FTP is not accepted. Passive peers must belong to the checked
  target address set, and every data port still requires operator egress approval.
* Optional operator CA PEM (`caPem`) and exact control-plane CIDRs (`serviceNetworks`).
  Control-plane network approval is separate from tenant target-network authority. Neither
  option disables TLS hostname or certificate checks.

The wire request binds audience, tenant/run/attempt, target origin and checked addresses, policy,
nonce, idempotency key, credential references, byte/request ceilings and an absolute finite lease.
The ticket is keyed BLAKE3 over UTF-8 JSON with `ticket` empty and every object's keys sorted
lexically, without extra whitespace; arrays retain order. Its key is `BLAKE3(scoped service
credential)`. The service verifies authentication and the ticket,
enforces a one-use nonce ledger, validates scope/schema and stops work at lease expiry.
The response echoes that scope, supplies checked socket evidence and carries bounded inline bytes,
not provider-selected artifact/storage handles. Unknown fields or versions, wrong audience/nonce/
ownership, missing attestation, private peers and wrong SSH keys are refused.
The client replay window holds at most 4096 attempt identities until their maximum lease plus a
five-second skew allowance. A full window refuses dispatch. The service's authenticated replay
ledger and idempotency handling remain mandatory across client process restarts.

The client pins checked service DNS, verifies the actual service peer, disables redirects and
environment proxies, caps streamed JSON/body bytes, and uses the same target origin governor.
Two isolated-service slots remain separate from native HTTP slots. Cancellation drops the local
call and releases its permits; remote termination depends on the approved enforced lease.
No cancellation acknowledgement is invented. No failed or unavailable service falls back to direct I/O.
Gateway HTTP 200 remains distinct from target 403. Missing final URL remains
`finalUrlEvidence=unavailable`; the requested URL may only serve as an extraction base.
Resources without a target HTTP status never enter HTTP `PageRecord` storage. Worker HTTP page
publication returns an explicit unavailable-status refusal with its acquisition receipt instead.
The operator protocol command emits a dedicated nullable-status resource envelope and does not
write HTTP pages.
All service results stay in the `diagnostic` lane. Browser writes still require the Session Actor.

`crawlx protocol --delegate APPROVED_ID --url sftp://approved.example/document.html --tenant UUID --run UUID
--attempt UNIQUE --policy-revision APPROVED_POLICY --allow-ports 22`
invokes this real boundary and sends the result through native extraction to stdout.
The registry must explicitly approve the tenant and zero retention for this no-persistence command.
Passive FTP requires each approved data port in `--allow-ports`; there is no broad high-port exemption.
The optional operator registry `whois` object enables `--delegate native_whois`:
`{"endpoints":{"registry.example":{"host":"registry.example","port":43}},"maxReferrals":2}`.
Each referral must name another registered authority. Its DNS set and connected peer are checked
before query I/O. No domain expansion or unregistered referral is followed.

Service responses must explicitly attest `bodyComplete=true`; an interrupted or prefix-only
representation never enters the successful publication path. Protocol page publication appends
authorized children while the parent's lease fence remains live, before terminalization.
Accepted, non-partial, privacy-projected articles use the declared article dataset; item acceptance,
delivery intent and terminal completion share one fenced commit. Child batches have their own
live-parent fence checks and are crash-idempotent, not an exactly-once network guarantee.

No FTP/SFTP service implementation or deployment is bundled or claimed available by default.
Operators must supply and audit the isolated implementation, its credential resolver and network
isolation. Local HTTPS fixtures exercise the client/server authentication and result contract;
they are not evidence of FTP/SFTP library interoperability or provider enforcement.
