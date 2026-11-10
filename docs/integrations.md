# Firecrawl clients and integrations on the crawlx facade

crawlx serves Firecrawl's v2 API under `/compat/firecrawl/v2` (`crates/crawlx-api/src/routes/mod.rs`,
`routes/compat_*.rs`). This page says how to point Firecrawl's SDKs, its CLI and the third-party
integrations at it, which endpoints each of them calls, which of those the facade serves, and what
is exercised by tests. Every statement is marked **run** (executed by `cargo test -p crawlx-cli --test sdk_python`),
**read** (read from the package or source file named, not executed) or **documented-only**.

Versions examined: `firecrawl-py` 4.54.0, `langchain-firecrawl` 0.1.0,
`langchain-community` 0.4.2, `llama-index-readers-web` 0.7.0, npm `firecrawl` 4.51.0 and
`firecrawl-cli` 1.26.24, `@mendable/n8n-nodes-firecrawl` 2.2.0, `n8n-nodes-firecrawl` 0.3.0, the
`main` branches of `langgenius/dify` and `FlowiseAI/Flowise`.

## 1. Run the facade for a client

```sh
export CRAWLX_DATABASE_URL=postgres://crawlx:...@db/crawlx
export CRAWLX_API_DATABASE_URL=postgres://crawlx_api:...@db/crawlx # restricted non-owner role
FC_KEY="fc-$(openssl rand -hex 16)"            # fc- + 32 hex characters, like Firecrawl's own keys
crawlx serve  --bind 0.0.0.0:8080 --firecrawl-keys --api-key "acme=$FC_KEY"
crawlx worker                                   # executes the runs the facade creates
```

Provision the restricted API login and its tenant-table grants before starting
(`docker/provision-api-role.sql`; see [tenant isolation](design/data-and-secrets.md#tenant-isolation)).
Deployments should use `CRAWLX_DATABASE_URL_FILE` and `CRAWLX_API_DATABASE_URL_FILE`
with secret-manager files instead of environment values containing credentials.

* **The worker is required.** `scrape`, `crawl`, `batch/scrape`, `map` and the pages `extract` reads
  are crawlx runs; `crawlx worker` leases them from PostgreSQL (`crates/crawlx-cli/src/ops.rs`,
  `worker`). `crawlx serve` without `--database-url` keeps its runs in the process, where no worker
  can see them.
* **Enable `fc-` keys.** An `fc-` key is accepted only when `compat.firecrawlKeys` is on:
  `crawlx serve --firecrawl-keys` or the environment variable `CRAWLX_COMPAT_FIRECRAWL_KEYS=1`
  (`1`, `true`, `yes` or `on`; `CompatConfig::from_lookup`, `crates/crawlx-api/src/config.rs`). In a
  library the setting is `ApiConfig.compat.firecrawl_keys`. **Run**: test
  `serve_bootstraps_fc_keys_with_the_flag_or_the_environment` starts the `crawlx` binary with the flag
  and with the variable, calls `GET /compat/firecrawl/v2/team/credit-usage` with the key (200) and
  checks that an unknown `fc-` key and the same key on `/v1/crawls/{id}` get 401.
* **Without the switch** a bootstrap `fc-` key is refused at startup (`bootstrap_keys`,
  `crates/crawlx-api/src/lib.rs`): `API key for tenant "acme" must look like cx_live_<26 base32
  characters>` (same test, third phase: the process exits non-zero with that message).
* **Key shape.** `fc-` followed by 16 to 64 ASCII alphanumerics (`parse_firecrawl_key`,
  `crates/crawlx-api/src/auth.rs`). An `fc-` key authenticates only on `/compat/...` routes and
  never opens a native `/v1/...` route (`auth_layer`); a `cx_live_` key works on both.
* **LLM and search backends** (needed by `/extract`, `/search`, the `json`, `summary`,
  `question`, `highlights` and `query` formats) come from the Firecrawl self-host variables:
  `OPENAI_BASE_URL` (or `OLLAMA_BASE_URL`), `MODEL_NAME`, `OPENAI_API_KEY`, `SEARXNG_ENDPOINT`,
  `SEARXNG_ENGINES`, `SEARXNG_CATEGORIES`, `SEARCHAPI_API_KEY`, `SEARCHAPI_ENGINE`
  (`IntelConfig::from_lookup`, `crates/crawlx-api/src/config.rs`). `crawlx serve` reads all of them;
  `crawlx worker` reads the LLM ones for the scrape formats. Without a backend the endpoint answers 503.

## 2. Which base URL a client needs

The facade lives at `http://HOST:8080/compat/firecrawl`; Firecrawl clients append `/v2/...` to the base URL
they are given. Clients differ in how they join the two, and one of them throws the prefix away:

| client | how it builds the URL | base URL to configure | status |
|---|---|---|---|
| `firecrawl-py` 4.54.0 (v2) | `urljoin(api_url + "/", "/v2/scrape")` (`firecrawl/v2/utils/http_client.py:35-39`): a rooted path **replaces** the path of `api_url` | the origin of a proxy that maps `/v2/*` to `/compat/firecrawl/v2/*` (section 3) | **run**: with `api_url=http://HOST/compat/firecrawl` the request goes to `/v2/scrape` and the facade answers `404 route not found` (row `scrape@prefix_base_url`); through the rewrite every method works |
| npm `firecrawl` 4.51.0 | axios `baseURL` + `/v2/scrape` (`src/v2/utils/httpClient.ts:45-50`): the prefix is kept | `http://HOST:8080/compat/firecrawl` | **run** (`node.*` rows); a logging server also saw `POST /compat/firecrawl/v2/scrape` and `POST /compat/firecrawl/v2/map` |
| `firecrawl` CLI 1.26.24 | the npm SDK, plus ``${apiUrl}${path}`` for `status`/`parse`/`feedback` (`dist/utils/client.js`, `dist/commands/*.js`) | `--api-url http://HOST:8080/compat/firecrawl` (or `FIRECRAWL_API_URL`) | **run** (`cli.*` rows) |
| LangChain `FirecrawlLoader`, LlamaIndex `FireCrawlWebReader` | build `firecrawl.Firecrawl(api_key, api_url)` (Python SDK) | as `firecrawl-py` | **run** for LangChain (`langchain.*` rows); LlamaIndex **read** |
| Dify `FirecrawlApp` | ``base_url.rstrip('/') + '/' + 'v2/scrape'`` (`api/core/rag/extractor/firecrawl/firecrawl_app.py`, `_build_url`): the prefix is kept | `http://HOST:8080/compat/firecrawl` | **read** |
| n8n `@mendable/n8n-nodes-firecrawl` 2.2.0 | credential `Base URL` (default `https://api.firecrawl.dev/v2`) + relative `/scrape`, `/crawl`, ... (`dist/credentials/FirecrawlApi.credentials.js:11-16`, `dist/nodes/Firecrawl/Firecrawl.node.js:30`) | `http://HOST:8080/compat/firecrawl/v2` (the `/v2` is part of the value) | **read** |
| n8n `n8n-nodes-firecrawl` 0.3.0 (third party) | credential `Base URL` default `https://api.firecrawl.dev/v1` + `/scrape`, `/map`, `/crawl`, `/crawl/{id}`, `/crawl/webhook`, `/crawl/websocket` (`dist/credentials/FireCrawlApi.credentials.js:12-14`, `dist/nodes/FireCrawl/resources/default/*/index.js`) | `http://HOST:8080/compat/firecrawl/v2` | **read** |
| Flowise `FireCrawl` document loader | ``this.apiUrl + '/v1/scrape'`` and `/v1/crawl`, `/v1/extract`, `/v1/search`, `/v1/crawl/{id}`, `/v1/extract/{id}` (`packages/components/nodes/documentloaders/FireCrawl/FireCrawl.ts`, lines 192, 294, 406, 445, 481, 508) | none works: the paths are v1 | **read** |
| Zapier, Make, any HTTP client | whatever URL you type | `http://HOST:8080/compat/firecrawl/v2/<endpoint>` | **documented-only** |

### 3. The `/v2/*` rewrite `firecrawl-py` needs

Put a reverse proxy in front of the API that maps `/v2/...` to `/compat/firecrawl/v2/...`, and give
the Python SDK the proxy's origin as `api_url`. The facade writes absolute links into its answers (the
`url` of a started crawl, the `next` link of a paged status; `base_url`,
`crates/crawlx-api/src/scrape_service.rs`) from the `Host` and `X-Forwarded-Proto` headers and names the
`/compat/firecrawl/v2/...` path, which the SDK follows on the `api_url` origin
(`firecrawl/v2/utils/api_origin.py`): forward both headers, and let `/compat/firecrawl/` pass through too.

```nginx
# not executed here: the same mapping as the rewrite used by the test
location /v2/ {
    proxy_pass http://crawlx:8080/compat/firecrawl/v2/;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
location /compat/firecrawl/ {
    proxy_pass http://crawlx:8080;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

The **run** evidence uses an in-process rewrite (`rewrite_v2` in `crates/crawlx-cli/tests/support/sdk_rig.rs`)
instead of nginx. The facade does not serve `/v2/...` at the root by itself.

## 4. Endpoints the facade serves

Mounted by `crates/crawlx-api/src/routes/mod.rs` behind the key check, all under `/compat/firecrawl`:

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

### Python SDK `firecrawl-py` 4.54.0 (official) - run

`tests/sdk/test_sdk.py` drives the real package (installed with `pip install --target` from
`tests/sdk/requirements.txt`) against the in-process facade with a real worker, a fixture site, a mock LLM
and a SearXNG stand-in. Results (`crates/crawlx-cli/tests/sdk_python.rs`,
`official_python_sdk_runs_against_the_facade`):

| SDK call | endpoint | result |
|---|---|---|
| `scrape(url, formats=[markdown, links, html])` | `POST /v2/scrape` | pass: markdown, links, html, metadata |
| `scrape` with a `json` format + schema | `POST /v2/scrape` | pass: `json` is the mock LLM's answer |
| `start_crawl` + `get_crawl_status` polling | `POST /v2/crawl`, `GET /v2/crawl/{id}` | pass: `scraping` then `completed`, 3 pages with markdown |
| `crawl` (waiter) | same | pass |
| `get_crawl_errors`, `cancel_crawl` (finished crawl), `get_active_crawls` | `/v2/crawl/{id}/errors`, `DELETE /v2/crawl/{id}`, `/v2/crawl/active` | pass (`cancel_crawl` returns `False`: the facade answers 409) |
| `map` | `POST /v2/map` | pass |
| `search`, `search(scrape_options=...)` | `POST /v2/search` | pass: hits from SearXNG, with markdown when scraped |
| `extract`, `start_extract` + `get_extract_status` | `POST /v2/extract`, `GET /v2/extract/{id}` | pass: `completed`, data = the mock LLM's answer for the SDK's schema |
| `batch_scrape` | `POST /v2/batch/scrape`, `GET /v2/batch/scrape/{id}` | pass |
| `get_credit_usage`, `get_token_usage` | `/v2/team/credit-usage`, `/v2/team/token-usage` | pass (`-1`: no balance) |
| `scrape` with `api_url=http://HOST/compat/firecrawl` | `POST /v2/scrape` on the host | **expected fail, 404**: the SDK drops the prefix (section 2) |
| `.v1.scrape_url`, `.v1.crawl_url`, `.v1.check_crawl_status`, `.v1.map_url` (`FirecrawlApp` is the v2 client in 4.54.0; the v1 methods hang off `Firecrawl(...).v1`) | `/compat/firecrawl/v1/...` | **expected fail, 404 `route not found`**: `/v1` is not served by design |

### Node SDK `firecrawl` 4.51.0 and the `firecrawl` CLI 1.26.24 (official) - run

`tests/sdk/test_node.mjs` (installed with `npm ci` from `tests/sdk/package-lock.json`;
`official_node_sdk_and_cli_run_against_the_facade`) with `apiUrl = http://HOST/compat/firecrawl`, no rewrite:
`scrape`, `startCrawl` + `getCrawlStatus`, `crawl`, `map`, `search`, `extract`, `batchScrape` all pass; the CLI
passes `scrape --format markdown,links --json`, `map --json`, `search --json`, `crawl --wait` and
`credit-usage --json` with `--api-url`/`--api-key`. `firecrawl search` also asks for the hosted `alexandria`
source; the facade ignores it and says so in `warning`.

### Agent skills (`npx firecrawl-cli init`) - partly run

`init` installs skill files into the detected coding agents (README of `firecrawl-cli`, "Agent skills") and
logs in; it does not talk to the facade. The skills tell the agent to run the `firecrawl` CLI, which does:
tell the CLI about the facade with `firecrawl config --api-url http://HOST:8080/compat/firecrawl --api-key fc-...`
or `FIRECRAWL_API_URL` / `FIRECRAWL_API_KEY` (README, "Self-hosted / Local Development"; a custom API URL skips
the browser login). **Run**: the CLI commands above. **Not run**: `init` itself, which writes to `~/.agents`
and downloads the skill catalog from Firecrawl's service. CLI commands that need hosted features
(`interact`, `browser`, Alexandria tools) are not served.

### LangChain - run (loader), read (community loader)

`langchain-firecrawl` 0.1.0 `FirecrawlLoader` (alias `FireCrawlLoader`) builds `firecrawl.Firecrawl(api_key,
api_url)` (`langchain_firecrawl/_utilities.py`, `create_client`) and calls `scrape` (`POST /v2/scrape`),
`crawl` (`POST /v2/crawl`, `GET /v2/crawl/{id}`), `map` (`POST /v2/map`), `extract` (`POST /v2/extract`,
`GET /v2/extract/{id}`) and `search` (`POST /v2/search`) with `integration="langchain"`
(`langchain_firecrawl/document_loaders.py:215-255`). **Run**: rows `langchain.scrape`, `.crawl`, `.map`,
`.search`, `.extract` pass against the facade through the `/v2/*` rewrite, so the extra `integration` body
field is accepted. `langchain_community.document_loaders.FireCrawlLoader` (0.4.2,
`document_loaders/firecrawl.py:100-246`) makes the same SDK calls (`FirecrawlApp` is `Firecrawl`): **read**,
not executed. Use `api_url=<rewrite origin>` for both.

### LlamaIndex - read

`llama-index-readers-web` 0.7.0 `FireCrawlWebReader`
(`llama_index/readers/web/firecrawl_web/base.py:44-56,410,549,632,679,843`) builds `Firecrawl(api_key, api_url)`
and calls `scrape`, `crawl`, `map`, `search` and `extract` with `integration="llamaindex"`: the same endpoints and the
same URL rule as the Python SDK. Not executed (the package pulls `llama-index-core` and a long dependency tree).

### n8n - read

The official node `@mendable/n8n-nodes-firecrawl` 2.2.0 posts `{..., "integration": "n8n"}` to `/scrape`, `/crawl`,
`/map`, `/search`, `/extract`, `/batch/scrape`, `/agent` and reads `/crawl/{id}`, `/crawl/{id}/errors`,
`/crawl/active`, `/extract/{id}`, `/batch/scrape/{id}[/errors]`, `/agent/{id}`, `/team/credit-usage`,
`/team/queue-status`, `/team/token-usage[/historical]`, `/team/credit-usage/historical` (relative to the credential
`Base URL`; `dist/nodes/Firecrawl/api/*/index.js`). Set the credential `Base URL` to
`http://HOST:8080/compat/firecrawl/v2` and the API key to the `fc-` key; the facade serves all of those. Its
`interact` and `browser` operations (`/scrape/{id}/interact`, `/browser`) are not served. The credential test
calls `GET /team/credit-usage`. The community node `n8n-nodes-firecrawl` 0.3.0 is a v1 node: with its `Base URL`
set to the v2 base, `scrape`, `map`, `crawl` and the crawl status call routes the facade serves; `crawl/webhook`
and `crawl/websocket` are routes of that node's own API that the facade does not have; its request
bodies were not compared with the facade. **HTTP Request node fallback**: any n8n workflow can call the facade
with the *HTTP Request* node and an `Authorization: Bearer fc-...` header (section 6).

### Dify - read

`FirecrawlApp` (`api/core/rag/extractor/firecrawl/firecrawl_app.py`) posts `v2/scrape`, `v2/crawl`, `v2/map` and
`v2/search` (the last two with `"integration": "dify"`) and reads `v2/crawl/{id}` plus the `next` links of
paged results, all relative to the configured base URL. The facade serves all five. The credential check and the
data-source flow of current Dify releases live in plugins that were not read (`api/services/auth/firecrawl` no
longer exists on `main`), so whether Dify's "authorize" step accepts a self-hosted URL is unknown here.

### Flowise - read: does not work

The `FireCrawl` document loader calls `/v1/scrape`, `/v1/crawl`, `/v1/extract`, `/v1/search`, `/v1/crawl/{id}` and
`/v1/extract/{id}` (`packages/components/nodes/documentloaders/FireCrawl/FireCrawl.ts`). The facade serves none
of them (the same 404 as the `v1.*` rows above), so Flowise's Firecrawl loader cannot use crawlx. Flowise's other
loaders (Cheerio, Puppeteer, ...) do not involve Firecrawl.

### Zapier, Make, Lovable, CrewAI and other no-code tools - documented-only

Zapier's *Webhooks by Zapier* (custom request) and Make's *HTTP > Make a request* send plain HTTP: use
the URL, headers and bodies of section 6. Firecrawl's dedicated Zapier app, the Lovable connector and the CrewAI tools were
not examined (closed or not read); if they take only an API key and cannot be given a base URL, they cannot reach
a self-hosted facade at all.

## 6. Plain HTTP (curl, n8n HTTP Request, Zapier, Make)

```sh
BASE=http://HOST:8080/compat/firecrawl/v2
AUTH="Authorization: Bearer $FC_KEY"

# one page
curl -s $BASE/scrape -H "$AUTH" -H 'content-type: application/json' \
  -d '{"url":"https://example.com","formats":["markdown","links"]}'

# a crawl: start, then poll until "status" is "completed" (statuses: scraping, completed, failed, cancelled)
curl -s $BASE/crawl -H "$AUTH" -H 'content-type: application/json' \
  -d '{"url":"https://example.com","limit":10,"scrapeOptions":{"formats":["markdown"]}}'   # {"success":true,"id":"...","url":"..."}
curl -s $BASE/crawl/<id> -H "$AUTH"                                                         # follow "next" while it is not null
```

The request and response shapes are the ones the SDK rows above exercise.

## 7. Caveats

* **`firecrawl-py` and its dependents (LangChain, LlamaIndex) need the `/v2/*` rewrite** (section 3); without it
  they get 404 for every call. Everything that builds URLs by concatenation (npm SDK, CLI, Dify, n8n) takes the
  `/compat/firecrawl` prefix as is.
* **No `/v1`.** Clients and integrations that call `/v1/...` (Flowise, the v1 methods of both SDKs, the third-party n8n
  node's default base URL) fail with 404.
* **Hosted-only features** answer 404 or a warning: `interact`, browser sandbox, Alexandria, threat protection.
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

## 9. ProxyX pool gateway (optional egress upstream)

[ProxyX](https://github.com/noxred-research/proxyx) is a proxy platform whose pool gateway serves
rotating and static exit addresses by country, city and provider. crawlx can use it as the upstream
of its `basic` and `enhanced` proxy tiers. It is optional: without `[fetch.proxyx]` nothing changes,
and the plain proxy URLs keep working.

* **What crawlx adds on top of a plain proxy URL.** A typed username built and validated from a
  selector; one sticky exit identity per crawl (the `sid` is derived from the run id, and the two
  tiers of a run never share a lease); `CONNECT`-only transport, with plain `http://` targets
  tunneled too; the pool session id and exit IP of each tunnel recorded as connection evidence; typed
  refusal causes with a terminal versus retryable split; and asynchronous, bounded block feedback to
  the gateway's control API.
* **What does not change.** Every target and the gateway host still pass the egress policy,
  authorization records and robots still apply, and no action is replayed. A gateway on a private
  address must be listed in `egress.deployment_allowlist`.
* **Configure it.** `[fetch.proxyx]` with a gateway URL, an optional control URL, the org key as an
  `env://` or `file://` reference, and a selector table per tier. Flags, environment variables, the
  precedence rules, the failure mapping and the metrics are in
  [reference: proxy tiers and the ProxyX pool gateway](reference.md#deployment-proxy-tiers-and-the-proxyx-pool-gateway).
* **Not covered.** SOCKS5 ingress (it does not carry the session id, so block feedback would be
  impossible), the gateway's admin API, and block feedback from the browser plane.
