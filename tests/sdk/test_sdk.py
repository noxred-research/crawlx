#!/usr/bin/env python3
"""Drives the official upstream Python SDK (`firecrawl-py`) against a live crawlx facade.

Run by `crates/crawlx-cli/tests/sdk_python.rs`, which starts the facade, a worker, a fixture
site, a mock LLM and a mock search backend, installs `requirements.txt` with
`pip install --target` and sets:

    CRAWLX_SDK_FACADE_URL    http://127.0.0.1:P/compat   (the facade as mounted)
    CRAWLX_SDK_REWRITE_URL   http://127.0.0.1:Q            (a `/v2/*` -> `/compat/v2/*` rewrite)
    CRAWLX_SDK_API_KEY       fc-...
    CRAWLX_SDK_SITE          http://site.example.test:PORT         (the fixture site)

Every SDK method is one result row, printed as one JSON line on stdout:

    {"method": str, "ok": bool, "detail": str, ...extra}

`ok` is true when the SDK call returned and its result passed this script's own sanity check;
the Rust test asserts the extra fields (`markdown`, `links`, `urls`, ...) row by row. A failing
row carries `error` (the exception class) and `status` (the HTTP status the SDK saw, if any).
Nothing but rows goes to stdout; the SDK's warnings go to stderr.
"""

import json
import os
import sys
import time
import warnings

warnings.simplefilter("ignore")

FACADE = os.environ["CRAWLX_SDK_FACADE_URL"]
REWRITE = os.environ["CRAWLX_SDK_REWRITE_URL"]
KEY = os.environ["CRAWLX_SDK_API_KEY"]
SITE = os.environ["CRAWLX_SDK_SITE"].rstrip("/")

POLL_DEADLINE_S = 120


def emit(method, ok, detail, **extra):
    print(json.dumps({"method": method, "ok": ok, "detail": detail, **extra}, default=str), flush=True)


def status_of(exc):
    """The HTTP status a failed SDK call saw (the SDK's typed v2 error, v1 `requests.HTTPError`)."""
    code = getattr(exc, "status_code", None)
    if code is None:
        code = getattr(getattr(exc, "response", None), "status_code", None)
    return code


def row(method, fn):
    """Run `fn() -> (detail, extra)` as one result row; an exception is a failed row."""
    try:
        detail, extra = fn()
        emit(method, True, detail, **extra)
    except Exception as exc:  # noqa: BLE001 - every SDK failure is a result row
        emit(method, False, f"{type(exc).__name__}: {exc}", error=type(exc).__name__, status=status_of(exc))


def doc_facts(doc):
    meta = doc.metadata
    return {
        "markdown": doc.markdown,
        "links": doc.links,
        "html": doc.html,
        "raw_html": doc.raw_html,
        "json": doc.json,
        "title": getattr(meta, "title", None),
        "description": getattr(meta, "description", None),
        "source_url": getattr(meta, "source_url", None),
        "status_code": getattr(meta, "status_code", None),
    }


def main():
    from firecrawl import Firecrawl
    from firecrawl import __version__ as version
    from firecrawl.v2.types import JsonFormat, ScrapeOptions

    emit("sdk_version", True, f"firecrawl-py {version}", version=version)

    # --- the base URL the task names: `api_url` with a path -------------------------------------
    # The SDK joins the rooted path `/v2/scrape` onto `api_url` with urllib.parse.urljoin, which
    # replaces the `/compat` prefix: the request goes to `/v2/scrape` on the facade host.
    direct = Firecrawl(api_key=KEY, api_url=FACADE)
    row("scrape@prefix_base_url", lambda: ("scraped", doc_facts(direct.scrape(f"{SITE}/", formats=["markdown"]))))

    # --- v2 through the rewrite ------------------------------------------------------------------
    fc = Firecrawl(api_key=KEY, api_url=REWRITE)

    def scrape():
        doc = fc.scrape(f"{SITE}/", formats=["markdown", "links", "html"])
        return "scraped the home page", doc_facts(doc)

    row("scrape", scrape)

    def scrape_json():
        schema = {
            "type": "object",
            "properties": {"headline": {"type": "string"}, "answer": {"type": "integer"}},
            "required": ["headline"],
        }
        doc = fc.scrape(
            f"{SITE}/",
            formats=["markdown", JsonFormat(type="json", prompt="Extract the headline", schema=schema)],
        )
        return "scraped with a json format", doc_facts(doc)

    row("scrape_json", scrape_json)

    crawl_opts = ScrapeOptions(formats=["markdown"])
    crawl_id = {}

    def start_and_poll():
        started = fc.start_crawl(f"{SITE}/", limit=3, scrape_options=crawl_opts)
        crawl_id["id"] = started.id
        seen = []
        deadline = time.monotonic() + POLL_DEADLINE_S
        while True:
            job = fc.get_crawl_status(started.id)
            seen.append(job.status)
            if job.status in ("completed", "failed", "cancelled"):
                break
            if time.monotonic() > deadline:
                raise TimeoutError(f"crawl {started.id} still {job.status} after {POLL_DEADLINE_S}s")
            time.sleep(0.5)
        return (
            f"crawl {started.id} {job.status}",
            {
                "id": started.id,
                "url": started.url,
                "status": job.status,
                "statuses": seen,
                "total": job.total,
                "completed": job.completed,
                "credits_used": job.credits_used,
                "urls": sorted(d.metadata.source_url for d in job.data),
                "markdown": {d.metadata.source_url: d.markdown for d in job.data},
            },
        )

    row("start_crawl+get_crawl_status", start_and_poll)

    def crawl_waiter():
        job = fc.crawl(f"{SITE}/", limit=3, scrape_options=crawl_opts, poll_interval=1, timeout=POLL_DEADLINE_S)
        return (
            f"crawl {job.id} {job.status}",
            {
                "status": job.status,
                "total": job.total,
                "completed": job.completed,
                "urls": sorted(d.metadata.source_url for d in job.data),
                "markdown": {d.metadata.source_url: d.markdown for d in job.data},
            },
        )

    row("crawl", crawl_waiter)

    def crawl_errors():
        errors = fc.get_crawl_errors(crawl_id["id"])
        return "crawl errors", {"errors": [e.model_dump() for e in errors.errors], "robots_blocked": errors.robots_blocked}

    row("get_crawl_errors", crawl_errors)

    def cancel_finished():
        return "cancel_crawl on a finished crawl", {"cancelled": fc.cancel_crawl(crawl_id["id"])}

    row("cancel_crawl", cancel_finished)

    def active():
        res = fc.get_active_crawls()
        return "active crawls", {"count": len(res.crawls)}

    row("get_active_crawls", active)

    def map_site():
        res = fc.map(f"{SITE}/")
        return "mapped the site", {"urls": [link.url for link in res.links]}

    row("map", map_site)

    def search():
        res = fc.search("fixture", limit=5)
        return "searched", {"web": [{"url": h.url, "title": h.title, "description": h.description} for h in res.web or []]}

    row("search", search)

    def search_scrape():
        res = fc.search("fixture", limit=2, scrape_options=ScrapeOptions(formats=["markdown"]))
        out = []
        for h in res.web or []:
            out.append({"url": getattr(h, "url", None) or getattr(getattr(h, "metadata", None), "source_url", None),
                        "markdown": getattr(h, "markdown", None)})
        return "searched with scrapeOptions", {"web": out}

    row("search+scrape_options", search_scrape)

    extract_schema = {
        "type": "object",
        "properties": {"headline": {"type": "string"}, "answer": {"type": "integer"}},
        "required": ["headline"],
    }

    def extract():
        res = fc.extract(urls=[f"{SITE}/"], prompt="Extract the headline and the answer", schema=extract_schema,
                         poll_interval=1, timeout=POLL_DEADLINE_S)
        return f"extract {res.status}", {"status": res.status, "data": res.data, "tokens_used": res.tokens_used,
                                         "credits_used": res.credits_used}

    row("extract", extract)

    def start_extract_status():
        started = fc.start_extract(urls=[f"{SITE}/"], prompt="Extract the headline", schema=extract_schema)
        deadline = time.monotonic() + POLL_DEADLINE_S
        while True:
            res = fc.get_extract_status(started.id)
            if res.status in ("completed", "failed", "cancelled"):
                return f"extract {res.status}", {"status": res.status, "data": res.data}
            if time.monotonic() > deadline:
                raise TimeoutError(f"extract {started.id} still {res.status}")
            time.sleep(0.5)

    row("start_extract+get_extract_status", start_extract_status)

    def batch():
        job = fc.batch_scrape([f"{SITE}/a", f"{SITE}/b"], formats=["markdown"], poll_interval=1, wait_timeout=POLL_DEADLINE_S)
        return (
            f"batch {job.status}",
            {
                "status": job.status,
                "total": job.total,
                "completed": job.completed,
                "markdown": {d.metadata.source_url: d.markdown for d in job.data},
            },
        )

    row("batch_scrape", batch)

    def credit_usage():
        usage = fc.get_credit_usage()
        return "credit usage", {"remaining_credits": usage.remaining_credits}

    row("get_credit_usage", credit_usage)

    def token_usage():
        usage = fc.get_token_usage()
        return "token usage", {"remaining_tokens": usage.remaining_tokens}

    row("get_token_usage", token_usage)

    # --- Framework loader built on the SDK client ---------------------------------------------------
    # The loader builds the SDK client (`api_key`, `api_url`) and calls scrape / crawl / map /
    # extract / search with an `integration` marker in the request body, so it shares the SDK's URL rule (needs the
    # `/v2/*` rewrite) and sends one more body field than the plain SDK rows above.
    def loader_docs(mode, url=None, **kwargs):
        from langchain_firecrawl import FirecrawlLoader

        docs = FirecrawlLoader(url, api_key=KEY, api_url=REWRITE, mode=mode, **kwargs).load()
        return "loaded", {"docs": [{"page_content": d.page_content, "metadata": d.metadata} for d in docs]}

    row("loader.scrape", lambda: loader_docs("scrape", f"{SITE}/", params={"formats": ["markdown"]}))
    row("loader.crawl", lambda: loader_docs("crawl", f"{SITE}/", params={"limit": 3, "poll_interval": 1, "timeout": POLL_DEADLINE_S}))
    row("loader.map", lambda: loader_docs("map", f"{SITE}/"))
    row("loader.search", lambda: loader_docs("search", query="fixture", params={"limit": 5}))
    row(
        "loader.extract",
        lambda: loader_docs(
            "extract",
            f"{SITE}/",
            params={"prompt": "Extract the headline and the answer", "schema": extract_schema,
                    "poll_interval": 1, "timeout": POLL_DEADLINE_S},
        ),
    )

    # --- v1 names ----------------------------------------------------------------------------------
    # The v1 client name is an alias of the unified client in this release; the v1 methods
    # live on the client's `.v1` attribute. v1 URLs are `{api_url}/v1/...` with plain string
    # concatenation, so with the facade `api_url` they land on `/compat/v1/...`, which the
    # facade does not serve.
    from firecrawl import FirecrawlApp

    emit("v1_client_alias", FirecrawlApp is Firecrawl, f"v1 client name is the unified client: {FirecrawlApp is Firecrawl}")
    v1 = Firecrawl(api_key=KEY, api_url=FACADE).v1
    row("v1.scrape_url", lambda: ("scraped", {"result": str(v1.scrape_url(f"{SITE}/", formats=["markdown"]))}))
    row("v1.crawl_url", lambda: ("crawled", {"result": str(v1.crawl_url(f"{SITE}/", limit=2, poll_interval=1))}))
    row(
        "v1.check_crawl_status",
        lambda: ("status", {"result": str(v1.check_crawl_status("00000000-0000-0000-0000-000000000000"))}),
    )
    row("v1.map_url", lambda: ("mapped", {"result": str(v1.map_url(f"{SITE}/"))}))


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # noqa: BLE001 - report a broken harness instead of a bare traceback
        emit("harness", False, f"{type(exc).__name__}: {exc}", error=type(exc).__name__, status=None)
        sys.exit(1)
