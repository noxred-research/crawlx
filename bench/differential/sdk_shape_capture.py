#!/usr/bin/env python3
"""Capture what the official `firecrawl-py` SDK sees from one Firecrawl v2 API.

Run once against the real self-hosted Firecrawl and once against the crawlx compat facade, with the
same calls on the same gym fixture; `sdk_shape_diff.py` diffs the two captures field by field.

    sdk_shape_capture.py --api URL --site ORIGIN --out FILE --label LABEL [--key KEY] [--fixture s1]

`--api` is the value handed to the SDK as `api_url`. firecrawl-py joins the rooted `/v2/...` paths
onto it, so the crawlx facade needs a root that serves `/v2/*` (the rig's `rewritten_root`, which
rewrites to `/compat/firecrawl/v2/*`). `--site` is the origin the API reaches the fixture at
(`http://gym.test:4100` for the self-host, `http://site.example.test:4100` for the rig); the seed is
`ORIGIN/<fixture>/`.

Each call is recorded twice:

* `sdk`: the typed result the SDK returns, as `model_dump(mode="json")`, so a field the server left
  out is `null` here (the SDK drops unknown wire fields);
* `sdk_wire` / `raw`: the HTTP exchange of the SDK itself (tapped from `requests`) and the same
  request replayed with plain `urllib` (method, path, body, status, header names and JSON body).
  The raw wire is the ground truth for "present upstream"; no idempotency key is ever sent.

A call that raises is data, not an error: the capture keeps `error` and the HTTP status the SDK saw.
Standard library plus `firecrawl-py` (`PYTHONPATH` of a `pip install --target`).
"""

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
import warnings
from urllib.parse import urlparse

warnings.simplefilter("ignore")

TERMINAL = ("completed", "failed", "cancelled")
DROPPED_HEADERS = {"date", "content-length", "connection", "keep-alive", "transfer-encoding"}
POLL_DEADLINE_S = 240
POLL_INTERVAL_S = 0.5
FULL_LIMIT = 50
SMALL_LIMIT = 5
# the call order of the report; `sdk_shape_diff.py` reads the keys it finds
SCRAPE_FORMATS = ["markdown", "links", "rawHtml", "html"]
CRAWL_FORMATS = ["markdown", "links"]


def typed(value):
    """A JSON-serializable view of an SDK result, every field kept (including `None`)."""
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    if isinstance(value, (bool, int, float, str, list, dict)) or value is None:
        return value
    return repr(value)


def parse_body(raw):
    """The JSON body of a response; anything else is kept as a short text."""
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return {"_text": raw[:2048].decode("utf-8", "replace")}


def path_of(url):
    parts = urlparse(url)
    return parts.path + (f"?{parts.query}" if parts.query else "")


def exchange(method, path, request, status, headers, raw):
    return {
        "method": method,
        "path": path,
        "request": request,
        "status": status,
        "headers": sorted(k.lower() for k in headers if k.lower() not in DROPPED_HEADERS),
        "response": parse_body(raw),
    }


# --- the SDK tap -------------------------------------------------------------------------------

TAP = []


def install_tap():
    """Record every HTTP exchange firecrawl-py makes through `requests.post/get/delete`."""
    import requests

    def wrap(verb):
        original = getattr(requests, verb)

        def tapped(url, *args, **kwargs):
            response = original(url, *args, **kwargs)
            TAP.append(
                exchange(verb.upper(), path_of(url), kwargs.get("json"), response.status_code,
                         response.headers, response.content)
            )
            return response

        setattr(requests, verb, tapped)

    for verb in ("post", "get", "delete"):
        wrap(verb)


def sdk_call(fn):
    """Run one SDK call; its typed result (or the failure) and the exchanges it made."""
    del TAP[:]
    try:
        record = {"ok": True, "result": typed(fn())}
    except Exception as exc:  # noqa: BLE001 - a failing call is a result of the capture
        record = {
            "ok": False,
            "error": type(exc).__name__,
            "message": str(exc)[:500],
            "status_code": getattr(exc, "status_code", None),
        }
    return record, list(TAP)


# --- the raw wire ---------------------------------------------------------------------------------


class Raw:
    """Plain HTTP against the API root, the way a client without the SDK talks to it."""

    def __init__(self, api, key):
        self.api = api.rstrip("/")
        self.key = key

    def request(self, method, path, body=None):
        data = None if body is None else json.dumps(body).encode()
        headers = {"Authorization": f"Bearer {self.key}", "Accept": "application/json"}
        if data is not None:
            headers["Content-Type"] = "application/json"
        req = urllib.request.Request(self.api + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=180) as response:
                status, hdrs, raw = response.status, response.headers, response.read()
        except urllib.error.HTTPError as error:
            status, hdrs, raw = error.code, error.headers, error.read()
        return exchange(method, path, body, status, hdrs, raw)

    def replay(self, wire):
        """The exchanges of an SDK call, sent again with plain HTTP."""
        return [self.request(w["method"], w["path"], w["request"]) for w in wire]


def crawl_id_of(wire):
    body = wire[0]["response"] if wire and isinstance(wire[0]["response"], dict) else {}
    return body.get("id")


class Watch:
    """Polls one crawl status to a terminal answer and keeps the first in-flight one."""

    def __init__(self, poll=None):
        self.poll = poll  # () -> (status or None, payload); None status ends the watch
        self.inflight = None
        self.last = None
        self.polls = 0
        self.done = poll is None

    def tick(self):
        if self.done:
            return
        status, payload = self.poll()
        self.polls += 1
        self.last = payload
        if status in TERMINAL or status is None:
            self.done = True
        elif self.inflight is None:
            self.inflight = payload


def watch_all(*watches):
    """Tick the watches in turn (SDK and raw see the same moment of the crawl) until all are done."""
    deadline = time.monotonic() + POLL_DEADLINE_S
    while time.monotonic() < deadline:
        for w in watches:
            w.tick()
        if all(w.done for w in watches):
            return
        time.sleep(POLL_INTERVAL_S)


def sdk_watch(fc, crawl_id):
    def poll():
        record, wire = sdk_call(lambda: fc.get_crawl_status(crawl_id))
        result = record.get("result")
        status = result.get("status") if record["ok"] and isinstance(result, dict) else None
        return status, (record, wire[:1])

    return Watch(poll) if crawl_id else Watch()


def raw_watch(raw, crawl_id):
    def poll():
        ex = raw.request("GET", f"/v2/crawl/{crawl_id}")
        body = ex["response"] if isinstance(ex["response"], dict) else {}
        return body.get("status"), ex

    return Watch(poll) if crawl_id else Watch()


def entry(sdk, sdk_wire, raw, **extra):
    return {"sdk": sdk, "sdk_wire": sdk_wire, "raw": raw, **extra}


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--api", required=True, help="api_url handed to the SDK (serves /v2/*)")
    parser.add_argument("--site", required=True, help="origin the API reaches the fixture at")
    parser.add_argument("--out", required=True)
    parser.add_argument("--label", required=True)
    parser.add_argument("--key", default="fc-self-host")
    parser.add_argument("--fixture", default="s1")
    args = parser.parse_args()

    from firecrawl import Firecrawl
    from firecrawl import __version__ as sdk_version
    from firecrawl.v2.types import ScrapeOptions

    install_tap()
    fc = Firecrawl(api_key=args.key, api_url=args.api)
    raw = Raw(args.api, args.key)
    site = args.site.rstrip("/")
    seed = f"{site}/{args.fixture}/"
    calls = {}

    def scrape_like(name, url):
        record, wire = sdk_call(lambda: fc.scrape(url, formats=SCRAPE_FORMATS))
        calls[name] = entry(record, wire, raw.replay(wire), url_path=path_of(url))

    scrape_like("scrape", seed)
    scrape_like("scrape_404", f"{site}/{args.fixture}/missing")
    scrape_like("scrape_500", f"{site}/{args.fixture}/error")
    scrape_like("scrape_robots_disallowed", f"{site}/{args.fixture}/private/")

    record, wire = sdk_call(lambda: fc.map(seed))
    calls["map"] = entry(record, wire, raw.replay(wire), url_path=path_of(seed))

    def crawl_family(suffix, limit):
        """start_crawl, get_crawl_status (in flight and terminal), get_crawl_errors; SDK and raw."""
        options = ScrapeOptions(formats=CRAWL_FORMATS)
        started, start_wire = sdk_call(lambda: fc.start_crawl(seed, limit=limit, scrape_options=options))
        raw_start = raw.replay(start_wire)
        calls[f"start_crawl{suffix}"] = entry(started, start_wire, raw_start, limit=limit)
        sdk_id = started["result"]["id"] if started["ok"] else None
        raw_id = crawl_id_of(raw_start)
        sdk_w, raw_w = sdk_watch(fc, sdk_id), raw_watch(raw, raw_id)
        watch_all(sdk_w, raw_w)
        polls = {"sdk": sdk_w.polls, "raw": raw_w.polls}
        if sdk_w.last:
            record, wire = sdk_w.last
            calls[f"get_crawl_status{suffix}"] = entry(record, wire, [raw_w.last] if raw_w.last else [], polls=polls)
        if sdk_w.inflight or raw_w.inflight:
            record, wire = sdk_w.inflight or (None, [])
            calls[f"get_crawl_status_inflight{suffix}"] = entry(
                record, wire, [raw_w.inflight] if raw_w.inflight else [], polls=polls
            )
        if sdk_id:
            errors, errors_wire = sdk_call(lambda: fc.get_crawl_errors(sdk_id))
            raw_errors = [raw.request("GET", f"/v2/crawl/{raw_id}/errors")] if raw_id else []
            calls[f"get_crawl_errors{suffix}"] = entry(errors, errors_wire, raw_errors)
        return sdk_id, raw_id

    main_sdk_id, main_raw_id = crawl_family("", SMALL_LIMIT)

    # the waiter: start_crawl plus polling to completion, in one SDK call
    options = ScrapeOptions(formats=CRAWL_FORMATS)
    waiter, waiter_wire = sdk_call(
        lambda: fc.crawl(seed, limit=SMALL_LIMIT, scrape_options=options, poll_interval=1, timeout=POLL_DEADLINE_S)
    )
    waiter_start = raw.replay(waiter_wire[:1])
    waiter_id = crawl_id_of(waiter_start)
    waiter_raw = raw_watch(raw, waiter_id)
    watch_all(waiter_raw)
    calls["crawl"] = entry(
        waiter,
        waiter_wire[:1] + waiter_wire[-1:],
        waiter_start + ([waiter_raw.last] if waiter_raw.last else []),
        polls={"sdk": len(waiter_wire) - 1, "raw": waiter_raw.polls},
    )

    # cancel a fresh crawl, then watch it settle; and cancel a finished one
    cancel_options = ScrapeOptions(formats=CRAWL_FORMATS)
    cancel_started, cancel_start_wire = sdk_call(
        lambda: fc.start_crawl(seed, limit=FULL_LIMIT, scrape_options=cancel_options)
    )
    raw_cancel_start = raw.replay(cancel_start_wire)
    cancel_sdk_id = cancel_started["result"]["id"] if cancel_started["ok"] else None
    cancel_raw_id = crawl_id_of(raw_cancel_start)
    if cancel_sdk_id:
        cancelled, cancel_wire = sdk_call(lambda: fc.cancel_crawl(cancel_sdk_id))
        raw_cancelled = [raw.request("DELETE", f"/v2/crawl/{cancel_raw_id}")] if cancel_raw_id else []
        calls["cancel_crawl"] = entry(cancelled, cancel_wire, raw_cancelled)
        after_sdk, after_raw = sdk_watch(fc, cancel_sdk_id), raw_watch(raw, cancel_raw_id)
        watch_all(after_sdk, after_raw)
        record, wire = after_sdk.last
        calls["get_crawl_status_cancelled"] = entry(record, wire, [after_raw.last] if after_raw.last else [])
    if main_sdk_id:
        finished, finished_wire = sdk_call(lambda: fc.cancel_crawl(main_sdk_id))
        raw_finished = [raw.request("DELETE", f"/v2/crawl/{main_raw_id}")] if main_raw_id else []
        calls["cancel_crawl_finished"] = entry(finished, finished_wire, raw_finished)

    # the whole fixture: the 404 and 500 pages, the robots-blocked area and the sitemap-only pages
    crawl_family("_full", FULL_LIMIT)

    capture = {
        "label": args.label,
        "api": args.api,
        "site": site,
        "seed": seed,
        "fixture": args.fixture,
        "sdk_version": sdk_version,
        "calls": calls,
    }
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(capture, fh, indent=1, sort_keys=True)
        fh.write("\n")
    print(f"{args.label}: {len(calls)} calls captured to {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
