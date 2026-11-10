#!/usr/bin/env python3
"""Crawl a gym fixture through a running upstream v2 API and export the result as data.

Used by `run.sh`. Upstream is a black box reached over HTTP only: the export is
the `GET /v2/crawl/{id}` body with every `next` page merged into `data[]` and the
`GET /v2/crawl/{id}/errors` body stored under `errors`, `rawHtml` reduced to `rawHtmlSha256` and
`rawHtmlBytes` (`bench/differential/README.md`, "Export
format"), plus a `crawlxSample` provenance block and, with `--gym-ledger`, the `accessLog` the
fixture server recorded. Standard library only.

No `x-idempotency-key` is sent: the pinned self-host without a database answers 409 "Idempotency
key already used" to a key that is not a UUID and crashes (process exit, whole stack stops) on a
UUID, because the idempotency store needs the Supabase client.

    upstream_export.py --api URL --origin URL --seed-path /s1/ --request '{"limit": 500}' \
        --family s1 --out FILE [--commit SHA]

`--request` is the upstream crawl request body minus `url`; the same options are applied to the
crawlx side by `crawlx-differential` (`--request`), so both systems receive the same request.
"""

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request

POLL_INTERVAL_S = 2
POLL_ROUNDS = 600


def call(method, url, body=None):
    data = json.dumps(body).encode() if body is not None else None
    headers = {"Content-Type": "application/json", "Authorization": "Bearer fc-self-host"}
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise SystemExit(f"{method} {url}: HTTP {error.code}: {error.read()[:500]!r}") from error


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--api", required=True, help="Upstream API root, e.g. http://127.0.0.1:3102")
    parser.add_argument("--origin", required=True, help="origin the containers reach the gym on")
    parser.add_argument("--seed-path", required=True, help="fixture entry path, e.g. /s1/")
    parser.add_argument("--request", default="{}", help="crawl request body (JSON) without `url`")
    parser.add_argument("--family", required=True)
    parser.add_argument("--commit", default=None, help="pinned upstream commit, recorded verbatim")
    parser.add_argument("--out", required=True)
    parser.add_argument(
        "--gym-ledger",
        default=None,
        help="URL of the gym's /__gym/ledger; its op rows are stored as `accessLog` (the gym must be fresh for this crawl)",
    )
    args = parser.parse_args()

    seed_url = args.origin.rstrip("/") + args.seed_path
    request = {
        "limit": 500,
        "maxConcurrency": 1,
        "scrapeOptions": {"formats": ["markdown", "links", "rawHtml"]},
    }
    request.update(json.loads(args.request))
    request["url"] = seed_url
    started = call("POST", f"{args.api}/v2/crawl", request)
    job = started["id"]
    status = {}
    for _ in range(POLL_ROUNDS):
        status = call("GET", f"{args.api}/v2/crawl/{job}")
        if status.get("status") in ("completed", "failed", "cancelled"):
            break
        time.sleep(POLL_INTERVAL_S)
    data = list(status.get("data") or [])
    pages = 1
    nxt = status.get("next")
    while nxt:
        page = call("GET", nxt)
        data.extend(page.get("data") or [])
        pages += 1
        nxt = page.get("next")
    # Source-change isolation without committing page bodies: the raw HTML is replaced by its
    # SHA-256 and length (the comparators read markdown, links and metadata only).
    for document in data:
        raw = document.pop("rawHtml", None)
        if raw is not None:
            document["rawHtmlSha256"] = hashlib.sha256(raw.encode()).hexdigest()
            document["rawHtmlBytes"] = len(raw.encode())
    status["data"] = data
    status["next"] = None
    status["errors"] = call("GET", f"{args.api}/v2/crawl/{job}/errors")
    status["crawlxSample"] = {
        "provenance": "black_box_run",
        "family": args.family,
        "job": job,
        "seedUrl": seed_url,
        "request": {k: v for k, v in request.items() if k != "url"},
        "upstreamCommit": args.commit,
        "statusPages": pages,
    }
    if args.gym_ledger:
        # what the gym server saw while upstream crawled (the fresh gym served this crawl only):
        # the requested-set observable
        ledger = call("GET", args.gym_ledger)
        status["accessLog"] = {
            "entries": [
                {k: row[k] for k in ("method", "path", "query", "host") if row.get(k) is not None}
                for row in ledger.get("entries", [])
                if row.get("kind") == "op"
            ]
        }
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(status, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(
        f"upstream[{args.family}]: {status.get('status')} total={status.get('total')} "
        f"completed={status.get('completed')} documents={len(data)}",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
