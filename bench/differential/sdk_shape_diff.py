#!/usr/bin/env python3
"""Diff two `sdk_shape_capture.py` captures (real upstream vs the crawlx facade) field by field.

    sdk_shape_diff.py --upstream FILE --crawlx FILE --out REPORT.md
                      [--meta KEY=VALUE ...] [--evidence-dir DIR]

For every captured call and every HTTP exchange of it, the RAW wire JSON of each side is flattened
to `JSON path -> types` (arrays collapse to `[]`, the keys of the elements of an array are
unioned, `null` is a type of its own so "sent as null" differs from "left out") and compared:
paths only upstream, paths only crawlx, paths whose types differ, paths that one side always
sends and the other only sometimes. Stable scalar leaves (status codes, `success`, `status`,
`total`, URLs with the two fixture origins made equal, ...) are also compared by value; volatile
ones (ids, timestamps, durations, the status URL) are compared by shape only. The typed SDK
results are compared as the SDK user sees them: a field that is set upstream and `null` on the
facade, or the other way round. Page bodies are scored too: for every page that both sides
returned (paired by origin-independent `metadata.sourceURL`), the two `markdown` bodies are
normalized (`markdown_metrics.py`) and compared by block-level F1 and by the ordered-subsequence
ratio of their blocks; the report lists both per page and as an exchange mean. Standard library only.

`--evidence-dir` additionally writes both captures there with every string over 2 KiB cut to its
head plus a byte count and every long array of objects reduced to the elements of distinct shape
(`_trimmed` lists what was cut), small enough to commit.
"""

import argparse
import json
import os
import re
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import markdown_metrics as mdm  # noqa: E402  (the sibling module; the path is set just above)

ORIGIN_TOKEN = "<ORIGIN>"
UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")

# scalar leaves compared by value
STABLE_LEAVES = {
    "success", "status", "statusCode", "code", "error", "total", "completed", "creditsUsed",
    "contentType", "title", "language", "description", "proxyUsed", "cacheState",
    "concurrencyLimited", "sourceURL", "url", "links", "robotsBlocked",
}
# scalar leaves that are never compared by value (ids, clocks, per-run URLs)
VOLATILE_LEAVES = {
    "id", "scrapeId", "timestamp", "createdAt", "completedAt", "expiresAt", "duration", "cachedAt",
    "concurrencyQueueDurationMs", "next", "webhookId",
}
VOLATILE_PATHS = {"$.url"}  # the status URL of a started crawl
# page bodies: only counted, since the converters differ by design
CONTENT_LEAVES = {"markdown", "html", "rawHtml"}

TRIM_STRING_BYTES = 2048
TRIM_ARRAY_ELEMENTS = 8

# what `sdk_shape_capture.py` runs per call (seed = the fixture entry page, limit 5 unless `full`)
CALL_DESCRIPTIONS = {
    "scrape": "`scrape(seed, formats=[markdown, links, rawHtml, html])`",
    "scrape_404": "`scrape(<fixture>/missing, ...)`: a page that answers 404",
    "scrape_500": "`scrape(<fixture>/error, ...)`: a page that answers 500",
    "scrape_robots_disallowed": "`scrape(<fixture>/private/, ...)`: a page robots.txt disallows",
    "map": "`map(seed)`",
    "start_crawl": "`start_crawl(seed, limit=5, scrape_options=ScrapeOptions(formats=[markdown, links]))`",
    "get_crawl_status_inflight": "the first `get_crawl_status(id)` that answered `scraping`",
    "get_crawl_status": "`get_crawl_status(id)` polled to `completed` (the terminal answer)",
    "get_crawl_errors": "`get_crawl_errors(id)` of the limit-5 crawl",
    "crawl": "`crawl(seed, limit=5, ..., poll_interval=1)`: the waiter (POST, then the last status poll)",
    "cancel_crawl": "`cancel_crawl(id)` of a fresh crawl with `limit=50`",
    "cancel_crawl_finished": "`cancel_crawl(id)` of the finished limit-5 crawl",
    "get_crawl_status_cancelled": "`get_crawl_status(id)` of that cancelled crawl",
    "start_crawl_full": "`start_crawl` with `limit=50`: the whole fixture (error pages, robots-blocked area, sitemap-only pages)",
    "get_crawl_status_inflight_full": "the first in-flight `get_crawl_status(id)` of the full crawl",
    "get_crawl_status_full": "`get_crawl_status(id)` of the full crawl, terminal",
    "get_crawl_errors_full": "`get_crawl_errors(id)` of the full crawl",
}


# --- flattening ---------------------------------------------------------------------------------


def type_name(value):
    """The JSON type of a value; integers and floats are one `number` (a JS and a Rust server
    print `1` and `1.0` differently and no client can tell)."""
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


class Shape:
    """A JSON document reduced to its paths."""

    def __init__(self, value=None):
        self.types = {}  # path -> set of type names
        self.keys = Counter()  # path of an object member -> objects that carry it
        self.objects = Counter()  # path -> objects at it
        self.parent = {}  # path of an object member -> path of its object
        self.values = {}  # path of a scalar -> every scalar seen there
        self.empty_arrays = set()
        if value is not None:
            self.walk(value, "$")

    def walk(self, value, path):
        kind = type_name(value)
        self.types.setdefault(path, set()).add(kind)
        if kind == "object":
            self.objects[path] += 1
            for key, child in value.items():
                child_path = f"{path}.{key}"
                self.keys[child_path] += 1
                self.parent[child_path] = path
                self.walk(child, child_path)
        elif kind == "array":
            if not value:
                self.empty_arrays.add(path)
            for child in value:
                self.walk(child, f"{path}[]")
        else:
            self.values.setdefault(path, []).append(value)

    def optional(self, path):
        """True when some object at the parent path lacks this member."""
        parent = self.parent.get(path)
        return parent is not None and self.keys[path] < self.objects[parent]

    def populated(self):
        """Paths that hold something other than `null`."""
        return {p for p, kinds in self.types.items() if kinds - {"null"}}


def shape_of(value):
    return Shape(value) if value is not None else Shape()


# --- comparing shapes -----------------------------------------------------------------------------


def leaf_name(path):
    return path.rsplit(".", 1)[-1].replace("[]", "")


def normalize(value, origins):
    if isinstance(value, str):
        for origin in origins:
            value = value.replace(origin, ORIGIN_TOKEN)
    return value


def render(value, limit=70):
    text = value if isinstance(value, str) else json.dumps(value)
    return text if len(text) <= limit else text[: limit - 1] + "\u2026"


def describe_polls(polls):
    """`{"sdk": n, "raw": m}` of a capture as text."""
    return f"{polls['sdk']} (SDK) / {polls['raw']} (raw)" if polls else "-"


def render_counter(counter, limit=6):
    items = sorted(counter.items(), key=lambda kv: kv[0])
    shown = [f"`{render(json.loads(k))}`" + (f" x{n}" if n > 1 else "") for k, n in items[:limit]]
    if len(items) > limit:
        shown.append(f"... {len(items) - limit} more")
    return ", ".join(shown) if shown else "-"


def kinds(shape, path):
    return "|".join(sorted(shape.types[path]))


def diff_shapes(up, cx):
    """The structural difference of two shapes."""
    up_paths, cx_paths = set(up.types), set(cx.types)
    both = up_paths & cx_paths
    return {
        "only_upstream": sorted(up_paths - cx_paths),
        "only_crawlx": sorted(cx_paths - up_paths),
        "type_diff": sorted(p for p in both if up.types[p] != cx.types[p]),
        "presence_diff": sorted(
            p for p in both if up.types[p] == cx.types[p] and up.optional(p) != cx.optional(p)
        ),
    }


def value_diffs(up, cx, up_origin, cx_origin):
    """Stable scalar leaves whose values differ, and page bodies that differ."""
    rows = []
    for path in sorted(set(up.values) & set(cx.values)):
        leaf = leaf_name(path)
        if path in VOLATILE_PATHS or leaf in VOLATILE_LEAVES:
            continue
        if leaf not in STABLE_LEAVES and leaf not in CONTENT_LEAVES:
            continue
        a = Counter(json.dumps(normalize(v, [up_origin])) for v in up.values[path])
        b = Counter(json.dumps(normalize(v, [cx_origin])) for v in cx.values[path])
        if a == b:
            continue
        if leaf in CONTENT_LEAVES:
            same = sum((a & b).values())
            rows.append((path, f"{sum(a.values())} bodies, {same} identical", f"{sum(b.values())} bodies"))
        else:
            rows.append((path, render_counter(a - b), render_counter(b - a)))
    return rows


def typed_diffs(up_record, cx_record):
    """What the SDK user sees: fields set on one side and `null` (or absent) on the other."""
    if up_record is None or cx_record is None:
        return None
    if not (up_record.get("ok") and cx_record.get("ok")):
        return {"failure": (describe_failure(up_record), describe_failure(cx_record))}
    up, cx = shape_of(up_record["result"]), shape_of(cx_record["result"])
    up_set, cx_set = up.populated(), cx.populated()
    return {
        "set_upstream_only": sorted(up_set - cx_set),
        "set_crawlx_only": sorted(cx_set - up_set),
    }


def describe_failure(record):
    if record.get("ok"):
        return "ok"
    return f"{record.get('error')} (HTTP {record.get('status_code')}): {record.get('message', '')[:120]}"


# --- exchanges ------------------------------------------------------------------------------------


def template(path):
    return UUID.sub("{id}", path)


def label(exchange):
    return f"{exchange['method']} {template(exchange['path'])}"


def pages_of(body):
    """Every document of a wire body that carries a markdown string: `{source URL: markdown}`.
    Finds `data` of a scrape and the `data[]` of a crawl status alike."""
    found = {}

    def walk(value):
        if isinstance(value, dict):
            meta = value.get("metadata")
            markdown = value.get("markdown")
            if isinstance(markdown, str) and isinstance(meta, dict) and isinstance(meta.get("sourceURL"), str):
                found.setdefault(meta["sourceURL"], markdown)
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(body)
    return found


def markdown_scores(up_body, cx_body, up_origin, cx_origin):
    """Block-level F1 and ordered-subsequence ratio of every page both wires carry.
    Pages are paired by their origin-independent URL key; unpaired pages are counted."""
    up_pages = {mdm.url_key(u, up_origin): (u, md) for u, md in pages_of(up_body).items()}
    cx_pages = {mdm.url_key(u, cx_origin): (u, md) for u, md in pages_of(cx_body).items()}
    rows = []
    for key in sorted(set(up_pages) & set(cx_pages)):
        (up_url, up_md), (cx_url, cx_md) = up_pages[key], cx_pages[key]
        metrics = mdm.page_metrics(up_md, up_url, up_origin, cx_md, cx_url, cx_origin)
        rows.append({"page": key, **metrics})
    ratios = [r["ordered_ratio"] for r in rows if r["ordered_ratio"] is not None]
    return {
        "pages": rows,
        "only_upstream": len(set(up_pages) - set(cx_pages)),
        "only_crawlx": len(set(cx_pages) - set(up_pages)),
        "mean_block_f1": sum(r["block_f1"] for r in rows) / len(rows) if rows else None,
        "mean_ordered_ratio": sum(ratios) / len(ratios) if ratios else None,
    }


def compare_exchange(up, cx, up_origin, cx_origin):
    """The difference of the i-th HTTP exchange of one call."""
    up_shape = shape_of(up["response"]) if up else Shape()
    cx_shape = shape_of(cx["response"]) if cx else Shape()
    result = {
        "label": label(up or cx),
        "status": (up or {}).get("status"),
        "status_crawlx": (cx or {}).get("status"),
        "missing": "upstream" if up is None else "crawlx" if cx is None else None,
        "shape": diff_shapes(up_shape, cx_shape),
        "up_shape": up_shape,
        "cx_shape": cx_shape,
        "values": value_diffs(up_shape, cx_shape, up_origin, cx_origin),
        "markdown": markdown_scores(
            (up or {}).get("response"), (cx or {}).get("response"), up_origin, cx_origin
        ),
        "headers_only_upstream": [],
        "headers_only_crawlx": [],
    }
    if up and cx:
        result["headers_only_upstream"] = sorted(set(up["headers"]) - set(cx["headers"]))
        result["headers_only_crawlx"] = sorted(set(cx["headers"]) - set(up["headers"]))
    return result


def compare_call(up_call, cx_call, up_origin, cx_origin):
    up_raw = (up_call or {}).get("raw") or []
    cx_raw = (cx_call or {}).get("raw") or []
    exchanges = []
    for i in range(max(len(up_raw), len(cx_raw))):
        exchanges.append(
            compare_exchange(
                up_raw[i] if i < len(up_raw) else None,
                cx_raw[i] if i < len(cx_raw) else None,
                up_origin,
                cx_origin,
            )
        )
    return {
        "exchanges": exchanges,
        "typed": typed_diffs((up_call or {}).get("sdk"), (cx_call or {}).get("sdk")),
        "present": (up_call is not None, cx_call is not None),
        "polls": ((up_call or {}).get("polls"), (cx_call or {}).get("polls")),
    }


def compare(upstream, crawlx):
    """The comparison of every captured call: the known ones in `CALL_DESCRIPTIONS` order, then the rest."""
    up_origin, cx_origin = upstream["site"], crawlx["site"]
    captured = set(upstream["calls"]) | set(crawlx["calls"])
    names = [n for n in CALL_DESCRIPTIONS if n in captured] + sorted(captured - set(CALL_DESCRIPTIONS))
    return {
        name: compare_call(upstream["calls"].get(name), crawlx["calls"].get(name), up_origin, cx_origin)
        for name in names
    }


# --- the report -------------------------------------------------------------------------------


NESTED_SHOWN = 8


def nest(paths):
    """Group `paths` under the top-most ancestor that is also in the set: [(top, [nested paths])]."""
    members = set(paths)
    groups = {}
    for path in sorted(members):
        top = next((path[:i] for i in range(2, len(path)) if path[i] in ".[" and path[:i] in members), None)
        if top is None:
            groups.setdefault(path, [])
        else:
            groups[top].append(path)
    return list(groups.items())


def describe_nested(top, nested):
    """The paths below `top` as suffixes: the first few by name, the rest counted."""
    if not nested:
        return "-"
    shown = ", ".join(f"`{n[len(top):]}`" for n in nested[:NESTED_SHOWN])
    more = f", ... +{len(nested) - NESTED_SHOWN}" if len(nested) > NESTED_SHOWN else ""
    return f"{len(nested)}: {shown}{more}"


def paths_table(shape, paths):
    lines = ["| path | type | presence | nested paths |", "|---|---|---|---|"]
    for top, nested in nest(paths):
        presence = "sometimes" if shape.optional(top) else "always"
        if top in shape.empty_arrays:
            presence += " (empty here)"
        lines.append(f"| `{top}` | {kinds(shape, top)} | {presence} | {describe_nested(top, nested)} |")
    return lines


def render_exchange(ex):
    lines = [f"#### {ex['label']}", ""]
    if ex["missing"]:
        lines += [f"Not observed on {ex['missing']}.", ""]
        return lines
    lines.append(f"HTTP status: upstream **{ex['status']}**, crawlx **{ex['status_crawlx']}**.")
    lines.append("")
    shape = ex["shape"]
    clean = not (
        shape["only_upstream"] or shape["only_crawlx"] or shape["type_diff"] or shape["presence_diff"]
        or ex["values"] or ex["headers_only_upstream"] or ex["headers_only_crawlx"]
    )
    if clean:
        return lines + ["No difference in paths, types, presence or stable values.", ""]
    if shape["only_upstream"]:
        lines += [f"Paths only in the upstream body ({len(shape['only_upstream'])}):", ""]
        lines += paths_table(ex["up_shape"], shape["only_upstream"]) + [""]
    if shape["only_crawlx"]:
        lines += [f"Paths only in the crawlx body ({len(shape['only_crawlx'])}):", ""]
        lines += paths_table(ex["cx_shape"], shape["only_crawlx"]) + [""]
    if shape["type_diff"]:
        lines += ["Paths in both with different types:", "", "| path | upstream | crawlx |", "|---|---|---|"]
        for p in shape["type_diff"]:
            lines.append(f"| `{p}` | {kinds(ex['up_shape'], p)} | {kinds(ex['cx_shape'], p)} |")
        lines.append("")
    if shape["presence_diff"]:
        lines += ["Paths in both that one side always sends and the other only sometimes:", "",
                  "| path | upstream | crawlx |", "|---|---|---|"]
        for p in shape["presence_diff"]:
            up_p = "sometimes" if ex["up_shape"].optional(p) else "always"
            cx_p = "sometimes" if ex["cx_shape"].optional(p) else "always"
            lines.append(f"| `{p}` | {up_p} | {cx_p} |")
        lines.append("")
    if ex["values"]:
        lines += ["Stable values that differ (fixture origins made equal; listed as the values only one side has):",
                  "", "| path | only upstream | only crawlx |", "|---|---|---|"]
        for path, a, b in ex["values"]:
            lines.append(f"| `{path}` | {a} | {b} |")
        lines.append("")
    if ex["headers_only_upstream"] or ex["headers_only_crawlx"]:
        up_h = ", ".join(f"`{h}`" for h in ex["headers_only_upstream"]) or "-"
        cx_h = ", ".join(f"`{h}`" for h in ex["headers_only_crawlx"]) or "-"
        lines += [f"Response headers only upstream: {up_h}. Only crawlx: {cx_h}.", ""]
    return lines


def fmt_score(value):
    return "n/a" if value is None else f"{value:.4f}"


def render_markdown(ex):
    """Markdown block-level F1 and ordered-subsequence ratio per paired page of one exchange."""
    md = ex.get("markdown")
    if ex["missing"] or md is None or not (md["pages"] or md["only_upstream"] or md["only_crawlx"]):
        return []
    lines = [
        f"Markdown (normalized, {len(md['pages'])} page(s) on both sides; "
        f"{md['only_upstream']} only upstream, {md['only_crawlx']} only crawlx): "
        f"mean block F1 {fmt_score(md['mean_block_f1'])}, "
        f"mean ordered-subsequence ratio {fmt_score(md['mean_ordered_ratio'])}.",
        "",
    ]
    if md["pages"]:
        lines += ["| page | blocks up / crawlx | block F1 | ordered-subsequence ratio |", "|---|---|---|---|"]
        for row in md["pages"]:
            lines.append(
                f"| `{row['page']}` | {row['blocks'][0]} / {row['blocks'][1]} "
                f"| {fmt_score(row['block_f1'])} | {fmt_score(row['ordered_ratio'])} |"
            )
        lines.append("")
    return lines


def markdown_summary(comparison):
    """One row per exchange that carries pages on either side."""
    lines = [
        "| call | exchange | pages on both | only upstream | only crawlx | mean block F1 | mean ordered-subsequence ratio |",
        "|---|---|---|---|---|---|---|",
    ]
    rows = 0
    for name, call in comparison.items():
        for ex in call["exchanges"]:
            md = ex.get("markdown")
            if ex["missing"] or md is None or not (md["pages"] or md["only_upstream"] or md["only_crawlx"]):
                continue
            rows += 1
            lines.append(
                f"| `{name}` | {ex['label']} | {len(md['pages'])} | {md['only_upstream']} | {md['only_crawlx']} "
                f"| {fmt_score(md['mean_block_f1'])} | {fmt_score(md['mean_ordered_ratio'])} |"
            )
    return lines if rows else ["No page bodies on both sides."]


def render_typed(typed):
    if typed is None:
        return []
    if "failure" in typed:
        up, cx = typed["failure"]
        return [f"SDK result: upstream {up}; crawlx {cx}.", ""]
    up_only, cx_only = typed["set_upstream_only"], typed["set_crawlx_only"]
    if not up_only and not cx_only:
        return ["SDK-visible fields (typed result): same set of populated fields.", ""]
    lines = ["SDK-visible fields (typed result, `null` counts as unset):", ""]
    if up_only:
        lines.append("* set upstream, `null` on crawlx: " + ", ".join(f"`{p}`" for p in up_only))
    if cx_only:
        lines.append("* set on crawlx, `null` upstream: " + ", ".join(f"`{p}`" for p in cx_only))
    return lines + [""]


def summary_table(comparison):
    lines = [
        "| call | exchange | HTTP up | HTTP crawlx | only upstream | only crawlx | type diffs | presence diffs | value diffs |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, call in comparison.items():
        for ex in call["exchanges"]:
            if ex["missing"]:
                lines.append(f"| `{name}` | {ex['label']} | not observed on {ex['missing']} | | | | | | |")
                continue
            s = ex["shape"]
            lines.append(
                f"| `{name}` | {ex['label']} | {ex['status']} | {ex['status_crawlx']} | {len(s['only_upstream'])} "
                f"| {len(s['only_crawlx'])} | {len(s['type_diff'])} | {len(s['presence_diff'])} | {len(ex['values'])} |"
            )
    return lines


def collect(comparison, key):
    """path -> sorted exchange labels, over every call, for one structural difference."""
    seen = {}
    for call in comparison.values():
        for ex in call["exchanges"]:
            if ex["missing"]:
                continue
            for path in ex["shape"][key]:
                seen.setdefault(path, set()).add(ex["label"])
    return seen


def render_report(upstream, crawlx, comparison, meta):
    lines = ["# SDK shape diff: real upstream vs the crawlx compat facade", ""]
    lines += [f"* SDK: `firecrawl-py {upstream.get('sdk_version')}` (crawlx side: `{crawlx.get('sdk_version')}`)"]
    lines += [
        f"* upstream: `{upstream['api']}`, fixture `{upstream['seed']}`",
        f"* crawlx: `{crawlx['api']}` (in-process facade behind the `/v2/*` rewrite), fixture `{crawlx['seed']}`",
    ]
    for key, value in meta:
        lines.append(f"* {key}: {value}")
    lines += [
        "",
        "Both sides ran the same `bench/differential/sdk_shape_capture.py` calls. The diff is of the raw "
        "wire JSON (the SDK drops fields it does not model); the typed SDK result is compared second. "
        "Integers and floats are one `number`; fixture origins are made equal before values are compared; "
        "ids, timestamps, durations and the status URL are compared by shape only.",
        "",
        "## Calls",
        "",
        "| call | what ran |",
        "|---|---|",
    ]
    lines += [f"| `{name}` | {CALL_DESCRIPTIONS.get(name, name)} |" for name in comparison]
    lines += ["", "## Summary", ""]
    lines += summary_table(comparison) + [""]
    lines += ["## Markdown metrics", "",
              "Per exchange, the pages both sides returned (paired by origin-independent `sourceURL`), "
              "normalized and scored: block-level F1 (multiset of exactly equal blocks) and the "
              "ordered-subsequence ratio (`2 * LCS / (|a| + |b|)` over the block order).", ""]
    lines += markdown_summary(comparison) + [""]
    for name, call in comparison.items():
        lines += [f"## `{name}`", ""]
        if not all(call["present"]):
            lines += [f"Captured by {'upstream' if call['present'][0] else 'crawlx'} only.", ""]
        polls = call["polls"]
        if polls[0] or polls[1]:
            lines += [f"Status polls until the answer: upstream {describe_polls(polls[0])}, crawlx {describe_polls(polls[1])}.", ""]
        for ex in call["exchanges"]:
            lines += render_exchange(ex)
            lines += render_markdown(ex)
        lines += render_typed(call["typed"])
    for title, key in (
        ("Every path only upstream", "only_upstream"),
        ("Every path only crawlx", "only_crawlx"),
        ("Every path with a different type", "type_diff"),
    ):
        seen = collect(comparison, key)
        lines += [f"## {title}", ""]
        if not seen:
            lines += ["None.", ""]
            continue
        lines += ["| path | nested paths | exchanges |", "|---|---|---|"]
        for top, nested in nest(seen):
            lines.append(f"| `{top}` | {describe_nested(top, nested)} | {'; '.join(sorted(seen[top]))} |")
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


# --- evidence copies ---------------------------------------------------------------------------


def trim_value(value, path, notes):
    """`value` with long strings cut and long arrays of objects reduced to distinct shapes."""
    if isinstance(value, str):
        raw = value.encode("utf-8")
        if len(raw) > TRIM_STRING_BYTES:
            head = raw[:TRIM_STRING_BYTES].decode("utf-8", "ignore")
            notes.append({"path": path, "bytes": len(raw)})
            return f"{head}\u2026[trimmed, {len(raw)} bytes in total]"
        return value
    if isinstance(value, dict):
        return {k: trim_value(v, f"{path}.{k}", notes) for k, v in value.items()}
    if isinstance(value, list):
        if len(value) > TRIM_ARRAY_ELEMENTS and all(isinstance(v, dict) for v in value):
            kept, signatures = [], set()
            for item in value:
                signature = tuple(sorted(Shape(item).types))
                if signature not in signatures:
                    signatures.add(signature)
                    kept.append(item)
                if len(kept) == TRIM_ARRAY_ELEMENTS:
                    break
            if len(kept) < 2:
                kept = value[:2]
            notes.append({"path": f"{path}[]", "kept": len(kept), "of": len(value)})
            value = kept
        return [trim_value(v, f"{path}[]", notes) for v in value]
    return value


def trim_capture(capture):
    notes = []
    trimmed = trim_value(capture, "$", notes)
    trimmed["_trimmed"] = notes
    return trimmed


# --- command line ---------------------------------------------------------------------------------


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--upstream", required=True)
    parser.add_argument("--crawlx", required=True)
    parser.add_argument("--out", required=True)
    parser.add_argument("--meta", action="append", default=[], metavar="KEY=VALUE")
    parser.add_argument("--evidence-dir")
    args = parser.parse_args(argv)

    upstream, crawlx = load(args.upstream), load(args.crawlx)
    meta = [tuple(item.split("=", 1)) if "=" in item else (item, "") for item in args.meta]
    report = render_report(upstream, crawlx, compare(upstream, crawlx), meta)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(report)
    if args.evidence_dir:
        os.makedirs(args.evidence_dir, exist_ok=True)
        for name, capture in (("upstream.json", upstream), ("crawlx.json", crawlx)):
            with open(os.path.join(args.evidence_dir, name), "w", encoding="utf-8") as fh:
                json.dump(trim_capture(capture), fh, indent=1, sort_keys=True)
                fh.write("\n")
    print(f"wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
