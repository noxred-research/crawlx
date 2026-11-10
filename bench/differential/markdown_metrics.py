#!/usr/bin/env python3
"""Markdown normalization metrics for the differential scorer (standard library only).

Both systems' markdown of the same page goes through the same normalization, is split into
blocks (one per heading, list item, table row, fenced code span and paragraph) and is scored:

* block-level F1: multiset precision and recall of exactly equal blocks (first side = reference);
* ordered-subsequence ratio: `2 * LCS / (|a| + |b|)` over the block lists, so a missing, an extra
  or a reordered block lowers it while the multiset F1 does not see a reorder.

The definitions and the normalization follow the Rust scorer in `crates/crawlx-bench/src/differential`
(`normalize.rs`) so the two scorers rank a page the same way. The normalization is: NFC, line
endings, trailing whitespace, entity decoding, setext to ATX headings, `*`/`+` to `-` list markers,
`__` to `**`, link targets resolved against the page URL with tracking parameters stripped and the
origin rebased, canonical table rows, blank-line runs collapsed.
"""

import unicodedata
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

ORIGIN = "{origin}"
PORT = "{port}"

TRACKING = frozenset({
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "fbclid", "gclid", "msclkid", "mc_cid", "mc_eid", "ref",
})

# Block lists whose length product exceeds this are not aligned (the LCS table is quadratic).
LCS_CELLS = 4_000_000

_ENTITIES = (("&nbsp;", " "), ("&lt;", "<"), ("&gt;", ">"), ("&quot;", '"'), ("&#39;", "'"),
             ("&apos;", "'"), ("&amp;", "&"))
_FENCES = ("```", "~~~")


# --- urls -----------------------------------------------------------------------------------------


def _default_port(scheme):
    return {"http": 80, "https": 443}.get(scheme)


def _port_of(parts):
    try:
        return parts.port or _default_port(parts.scheme)
    except ValueError:
        return None


def url_key(raw, origin):
    """An origin-independent key of `raw`: `{origin}/path?query` for the page's own origin,
    fragment dropped, tracking parameters dropped, trailing slash removed."""
    raw = raw.strip()
    parts = urlsplit(raw)
    base = urlsplit(origin)
    if not parts.scheme or not parts.hostname:
        return raw
    path = parts.path.rstrip("/") or "/"
    if (parts.scheme, parts.hostname, _port_of(parts)) == (base.scheme, base.hostname, _port_of(base)):
        key = f"{ORIGIN}{path}"
    elif base.port is not None and parts.scheme == base.scheme and _port_of(parts) == _port_of(base):
        key = f"{parts.scheme}://{parts.hostname}:{PORT}{path}"
    else:
        netloc = parts.hostname + (f":{parts.port}" if parts.port else "")
        key = f"{parts.scheme}://{netloc}{path}"
    pairs = sorted((k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in TRACKING)
    if pairs:
        key += "?" + urlencode(pairs)
    return key


def _normalize_target(target, page, origin):
    t = target.strip().strip("<>")
    t = t.split()[0] if t.split() else ""
    if t.startswith("#"):
        return ""
    return url_key(urljoin(page, t), origin)


def _normalize_links(line, page, origin):
    out, rest = [], line
    while True:
        start = rest.find("](")
        if start < 0:
            break
        out.append(rest[: start + 2])
        tail = rest[start + 2:]
        end = tail.find(")")
        if end < 0:
            out.append(tail)
            return _autolinks("".join(out), page, origin)
        out.append(_normalize_target(tail[:end], page, origin))
        out.append(")")
        rest = tail[end + 1:]
    out.append(rest)
    return _autolinks("".join(out), page, origin)


def _autolinks(line, page, origin):
    if "<http" not in line:
        return line
    out, rest = [], line
    while True:
        start = rest.find("<http")
        if start < 0:
            break
        out.append(rest[:start])
        tail = rest[start:]
        end = tail.find(">")
        if end < 0:
            out.append(tail)
            return "".join(out)
        key = _normalize_target(tail[1:end], page, origin)
        out.append(f"[{key}]({key})")
        rest = tail[end + 1:]
    out.append(rest)
    return "".join(out)


# --- normalization --------------------------------------------------------------------------------


def _decode_entities(text):
    if "&" not in text:
        return text
    for entity, plain in _ENTITIES:
        text = text.replace(entity, plain)
    return text


def _is_setext_underline(line, ch):
    t = line.strip()
    return len(t) >= 2 and set(t) == {ch}


def _normalize_list_marker(line):
    body = line.lstrip()
    indent = line[: len(line) - len(body)]
    if body[:2] in ("* ", "+ "):
        return f"{indent}-{body[1:]}"
    digits = len(body) - len(body.lstrip("0123456789"))
    if digits and body[digits:digits + 2] == ") ":
        return f"{indent}{body[:digits]}. {body[digits + 2:]}"
    return line


def _normalize_table_row(line):
    t = line.strip()
    if not t.startswith("|"):
        return line
    cells = []
    for cell in t.strip("|").split("|"):
        cell = cell.strip()
        cells.append("---" if cell and set(cell) <= {"-", ":"} else cell)
    return "| " + " | ".join(cells) + " |"


def normalize_markdown(markdown, page_url, origin):
    """The normalized form of `markdown` fetched from `page_url`; `origin` is the site origin
    (`scheme://host[:port]`) the page's links are rebased on."""
    text = unicodedata.normalize("NFC", markdown)
    text = _decode_entities(text.replace("\r\n", "\n").replace("\r", "\n"))
    raw = text.split("\n")
    if raw and raw[-1] == "":
        raw.pop()
    lines, in_code, i = [], False, 0
    while i < len(raw):
        line = raw[i].rstrip()
        if line.lstrip().startswith(_FENCES):
            in_code = not in_code
            lines.append(line.lstrip())
            i += 1
            continue
        if in_code:
            lines.append(line)
            i += 1
            continue
        if line.strip() and i + 1 < len(raw):
            nxt = raw[i + 1]
            prefix = None
            if _is_setext_underline(nxt, "="):
                prefix = "# "
            elif _is_setext_underline(nxt, "-") and not line.lstrip().startswith("|"):
                prefix = "## "
            if prefix:
                lines.append(prefix + line.strip())
                i += 2
                continue
        if line.lstrip().startswith("#"):
            t = line.lstrip()
            hashes = len(t) - len(t.lstrip("#"))
            body = t[hashes:].strip().rstrip("#").strip()
            line = f"{'#' * hashes} {body}"
        else:
            line = _normalize_table_row(_normalize_list_marker(line))
        line = _normalize_links(line.replace("__", "**"), page_url, origin)
        indent = line[: len(line) - len(line.lstrip())]
        lines.append(indent + " ".join(line.split()))
        i += 1
    out = []
    for line in lines:
        if not line.strip():
            if not out or out[-1] == "":
                continue
            out.append("")
        else:
            out.append(line)
    while out and out[-1] == "":
        out.pop()
    return "\n".join(out)


# --- blocks and scores ----------------------------------------------------------------------------


def markdown_blocks(normalized):
    """Split normalized markdown into blocks: one per heading, list item, table row, fenced code
    span and paragraph; whitespace inside a block (outside code) is collapsed."""
    blocks, paragraph, code = [], [], None

    def flush():
        if paragraph:
            blocks.append(" ".join(paragraph))
            paragraph.clear()

    for line in normalized.split("\n"):
        t = line.strip()
        fence = t.startswith(_FENCES)
        if code is not None:
            if fence:
                blocks.append("```" + "\n".join(code))
                code = None
            else:
                code.append(line)
            continue
        if fence:
            flush()
            code = []
            continue
        digits = len(t) - len(t.lstrip("0123456789"))
        item = t.startswith("- ") or (digits > 0 and t[digits:].startswith(". "))
        if not t:
            flush()
        elif t.startswith(("#", "|")) or item:
            flush()
            blocks.append(" ".join(t.split()))
        else:
            paragraph.append(" ".join(t.split()))
    if code is not None:
        blocks.append("```" + "\n".join(code))
    flush()
    return blocks


def block_f1(reference, candidate):
    """Block-level F1: multiset precision and recall of exactly equal blocks, `reference` first.
    Two empty lists score 1.0."""
    if not reference and not candidate:
        return 1.0
    remaining = {}
    for block in reference:
        remaining[block] = remaining.get(block, 0) + 1
    matched = 0
    for block in candidate:
        if remaining.get(block, 0) > 0:
            remaining[block] -= 1
            matched += 1
    if matched == 0:
        return 0.0
    precision, recall = matched / len(candidate), matched / len(reference)
    return 2.0 * precision * recall / (precision + recall)


def ordered_subsequence_ratio(a, b):
    """`2 * LCS / (|a| + |b|)` over two block lists; 1.0 only when they are equal, lower when
    blocks are missing, extra or reordered. Two empty lists score 1.0. Lists whose length product
    exceeds `LCS_CELLS` return `None` (the quadratic alignment is skipped)."""
    if not a and not b:
        return 1.0
    if len(a) * len(b) > LCS_CELLS:
        return None
    previous = [0] * (len(b) + 1)
    for x in reversed(a):
        current = [0] * (len(b) + 1)
        for j in range(len(b) - 1, -1, -1):
            current[j] = previous[j + 1] + 1 if x == b[j] else max(previous[j], current[j + 1])
        previous = current
    return 2.0 * previous[0] / (len(a) + len(b))


def page_metrics(reference_markdown, reference_url, reference_origin,
                 candidate_markdown, candidate_url, candidate_origin):
    """The two metrics of one page, each side normalized against its own page URL and origin so a
    fixture served from two hosts compares equal. Returns `{"blocks": (n_ref, n_cand),
    "block_f1": f, "ordered_ratio": r_or_None}`."""
    ref = markdown_blocks(normalize_markdown(reference_markdown, reference_url, reference_origin))
    cand = markdown_blocks(normalize_markdown(candidate_markdown, candidate_url, candidate_origin))
    return {
        "blocks": (len(ref), len(cand)),
        "block_f1": block_f1(ref, cand),
        "ordered_ratio": ordered_subsequence_ratio(ref, cand),
    }
