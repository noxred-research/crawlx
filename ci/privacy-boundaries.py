#!/usr/bin/env python3
"""Keep raw transport and secret-provider SDKs inside reviewed adapter files.

This source gate complements Clippy's resolved disallowed-types lint. It rejects
namespace imports, aliases, glob imports and fully qualified uses, regardless of
local lint allows. It does not claim to prove taint flow or replace Rust's type
checker. Run with Python's standard library; no Cargo metadata or network needed.
"""

from pathlib import Path
import re
import sys


RAW_NAMESPACES = frozenset({
    "reqwest", "wreq", "hyper", "hyper_util", "aws_sdk_kms", "aws_sdk_secretsmanager",
})
RAW_TYPES = {
    "reqwest": frozenset({"Client", "ClientBuilder", "Request", "RequestBuilder", "Response", "Error", "Result"}),
    "wreq": frozenset({"Client", "ClientBuilder", "Request", "RequestBuilder", "Response", "Error", "Result"}),
    "hyper": frozenset({"Request", "Response", "Error", "Incoming", "SendRequest"}),
    "hyper_util": frozenset({"Client"}),
    "aws_sdk_kms": frozenset({"Client"}),
    "aws_sdk_secretsmanager": frozenset({"Client"}),
}

# These exact files are envelopes, not permissions: every raw-typed item also
# needs an outer disallowed_types allow with a nonempty boundary reason.
ADAPTERS = {
    "crawlx-api/src/webhooks.rs": ({"reqwest"}, "pinned webhook delivery"),
    "crawlx-api/src/intel/metasearch.rs": ({"reqwest"}, "search HTTP adapter"),
    "crawlx-api/src/intel/search_http.rs": ({"reqwest"}, "bounded search response translation"),
    "crawlx-api/src/intel/serp.rs": ({"reqwest"}, "search HTTP adapter"),
    "crawlx-bench/src/decision_rig.rs": ({"reqwest"}, "explicit model fixture health probe"),
    "crawlx-bench/src/load.rs": ({"reqwest"}, "API load driver"),
    "crawlx-bench/src/crawl_bench/recorder.rs": ({"reqwest"}, "recording HTTP proxy"),
    "crawlx-bench/src/differential/wire/driver.rs": ({"reqwest"}, "wire comparison driver"),
    "crawlx-browser/src/captcha.rs": ({"reqwest"}, "bounded challenge service adapter"),
    "crawlx-browser/src/install.rs": ({"reqwest"}, "Chromium download adapter"),
    "crawlx-cli/src/authz.rs": ({"reqwest"}, "authorization API client"),
    "crawlx-cli/src/dataset_export_remote.rs": ({"reqwest"}, "authenticated dataset download"),
    "crawlx-cli/src/dataset_feed.rs": ({"reqwest"}, "authenticated dataset append client"),
    "crawlx-cli/src/dataset_import.rs": ({"reqwest"}, "authenticated dataset import client"),
    "crawlx-cli/src/healthcheck.rs": ({"reqwest"}, "operator health probe"),
    "crawlx-cli/src/update.rs": ({"reqwest"}, "release metadata download"),
    "crawlx-cli/src/mcp/api.rs": ({"reqwest"}, "bounded API protocol client"),
    "crawlx-fetch/src/acquisition_service.rs": ({"reqwest"}, "authorized HTML acquisition service adapter"),
    "crawlx-fetch/src/identity_profile.rs": ({"wreq"}, "explicit HTTP identity transport profile"),
    "crawlx-cli/src/mcp/tools.rs": ({"reqwest"}, "multipart MIME validation only"),
    "crawlx-fetch/src/client.rs": ({"reqwest", "wreq"}, "policy-pinned HTTP acquisition"),
    "crawlx-fetch/src/tls.rs": ({"reqwest", "wreq"}, "HTTP transport translation"),
    "crawlx-fetch/src/error.rs": ({"reqwest", "wreq"}, "typed transport failure translation"),
    "crawlx-fetch/src/egress.rs": ({"hyper", "hyper_util"}, "policy-pinned proxy transport"),
    "crawlx-fetch/src/resolver_https.rs": ({"reqwest"}, "pinned HTTPS resolver transport"),
    "crawlx-fetch/src/protocol/mod.rs": ({"reqwest"}, "typed service transport failures"),
    "crawlx-fetch/src/protocol/service.rs": ({"reqwest"}, "bounded protocol service adapter"),
    "crawlx-fetch/src/proxyx/signals.rs": ({"reqwest"}, "ProxyX signal transport"),
    "crawlx-model/src/decision_http.rs": ({"reqwest"}, "typed decision provider adapter"),
    "crawlx-model/src/planner_http.rs": ({"reqwest"}, "typed planner provider adapter"),
    "crawlx-model/src/llm/chat_completions.rs": ({"reqwest"}, "bounded completion provider adapter"),
    "crawlx-model/src/llm/embeddings.rs": ({"reqwest"}, "bounded embedding provider adapter"),
    "crawlx-storage/src/artifact_key_crypto.rs": ({"aws_sdk_kms"}, "artifact key-service adapter"),
    "crawlx-storage/src/checkpoint_crypto.rs": ({"aws_sdk_kms"}, "checkpoint key-service adapter"),
    "crawlx-worker/src/delivery.rs": ({"reqwest"}, "authorized feed delivery adapter"),
    "crawlx-worker/src/delivery/config.rs": ({"reqwest"}, "delivery header validation only"),
    "crawlx-worker/src/delivery/backends/http.rs": ({"reqwest"}, "bounded infrastructure sink HTTP adapter"),
    "crawlx-worker/src/secrets/mod.rs": ({"reqwest"}, "typed secret-provider failure translation"),
    "crawlx-worker/src/secrets/vault.rs": ({"reqwest"}, "secret resolution transport"),
    "crawlx-worker/src/secrets/cloud_sm.rs": ({"aws_sdk_secretsmanager"}, "managed secret resolution adapter"),
    "crawlx-worker/src/surface/traffic_export.rs": ({"reqwest"}, "explicit authenticated traffic export"),
}


HTTP_ADAPTERS = {
    "crawlx-api/src/util.rs": "HTTP ingress extraction and middleware",
    "crawlx-bench/src/crawl_bench/recorder.rs": "recording proxy ingress",
    "crawlx-fetch/src/egress.rs": "policy-pinned proxy messages",
}
RAW_LITERAL = re.compile(r'(?:br|cr|r)(#*)"')
CHAR_LITERAL = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'")
HTTP_RAW_USE = re.compile(
    r"\bhttp\s*::\s*(?:(?:request|response)\s*::\s*)?(?:Request|Response|Parts|Builder)\b"
    r"|\buse\b[^;]*\bhttp\s*::\s*\{[^;]*\b(?:Request|Response|request|response|self)\b"
    r"|\buse\b[^;]*\bhttp\s*(?:::)?\s*(?:as\b|\*)"
)


def code_only(source):
    """Mask comments and Rust string/character literals while preserving offsets."""
    out = list(source)
    index = 0
    while index < len(source):
        start = index
        if source.startswith("//", index):
            end = source.find("\n", index)
            index = len(source) if end < 0 else end
        elif source.startswith("/*", index):
            depth = 1
            index += 2
            while index < len(source) and depth:
                if source.startswith("/*", index):
                    depth += 1
                    index += 2
                elif source.startswith("*/", index):
                    depth -= 1
                    index += 2
                else:
                    index += 1
            if depth:
                raise ValueError("unterminated Rust block comment")
        else:
            raw = RAW_LITERAL.match(source, index)
            if raw:
                closing = '"' + raw.group(1)
                end = source.find(closing, raw.end())
                if end < 0:
                    raise ValueError("unterminated Rust raw string")
                index = end + len(closing)
            elif source[index] == '"':
                index += 1
                while index < len(source):
                    if source[index] == "\\":
                        index += 2
                    elif source[index] == '"':
                        index += 1
                        break
                    else:
                        index += 1
                else:
                    raise ValueError("unterminated Rust string")
            elif source[index] == "'":
                # Lifetimes are identifiers, not character literals.
                character = CHAR_LITERAL.match(source, index)
                if not character:
                    index += 1
                    continue
                index = character.end()
            else:
                index += 1
                continue
        for position in range(start, min(index, len(source))):
            if source[position] != "\n":
                out[position] = " "
    return "".join(out)


def item_end(code, start):
    """Locate an item's body or declaration terminator in masked Rust code."""
    item_start = start
    while attribute := re.compile(r"\s*#\s*\[").match(code, item_start):
        cursor = attribute.end()
        depth = 1
        while cursor < len(code) and depth:
            depth += (code[cursor] == "[") - (code[cursor] == "]")
            cursor += 1
        if depth:
            raise ValueError("item has unbalanced attributes")
        item_start = cursor
    field = re.compile(r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:r#)?[A-Za-z_][A-Za-z_0-9]*\s*:(?!:)").match(code, item_start)
    if field:
        cursor = field.end()
        stack = []
        closers = {"(": ")", "[": "]", "<": ">", "{": "}"}
        while cursor < len(code):
            character = code[cursor]
            if not stack and character in ",}":
                return cursor + (character == ",")
            if character in closers:
                stack.append(closers[character])
            elif stack and character == stack[-1] and not (character == ">" and code[cursor - 1] == "-"):
                stack.pop()
            cursor += 1
        raise ValueError("field has no terminator")
    cursor = start
    brackets = 0
    while cursor < len(code):
        if code[cursor] == "[":
            brackets += 1
        elif code[cursor] == "]":
            brackets -= 1
        elif not brackets and code[cursor] in "{;":
            break
        cursor += 1
    if cursor == len(code):
        raise ValueError("item has no terminator")
    if code[cursor] == ";":
        return cursor + 1
    depth = 1
    cursor += 1
    while cursor < len(code) and depth:
        depth += (code[cursor] == "{") - (code[cursor] == "}")
        cursor += 1
    if depth:
        raise ValueError("item has unbalanced braces")
    return cursor


def justified_ranges(source, code):
    """Only outer item-level allows with a nonempty reason grant exceptions."""
    ranges = []
    pattern = re.compile(r"#\s*\[\s*allow\s*\([^]]*\bclippy\s*::\s*disallowed_types\b[^]]*\]\s*")
    for match in pattern.finditer(code):
        reason_token = re.search(r"\breason\s*=", code[match.start():match.end()])
        if not reason_token:
            continue
        literal_start = match.start() + reason_token.end()
        reason = re.match(r'\s*"((?:\\.|[^"\\])*)"', source[literal_start:match.end()])
        if reason and reason.group(1).strip():
            ranges.append((match.start(), item_end(code, match.end())))
    return ranges


def test_ranges(code):
    """Find explicit test-only item boundaries without ignoring their contents."""
    return [
        (match.start(), item_end(code, match.end()))
        for match in re.finditer(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]", code)
    ]


def in_ranges(position, ranges):
    return any(start <= position < end for start, end in ranges)


def fixture_path(relative):
    parts = Path(relative).parts
    return ("tests" in parts or "benches" in parts or "testkit" in parts
            or Path(relative).stem.endswith("_tests") or Path(relative).stem == "tests")


def raw_sites(code):
    """Resolve raw namespace paths and import trees, not benign status/header types."""
    sites = set()
    for namespace, types in RAW_TYPES.items():
        path = re.compile(rf"\b{namespace}\s*::\s*((?:[A-Za-z_][A-Za-z_0-9]*\s*::\s*)*[A-Za-z_][A-Za-z_0-9]*)")
        for match in path.finditer(code):
            if types.intersection(re.findall(r"\b[A-Za-z_][A-Za-z_0-9]*\b", match.group(1))):
                sites.add((match.start(), namespace))
        for match in re.finditer(r"\b(?:use|extern\s+crate)\s+([^;]+);", code):
            imported = match.group(1)
            root = re.search(rf"\b{namespace}\b", imported)
            if root and (
                types.intersection(re.findall(r"\b[A-Za-z_][A-Za-z_0-9]*\b", imported))
                or re.search(r"\*|\bself\b|\bas\b", imported)
                or re.fullmatch(rf"\s*{namespace}\s*", imported)
            ):
                sites.add((match.start(1) + root.start(), namespace))
    for match in HTTP_RAW_USE.finditer(code):
        sites.add((match.start(), "http-message"))
    yield from sorted(sites)


def violations(relative, source):
    """Require both an approved adapter boundary and a justified concrete item."""
    namespaces, _ = ADAPTERS.get(relative, (set(), ""))
    code = code_only(source)
    approved = justified_ranges(source, code)
    tests = test_ranges(code)
    result = []
    for position, namespace in raw_sites(code):
        fixture = fixture_path(relative) or in_ranges(position, tests)
        boundary = (namespace in namespaces
                    or namespace == "http-message" and relative in HTTP_ADAPTERS
                    or fixture)
        if not boundary or not in_ranges(position, approved):
            line = code.count("\n", 0, position) + 1
            result.append(
                f"{relative}:{line}: raw {namespace} requires approved adapter "
                "and justified item-level disallowed_types allow"
            )
    # Raw re-exports remain forbidden even inside annotated adapters.
    for match in re.finditer(r"\bpub(?:\s*\([^)]*\))?\s+use\s+([^;]+);", code):
        if (any(re.search(rf"\b{namespace}\b", match.group(1)) for namespace in RAW_NAMESPACES)
                or HTTP_RAW_USE.search(match.group())):
            line = code.count("\n", 0, match.start()) + 1
            result.append(f"{relative}:{line}: raw adapter namespace re-export")
    return result


def sources(root):
    """Include every Rust source, integration test, benchmark and test fixture."""
    return sorted((root / "crates").glob("*/**/*.rs"))


def inventory(root):
    """Describe raw sites and their smallest enclosing item; do not run a gate."""
    rows = set()
    declaration = re.compile(
        r"(?m)^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:(?:async|unsafe|const)\s+)*"
        r"(?:fn|struct|enum|impl|mod|type|use)\b"
    )
    for path in sources(root):
        relative = path.relative_to(root / "crates").as_posix()
        code = code_only(path.read_text(encoding="utf-8"))
        items = []
        for match in declaration.finditer(code):
            if code.count("(", 0, match.start()) != code.count(")", 0, match.start()):
                continue
            try:
                end = item_end(code, match.end())
            except ValueError:
                continue
            header = re.split(r"[{;]", code[match.start():end], maxsplit=1)[0]
            header = " ".join(header.split())
            items.append((match.start(), end, header))
        for position, namespace in raw_sites(code):
            enclosing = [item for item in items if item[0] <= position < item[1]]
            item = min(enclosing, key=lambda value: value[1] - value[0]) if enclosing else None
            line = code.count("\n", 0, item[0] if item else position) + 1
            rows.add((relative, line, namespace, item[2] if item else "unscoped"))
    return sorted(rows)


def check(root):
    crates = root / "crates"
    if not crates.is_dir():
        return ["privacy-boundaries: crates directory missing"]
    paths = sources(root)
    if not paths:
        return ["privacy-boundaries: no Rust sources found"]
    problems = []
    for path in paths:
        relative = path.relative_to(crates).as_posix()
        try:
            problems.extend(violations(relative, path.read_text(encoding="utf-8")))
        except (OSError, UnicodeError, ValueError) as error:
            problems.append(f"{relative}: cannot inspect source ({type(error).__name__})")
    return problems


def main():
    arguments = sys.argv[1:]
    describe = "--inventory" in arguments
    arguments = [argument for argument in arguments if argument != "--inventory"]
    if len(arguments) > 1:
        print("usage: python3 ci/privacy-boundaries.py [--inventory] [repository-root]", file=sys.stderr)
        return 2
    root = Path(arguments[0]).resolve() if arguments else Path(__file__).resolve().parent.parent
    if describe:
        for relative, line, namespace, item in inventory(root):
            print(f"{relative}:{line}\t{namespace}\t{item}")
        return 0
    problems = check(root)
    for problem in problems:
        print(problem, file=sys.stderr)
    if problems:
        return 1
    paths = sources(root)
    fixtures = sum(fixture_path(path.relative_to(root / "crates").as_posix()) for path in paths)
    print(f"privacy-boundaries: ok ({len(paths)} Rust files scanned; {fixtures} fixture files included)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
