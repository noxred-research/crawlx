#!/usr/bin/env python3
"""Compare normalized source shingles without retaining or printing upstream source.

This is an engineering tripwire, not a legal determination of derivation. The
default threshold is 40; identifiers and literals lose their values,
comments disappear, and keywords/operators remain. Only distinct shingles count,
and shingles that are common idioms (present in more than `--max-doc-freq` files of
either tree) do not.
"""

import argparse
from collections import Counter, defaultdict
import hashlib
from pathlib import Path
import re
import sys

K = 12
DEFAULT_THRESHOLD = 40
# Idiom filter: a window in more than this many files of either tree is boilerplate. Calibrated
# on the pinned Firecrawl tree and unrelated crawlers.
DEFAULT_MAX_DOC_FREQ = 5
UPSTREAM_SUFFIXES = {".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
KEYWORDS = frozenset("""
    abstract as async await become bool box break case catch char class const
    continue crate debugger declare default delete do dyn else enum export extends
    extern false final finally fn for from function if impl import in instanceof
    interface let loop macro match mod move mut namespace never new null of override
    package private protected pub public readonly ref return self Self static struct
    super switch symbol this throw trait true try type typeof undefined union unsafe
    unsized use var virtual void where while with yield
""".split())
LITERAL_WORDS = {"true", "false", "null", "undefined"}
RAW_STRING = re.compile(r'(?:br|cr|r)(?P<hashes>#+)?"')
IDENTIFIER = re.compile(r"(?:[^\W\d]|[_$])[\w$]*", re.UNICODE)
NUMBER = re.compile(r"(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|0[oO][0-7_]+|(?:\d[\d_]*(?:\.\d[\d_]*)?|\.\d[\d_]*)(?:[eE][+-]?[\d_]+)?)(?:[a-zA-Z][a-zA-Z0-9_]*)?")
CHAR = re.compile(r"(?:b)?'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\\n])'")
OPERATORS = re.compile(r"===|!==|>>>=|>>>|<<=|>>=|\*\*=|&&=|\|\|=|\?\?=|\.\.\.|\.\.=|=>|->|::|==|!=|<=|>=|&&|\|\||\?\?|\?\.|\+=|-=|\*=|/=|%=|&=|\|=|\^=|<<|>>|\*\*|\+\+|--|\.\.")
JS_REGEXP = re.compile(r"/(?:\\.|[^/\\\r\n\[]|\[(?:\\.|[^\]\\\r\n])*\])+/[dgimsuvy]*")
REGEXP_PREFIXES = {None, "=", "(", "[", "{", ",", ":", ";", "!", "&&", "||",
                   "??", "?", "=>", "return", "throw", "case", "yield"}


def quoted_end(source, start, quote):
    """Skip escaped quotes, including JavaScript template literals."""
    index = start + 1
    while index < len(source):
        if source[index] == "\\":
            index += 2
        elif source[index] == quote:
            return index + 1
        else:
            index += 1
    raise ValueError("unterminated string literal")


def comment_end(source, start, nested):
    """Rust block comments nest; JavaScript block comments do not."""
    depth = 1
    index = start + 2
    while index < len(source):
        if source.startswith("*/", index):
            depth -= 1
            index += 2
            if not depth:
                return index
        elif nested and source.startswith("/*", index):
            depth += 1
            index += 2
        else:
            index += 1
    raise ValueError("unterminated block comment")


def tokenize(source, rust=False):
    """Yield lexical tokens, normalizing identifier and literal values."""
    index = 0
    previous = None
    while index < len(source):
        char = source[index]
        if char.isspace():
            index += 1
            continue
        if source.startswith("//", index) or (index == 0 and source.startswith("#!") and not rust):
            end = source.find("\n", index)
            index = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", index):
            index = comment_end(source, index, rust)
            continue
        if not rust and char == "/" and previous in REGEXP_PREFIXES:
            regexp = JS_REGEXP.match(source, index)
            if regexp:
                index = regexp.end()
                previous = "LIT"
                yield previous
                continue
        raw = RAW_STRING.match(source, index) if rust else None
        if raw:
            terminator = '"' + (raw["hashes"] or "")
            end = source.find(terminator, raw.end())
            if end < 0:
                raise ValueError("unterminated raw string literal")
            index = end + len(terminator)
            previous = "LIT"
            yield "LIT"
            continue
        literal = CHAR.match(source, index) if rust else None
        if literal:
            index = literal.end()
            previous = "LIT"
            yield "LIT"
            continue
        if rust and source.startswith(("b\"", "c\""), index):
            index += 1
            char = '"'
        if char == '"' or (not rust and char in "'`"):
            index = quoted_end(source, index, char)
            previous = "LIT"
            yield "LIT"
            continue
        number = NUMBER.match(source, index)
        if number:
            index = number.end()
            previous = "LIT"
            yield "LIT"
            continue
        identifier = IDENTIFIER.match(source, index)
        if identifier:
            word = identifier.group()
            previous = "LIT" if word in LITERAL_WORDS else word if word in KEYWORDS else "ID"
            yield previous
            index = identifier.end()
            continue
        operator = OPERATORS.match(source, index)
        if operator:
            previous = operator.group()
            yield previous
            index = operator.end()
        else:
            previous = char
            yield previous
            index += 1


def shingles(source, rust=False):
    """Return stable 128-bit hashes of distinct normalized 12-token windows."""
    tokens = list(tokenize(source, rust))
    return {
        hashlib.blake2b("\0".join(tokens[index:index + K]).encode(), digest_size=16).digest()
        for index in range(len(tokens) - K + 1)
    }


def source_files(root, suffixes):
    """Enumerate source files deterministically, excluding third-party installs."""
    if not root.is_dir():
        raise ValueError(f"source tree is not a directory: {root}")
    files = sorted(
        path for path in root.rglob("*")
        if path.suffix in suffixes and path.is_file() and not path.is_symlink()
        and not {".git", "node_modules"}.intersection(path.relative_to(root).parts)
    )
    if not files:
        raise ValueError(f"no matching source files under {root}")
    return files


def file_shingles(path):
    """Attach the file name to lexical and input errors."""
    try:
        return shingles(path.read_text(encoding="utf-8-sig"), rust=path.suffix == ".rs")
    except (OSError, UnicodeError, ValueError) as error:
        raise ValueError(f"{path}: {error}") from error


def scan(crawlx_tree, upstream_tree, max_doc_freq=DEFAULT_MAX_DOC_FREQ):
    """Use an inverted index, avoiding every-pair source-set intersections.

    A shingle that occurs in more than `max_doc_freq` files of either tree is an idiom (object
    literal field lists, argument chains, `ID . ID ( ID )` runs), not distinctive code, and is
    ignored; 0 disables the filter. Copied code is distinctive: its windows occur once per tree.
    """
    upstream_files = source_files(upstream_tree, UPSTREAM_SUFFIXES)
    crawlx_files = source_files(crawlx_tree, {".rs"})
    upstream_sets = [file_shingles(path) for path in upstream_files]
    crawlx_sets = [file_shingles(path) for path in crawlx_files]
    if max_doc_freq:
        upstream_df = Counter(hash_ for hashes in upstream_sets for hash_ in hashes)
        crawlx_df = Counter(hash_ for hashes in crawlx_sets for hash_ in hashes)
    index = defaultdict(list)
    for number, hashes in enumerate(upstream_sets):
        for shingle in hashes:
            if not max_doc_freq or upstream_df[shingle] <= max_doc_freq:
                index[shingle].append(number)
    matches = []
    for path, hashes in zip(crawlx_files, crawlx_sets):
        counts = Counter()
        for shingle in hashes:
            if not max_doc_freq or crawlx_df[shingle] <= max_doc_freq:
                counts.update(index.get(shingle, ()))
        matches.extend(
            (count, path.relative_to(crawlx_tree).as_posix(),
             upstream_files[number].relative_to(upstream_tree).as_posix())
            for number, count in counts.items()
        )
    matches.sort(key=lambda match: (-match[0], match[1], match[2]))
    return matches, len(crawlx_files), len(upstream_files)


def positive_integer(value):
    """Reject disabled or nonsensical gate settings."""
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError("must be a positive integer")
    return number


def non_negative_integer(value):
    """`--max-doc-freq 0` turns the idiom filter off; negative values are nonsense."""
    number = int(value)
    if number < 0:
        raise argparse.ArgumentTypeError("must be a non-negative integer")
    return number


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--crawlx-tree", type=Path, default=Path("crates"))
    parser.add_argument("--upstream-tree", type=Path, required=True)
    parser.add_argument("--threshold", type=positive_integer, default=DEFAULT_THRESHOLD)
    parser.add_argument("--top", type=positive_integer, default=20)
    parser.add_argument("--max-doc-freq", type=non_negative_integer, default=DEFAULT_MAX_DOC_FREQ,
                        help="ignore shingles present in more than N files of either tree (0: off)")
    args = parser.parse_args(argv)
    try:
        matches, local_count, upstream_count = scan(args.crawlx_tree, args.upstream_tree, args.max_doc_freq)
    except (OSError, ValueError) as error:
        print(f"shingle-scan: {error}", file=sys.stderr)
        return 2
    flagged = sum(count >= args.threshold for count, _, _ in matches)
    print(f"shingle-scan: k={K} threshold={args.threshold} max_doc_freq={args.max_doc_freq} "
          f"crawlx_files={local_count} upstream_files={upstream_count} flagged_pairs={flagged}")
    print("shared\tcrawlx file\tupstream file")
    for count, local, upstream in matches[:args.top]:
        print(f"{count}\t{local}\t{upstream}")
    if flagged:
        print("shingle-scan: FAIL: normalized source overlap requires provenance review", file=sys.stderr)
    else:
        print("shingle-scan: ok")
    return 1 if flagged else 0


if __name__ == "__main__":
    sys.exit(main())
