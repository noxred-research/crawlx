#!/usr/bin/env bash
# Gate: every job runs on a self-hosted runner, and no dependency-update bot is configured.
#
#   ci/lint-runners.sh [ROOT]     check ROOT (default: the repository)
#   ci/lint-runners.sh --self-test  prove the gate fails on synthetic bad copies
#
# Fails when a `runs-on` in .github/workflows has no `self-hosted` label (string, flow-list and
# block-list forms), when a `runs-on` is not a literal (an expression or a mapping cannot be
# checked statically), or when .github/dependabot.yml or .github/dependabot.yaml exists.
set -euo pipefail
cd "$(dirname "$0")/.."
exec python3 - "$@" <<'PY'
import os
import re
import sys
import tempfile

KEY = re.compile(r"^(\s*)runs-on\s*:\s*(.*?)\s*$")


def strip_comment(text):
    out, quote = [], None
    for ch in text:
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#":
            break
        out.append(ch)
    return "".join(out).strip()


def labels(value):
    value = value.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    elif value.startswith("[") or value.endswith("]"):
        return None
    items = [v.strip().strip("'\"") for v in value.split(",")]
    return items if all(items) else None


def check_workflow(path):
    problems = []
    lines = open(path, encoding="utf-8").read().splitlines()
    for number, raw in enumerate(lines, 1):
        found = KEY.match(raw)
        if not found:
            continue
        indent = len(found.group(1))
        inline = strip_comment(found.group(2))
        where = f"{path}:{number}"
        if inline:
            items = labels(inline)
        else:
            items, index = [], number
            while index < len(lines):
                nxt = lines[index]
                stripped = strip_comment(nxt)
                index += 1
                if not stripped:
                    continue
                lead = len(nxt) - len(nxt.lstrip())
                if lead < indent or (lead == indent and not stripped.startswith("-")):
                    break
                if not stripped.startswith("-"):
                    items = None  # a mapping (`group:`/`labels:`) is not a literal label list
                    break
                items.append(stripped[1:].strip().strip("'\""))
            if items is not None and not items:
                items = None
        if items is None:
            problems.append(f"{where}: runs-on is not a literal list of labels; spell the runner out")
        elif any("${{" in item for item in items):
            problems.append(f"{where}: runs-on uses an expression; spell the runner out")
        elif "self-hosted" not in items:
            problems.append(f"{where}: runs-on {items} lacks the self-hosted label")
    return problems


def check(root):
    problems = []
    github = os.path.join(root, ".github")
    for name in ("dependabot.yml", "dependabot.yaml"):
        if os.path.exists(os.path.join(github, name)):
            problems.append(f".github/{name} exists: dependency updates are made by hand, never by a hosted bot")
    workflows = os.path.join(github, "workflows")
    files = (
        sorted(
            os.path.join(workflows, f)
            for f in os.listdir(workflows)
            if f.endswith((".yml", ".yaml"))
        )
        if os.path.isdir(workflows)
        else []
    )
    if not files:
        problems.append(".github/workflows has no workflow to check")
    for path in files:
        problems += check_workflow(path)
    return problems


def workflow(runs_on_lines):
    return "name: t\non: push\njobs:\n  a:\n" + runs_on_lines + "    steps:\n      - run: true\n"


def self_test():
    good = {
        "flow list": "    runs-on: [self-hosted, noxred]\n",
        "string": "    runs-on: self-hosted\n",
        "quoted string": "    runs-on: 'self-hosted'  # comment\n",
        "block list": "    runs-on:\n      - self-hosted\n      - noxred\n",
    }
    bad = {
        "hosted string": "    runs-on: ubuntu-latest\n",
        "hosted flow list": "    runs-on: [ubuntu-latest]\n",
        "label but not self-hosted": "    runs-on: [noxred, linux]\n",
        "hosted block list": "    runs-on:\n      - ubuntu-24.04\n",
        "expression": "    runs-on: ${{ matrix.os }}\n",
        "group mapping": "    runs-on:\n      group: hosted\n",
        "empty": "    runs-on:\n",
    }
    failures = []
    for label, body in good.items():
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".github", "workflows"))
            with open(os.path.join(root, ".github", "workflows", "w.yml"), "w") as f:
                f.write(workflow(body))
            if check(root):
                failures.append(f"accepted form rejected: {label}: {check(root)}")
    for label, body in bad.items():
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".github", "workflows"))
            with open(os.path.join(root, ".github", "workflows", "w.yml"), "w") as f:
                f.write(workflow(body))
            if not check(root):
                failures.append(f"bad form accepted: {label}")
    for name in ("dependabot.yml", "dependabot.yaml"):
        with tempfile.TemporaryDirectory() as root:
            os.makedirs(os.path.join(root, ".github", "workflows"))
            with open(os.path.join(root, ".github", "workflows", "w.yml"), "w") as f:
                f.write(workflow(good["flow list"]))
            open(os.path.join(root, ".github", name), "w").close()
            if not any(name in p for p in check(root)):
                failures.append(f"{name} accepted")
    with tempfile.TemporaryDirectory() as root:
        if not check(root):
            failures.append("a tree without workflows accepted")
    if failures:
        print("lint-runners self-test FAILED:\n  " + "\n  ".join(failures))
        return 1
    print(f"lint-runners self-test: ok ({len(good)} accepted forms, {len(bad) + 3} refused cases)")
    return 0


if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
    sys.exit(self_test())
root = sys.argv[1] if len(sys.argv) > 1 else "."
problems = check(root)
for problem in problems:
    print(f"lint-runners: {problem}")
if problems:
    sys.exit(1)
print("lint-runners: ok")
PY
