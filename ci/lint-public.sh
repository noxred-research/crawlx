#!/usr/bin/env bash
# Public-tree hygiene gate: fails when a tracked file (or an untracked, non-ignored file in a
# local checkout) is an internal-only path or contains a reference that must not be public:
# internal design-document citations, host-specific paths and the privileged fork-PR trigger.
#
# Additional private rules (names that must not appear in this repository, so they cannot be
# listed here) come from the PUBLIC_LINT_RULES environment variable, one rule per line:
#   content<TAB>NAME<TAB>PCRE[<TAB>ERE line filter]   a matching line is a violation
#   path<TAB>NAME<TAB>PATH                            a file at or below PATH must not exist
#   file<TAB>NAME<TAB>BASENAME                        a file with this name must not exist
# CI provides them from a repository secret and sets PUBLIC_LINT_REQUIRE_PRIVATE=1, which makes
# a missing rule set an error. Local runs without the variable check the built-in rules only.
#
# Vendored code, the public-suffix list, lock files and this script are not scanned.
#
# Usage: ci/lint-public.sh        (run from anywhere inside the repository)
# Output: one `file:line: [rule] text` line per hit, sorted; a per-rule summary; exit 1 on any hit.
set -euo pipefail
export LC_ALL=C

cd "$(git rev-parse --show-toplevel)"

# Files that are never scanned or flagged.
EXCLUDES=(
  ':(exclude)vendor'
  ':(exclude)crates/crawlx-policy/data/public_suffix_list.dat'
  ':(exclude,glob)**/Cargo.lock'
  ':(exclude,glob)**/package-lock.json'
  ':(exclude)ci/lint-public.sh'
)

# Internal-only paths: a file at or below any of these must not exist.
FORBIDDEN_PATHS=(
  docs/plans docs/adr docs/review docs/research
  bench/evidence
  crawlx-artifacts
)
# Internal-only file names, forbidden at any depth (extended by private `file` rules).
FORBIDDEN_NAMES=()

# Content rules: `name<TAB>PCRE`. A rule may carry a line filter: `name<TAB>PCRE<TAB>ERE`,
# lines matching the ERE are not counted.
RULES=(
  $'adr-citation\tADR-[0-9]{4}'
  $'plan-citation\t\\bplans/[0-9]{2}\\b'
  $'plan-number\t\\b[Pp]lans? [0-9]{1,2}\\b'
  $'audit-row\t(?i)audit row [0-9]'
  $'internal-doc-path\tdocs/(plans|adr|review|research)'
  $'bench-evidence\tbench/evidence'
  $'host-path\t/data/(tmp|cache|workspace)'
  $'privileged-pr-trigger\tpull_request_target'
)

# --- private rules -------------------------------------------------------------------------
PRIVATE_RULES=0
if [ -n "${PUBLIC_LINT_RULES:-}" ]; then
  while IFS=$'\t' read -r kind name value filter; do
    [ -n "${kind:-}" ] || continue
    case "$kind" in
      \#*) continue ;;
      content) RULES+=("$name"$'\t'"$value${filter:+$'\t'$filter}") ;;
      path) FORBIDDEN_PATHS+=("$value") ;;
      file) FORBIDDEN_NAMES+=("$value") ;;
      *) echo "lint-public: unknown private rule kind '$kind'" >&2; exit 2 ;;
    esac
    PRIVATE_RULES=$((PRIVATE_RULES + 1))
  done <<<"$PUBLIC_LINT_RULES"
fi
if [ "$PRIVATE_RULES" -eq 0 ] && [ "${PUBLIC_LINT_REQUIRE_PRIVATE:-0}" = 1 ]; then
  echo "lint-public: PUBLIC_LINT_REQUIRE_PRIVATE=1 but PUBLIC_LINT_RULES is empty" >&2
  exit 2
fi

hits=$(mktemp)
trap 'rm -f "$hits"' EXIT

# --- path rules ----------------------------------------------------------------------------
while IFS= read -r -d '' file; do
  [ -e "$file" ] || continue
  for dir in "${FORBIDDEN_PATHS[@]}"; do
    if [ "$file" = "$dir" ] || [[ "$file" == "$dir"/* ]]; then
      printf '%s:0: [forbidden-path] internal path %s must not exist\n' "$file" "$dir" >> "$hits"
    fi
  done
  base=${file##*/}
  for name in "${FORBIDDEN_NAMES[@]}"; do
    if [ "$base" = "$name" ]; then
      printf '%s:0: [forbidden-path] internal file %s must not exist\n' "$file" "$name" >> "$hits"
    fi
  done
done < <(git ls-files -z --cached --others --exclude-standard -- . "${EXCLUDES[@]}")

# --- content rules -------------------------------------------------------------------------
for rule in "${RULES[@]}"; do
  IFS=$'\t' read -r name pattern filter <<<"$rule"
  # git grep exits 1 on no match; that is the clean case.
  matches=$(git grep -I -n -P --untracked --no-color -e "$pattern" -- . "${EXCLUDES[@]}" || true)
  [ -n "$matches" ] || continue
  if [ -n "${filter:-}" ]; then
    matches=$(printf '%s\n' "$matches" | grep -Ev -- "$filter" || true)
    [ -n "$matches" ] || continue
  fi
  # file:line:text -> file:line: [rule] text (text cut at 120 columns)
  printf '%s\n' "$matches" | awk -F: -v rule="$name" '
    {
      file = $1; line = $2
      text = substr($0, length(file) + length(line) + 3)
      gsub(/^[ \t]+/, "", text)
      printf "%s:%s: [%s] %.120s\n", file, line, rule, text
    }' >> "$hits"
done

if [ ! -s "$hits" ]; then
  echo "lint-public: clean"
  exit 0
fi

sort -u "$hits" -o "$hits"
cat "$hits"
echo
echo "lint-public: violations per rule:"
awk 'match($0, /:[0-9]+: \[[a-z0-9-]+\] /) {
       tag = substr($0, RSTART, RLENGTH); sub(/^:[0-9]+: \[/, "", tag); sub(/\] $/, "", tag); n[tag]++
     }
     END { for (t in n) printf "  %-24s %d\n", t, n[t] }' "$hits" | sort
echo "lint-public: $(wc -l < "$hits") violation(s)"
exit 1
