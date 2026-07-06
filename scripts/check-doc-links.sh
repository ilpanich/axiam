#!/usr/bin/env bash
# check-doc-links.sh — Zero-dependency internal-link checker for AXIAM docs.
#
# Scans docs/**/*.md and claude_dev/security-audit.md for markdown inline
# links of the form [label](target), filters to RELATIVE targets only
# (skips http(s):, mailto:, and pure #anchor fragments), strips any
# trailing #anchor, resolves each target relative to the containing file's
# directory, and asserts the resolved path exists (as a file OR a
# directory, so links to directories like `../../sdks/` also resolve).
#
# Exits 0 if every relative link resolves. Exits 1 (and prints every
# broken link with its source file) if any target is missing.
#
# Stdlib-only: grep/sed/find + bash builtins. No npm, no curl, no network.
#
# Usage: scripts/check-doc-links.sh
#   (run from anywhere inside the repo; resolves the repo root itself)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

# Fixed doc set to scan (D-11): every markdown file under docs/, plus the
# CMPL-01 master compliance doc.
DOC_FILES=()
while IFS= read -r -d '' f; do
  DOC_FILES+=("$f")
done < <(find docs -type f -name '*.md' -print0 | sort -z)

if [ -f claude_dev/security-audit.md ]; then
  DOC_FILES+=("claude_dev/security-audit.md")
fi

if [ "${#DOC_FILES[@]}" -eq 0 ]; then
  echo "check-doc-links: no doc files found to scan (expected docs/**/*.md)" >&2
  exit 1
fi

broken=0
checked=0

for doc in "${DOC_FILES[@]}"; do
  doc_dir="$(dirname "$doc")"

  # Extract every [label](target) markdown link's target. grep -o with a
  # capture-free pattern, then sed strips the wrapping "](" / ")".
  # -E: extended regex; the target group excludes ')' and whitespace to
  # avoid swallowing trailing prose.
  while IFS= read -r target; do
    [ -z "$target" ] && continue

    # Skip external / non-filesystem targets.
    case "$target" in
      http://*|https://*|mailto:*|\#*)
        continue
        ;;
    esac

    # Strip a trailing #anchor fragment, if present.
    target_path="${target%%#*}"
    [ -z "$target_path" ] && continue

    resolved="$doc_dir/$target_path"

    if [ ! -e "$resolved" ]; then
      echo "BROKEN LINK: $doc -> $target (resolved: $resolved)"
      broken=$((broken + 1))
    fi
    checked=$((checked + 1))
  done < <(grep -oE '\]\([^) ]+\)' "$doc" | sed -E 's/^\]\((.*)\)$/\1/')
done

if [ "$broken" -gt 0 ]; then
  echo ""
  echo "check-doc-links: $broken broken link(s) out of $checked checked across ${#DOC_FILES[@]} file(s)." >&2
  exit 1
fi

echo "check-doc-links: OK — $checked relative link(s) resolved across ${#DOC_FILES[@]} file(s)."
exit 0
