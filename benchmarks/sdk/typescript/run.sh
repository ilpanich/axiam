#!/usr/bin/env bash
# Run the TypeScript SDK bench. Falls back to a pending record if node is absent.
#
# H8 fix: previously execed `node bench.mjs` directly, which fails with
# "Cannot find package 'axiam-sdk'" because nothing ever installed it.
# package.json in this directory declares axiam-sdk as a `file:` dependency
# on the sibling axiam-typescript-sdk checkout; `npm install` it (building the
# sibling's dist/ first if it hasn't been built yet — see comment below)
# whenever node_modules/axiam-sdk is missing, then run bench.mjs.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SIBLING_SDK="${AXIAM_TYPESCRIPT_SDK_DIR:-$HERE/../../../../axiam-typescript-sdk}"

if ! command -v node >/dev/null 2>&1; then
  # shellcheck disable=SC1091
  source "$HERE/../_pending.sh"; emit_pending typescript
  exit 0
fi

if [ ! -d "$HERE/node_modules/axiam-sdk" ]; then
  if [ -f "$SIBLING_SDK/package.json" ]; then
    if [ ! -d "$SIBLING_SDK/dist" ]; then
      echo "[typescript] sibling SDK has no dist/ — building it first (npm install + tsup)" >&2
      ( cd "$SIBLING_SDK" && npm install --no-audit --no-fund --quiet \
        && npx --no-install tsup 2>/dev/null || npx tsup ) >&2
    fi
    echo "[typescript] axiam-sdk not linked in node_modules — npm install $SIBLING_SDK" >&2
    ( cd "$HERE" && npm install --no-audit --no-fund --quiet ) >&2
  fi
fi

if [ ! -d "$HERE/node_modules/axiam-sdk" ]; then
  echo "[typescript] axiam-sdk still not resolvable after 'npm install $SIBLING_SDK' — is the sibling checkout present?" >&2
  # shellcheck disable=SC1091
  source "$HERE/../_pending.sh"; emit_pending typescript
  exit 0
fi

exec node "$HERE/bench.mjs"
