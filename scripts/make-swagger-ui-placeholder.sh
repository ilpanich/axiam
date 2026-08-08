#!/usr/bin/env bash
# Regenerate the local placeholder swagger-ui archive that lets
# `axiam-api-rest` build in a sandbox with no GitHub egress.
#
# Why this exists
# ---------------
# `utoipa-swagger-ui`'s build script downloads `swagger-ui-<version>.zip` from
# github.com at compile time. This project's sandboxes proxy outbound HTTPS and
# the proxy answers github.com with 403, so any build of `axiam-api-rest` — or
# of anything depending on it, which is most of the workspace's tests — fails
# in the build script before a single line of AXIAM code is compiled.
#
# CLAUDE.md documents pointing `SWAGGER_UI_DOWNLOAD_URL` at a cached zip. That
# cache lives outside the repo and does not survive a fresh container, so the
# instruction was true and the file was missing, which reads as "the documented
# workaround is broken". This script rebuilds it in a second.
#
# What the placeholder is
# -----------------------
# A syntactically valid archive with the directory layout the build script
# extracts (`swagger-ui-<version>/dist/…`) and *empty* asset files. It is
# enough to compile and to serve a working `/swagger-ui` route shell; it is NOT
# the real Swagger UI, so the interactive documentation page renders blank.
# That is the right trade for a build environment: nothing in CI or production
# uses it — release images build with real egress — and no test asserts on the
# page's contents.
#
# Usage:
#   scripts/make-swagger-ui-placeholder.sh [version] [dest-dir]
#   export SWAGGER_UI_DOWNLOAD_URL="file://$(scripts/make-swagger-ui-placeholder.sh)"
set -euo pipefail

VERSION="${1:-5.17.14}"
DEST_DIR="${2:-$HOME/.axiam-build-cache}"
DEST="$DEST_DIR/swagger-ui-$VERSION.zip"

mkdir -p "$DEST_DIR"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
DIST="$STAGE/swagger-ui-$VERSION/dist"
mkdir -p "$DIST"

# The build script rewrites the `url: … deepLinking: true,` block in this file
# with utoipa's own config, so the pattern has to be present for the regex to
# match. Everything else can be empty.
cat > "$DIST/swagger-initializer.js" <<'JS'
window.onload = function() {
  window.ui = SwaggerUIBundle({
    url: "https://petstore.swagger.io/v2/swagger.json",
    dom_id: '#swagger-ui',
    deepLinking: true,
  });
};
JS

cat > "$DIST/index.html" <<'HTML'
<!DOCTYPE html><html><head><title>Swagger UI</title></head>
<body><div id="swagger-ui"></div><script src="./swagger-initializer.js"></script></body></html>
HTML

: > "$DIST/swagger-ui.css"
: > "$DIST/swagger-ui-bundle.js"
: > "$DIST/swagger-ui-standalone-preset.js"

python3 - "$STAGE" "$DEST" "$VERSION" <<'PY'
import os, sys, zipfile
stage, dest, version = sys.argv[1], sys.argv[2], sys.argv[3]
root = f"swagger-ui-{version}"
with zipfile.ZipFile(dest, "w") as z:
    for dirpath, _, files in os.walk(os.path.join(stage, root)):
        for name in files:
            full = os.path.join(dirpath, name)
            z.write(full, os.path.relpath(full, stage))
PY

echo "$DEST"
