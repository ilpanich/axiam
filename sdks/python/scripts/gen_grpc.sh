#!/usr/bin/env bash
# Generate the Python gRPC stubs for the AXIAM SDK from proto/axiam/v1.
#
# D-04 (Phase 19): the `buf` CLI is absent from the local dev sandbox (same
# gap Phase 18 / Go hit — see 19-RESEARCH.md Pitfall 5). Standardize on
# `python -m grpc_tools.protoc` for BOTH local and CI codegen so the
# committed stubs are reproducible without a `buf` install. This is the
# drift-check anchor for the CI job wired in a later plan (19-07): CI
# re-runs this exact script and asserts `git diff --exit-code` is clean
# against `sdks/python/src/axiam_sdk/grpc/gen`.
#
# grpc_tools.protoc's generated `*_pb2_grpc.py` uses a bare
# `import authorization_pb2 as authorization__pb2` import that breaks once
# the stub is nested inside a package (axiam_sdk.grpc.gen). This script
# applies the mandatory Pitfall-1 fixup: rewrite that bare import to a
# package-relative `from . import authorization_pb2 as authorization__pb2`.
# Only the generated `_pb2_grpc.py` service file needs this; the `_pb2.py`
# message file is fine standalone.
#
# IMPORTANT: install `grpcio-tools==1.78.*` (matching the PY-01-pinned
# `grpcio==1.78.*` runtime dependency in pyproject.toml) before running this
# script. grpc_tools.protoc embeds its own version as
# `GRPC_GENERATED_VERSION` in the generated `_pb2_grpc.py` and raises
# RuntimeError at import time if the installed `grpcio` is older than that
# embedded version. Generating with a newer grpcio-tools than the pinned
# grpcio runtime would silently break every consumer's import.
#
# Usage (from repo root or anywhere — path resolution is relative to the
# repo root via `git rev-parse --show-toplevel`):
#   bash sdks/python/scripts/gen_grpc.sh

set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
PROTO_DIR="${REPO_ROOT}/proto/axiam/v1"
OUT_DIR="${REPO_ROOT}/sdks/python/src/axiam_sdk/grpc/gen"
PROTO_FILE="authorization.proto"

mkdir -p "${OUT_DIR}"

cd "${REPO_ROOT}"

# -I points directly at the directory containing authorization.proto so
# grpc_tools.protoc emits the generated files flat into OUT_DIR (no
# axiam/v1/ subdirectory mirroring) — matching the plan's committed-stub
# layout (grpc/gen/authorization_pb2*.py).
python3 -m grpc_tools.protoc \
  -I "${PROTO_DIR}" \
  --python_out="${OUT_DIR}" \
  --grpc_python_out="${OUT_DIR}" \
  --pyi_out="${OUT_DIR}" \
  "${PROTO_FILE}"

GRPC_FILE="${OUT_DIR}/authorization_pb2_grpc.py"

if [ ! -f "${GRPC_FILE}" ]; then
  echo "ERROR: expected generated file not found: ${GRPC_FILE}" >&2
  exit 1
fi

# Pitfall-1 fixup: rewrite the bare top-level import to a package-relative
# import. Targeted at the exact generated import statement so unrelated
# lines are never touched.
python3 - "${GRPC_FILE}" <<'PYEOF'
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    content = f.read()

old_import = "import authorization_pb2 as authorization__pb2"
new_import = "from . import authorization_pb2 as authorization__pb2"

if old_import not in content:
    if new_import in content:
        print(f"NOTE: {path} already has the package-relative import; nothing to fix.")
        sys.exit(0)
    print(f"ERROR: expected bare import '{old_import}' not found in {path}", file=sys.stderr)
    sys.exit(1)

content = content.replace(old_import, new_import)

with open(path, "w", encoding="utf-8") as f:
    f.write(content)

print(f"Fixed up import in {path}")
PYEOF

echo "gRPC stubs generated and import-fixed at ${OUT_DIR}"
