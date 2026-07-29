#!/usr/bin/env bash
# Run the Python SDK bench. Falls back to a pending record if python3 is absent.
#
# H8 fix: previously execed `python3 bench.py` against the ambient interpreter,
# which fails with "No module named 'axiam_sdk'" unless the package happens to
# already be installed there. Use a local venv (created once, cached) and
# `pip install -e` the sibling axiam-python-sdk checkout into it whenever the
# module isn't importable yet.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
SIBLING_SDK="${AXIAM_PYTHON_SDK_DIR:-$HERE/../../../../axiam-python-sdk}"
VENV="$HERE/.venv"

if ! command -v python3 >/dev/null 2>&1; then
  # shellcheck disable=SC1091
  source "$HERE/../_pending.sh"; emit_pending python
  exit 0
fi

if [ ! -x "$VENV/bin/python" ]; then
  python3 -m venv "$VENV" >&2
fi
PY="$VENV/bin/python"

if ! "$PY" -c 'import axiam_sdk' >/dev/null 2>&1; then
  if [ -f "$SIBLING_SDK/pyproject.toml" ] || [ -f "$SIBLING_SDK/setup.py" ]; then
    echo "[python] axiam_sdk not importable in $VENV — installing from $SIBLING_SDK" >&2
    "$PY" -m pip install --quiet --upgrade pip >&2
    "$PY" -m pip install --quiet -e "$SIBLING_SDK" >&2
  fi
fi

if ! "$PY" -c 'import axiam_sdk' >/dev/null 2>&1; then
  echo "[python] axiam_sdk still not importable after attempting 'pip install -e $SIBLING_SDK' — is the sibling checkout present?" >&2
  # shellcheck disable=SC1091
  source "$HERE/../_pending.sh"; emit_pending python
  exit 0
fi

exec "$PY" "$HERE/bench.py"
