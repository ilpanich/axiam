#!/usr/bin/env bash
# first-boot-token.sh — print the one-time bootstrap setup token that
# axiam-server logs on its first boot.
#
# This is the ONE place the token is extracted from a log; e2e-bootstrap.sh and
# benchmarks/runner/seed.sh both call it. The server logs the token exactly once
# (a JSON log line carrying a `setup_token` field) and stores only its hash, so
# the log is the only place a running stack's token can be read. Treat that log
# as secret until bootstrap completes.
#
# Usage:
#   scripts/first-boot-token.sh [container]     # docker logs <container>
#   kubectl -n axiam logs deploy/axiam-server | scripts/first-boot-token.sh -
#
# Prints the token on stdout and exits 0, or prints nothing and exits 1 when no
# token line is found (already bootstrapped, token rotated out of the log, or
# the wrong container). Default container: ${AXIAM_SERVER_CONTAINER:-axiam-e2e-server}.

set -euo pipefail

SRC="${1:-${AXIAM_SERVER_CONTAINER:-axiam-e2e-server}}"

if [ "${SRC}" = "-" ]; then
  LOG="$(cat)"
else
  # docker logs writes the container's stderr to stderr; fold both together.
  LOG="$(docker logs "${SRC}" 2>&1)" || { echo "first-boot-token: cannot read logs of ${SRC}" >&2; exit 1; }
fi

TOKEN="$(printf '%s\n' "${LOG}" \
  | grep 'first-run bootstrap setup token minted' \
  | sed -n 's/.*"setup_token":"\([^"]*\)".*/\1/p' \
  | head -n 1)"

if [ -z "${TOKEN}" ]; then
  echo "first-boot-token: no setup token in the log of ${SRC}" >&2
  exit 1
fi
printf '%s\n' "${TOKEN}"
