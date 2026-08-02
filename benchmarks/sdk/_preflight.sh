#!/usr/bin/env bash
# _preflight.sh — verify the target is actually serving the profile we are
# about to bench, BEFORE any language bench runs.
#
# Why this exists: `just bench-up` selects a compose overlay from the profile
# (p2/p3 swap in docker-compose.native-tls.yml, whose `ports: !override`
# REPLACES 8090:8090 with 8443:8090), so a TLS profile has no plaintext port
# and a plaintext stack has no TLS port. Nothing tied the two together at
# bench time: running `just profile=p2-tls13 sdk-bench-all` against a stack
# still up from p0-plaintext pointed every bench at :8443, where nothing was
# listening. Each of the eleven then failed independently, several minutes
# apart, with its own phrasing of "server unreachable" — a wall of red that
# reads as "every SDK is broken" instead of "wrong listener", which is
# exactly how it was reported. One connect attempt up front turns that into
# a single actionable line, and costs a few milliseconds when things are fine.
#
# Sourced by the sdk-bench / sdk-bench-all justfile recipes, which have
# already sourced profiles/<profile>.env, so BENCH_SCHEME/HOST/PORT and the
# p3 client-cert pair are in the environment.
#
# Usage:  source sdk/_preflight.sh; preflight_target || exit 1

preflight_target() {
  local scheme="${BENCH_SCHEME:-http}"
  local host="${BENCH_HOST:-localhost}"
  local port="${BENCH_PORT:-8090}"
  local profile="${BENCH_PROFILE:-p0-plaintext}"
  local target="${BENCH_TARGET:-axiam}"
  # Same readiness paths bench-up gates on — /health is AXIAM's and 404s on
  # the competitors, which would turn a healthy stack into a false FATAL.
  local path
  case "$target" in
    zitadel)  path="/debug/ready" ;;
    keycloak) path="/realms/master" ;;
    *)        path="/health" ;;
  esac
  local url="${scheme}://${host}:${port}${path}"

  # -k: every TLS profile fronts a throwaway private CA that is in no system
  # trust store. We are probing reachability, not trust — each bench verifies
  # the chain itself via BENCH_CA_CERT.
  local curl_args=(-s -o /dev/null --max-time 15 -k)
  # p3-mtls: the listener runs client_auth=required, so an anonymous probe is
  # refused at the handshake and would report a healthy stack as unreachable.
  if [ -n "${BENCH_CLIENT_CERT:-}" ] && [ -n "${BENCH_CLIENT_KEY:-}" ]; then
    curl_args+=(--cert "$BENCH_CLIENT_CERT" --key "$BENCH_CLIENT_KEY")
  fi

  if curl "${curl_args[@]}" -f "$url"; then
    return 0
  fi

  echo "[preflight] FATAL: $target is not serving $profile at $url" >&2
  echo >&2

  # Name the mismatch when we can see it, rather than making the operator
  # guess: probing the OTHER profile's port distinguishes "stack is up on the
  # wrong profile" (the common case) from "stack is down" (the obvious one).
  local other_port other_scheme
  if [ "$scheme" = "https" ]; then
    other_port="${BENCH_APP_PORT:-8090}"; other_scheme="http"
  else
    other_port="${BENCH_TLS_PORT:-8443}"; other_scheme="https"
  fi
  if curl -s -o /dev/null --max-time 5 -k "${other_scheme}://${host}:${other_port}${path}"; then
    echo "[preflight] Something IS serving ${other_scheme}://${host}:${other_port} — the stack is up," >&2
    echo "            but under a different security profile than the one you asked to bench." >&2
    echo "            The profile selects a compose overlay, so the listener has to be" >&2
    echo "            rebuilt for it; the client env alone cannot switch it." >&2
  else
    echo "[preflight] Nothing is serving ${other_scheme}://${host}:${other_port} either — the stack looks down." >&2
  fi
  echo >&2
  echo "            Bring the stack up on THIS profile — bench-up recreates the" >&2
  echo "            container under the profile's overlay in place, keeping the" >&2
  echo "            database volume (and therefore the existing seed):" >&2
  echo >&2
  echo "              just target=$target profile=$profile bench-up" >&2
  echo >&2
  echo "            Seed too, if this is a fresh volume (or the run below reports a" >&2
  echo "            missing tenant/grant):" >&2
  echo >&2
  echo "              just target=$target profile=$profile bench-seed" >&2
  echo >&2
  echo "            Note 'just target=$target bench-down' runs 'docker compose down -v'," >&2
  echo "            which DROPS the database volume — after it, the re-seed is mandatory." >&2
  return 1
}
