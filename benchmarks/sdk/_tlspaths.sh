#!/usr/bin/env bash
# _tlspaths.sh — resolve the harness' TLS input PATHS to absolute paths.
#
# HARNESS-SPEC.md documents three TLS inputs, all of them file PATHS:
#
#   BENCH_CA_CERT      the profile's CA, trusted for server verification (p1+)
#   BENCH_CLIENT_CERT  the §6.1 client-certificate chain (p3-mtls)
#   BENCH_CLIENT_KEY   its private key                  (p3-mtls)
#
# profiles/*.env derives all three from ${BENCH_CERTS_DIR:-profiles/certs},
# which is RELATIVE to the benchmarks root. Most language run.sh scripts `cd`
# into their own directory before exec'ing the bench (they must, for
# go.mod/pom.xml/Cargo.toml resolution), at which point a relative path no
# longer resolves and the bench dies with "No such file or directory" on a
# file the caller's shell could see perfectly well. Resolve them here, once,
# before any `cd`.
#
# Sourced by every language's run.sh — a shared helper rather than the copy
# per script this replaces, so a fourth TLS input (or a fix to this logic)
# lands in one place instead of six. `just sdk-bench`/`sdk-bench-all` already
# export an absolute BENCH_CERTS_DIR, so in the normal path this is a no-op;
# it earns its keep when a run.sh is invoked directly.
#
# Usage:  source "$HERE/../_tlspaths.sh"; absolutize_tls_paths

absolutize_tls_paths() {
  local var val
  for var in BENCH_CA_CERT BENCH_CLIENT_CERT BENCH_CLIENT_KEY; do
    val="${!var:-}"
    # Leave unset/empty vars alone (they mean "not configured for this
    # profile") and leave non-existent paths alone too: the bench itself
    # reports an unreadable path with a message naming the env var, which is
    # a better error than one silently rewritten here.
    [ -n "$val" ] && [ -f "$val" ] || continue
    export "$var=$(cd "$(dirname "$val")" && pwd)/$(basename "$val")"
  done
}
