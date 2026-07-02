#!/usr/bin/env bash
# TLS-bypass CI grep gate (SC#4, T-20-01).
#
# Source: .planning/phases/20-java-sdk/20-RESEARCH.md Code Examples
# "TLS-bypass CI grep gate" + .planning/research/PITFALLS.md's Java-specific
# "TrustManager that accepts all certs" finding + CONTRACT.md §6's "any other
# API surface that bypasses TLS verification" absolute prohibition.
#
# Scope: sdks/java/src + sdks/java/examples ONLY — deliberately excludes
# sdks/java/scripts (this script itself) and sdks/java/src/test (so a
# future reflection-based TLS regression test, which legitimately references
# these idioms as literal strings to assert their ABSENCE, cannot trip its
# own gate).
#
# NOTE (20-05 correction): the literal method-name substrings
# `hostnameVerifier(`/`sslSocketFactory(` were dropped from this pattern.
# OkHttp's own `OkHttpClient.Builder.sslSocketFactory(SSLSocketFactory,
# X509TrustManager)` is the ONLY API surface through which a JDK OkHttp
# client can be configured with strict TLS + an additional trusted CA
# (`Platform.platformTrustManager()`/`newSslSocketFactory()` build a fresh
# `SSLContext` straight from the system trust store on every un-configured
# `OkHttpClient` — they never consult `SSLContext.setDefault()`, so there is
# no alternate stdlib-only path to implement CONTRACT.md §6's required
# `customCa` escape hatch). Banning the method NAME outright — regardless of
# whether it is called with a strict, correctly-implemented trust manager —
# made a required CONTRACT.md §6 feature unimplementable, which is a defect
# in the gate, not in the SDK. The gate still catches every concrete
# bypass idiom PITFALLS.md documents: a trust-all `X509TrustManager`
# (empty-body `checkServerTrusted`), and the well-known insecure identifiers
# `TrustAllCerts`/`ALLOW_ALL_HOSTNAME_VERIFIER`/`NoopHostnameVerifier`. A
# permissive inline `HostnameVerifier` lambda (`(host, session) -> true`) is
# still caught by the `-> true` pattern below.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAVA_SDK_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PATTERN='setHostnameVerifier|X509TrustManager\s*\(\s*\)\s*\{|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier|->\s*true\b'

TARGETS=()
[ -d "${JAVA_SDK_ROOT}/src" ] && TARGETS+=("${JAVA_SDK_ROOT}/src")
[ -d "${JAVA_SDK_ROOT}/examples" ] && TARGETS+=("${JAVA_SDK_ROOT}/examples")

if [ "${#TARGETS[@]}" -eq 0 ]; then
  echo "OK: no TLS-bypass patterns found under sdks/java/ (no src/examples dirs yet)"
  exit 0
fi

# Exclude sdks/java/src/test — a future reflection-based TLS regression test
# legitimately asserts the ABSENCE of these idioms and must not self-trip
# this gate by referencing the literal strings.
MATCHES=$(grep -rnE "${PATTERN}" "${TARGETS[@]}" --exclude-dir=test 2>/dev/null || true)

if [ -n "${MATCHES}" ]; then
  echo "FAIL: found a TLS-bypass pattern under sdks/java/"
  echo "${MATCHES}"
  exit 1
fi

echo "OK: no TLS-bypass patterns found under sdks/java/"
