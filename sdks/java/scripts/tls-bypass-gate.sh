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
# The literal SC#4 substrings (`hostnameVerifier`/`sslSocketFactory`) are
# necessary but not sufficient: an empty-body checkServerTrusted(...)
# override or an unconditional `return true` HostnameVerifier lambda
# bypasses TLS just as completely without containing either literal
# substring in a suspicious way. This pattern is intentionally broader,
# matching Go's own Pitfall-1 precedent of extending the literal SC wording.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
JAVA_SDK_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

PATTERN='hostnameVerifier\s*\(|setHostnameVerifier|sslSocketFactory\s*\(|X509TrustManager\s*\(\s*\)\s*\{|checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER|NoopHostnameVerifier'

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
