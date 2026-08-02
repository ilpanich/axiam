#!/usr/bin/env bash
# test-client-cert-wiring.sh — prove every language bench presents the §6.1
# client certificate under p3-mtls, without needing a live AXIAM stack.
#
# Why this exists: the p3-mtls SDK matrix used to fail every language with an
# identical, uninformative "server unreachable" — the benches simply never read
# BENCH_CLIENT_CERT/BENCH_CLIENT_KEY, so the TLS handshake was rejected before
# any HTTP request existed. That failure mode is indistinguishable from a real
# outage in the results table, which is exactly why it survived so long. This
# test pins the wiring down at the layer where it actually broke: the TLS
# handshake.
#
# It runs two phases:
#
#   A. Misconfiguration — with only BENCH_CLIENT_CERT set (no key), every bench
#      must emit the harness' contractual status:"error" record (HARNESS-SPEC.md)
#      naming BOTH env vars. Not a crash, not a silent pass.
#
#   B. Handshake — against a stub HTTPS server that REQUIRES a client
#      certificate (ssl.CERT_REQUIRED against the profile CA), every bench must
#      complete a TLS handshake presenting the bench client cert, i.e. the
#      server must observe peer CN=bench-client. The stub answers 503 to
#      everything, so the bench itself reports an error record — irrelevant
#      here: the assertion is what the server saw on the wire. A bench that
#      ignores BENCH_CLIENT_CERT cannot get past the handshake at all, so this
#      cannot pass by accident.
#
# Phase B's negative control (no client cert configured -> handshake refused,
# server observes nothing) runs first, so a stub server that accidentally
# accepted anonymous clients would fail the test rather than green-light it.
#
# Usage:
#   bash sdk/test-client-cert-wiring.sh              # all wired languages
#   bash sdk/test-client-cert-wiring.sh python go    # just these
#
# Requires: the profile certs (just bench-certs) and each language's toolchain.
# A language whose toolchain is absent is reported SKIP, not FAIL.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
BENCH="$(cd "$HERE/.." && pwd)"
CERTS="${BENCH_CERTS_DIR:-$BENCH/profiles/certs}"

# Every language bench, without exception. c/cpp/swift were held out of this
# list on the grounds that they "implement it too" and merely had extra build
# requirements (cmake, a Swift toolchain) — but a language absent from the
# gate is a language whose wiring nobody checks, and the C bench in fact read
# NONE of the three TLS env vars at all: it failed every p2-tls13 and p3-mtls
# run with libcurl's "SSL peer certificate or SSH remote key was not OK" while
# this test reported the suite green. Their toolchains are present in the
# normal setup, and a language whose toolchain is missing reports SKIP rather
# than FAIL, so listing one is safe either way.
ALL_SDKS=(c cpp csharp go java kotlin php python rust swift typescript)
if [ "$#" -gt 0 ]; then SDKS=("$@"); else SDKS=("${ALL_SDKS[@]}"); fi

# Languages blocked by a defect OUTSIDE this harness. Their phase-B failure is
# reported in full but does not fail the run, so this test stays usable as a
# gate for everything else. Set STRICT=1 to make them hard failures again —
# which is how you check whether an upstream fix has landed.
#
# Empty: `typescript` lived here until axiam-typescript-sdk fixed the two
# defects that made customCa/clientCert unusable in its Node persona (the ESM
# `require` shim, and axios-cookiejar-support's interceptor rejecting any
# externally-supplied agent). Both are fixed; it passes under STRICT=1.
KNOWN_BLOCKED=()
STRICT="${STRICT:-0}"

is_known_blocked() {
  local s
  [ "$STRICT" = "1" ] && return 1
  for s in "${KNOWN_BLOCKED[@]}"; do [ "$s" = "$1" ] && return 0; done
  return 1
}

PASS=0; FAIL=0; SKIP=0; BLOCKED=0
FAILED_NAMES=()

pass() { echo "  ✓ $*"; PASS=$((PASS + 1)); }
fail() { echo "  ✗ $*" >&2; FAIL=$((FAIL + 1)); FAILED_NAMES+=("$*"); }
skip() { echo "  – $* (toolchain absent)"; SKIP=$((SKIP + 1)); }
blocked() { echo "  ! $* [known upstream blocker — not counted as a failure; STRICT=1 to enforce]" >&2; BLOCKED=$((BLOCKED + 1)); }

for f in ca.crt server.crt server.key client.crt client.key; do
  [ -f "$CERTS/$f" ] || { echo "FATAL: $CERTS/$f missing — run 'just bench-certs' first" >&2; exit 1; }
done

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"; [ -n "${SERVER_PID:-}" ] && kill "$SERVER_PID" 2>/dev/null' EXIT

# --- stub mTLS server ------------------------------------------------------
# Requires a client certificate signed by the profile CA and appends the peer
# certificate's CN (empty line if none) to $PEERS for every request it serves.
PEERS="$TMP/peers.txt"
: > "$PEERS"
cat > "$TMP/server.py" <<'PY'
import http.server, ssl, sys

certs, peers = sys.argv[1], sys.argv[2]


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _record_peer(self):
        cn = ""
        cert = self.connection.getpeercert()
        for rdn in (cert or {}).get("subject", ()):
            for key, value in rdn:
                if key == "commonName":
                    cn = value
        with open(peers, "a") as fh:
            fh.write(cn + "\n")

    def _respond(self):
        self._record_peer()
        body = b'{"error":"stub mTLS probe server"}'
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    do_GET = do_POST = do_PUT = do_DELETE = _respond

    def log_message(self, *args):  # keep stderr clean
        pass


ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain(certs + "/server.crt", certs + "/server.key")
ctx.load_verify_locations(certs + "/ca.crt")
# The whole point: a client that presents no certificate is refused at the
# handshake, before any HTTP request exists.
ctx.verify_mode = ssl.CERT_REQUIRED

server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
server.handle_error = lambda *a: None  # a refused handshake is expected traffic
server.socket = ctx.wrap_socket(server.socket, server_side=True)
print(server.server_address[1], flush=True)
server.serve_forever()
PY

exec 3< <(python3 "$TMP/server.py" "$CERTS" "$PEERS" 2>/dev/null)
SERVER_PID=$!
read -r -u 3 -t 20 PORT || { echo "FATAL: stub mTLS server did not start" >&2; exit 1; }
echo "[test] stub mTLS server on 127.0.0.1:$PORT (requires client cert, answers 503)"

# Env every bench run shares. A real UUID for BENCH_RESOURCE_ID: some benches
# (rust) validate it up front and would fail for the wrong reason.
common_env() {
  echo "BENCH_TARGET=axiam"
  echo "BENCH_PROFILE=p3-mtls"
  echo "BENCH_SCHEME=https"
  echo "BENCH_HOST=127.0.0.1"
  echo "BENCH_PORT=$PORT"
  echo "BENCH_CA_CERT=$CERTS/ca.crt"
  echo "BENCH_TENANT_SLUG=default"
  echo "BENCH_ORG_SLUG=bench-org"
  echo "BENCH_RESOURCE_ID=00000000-0000-4000-8000-000000000000"
  echo "BENCH_SUBJECT_ID=00000000-0000-4000-8000-000000000001"
  echo "BENCH_CLIENT_ID=stub"
  echo "BENCH_CLIENT_SECRET=stub"
  echo "SDK_BENCH_ITERATIONS=1"
  echo "SDK_BENCH_WARMUP=0"
  echo "SDK_BENCH_CONCURRENCY=1"
}

# run_bench <sdk> [extra KEY=VAL ...] -> stdout of the bench, or non-zero if
# the toolchain is missing (detected via the harness' own "pending" status).
run_bench() {
  local sdk="$1"; shift
  local envs=()
  while IFS= read -r line; do envs+=("$line"); done < <(common_env)
  envs+=("$@")
  ( cd "$BENCH" && env "${envs[@]}" bash "$HERE/$sdk/run.sh" 2>"$TMP/$sdk.stderr" )
}

json_field() { python3 -c '
import json,sys
try: print(json.loads(sys.stdin.read()).get(sys.argv[1], ""))
except Exception: print("")
' "$1"; }

# --- phase B negative control ---------------------------------------------
echo
echo "[test] phase B control: a client with NO certificate must be refused"
: > "$PEERS"
out="$(run_bench python BENCH_CLIENT_CERT= BENCH_CLIENT_KEY=)"
if [ -s "$PEERS" ]; then
  fail "control: stub server served a request from a client presenting no certificate — the server is not enforcing mTLS, so phase B would prove nothing"
else
  pass "control: anonymous client refused at the handshake (server observed no peer)"
fi

# --- phase A: misconfiguration --------------------------------------------
echo
echo "[test] phase A: half-configured identity must yield a status:\"error\" record naming both vars"
for sdk in "${SDKS[@]}"; do
  out="$(run_bench "$sdk" "BENCH_CLIENT_CERT=$CERTS/client.crt" "BENCH_CLIENT_KEY=")"
  status="$(printf '%s' "$out" | json_field status)"
  notes="$(printf '%s' "$out" | json_field notes)"
  if [ "$status" = "pending" ]; then skip "$sdk"; continue; fi
  if [ "$status" != "error" ]; then
    fail "$sdk phase A: expected status=error, got status=${status:-<no record>}"
  elif [[ "$notes" != *BENCH_CLIENT_CERT* || "$notes" != *BENCH_CLIENT_KEY* ]]; then
    fail "$sdk phase A: error record does not name both env vars: $notes"
  else
    pass "$sdk phase A: $notes"
  fi
done

# --- phase B: the handshake actually presents the certificate --------------
echo
echo "[test] phase B: a fully-configured bench must present CN=bench-client on the wire"
for sdk in "${SDKS[@]}"; do
  : > "$PEERS"
  out="$(run_bench "$sdk" "BENCH_CLIENT_CERT=$CERTS/client.crt" "BENCH_CLIENT_KEY=$CERTS/client.key")"
  status="$(printf '%s' "$out" | json_field status)"
  if [ "$status" = "pending" ]; then skip "$sdk"; continue; fi
  if grep -qx "bench-client" "$PEERS"; then
    pass "$sdk phase B: server observed peer CN=bench-client"
  elif [ -s "$PEERS" ]; then
    fail "$sdk phase B: server saw a peer, but not CN=bench-client: $(sort -u "$PEERS" | tr '\n' ' ')"
  elif is_known_blocked "$sdk"; then
    blocked "$sdk phase B: server observed no peer (notes: $(printf '%s' "$out" | json_field notes))"
  else
    fail "$sdk phase B: server observed NO peer — the bench never presented a client certificate (notes: $(printf '%s' "$out" | json_field notes))"
  fi
done

echo
echo "[test] $PASS passed, $FAIL failed, $SKIP skipped, $BLOCKED known-blocked"
if [ "$FAIL" -gt 0 ]; then
  printf '[test] FAILED: %s\n' "${FAILED_NAMES[@]}" >&2
  exit 1
fi
echo "[test] client-certificate wiring OK"
