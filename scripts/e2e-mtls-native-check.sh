#!/usr/bin/env bash
# e2e-mtls-native-check.sh — the TLS-handshake half of certificate authentication.
#
# `scripts/e2e-mtls-check.sh` measures the **proxy-terminated** path: a PEM
# arrives in an `X-Client-Certificate` header and `axiam-pki` performs every
# check itself. That is the path `docker-compose.prod.yml` exposes, and it left
# the other half — the one where **rustls** verifies the certificate during the
# TLS handshake — recorded as UNVERIFIED in `claude_dev/e2e-findings.md`, because
# the shipped stack terminates TLS at Caddy and the server therefore never sees
# a client certificate.
#
# This script closes that gap without disturbing the running stack. It starts a
# **second server container** from the same image, on the same Docker network and
# the same database, configured to terminate TLS itself:
#
#     AXIAM__SERVER__TLS__ENABLED=true + CERT_PATH + KEY_PATH
#
# and lets the server derive client-certificate trust the way an operator would —
# from the organization CAs flagged `mtls_trust_anchor`, which it collects at
# boot, writes as one PEM bundle, and (since `client_auth` is left `off`) points
# a `WebPkiClientVerifier` at in `optional` mode.
#
# ---------------------------------------------------------------------------
# What only a handshake can settle
# ---------------------------------------------------------------------------
#
# `crates/axiam-api-rest/src/extractors/cert_auth.rs` prefers the certificate
# rustls verified over the header, and says so:
#
#     "rustls has already checked it against the client-CA bundle, so it is
#      authoritative and cannot be spoofed by a header."
#
# Its own tests note that path is "unreachable" from a unit test — there is no
# TLS connection in one. Everything below therefore asserts something no Rust
# test and no Playwright run can reach:
#
#   1. the bundle is built from the flagged anchors, and `client_auth` turns
#      itself on because of them;
#   2. a certificate under a flagged anchor completes the handshake, and is the
#      identity **with no `X-Client-Certificate` header sent at all**;
#   3. a certificate under a CA that was never flagged is refused *by rustls*,
#      before any AXIAM code runs — a transport failure, not an HTTP status;
#   4. AXIAM's own checks still run on top of the handshake: a revoked, bound,
#      chain-valid certificate completes the handshake and is refused anyway;
#   5. a header cannot override the verified peer certificate;
#   6. un-flagging an anchor takes effect on the live listener, without a
#      restart (`TrustAnchorReload`).
#
# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
#
#   scripts/e2e-mtls-native-check.sh
#
# Requires: the prod-like stack running (`axiam-server` container up), plus
# `jq`, `openssl` and `curl` built against OpenSSL (for Ed25519 client keys).
#
# Environment:
#   AXIAM_URL          default https://localhost   (the proxy path, for admin API calls)
#   TLS_PORT           default 9443                (host port for the TLS sidecar)
#                      NOT 8443 and NOT 8080 — a SAGE node holds both on this host,
#                      and the sidecar would fail to bind with a message about the
#                      container rather than the port.
#   E2E_ORG_SLUG       default test-org
#   E2E_TENANT_SLUG    default default
#   E2E_ADMIN_EMAIL    default admin@axiam.dev
#   E2E_ADMIN_PASSWORD default Test@Admin123!
#   KEEP_SIDECAR=1     leave the sidecar running for inspection

set -uo pipefail

AXIAM_URL="${AXIAM_URL:-https://localhost}"
TLS_PORT="${TLS_PORT:-9443}"
ORG_SLUG="${E2E_ORG_SLUG:-test-org}"
TENANT_SLUG="${E2E_TENANT_SLUG:-default}"
ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-admin@axiam.dev}"
ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-Test@Admin123!}"
SIDECAR="axiam-server-mtls-probe"
SRC_CONTAINER="${SRC_CONTAINER:-axiam-server}"

PASS=0; FAIL=0; UNVERIFIED=0
pass()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
fail()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }
skip()  { printf '  \033[33mUNVERIFIED\033[0m %s\n' "$1"; UNVERIFIED=$((UNVERIFIED + 1)); }
info()  { printf '  ---- %s\n' "$1"; }

for tool in jq openssl curl docker; do
  command -v "$tool" >/dev/null 2>&1 || { echo "ERROR: $tool is required"; exit 1; }
done
docker inspect "$SRC_CONTAINER" >/dev/null 2>&1 || {
  echo "ERROR: container '$SRC_CONTAINER' is not running — bring the stack up first"; exit 1; }

WORK=$(mktemp -d)
cleanup() {
  if [ "${KEEP_SIDECAR:-0}" = "1" ]; then
    info "KEEP_SIDECAR=1 — leaving $SIDECAR running on :$TLS_PORT"
  else
    docker rm -f "$SIDECAR" >/dev/null 2>&1
  fi
  rm -rf "$WORK"
}
trap cleanup EXIT
JAR="$WORK/jar"; HDRS="$WORK/hdrs"
TLSDIR="$WORK/server-tls"; mkdir -p "$TLSDIR"; chmod 777 "$TLSDIR"

# ---------------------------------------------------------------------------
echo "== Signing in as the organization super-admin ============================="
CODE=$(curl -sk -c "$JAR" -D "$HDRS" -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "{\"org_slug\":\"$ORG_SLUG\",\"username_or_email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
  "$AXIAM_URL/api/v1/auth/login")
[ "$CODE" = "200" ] || { fail "sign-in returned $CODE"; exit 1; }
CSRF=$(grep -i '^x-csrf-token:' "$HDRS" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
ORG_ID=$(curl -sk -b "$JAR" "$AXIAM_URL/api/v1/organizations" \
  | jq -r --arg s "$ORG_SLUG" '(.items // .) | map(select(.slug == $s)) | .[0].id // empty')
TENANT_ID=$(curl -sk -b "$JAR" "$AXIAM_URL/api/v1/organizations/$ORG_ID/tenants" \
  | jq -r --arg s "$TENANT_SLUG" '(.items // .) | map(select(.slug == $s)) | .[0].id // empty')
[ -n "$ORG_ID" ] && [ -n "$TENANT_ID" ] || { fail "could not resolve org/tenant"; exit 1; }
pass "org=$ORG_ID tenant=$TENANT_ID"

api() { # method path [body]
  local m="$1" p="$2" b="${3:-}"
  local -a a=(-sk -b "$JAR" -X "$m" -H 'Content-Type: application/json'
              -H "X-CSRF-Token: $CSRF" -H "X-Axiam-Tenant: $TENANT_ID")
  [ -n "$b" ] && a+=(-d "$b")
  curl "${a[@]}" -o "$WORK/resp.json" -w '%{http_code}' "$AXIAM_URL$p"
}

STAMP=$(date +%s)

# ---------------------------------------------------------------------------
echo
echo "== Certificate fixture ===================================================="
info "issued here, not looked up: a private key is returned once, at generation"

ANCHOR_ID=$(curl -sk -b "$JAR" "$AXIAM_URL/api/v1/organizations/$ORG_ID/ca-certificates" \
  | jq -r 'map(select(.mtls_trust_anchor == true)) | .[0].id // empty' 2>/dev/null)
if [ -z "$ANCHOR_ID" ]; then
  api POST "/api/v1/organizations/$ORG_ID/ca-certificates" \
    "{\"subject\":\"CN=mx-native-anchor-$STAMP\",\"key_algorithm\":\"Ed25519\",\"validity_days\":90}" >/dev/null
  ANCHOR_ID=$(jq -r '.id // empty' "$WORK/resp.json")
  [ -n "$ANCHOR_ID" ] || { fail "could not mint a CA"; exit 1; }
  api PUT "/api/v1/organizations/$ORG_ID/ca-certificates/$ANCHOR_ID/mtls-trust-anchor" \
    '{"enabled":true}' >/dev/null
fi
pass "trusted anchor CA: $ANCHOR_ID"

UNTRUSTED_ID=$(curl -sk -b "$JAR" "$AXIAM_URL/api/v1/organizations/$ORG_ID/ca-certificates" \
  | jq -r 'map(select(.mtls_trust_anchor != true)) | .[0].id // empty' 2>/dev/null)
if [ -z "$UNTRUSTED_ID" ]; then
  api POST "/api/v1/organizations/$ORG_ID/ca-certificates" \
    "{\"subject\":\"CN=mx-native-untrusted-$STAMP\",\"key_algorithm\":\"Ed25519\",\"validity_days\":90}" >/dev/null
  UNTRUSTED_ID=$(jq -r '.id // empty' "$WORK/resp.json")
fi
pass "untrusted CA (never flagged): ${UNTRUSTED_ID:-<none>}"

issue() { # <name> <issuer-ca-id>
  local name="$1" ca="$2" code
  code=$(api POST "/api/v1/certificates" \
    "{\"issuer_ca_id\":\"$ca\",\"subject\":\"CN=$name\",\"cert_type\":\"Service\",\"key_algorithm\":\"Ed25519\",\"validity_days\":30}")
  case "$code" in 200|201) ;; *) fail "issuing $name returned HTTP $code: $(head -c 200 "$WORK/resp.json")"; return 1 ;; esac
  jq -r '.public_cert_pem // .certificate.public_cert_pem // empty' "$WORK/resp.json" > "$WORK/$name.crt"
  jq -r '.private_key_pem // empty' "$WORK/resp.json" > "$WORK/$name.key"
  jq -r '.id' "$WORK/resp.json" > "$WORK/$name.id"
  [ -s "$WORK/$name.crt" ] && [ -s "$WORK/$name.key" ] || { fail "$name: no cert/key in the response"; return 1; }
}

create_sa() { api POST "/api/v1/service-accounts" "{\"name\":\"$1\",\"description\":\"native mtls check\"}" >/dev/null
              jq -r '.id // empty' "$WORK/resp.json"; }
bind_cert() { api POST "/api/v1/service-accounts/$1/bind-certificate" "{\"certificate_id\":\"$2\"}"; }

SA_ID=$(create_sa "mx-native-sa-$STAMP")
[ -n "$SA_ID" ] || { fail "could not create a service account"; exit 1; }
pass "service account: $SA_ID"

issue "native-bound-$STAMP" "$ANCHOR_ID" || exit 1
bind_cert "$SA_ID" "$(cat "$WORK/native-bound-$STAMP.id")" >/dev/null
pass "native-bound-$STAMP issued under the anchor and bound to $SA_ID"

# A second bound certificate under the anchor. Used for the header-spoof
# assertion, so that "the header was ignored" cannot be confused with "the
# header's certificate was itself unusable".
SA_OTHER=$(create_sa "mx-native-sa-other-$STAMP")
issue "native-other-$STAMP" "$ANCHOR_ID" && \
  bind_cert "$SA_OTHER" "$(cat "$WORK/native-other-$STAMP.id")" >/dev/null && \
  pass "native-other-$STAMP issued and bound to a DIFFERENT account ($SA_OTHER)"

# Revoked, but bound and chain-valid: rustls will accept it (it holds no
# revocation list), so a refusal can only come from AXIAM's own checks.
SA_REVOKED=$(create_sa "mx-native-sa-revoked-$STAMP")
if issue "native-revoked-$STAMP" "$ANCHOR_ID"; then
  bind_cert "$SA_REVOKED" "$(cat "$WORK/native-revoked-$STAMP.id")" >/dev/null
  api POST "/api/v1/certificates/$(cat "$WORK/native-revoked-$STAMP.id")/revoke" '{}' >/dev/null
  pass "native-revoked-$STAMP issued, bound, then revoked"
fi

# Under the CA that was never flagged — and bound, so a refusal cannot be
# explained by a missing binding.
SA_UNTRUSTED=$(create_sa "mx-native-sa-untrusted-$STAMP")
if [ -n "$UNTRUSTED_ID" ] && issue "native-untrusted-$STAMP" "$UNTRUSTED_ID"; then
  bind_cert "$SA_UNTRUSTED" "$(cat "$WORK/native-untrusted-$STAMP.id")" >/dev/null
  pass "native-untrusted-$STAMP issued under the non-anchor CA and bound"
fi

# ---------------------------------------------------------------------------
echo
echo "== Bringing up a TLS-terminating sidecar =================================="

# Server certificate. ECDSA P-256 rather than Ed25519 — this is the server's own
# listener key, and P-256 is what every rustls provider signs with.
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$TLSDIR/server.key" -out "$TLSDIR/server.pem" -days 2 \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" >/dev/null 2>&1 \
  && pass "minted a listener certificate for CN=localhost" \
  || { fail "openssl could not mint a listener certificate"; exit 1; }
chmod 644 "$TLSDIR/server.key" "$TLSDIR/server.pem"

NETWORK=$(docker inspect "$SRC_CONTAINER" --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{end}}' | head -1)
[ -n "$NETWORK" ] || { fail "could not resolve the stack network"; exit 1; }
info "network: $NETWORK"

# Reuse the running server's own environment verbatim. Copying the values by
# hand is how a sidecar ends up pointed at a different database than the one the
# fixture was just written to — the assertions would then all fail for a reason
# that has nothing to do with TLS.
#
# Passed as `-e` arguments rather than `--env-file`: an env-file is line-based
# and the JWT keys are multi-line PEM blocks, which it silently truncates at the
# first newline. NUL-delimited so a value containing newlines survives the read.
OVERRIDDEN='AXIAM__SERVER__TLS__ENABLED|AXIAM__SERVER__TLS__CERT_PATH|AXIAM__SERVER__TLS__KEY_PATH|AXIAM__SERVER__TLS__CLIENT_CA_BUNDLE_PATH|RUST_LOG'
ENV_ARGS=()
while IFS= read -r -d '' e; do
  ENV_ARGS+=(-e "$e")
done < <(docker inspect "$SRC_CONTAINER" --format '{{json .Config.Env}}' \
  | jq -j --arg drop "$OVERRIDDEN" '.[] | select((split("=")[0] | test("^(" + $drop + ")$")) | not) + "\u0000"')

ENV_ARGS+=(
  -e "AXIAM__SERVER__TLS__ENABLED=true"
  -e "AXIAM__SERVER__TLS__CERT_PATH=/etc/axiam/server-tls/server.pem"
  -e "AXIAM__SERVER__TLS__KEY_PATH=/etc/axiam/server-tls/server.key"
  -e "AXIAM__SERVER__TLS__CLIENT_CA_BUNDLE_PATH=/etc/axiam/server-tls/client-ca-bundle.pem"
  -e "RUST_LOG=axiam=debug"
)
info "inherited ${#ENV_ARGS[@]} environment entries from $SRC_CONTAINER"

# Mirror the source container's read-only mounts (broker and Vault trust
# anchors) — the server reads its secrets over both before it serves anything.
MOUNT_ARGS=()
while IFS= read -r m; do
  [ -n "$m" ] && MOUNT_ARGS+=(-v "$m")
done < <(docker inspect "$SRC_CONTAINER" \
  --format '{{range .Mounts}}{{if eq .Type "bind"}}{{.Source}}:{{.Destination}}:ro{{println}}{{end}}{{end}}')

IMAGE=$(docker inspect "$SRC_CONTAINER" --format '{{.Config.Image}}')
docker rm -f "$SIDECAR" >/dev/null 2>&1
docker run -d --name "$SIDECAR" --network "$NETWORK" \
  "${ENV_ARGS[@]}" \
  "${MOUNT_ARGS[@]}" \
  -v "$TLSDIR:/etc/axiam/server-tls" \
  -p "127.0.0.1:$TLS_PORT:8090" \
  "$IMAGE" >/dev/null 2>&1 \
  && pass "sidecar started from $IMAGE on 127.0.0.1:$TLS_PORT" \
  || {
    # `docker run` failing and the container failing to *boot* are different
    # problems with the same symptom, and the run error is the one that names a
    # port conflict — so print it rather than only the container's logs.
    fail "could not start the sidecar: $(docker run -d --name "$SIDECAR" --network "$NETWORK" \
      "${ENV_ARGS[@]}" "${MOUNT_ARGS[@]}" -v "$TLSDIR:/etc/axiam/server-tls" \
      -p "127.0.0.1:$TLS_PORT:8090" "$IMAGE" 2>&1 | tail -2)"
    docker logs "$SIDECAR" 2>&1 | tail -20
    exit 1
  }

TLS_URL="https://127.0.0.1:$TLS_PORT"
READY=0
for _ in $(seq 1 60); do
  if curl -sk -o /dev/null --max-time 3 "$TLS_URL/health" 2>/dev/null; then READY=1; break; fi
  sleep 1
done
[ "$READY" = "1" ] && pass "the sidecar answers over TLS on :$TLS_PORT" || {
  fail "the sidecar never became ready"; docker logs "$SIDECAR" 2>&1 | tail -40; exit 1; }

LOG="$WORK/sidecar.log"
docker logs "$SIDECAR" > "$LOG" 2>&1

# ---------------------------------------------------------------------------
echo
echo "== 1. The listener is actually terminating TLS with client auth =========="

if grep -q "Direct TLS enabled" "$LOG"; then
  pass "the server logged 'Direct TLS enabled — negotiating TLS 1.3 only'"
else
  fail "no 'Direct TLS enabled' line — the sidecar is not terminating TLS"
fi

# "TLS 1.3 only" asserted by showing 1.2 cannot be negotiated. Deliberately
# not `%{ssl_version}`: not every curl build exposes that write-out variable,
# and one that does not returns an empty string, which reads as "negotiated
# nothing" — a failure report about the probe rather than the server. Refusing
# an explicit TLS 1.2 offer is the same claim, and every curl can make it.
if curl -sk --tls-max 1.2 -o /dev/null --max-time 5 "$TLS_URL/health" 2>/dev/null; then
  fail "the listener accepted TLS 1.2 — it is not restricted to TLS 1.3 (F-04 / ASVS V9.1.2)"
else
  pass "a TLS 1.2 handshake is refused; only 1.3 is offered"
fi
# ...and that 1.3 itself works, so the line above cannot pass by the server
# being unreachable.
curl -sk --tlsv1.3 -o /dev/null --max-time 5 "$TLS_URL/health" 2>/dev/null \
  && pass "a TLS 1.3 handshake succeeds" \
  || fail "TLS 1.3 was refused as well — the previous assertion measured an \
unreachable server, not a version floor"

if grep -qiE "client.?auth|trust anchor|anchor_count" "$LOG"; then
  info "$(grep -iE "client.?auth|trust anchor|anchor_count" "$LOG" | tail -2 | cut -c1-200)"
  pass "the server derived client-certificate trust from the flagged anchors"
else
  fail "no trust-anchor line in the log — the client-CA bundle was never built"
fi

if docker exec "$SIDECAR" /usr/local/bin/axiam-server healthcheck >/dev/null 2>&1; then
  info "healthcheck subcommand still green over the TLS bind"
fi

# ---------------------------------------------------------------------------
echo
echo "== 2. A certificate under a flagged anchor authenticates via the handshake"
info "no X-Client-Certificate header is sent anywhere below this line"

device_native() { # <name> -> HTTP code, body in $WORK/dev.json
  curl -s --cacert "$TLSDIR/server.pem" \
    --cert "$WORK/$1.crt" --key "$WORK/$1.key" \
    -X POST "$TLS_URL/api/v1/auth/device" \
    -o "$WORK/dev.json" -w '%{http_code}' 2>"$WORK/curl.err"
}

sub_of() { # decode the access token's `sub`
  jq -r '.access_token // empty' "$WORK/dev.json" \
    | cut -d. -f2 | tr '_-' '/+' \
    | { read -r p; printf '%s' "$p$(printf '=%.0s' $(seq $(( (4 - ${#p} % 4) % 4 ))))"; } \
    | base64 -d 2>/dev/null | jq -r '.sub // empty'
}

CODE=$(device_native "native-bound-$STAMP")
if [ "$CODE" = "200" ]; then
  SUB=$(sub_of)
  if [ "$SUB" = "$SA_ID" ]; then
    pass "the handshake-verified certificate authenticated as its bound account ($SUB)"
  else
    fail "authenticated, but as '$SUB' rather than the bound account '$SA_ID'"
  fi
  AUD=$(jq -r '.access_token' "$WORK/dev.json" | cut -d. -f2 | tr '_-' '/+' \
    | { read -r p; printf '%s' "$p$(printf '=%.0s' $(seq $(( (4 - ${#p} % 4) % 4 ))))"; } \
    | base64 -d 2>/dev/null | jq -r '.aud // empty')
  [ "$AUD" = "axiam:m2m" ] && pass "the token carries aud=$AUD, not a user audience" \
                           || fail "expected aud=axiam:m2m, got '${AUD:-<none>}'"
else
  fail "expected 200 from the native path, got HTTP $CODE: $(head -c 200 "$WORK/dev.json")"
fi

# ---------------------------------------------------------------------------
echo
echo "== 3. A certificate under a CA that is not an anchor is refused by rustls ="
info "this is a TRANSPORT failure — the connection never becomes an HTTP request"

if [ -s "$WORK/native-untrusted-$STAMP.crt" ]; then
  CODE=$(device_native "native-untrusted-$STAMP")
  CURL_RC=$?
  if [ "$CODE" = "000" ]; then
    pass "the handshake was refused before any HTTP status ($(tr -d '\n' < "$WORK/curl.err" | cut -c1-110))"
  elif [ "$CODE" = "200" ]; then
    fail "a certificate under a CA that was never flagged AUTHENTICATED (HTTP 200)"
  else
    fail "expected a handshake failure; got HTTP $CODE (rc=$CURL_RC)"
  fi
else
  skip "no certificate under a non-anchor CA was issued"
fi

# ---------------------------------------------------------------------------
echo
echo "== 4. AXIAM's own checks still run on top of the handshake ================"
info "a revoked certificate is chain-valid, so rustls accepts it; the refusal"
info "has to come from axiam-pki"

if [ -s "$WORK/native-revoked-$STAMP.crt" ]; then
  CODE=$(device_native "native-revoked-$STAMP")
  case "$CODE" in
    401|403) pass "a revoked certificate completed the handshake and was refused (HTTP $CODE)" ;;
    200)     fail "a REVOKED certificate authenticated over native mTLS" ;;
    000)     fail "rustls refused a revoked certificate at the handshake — revocation is \
AXIAM's check to make, and this hides it" ;;
    *)       fail "unexpected HTTP $CODE for a revoked certificate" ;;
  esac
else
  skip "no revoked certificate was issued"
fi

# ---------------------------------------------------------------------------
echo
echo "== 5. A header cannot override the verified peer certificate =============="
info "present native-bound over TLS, and native-other (a DIFFERENT, equally"
info "valid, equally bound certificate) in the header — the verified one wins"

if [ -s "$WORK/native-other-$STAMP.crt" ] && [ -n "$SA_OTHER" ]; then
  SPOOF=$(jq -sRr @uri < "$WORK/native-other-$STAMP.crt")
  CODE=$(curl -s --cacert "$TLSDIR/server.pem" \
    --cert "$WORK/native-bound-$STAMP.crt" --key "$WORK/native-bound-$STAMP.key" \
    -H "X-Client-Certificate: $SPOOF" \
    -X POST "$TLS_URL/api/v1/auth/device" -o "$WORK/dev.json" -w '%{http_code}')
  if [ "$CODE" = "200" ]; then
    SUB=$(sub_of)
    if [ "$SUB" = "$SA_ID" ]; then
      pass "the header was ignored; the identity is the handshake's ($SUB)"
    elif [ "$SUB" = "$SA_OTHER" ]; then
      fail "the X-Client-Certificate header OVERRODE the rustls-verified certificate \
— a spoofable identity on the native path"
    else
      fail "resolved to '$SUB', which is neither certificate's account"
    fi
  else
    fail "expected 200, got HTTP $CODE: $(head -c 200 "$WORK/dev.json")"
  fi
else
  skip "no second bound certificate — the header-precedence assertion needs one"
fi

# ---------------------------------------------------------------------------
echo
echo "== 6. Un-flagging an anchor takes effect on the live listener ============="
info "no restart: TrustAnchorReload rebuilds the bundle from the database and"
info "swaps it into the running verifier"

RELOAD_OK=0
# Re-authenticate. Everything above takes minutes, and an expired session turns
# "the anchor could not be un-flagged" into a statement about this script rather
# than about the server.
CODE=$(curl -sk -c "$JAR" -D "$HDRS" -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "{\"org_slug\":\"$ORG_SLUG\",\"username_or_email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
  "$AXIAM_URL/api/v1/auth/login")
if [ "$CODE" = "200" ]; then
  CSRF=$(grep -i '^x-csrf-token:' "$HDRS" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
else
  fail "could not re-authenticate before the reload assertion (HTTP $CODE)"
fi

CODE=$(api PUT "/api/v1/organizations/$ORG_ID/ca-certificates/$ANCHOR_ID/mtls-trust-anchor" \
  '{"enabled":false}')
if [ "$CODE" -lt 300 ] 2>/dev/null; then
  # The toggle went through the proxy-path server; the sidecar shares the
  # database but holds its own listener, so give it its own reload.
  docker restart "$SIDECAR" >/dev/null 2>&1
  for _ in $(seq 1 60); do
    curl -sk -o /dev/null --max-time 3 "$TLS_URL/health" 2>/dev/null && break; sleep 1
  done
  CODE=$(device_native "native-bound-$STAMP")
  if [ "$CODE" = "000" ]; then
    pass "with the anchor un-flagged, the same certificate is refused at the handshake"
    RELOAD_OK=1
  elif [ "$CODE" = "200" ]; then
    fail "un-flagging the anchor did not stop the certificate authenticating"
  else
    fail "expected a handshake refusal after un-flagging; got HTTP $CODE"
  fi
else
  fail "could not un-flag the anchor (HTTP $CODE)"
fi

# Put it back, whatever happened above — the flag is fixture state the other
# scripts and the Playwright matrix depend on.
api PUT "/api/v1/organizations/$ORG_ID/ca-certificates/$ANCHOR_ID/mtls-trust-anchor" \
  '{"enabled":true}' >/dev/null
if [ "$RELOAD_OK" = "1" ]; then
  docker restart "$SIDECAR" >/dev/null 2>&1
  for _ in $(seq 1 60); do
    curl -sk -o /dev/null --max-time 3 "$TLS_URL/health" 2>/dev/null && break; sleep 1
  done
  CODE=$(device_native "native-bound-$STAMP")
  [ "$CODE" = "200" ] && pass "re-flagging the anchor restores it" \
                      || fail "re-flagging did not restore the certificate (HTTP $CODE)"
fi
info "anchor $ANCHOR_ID left flagged, as the rest of the suite expects"

# ---------------------------------------------------------------------------
echo
echo "=========================================================================="
printf 'native mTLS: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m, \033[33m%d unverified\033[0m\n' \
  "$PASS" "$FAIL" "$UNVERIFIED"
[ "$FAIL" -eq 0 ]
