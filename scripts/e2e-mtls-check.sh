#!/usr/bin/env bash
# e2e-mtls-check.sh — certificate-based authentication, from outside the browser.
#
# `E2E-TESTS.md` §4: "This is the one area where a green browser suite proves
# nothing." A Playwright run never presents a client certificate, so every
# assertion about what a certificate authenticates *as* has to be made by a
# client that holds one.
#
# ---------------------------------------------------------------------------
# What is asserted, and against which path
# ---------------------------------------------------------------------------
#
# `POST /api/v1/auth/device` resolves a client certificate to the service
# account it is bound to. It accepts the certificate two ways, and they are NOT
# equivalent:
#
#   1. **Native mTLS** — rustls verifies the certificate at handshake time
#      against the client-CA bundle the server builds from the organization CAs
#      flagged `mtls_trust_anchor`, and the verified DER is what the extractor
#      reads. Requires the server to terminate TLS itself
#      (`AXIAM__SERVER__TLS__ENABLED=true` + `CLIENT_AUTH`).
#   2. **`X-Client-Certificate` header** — the path for a deployment that
#      terminates TLS at a reverse proxy, which is what
#      `docker-compose.prod.yml` does. The proxy is then responsible for the
#      handshake; AXIAM still performs its own checks in `axiam-pki`'s
#      `mtls.rs`: fingerprint lookup, revocation status, validity window, chain
#      verification to the issuing CA, and the service-account binding.
#
# This script drives path 2 — the one this stack actually exposes — and says so
# for each result. Where an assertion can only be settled by a TLS handshake it
# is reported as **UNVERIFIED**, never as a pass.
#
# Requires: an org super-admin, and `jq`. Issues its own certificates, because a
# private key is returned exactly once, at generation, and never stored.
#
# Usage: scripts/e2e-mtls-check.sh
#
# Environment:
#   AXIAM_URL          default https://localhost
#   E2E_ORG_SLUG       default test-org
#   E2E_TENANT_SLUG    default default
#   E2E_ADMIN_EMAIL    default admin@axiam.dev
#   E2E_ADMIN_PASSWORD default Test@Admin123!

set -uo pipefail

AXIAM_URL="${AXIAM_URL:-https://localhost}"
ORG_SLUG="${E2E_ORG_SLUG:-test-org}"
TENANT_SLUG="${E2E_TENANT_SLUG:-default}"
ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-admin@axiam.dev}"
ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-Test@Admin123!}"

PASS=0; FAIL=0; UNVERIFIED=0
pass()  { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
fail()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }
skip()  { printf '  \033[33mUNVERIFIED\033[0m %s\n' "$1"; UNVERIFIED=$((UNVERIFIED + 1)); }
info()  { printf '  ---- %s\n' "$1"; }

command -v jq >/dev/null 2>&1 || { echo "ERROR: jq is required"; exit 1; }

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
JAR="$WORK/jar"; HDRS="$WORK/hdrs"

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
echo "== Building the certificate fixture ======================================="
info "the private key is returned ONCE, at generation, and never stored — so a"
info "client certificate has to be issued here rather than looked up"

# The trust anchor: an organization CA flagged as one. Reused across runs when
# present, because flagging is what the native-mTLS bundle is built from.
ANCHOR_ID=$(curl -sk -b "$JAR" "$AXIAM_URL/api/v1/organizations/$ORG_ID/ca-certificates" \
  | jq -r 'map(select(.mtls_trust_anchor == true)) | .[0].id // empty' 2>/dev/null)
if [ -z "$ANCHOR_ID" ]; then
  CODE=$(api POST "/api/v1/organizations/$ORG_ID/ca-certificates" \
    "{\"subject\":\"CN=mx-mtls-anchor-$STAMP\",\"key_algorithm\":\"Ed25519\",\"validity_days\":90}")
  ANCHOR_ID=$(jq -r '.id // empty' "$WORK/resp.json")
  [ -n "$ANCHOR_ID" ] || { fail "could not mint a CA (HTTP $CODE): $(head -c 200 "$WORK/resp.json")"; exit 1; }
  api PUT "/api/v1/organizations/$ORG_ID/ca-certificates/$ANCHOR_ID/mtls-trust-anchor" '{"enabled":true}' >/dev/null
fi
pass "trusted anchor CA: $ANCHOR_ID"

# A second CA that is deliberately NOT an anchor.
UNTRUSTED_ID=$(curl -sk -b "$JAR" "$AXIAM_URL/api/v1/organizations/$ORG_ID/ca-certificates" \
  | jq -r 'map(select(.mtls_trust_anchor != true)) | .[0].id // empty' 2>/dev/null)
if [ -z "$UNTRUSTED_ID" ]; then
  api POST "/api/v1/organizations/$ORG_ID/ca-certificates" \
    "{\"subject\":\"CN=mx-mtls-untrusted-$STAMP\",\"key_algorithm\":\"Ed25519\",\"validity_days\":90}" >/dev/null
  UNTRUSTED_ID=$(jq -r '.id // empty' "$WORK/resp.json")
fi
pass "untrusted CA (never flagged): ${UNTRUSTED_ID:-<none>}"

# issue <name> <issuer-ca-id>  -> writes $WORK/<name>.crt and .key
issue() {
  local name="$1" ca="$2" code
  code=$(api POST "/api/v1/certificates" \
    "{\"issuer_ca_id\":\"$ca\",\"subject\":\"CN=$name\",\"cert_type\":\"Service\",\"key_algorithm\":\"Ed25519\",\"validity_days\":30}")
  if [ "$code" != "201" ] && [ "$code" != "200" ]; then
    fail "issuing $name returned HTTP $code: $(head -c 200 "$WORK/resp.json")"
    return 1
  fi
  # `public_cert_pem` is the field name on `Certificate` (sdks/openapi.json);
  # the alternatives are kept as a fallback for a response shape that nests it.
  jq -r '.public_cert_pem // .certificate.public_cert_pem // empty' "$WORK/resp.json" > "$WORK/$name.crt"
  jq -r '.private_key_pem // empty'        "$WORK/resp.json" > "$WORK/$name.key"
  jq -r '.id'                              "$WORK/resp.json" > "$WORK/$name.id"
  [ -s "$WORK/$name.crt" ] || { fail "$name: no certificate PEM in the response"; return 1; }
  return 0
}

SA_ID=""
create_sa() {
  local name="$1"
  api POST "/api/v1/service-accounts" "{\"name\":\"$name\",\"description\":\"mtls check\"}" >/dev/null
  jq -r '.id // empty' "$WORK/resp.json"
}

SA_ID=$(create_sa "mx-mtls-sa-$STAMP")
[ -n "$SA_ID" ] && pass "service account: $SA_ID" || fail "could not create a service account"

issue "bound-$STAMP"     "$ANCHOR_ID"    && pass "issued bound-$STAMP under the trusted anchor"
issue "unbound-$STAMP"   "$ANCHOR_ID"    && pass "issued unbound-$STAMP (bound to nothing)"
issue "revoked-$STAMP"   "$ANCHOR_ID"    && pass "issued revoked-$STAMP"
[ -n "$UNTRUSTED_ID" ] && issue "untrusted-$STAMP" "$UNTRUSTED_ID" \
  && pass "issued untrusted-$STAMP under the CA that is not an anchor"

# The untrusted certificate is bound to its OWN service account on purpose.
# Unbound, it would be refused — but for the wrong reason, and the assertion
# "a certificate under an untrusted CA is refused" would pass without testing
# trust at all. Binding it removes the other explanation.
if [ -s "$WORK/untrusted-$STAMP.id" ]; then
  SA_UNTRUSTED=$(create_sa "mx-mtls-sa-untrusted-$STAMP")
  [ -n "$SA_UNTRUSTED" ] && api POST "/api/v1/service-accounts/$SA_UNTRUSTED/bind-certificate" \
    "{\"certificate_id\":\"$(cat "$WORK/untrusted-$STAMP.id")\"}" >/dev/null \
    && pass "untrusted-$STAMP is bound, so a refusal can only be about trust"
fi

# Bind one, revoke another.
if [ -n "$SA_ID" ] && [ -s "$WORK/bound-$STAMP.id" ]; then
  CODE=$(api POST "/api/v1/service-accounts/$SA_ID/bind-certificate" \
    "{\"certificate_id\":\"$(cat "$WORK/bound-$STAMP.id")\"}")
  [ "$CODE" -lt 300 ] && pass "bound-$STAMP is bound to the service account" \
                      || fail "binding returned HTTP $CODE: $(head -c 200 "$WORK/resp.json")"
fi
if [ -s "$WORK/revoked-$STAMP.id" ]; then
  CODE=$(api POST "/api/v1/certificates/$(cat "$WORK/revoked-$STAMP.id")/revoke" '{}')
  [ "$CODE" -lt 300 ] && pass "revoked-$STAMP is revoked" || fail "revoke returned HTTP $CODE"
  # Bind it too: a revoked certificate that is ALSO unbound would be refused for
  # the wrong reason, and the assertion would pass without testing revocation.
  SA2=$(create_sa "mx-mtls-sa-revoked-$STAMP")
  [ -n "$SA2" ] && api POST "/api/v1/service-accounts/$SA2/bind-certificate" \
    "{\"certificate_id\":\"$(cat "$WORK/revoked-$STAMP.id")\"}" >/dev/null
fi

# ---------------------------------------------------------------------------
# Percent-encode a PEM for the header, exactly as a reverse proxy does.
urlencode() { jq -sRr @uri < "$1"; }

device_auth() { # <cert file> -> HTTP code, body in $WORK/dev.json
  curl -sk -X POST "$AXIAM_URL/api/v1/auth/device" \
    -H "X-Client-Certificate: $(urlencode "$1")" \
    -o "$WORK/dev.json" -w '%{http_code}'
}

echo
echo "== Certificate authentication (proxy-terminated path) ====================="
info "POST /api/v1/auth/device with X-Client-Certificate — the path this stack"
info "exposes, since TLS terminates at the reverse proxy. AXIAM still performs"
info "its own fingerprint, revocation, validity, chain and binding checks."

if [ -s "$WORK/bound-$STAMP.crt" ]; then
  CODE=$(device_auth "$WORK/bound-$STAMP.crt")
  if [ "$CODE" = "200" ]; then
    # `DeviceAuthResponse` carries an access token, not the principal — so the
    # question "which account did it resolve to?" is answered by the token's
    # own `sub` claim, which is what every downstream authorization decision
    # will key on. Decoding the payload is enough; its signature is the
    # server's own and is not what this asserts.
    RESOLVED=$(jq -r '.access_token' "$WORK/dev.json" \
      | cut -d. -f2 \
      | python3 -c 'import sys,base64,json; p=sys.stdin.read().strip(); p+="="*(-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p)).get("sub",""))' 2>/dev/null)
    if [ "$RESOLVED" = "$SA_ID" ]; then
      pass "a bound certificate authenticates AS THE ACCOUNT IT IS BOUND TO (token sub = $RESOLVED)"
    else
      fail "a bound certificate authenticated, but its token's sub is '$RESOLVED', not $SA_ID"
    fi
    AUD=$(jq -r '.access_token' "$WORK/dev.json" | cut -d. -f2 \
      | python3 -c 'import sys,base64,json; p=sys.stdin.read().strip(); p+="="*(-len(p)%4); print(json.loads(base64.urlsafe_b64decode(p)).get("aud",""))' 2>/dev/null)
    [ "$AUD" = "axiam:m2m" ] \
      && pass "and the token carries the machine audience ($AUD), not a user one" \
      || fail "the device token's audience is '$AUD'; a certificate identifies a machine, so it must be axiam:m2m"
  else
    fail "a bound certificate was refused: HTTP $CODE $(head -c 200 "$WORK/dev.json")"
  fi
fi

if [ -s "$WORK/unbound-$STAMP.crt" ]; then
  CODE=$(device_auth "$WORK/unbound-$STAMP.crt")
  [ "$CODE" != "200" ] \
    && pass "a certificate bound to no service account is refused (HTTP $CODE)" \
    || fail "a certificate bound to NO service account authenticated (HTTP 200)"
fi

if [ -s "$WORK/revoked-$STAMP.crt" ]; then
  CODE=$(device_auth "$WORK/revoked-$STAMP.crt")
  [ "$CODE" != "200" ] \
    && pass "a revoked certificate is refused (HTTP $CODE)" \
    || fail "a REVOKED certificate authenticated (HTTP 200) — revocation has no effect here"
fi

if [ -s "$WORK/untrusted-$STAMP.crt" ]; then
  CODE=$(device_auth "$WORK/untrusted-$STAMP.crt")
  if [ "$CODE" != "200" ]; then
    pass "a certificate under a CA that is not a trust anchor is refused (HTTP $CODE)"
  else
    fail "a certificate under a CA that is NOT flagged as an mTLS trust anchor authenticated.
       On the native-mTLS path rustls refuses it at the handshake, because the client-CA
       bundle contains only flagged anchors. On this proxy-terminated path the check is
       AXIAM's own, and it verifies the chain to whichever CA issued the certificate —
       so un-flagging a CA does not stop certificates under it from authenticating."
  fi
fi

# --- unbinding must take effect immediately -------------------------------
if [ -n "$SA_ID" ] && [ -s "$WORK/bound-$STAMP.id" ]; then
  echo
  echo "== Revoking the binding ==================================================="
  CODE=$(api DELETE "/api/v1/service-accounts/$SA_ID" "")
  if [ "$CODE" -lt 300 ]; then
    AFTER=$(device_auth "$WORK/bound-$STAMP.crt")
    [ "$AFTER" != "200" ] \
      && pass "deleting the service account stops its certificate authenticating (HTTP $AFTER)" \
      || fail "the certificate still authenticates after its service account was deleted"
  else
    skip "could not delete the service account (HTTP $CODE) — binding revocation not measured"
  fi
fi

# ---------------------------------------------------------------------------
echo
echo "== Native mTLS (TLS handshake) ============================================"
TLS_ON=$(docker exec axiam-server printenv AXIAM__SERVER__TLS__ENABLED 2>/dev/null || echo "")
if [ "$TLS_ON" = "true" ]; then
  info "direct TLS is enabled; presenting the certificate at the handshake"
  CODE=$(curl -s -o "$WORK/mtls.json" -w '%{http_code}' \
    --cert "$WORK/bound-$STAMP.crt" --key "$WORK/bound-$STAMP.key" -k \
    -X POST "$AXIAM_URL/api/v1/auth/device" || echo "000")
  [ "$CODE" = "200" ] && pass "a client certificate authenticates over a real TLS handshake" \
                      || fail "native mTLS returned HTTP $CODE: $(head -c 200 "$WORK/mtls.json")"
else
  skip "the server does not terminate TLS (AXIAM__SERVER__TLS__ENABLED is not true),
       so the handshake half of §4 is not measured. It needs
       AXIAM__SERVER__TLS__ENABLED=true, CERT_PATH, KEY_PATH and
       CLIENT_AUTH=optional|required, plus a published TLS port. The server logs
       exactly this at boot: 'CA certificates are flagged as mTLS trust anchors
       but there is nowhere to write the bundle'."
  skip "and with it: whether a certificate under an unflagged CA is refused AT THE
       HANDSHAKE, which is where the mtls_trust_anchor flag actually takes effect."
fi

echo
echo "==========================================================================="
printf 'mTLS checks: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m, \033[33m%d unverified\033[0m\n' \
  "$PASS" "$FAIL" "$UNVERIFIED"
[ "$FAIL" -eq 0 ]
