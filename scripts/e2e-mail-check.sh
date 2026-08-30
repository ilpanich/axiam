#!/usr/bin/env bash
# e2e-mail-check.sh — assert AXIAM's transactional mail flows at the server log.
#
# There is no mailbox in this exercise, and there does not need to be: what is
# under test is that AXIAM *sends*, not that a provider delivers. The server
# logs one `sending email` line per attempt, carrying a `provider` field, and
# that line is the signal.
#
# The reason this is a script and not a Playwright spec: every assertion here is
# about the *absence or presence of a log line*, correlated with an API call.
# That is a container-log question, and a browser is the wrong instrument for it.
#
# ---------------------------------------------------------------------------
# The trap this exists to catch
# ---------------------------------------------------------------------------
#
# `POST /api/v1/auth/reset` answers `{"sent": true}` for EVERY outcome, by
# design (D-15) — an unknown address and an unknown organization must be
# indistinguishable from a real one, or the endpoint becomes an account
# enumeration oracle. So the response body cannot tell a working reset from a
# silently broken one, and a test that only checks the body passes vacuously
# against a server that queues nothing at all.
#
# The log is the only place the difference is visible. This script therefore
# asserts BOTH directions:
#
#   * a reset for a real principal produces exactly one `sending email` line;
#   * a reset for an unknown address, and one naming an unknown organization,
#     produce NONE — while both still answer `{"sent": true}`.
#
# ---------------------------------------------------------------------------
# Before anything else: is the consumer even alive?
# ---------------------------------------------------------------------------
#
# Without an email encryption key the server logs
#   "Mail consumer NOT spawned — ... NO transactional mail will be delivered"
# and every mail assertion below passes vacuously against an API that still
# looks healthy. That is checked first, and it is fatal.
#
# Usage:
#   scripts/e2e-mail-check.sh [--compose-file docker/docker-compose.prod.yml]
#
# Environment (with defaults matching scripts/e2e-bootstrap.sh):
#   AXIAM_URL          backend base URL          (default https://localhost)
#   E2E_ORG_SLUG       organization slug         (default test-org)
#   E2E_TENANT_SLUG    tenant slug               (default default)
#   E2E_ADMIN_EMAIL    the org super-admin       (default admin@axiam.dev)
#   E2E_ADMIN_PASSWORD its password              (default Test@Admin123!)
#
# ---------------------------------------------------------------------------
# Why this mints its own probe users
# ---------------------------------------------------------------------------
#
# `PasswordResetService` caps a single user at MAX_RESETS_PER_DAY = 3, and a
# request over the cap funnels into the same enumeration-safe
# `{"sent": true}` with no mail queued — correct behaviour, and indistinguishable
# from the broken case this script exists to detect. Running the script four
# times in a day against a fixed address would therefore start reporting a
# working system as broken.
#
# So each run creates a throwaway user per scope, with a fresh daily budget:
# one in the organization scope, one in the tenant. They are left behind
# (AXIAM anonymises rather than hard-deletes, and a test stack is the wrong
# place to exercise that); they are named `mx-mailprobe-<epoch>` so a run can
# be told from the fixture.

set -uo pipefail

AXIAM_URL="${AXIAM_URL:-https://localhost}"
ORG_SLUG="${E2E_ORG_SLUG:-test-org}"
TENANT_SLUG="${E2E_TENANT_SLUG:-default}"
ADMIN_EMAIL="${E2E_ADMIN_EMAIL:-admin@axiam.dev}"
ADMIN_PASSWORD="${E2E_ADMIN_PASSWORD:-Test@Admin123!}"
SERVICE="${AXIAM_SERVICE:-axiam-server}"

command -v jq >/dev/null 2>&1 || { echo "[e2e-mail-check] ERROR: 'jq' is required on PATH"; exit 1; }

PASS=0
FAIL=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; PASS=$((PASS + 1)); }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAIL=$((FAIL + 1)); }
info() { printf '  ---- %s\n' "$1"; }

# `docker logs` on the container by name: it needs no compose interpolation,
# which the prod compose file demands in quantity even for a read-only
# subcommand.
logs_since() { docker logs --since "$1" "$SERVICE" 2>&1; }

# The trailing `Z` is load-bearing. `docker logs --since` reads a bare
# timestamp as LOCAL time, so a UTC instant emitted without a zone is read as
# local and the window silently opens hours early — on a UTC+2 host every
# "window" was two hours wide, every probe saw every earlier message's retries,
# and the consumer appeared never to go quiet. An RFC 3339 instant is
# unambiguous.
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }

# ---------------------------------------------------------------------------
echo "== 0. Is the mail consumer alive? =========================================="
BOOT_LOG=$(docker logs "$SERVICE" 2>&1 | grep -E 'Mail consumer' | tail -1)
if [ -z "$BOOT_LOG" ]; then
  fail "no 'Mail consumer' line in the server log at all — cannot tell whether mail is wired up"
elif printf '%s' "$BOOT_LOG" | grep -q 'NOT spawned'; then
  fail "Mail consumer NOT spawned. Every assertion below would pass vacuously."
  info "$BOOT_LOG"
  echo
  echo "Set AXIAM__EMAIL_ENCRYPTION_KEY (or seed email_encryption_key into the"
  echo "configured secret provider) and restart the server. Nothing is delivered"
  echo "without it, and the API still looks healthy: /auth/reset answers"
  echo '{"sent": true} for every outcome by design.'
  exit 1
else
  pass "Mail consumer spawned"
fi

# ---------------------------------------------------------------------------
# Each probe: mark the clock, make the call, read the log written since.
# ---------------------------------------------------------------------------
# Waits until the mail consumer has been quiet for a few seconds.
#
# Necessary because the assertions below are "did THIS call produce a mail?",
# measured as "were there mail lines in the window after it" — and the consumer
# retries a failed delivery twice with a 20s backoff before dead-lettering. A
# probe fired while an earlier message is still retrying counts that message's
# lines and reports a mail nobody asked for. Waiting for quiet first is what
# makes the window belong to the probe.
# The window must be LONGER than the consumer's largest retry backoff, or a
# quiet stretch inside a backoff reads as "settled" and the retry then lands in
# the next probe's window and is counted as its mail. The schedule is
# immediate → 10s → 20s → dead-letter, so 25s is the smallest honest choice.
QUIET_WINDOW_SECS=25

wait_for_quiet() {
  local waited=0 marker
  while [ "$waited" -lt 180 ]; do
    marker=$(now)
    sleep "$QUIET_WINDOW_SECS"
    if [ "$(logs_since "$marker" | grep -cE 'mail_consumer|sending email')" -eq 0 ]; then
      return 0
    fi
    waited=$((waited + QUIET_WINDOW_SECS))
  done
  info "mail consumer never went quiet after ${waited}s — the next result may include retry noise"
  return 1
}

probe() {
  local label="$1" expect_send="$2" body="$3"
  local since http out attempt
  wait_for_quiet
  # `password_reset_per_min` is 3 in the shipped posture and this script makes
  # four reset calls, so a 429 is expected rather than exceptional. Wait out the
  # window instead of reporting the limiter as a mail defect.
  for attempt in 1 2 3 4 5; do
    since=$(now)
    http=$(curl -sk -o /tmp/mailprobe.json -w '%{http_code}' \
      -X POST "$AXIAM_URL/api/v1/auth/reset" \
      -H 'Content-Type: application/json' -d "$body")
    [ "$http" != "429" ] && break
    info "$label: rate-limited (password_reset_per_min); waiting out the window"
    sleep 21
  done
  # Give the AMQP round trip a moment: the handler enqueues, the consumer sends.
  sleep 4
  out=$(logs_since "$since" | grep -c 'sending email')

  # Every outcome must answer 200 {"sent": true} — that is the enumeration-safe
  # contract, and it is asserted for the silent cases too, because a 404 there
  # would leak exactly what the design refuses to leak.
  if [ "$http" = "200" ] && grep -q '"sent":true' /tmp/mailprobe.json; then
    pass "$label: answered 200 {\"sent\":true} (enumeration-safe)"
  else
    fail "$label: expected 200 {\"sent\":true}, got HTTP $http $(head -c 120 /tmp/mailprobe.json)"
  fi

  # Two distinguishable signals, and the difference matters:
  #   `sending email`  — the consumer reached a provider and attempted delivery.
  #   mail_consumer line naming a `mail_type` — the message was enqueued, routed
  #                      and picked up, but no provider is configured for that
  #                      org/tenant, so there was nothing to attempt.
  # The property under test is that the RESET RESOLVED A PRINCIPAL AND QUEUED
  # MAIL. Both lines prove that; only the first proves delivery was attempted.
  # Conflating them would report an unconfigured provider as the reset bug.
  local queued
  queued=$(logs_since "$since" | grep -c 'mail_consumer')

  if [ "$expect_send" = "yes" ]; then
    if [ "$out" -ge 1 ]; then
      pass "$label: $out 'sending email' line(s) — delivery was attempted"
      logs_since "$since" | grep 'sending email' | head -1 | sed 's/^/       /'
    elif [ "$queued" -ge 1 ]; then
      fail "$label: mail WAS queued and consumed, but no delivery was attempted — no email provider is configured for this scope"
      logs_since "$since" | grep 'mail_consumer' | head -1 | sed 's/^/       /'
    else
      fail "$label: NOTHING was queued. The endpoint answered success and resolved no principal."
    fi
  else
    if [ "$out" -eq 0 ] && [ "$queued" -eq 0 ]; then
      pass "$label: nothing queued and nothing sent, as required — the silence is the assertion"
    else
      fail "$label: $out send(s) / $queued consumer line(s) for a principal that does not exist"
    fi
  fi

  local errs
  errs=$(logs_since "$since" | grep -c 'mail_consumer.*ERROR')
  [ "$errs" -eq 0 ] || fail "$label: $errs mail-consumer ERROR line(s) accompanied the attempt"
}

# ---------------------------------------------------------------------------
echo
echo "== 0b. Minting a probe user per scope ======================================"

JAR=$(mktemp); HDRS=$(mktemp)
trap 'rm -f "$JAR" "$HDRS"' EXIT

LOGIN_CODE=$(curl -sk -c "$JAR" -D "$HDRS" -o /dev/null -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d "{\"org_slug\":\"$ORG_SLUG\",\"username_or_email\":\"$ADMIN_EMAIL\",\"password\":\"$ADMIN_PASSWORD\"}" \
  "$AXIAM_URL/api/v1/auth/login")
if [ "$LOGIN_CODE" != "200" ]; then
  fail "organization-level sign-in as $ADMIN_EMAIL returned $LOGIN_CODE — cannot mint probe users"
  exit 1
fi
CSRF=$(grep -i '^x-csrf-token:' "$HDRS" | tail -1 | tr -d '\r' | cut -d' ' -f2-)
ORG_ID=$(curl -sk -b "$JAR" "$AXIAM_URL/api/v1/organizations" \
  | jq -r --arg s "$ORG_SLUG" '(.items // .) | map(select(.slug == $s)) | .[0].id // empty')
TENANT_ID=$(curl -sk -b "$JAR" "$AXIAM_URL/api/v1/organizations/$ORG_ID/tenants" \
  | jq -r --arg s "$TENANT_SLUG" '(.items // .) | map(select(.slug == $s)) | .[0].id // empty')

STAMP=$(date +%s)

# `$2` is the acting tenant, or empty for the organization's own scope.
mint_probe_user() {
  local username="$1" acting="$2" code id
  local -a hdr=(-H 'Content-Type: application/json' -H "X-CSRF-Token: $CSRF")
  [ -n "$acting" ] && hdr+=(-H "X-Axiam-Tenant: $acting")
  code=$(curl -sk -b "$JAR" -o /tmp/mailuser.json -w '%{http_code}' \
    "${hdr[@]}" \
    -d "{\"username\":\"$username\",\"email\":\"$username@axiam.dev\",\"password\":\"$ADMIN_PASSWORD\"}" \
    "$AXIAM_URL/api/v1/users")
  [ "$code" = "201" ] || { echo ""; return 1; }
  id=$(jq -r '.id' /tmp/mailuser.json)
  # REST-created users land PendingVerification; activate so the account is a
  # normal one and the reset path is not exercising a special case.
  curl -sk -b "$JAR" -X PUT -o /dev/null "${hdr[@]}" -d '{"status":"Active"}' \
    "$AXIAM_URL/api/v1/users/$id" >/dev/null
  echo "$username@axiam.dev"
}

ORG_PROBE_EMAIL=$(mint_probe_user "mx-mailprobe-org-$STAMP" "")
TENANT_PROBE_EMAIL=$(mint_probe_user "mx-mailprobe-tenant-$STAMP" "$TENANT_ID")

if [ -n "$ORG_PROBE_EMAIL" ]; then
  pass "organization-scope probe user: $ORG_PROBE_EMAIL"
else
  fail "could not mint an organization-scope probe user; falling back to $ADMIN_EMAIL (may be over its daily reset cap)"
  ORG_PROBE_EMAIL="$ADMIN_EMAIL"
fi
if [ -n "$TENANT_PROBE_EMAIL" ]; then
  pass "tenant-scope probe user: $TENANT_PROBE_EMAIL"
else
  fail "could not mint a tenant-scope probe user; falling back to tenant-admin@axiam.dev (may be over its daily reset cap)"
  TENANT_PROBE_EMAIL="tenant-admin@axiam.dev"
fi

echo
echo "== 1. Password reset at ORGANIZATION level ================================="
info "an organization-level sign-in carries an org slug and NO tenant; this is the"
info "shape that once resolved to nothing and answered {\"sent\": true} regardless"
probe "org-level reset for a real principal" yes \
  "{\"org_slug\":\"$ORG_SLUG\",\"email\":\"$ORG_PROBE_EMAIL\"}"

echo
echo "== 2. Password reset at TENANT level ======================================="
probe "tenant-level reset for a real principal" yes \
  "{\"org_slug\":\"$ORG_SLUG\",\"tenant_slug\":\"$TENANT_SLUG\",\"email\":\"$TENANT_PROBE_EMAIL\"}"

echo
echo "== 3. The silences ========================================================="
info "same answer, no mail — the difference is visible only in the log, which is"
info "exactly why a body-only test cannot tell these from the cases above"
probe "reset for an address that does not exist" no \
  "{\"org_slug\":\"$ORG_SLUG\",\"tenant_slug\":\"$TENANT_SLUG\",\"email\":\"nobody-at-all@example.invalid\"}"
probe "reset naming an organization that does not exist" no \
  "{\"org_slug\":\"no-such-org-anywhere\",\"email\":\"$ORG_PROBE_EMAIL\"}"

echo
echo "==========================================================================="
printf 'mail checks: \033[32m%d passed\033[0m, \033[31m%d failed\033[0m\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ]
