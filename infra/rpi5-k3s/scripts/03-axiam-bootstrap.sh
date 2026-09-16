#!/usr/bin/env bash
# AXIAM's own first-run configuration: the bootstrap call, and the federation
# configs.
#
# WHY THIS IS NOT OPENTOFU. There is no AXIAM provider, and a generic REST
# provider would be the wrong shape for what these two calls are.
# `POST /api/v1/admin/bootstrap` is ONE-SHOT — a `bootstrap_lock:global`
# uniqueness invariant means a second call answers 409 — and fail-closed: it
# refuses unless AXIAM_BOOTSTRAP_ADMIN_EMAIL matches the request, or the request
# carries a one-time setup token the server printed once, at first boot, in its
# log. That is the opposite of a resource that converges. A script that reads
# the token out of the pod log and posts twice is honest about what it is.
#
# IDEMPOTENT, and by asking rather than inferring: it signs in first, and skips
# the bootstrap if the super-admin already authenticates. With a setup token the
# 409 branch is unreachable — the token is consumed by the first success, so a
# second call is refused by the GATE (403) before anything checks whether the
# system is initialised.
#
# Usage:
#   AXIAM_ADMIN_PASSWORD='...' ./03-axiam-bootstrap.sh
#   AXIAM_ADMIN_PASSWORD='...' ./03-axiam-bootstrap.sh --federation providers.yml
#
# Environment:
#   AXIAM_HOST            public hostname   (default: axiam-iam.duckdns.org)
#   AXIAM_ORG_NAME        (default: Home Lab)
#   AXIAM_ORG_SLUG        (default: homelab)
#   AXIAM_ADMIN_EMAIL     must match AXIAM_BOOTSTRAP_ADMIN_EMAIL in the overlay,
#                         unless a setup token is used
#   AXIAM_ADMIN_USERNAME  (default: admin)
#   AXIAM_ADMIN_PASSWORD  REQUIRED. Pass it through the environment, not as an
#                         argument — arguments are in /proc and in your history.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

HOST="${AXIAM_HOST:-axiam-iam.duckdns.org}"
BASE="https://${HOST}"
NS="${AXIAM_NAMESPACE:-axiam}"
ORG_NAME="${AXIAM_ORG_NAME:-Home Lab}"
ORG_SLUG="${AXIAM_ORG_SLUG:-homelab}"
ADMIN_EMAIL="${AXIAM_ADMIN_EMAIL:-}"
ADMIN_USERNAME="${AXIAM_ADMIN_USERNAME:-admin}"
FEDERATION_FILE=""

while (( $# )); do
    case "$1" in
        --federation) FEDERATION_FILE="${2:?--federation needs a file}"; shift 2 ;;
        -h | --help) sed -n '2,32p' "${BASH_SOURCE[0]}"; exit 0 ;;
        *) die "Unknown argument: $1" ;;
    esac
done

need kubectl; need jq; need curl
: "${AXIAM_ADMIN_PASSWORD:?AXIAM_ADMIN_PASSWORD is required. Set it with \`read -rs AXIAM_ADMIN_PASSWORD && export AXIAM_ADMIN_PASSWORD\` so it does not land in your shell history.}"

if [[ -z "$ADMIN_EMAIL" ]]; then
    ADMIN_EMAIL="$(kubectl -n "$NS" get configmap axiam-config \
        -o jsonpath='{.data.AXIAM_BOOTSTRAP_ADMIN_EMAIL}' 2>/dev/null || true)"
    [[ -n "$ADMIN_EMAIL" ]] || die "Could not read AXIAM_BOOTSTRAP_ADMIN_EMAIL from
  the axiam-config ConfigMap, and AXIAM_ADMIN_EMAIL is not set. One of the two
  has to name the first administrator — bootstrap is fail-closed without it."
    say "Admin email from the ConfigMap: $ADMIN_EMAIL"
fi

# Everything below goes through the PUBLIC front door, on purpose: it exercises
# DNS, the router's port forward, the ingress, the public certificate and the
# backend leg in one go. If this script works, the deployment works. Every call
# verifies the certificate; there is no -k anywhere in this tree, and a TLS
# failure here is a finding, not an obstacle.

# ---------------------------------------------------------------------------
# 1. Is it already bootstrapped? Ask, do not infer.
# ---------------------------------------------------------------------------
login_body="$(jq -nc --arg o "$ORG_SLUG" --arg u "$ADMIN_EMAIL" --arg p "$AXIAM_ADMIN_PASSWORD" \
    '{org_slug:$o, username_or_email:$u, password:$p}')"

probe="$(curl -sS -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
    -d "$login_body" "${BASE}/api/v1/auth/login" || echo 000)"

case "$probe" in
    200) ok "Already bootstrapped — $ADMIN_EMAIL signs in. Skipping bootstrap." ;;
    000) die "Could not reach ${BASE}/api/v1/auth/login at all.
  Work outwards: 05-verify.sh checks each hop separately, which is faster than
  guessing which one is broken." ;;
    *)
        # -----------------------------------------------------------------
        # 2. The setup token, from the FIRST-BOOT log
        # -----------------------------------------------------------------
        # Only needed when the ConfigMap's AXIAM_BOOTSTRAP_ADMIN_EMAIL does not
        # match; harmless to send when it does, since the handler ignores the
        # field then. Read from the log because that is the only place it is
        # ever written — it is minted once and never stored.
        say "Looking for the one-time setup token in the server's log"
        setup_token="$(kubectl -n "$NS" logs deploy/axiam-server --tail=-1 2>/dev/null \
            | grep -o '"setup_token":"[^"]*"' | head -1 | cut -d'"' -f4 || true)"
        if [[ -n "$setup_token" ]]; then
            ok "Found a setup token in the log."
        else
            warn "No setup token in the current log. That is expected if the pod
  has restarted since first boot — the line is printed ONCE and Kubernetes keeps
  only the current container's output. Falling back to the email gate, which
  works as long as AXIAM_BOOTSTRAP_ADMIN_EMAIL matches:
      $ADMIN_EMAIL
  If it does not, and the token is gone, the log of the PREVIOUS container may
  still have it:  kubectl -n $NS logs deploy/axiam-server --previous"
        fi

        body="$(jq -nc \
            --arg org_name "$ORG_NAME" --arg org_slug "$ORG_SLUG" \
            --arg email "$ADMIN_EMAIL" --arg username "$ADMIN_USERNAME" \
            --arg password "$AXIAM_ADMIN_PASSWORD" --arg tok "$setup_token" \
            '{organization_name:$org_name, organization_slug:$org_slug,
              email:$email, username:$username, password:$password}
             + (if $tok == "" then {} else {setup_token:$tok} end)')"

        say "POST /api/v1/admin/bootstrap"
        resp="$(mktemp)"; trap 'rm -f "$resp"' EXIT
        status="$(curl -sS -o "$resp" -w '%{http_code}' -X POST \
            -H 'Content-Type: application/json' -d "$body" \
            "${BASE}/api/v1/admin/bootstrap" || echo 000)"
        case "$status" in
            201) ok "Bootstrapped. Organization '$ORG_SLUG', its organization-scope
  tenant, the permission and role seed, and the super-admin all exist." ;;
            409) ok "Already initialised (409)." ;;
            403) die "403 — the bootstrap gate is not satisfied. Either
  AXIAM_BOOTSTRAP_ADMIN_EMAIL does not match '$ADMIN_EMAIL', or the setup token
  has already been consumed. $(cat "$resp")" ;;
            *) die "Bootstrap returned $status: $(cat "$resp")" ;;
        esac
        ;;
esac

# ---------------------------------------------------------------------------
# 3. Federation configs, if a file was given
# ---------------------------------------------------------------------------
# NOTE ON TENANCY: `handlers::federation::create` writes
# `tenant_id: user.tenant_id` — the tenant of whoever is signed in. As the
# bootstrap super-admin that is the ORGANIZATION-SCOPE tenant, which is
# usually what you want: a config there with `allow_tenant_inheritance: true`
# is visible to every tenant beneath it. To federate into one ordinary tenant
# only, create that tenant first and sign in as a user inside it.
if [[ -z "$FEDERATION_FILE" ]]; then
    echo
    ok "Done. Add identity providers in the admin UI at ${BASE}/login, or re-run
  with --federation providers.yml (see providers.example.yml in this directory)."
    exit 0
fi

[[ -r "$FEDERATION_FILE" ]] || die "Cannot read $FEDERATION_FILE"
need python3

say "Signing in at organization level"
JAR="$(mktemp)"; HDRS="$(mktemp)"
trap 'rm -f "$JAR" "$HDRS" "${resp:-}"' EXIT
login_status="$(curl -sS -o /dev/null -w '%{http_code}' -D "$HDRS" -c "$JAR" \
    -H 'Content-Type: application/json' -d "$login_body" \
    "${BASE}/api/v1/auth/login" || echo 000)"
[[ "$login_status" == "200" ]] || die "Login returned $login_status."
CSRF="$(grep -i '^x-csrf-token:' "$HDRS" | tail -1 | tr -d '\r' | cut -d' ' -f2-)"
[[ -n "$CSRF" ]] || die "No X-CSRF-Token on the login response."
ok "Signed in."

# The YAML is converted to a JSON array here rather than hand-assembled with jq,
# so the file the operator edits can carry comments and multi-line values — an
# Apple .p8 key is multi-line, and that is the single most fiddly value in §10.
mapfile -t CONFIGS < <(python3 - "$FEDERATION_FILE" <<'PY'
import json, sys, yaml
doc = yaml.safe_load(open(sys.argv[1], encoding="utf-8")) or {}
for entry in doc.get("federation_configs") or []:
    # One JSON object per line: the shell reads them as an array of strings.
    print(json.dumps({k: v for k, v in entry.items() if v is not None}))
PY
)

(( ${#CONFIGS[@]} )) || die "No entries under 'federation_configs:' in $FEDERATION_FILE"

existing="$(curl -sS -b "$JAR" -c "$JAR" "${BASE}/api/v1/federation-configs" 2>/dev/null \
    | jq -r '(.items // .) | map(.provider) | join("\n")' 2>/dev/null || true)"

for cfg in "${CONFIGS[@]}"; do
    provider="$(printf '%s' "$cfg" | jq -r '.provider')"
    if printf '%s\n' "$existing" | grep -Fxq "$provider"; then
        ok "Provider '$provider' already configured — skipping."
        continue
    fi
    say "POST /api/v1/federation-configs — $provider"
    resp="$(mktemp)"
    status="$(curl -sS -o "$resp" -w '%{http_code}' -X POST \
        -b "$JAR" -c "$JAR" -H "X-CSRF-Token: ${CSRF}" \
        -H 'Content-Type: application/json' -d "$cfg" \
        "${BASE}/api/v1/federation-configs" || echo 000)"
    case "$status" in
        200 | 201) ok "$provider created and enabled." ;;
        *)
            warn "$provider returned $status: $(cat "$resp")"
            if grep -q 'federation encryption key' "$resp" 2>/dev/null; then
                warn "  That specific message means 'federation_encryption_key' is
  missing from Vault. Re-run stage 30 (which runs scripts/vault-seed.sh) and
  restart the server:  kubectl -n $NS rollout restart deploy/axiam-server"
            fi
            ;;
    esac
    rm -f "$resp"
done

echo
ok "Open ${BASE}/login in a private window, type the organization slug
  '$ORG_SLUG', submit the workspace step, and the 'Sign in with …' buttons
  appear — one per enabled config."
