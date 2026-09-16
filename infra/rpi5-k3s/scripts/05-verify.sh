#!/usr/bin/env bash
# Verify the deployment, one layer at a time.
#
# Layered on purpose: when something is wrong, knowing WHICH hop failed saves an
# hour. Each check prints PASS, FAIL or SKIP with the reason, and the script
# exits non-zero if anything failed — so it is usable from cron as well as by
# hand.
#
# Nothing here uses -k, --insecure or any verification-skip option. A TLS
# failure in this script is a finding.
#
# Usage:
#   ./05-verify.sh                 # everything that needs no credentials
#   VAULT_TOKEN=... ./05-verify.sh # and the Vault token-scope + seal report
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"
ROOT="$(cd "$HERE/../../.." && pwd)"

NS="${AXIAM_NAMESPACE:-axiam}"
HOST="${AXIAM_HOST:-axiam-iam.duckdns.org}"
BASE="https://${HOST}"
FAILED=0
pass() { printf '  %sPASS%s  %s\n' "$(_c 32)" "$(_c 0)" "$*"; }
fail() { printf '  %sFAIL%s  %s\n' "$(_c 31)" "$(_c 0)" "$*"; FAILED=1; }
skip() { printf '  %sSKIP%s  %s\n' "$(_c 33)" "$(_c 0)" "$*"; }
need kubectl; need curl; need jq

# ===========================================================================
section() { printf '\n%s== %s%s\n' "$(_c 36)" "$*" "$(_c 0)"; }

section "1. Cluster"
if kubectl get --raw='/readyz' >/dev/null 2>&1; then
    pass "API server ready"
else
    fail "API server not ready — nothing below can be trusted."
    exit 1
fi
# Process substitution, not a pipe: a `while` on the right of a pipe runs in a
# subshell, and every FAILED=1 it sets is discarded when that subshell exits —
# so the script would report success while printing FAIL.
while read -r name status _; do
    [[ -z "$name" ]] && continue
    if [[ "$status" == "Ready" ]]; then pass "node $name Ready"; else fail "node $name is $status"; fi
done < <(kubectl get nodes --no-headers)

section "2. Certificates (cert-manager)"
if ! kubectl get crd certificates.cert-manager.io >/dev/null 2>&1; then
    fail "cert-manager CRDs are absent. Run: infra/rpi5-k3s/run.sh 10-platform apply"
else
    # A Certificate reports Ready=True only once the Secret exists and holds a
    # leaf that matches the spec. It is the single most informative object in
    # this deployment when TLS is wrong anywhere.
    while read -r ns name ready reason; do
        [[ -z "$name" ]] && continue
        if [[ "$ready" == "True" ]]; then
            pass "Certificate $ns/$name Ready"
        else
            fail "Certificate $ns/$name is Ready=$ready ($reason)
        kubectl -n $ns describe certificate $name
        kubectl -n $ns get certificaterequest,order,challenge"
        fi
    done < <(kubectl get certificate -A -o jsonpath='{range .items[*]}{.metadata.namespace} {.metadata.name} {.status.conditions[?(@.type=="Ready")].status} {.status.conditions[?(@.type=="Ready")].reason}{"\n"}{end}' 2>/dev/null)
fi

section "3. Pods"
while read -r name ready status _; do
    [[ -z "$name" ]] && continue
    want="${ready#*/}"; have="${ready%/*}"
    if [[ "$status" == "Running" && "$have" == "$want" ]]; then
        pass "$name  $ready  $status"
    else
        fail "$name  $ready  $status
        kubectl -n $NS describe pod $name | tail -30"
    fi
done < <(kubectl -n "$NS" get pods --no-headers 2>/dev/null)

section "4. Ingress controller — hostNetwork, and the one public listener"
# hostNetwork is not a convenience: it is what makes \$remote_addr at the
# controller the real client's address, which is what TRUSTED_HOPS=0 rests on.
hn="$(kubectl -n ingress-nginx get ds,deploy -o jsonpath='{.items[*].spec.template.spec.hostNetwork}' 2>/dev/null | tr -d ' ')"
case "$hn" in
    *true*) pass "ingress-nginx runs with hostNetwork: true" ;;
    "")     fail "no ingress-nginx DaemonSet or Deployment found in namespace ingress-nginx.
        The two NetworkPolicies select that namespace BY NAME; installing the
        controller anywhere else means nothing can reach the server." ;;
    *)      fail "ingress-nginx is NOT in hostNetwork mode (hostNetwork=$hn).
        Whatever is in front of it — ServiceLB, MetalLB, a NodePort — SNATs, so
        \$remote_addr is that hop's address and every client on the internet
        shares one rate-limit bucket, /auth/login included. Fix the controller,
        do not change TRUSTED_HOPS: no value of it rescues this." ;;
esac
ufh="$(kubectl -n ingress-nginx get cm -o jsonpath='{range .items[*]}{.data.use-forwarded-headers}{"\n"}{end}' 2>/dev/null | grep -v '^$' | head -1)"
if [[ "${ufh:-false}" == "true" ]]; then
    fail "use-forwarded-headers is \"true\" on the controller ConfigMap.
        That makes nginx PASS THROUGH a client's own X-Forwarded-For instead of
        replacing it with the socket peer, and a client then picks its own
        rate-limit bucket. Set it to \"false\" unless something you control sits
        in front of this controller — and if something does, TRUSTED_HOPS is no
        longer 0."
else
    pass "use-forwarded-headers is false — nginx replaces X-Forwarded-For with the socket peer"
fi

section "5. The backend's own TLS listener (bypassing the ingress)"
# Through a port-forward, which reaches the pod's network namespace directly —
# so this tests the server's rustls listener and nothing else. --resolve keeps
# the certificate name honest rather than turning verification off.
PF_PID=""
cleanup() { [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null || true; rm -f "${CA_FILE:-}" "${CAPS:-}" "${SEAL:-}" "${KV:-}"; }
trap cleanup EXIT
CA_FILE="$(mktemp)"
if kubectl -n "$NS" get secret axiam-server-tls -o jsonpath='{.data.ca\.crt}' 2>/dev/null | base64 -d > "$CA_FILE" && [[ -s "$CA_FILE" ]]; then
    kubectl -n "$NS" port-forward svc/axiam-server 18090:8090 >/dev/null 2>&1 &
    PF_PID=$!
    for _ in $(seq 1 20); do sleep 0.5; (exec 3<>/dev/tcp/127.0.0.1/18090) 2>/dev/null && break; done
    if curl -fsS --cacert "$CA_FILE" \
            --resolve "axiam-server.axiam.svc:18090:127.0.0.1" \
            "https://axiam-server.axiam.svc:18090/health" >/dev/null 2>&1; then
        pass "backend answers /health over its own TLS, certificate verified against the in-cluster CA"
    else
        fail "backend did not answer /health over TLS on a port-forward.
        kubectl -n $NS logs deploy/axiam-server --tail=50
        'failed to open TLS key file' means the 0440 mount and fsGroup 65532
        disagree; a handshake failure means the leaf does not carry
        axiam-server.axiam.svc."
    fi
    kill "$PF_PID" 2>/dev/null || true; PF_PID=""
else
    skip "no axiam-server-tls Secret with a ca.crt — cannot verify the backend leg"
fi

section "6. Through the public front door"
if curl -fsS "${BASE}/.well-known/openid-configuration" 2>/dev/null | jq -e '.issuer' >/dev/null 2>&1; then
    issuer="$(curl -fsS "${BASE}/.well-known/openid-configuration" | jq -r '.issuer')"
    if [[ "$issuer" == "$BASE" ]]; then
        pass "discovery served, issuer = $issuer"
    else
        fail "discovery served, but issuer is '$issuer' and this host is '$BASE'.
        AXIAM__AUTH__OAUTH2_ISSUER_URL is wrong. Apple and every SAML IdP build
        their redirect URIs from it, and they will fail with a mismatch that
        points nowhere useful."
    fi
else
    fail "no OIDC discovery document at ${BASE}/.well-known/openid-configuration.
        Work outwards: does DNS resolve ($HOST)? Does the router forward 443?
        Is the public Certificate Ready (section 2)? Does
        'kubectl -n $NS get ingress' show an ADDRESS?"
fi
code="$(curl -sS -o /dev/null -w '%{http_code}' "${BASE}/" 2>/dev/null || echo 000)"
[[ "$code" == "200" ]] && pass "SPA served (HTTP $code)" || fail "SPA route returned $code"

section "7. Health endpoints are NOT public"
# They must land on the SPA route and return HTML. /health/jobs reports per-job
# scheduler state — names, last-run times, consecutive failures — which is a
# free map of what you run and what is currently broken in it.
for path in /health /ready /health/jobs; do
    body="$(curl -sS "${BASE}${path}" 2>/dev/null | head -c 200 || true)"
    if printf '%s' "$body" | grep -qi '<!doctype html\|<html'; then
        pass "${path} returns the SPA, not the endpoint"
    elif printf '%s' "$body" | jq -e . >/dev/null 2>&1; then
        fail "${path} is PUBLICLY ROUTED and returns JSON. Remove it from the
        Ingress paths — it is not meant to be reachable from the internet."
    else
        skip "${path} returned something unrecognised (is the host reachable?)"
    fi
done

section "8. NetworkPolicy — default-deny is actually denying"
# The frontend has no business reaching the datastore. If it can, default-deny
# is not in force: either the policies were not applied, or the CNI is not
# enforcing them (k3s ships one that does).
fe_pod="$(kubectl -n "$NS" get pod -l component=frontend -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || true)"
if [[ -z "$fe_pod" ]]; then
    skip "no frontend pod to probe from"
elif kubectl -n "$NS" exec "$fe_pod" -- timeout 4 sh -c \
        '(exec 3<>/dev/tcp/surrealdb/8000) 2>/dev/null' >/dev/null 2>&1; then
    fail "the frontend pod REACHED surrealdb:8000. default-deny is not in force.
        kubectl -n $NS get networkpolicy
        A NetworkPolicy with no enforcing CNI is a document, not a control."
else
    pass "frontend cannot reach surrealdb:8000 (default-deny in force)"
fi

section "9. Pod Security Admission — restricted is enforcing"
enf="$(kubectl get ns "$NS" -o jsonpath='{.metadata.labels.pod-security\.kubernetes\.io/enforce}' 2>/dev/null || true)"
[[ "$enf" == "restricted" ]] && pass "namespace $NS enforces 'restricted'" \
    || fail "namespace $NS enforce label is '${enf:-unset}', not 'restricted'"
# Prove it, rather than trusting the label: admission is what matters, and a
# dry-run costs nothing and creates nothing.
if kubectl -n "$NS" run psa-probe --image=busybox --dry-run=server --restart=Never \
        --overrides='{"spec":{"containers":[{"name":"c","image":"busybox","securityContext":{"privileged":true}}]}}' \
        >/dev/null 2>&1; then
    fail "a privileged pod was ADMITTED by a server-side dry run. The label says
        restricted but admission is not applying it."
else
    pass "a privileged pod is refused at admission (server-side dry run)"
fi

section "10. Vault"
seal_type="$(kubectl -n "$NS" exec vault-0 -- env VAULT_ADDR=https://127.0.0.1:8200 \
    VAULT_CACERT=/vault/tls/ca.crt vault status -format=json 2>/dev/null | jq -r '.type // "unknown"' || echo unknown)"
sealed="$(kubectl -n "$NS" exec vault-0 -- env VAULT_ADDR=https://127.0.0.1:8200 \
    VAULT_CACERT=/vault/tls/ca.crt vault status -format=json 2>/dev/null | jq -r '.sealed // "unknown"' || echo unknown)"
if [[ "$sealed" == "true" ]]; then
    fail "Vault is SEALED right now. axiam-server cannot start until it is
        unsealed: ./02-vault-ceremony.sh"
elif [[ "$sealed" == "unknown" ]]; then
    skip "could not read Vault's status"
else
    pass "Vault unsealed"
fi
if [[ "$seal_type" == "shamir" ]]; then
    warn "Seal type is 'shamir' — NO AUTO-UNSEAL. Every restart (power cut,
  upgrade, OOM kill) leaves Vault sealed and axiam-server crash-looping until a
  human arrives with three shares. That is a legitimate home-lab choice; it is
  not a production deployment, and this line is the deployment saying so.
  infra/rpi5-k3s/overlay/vault-seal.yml is one file to edit."
elif [[ "$seal_type" != "unknown" ]]; then
    pass "Seal type '$seal_type' — auto-unseal configured"
fi

# The token-scope report. Reuses scripts/vault-status.py verbatim — it is pure
# stdin/JSON and assumes nothing about Docker; only `just vault-status`'s
# plumbing was Compose-specific, and this replaces that plumbing, not the tool.
if [[ -n "${VAULT_TOKEN:-}" ]]; then
    kubectl -n "$NS" port-forward svc/vault 18200:8200 >/dev/null 2>&1 &
    PF_PID=$!
    for _ in $(seq 1 20); do sleep 0.5; (exec 3<>/dev/tcp/127.0.0.1/18200) 2>/dev/null && break; done
    CA_FILE="$(mktemp)"; CAPS="$(mktemp)"; SEAL="$(mktemp)"; KV="$(mktemp)"
    kubectl -n "$NS" get secret vault-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > "$CA_FILE"
    # 127.0.0.1 is an IP SAN on the listener certificate (k8s/certs/), so this
    # verifies properly rather than needing a name override.
    V="https://127.0.0.1:18200"
    curl -fsS --cacert "$CA_FILE" -H "X-Vault-Token: $VAULT_TOKEN" -X POST \
        --data "$(python3 "$ROOT/scripts/vault-status.py" --print-paths)" \
        "$V/v1/sys/capabilities-self" > "$CAPS" 2>/dev/null || true
    curl -fsS --cacert "$CA_FILE" "$V/v1/sys/seal-status" > "$SEAL" 2>/dev/null || true
    if curl -fsS --cacert "$CA_FILE" -H "X-Vault-Token: $VAULT_TOKEN" \
            "$V/v1/secret/data/axiam" > "$KV" 2>/dev/null; then
        echo
        python3 "$ROOT/scripts/vault-status.py" --capabilities "$CAPS" --seal-status "$SEAL" < "$KV" \
            || fail "vault-status reported a problem (see above)"
    else
        fail "could not read secret/data/axiam with the supplied token"
    fi
    kill "$PF_PID" 2>/dev/null || true; PF_PID=""
else
    skip "VAULT_TOKEN not set — token scope and secret presence not checked.
        Run the server's OWN token through it, not root: that is the thing you
        want to know the scope of.
          kubectl -n $NS get secret axiam-secrets \\
            -o jsonpath='{.data.AXIAM__AUTH__VAULT_TOKEN}' | base64 -d"
fi

section "11. TRUSTED_HOPS — the one check this script cannot do for you"
hops="$(kubectl -n "$NS" get configmap axiam-config -o jsonpath='{.data.AXIAM__RATE_LIMIT__TRUSTED_HOPS}' 2>/dev/null || true)"
printf '  %-6s AXIAM__RATE_LIMIT__TRUSTED_HOPS = %s\n' "INFO" "${hops:-unset (defaults to 0)}"
cat <<MSG
  This is correct for exactly one topology: ONE proxy between the client and the
  server, and that proxy binding the node's ports directly (sections 4 and 5).
  No probe from inside the cluster can confirm it — the value only misbehaves
  for clients arriving from different public addresses.

  Do this from TWO devices on DIFFERENT networks (one on mobile data):

    for i in \$(seq 1 40); do
      curl -s -o /dev/null -w '%{http_code} ' -X POST \\
        ${BASE}/api/v1/auth/login \\
        -H 'Content-Type: application/json' \\
        -d '{"org_slug":"nope","username":"nope","password":"nope"}'
    done; echo

  You should see 401s turning into 429 per source address. If the SECOND device
  is throttled the instant the first one is, they are sharing a bucket and the
  value is wrong for your topology — see docs/deployment/rpi5-k3s.md §6.3.
MSG

echo
if (( FAILED )); then
    printf '%s✗ some checks failed%s\n' "$(_c 31)" "$(_c 0)"
    exit 1
fi
ok "All executed checks passed. Section 11 is still yours to run."
