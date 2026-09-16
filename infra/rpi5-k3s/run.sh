#!/usr/bin/env bash
# Stage wrapper — D5.
#
#   ./run.sh <stage> <init|plan|apply|destroy|output> [extra args...]
#
#   stages:  10-platform  20-axiam  30-vault-config
#
# It does the boring parts so they cannot be got wrong at 2am:
#
#   * `tofu init` on first use, with the state kept OUTSIDE the repository
#     (~/axiam-infra/state/<stage>/), so a `git clean` is not a deployment
#     incident;
#   * the port-forward stage 30 needs, and the CA bundle it verifies Vault with,
#     both torn down on exit;
#   * refuses `destroy` on stage 20 without an explicit flag, because the PVCs
#     ARE the datastore;
#   * refuses to run stage 30 without VAULT_TOKEN in the environment, and says
#     how to set it without putting a root token in your shell history.
#
# Works with `terraform` too: it uses whichever binary it finds, and nothing in
# tofu/ uses OpenTofu-only syntax except encryption.tofu, whose `.tofu`
# extension Terraform ignores by design.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/_lib.sh
source "$HERE/scripts/_lib.sh"
REPO_ROOT="$(cd "$HERE/../.." && pwd)"

STATE_ROOT="${AXIAM_TOFU_STATE_DIR:-${HOME}/axiam-infra/state}"
KUBECONFIG_PATH="${KUBECONFIG:-${HOME}/.kube/config}"
NS="${AXIAM_NAMESPACE:-axiam}"
VAULT_PF_PORT="${AXIAM_VAULT_PF_PORT:-18200}"
# Must match AXIAM__AUTH__VAULT_MOUNT in k8s/server/configmap.yml and the
# vault_mount variable in stage 30.
VAULT_MOUNT="${AXIAM_VAULT_MOUNT:-secret}"

usage() {
    sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-1}"
}

(( $# >= 2 )) || usage 1
STAGE="$1"; COMMAND="$2"; shift 2
DESTROY_ACK=0
EXTRA=()
for arg in "$@"; do
    case "$arg" in
        --i-understand-this-deletes-the-datastore) DESTROY_ACK=1 ;;
        *) EXTRA+=("$arg") ;;
    esac
done

STAGE_DIR="$HERE/tofu/$STAGE"
[[ -d "$STAGE_DIR" ]] || die "No such stage: $STAGE
  Stages, in order: 10-platform  20-axiam  30-vault-config
  The ceremony (scripts/02-vault-ceremony.sh) goes between 20 and 30."

# OpenTofu by preference, Terraform if that is what is installed.
if command -v tofu >/dev/null 2>&1; then TF=tofu
elif command -v terraform >/dev/null 2>&1; then TF=terraform
else die "Neither \`tofu\` nor \`terraform\` is on PATH. scripts/01-install-k3s.sh installs OpenTofu."
fi

STATE_DIR="$STATE_ROOT/$STAGE"
mkdir -p "$STATE_DIR"
chmod 700 "$STATE_ROOT" "$STATE_DIR"
STATE_FILE="$STATE_DIR/terraform.tfstate"

# ---------------------------------------------------------------------------
# Guards
# ---------------------------------------------------------------------------
if [[ "$COMMAND" == "destroy" ]]; then
    case "$STAGE" in
        20-axiam)
            (( DESTROY_ACK )) || die "Refusing to destroy stage 20 without
  --i-understand-this-deletes-the-datastore.

  The PVCs ARE the datastore: every user, role, resource, certificate and audit
  record. And the credentials cannot simply be re-minted — SurrealDB and
  RabbitMQ record theirs on the first boot of an empty volume, so a destroy and
  re-apply is a NEW deployment, not the same one restarted.

  Note also that credentials.tf carries \`prevent_destroy = true\` on every
  credential resource, so even with this flag the destroy will refuse until
  somebody edits that file. That is deliberate: this flag stops an accident,
  the lifecycle block stops a determined mistake, and editing it is a diff
  somebody can review.

  Run scripts/04-backup.sh first. Then decide again."
            ;;
        30-vault-config)
            warn "Destroying stage 30 revokes the server's Vault token and removes
  the axiam-vault-token Secret. The server will crash-loop until stage 30 is
  applied again — which needs the root token, and therefore the ceremony's
  output. The KV mount itself carries prevent_destroy and survives."
            confirm "Destroy stage 30?"
            ;;
    esac
fi

if [[ "$STAGE" == "30-vault-config" && "$COMMAND" != "output" && "$COMMAND" != "init" ]]; then
    [[ -n "${VAULT_TOKEN:-}" ]] || die "VAULT_TOKEN is not set.

  Stage 30 configures Vault, so it needs a token that can — the root token from
  scripts/02-vault-ceremony.sh. Give it through the environment of this one
  command and nowhere else:

      read -rs VAULT_TOKEN && export VAULT_TOKEN
      $0 $STAGE $COMMAND
      unset VAULT_TOKEN

  \`read -rs\` rather than \`export VAULT_TOKEN=...\`: the second form puts a
  root token in ~/.bash_history, where it outlives the twenty minutes it was
  supposed to exist for. It is not a tofu VARIABLE either, because every value
  in a .tfvars file ends up in the state."
fi

# ---------------------------------------------------------------------------
# Stage 30: the port-forward and the CA bundle
# ---------------------------------------------------------------------------
PF_PID=""
CA_FILE=""
cleanup() {
    [[ -n "$PF_PID" ]] && kill "$PF_PID" 2>/dev/null || true
    [[ -n "$CA_FILE" ]] && rm -f "$CA_FILE" || true
}
trap cleanup EXIT

TF_ARGS=(-var "kubeconfig_path=$KUBECONFIG_PATH")
# `namespace` is declared by stages 20 and 30 only; passing a variable a stage
# does not declare is an error, not a warning.
[[ "$STAGE" == "20-axiam" ]] && TF_ARGS+=(-var "namespace=$NS")

if [[ "$STAGE" == "30-vault-config" ]]; then
    need kubectl
    # Vault is ClusterIP and is never published — reaching it means a
    # port-forward, which tunnels through the kubelet into the pod's network
    # namespace rather than crossing the pod network. NetworkPolicy therefore
    # does not apply to it, which is why allow-ingress-to-vault.yml names only
    # the server.
    CA_FILE="$(mktemp)"; chmod 600 "$CA_FILE"
    kubectl -n "$NS" get secret vault-tls -o jsonpath='{.data.ca\.crt}' 2>/dev/null \
        | base64 -d > "$CA_FILE"
    [[ -s "$CA_FILE" ]] || die "Could not read ca.crt from the vault-tls Secret in
  namespace $NS. Stage 20 creates it; is it applied, and is the Certificate
  Ready?
      kubectl -n $NS get certificate vault-tls"

    say "Port-forwarding Vault to 127.0.0.1:${VAULT_PF_PORT}"
    kubectl -n "$NS" port-forward svc/vault "${VAULT_PF_PORT}:8200" >/dev/null 2>&1 &
    PF_PID=$!
    ready=0
    for _ in $(seq 1 30); do
        sleep 0.5
        if (exec 3<>"/dev/tcp/127.0.0.1/${VAULT_PF_PORT}") 2>/dev/null; then ready=1; break; fi
    done
    (( ready )) || die "The port-forward to Vault did not come up. Is vault-0 Running?"
    ok "Vault reachable on 127.0.0.1:${VAULT_PF_PORT} (certificate verified against the in-cluster CA)"

    TF_ARGS+=(
        -var "vault_ca_cert_path=$CA_FILE"
        -var "vault_port_forward=$VAULT_PF_PORT"
        -var "repo_root=$REPO_ROOT"
        -var "namespace=$NS"
    )
fi

# ---------------------------------------------------------------------------
# init, once
# ---------------------------------------------------------------------------
#
# The state lives OUTSIDE the repository. `-backend-config` on a local backend
# sets the path without a backend block in the HCL, so the same tree works if
# you later move the state to a bucket.
#
# NOTE ON .terraform.lock.hcl: this repository does NOT ship one. Generating a
# valid lock file requires downloading each provider and recording its real
# checksum, and the environment these files were authored in had no route to
# either provider registry — a hand-written lock file would have made
# `tofu init` fail with a checksum mismatch, which is strictly worse than none.
# Every provider is pinned to an EXACT version in each stage's versions.tf, so
# what you get is reproducible; the first `init` here writes the lock file, and
# you should commit it (or at least back it up with the state) so the checksums
# are pinned too.
cd "$STAGE_DIR"
if [[ ! -d .terraform || "$COMMAND" == "init" ]]; then
    INIT_ARGS=(-input=false -backend-config="path=$STATE_FILE")
    # `-upgrade` only on an explicit `init`: an automatic one would silently
    # move a provider within its constraint on an unrelated `apply`, which is
    # the opposite of pinning.
    [[ "$COMMAND" == "init" ]] && INIT_ARGS+=(-upgrade)
    say "$TF init ($STAGE)"
    "$TF" init "${INIT_ARGS[@]}"
    if [[ "$COMMAND" == "init" ]]; then
        ok "Initialised. State: $STATE_FILE"
        exit 0
    fi
fi

# ---------------------------------------------------------------------------
# The command
# ---------------------------------------------------------------------------
case "$COMMAND" in
    plan)
        "$TF" plan -input=false "${TF_ARGS[@]}" "${EXTRA[@]+"${EXTRA[@]}"}"
        ;;
    apply)
        # Plan to a file, then apply that file: what you approve is what runs.
        # The plan file holds the same values the state will, so it goes in the
        # 0700 state directory and is removed afterwards — and encryption.tofu
        # encrypts it too, if you configured it.
        PLAN_FILE="$STATE_DIR/plan.$$.tfplan"
        "$TF" plan -input=false -out="$PLAN_FILE" "${TF_ARGS[@]}" "${EXTRA[@]+"${EXTRA[@]}"}"
        echo
        confirm "Apply this plan to stage $STAGE?"
        "$TF" apply -input=false "$PLAN_FILE"
        rm -f "$PLAN_FILE"
        echo
        "$TF" output 2>/dev/null || true
        ;;
    destroy)
        "$TF" destroy -input=false "${TF_ARGS[@]}" "${EXTRA[@]+"${EXTRA[@]}"}"
        ;;
    output)
        "$TF" output "${EXTRA[@]+"${EXTRA[@]}"}"
        ;;
    *)
        die "Unknown command: $COMMAND (init|plan|apply|destroy|output)"
        ;;
esac

# ---------------------------------------------------------------------------
# Stage 30: the scope check, which is the point of the whole ceremony
# ---------------------------------------------------------------------------
if [[ "$STAGE" == "30-vault-config" && "$COMMAND" == "apply" ]]; then
    echo
    say "Token scope — writing a policy and ATTACHING it are two steps, and
  nothing inside AXIAM can tell a scoped token from a root one: both read the
  secret successfully. This is the only thing that can."
    SRV_TOKEN="$(kubectl -n "$NS" get secret axiam-vault-token \
        -o jsonpath='{.data.AXIAM__AUTH__VAULT_TOKEN}' 2>/dev/null | base64 -d || true)"
    if [[ -n "$SRV_TOKEN" ]]; then
        CAPS="$(mktemp)"; SEAL="$(mktemp)"; KV="$(mktemp)"
        V="https://127.0.0.1:${VAULT_PF_PORT}"
        curl -fsS --cacert "$CA_FILE" -H "X-Vault-Token: $SRV_TOKEN" -X POST \
            --data "$(python3 "$REPO_ROOT/scripts/vault-status.py" --print-paths)" \
            "$V/v1/sys/capabilities-self" > "$CAPS" 2>/dev/null || true
        curl -fsS --cacert "$CA_FILE" "$V/v1/sys/seal-status" > "$SEAL" 2>/dev/null || true
        curl -fsS --cacert "$CA_FILE" -H "X-Vault-Token: $SRV_TOKEN" \
            "$V/v1/${VAULT_MOUNT}/data/axiam" > "$KV" 2>/dev/null || true
        if [[ -s "$KV" ]]; then
            python3 "$REPO_ROOT/scripts/vault-status.py" \
                --capabilities "$CAPS" --seal-status "$SEAL" < "$KV" || true
        fi
        rm -f "$CAPS" "$SEAL" "$KV"
    fi
    echo
    warn "NOW REVOKE THE ROOT TOKEN. It has done its job and it is the one
  credential that can undo everything above:

      kubectl -n $NS exec vault-0 -- \\
        env VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/vault/tls/ca.crt \\
            VAULT_TOKEN=\"\$VAULT_TOKEN\" vault token revoke -self
      unset VAULT_TOKEN"
fi
