#!/usr/bin/env bash
# The Vault initialisation ceremony: 5 shares, threshold 3.
#
# THIS SCRIPT NEVER WRITES A SHARE OR THE ROOT TOKEN TO DISK. Not to a file, not
# to a variable it later echoes, not to your shell history. `vault operator init`
# runs attached to your terminal and its output goes to your eyes and nowhere
# else. If you lose what it prints, it is gone — that is the property, not a
# shortcoming.
#
# WHY THIS IS NOT OPENTOFU. There is no `vault_init` resource and there must not
# be one. `vault operator init` produces five secrets ONCE, to be handed to five
# places that do not fail together; a tool whose job is to record its inputs in
# a state file is the wrong tool for a value whose whole security property is
# that it is not recorded in one place. The Compose path's `just prod-up` writes
# a single unseal key next to the sealed data, and
# claude_dev/rpi5-prod-google-federation-guide.md spends all of §7 undoing it.
# This does not repeat it.
#
# Run it AFTER `run.sh 20-axiam apply` has created the Vault pod, and BEFORE
# `run.sh 30-vault-config apply`.
#
# Usage:  ./02-vault-ceremony.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"

NS="${AXIAM_NAMESPACE:-axiam}"
POD="vault-0"
need kubectl

# Inside the pod: VAULT_ADDR is https://127.0.0.1:8200 (set on the container),
# and the listener's certificate carries 127.0.0.1 as an IP SAN precisely so
# this works without -tls-skip-verify. `ca.crt` is in the same Secret
# cert-manager writes the leaf into.
VEXEC=(kubectl -n "$NS" exec "$POD" --
       env VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/vault/tls/ca.crt)
VEXEC_TTY=(kubectl -n "$NS" exec -it "$POD" --
       env VAULT_ADDR=https://127.0.0.1:8200 VAULT_CACERT=/vault/tls/ca.crt)

# ---------------------------------------------------------------------------
# 1. Is the pod there, and what state is Vault in?
# ---------------------------------------------------------------------------
say "Waiting for $POD to be Running in namespace $NS"
kubectl -n "$NS" wait --for=jsonpath='{.status.phase}'=Running "pod/$POD" --timeout=180s >/dev/null \
    || die "$POD is not Running. Check:
      kubectl -n $NS get pod $POD
      kubectl -n $NS describe pod $POD
  A pod stuck in ContainerCreating is usually the 'vault-tls' Secret: it is
  issued by cert-manager from k8s/certs/, which stage 10 installs and stage 20
  applies. \`kubectl -n $NS get certificate vault-tls\` should say Ready=True."

# `vault status` exits 0 unsealed, 2 sealed, 1 on an error and 2 also when
# uninitialised — so read the JSON rather than the exit code.
status_json="$("${VEXEC[@]}" vault status -format=json 2>/dev/null || true)"
if [[ -z "$status_json" ]]; then
    die "Could not read Vault's status. Look at:
      kubectl -n $NS logs $POD --tail=50
  A TLS error here means the listener certificate does not cover 127.0.0.1;
  k8s/certs/10-internal-leaves.yml carries the IP SAN that fixes it. There is
  deliberately no -tls-skip-verify escape hatch in this script — the command
  that prints your unseal shares is the last one to run unverified."
fi
initialized="$(printf '%s' "$status_json" | jq -r '.initialized')"
sealed="$(printf '%s' "$status_json" | jq -r '.sealed')"
seal_type="$(printf '%s' "$status_json" | jq -r '.type // "shamir"')"

say "Vault: initialized=$initialized sealed=$sealed seal=$seal_type"

# ---------------------------------------------------------------------------
# 2. Initialise, if it has not been
# ---------------------------------------------------------------------------
if [[ "$initialized" == "true" ]]; then
    ok "Already initialised. Nothing to do here — re-initialising is not a thing
  that exists, and destroying the PVC to get a fresh one would change the OPAQUE
  setup key, which means a password reset for every user in every tenant."
else
    cat <<'MSG'

  ────────────────────────────────────────────────────────────────────────
  About to run:  vault operator init -key-shares=5 -key-threshold=3

  It prints FIVE unseal shares and ONE root token, ONCE. They will appear on
  this terminal and be stored nowhere. Before you continue:

    * Have five places ready that do not fail together. Five different people
      is the intent; five different password managers is the minimum. Three of
      the five must cooperate to unseal — that is the entire point, and it is
      defeated by putting all five in one vault, one laptop, or one backup.

    * Do NOT put any share in the same place as the root token. The root token
      is revoked at the end of stage 30 and is short-lived by design; a share
      is not.

    * Do not screenshot this. Do not paste it into a chat window to "save it
      for a second". Do not run this over a session that is being recorded.

    * Scroll-back is a file. If your terminal logs to disk, clear it afterwards.
  ────────────────────────────────────────────────────────────────────────

MSG
    confirm "Ready to see the shares and record them now?"

    echo
    # Attached to the terminal. No pipe, no tee, no capture — a pipe here would
    # put five unseal shares in a shell variable and, from there, anywhere.
    "${VEXEC_TTY[@]}" vault operator init -key-shares=5 -key-threshold=3
    echo

    confirm "Have you recorded all five shares AND the root token, in separate places?"
    ok "Initialised."
fi

# ---------------------------------------------------------------------------
# 3. Unseal
# ---------------------------------------------------------------------------
sealed="$("${VEXEC[@]}" vault status -format=json 2>/dev/null | jq -r '.sealed')"
if [[ "$sealed" != "true" ]]; then
    ok "Vault is already unsealed."
elif [[ "$seal_type" != "shamir" ]]; then
    warn "Vault reports seal type '$seal_type' but is sealed. With auto-unseal
  configured it should unseal itself; it has not. Check its log:
      kubectl -n $NS logs $POD --tail=50
  The usual cause is egress: default-deny does not permit Vault to reach a cloud
  KMS. infra/rpi5-k3s/overlay/vault-seal.yml carries the rule, commented."
else
    cat <<'MSG'

  Unsealing. You will be prompted for a share three times. Each prompt reads
  the share from your terminal without echoing it.

  With auto-unseal configured (infra/rpi5-k3s/overlay/vault-seal.yml) you would
  not be doing this at all — not now, and not after every power cut, upgrade
  and OOM kill for the life of this deployment. If you are typing shares here,
  write down that you are running a manually-unsealed Vault, because that is
  what `just vault-status` will report and it will be telling the truth.

MSG
    for attempt in 1 2 3; do
        say "Unseal key $attempt of 3 (threshold)"
        "${VEXEC_TTY[@]}" vault operator unseal || die "Unseal failed. A wrong
  share is counted and the progress counter does not reset, so just enter a
  correct one at the next prompt: re-run this script."
        sealed="$("${VEXEC[@]}" vault status -format=json 2>/dev/null | jq -r '.sealed')"
        [[ "$sealed" == "true" ]] || break
    done
    [[ "$sealed" == "true" ]] && die "Still sealed after three shares."
    ok "Unsealed."
fi

# ---------------------------------------------------------------------------
# 4. What happens next, and what NOT to do with the root token
# ---------------------------------------------------------------------------
cat <<'MSG'

  ────────────────────────────────────────────────────────────────────────
  NEXT: stage 30 enables the KV v2 mount, writes AXIAM's policy from
  docker/vault/axiam-policy.hcl, seeds the secrets, issues the server a
  periodic token scoped to that policy, and REVOKES the root token.

  Give it the root token through the environment of that one command, and
  nowhere else:

      read -rs VAULT_TOKEN && export VAULT_TOKEN      # no echo, no history
      infra/rpi5-k3s/run.sh 30-vault-config apply
      unset VAULT_TOKEN

  `read -rs` rather than `export VAULT_TOKEN=...` because the second form puts
  a root token in ~/.bash_history, where it outlives the twenty minutes it was
  supposed to exist for.

  Do NOT write the root token to a file "temporarily". Do not put it in
  terraform.tfvars — every value in a tfvars file ends up in the state, and
  the state is not where a root token goes even when it is encrypted.
  ────────────────────────────────────────────────────────────────────────

MSG
ok "Ceremony complete."
