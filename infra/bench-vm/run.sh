#!/usr/bin/env bash
# The benchmark VM, from your own machine.
#
#   ./run.sh init | plan | apply | destroy | output | test   OpenTofu (or Terraform)
#   ./run.sh push                 copy scripts/ to the VM (~/bench-vm/scripts)
#   ./run.sh ssh [command...]     SSH to the VM, with a TTY
#   ./run.sh fetch [dir]          copy the packed results and ~/bench/logs back (default: here)
#   ./run.sh snapshot [name]      image the provisioned VM (default: axiam-bench-provisioned)
#
# The OpenStack credentials come from your openrc, sourced in this shell
# (`source ~/Downloads/<project>-openrc.sh`); nothing here asks for or stores
# them. The state lives OUTSIDE the repository (~/axiam-infra/state/bench-vm/),
# as in infra/rpi5-k3s/, so a `git clean` cannot lose track of a billed VM.
#
# The order of a round: claude_dev/bench-vm-runbook.md, and README.md here.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=scripts/_lib.sh
source "$HERE/scripts/_lib.sh"

TOFU_DIR="$HERE/tofu"
STATE_DIR="${AXIAM_TOFU_STATE_DIR:-$HOME/axiam-infra/state}/bench-vm"
STATE_FILE="$STATE_DIR/terraform.tfstate"
SSH_USER="${BENCH_VM_USER:-ubuntu}"

usage() { sed -n '2,15p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit "${1:-1}"; }
(( $# >= 1 )) || usage 1
CMD="$1"; shift

if command -v tofu >/dev/null 2>&1; then TF=tofu
elif command -v terraform >/dev/null 2>&1; then TF=terraform
else TF=""; fi

tf() {
    [[ -n "$TF" ]] || die "Neither \`tofu\` nor \`terraform\` is on PATH (OpenTofu >= 1.6, or Terraform >= 1.7 for \`test\`)."
    (cd "$TOFU_DIR" && "$TF" "$@")
}

need_cloud() {
    [[ -n "${OS_AUTH_URL:-}${OS_CLOUD:-}" ]] || die "No OpenStack credentials in this shell. Source your project's openrc first:
      source ~/Downloads/<project>-openrc.sh"
}

ensure_init() {
    mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
    if [[ ! -d "$TOFU_DIR/.terraform" ]]; then
        say "$TF init"
        tf init -input=false -backend-config="path=$STATE_FILE"
    fi
}

vm_ip() {
    local ip
    # `output -raw` prints a warning, not an address, when the state is empty.
    ip="$(tf output -raw ipv4 2>/dev/null)" || true
    [[ "$ip" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] || die "No VM in the state ($STATE_FILE). Run ./run.sh apply first."
    printf '%s' "$ip"
}

case "$CMD" in
    init)
        mkdir -p "$STATE_DIR"; chmod 700 "$STATE_DIR"
        tf init -input=false -upgrade -backend-config="path=$STATE_FILE" "$@"
        ok "Initialised. State: $STATE_FILE"
        ;;
    plan | apply)
        need_cloud; ensure_init
        [[ -f "$TOFU_DIR/bench-vm.auto.tfvars" ]] || die "No tofu/bench-vm.auto.tfvars. Start from the example:
      cp $TOFU_DIR/example.tfvars $TOFU_DIR/bench-vm.auto.tfvars"
        tf "$CMD" "$@"
        if [[ "$CMD" == apply ]]; then
            echo
            ok "Next: ./run.sh push, then ./run.sh ssh and run ~/bench-vm/scripts/00-host-prepare.sh"
        fi
        ;;
    destroy)
        need_cloud; ensure_init
        warn "This deletes the VM and its disk, with every result on it."
        echo "  Fetch the results first (./run.sh fetch), and snapshot it (./run.sh snapshot)"
        echo "  if you want to reuse the provisioning for the improvement benchmarks."
        confirm "Destroy the benchmark VM?"
        tf destroy "$@"
        ;;
    output)
        tf output "$@"
        ;;
    test)
        tf init -input=false -backend=false >/dev/null
        tf test "$@"
        ;;
    push)
        ip="$(vm_ip)"
        ssh "$SSH_USER@$ip" 'mkdir -p ~/bench-vm/scripts'
        rsync -av --delete --chmod=Du=rwx,Dgo=,Fu=rwx,Fgo= "$HERE/scripts/" "$SSH_USER@$ip:bench-vm/scripts/"
        ok "Scripts on the VM: ~/bench-vm/scripts. Next: ./run.sh ssh, then ~/bench-vm/scripts/00-host-prepare.sh"
        ;;
    ssh)
        ip="$(vm_ip)"
        exec ssh -t "$SSH_USER@$ip" "$@"
        ;;
    fetch)
        ip="$(vm_ip)"
        dest="${1:-$PWD}"
        mkdir -p "$dest"
        rsync -av "$SSH_USER@$ip:bench/axiam/benchmarks/results-*.tar.xz" "$dest/"
        rsync -av "$SSH_USER@$ip:bench/logs" "$dest/"
        ok "Results and logs in $dest"
        ;;
    snapshot)
        need_cloud
        need openstack "Install the OpenStack CLI (pipx install python-openstackclient): OpenTofu has no resource that images a running instance."
        name="${1:-axiam-bench-provisioned}"
        id="$(tf output -raw instance_id 2>/dev/null)" || true
        [[ "$id" =~ ^[0-9a-f-]{36}$ ]] || die "No VM in the state ($STATE_FILE)."
        warn "Snapshot before any credential is on the VM, or after 'docker logout': ~/.docker/config.json is part of the image."
        confirm "Image instance $id as '$name'?"
        openstack server image create --wait --name "$name" "$id"
        ok "Snapshot '$name'. To boot it later: image_name = \"$name\" in tofu/bench-vm.auto.tfvars"
        ;;
    -h | --help | help)
        usage 0
        ;;
    *)
        usage 1
        ;;
esac
