#!/usr/bin/env bash
# Install k3s and the client tools. Idempotent; safe to re-run.
#
# This is the one step OpenTofu does NOT do, and the omission is deliberate: the
# providers that apply everything else need a cluster to talk to, and a
# `terraform_data` wrapping this script would hide a one-time host mutation
# behind a tool whose entire value is convergence — on something that converges
# on nothing.
#
# Traefik and ServiceLB are disabled at install time. Both matter:
#
#   --disable traefik    `k8s/ingress.yml` is `ingressClassName: nginx` with
#                        ingress-nginx annotations, and two NetworkPolicies
#                        select the namespace `ingress-nginx` by name. Running
#                        Traefik as well means two controllers racing for the
#                        node's 80/443, and adopting it instead would mean
#                        rewriting the Ingress objects, both policies and the
#                        gRPC route.
#
#   --disable servicelb  klipper-lb is a DaemonSet of iptables-DNAT pods. It is
#                        a HOP, and a hop changes what `$remote_addr` is at the
#                        ingress controller — which is what
#                        AXIAM__RATE_LIMIT__TRUSTED_HOPS=0 rests on. See
#                        docs/deployment/rpi5-k3s.md §6.3.
#
# Usage:  ./01-install-k3s.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=_lib.sh
source "$HERE/_lib.sh"
# shellcheck source=versions.env
source "$HERE/versions.env"

ARCH_SUFFIX="arm64"
case "$(uname -m)" in
    aarch64 | arm64) ARCH_SUFFIX="arm64" ;;
    x86_64) ARCH_SUFFIX="amd64" ;;
    *) die "Unsupported architecture $(uname -m)." ;;
esac

# ---------------------------------------------------------------------------
# 0. Refuse to run before the host is prepared
# ---------------------------------------------------------------------------
if [[ "$(awk '$1=="memory" {print $4}' /proc/cgroups 2>/dev/null)" != "1" ]] \
   && ! grep -qw memory /sys/fs/cgroup/cgroup.controllers 2>/dev/null; then
    die "The memory cgroup controller is not active in the running kernel.
  Run ./00-host-prepare.sh and reboot first. Installing k3s now gives you a
  service that restart-loops with an error that reads like a k3s bug."
fi
if swapon --show --noheadings 2>/dev/null | grep -q .; then
    die "Swap is on. Run ./00-host-prepare.sh first — the kubelet refuses to
  start with swap enabled, and tolerating it on this node is the wrong trade."
fi

# ---------------------------------------------------------------------------
# 1. k3s
# ---------------------------------------------------------------------------
if systemctl is-active --quiet k3s 2>/dev/null; then
    running="$(k3s --version 2>/dev/null | awk '/^k3s/ {print $3}')"
    ok "k3s is already running (${running:-version unknown})"
    if [[ -n "$running" && "$running" != "$K3S_VERSION" ]]; then
        warn "Running $running, versions.env pins $K3S_VERSION.
  This script will NOT upgrade in place: an upgrade restarts the API server and
  every pod on your only node. Do it deliberately, after ./04-backup.sh:
      curl -sfL https://get.k3s.io | INSTALL_K3S_VERSION='$K3S_VERSION' \\
        INSTALL_K3S_EXEC='server --disable traefik --disable servicelb' sh -"
    fi
else
    say "Installing k3s $K3S_VERSION"
    # The installer is piped from the network, which is how k3s is distributed.
    # It is pinned to an exact version rather than taking whatever is current
    # the day it runs.
    curl -sfL https://get.k3s.io \
        | INSTALL_K3S_VERSION="$K3S_VERSION" \
          INSTALL_K3S_EXEC="server --disable traefik --disable servicelb --write-kubeconfig-mode 0600" \
          sh -
    ok "k3s installed"
fi

say "Waiting for the API server"
for _ in $(seq 1 60); do
    if sudo k3s kubectl get --raw='/readyz' >/dev/null 2>&1; then break; fi
    sleep 2
done
sudo k3s kubectl get --raw='/readyz' >/dev/null 2>&1 \
    || die "The API server did not become ready. Look at: sudo journalctl -u k3s -n 100"
ok "API server ready"

# ---------------------------------------------------------------------------
# 2. kubeconfig for the operator's user
# ---------------------------------------------------------------------------
# k3s writes /etc/rancher/k3s/k3s.yaml root-owned. Copy rather than chmod the
# original: the file holds a client certificate that is cluster-admin, and
# loosening it in place would hand that to every local user.
KUBECONFIG_DEST="${HOME}/.kube/config"
if [[ -f "$KUBECONFIG_DEST" ]] && grep -q 'default' "$KUBECONFIG_DEST" 2>/dev/null; then
    ok "kubeconfig already at $KUBECONFIG_DEST (not overwriting)"
else
    mkdir -p "$(dirname "$KUBECONFIG_DEST")"
    sudo install -m 0600 -o "$(id -u)" -g "$(id -g)" \
        /etc/rancher/k3s/k3s.yaml "$KUBECONFIG_DEST"
    ok "kubeconfig written to $KUBECONFIG_DEST (mode 600)"
fi

# ---------------------------------------------------------------------------
# 3. Client tools
# ---------------------------------------------------------------------------
if command -v kubectl >/dev/null 2>&1; then
    ok "kubectl present: $(kubectl version --client 2>/dev/null | head -1)"
else
    say "Installing kubectl $KUBECTL_VERSION"
    fetch_to "https://dl.k8s.io/release/${KUBECTL_VERSION}/bin/linux/${ARCH_SUFFIX}/kubectl" \
             /usr/local/bin/kubectl \
        || die "Could not download kubectl. \`sudo k3s kubectl\` works in the
  meantime and is the same binary."
    ok "kubectl installed"
fi

if command -v tofu >/dev/null 2>&1; then
    ok "OpenTofu present: $(tofu version | head -1)"
elif command -v terraform >/dev/null 2>&1; then
    ok "Terraform present: $(terraform version | head -1) — the tofu/ tree works
  with either. run.sh uses whichever it finds."
else
    say "Installing OpenTofu $TOFU_VERSION"
    tmpzip="$(mktemp --suffix=.zip)"
    if curl --fail --location --silent --show-error --retry 3 \
            --output "$tmpzip" \
            "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_${ARCH_SUFFIX}.zip"; then
        tmpdir="$(mktemp -d)"
        unzip -oq "$tmpzip" tofu -d "$tmpdir"
        sudo install -m 0755 "$tmpdir/tofu" /usr/local/bin/tofu
        rm -rf "$tmpzip" "$tmpdir"
        ok "OpenTofu installed"
    else
        rm -f "$tmpzip"
        die "Could not download OpenTofu. Install it or Terraform by hand; the
  tofu/ tree is written for both."
    fi
fi

# Helm is genuinely optional: the OpenTofu `helm` provider speaks to chart
# repositories itself and never shells out to this binary. It is here for
# `helm template`, which is how you see what a chart renders before applying it.
if command -v helm >/dev/null 2>&1; then
    ok "helm present: $(helm version --short 2>/dev/null)"
else
    say "Installing helm $HELM_VERSION (optional)"
    tmptgz="$(mktemp --suffix=.tgz)"
    if curl --fail --location --silent --show-error --retry 2 \
            --output "$tmptgz" \
            "https://get.helm.sh/helm-${HELM_VERSION}-linux-${ARCH_SUFFIX}.tar.gz"; then
        tmpdir="$(mktemp -d)"
        tar -xzf "$tmptgz" -C "$tmpdir" --strip-components=1 "linux-${ARCH_SUFFIX}/helm"
        sudo install -m 0755 "$tmpdir/helm" /usr/local/bin/helm
        rm -rf "$tmptgz" "$tmpdir"
        ok "helm installed"
    else
        rm -f "$tmptgz"
        warn "Could not download helm. Nothing here needs it — the OpenTofu helm
  provider does not use the CLI — so this is not a failure. Install it later if
  you want \`helm template\`."
    fi
fi

# ---------------------------------------------------------------------------
# 4. Report what we got
# ---------------------------------------------------------------------------
echo
KUBECONFIG="$KUBECONFIG_DEST" kubectl get nodes -o wide 2>/dev/null || sudo k3s kubectl get nodes -o wide
echo
say "Cluster CIDRs — confirm these against infra/rpi5-k3s/overlay/network-policy-cidrs.yml"
pod_cidr="$(KUBECONFIG="$KUBECONFIG_DEST" kubectl get node -o jsonpath='{.items[0].spec.podCIDR}' 2>/dev/null || true)"
svc_ip="$(KUBECONFIG="$KUBECONFIG_DEST" kubectl -n kube-system get svc kube-dns -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)"
printf '    pod CIDR     : %s   (overlay expects 10.42.0.0/16)\n' "${pod_cidr:-unknown}"
printf '    kube-dns IP  : %s   (service CIDR is its first two octets + .0.0/16; overlay expects 10.43.0.0/16)\n' "${svc_ip:-unknown}"
if [[ -n "$pod_cidr" && "$pod_cidr" != "10.42.0.0/24" && "$pod_cidr" != 10.42.* ]]; then
    warn "Pod CIDR is $pod_cidr, not in 10.42.0.0/16.
  Edit the 'except:' list in infra/rpi5-k3s/overlay/network-policy-cidrs.yml
  before applying stage 20, or the 443 egress rule will let the server reach
  in-cluster services — the lateral-movement hole that list exists to close."
fi

echo
ok "Next: ./02-vault-ceremony.sh comes LATER. First run:
      infra/rpi5-k3s/run.sh 10-platform apply
      infra/rpi5-k3s/run.sh 20-axiam    apply"
