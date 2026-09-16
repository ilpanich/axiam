# Stage 10 — cluster add-ons: ingress-nginx, cert-manager, the issuers.
#
# Runs first, against a k3s that scripts/01-install-k3s.sh has already
# installed. Everything after this stage depends on cert-manager's CRDs and
# webhook existing, which is the whole reason the tree is staged at all:
# a provider's configuration cannot depend on a resource the same root module
# creates.
terraform {
  # 1.6 is where both OpenTofu and Terraform have everything used here. The
  # tree deliberately uses no OpenTofu-only syntax except `encryption.tofu`,
  # whose `.tofu` extension Terraform ignores by design — so the same files
  # validate under either binary.
  required_version = ">= 1.6"

  required_providers {
    # EXACT pins, not `~>`. On a single node there is nothing to roll back to,
    # and "it worked last month" is not a deployment method. Bump deliberately.
    helm = {
      source  = "hashicorp/helm"
      version = "2.17.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.35.1"
    }
    kubectl = {
      # The provider that applies a raw manifest without needing its CRD to
      # exist at plan time — which is exactly the cert-manager ClusterIssuer
      # problem. `kubernetes_manifest` reads the API schema during PLAN, so it
      # cannot plan a ClusterIssuer in the same apply that installs the CRD.
      source  = "gavinbunney/kubectl"
      version = "1.19.0"
    }
  }
}

provider "kubernetes" {
  config_path = var.kubeconfig_path
}

provider "kubectl" {
  config_path       = var.kubeconfig_path
  load_config_file  = true
  apply_retry_count = 3
}

provider "helm" {
  kubernetes {
    config_path = var.kubeconfig_path
  }
}
