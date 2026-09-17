# Stage 20 — credentials, the internal certificates, and the AXIAM manifests.
#
# Depends on stage 10: cert-manager's CRDs must exist and its webhook must be
# serving before a `Certificate` can be created, and `ClusterIssuer/axiam-ca`
# must exist before one can be issued.
terraform {
  required_version = ">= 1.6"

  required_providers {
    # EXACT pins. Each was confirmed to exist and publish a linux/arm64 build.
    #
    # These are also the MAJORS this tree's syntax is written against, which
    # matters for two of them: the helm and kubernetes providers have since
    # released a 3.x whose provider block is an attribute rather than a nested
    # block. Bumping those two is a code change, not a number change — read
    # their upgrade guides rather than editing the string and hoping.
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "2.35.1"
    }
    kubectl = {
      source  = "gavinbunney/kubectl"
      version = "1.19.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "3.6.3"
    }
    kustomization = {
      # kbst/kustomization renders a kustomize overlay into one state object per
      # manifest, so `tofu plan` shows a real per-object diff. The alternative,
      # one `kubernetes_manifest` per object, is the same thing with more
      # boilerplate and a CRD-ordering problem; `kubectl apply -k` in a
      # local-exec is the same thing with no diff at all.
      source  = "kbst/kustomization"
      version = "0.9.6"
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

provider "kustomization" {
  kubeconfig_path = var.kubeconfig_path
}
