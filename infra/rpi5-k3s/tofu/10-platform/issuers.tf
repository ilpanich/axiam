# ---------------------------------------------------------------------------
# The four issuers — D3
# ---------------------------------------------------------------------------
#
# Applied with the `kubectl` provider rather than `kubernetes_manifest`, and the
# reason is structural: `kubernetes_manifest` reads the API schema during PLAN,
# so it cannot plan a ClusterIssuer in the same apply that installs
# cert-manager's CRDs. `kubectl_manifest` sends YAML and lets the API server
# decide, which is what is wanted for a resource whose kind appears mid-apply.
#
# These are the same objects as `k8s/certs/00-private-ca.yml` and
# `20-public-acme.yml`, with the ACME email substituted. Those files stay as the
# hand-apply path for a cluster that is not this Pi; this is the automated one.

locals {
  # Where a CA ClusterIssuer looks for its Secret: the controller's
  # --cluster-resource-namespace, which defaults to the namespace cert-manager
  # runs in. Putting the root in `axiam` instead is the commonest reason a
  # freshly created CA ClusterIssuer reports `Secret "axiam-ca-root" not found`
  # while `kubectl -n axiam get secret` shows it plainly.
  cluster_resource_namespace = "cert-manager"
}

# Bootstrapping a CA needs a signer that trusts nothing. This signs exactly one
# thing: the root below.
resource "kubectl_manifest" "selfsigned_issuer" {
  depends_on = [terraform_data.cert_manager_ready]

  yaml_body = yamlencode({
    apiVersion = "cert-manager.io/v1"
    kind       = "ClusterIssuer"
    metadata   = { name = "axiam-selfsigned" }
    spec       = { selfSigned = {} }
  })
}

resource "kubectl_manifest" "private_ca_root" {
  depends_on = [kubectl_manifest.selfsigned_issuer]

  yaml_body = yamlencode({
    apiVersion = "cert-manager.io/v1"
    kind       = "Certificate"
    metadata = {
      name      = "axiam-ca"
      namespace = local.cluster_resource_namespace
    }
    spec = {
      isCA       = true
      commonName = "axiam-internal-ca"
      secretName = "axiam-ca-root"
      # Ed25519: the project standard, supported by every consumer here, and 32
      # bytes rather than 512 — which is not nothing on a Pi doing the signing.
      privateKey  = { algorithm = "Ed25519", rotationPolicy = "Always" }
      duration    = "${var.private_ca_duration_hours}h"
      renewBefore = "${floor(var.private_ca_duration_hours / 10)}h"
      issuerRef = {
        name  = "axiam-selfsigned"
        kind  = "ClusterIssuer"
        group = "cert-manager.io"
      }
    }
  })
}

resource "kubectl_manifest" "private_ca_issuer" {
  depends_on = [kubectl_manifest.private_ca_root]

  yaml_body = yamlencode({
    apiVersion = "cert-manager.io/v1"
    kind       = "ClusterIssuer"
    metadata   = { name = "axiam-ca" }
    spec       = { ca = { secretName = "axiam-ca-root" } }
  })
}

# ---------------------------------------------------------------------------
# ACME, for the PUBLIC leaf
# ---------------------------------------------------------------------------
#
# Both issuers are created; which one the Ingress uses is stage 20's
# `acme_issuer` variable. USE STAGING FIRST, every time, on a new deployment:
# production rate limits are per registered domain per week, and five failed
# orders is a lockout that outlasts the afternoon you have to debug in. Staging
# issues an untrusted certificate from the same code path, which is exactly what
# you want to be wrong about.
#
# HTTP-01 works here because the controller above binds the node's port 80 and
# the router forwards 80 to the Pi. If your ISP blocks inbound 80, no
# configuration on this side changes that — see docs/deployment/rpi5-k3s.md §4.4
# for the DNS-01 options, and note that this plan deliberately does NOT ship an
# unpinned third-party DuckDNS webhook image.
resource "kubectl_manifest" "acme_issuers" {
  for_each = {
    "letsencrypt-http01"  = "https://acme-v02.api.letsencrypt.org/directory"
    "letsencrypt-staging" = "https://acme-staging-v02.api.letsencrypt.org/directory"
  }
  depends_on = [terraform_data.cert_manager_ready]

  yaml_body = yamlencode({
    apiVersion = "cert-manager.io/v1"
    kind       = "ClusterIssuer"
    metadata   = { name = each.key }
    spec = {
      acme = {
        server = each.value
        email  = var.acme_email
        # The ACME ACCOUNT key, not a certificate. Losing it means
        # re-registering, which resets your rate-limit history with
        # Let's Encrypt — 04-backup.sh does not capture it, so if you care,
        # `kubectl get secret -n cert-manager ${each.key}-account-key` is the
        # thing to copy.
        privateKeySecretRef = { name = "${each.key}-account-key" }
        solvers = [{
          http01 = { ingress = { ingressClassName = "nginx" } }
        }]
      }
    }
  })
}
