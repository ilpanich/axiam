# ---------------------------------------------------------------------------
# The four internal leaves — K8S-F4 / K8S-F5 / D3
# ---------------------------------------------------------------------------
#
# Same objects as `k8s/certs/10-internal-leaves.yml`, which stays as the
# hand-apply path for a cluster that is not this Pi. Issued by
# `ClusterIssuer/axiam-ca` from stage 10.
#
# Three of these fill Secrets that `k8s/` CONSUMES and nothing produces —
# `vault-tls`, `rabbitmq-broker-tls`, `axiam-server-tls`. Without them the Vault
# and RabbitMQ pods stay ContainerCreating forever and the server cannot
# terminate TLS. cert-manager is a requirement of the shipped manifests, not an
# addition of this deployment.
#
# WHY A PRIVATE CA AND NOT THE PUBLIC LEAF, unlike the Compose path:
# claude_dev/public-backend-tls-design.md §3.1 already says the public-leaf
# reuse was a Pi-without-a-CA expedient and that cert-manager is what Kubernetes
# would do. Concretely: ingress-nginx verifies an upstream with
# `proxy-ssl-verify: on` + `proxy-ssl-secret`, and that Secret must hold a
# CLIENT keypair as well as `ca.crt`. Verifying against the public roots would
# mean minting a client certificate for the ingress from nowhere.

locals {
  # Every form a client might present as SNI. A caller that resolves `vault` and
  # one that resolves the FQDN present different names, and rustls checks what
  # was presented, not what was meant.
  svc_names = { for svc in ["vault", "rabbitmq", "axiam-server"] :
    svc => [svc, "${svc}.${var.namespace}.svc", "${svc}.${var.namespace}.svc.cluster.local"]
  }

  issuer_ref = {
    name  = "axiam-ca"
    kind  = "ClusterIssuer"
    group = "cert-manager.io"
  }
}

resource "kubectl_manifest" "vault_tls" {
  depends_on = [kustomization_resource.p0]

  yaml_body = yamlencode({
    apiVersion = "cert-manager.io/v1"
    kind       = "Certificate"
    metadata   = { name = "vault-tls", namespace = var.namespace }
    spec = {
      # The listener in k8s/vault/statefulset.yml names /vault/tls/tls.crt and
      # /vault/tls/tls.key — exactly the keys cert-manager writes into a
      # kubernetes.io/tls Secret.
      secretName = "vault-tls"
      dnsNames   = local.svc_names["vault"]
      # 127.0.0.1 is not decoration. The pod sets VAULT_ADDR=https://127.0.0.1:8200,
      # so every `kubectl exec ... vault operator {init,unseal,status}` — the
      # whole ceremony — verifies this certificate against that literal address.
      # Without the IP SAN the only way past it would be -tls-skip-verify on the
      # one command that hands you the unseal shares.
      ipAddresses = ["127.0.0.1"]
      privateKey  = { algorithm = "Ed25519", rotationPolicy = "Always" }
      duration    = "${var.restart_required_leaf_duration_hours}h"
      renewBefore = "720h"
      issuerRef   = local.issuer_ref
    }
  })
}

resource "kubectl_manifest" "rabbitmq_broker_tls" {
  depends_on = [kustomization_resource.p0]

  yaml_body = yamlencode({
    apiVersion = "cert-manager.io/v1"
    kind       = "Certificate"
    metadata   = { name = "rabbitmq-broker-tls", namespace = var.namespace }
    spec = {
      # Three keys land here: tls.crt, tls.key and ca.crt. The broker mounts all
      # three; the server pod projects ONLY ca.crt, which is the whole point of
      # the split — it verifies the broker and must not hold the broker's key.
      secretName  = "rabbitmq-broker-tls"
      dnsNames    = local.svc_names["rabbitmq"]
      privateKey  = { algorithm = "Ed25519", rotationPolicy = "Always" }
      duration    = "${var.restart_required_leaf_duration_hours}h"
      renewBefore = "720h"
      issuerRef   = local.issuer_ref
    }
  })
}

resource "kubectl_manifest" "axiam_server_tls" {
  depends_on = [kustomization_resource.p0]

  yaml_body = yamlencode({
    apiVersion = "cert-manager.io/v1"
    kind       = "Certificate"
    metadata   = { name = "axiam-server-tls", namespace = var.namespace }
    spec = {
      # The backend's own TLS 1.3 listener. These names are what ingress-nginx
      # verifies against via `proxy-ssl-name`, NOT the public hostname a browser
      # types — the ingress terminates that and opens a second connection.
      secretName = "axiam-server-tls"
      dnsNames   = local.svc_names["axiam-server"]
      privateKey = { algorithm = "Ed25519", rotationPolicy = "Always" }
      # Ninety days is fine here, unlike Vault and RabbitMQ: the server re-stats
      # its leaf every AXIAM__SERVER__TLS__RELOAD_INTERVAL_SECS and swaps it
      # behind an ArcSwap rustls consults per handshake. No restart, no dropped
      # request — provided the volume is not mounted with subPath, which the
      # kubelet does not refresh.
      duration    = "${var.internal_leaf_duration_hours}h"
      renewBefore = "360h"
      issuerRef   = local.issuer_ref
    }
  })
}

resource "kubectl_manifest" "ingress_client" {
  depends_on = [kustomization_resource.p0]

  yaml_body = yamlencode({
    apiVersion = "cert-manager.io/v1"
    kind       = "Certificate"
    metadata   = { name = "axiam-ingress-client", namespace = var.namespace }
    spec = {
      # Referenced by proxy-ssl-secret on the API Ingress. Two things come out
      # of this Secret and the annotation needs both: `ca.crt`, the anchor
      # ingress-nginx verifies the backend against, and a client keypair nginx
      # presents upstream. The server ignores the client certificate under
      # `client_auth: off`, but the controller writes proxy_ssl_certificate
      # unconditionally from this Secret, so one holding only ca.crt is a
      # configuration it will not accept.
      secretName  = "axiam-ingress-client"
      commonName  = "axiam-ingress"
      usages      = ["client auth"]
      privateKey  = { algorithm = "Ed25519", rotationPolicy = "Always" }
      duration    = "${var.internal_leaf_duration_hours}h"
      renewBefore = "360h"
      issuerRef   = local.issuer_ref
    }
  })
}

# The manifests below mount these Secrets, and a pod whose Secret does not exist
# yet sits in ContainerCreating until it does. Waiting here turns "why is
# everything stuck" into an apply that either finishes or says which certificate
# did not become Ready and why.
resource "terraform_data" "certificates_ready" {
  depends_on = [
    kubectl_manifest.vault_tls,
    kubectl_manifest.rabbitmq_broker_tls,
    kubectl_manifest.axiam_server_tls,
    kubectl_manifest.ingress_client,
  ]

  provisioner "local-exec" {
    command = <<-EOT
      kubectl --kubeconfig='${var.kubeconfig_path}' -n '${var.namespace}' \
        wait --for=condition=Ready certificate --all --timeout=300s
    EOT
  }
}
