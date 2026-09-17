# ---------------------------------------------------------------------------
# The AXIAM manifests — the base plus the Pi overlay
# ---------------------------------------------------------------------------
#
# `kustomization_overlay` renders an overlay described in HCL. It exists here
# rather than a plain `kustomization_build` of the directory for one reason: the
# gRPC Ingress has to be conditional, and `grpc_public` is the single place that
# decision is recorded. Everything else is the on-disk overlay, unchanged, so
# `kubectl kustomize infra/rpi5-k3s/overlay` and what this applies are the same
# objects.
data "kustomization_overlay" "axiam" {
  namespace = var.namespace

  resources = concat(
    [var.overlay_path],
    # D6. NOT in the overlay's own kustomization.yml — off by default, and this
    # is where turning it on shows up in a `tofu plan`.
    var.grpc_public ? ["${var.overlay_path}/ingress-grpc.yml"] : [],
  )

  # The three gRPC settings that have to move together with the Ingress above.
  # Miss any one and you get a listener in cleartext, a second certificate to
  # renew, or a session that stays valid over gRPC for fifteen minutes after
  # logout. One variable, three effects, no way to set half of it.
  dynamic "patches" {
    for_each = var.grpc_public ? [1] : []
    content {
      target {
        kind = "Deployment"
        name = "axiam-server"
      }
      patch = yamlencode({
        apiVersion = "apps/v1"
        kind       = "Deployment"
        metadata   = { name = "axiam-server", namespace = var.namespace }
        spec = {
          template = {
            spec = {
              containers = [{
                name = "axiam-server"
                env = [
                  # FLAT names, read straight out of the process environment —
                  # NOT AXIAM__GRPC__TLS__CERT_PATH. The wrong spelling is
                  # silently ignored and the listener comes up in cleartext.
                  # Both or neither: the server panics at startup if either
                  # names a file it cannot read, which is deliberate.
                  #
                  # The SAME files the REST listener serves. One certificate,
                  # both listeners, one reloader — there is no second
                  # certificate and there must not be.
                  { name = "AXIAM__GRPC_TLS_CERT_PATH", value = "/etc/axiam/server-tls/tls.crt" },
                  { name = "AXIAM__GRPC_TLS_KEY_PATH", value = "/etc/axiam/server-tls/tls.key" },
                  # REST re-checks session revocation on every request; the gRPC
                  # data plane validates signature and expiry and stops there
                  # unless this is on. On a listener the internet can reach,
                  # take REST's semantics — otherwise a session revoked by
                  # logout keeps passing gRPC authorization until the access
                  # token expires, up to fifteen minutes.
                  { name = "AXIAM__GRPC__STRICT_REVOCATION", value = "true" },
                ]
              }]
            }
          }
        }
      })
    }
  }
}

# ---------------------------------------------------------------------------
# Applied in three passes, because ordering is not optional
# ---------------------------------------------------------------------------
#
# The provider sorts every rendered object into three priority sets:
#   [0] Namespaces, CRDs — things other objects cannot be created without
#   [1] everything else
#   [2] validating/mutating webhook configurations, last
#
# Pass 0 is separated out for a concrete reason and not for tidiness: the
# Secrets in credentials.tf and the Certificates in certificates.tf are created
# IN the `axiam` namespace, and that namespace is itself one of these manifests.
# Without the split, an apply on a clean cluster races and roughly half the
# objects fail with `namespaces "axiam" not found`.
resource "kustomization_resource" "p0" {
  for_each = data.kustomization_overlay.axiam.ids_prio[0]
  manifest = data.kustomization_overlay.axiam.manifests[each.value]
}

resource "kustomization_resource" "p1" {
  for_each = data.kustomization_overlay.axiam.ids_prio[1]
  manifest = data.kustomization_overlay.axiam.manifests[each.value]

  # The workloads mount `vault-tls`, `rabbitmq-broker-tls`, `axiam-server-tls`
  # and the three credential Secrets. Creating them before those exist is not an
  # error — the pods sit in ContainerCreating and recover on their own — but it
  # turns an apply that either finishes or names the certificate that failed
  # into "why is everything stuck", which is a worse afternoon.
  depends_on = [
    terraform_data.certificates_ready,
    kubernetes_secret.surrealdb,
    kubernetes_secret.rabbitmq,
    kubernetes_secret.axiam,
  ]
}

resource "kustomization_resource" "p2" {
  for_each   = data.kustomization_overlay.axiam.ids_prio[2]
  manifest   = data.kustomization_overlay.axiam.manifests[each.value]
  depends_on = [kustomization_resource.p1]
}
