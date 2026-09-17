# ---------------------------------------------------------------------------
# ingress-nginx — D2
# ---------------------------------------------------------------------------
#
# In namespace `ingress-nginx`, with class `nginx`, because that is what the
# shipped manifests already assume: `k8s/ingress.yml` is
# `ingressClassName: nginx` with ingress-nginx annotations, and
# `allow-ingress-to-server.yml` / `allow-ingress-to-frontend.yml` select the
# namespace BY NAME. Installing it anywhere else, or under any other class,
# means nothing can reach the server and the NetworkPolicies say why only if
# you read them.
#
# HOSTNETWORK IS NOT A CONVENIENCE. It is what keeps invariant 1 true. Every
# alternative on a single node puts something between the client and the
# controller: k3s's ServiceLB (klipper-lb) is a DaemonSet of iptables-DNAT
# pods, MetalLB is another controller, a NodePort needs a non-standard port.
# With hostNetwork the controller binds the node's 80/443 directly and the
# client's address IS the socket peer — which is the property
# AXIAM__RATE_LIMIT__TRUSTED_HOPS=0 rests on. 01-install-k3s.sh disables
# ServiceLB for the same reason.
resource "helm_release" "ingress_nginx" {
  name             = "ingress-nginx"
  repository       = "https://kubernetes.github.io/ingress-nginx"
  chart            = "ingress-nginx"
  version          = var.ingress_nginx_chart_version
  namespace        = "ingress-nginx"
  create_namespace = true
  # A Pi is not fast. The default 5 minutes is enough for the controller but not
  # always for its admission webhook's certificate job on first install.
  timeout = 900
  wait    = true

  values = [yamlencode({
    controller = {
      kind        = "DaemonSet"
      hostNetwork = true
      # Required with hostNetwork: a pod on the host's network namespace
      # resolves through the host's /etc/resolv.conf by default, and the
      # controller has to resolve in-cluster Service names to find its backends.
      dnsPolicy = "ClusterFirstWithHostNet"

      service = {
        # The controller already owns the node's ports. A LoadBalancer or
        # NodePort Service here would be a second path to the same listener —
        # one that SNATs, and whose source-IP behaviour is a setting rather
        # than a guarantee.
        enabled = false
      }

      # One node, one copy. `replicaCount` is ignored for a DaemonSet; this is
      # here so the intent survives someone switching kind back to Deployment.
      replicaCount = 1

      # The admission webhook validates Ingress objects before they are stored,
      # which is worth having: a bad annotation becomes a rejected apply rather
      # than a controller that silently drops a route.
      admissionWebhooks = { enabled = true }

      config = {
        # LOAD-BEARING. At chart 4.15.1 the controller's nginx.tmpl emits
        #     proxy_set_header X-Forwarded-For $remote_addr;
        # unless BOTH use-forwarded-headers and compute-full-forwarded-for are
        # true. False here therefore means nginx REPLACES the header with the
        # socket peer rather than passing through whatever the client sent.
        #
        # That is what makes TRUSTED_HOPS=0 correct AND forgery-proof: a client
        # that sends its own X-Forwarded-For has it discarded, not merely
        # out-voted. Set this to "true" and a client picks its own rate-limit
        # bucket — including on /auth/login, which is deliberately always keyed
        # per-IP so an attacker cannot lock out a victim.
        #
        # Turn it on ONLY if something you control sits in front of this
        # controller, and then TRUSTED_HOPS is no longer 0. See
        # docs/deployment/rpi5-k3s.md §6.3.
        use-forwarded-headers = "false"

        # TLS 1.3 only on the public listener, matching the project standard.
        ssl-protocols = "TLSv1.3"

        # Do not advertise the version in the Server header or on error pages.
        server-tokens = "false"

        # A Pi with 8 GB. The chart's default worker_processes is auto (4 on a
        # Pi 5) and 16384 connections each; the ceiling is not the problem here,
        # memory is.
        max-worker-connections = "4096"
      }

      resources = {
        requests = { cpu = "100m", memory = "128Mi" }
        limits   = { cpu = "500m", memory = "256Mi" }
      }
    }
  })]
}

# ---------------------------------------------------------------------------
# cert-manager — D3
# ---------------------------------------------------------------------------
#
# CRDs installed by the chart rather than applied separately. The trade is that
# `helm uninstall` leaves them behind (the chart does not delete CRDs, on
# purpose — deleting a CRD deletes every object of that kind, which here would
# be every certificate in the cluster). That is the safer failure.
resource "helm_release" "cert_manager" {
  name             = "cert-manager"
  repository       = "https://charts.jetstack.io"
  chart            = "cert-manager"
  version          = var.cert_manager_version
  namespace        = "cert-manager"
  create_namespace = true
  timeout          = 900
  wait             = true

  values = [yamlencode({
    crds = { enabled = true }
    # One of each on one node. The chart defaults to one replica already; said
    # explicitly because the webhook and cainjector defaults have changed
    # between versions and a silent 2 here is 120 MB.
    replicaCount = 1
    webhook      = { replicaCount = 1 }
    cainjector   = { replicaCount = 1 }
    resources = {
      requests = { cpu = "50m", memory = "64Mi" }
      limits   = { memory = "128Mi" }
    }
  })]
}

# The webhook is what rejects a bad Certificate at admission, and it is not
# serving the instant the Deployment reports Available. Everything below creates
# cert-manager custom resources, so this wait is the difference between a clean
# apply and one that fails with `connection refused` on the webhook service and
# succeeds on a second run — the kind of flake an operator learns to re-run
# through instead of reading.
resource "terraform_data" "cert_manager_ready" {
  depends_on = [helm_release.cert_manager]

  provisioner "local-exec" {
    command = <<-EOT
      kubectl --kubeconfig='${var.kubeconfig_path}' -n cert-manager \
        wait --for=condition=Available deployment --all --timeout=300s
    EOT
  }
}
