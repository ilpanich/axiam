# ---------------------------------------------------------------------------
# Credentials — K8S-F8
# ---------------------------------------------------------------------------
#
# `surrealdb-credentials`, `rabbitmq-credentials` and `axiam-secrets` ship blank
# in `k8s/`, by design: a manifest with a real password in it is a manifest
# nobody can commit. This stage fills them, and OWNS them — the overlay deletes
# the three blank ones from the render (overlay/secrets-owned-by-tofu.yml) so
# there is exactly one manager per object. Two managers of a Secret is how a
# `kubectl apply -k` at the wrong moment blanks a live datastore's password.
#
# ###########################################################################
# THESE ARE HONOURED ONLY ON THE FIRST BOOT OF AN EMPTY VOLUME.
# ###########################################################################
#
# SurrealDB writes its root user into the datastore the first time it starts on
# an empty `/data`, and RabbitMQ does the same for RABBITMQ_DEFAULT_USER /
# _PASS / _VHOST on an empty `/var/lib/rabbitmq`. After that the values here are
# the credentials the SERVER presents, and the datastore's own idea of what they
# should be is whatever it recorded on day one. Change one and you do not
# rotate anything — you break authentication, and the only ways back are
# `rabbitmqctl change_password` / a SurrealDB `DEFINE USER`, or deleting the
# PVC and everything in it.
#
# Hence the lifecycle blocks on every one of them:
#
#   ignore_changes = all   a later `tofu apply` that would regenerate the value
#                          (a provider upgrade changing `random_password`'s
#                          keepers, an edited `length`) is a no-op instead.
#   prevent_destroy = true `tofu destroy` on this stage refuses. Deliberately
#                          stronger than run.sh's flag: the flag stops an
#                          accident, this stops a determined mistake. An
#                          operator who genuinely means it edits this block,
#                          which is a diff somebody can review.
#
# AND: THE STATE FILE IS A SECRET. Every value below is in it in cleartext
# unless you configured `encryption.tofu`. See §6 of the operator guide.

resource "random_password" "db" {
  length = 32
  # No punctuation. This value goes into the AMQP URL below by way of
  # `urlencode`, and into a SurrealDB `--pass` argument; a generator that only
  # ever emits [A-Za-z0-9] removes a whole class of quoting bug from two places
  # at the cost of ~1.6 bits per character, which at length 32 leaves 190 bits.
  special = false

  lifecycle {
    ignore_changes  = all
    prevent_destroy = true
  }
}

resource "random_password" "rabbitmq" {
  length  = 32
  special = false

  lifecycle {
    ignore_changes  = all
    prevent_destroy = true
  }
}

resource "kubernetes_secret" "surrealdb" {
  depends_on = [kustomization_resource.p0]

  metadata {
    name      = "surrealdb-credentials"
    namespace = var.namespace
    labels    = { app = "axiam", component = "surrealdb" }
  }
  # Key names are fixed by k8s/surrealdb/statefulset.yml's secretKeyRefs.
  data = {
    username = var.db_username
    password = random_password.db.result
  }

  lifecycle {
    ignore_changes  = all
    prevent_destroy = true
  }
}

resource "kubernetes_secret" "rabbitmq" {
  depends_on = [kustomization_resource.p0]

  metadata {
    name      = "rabbitmq-credentials"
    namespace = var.namespace
    labels    = { app = "axiam", component = "rabbitmq" }
  }
  data = {
    username = var.rabbitmq_username
    password = random_password.rabbitmq.result
  }

  lifecycle {
    ignore_changes  = all
    prevent_destroy = true
  }
}

resource "kubernetes_secret" "axiam" {
  depends_on = [kustomization_resource.p0]

  metadata {
    name      = "axiam-secrets"
    namespace = var.namespace
    labels    = { app = "axiam", component = "server" }
  }
  data = {
    AXIAM__DB__USERNAME = var.db_username
    AXIAM__DB__PASSWORD = random_password.db.result

    # The full AMQP URI, credentials included: `AmqpConfig` has only a `url`
    # field, so there is nowhere else for the broker password to go — which is
    # exactly why this cannot live in the ConfigMap.
    #
    # `amqps://`, not `amqp://`: `validate_transport_security` refuses every
    # other scheme in every build profile, and the broker has no plaintext
    # listener to fall back to anyway.
    #
    # The trailing vhost is not decoration. Omitting it connects to the default
    # vhost `/`, where this user has no permissions at all, and the failure
    # reads as an authentication error rather than an authorization one.
    #
    # urlencode on the password even though `special = false` makes it
    # unnecessary today: the invariant is "this value is percent-encoded", not
    # "this generator happens to emit safe characters".
    AXIAM__AMQP__URL = format(
      "amqps://%s:%s@rabbitmq:5671/%s",
      var.rabbitmq_username,
      urlencode(random_password.rabbitmq.result),
      var.amqp_vhost,
    )
  }

  # AXIAM__AUTH__VAULT_TOKEN is NOT here. It is a separate Secret
  # (`axiam-vault-token`) created by stage 30, because it does not exist until
  # after the human ceremony and one object with two owners across two stages
  # is how a token gets blanked by a re-apply of the stage that does not have
  # it. The overlay adds a second `envFrom` for it.
  #
  # Between this stage and stage 30 the server pod therefore sits in
  # CreateContainerConfigError saying `secret "axiam-vault-token" not found`.
  # That is correct and expected: it genuinely cannot run before the ceremony.

  lifecycle {
    ignore_changes  = all
    prevent_destroy = true
  }
}
