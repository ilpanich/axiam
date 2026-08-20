import type { DocPage } from "./types";

/**
 * "Operate" — running AXIAM rather than integrating with it.
 *
 * The hardening page is the one to keep as a checklist rather than prose: it is
 * meant to be worked through before a deployment carries real traffic, and a
 * checklist is checkable in a way an essay is not.
 */
export const OPERATE_PAGES: DocPage[] = [
  {
    slug: "deploy",
    section: "Operate",
    navLabel: "Docker & Kubernetes",
    title: "Docker & Kubernetes",
    intro:
      "Package AXIAM as a container and run it on Kubernetes with the shipped manifests.",
    blocks: [
      { type: "h", id: "docker", text: "Docker" },
      {
        type: "p",
        text: "`docker/` holds the Dockerfiles and the compose configurations. `docker-compose.dev.yml` runs only SurrealDB and RabbitMQ, for developing against a natively-run server. `docker-compose.prod.yml` runs the whole stack — server, admin console, database, broker and Vault — and is documented in the file itself as **not** intended for real production use.",
      },
      {
        type: "code",
        code: "just dev-up      # SurrealDB + RabbitMQ only\njust prod-up     # the whole stack, including the Vault ceremony\njust prod-down   # stop, keep volumes\njust prod-clean  # stop and remove volumes",
      },
      {
        type: "p",
        text: "`docker-compose.prod.yml` refuses to start without the database and broker credentials and the JWT keypair present in the environment — it uses Compose's fail-fast variable syntax rather than silently defaulting. Secret material lives in a gitignored `docker/.secrets/` directory, never in the compose file.",
      },
      { type: "h", id: "k8s", text: "Kubernetes" },
      {
        type: "p",
        text: "The manifests under `k8s/` are assembled by a kustomization and deploy `axiam-server`, the admin console, SurrealDB, RabbitMQ and Vault, together with the NetworkPolicies that keep them talking only to each other.",
      },
      {
        type: "code",
        caption: "apply",
        code: "kubectl apply -k k8s/\nkubectl -n axiam get pods\nkubectl -n axiam logs deploy/axiam-server",
      },
      { type: "h", id: "ports", text: "What is exposed, and what is not" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Port", "Service", "Exposure"],
        rows: [
          ["8090", "REST API", "Through the Ingress, TLS-terminated."],
          ["8081", "Admin console", "Through the Ingress, TLS-terminated."],
          [
            "50051",
            "gRPC",
            "**Deliberately not routed through the Ingress.** Reachable only via the in-cluster ClusterIP service.",
          ],
          ["5671", "AMQP", "In-cluster only, TLS-only (`amqps://`)."],
          ["8200", "Vault", "In-cluster only, TLS."],
        ],
      },
      { type: "h", id: "probes", text: "Probes" },
      {
        type: "p",
        text: "Point the liveness probe at `/health` and the readiness probe at `/ready`. The distinction matters: `/health` answers 200 whenever the process is up, while `/ready` checks database connectivity and answers 503 when it cannot reach SurrealDB — so a database blip takes replicas out of the load-balancer rotation instead of restarting them in a loop.",
      },
      { type: "h", id: "scaling", text: "Scaling" },
      {
        type: "p",
        text: "`axiam-server` is stateless — every piece of durable state is in SurrealDB — so replicas scale horizontally behind an ordinary load balancer with no session affinity required.",
      },
      {
        type: "warn",
        text: "One caveat when scaling out: the cross-replica shared rate-limit counter is **write-behind**, so enforcement across replicas is eventual rather than synchronous. Worst-case overshoot beyond a configured limit is roughly `(replicas − 1) × arrival_rate_per_replica × sync_interval`, and is zero on a single replica. The per-replica in-memory governor still caps overshoot independently.",
      },
      { type: "h", id: "tls", text: "TLS" },
      {
        type: "p",
        text: "By default the server binds plaintext and expects an ingress or proxy to terminate TLS 1.3 in front of it. To terminate inside the process instead, set `AXIAM__SERVER__TLS__ENABLED` with a certificate and key path; the listener then binds with rustls restricted to TLS 1.3 only, and fails fast at startup on a missing, unreadable or mismatched pair rather than falling back to plaintext.",
      },
      {
        type: "warn",
        text: "AXIAM is pre-1.0. Treat these manifests as a solid starting point for a staging environment, and work through [Production hardening](#/docs/hardening) before anything real depends on them.",
      },
    ],
  },

  {
    slug: "secrets",
    section: "Operate",
    navLabel: "Secrets & Vault",
    title: "Secrets & HashiCorp Vault",
    intro:
      "AXIAM holds ten long-lived secrets. Two of them are the difference between \"an attacker read your database\" and \"an attacker owns your identity provider\".",
    blocks: [
      { type: "h", id: "what", text: "The ten secrets" },
      {
        type: "table",
        headers: ["Field", "Shape", "What losing it costs"],
        rows: [
          [
            "opaque_setup_key",
            "32-byte hex",
            "**A password reset for every user in every tenant.** It encrypts each tenant's OPRF seed; without it no OPAQUE record can be opened.",
          ],
          [
            "jwt_private_key_pem",
            "Ed25519 PEM",
            "**Total compromise.** Whoever holds it can mint a token for any principal in any tenant.",
          ],
          [
            "pki_encryption_key",
            "32-byte hex",
            "**CA compromise.** It encrypts CA private keys at rest; a leak lets an attacker issue certificates every mTLS client trusts.",
          ],
          [
            "auth_pepper",
            "text",
            "Every stored password hash is invalidated if it *changes*; a leak makes offline attack on stolen hashes cheaper.",
          ],
          [
            "opaque_session_key",
            "32-byte hex",
            "In-flight OPAQUE exchanges (120 s) are invalidated. Cheap to rotate — deliberately separate from the setup key.",
          ],
          ["mfa_encryption_key", "32-byte hex", "Stored TOTP secrets become undecryptable."],
          ["federation_encryption_key", "32-byte hex", "Stored IdP client secrets become undecryptable."],
          ["email_encryption_key", "32-byte hex", "Stored email addresses become undecryptable."],
          [
            "gdpr_pseudonym_pepper",
            "32-byte hex",
            "Existing audit pseudonyms stop linking to new ones; the audit trail breaks.",
          ],
          [
            "jwt_public_key_pem",
            "Ed25519 PEM",
            "Not secret, but a mismatched pair is a confusing outage.",
          ],
        ],
      },
      { type: "h", id: "providers", text: "Three providers" },
      {
        type: "p",
        text: "`AXIAM__AUTH__SECRET_PROVIDER` selects where the server fetches these at startup. An unknown value is **refused at startup** rather than falling back to `env`, because a typo that silently reverted a deployment to reading unset environment variables presents as \"OPAQUE stopped working\" with nothing in the logs explaining why.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Provider", "Reads from", "Use it for"],
        rows: [
          [
            "`env` (default)",
            "Environment variables — `AXIAM__AUTH__JWT_PRIVATE_KEY_PEM` and friends.",
            "Local development. Fine for a workstation, poor for anything that has a `kubectl describe pod`.",
          ],
          [
            "`file`",
            "One file per secret in `AXIAM__AUTH__SECRET_DIR`, named after the field.",
            "Kubernetes and Docker secret volumes — the shape those already produce, with no Vault to run.",
          ],
          [
            "`vault`",
            "A KV v2 secret at `<mount>/<path>` whose fields are named after the list above.",
            "Production. Rotation, audit, and a leak surface that is not \"anything that can read the pod spec\".",
          ],
        ],
      },
      {
        type: "note",
        text: "AXIAM's actual requirement is small: a KV v2 secret whose fields carry those names. It does not care who runs Vault, whether it is HA, or how it is unsealed. If your organization already runs one, point `AXIAM__AUTH__VAULT_ADDR` at it, create the read-only policy, and skip the rest.",
      },
      { type: "h", id: "honesty", text: "What Vault does and does not defend against" },
      {
        type: "warn",
        text: "**Vault does not defend against a compromised application server.** It defends against the ways keys actually leak — a config file committed to git, an over-shared CI variable, a `kubectl describe pod`, a backup of an orchestrator's etcd. An attacker with code execution on the server can read whatever the server can read, and the server must be able to read these.",
      },
      {
        type: "p",
        text: "The construction that *would* defend against that is envelope encryption against a Transit-style API, where the plaintext key never leaves the KMS — at the cost of a network round trip per seal and open. The `SecretProvider` trait is the place to add it, and doing so requires no change to any authentication code.",
      },
      { type: "h", id: "local", text: "Local development" },
      {
        type: "code",
        code: "just dev-up       # SurrealDB + RabbitMQ. No Vault; provider stays `env`.\njust vault-up     # adds a dev-mode Vault and seeds every secret into it\njust vault-status # which secrets Vault holds — presence only, never values",
      },
      {
        type: "p",
        text: "Dev-mode Vault is in-memory, starts unsealed, listens on plain HTTP and uses a fixed root token. Every one of those is wrong for production — which is exactly the point: it removes the unseal ceremony from an edit-compile-run loop.",
      },
      { type: "h", id: "production", text: "Production: what cannot be automated" },
      {
        type: "p",
        text: "The manifests under `k8s/vault/` deploy a single-node Vault with file storage — production-*shaped*, not production-*ready*. Most teams should run HashiCorp's Helm chart with Raft and three to five replicas, or use an existing Vault. Either way these steps are what AXIAM needs, and none of them is safe to automate.",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Give Vault's listener TLS",
            body: "The token AXIAM presents on every fetch is a bearer credential for the setup key. Over plaintext, anything on the pod network can take it.",
          },
          {
            title: "Initialise — once, and never again",
            body: "The output is printed once and cannot be recovered. It contains five unseal key shares and a root token. Give each share to a **different person** — three of five must cooperate to unseal, which is the whole point of the scheme. Do not put all five in one password manager, and do not store them with the root token.",
            code: "kubectl exec -n axiam vault-0 -- vault operator init \\\n    -key-shares=5 -key-threshold=3 -format=json",
          },
          {
            title: "Configure auto-unseal before you go live",
            body: "Without it, every restart — a node drain, an upgrade, an OOM kill — leaves Vault sealed and AXIAM unable to start until three people are woken up. This is the single most important production step, and the one most often deferred.",
          },
          {
            title: "Create a read-only, single-path policy",
            body: "A leaked AXIAM token must not be a key to the rest of your Vault.",
            code: "vault policy write axiam - <<'EOF'\npath \"secret/data/axiam\"     { capabilities = [\"read\"] }\npath \"secret/metadata/axiam\" { capabilities = [\"read\"] }\nEOF",
          },
          {
            title: "Seed the secrets",
            body: "The seeding script **never regenerates a secret that already exists**, so re-running it after adding a key or after a restore is safe. That behaviour is unit-tested, precisely because getting it wrong would mean a password reset for every user.",
            code: "scripts/vault-seed.sh",
          },
          {
            title: "Prefer Kubernetes auth over a static token",
            body: "A static token works and is what the manifests ship with, because something has to bootstrap the trust chain. It does not rotate and it sits in etcd. With the Kubernetes auth method the Secret disappears and the pod authenticates with its ServiceAccount token, which Kubernetes rotates.",
          },
          {
            title: "Revoke the root token",
            body: "Use it for the policy and seeding steps, then revoke it. Generate a new one with the root-generation ceremony on the rare occasions you need one.",
          },
        ],
      },
      {
        type: "note",
        text: "Only the *ciphertext* of the OPRF seeds lives in the database. Moving the seeds themselves to a file on the server volume would put them on the same side of the trust boundary as the key, break replicas, lose transactionality with the credential rows, and turn a lost volume into total tenant lockout.",
      },
    ],
  },

  {
    slug: "settings",
    section: "Operate",
    navLabel: "Settings & policies",
    title: "Settings & policies",
    intro:
      "Password, lockout, MFA, token, certificate, email and OPAQUE policy — set as an organization baseline, and tightened per tenant.",
    blocks: [
      { type: "h", id: "shape", text: "Baseline and overrides" },
      {
        type: "p",
        text: "Policy is hierarchical. An **organization** holds the baseline; a **tenant** may override individual fields. An override of `null` means *inherit*, so a tenant only states what it wants to differ — and reading a tenant's effective settings returns every field fully resolved, with nothing left to work out by hand.",
      },
      {
        type: "warn",
        text: "Tenant overrides are **tighten-only**. A tenant can make its posture stricter than the organization baseline; it cannot make it looser. That is what keeps an organization-level security decision meaningful once tenants can edit their own configuration.",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/organizations/{org_id}/settings", summary: "Read the organization baseline." },
          { method: "PUT", path: "/api/v1/organizations/{org_id}/settings", summary: "Set it." },
          { method: "GET", path: "/api/v1/settings", summary: "Read the calling tenant's fully-resolved settings." },
          { method: "PUT", path: "/api/v1/settings", summary: "Set the tenant's overrides." },
        ],
      },
      { type: "h", id: "password", text: "Password policy" },
      {
        type: "table",
        headers: ["Field", "Meaning"],
        rows: [
          ["min_length", "Minimum password length."],
          ["require_uppercase", "Require at least one uppercase character."],
          ["require_lowercase", "Require at least one lowercase character."],
          ["require_digits", "Require at least one digit."],
          ["require_symbols", "Require at least one symbol."],
          [
            "password_history_count",
            "How many previous passwords a new one is checked against, so a rotation cannot cycle back.",
          ],
          [
            "hibp_check_enabled",
            "Reject passwords appearing in known-breach corpora. Worth more than any three complexity rules combined.",
          ],
        ],
      },
      {
        type: "note",
        text: "If you are choosing where to spend policy strictness, spend it on `hibp_check_enabled` and length rather than on symbol classes. Composition rules push users toward predictable substitutions; breach-checking rejects the passwords attackers actually try.",
      },
      { type: "h", id: "lockout", text: "Lockout policy" },
      {
        type: "table",
        headers: ["Field", "Meaning"],
        rows: [
          ["max_failed_login_attempts", "Failures before the account locks."],
          ["lockout_duration_secs", "How long the first lock lasts."],
          ["lockout_backoff_multiplier", "Multiplier applied on each subsequent lock."],
          ["max_lockout_duration_secs", "Ceiling the backoff is clamped to."],
        ],
      },
      { type: "h", id: "tokens", text: "Token & MFA policy" },
      {
        type: "table",
        headers: ["Field", "Meaning"],
        rows: [
          ["access_token_lifetime_secs", "How long an access token is valid. Shorter is better; 15 minutes is the default."],
          ["refresh_token_lifetime_secs", "How long a refresh token remains usable before re-authentication."],
          ["mfa_enforced", "Require a second factor for every user in scope."],
          ["mfa_challenge_lifetime_secs", "How long an issued MFA challenge stays answerable."],
        ],
      },
      { type: "h", id: "other", text: "Email, certificate & OPAQUE policy" },
      {
        type: "table",
        headers: ["Field", "Meaning"],
        rows: [
          ["email_verification_required", "Whether an unverified address blocks sign-in."],
          ["email_verification_grace_period_hours", "How long an unverified account keeps working before it does."],
          ["default_cert_validity_days", "Validity applied to issued certificates when none is requested."],
          ["max_cert_validity_days", "Ceiling on requested certificate validity."],
          ["opaque_mode", "`disabled` | `optional` | `required` — see [OPAQUE](#/docs/opaque)."],
          ["opaque_suite", "RFC 9807 ciphersuite. Default `ristretto255_sha512`."],
          ["opaque_ksf", "Client key-stretching function. Default `argon2id`; `scrypt` is the alternative."],
        ],
      },
      {
        type: "warn",
        text: "`opaque_mode: required` is the one setting that can lock every user out of a tenant. Nobody can be enrolled retroactively, so it is only safe once every user already has a registration record. Run `optional` until enrolment is complete.",
      },
    ],
  },

  {
    slug: "pki",
    section: "Operate",
    navLabel: "PKI & certificates",
    title: "PKI & certificates",
    intro:
      "Per-tenant X.509 issuance under an organization CA, for users, services and IoT devices — plus the OpenPGP keys that sign the audit trail.",
    blocks: [
      { type: "h", id: "hierarchy", text: "Certificate hierarchy" },
      {
        type: "p",
        text: "An organization holds one or more **CA certificates**. Tenants issue leaf certificates under them, with RSA-4096 or Ed25519 keys. Private keys are **never stored server-side** — a leaf key is returned exactly once at issuance and cannot be recovered afterwards. CA signing keys are encrypted at rest with AES-256-GCM under `AXIAM__PKI__ENCRYPTION_KEY`.",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/organizations/{org_id}/ca-certificates", summary: "List the organization's CAs." },
          { method: "POST", path: "/api/v1/organizations/{org_id}/ca-certificates", summary: "Create one." },
          { method: "POST", path: "/api/v1/organizations/{org_id}/ca-certificates/{id}/revoke", summary: "Revoke a CA." },
          { method: "GET", path: "/api/v1/certificates", summary: "List issued leaf certificates in the tenant." },
          { method: "POST", path: "/api/v1/certificates", summary: "Issue one. The private key is returned once." },
          { method: "GET", path: "/api/v1/certificates/{id}", summary: "Read one." },
          { method: "POST", path: "/api/v1/certificates/{id}/revoke", summary: "Revoke it." },
        ],
      },
      {
        type: "warn",
        text: "Revoking a CA invalidates every certificate issued under it. That is the intended behaviour and it is not reversible — plan the blast radius before you do it, and prefer issuing under a fresh CA and migrating.",
      },
      { type: "h", id: "mtls", text: "mTLS for devices and services" },
      {
        type: "p",
        text: "Certificate-based authentication gives machine identities the same tenant-scoped authorization as human users. A certificate is bound to a service account, and the TLS handshake is verified **in-process** — there is no proxy-asserted identity header in the trusted path.",
      },
      {
        type: "table",
        headers: ["Variable", "Values", "Default", "Meaning"],
        rows: [
          ["AXIAM__SERVER__TLS__CLIENT_AUTH", "off | optional | required", "off", "Client-certificate policy."],
          ["AXIAM__SERVER__TLS__CLIENT_CA_PATH", "PEM bundle path", "—", "Trust anchors for client certificates."],
        ],
      },
      {
        type: "p",
        text: "`optional` requests a certificate and verifies it if presented, while still accepting anonymous clients. `required` rejects the handshake outright without a verifying certificate. A misconfigured client-auth setup **fails fast at startup** rather than serving without verification.",
      },
      { type: "h", id: "iot", text: "IoT commissioning" },
      {
        type: "p",
        text: "This is the shape AXIAM was built for on the device side: a device is issued a certificate at commissioning, presents it for mTLS, and is authorized by the same RBAC engine as everything else. Where a device cannot show a browser to enrol, the [device authorization grant](#/docs/device-flow) covers the human-approval half.",
      },
      { type: "h", id: "gnupg", text: "OpenPGP keys" },
      {
        type: "p",
        text: "PGP keys managed through the PKI layer sign the audit trail and encrypt data exports, so exported data and audit records are verifiable and confidential end to end.",
      },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/pgp-keys", summary: "List the tenant's PGP keys." },
          { method: "POST", path: "/api/v1/pgp-keys", summary: "Create one." },
          { method: "POST", path: "/api/v1/pgp-keys/{id}/encrypt", summary: "Encrypt a payload to a key." },
          { method: "POST", path: "/api/v1/pgp-keys/{id}/revoke", summary: "Revoke it." },
          { method: "POST", path: "/api/v1/pgp-keys/sign-audit-batch", summary: "Sign a batch of audit records." },
        ],
      },
    ],
  },

  {
    slug: "audit",
    section: "Operate",
    navLabel: "Audit logging",
    title: "Audit logging",
    intro:
      "An append-only, cryptographically signed record of every privileged action — tamper-evident rather than merely tamper-resistant.",
    blocks: [
      { type: "h", id: "appendonly", text: "Append-only by design" },
      {
        type: "p",
        text: "The audit log has no UPDATE and no DELETE path. Not \"they are permission-guarded\" — they do not exist. Records are chained and signed, so any attempt to alter or remove history is detectable after the fact rather than silent.",
      },
      {
        type: "p",
        text: "Ingestion runs asynchronously over AMQP so that writing an audit record never slows down the operation being audited, and never fails it. Every authentication, authorization decision and administrative mutation across every tenant flows through the same pipeline.",
      },
      { type: "h", id: "signing", text: "Cryptographic signing" },
      {
        type: "p",
        text: "Entries are signed with OpenPGP keys managed by the PKI layer, which gives you a trail verifiable independently of AXIAM itself. Combined with the chain between records, that is what makes the log tamper-*evident*: an attacker who can write to the database still cannot rewrite history without breaking a signature or a chain link.",
      },
      { type: "h", id: "reading", text: "Reading it" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/api/v1/audit-logs", summary: "Query the tenant's audit trail." },
          { method: "GET", path: "/api/v1/audit-logs/system", summary: "System-level audit events." },
        ],
      },
      {
        type: "note",
        text: "Reading audit logs is itself permission-guarded (`audit_logs:*`) and itself audited. An investigator's access to the trail is part of the trail.",
      },
      { type: "h", id: "gdpr", text: "Audit and the right to erasure" },
      {
        type: "p",
        text: "An append-only log and a legal obligation to erase data are in obvious tension. AXIAM resolves it by **pseudonymising** the actor identity rather than deleting records: on erasure, the identity is replaced by an HMAC-SHA256 pseudonym derived under `AXIAM__GDPR_PSEUDONYM_PEPPER`. The trail's integrity survives; the link to a natural person does not.",
      },
      {
        type: "warn",
        text: "Changing `AXIAM__GDPR_PSEUDONYM_PEPPER` breaks the linkage between existing pseudonyms and new ones — the same person will appear as two different actors either side of the change. Treat it as permanent.",
      },
      { type: "h", id: "retention", text: "Retention" },
      {
        type: "p",
        text: "Because the log only grows, retention is an operational decision you have to make deliberately: size the database for the volume your compliance obligation requires, and archive to cold storage rather than expecting the system to prune for you.",
      },
    ],
  },

  {
    slug: "observability",
    section: "Operate",
    navLabel: "Health & observability",
    title: "Health & observability",
    intro:
      "Probes, structured logs, telemetry hooks and the audit trail — what AXIAM tells you about itself, and what it deliberately does not.",
    blocks: [
      { type: "h", id: "probes", text: "Probes" },
      {
        type: "api",
        endpoints: [
          { method: "GET", path: "/health", summary: "Liveness. Always 200 while the process is up.", public: true },
          { method: "GET", path: "/ready", summary: "Readiness. 200 only when SurrealDB answers; 503 otherwise.", public: true },
        ],
      },
      {
        type: "p",
        text: "Wire these to the right probes and the difference matters operationally: a database blip should remove a replica from the load-balancer rotation, not restart it. Pointing liveness at `/ready` converts a transient dependency failure into a restart loop that makes the outage worse.",
      },
      { type: "h", id: "logs", text: "Logs" },
      {
        type: "p",
        text: "`RUST_LOG` sets verbosity and filtering. Keep it narrow in production — `info` is the intended level, and raising it exposes internal module structure without telling you much you can act on.",
      },
      {
        type: "warn",
        text: "Two things are never in a log line, by construction: **plaintext credentials** and **token strings**. SDKs wrap secrets in redacting types, and error messages are explicitly forbidden from carrying tokens in messages, context fields or stack traces. If you find either in a log, that is a security bug worth reporting.",
      },
      {
        type: "p",
        text: "The rate limiter emits observability lines of its own — including whether the shared cross-replica counter is reachable — which is the signal to watch when limits appear not to be applying as configured.",
      },
      { type: "h", id: "telemetry", text: "Client-side telemetry hooks" },
      {
        type: "p",
        text: "Every SDK exposes telemetry hooks so a client can record request latency, retries, refresh attempts and authorization decisions into whatever tracing system it already uses. This is where per-request visibility lives — the hooks are in the client, where the span you want to attach to already exists.",
      },
      { type: "h", id: "metrics", text: "On metrics" },
      {
        type: "note",
        text: "AXIAM does not currently expose a Prometheus-style `/metrics` endpoint. Today the sources of operational truth are the probes, the structured logs, the audit trail and client-side telemetry. If you need scrape-based metrics now, derive them from log ingestion rather than expecting an endpoint that is not there.",
      },
      { type: "h", id: "audit-as-obs", text: "The audit trail is observability too" },
      {
        type: "p",
        text: "For questions about *who did what*, the audit log is the authoritative source and is queryable through the API — it is not merely a compliance artefact. Authorization decisions carry their reason (`no_grant` versus `denied_by_rule`), which is usually the fastest way to answer \"why was this refused?\" without reconstructing the role model by hand.",
      },
      { type: "h", id: "capacity", text: "Capacity signals" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Symptom", "Usually means"],
        rows: [
          [
            "503s on login under load",
            "The Argon2id concurrency semaphore is shedding. Raise `AXIAM__AUTH__MAX_CONCURRENT_HASHES` only if you have the memory — each permit holds a ~19 MiB arena.",
          ],
          [
            "429s from machine clients that share an egress IP",
            "Per-IP buckets colliding behind NAT. This is the `gateway` rate-limit profile's exact use case.",
          ],
          [
            "Authorization checks slow before anything else does",
            "Database CPU. Those paths scale with it — measured ~90% from a second pair of DB cores — while token issuance does not.",
          ],
          [
            "`/ready` flapping",
            "SurrealDB connectivity, not the server. Check the database before restarting replicas.",
          ],
        ],
      },
    ],
  },

  {
    slug: "hardening",
    section: "Operate",
    navLabel: "Production hardening",
    title: "Production hardening checklist",
    intro:
      "Work through this before a deployment carries real identity traffic. Every item is something AXIAM leaves to you on purpose, because it cannot be decided from inside the process.",
    blocks: [
      { type: "h", id: "secrets", text: "Secrets" },
      {
        type: "list",
        items: [
          "Set `AXIAM__AUTH__SECRET_PROVIDER` to `vault` or `file`. `env` is a development default, not a production one.",
          "**Back up `opaque_setup_key`** if any tenant uses OPAQUE. Losing it is a password reset for every user in every tenant.",
          "Back up `jwt_private_key_pem` and confirm the public key is its actual pair — a mismatch is a confusing outage rather than a clear error.",
          "Configure Vault auto-unseal *before* going live. Without it, any restart leaves AXIAM unable to start until three keyholders are woken up.",
          "Distribute unseal shares to different people, and revoke the root token once the policy and seeding are done.",
          "Confirm no real key material is in a compose file, a manifest, a CI variable or git history.",
        ],
      },
      { type: "h", id: "network", text: "Network & TLS" },
      {
        type: "list",
        items: [
          "TLS 1.3 on every external listener — terminated at the ingress, or in-process with `AXIAM__SERVER__TLS__ENABLED`.",
          "**gRPC (50051) must not be publicly routed.** It is an internal service surface; the shipped manifests deliberately keep it off the Ingress.",
          "AMQP must be `amqps://`. Any other scheme is refused at startup, so a failure here is a configuration error, not a silent downgrade.",
          "Set `AXIAM__SERVER__CORS_ALLOWED_ORIGINS` to your actual admin origins. Empty disables cross-origin requests, which is the safe default.",
          "Set `AXIAM__RATE_LIMIT__TRUSTED_HOPS` to the number of reverse proxies in front of you — otherwise every client shares one apparent IP and per-IP limits become meaningless.",
        ],
      },
      { type: "h", id: "identity", text: "Identity" },
      {
        type: "list",
        items: [
          "Enforce MFA on administrative accounts. Prefer passkeys over TOTP where the browsers in use support them.",
          "Create a second super-admin. Bootstrap cannot be run again to rescue you from losing the first.",
          "Unset `AXIAM_BOOTSTRAP_ADMIN_EMAIL` after bootstrap completes — it is inert afterwards, and leaving it implies otherwise.",
          "Turn on `hibp_check_enabled` and set a sensible `min_length` on the organization baseline.",
          "Review the seeded roles. `super-admin` should have very few holders; most administrators want `admin`, and most humans want neither.",
          "Prefer service accounts with bound certificates over shared secrets for machine access.",
        ],
      },
      { type: "h", id: "limits", text: "Rate limits & capacity" },
      {
        type: "list",
        items: [
          "Pick a rate-limit profile that matches your topology: `internet` for a public deployment, `gateway` behind a NAT or API gateway, `mesh` on a private network.",
          "Leave the key mode at `ip` unless something already authenticates callers at the edge. `client_id` is minted by the caller, so it is a fairness control, not an abuse control.",
          "Size database CPU first if your traffic is authorization-check-heavy; size limits first if it is token-heavy.",
          "Measure before enabling the decision cache, and check its logged hit rate afterwards — it is transformative on gRPC checks and marginal on REST ones.",
        ],
      },
      { type: "h", id: "ops", text: "Operations" },
      {
        type: "list",
        items: [
          "Liveness on `/health`, readiness on `/ready`. Not the other way round.",
          "Keep `RUST_LOG` at `info` and ship logs somewhere they survive the pod.",
          "Decide audit retention deliberately — the log only grows, and nothing prunes it for you.",
          "Register relying parties for back-channel logout **before** you need to revoke an account in an incident.",
          "If you run intercepting Reactors, decide their failure policy explicitly and monitor it. Fail-closed makes a Reactor outage your outage; fail-open makes it a silently unenforced control.",
        ],
      },
      {
        type: "warn",
        text: "One item this checklist cannot give you: AXIAM is pre-1.0 and its security posture is a self-assessment backed by tests and a threat model, not a certified third-party audit. Weigh that against what the deployment is protecting.",
      },
      {
        type: "cards",
        cards: [
          {
            title: "The security model →",
            body: "Threat model, cryptography choices and the shared-responsibility boundary.",
            to: "security",
          },
          {
            title: "Configuration reference →",
            body: "Every variable, its default, and a worked example value.",
            to: "docs",
            doc: "configuration",
          },
        ],
      },
    ],
  },

  {
    slug: "troubleshooting",
    section: "Operate",
    navLabel: "Troubleshooting",
    title: "Troubleshooting",
    intro:
      "The failures that come up most often, what they actually mean, and the fix.",
    blocks: [
      { type: "h", id: "startup", text: "The server will not start" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Symptom", "Cause", "Fix"],
        rows: [
          [
            "`AXIAM__AUTH__SECRET_PROVIDER=... is not a known provider`",
            "A typo in the provider name. AXIAM refuses rather than falling back to `env`.",
            "Use exactly `env`, `file` or `vault`.",
          ],
          [
            "`SECRET_PROVIDER=vault requires AXIAM__AUTH__VAULT_ADDR`",
            "The vault provider is selected but not fully configured.",
            "Set `VAULT_ADDR` and `VAULT_TOKEN`; `VAULT_MOUNT` and `VAULT_PATH` have defaults.",
          ],
          [
            "Startup aborts on the TLS listener",
            "Client authentication is enabled but the CA path is unset, unreadable, empty or malformed. A misconfigured mTLS server never starts serving.",
            "Fix `AXIAM__SERVER__TLS__CLIENT_CA_PATH`, or set `CLIENT_AUTH=off`.",
          ],
          [
            "AMQP refused at startup",
            "`AXIAM__AMQP__URL` does not use `amqps://`. AMQP is TLS-only.",
            "Use the `amqps://` scheme.",
          ],
          [
            "The OIDC issuer is rejected",
            "`AXIAM__AUTH__OAUTH2_ISSUER_URL` is a path, not an origin.",
            "Use an origin — `https://iam.acme.dev`, not `https://iam.acme.dev/acme`.",
          ],
          [
            "Vault is sealed after a restart",
            "No auto-unseal is configured.",
            "Configure auto-unseal. Until then, unseal manually with the key threshold.",
          ],
        ],
      },
      { type: "h", id: "config", text: "A setting has no effect" },
      {
        type: "warn",
        text: "The most common cause by far: a **single underscore** after the prefix. `AXIAM_DB__USERNAME` is silently ignored and the in-code default wins; `AXIAM__DB__USERNAME` is read. The one exception is `AXIAM_BOOTSTRAP_ADMIN_EMAIL`, which is genuinely single-underscore because it is read directly rather than through the layered config.",
      },
      {
        type: "list",
        items: [
          "`AXIAM__DB__URL` takes a bare `host:port`, **not** a URL scheme. The engine resolves a scheme as a hostname and fails.",
          "Rate limits appearing not to apply across replicas: the shared counter is write-behind, so cross-replica enforcement is eventual. Check the limiter's own log lines.",
          "Limits applying to everyone at once: `AXIAM__RATE_LIMIT__TRUSTED_HOPS` is unset behind a proxy, so every client looks like the proxy's IP.",
        ],
      },
      { type: "h", id: "auth-issues", text: "Authentication problems" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Symptom", "Cause", "Fix"],
        rows: [
          [
            "`403` from bootstrap",
            "The gate is not satisfied — email mismatch, or a missing/consumed setup token.",
            "The error names which. Check the variable is set on the *server* process and matches exactly.",
          ],
          [
            "`409` from bootstrap",
            "Bootstrap already completed. It is one-shot, enforced by a uniqueness invariant.",
            "Log in as the existing admin; create further tenants through the API.",
          ],
          [
            "Every OPAQUE login fails after a config change",
            "`opaque_setup_key` changed or is being read from a different provider, so tenant OPRF seeds cannot be decrypted.",
            "Restore the original key. Without it, every user needs a password reset.",
          ],
          [
            "OPAQUE login fails for everyone in one tenant",
            "`opaque_mode` was set to `required` before users enrolled. Nobody can be enrolled retroactively.",
            "Set it back to `optional`, let enrolment complete, then flip.",
          ],
          [
            "Tokens stop verifying after a restart",
            "The JWT keypair changed, or the private and public keys are not a pair.",
            "Restore the original keypair from your secret store.",
          ],
          [
            "Passkey registration buttons never appear",
            "The browser does not support WebAuthn, or the page is not on a secure origin.",
            "WebAuthn requires HTTPS (or localhost). Other sign-in methods are unaffected.",
          ],
          [
            "Passkeys are rejected after setting an attestation policy",
            "Platform authenticators commonly attest as `none` for privacy reasons.",
            "A strict attestation policy is a security-key-only policy in practice. Decide which you meant.",
          ],
        ],
      },
      { type: "h", id: "authz-issues", text: "Authorization problems" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Symptom", "Cause", "Fix"],
        rows: [
          [
            "A user is denied despite holding an allowing role",
            "A **deny** grant applies — possibly inherited from an ancestor resource or through a group. Deny beats every allow.",
            "Find the deny and narrow it. Adding another allow will not help; that is the design.",
          ],
          [
            "Denied with `no_grant` rather than `denied_by_rule`",
            "Nothing granted the action at all — default deny, not an explicit refusal.",
            "Grant the permission, or check that the resource id and action name are what you think they are.",
          ],
          [
            "A scoped allow behaves as if it were not there",
            "A resource-level deny with no scopes is a wildcard and masks every scope for that action.",
            "Narrow the deny to the specific scopes you meant to exclude.",
          ],
          [
            "A revocation seems not to take effect",
            "Almost never the decision cache — access-narrowing mutations invalidate immediately. Check group membership and inherited roles first.",
            "Trace the role model; the TTL is a backstop, not the mechanism.",
          ],
        ],
      },
      { type: "h", id: "build", text: "Build problems" },
      {
        type: "list",
        items: [
          "**`libxml2` headers missing** — the default `saml` feature links `libxml`. Build with `--no-default-features`, which is what CI's *Build (SAML off)* job does.",
          "**MSRV complaints from `axiam-opaque`** — it states its own floor (1.88) rather than inheriting the workspace's, because it is vendored into SDKs with lower MSRVs. That is deliberate.",
        ],
      },
      {
        type: "note",
        text: "Not covered here? The authorization decision reason, the audit trail and the limiter's log lines answer most \"why did that happen\" questions between them. For a suspected security issue, use the private advisory process rather than a public issue.",
      },
    ],
  },
];
