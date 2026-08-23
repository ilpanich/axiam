import type { DocPage } from "./types";
import { DOCS_VERIFIED_RELEASE } from "../version";

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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
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
      { type: "h", id: "sizing-guides", text: "Sizing, measured" },
      {
        type: "p",
        text: "Two deployment guides in the repository answer the questions this page raises and does not settle — both are derived from benchmark runs and query plans rather than from estimates.",
      },
      {
        type: "links",
        links: [
          {
            label: "Sizing your rate limits",
            href: "https://github.com/ilpanich/axiam/blob/main/docs/deployment/rate-limit-sizing.md",
            note: "Which of the three postures fits your topology, what the presets are worth, and the measured envelope behind them.",
          },
          {
            label: "The authorization read path",
            href: "https://github.com/ilpanich/axiam/blob/main/docs/deployment/authz-read-path.md",
            note: "What one uncached check costs in database round-trips, and which cache removes which one.",
          },
        ],
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["You are", "Rate-limit posture", "Why"],
        rows: [
          [
            "A small internet-facing deployment where humans log in from many addresses",
            "the shipped defaults",
            "Sized to stop single-source credential stuffing and token probing.",
          ],
          [
            "A machine-to-machine, microservice or IoT fleet arriving through a shared NAT or egress gateway",
            "`gateway`",
            "Many distinct OAuth2 clients share one source address, so per-IP buckets collide and the fleet throttles itself.",
          ],
          [
            "Reachable only on a private network or service mesh",
            "`mesh`",
            "Ceilings become runaway-loop guards; abuse control belongs at the network edge.",
          ],
        ],
      },
      {
        type: "note",
        text: "Presets are opt-in — setting no profile keeps the shipped defaults byte for byte — and **no profile ever changes the human endpoints**. Login, registration, password reset and MFA stay strict and per-IP in every posture, because a service-mesh capacity decision must not silently widen the surface an attacker actually attacks.",
      },
      {
        type: "p",
        text: "On the read path, the thing worth knowing before tuning: an uncached authorization check is a short sequence of *sequential* database round-trips, and the REST surface carries one the gRPC surface does not — a session-revocation lookup, because the gRPC interceptor validates the token signature and stops. Enabling only the decision cache therefore helps gRPC considerably more than REST; the session-validation cache is what closes the gap.",
      },
      {
        type: "warn",
        text: "Both caches are process-local by default, and both carry the same multi-replica caveat: a revocation handled by one replica is not seen by the others until their entries expire. Enable them at the same TTL — a deployment that has accepted a five-second decision-staleness window gains nothing from a zero-second session-staleness window, and the reverse leaves the looser of the two setting your actual revocation latency.",
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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
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
      { type: "h", id: "iot", text: "Enrolling an IoT device, end to end" },
      {
        type: "p",
        text: "This is the shape AXIAM was built for on the device side: a device is issued a certificate at commissioning, presents it for mTLS, and is then authorized by the same RBAC engine as everything else. Four steps, and one of them is the one people expect to need and do not.",
      },
      {
        type: "steps",
        steps: [
          {
            title: "Have an organization CA",
            body: "CA certificates are organization-scoped and are the trust root every leaf in that organization chains to. The response carries the CA's signing private key **once** — AXIAM never persists the plaintext — so store it in your secret manager before you do anything else.",
            code: 'POST /api/v1/organizations/{org_id}/ca-certificates\n{\n  "subject": "CN=Acme Corp Root CA",\n  "key_algorithm": "Ed25519",\n  "validity_days": 3650\n}',
          },
          {
            title: "Issue the device certificate",
            body: "Leaf certificates are tenant-scoped. Set `cert_type` to `Device` — that is what makes the certificate addressable by fingerprint at authentication time. The private key comes back once and is never stored.",
            code: 'POST /api/v1/certificates\n{\n  "issuer_ca_id": "<ca-certificate-uuid>",\n  "subject": "CN=sensor-0421.acme.dev",\n  "cert_type": "Device",\n  "key_algorithm": "Ed25519",\n  "validity_days": 365\n}',
          },
          {
            title: "Commission the device with the key pair",
            body: "Write the certificate and its private key into the device at manufacture or first provisioning. This is the only moment the private key exists outside the device, which is why the issuing response is the one call whose output you must capture.",
          },
          {
            title: "Let it connect over mTLS",
            body: "The device presents its client certificate on the TLS handshake. Nothing further needs registering — the binding step that service accounts require does not apply here.",
          },
        ],
      },
      {
        type: "warn",
        text: "**Device certificates are not bound to anything.** A `Service` certificate must be attached to a service account explicitly, and it is natural to assume a device needs the same. It does not: on connection AXIAM computes the certificate's SHA-256 fingerprint, looks a `Device` certificate up directly by it, checks the certificate is active and unexpired, and **verifies the full chain** to the issuing organization's CA. Looking for a bind endpoint for a device is looking for something that does not exist.",
      },
      {
        type: "note",
        text: "A fingerprint match alone never authenticates a device. If the organization has no active CA certificate, the chain check has nothing to verify against and the attempt fails closed — which is the behaviour you want, and also the first thing to check when a correctly-commissioned device is refused.",
      },
      {
        type: "p",
        text: "Two limits worth knowing before you commission a fleet. A tenant can cap certificate lifetime through its `max_certificate_validity_days` setting, and a request exceeding that cap is rejected rather than silently shortened. And where a device cannot show a browser to enrol a *user*, the [device authorization grant](#/docs/device-flow) covers the human-approval half — that is a different mechanism from this one, and the two are often confused.",
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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
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
      { type: "h", id: "jobs", text: "Scheduled-job liveness" },
      {
        type: "p",
        text: "A background sweep that stops running is invisible. Nothing errors and nothing returns a 500 — the work simply stops happening, and for the two jobs where that matters most, GDPR erasure and certificate expiry, the first symptom can be a regulator's question months later. A failure was always logged, but a log line nobody greps for is not a control.",
      },
      {
        type: "api",
        endpoints: [
          {
            method: "GET",
            path: "/health/jobs",
            summary: "Last-known outcome of every registered sweep. Always 200.",
          },
        ],
      },
      {
        type: "code",
        caption: "a degraded response",
        code: '{\n  "status": "degraded",\n  "jobs": [\n    {\n      "name": "gdpr_purge",\n      "last_success_at": "2026-08-21T02:00:04Z",\n      "last_failure_at": "2026-08-23T02:00:01Z",\n      "last_error": "database unreachable",\n      "consecutive_failures": 3,\n      "stalled": true\n    },\n    {\n      "name": "audit_retention",\n      "last_success_at": "2026-08-23T02:00:07Z",\n      "last_failure_at": null,\n      "last_error": null,\n      "consecutive_failures": 0,\n      "stalled": false\n    }\n  ]\n}',
      },
      {
        type: "p",
        text: "Six sweeps are registered: `saml_assertion_replay`, `federation_login_state`, `amqp_nonce_replay`, `gdpr_purge`, `gdpr_export` and `audit_retention`. Each appears in the snapshot from startup, before its first run — so a job that has never once succeeded is visible as such rather than simply absent.",
      },
      {
        type: "table",
        headers: ["Field", "What it tells you"],
        rows: [
          ["`stalled`", "The job has missed three consecutive expected runs. **This is the field to alert on.**"],
          ["`consecutive_failures`", "Failures since the last success; reset to zero on success."],
          ["`last_error`", "The last error text, for whoever is now looking at this wondering what broke."],
          ["`last_success_at`", "When it last completed cleanly. `null` means never."],
        ],
      },
      {
        type: "note",
        text: "`stalled` is computed server-side rather than left to the caller, because the sweep interval is configuration a dashboard does not have — and \"how long is too long\" is not a judgement worth re-deriving from timestamps in three places. The threshold is three missed intervals rather than one: a sweep that overruns, or a tick skipped under load, is normal and must not page anyone.",
      },
      {
        type: "warn",
        text: "The endpoint returns **200 even when degraded**, and that is deliberate. It is not a readiness gate: a stuck cleanup sweep is an operational problem, not a reason to pull a healthy server out of the load balancer and send its traffic to replicas running the same stuck code. Alert on `status` being `degraded`, or on a specific job's `stalled` — never wire this to a liveness probe.",
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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
    blocks: [
      {
        type: "p",
        text: "Each row is one check, the setting or action it turns on, and what goes wrong if you skip it. The last column is the point: an item whose consequence you cannot state is an item nobody will prioritise.",
      },
      { type: "h", id: "secrets", text: "Secrets" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Check", "Setting or action", "If you skip it"],
        rows: [
          [
            "Secrets come from a manager, not the environment",
            "`AXIAM__AUTH__SECRET_PROVIDER` = `vault` or `file`",
            "`env` is a development default. Key material ends up in a process listing, a compose file and a CI log.",
          ],
          [
            "OPAQUE setup key is backed up",
            "Back up `opaque_setup_key`",
            "Losing it is a forced password reset for every user in every tenant. There is no recovery path.",
          ],
          [
            "JWT key pair is backed up and actually a pair",
            "Back up `jwt_private_key_pem`; verify the public key matches",
            "A mismatch presents as a confusing outage — tokens are minted and then rejected — rather than as a clear error.",
          ],
          [
            "Vault auto-unseal is configured before go-live",
            "Vault auto-unseal",
            "Any restart leaves AXIAM unable to start until enough keyholders are woken up.",
          ],
          [
            "Vault trust anchor is set if it uses a private CA",
            "`AXIAM__AUTH__VAULT_CA_CERT_PATH`",
            "rustls does not trust an internal PKI, and the server dies at startup with a bare transport error that names nothing.",
          ],
          [
            "Unseal shares are distributed and the root token revoked",
            "Split shares across people; revoke root after seeding",
            "One person holding every share is the failure mode the threshold exists to prevent.",
          ],
          [
            "No key material in git, images, manifests or CI variables",
            "Audit history, not just the working tree",
            "A rotated secret that is still in git history is still a leaked secret.",
          ],
        ],
      },
      { type: "h", id: "network", text: "Network & TLS" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Check", "Setting or action", "If you skip it"],
        rows: [
          [
            "TLS 1.3 on every external listener",
            "Terminate at the ingress, or `AXIAM__SERVER__TLS__ENABLED` in-process",
            "The default binds plaintext and assumes something in front of it terminates TLS. If nothing does, nothing warns you.",
          ],
          [
            "gRPC is not publicly routed",
            "Keep 50051 off the Ingress",
            "It is an internal service surface. The shipped manifests deliberately keep it on the ClusterIP service only.",
          ],
          [
            "AMQP uses amqps://",
            "`AXIAM__AMQP__URL`",
            "Nothing — this one cannot be skipped. Any other scheme is refused at startup, so a mistake here is a visible configuration error rather than a silent downgrade.",
          ],
          [
            "CORS names your actual admin origins",
            "`AXIAM__SERVER__CORS_ALLOWED_ORIGINS`",
            "Empty disables cross-origin requests, which is the safe default — so the risk is over-broadening it, not forgetting it.",
          ],
          [
            "Proxy hop count is accurate",
            "`AXIAM__RATE_LIMIT__TRUSTED_HOPS`",
            "Every client shares one apparent address, per-IP limits become meaningless, and one abusive caller throttles everybody.",
          ],
        ],
      },
      { type: "h", id: "identity", text: "Identity" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Check", "Setting or action", "If you skip it"],
        rows: [
          [
            "MFA enforced on administrative accounts",
            "Tenant MFA policy; prefer passkeys over TOTP where browsers allow",
            "The accounts that can grant every other permission are protected by a password alone.",
          ],
          [
            "A second super-admin exists",
            "Create one deliberately",
            "Bootstrap cannot be run again to rescue you from losing the first.",
          ],
          [
            "Bootstrap variable unset after bootstrap",
            "Unset `AXIAM_BOOTSTRAP_ADMIN_EMAIL`",
            "It is inert afterwards, so this is hygiene rather than exposure — leaving it implies a live gate that is not there.",
          ],
          [
            "Password policy is set on the organization baseline",
            "`hibp_check_enabled`, plus a sensible `min_length`",
            "Known-breached passwords are accepted, and the strongest hash in the world does not help against a password already in a wordlist.",
          ],
          [
            "Seeded roles reviewed",
            "Audit who holds `super-admin`",
            "`super-admin` should have very few holders. Most administrators want `admin`; most humans want neither.",
          ],
          [
            "Machine access uses bound certificates",
            "Service accounts with certificates over shared secrets",
            "A shared secret is copyable, does not expire on its own, and leaves no evidence of which copy was used.",
          ],
          [
            "SCIM provisioning tokens treated as admin credentials",
            "Rotate and store like an admin password",
            "`scim:provision` can set any user's password in the tenant, including an administrator's. See [SCIM provisioning](#/docs/scim).",
          ],
        ],
      },
      { type: "h", id: "limits", text: "Rate limits & capacity" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Check", "Setting or action", "If you skip it"],
        rows: [
          [
            "Rate-limit posture matches the topology",
            "`AXIAM__RATE_LIMIT__PROFILE` — `internet`, `gateway` or `mesh`",
            "A NAT-fronted fleet throttles itself on per-IP buckets; a public deployment on mesh ceilings has effectively none.",
          ],
          [
            "Bucket key left at ip unless the edge authenticates",
            "`AXIAM__RATE_LIMIT__KEY`",
            "`client_id` is minted by the caller, which makes it a fairness control and not an abuse control.",
          ],
          [
            "Capacity sized against the right bottleneck",
            "Database CPU for check-heavy traffic; limits for token-heavy traffic",
            "Tuning the wrong one moves no numbers and costs a maintenance window.",
          ],
          [
            "Caches measured, not assumed",
            "Enable, then read the logged hit rate",
            "The decision cache is transformative on gRPC checks and marginal on REST ones, because REST carries a session lookup gRPC does not.",
          ],
        ],
      },
      { type: "h", id: "ops", text: "Operations" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Check", "Setting or action", "If you skip it"],
        rows: [
          [
            "Probes wired the right way round",
            "Liveness on `/health`, readiness on `/ready`",
            "Pointing liveness at `/ready` turns a database blip into a restart loop that makes the outage worse.",
          ],
          [
            "Scheduled jobs are alerted on",
            "Alert on `stalled` from `/health/jobs`",
            "A sweep that stops running raises nothing. For GDPR erasure the first symptom can be a regulator's question.",
          ],
          [
            "Logs survive the pod",
            "`RUST_LOG=info`, shipped off-host",
            "The audit trail persists; your diagnostic context does not.",
          ],
          [
            "Audit retention decided deliberately",
            "Set a retention policy",
            "The log only grows. Nothing prunes it for you, and it is append-only by design.",
          ],
          [
            "Back-channel logout relying parties registered in advance",
            "Register before you need them",
            "An incident is the wrong time to discover that revoking an account does not sign it out anywhere else.",
          ],
          [
            "Reactor failure policy chosen explicitly",
            "Decide fail-open versus fail-closed per hook, and monitor it",
            "Fail-closed makes a reactor outage your outage; fail-open makes it a silently unenforced control. Not choosing picks one anyway.",
          ],
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
    verifiedRelease: DOCS_VERIFIED_RELEASE,
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
      { type: "h", id: "vault", text: "Vault will not come up" },
      {
        type: "p",
        text: "Vault is the production secret provider, and the failures below are the ones actually hit while getting the shipped production stack running — each one presents as something other than what it is.",
      },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Symptom", "Cause", "Fix"],
        rows: [
          [
            "The server panics at startup with a bare transport error to Vault",
            "Vault's certificate is issued by an internal PKI. rustls compiles its roots in, so a private CA is not trusted and the failure surfaces as an unhelpful transport error rather than as a certificate problem.",
            "Point `AXIAM__AUTH__VAULT_CA_CERT_PATH` at the issuing CA.",
          ],
          [
            "Vault restart-loops on `error loading TLS cert`",
            "The listener key file is mode 0600 and unreadable to the uid the container runs as.",
            "Make the key readable by the container's user, not only by the host user that generated it.",
          ],
          [
            "Every run after a failed initialisation wedges",
            "An initialisation that failed mid-write left an empty state file behind, which later runs then treated as real.",
            "Drive initialisation from Vault's own `sys/init` status rather than from the presence of a state file, and validate before writing it.",
          ],
          [
            "Vault cannot be reached from the host to initialise or unseal it",
            "Its port is published on loopback only.",
            "Run the initialise, unseal and seed steps from the host, or publish the port where the tooling can reach it.",
          ],
        ],
      },
      {
        type: "note",
        text: "A compose stack that will not start at all, with no service logs to read, is worth checking for shell-style interpolation that Compose does not implement: `${VAR:default}` is not valid Compose syntax, and a file using it fails before anything runs.",
      },
      { type: "h", id: "database", text: "Database" },
      {
        type: "table",
        proseFirstCol: true,
        headers: ["Symptom", "Cause", "Fix"],
        rows: [
          [
            "Data vanishes on restart",
            "SurrealDB is running its in-memory datastore. AXIAM requires a persistent engine.",
            "Use a persistent engine; the shipped compose files and the Kubernetes StatefulSet already do.",
          ],
          [
            "A startup WARN saying the storage engine could not be attested",
            "Expected, and not a misconfiguration. SurrealDB publishes no datastore identity over the wire, so the attestation cannot confirm the engine either way.",
            "Nothing. The hard guard exists and refuses a memory datastore as soon as a SurrealDB release exposes the engine name.",
          ],
        ],
      },
      { type: "h", id: "jobs-stopped", text: "Cleanup work has silently stopped" },
      {
        type: "p",
        text: "Erasure requests that never complete, certificates that never expire, replay tables that grow without bound — these share a cause and a check. A scheduled sweep that stops running raises nothing, so the symptom is always downstream and always late.",
      },
      {
        type: "code",
        code: "curl -s localhost:8090/health/jobs | jq '.status, .jobs[] | select(.stalled)'",
      },
      {
        type: "p",
        text: "See [scheduled-job liveness](#/docs/observability) for the response shape and what `stalled` means. If a job shows `consecutive_failures` climbing, `last_error` is the reason.",
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
